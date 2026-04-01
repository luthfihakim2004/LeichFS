#include "leichfs/init.hpp"

#include <argon2.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <string>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <vector>

#include "enc/crypto.hpp"
#include "enc/params.hpp"
#include "util.hpp"

namespace leichfs {

// ── Internal helpers ─────────────────────────────────────────────────────────

// AAD for master key
static constexpr uint8_t WRAP_AAD[] = "leichfs-key-wrap";

// Read a passphrase from the terminal with echo disabled
// Returns the passphrase, or empty string on error
static std::string read_passphrase(const char* prompt) {
  int ttyfd = ::open("/dev/tty", O_RDWR | O_CLOEXEC);
  if (ttyfd == -1) ttyfd = STDIN_FILENO; // fallback

  // Print prompt directly to tty so it appears even if stdin is redirected
  ::dprintf(ttyfd, "%s", prompt);

  struct termios old{}, noecho{};
  bool have_termios = (::tcgetattr(ttyfd, &old) == 0);
  if (have_termios) {
    noecho = old;
    noecho.c_lflag &= ~static_cast<tcflag_t>(ECHO | ECHOE | ECHOK | ECHONL);
    ::tcsetattr(ttyfd, TCSANOW, &noecho);
  }

  std::string pass;
  char c;
  while (::read(ttyfd, &c, 1) == 1 && c != '\n' && c != '\r')
    pass += c;

  if (have_termios) ::tcsetattr(ttyfd, TCSANOW, &old);
  ::dprintf(ttyfd, "\n");

  if (ttyfd != STDIN_FILENO) ::close(ttyfd);
  return pass;
}

// Derive a 32-byte wrapping key from `passphrase` + `salt` using Argon2id
// Returns 0 on success, -1 on error
static int derive_wrap_key(const std::string&   passphrase,
                           const uint8_t        salt[enc::SALT_SIZE],
                           const Argon2Params&  p,
                           std::array<uint8_t, enc::KEY_SIZE>& out) {
  int rc = argon2id_hash_raw(
      p.t_cost, p.m_cost, p.parallelism,
      passphrase.data(), passphrase.size(),
      salt, enc::SALT_SIZE,
      out.data(), enc::KEY_SIZE);
  if (rc != ARGON2_OK) {
    std::fprintf(stderr, "[leichfs] argon2 error: %s\n", argon2_error_message(rc));
    return -1;
  }
  return 0;
}

// Simple hex helpers
static std::string to_hex(const uint8_t* p, size_t n) {
  static constexpr char H[] = "0123456789abcdef";
  std::string out(n * 2, '\0');
  for (size_t i = 0; i < n; ++i) {
    out[2*i]   = H[p[i] >> 4];
    out[2*i+1] = H[p[i] & 0xf];
  }
  return out;
}

static int from_hex(const std::string& s, uint8_t* out, size_t n) {
  if (s.size() != n * 2) return -1;
  auto h2n = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
  };
  for (size_t i = 0; i < n; ++i) {
    int hi = h2n(s[2*i]), lo = h2n(s[2*i+1]);
    if (hi < 0 || lo < 0) return -1;
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return 0;
}

// Write config file atomically (write to .tmp, then rename)
static int write_conf(const std::filesystem::path& path,
                      const Argon2Params& p,
                      const uint8_t salt[enc::SALT_SIZE],
                      const uint8_t wrapped_key[enc::KEY_SIZE],
                      const uint8_t wrap_nonce[enc::NONCE_SIZE],
                      const uint8_t wrap_tag[enc::TAG_SIZE]) {
  std::string tmp = path.string() + ".tmp";

  int fd = ::open(tmp.c_str(),
                  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd == -1) {
    std::fprintf(stderr, "[leichfs] cannot create config: %s\n",
                 std::strerror(errno));
    return -1;
  }

  // JSON — written manually to avoid pulling in any library
  std::string json =
    "{\n"
    "  \"version\": 1,\n"
    "  \"kdf\": \"argon2id\",\n"
    "  \"argon2_m\": " + std::to_string(p.m_cost) + ",\n"
    "  \"argon2_t\": " + std::to_string(p.t_cost) + ",\n"
    "  \"argon2_p\": " + std::to_string(p.parallelism) + ",\n"
    "  \"salt\": \""         + to_hex(salt,        enc::SALT_SIZE)  + "\",\n"
    "  \"wrapped_key\": \""  + to_hex(wrapped_key, enc::KEY_SIZE)   + "\",\n"
    "  \"wrap_nonce\": \""   + to_hex(wrap_nonce,  enc::NONCE_SIZE) + "\",\n"
    "  \"wrap_tag\": \""     + to_hex(wrap_tag,    enc::TAG_SIZE)   + "\"\n"
    "}\n";

  ssize_t w = ::write(fd, json.data(), json.size());
  ::close(fd);

  if (w != static_cast<ssize_t>(json.size())) {
    ::unlink(tmp.c_str());
    return -1;
  }

  if (::rename(tmp.c_str(), path.c_str()) == -1) {
    ::unlink(tmp.c_str());
    return -1;
  }
  return 0;
}

// Parse the config file — returns 0 on success
// This is a minimal hand-rolled parser for known fixed schema
static int parse_conf(const std::filesystem::path& path,
                      Argon2Params&   p,
                      std::array<uint8_t, enc::SALT_SIZE>&   salt,
                      std::array<uint8_t, enc::KEY_SIZE>&    wrapped_key,
                      std::array<uint8_t, enc::NONCE_SIZE>&  wrap_nonce,
                      std::array<uint8_t, enc::TAG_SIZE>&    wrap_tag) {
  int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd == -1) {
    std::fprintf(stderr, "[leichfs] cannot open config '%s': %s\n",
                 path.c_str(), std::strerror(errno));
    return -1;
  }

  // Read entire file content into memory
  std::string content;
  char buf[256];
  ssize_t n;
  while ((n = ::read(fd, buf, sizeof(buf))) > 0)
      content.append(buf, static_cast<size_t>(n));
  ::close(fd);

  // Parser for extracting "<key>" field
  auto field = [&](const std::string& key) -> std::string {
    // Look up for the key field first
    auto pos = content.find("\"" + key + "\"");
    if (pos == std::string::npos) return {};
    pos = content.find(':', pos);
    if (pos == std::string::npos) return {};
    ++pos;
    while (pos < content.size() && (content[pos] == ' ' || content[pos] == '\n')) ++pos;
    if (pos >= content.size()) return {};

    // Extract the value
    // String value is stored between `"`
    if (content[pos] == '"') {
      ++pos;
      auto end = content.find('"', pos);
      return end == std::string::npos ? std::string{} : content.substr(pos, end - pos);
    }
    // Numeric value
    auto end = content.find_first_of(",\n}", pos);
    return content.substr(pos, end - pos);
  };

  p.m_cost      = static_cast<uint32_t>(std::stoul(field("argon2_m")));
  p.t_cost      = static_cast<uint32_t>(std::stoul(field("argon2_t")));
  p.parallelism = static_cast<uint32_t>(std::stoul(field("argon2_p")));

  if (from_hex(field("salt"),        salt.data(),        enc::SALT_SIZE)  != 0 ||
      from_hex(field("wrapped_key"), wrapped_key.data(), enc::KEY_SIZE)   != 0 ||
      from_hex(field("wrap_nonce"),  wrap_nonce.data(),  enc::NONCE_SIZE) != 0 ||
      from_hex(field("wrap_tag"),    wrap_tag.data(),    enc::TAG_SIZE)   != 0) {
      std::fprintf(stderr, "[leichfs] config parse error: invalid hex fields\n");
      return -1;
  }
  return 0;
}


// ── Public API ────────────────────────────────────────────────────────────────

int leichfs_init(const char* dir, const Argon2Params& params) {
  std::error_code ec;
  std::filesystem::path backing{dir};
  if (!std::filesystem::exists(backing, ec) || ec) {
    std::fprintf(stderr, "[leichfs] --init: '%s' does not exist or is inaccessible\n", dir);
    return -1;
  }
  if (!std::filesystem::is_directory(backing, ec) || ec) {
    std::fprintf(stderr, "[leichfs] --init: '%s' is not a directory\n", dir);
    return -1;
  }

  // Check that it isn't already initialised
  std::filesystem::path conf_path = backing / CONF_FILENAME;
  if (::access(conf_path.c_str(), F_OK) == 0) {
    std::fprintf(stderr,
      "[leichfs] '%s' is already initialised (%s exists)\n"
      "  To re-initialise, delete %s first.\n",
      dir, CONF_FILENAME, conf_path.c_str());
    return -1;
  }

  // Prompt passphrase
  std::string pass1 = read_passphrase("Enter passphrase: ");
  if (pass1.empty()) {
      std::fprintf(stderr, "[leichfs] empty passphrase not allowed\n");
      return -1;
  }
  std::string pass2 = read_passphrase("Confirm passphrase: ");
  if (pass1 != pass2) {
      OPENSSL_cleanse(pass1.data(), pass1.size());
      OPENSSL_cleanse(pass2.data(), pass2.size());
      std::fprintf(stderr, "[leichfs] passphrases do not match\n");
      return -1;
  }
  OPENSSL_cleanse(pass2.data(), pass2.size());

  // Generate random salt and master key separately using fill_rand()
  std::array<uint8_t, enc::SALT_SIZE> salt{};
  std::array<uint8_t, enc::KEY_SIZE>  master_key{};
  if (util::enc::fill_rand(salt.data(), salt.size()) != 0 ||
      util::enc::fill_rand(master_key.data(), master_key.size()) != 0) {
    OPENSSL_cleanse(pass1.data(), pass1.size());
    std::fprintf(stderr, "[leichfs] getrandom failed\n");
    return -1;
  }

  // Derive wrapping key from passphrase.
  std::fprintf(stderr, "[leichfs] deriving key (this may take a moment)...\n");
  std::array<uint8_t, enc::KEY_SIZE> wrap_key{};
  if (derive_wrap_key(pass1, salt.data(), params, wrap_key) != 0) {
    OPENSSL_cleanse(pass1.data(), pass1.size());
    OPENSSL_cleanse(master_key.data(), master_key.size());
    return -1;
  }
  OPENSSL_cleanse(pass1.data(), pass1.size());

  // Wrap master key with AES-256-GCM using the derived wrapping key.
  std::array<uint8_t, enc::NONCE_SIZE> wrap_nonce{};
  std::array<uint8_t, enc::KEY_SIZE>   wrapped_key{};
  std::array<uint8_t, enc::TAG_SIZE>   wrap_tag{};

  if (util::enc::fill_rand(wrap_nonce.data(), wrap_nonce.size()) != 0) {
    OPENSSL_cleanse(master_key.data(), master_key.size());
    OPENSSL_cleanse(wrap_key.data(), wrap_key.size());
    return -1;
  }

  if (enc::aesgcm_encrypt(wrap_key.data(), wrap_nonce.data(),
                          master_key.data(), enc::KEY_SIZE,
                          WRAP_AAD, sizeof(WRAP_AAD) - 1,
                          wrapped_key.data(),
                          wrap_tag.data()) != 0) {
    OPENSSL_cleanse(master_key.data(), master_key.size());
    OPENSSL_cleanse(wrap_key.data(), wrap_key.size());
    std::fprintf(stderr, "[leichfs] key wrap failed\n");
    return -1;
  }

  OPENSSL_cleanse(master_key.data(), master_key.size());
  OPENSSL_cleanse(wrap_key.data(), wrap_key.size());

  // Write config file.
  if (write_conf(conf_path, params,
                 salt.data(),
                 wrapped_key.data(),
                 wrap_nonce.data(),
                 wrap_tag.data()) != 0) {
      std::fprintf(stderr, "[leichfs] failed to write config\n");
      return -1;
  }

  std::fprintf(stderr,
      "[leichfs] initialised '%s'\n"
      "  Config: %s\n"
      "  KDF: argon2id (m=%u KiB, t=%u, p=%u)\n"
      "  Keep your passphrase safe — there is no recovery.\n",
      dir, conf_path.c_str(),
      params.m_cost, params.t_cost, params.parallelism);
  return 0;
}

int load_master_key_from_conf(const char* dir,
                              std::array<uint8_t, enc::KEY_SIZE>& out) {
  std::filesystem::path conf_path = std::filesystem::path{dir} / CONF_FILENAME;
  
  Argon2Params p{};
  std::array<uint8_t, enc::SALT_SIZE>   salt{};
  std::array<uint8_t, enc::KEY_SIZE>    wrapped_key{};
  std::array<uint8_t, enc::NONCE_SIZE>  wrap_nonce{};
  std::array<uint8_t, enc::TAG_SIZE>    wrap_tag{};

  if (parse_conf(conf_path, p, salt, wrapped_key, wrap_nonce, wrap_tag) != 0)
      return -1;

  // Validate the passphrase
  std::string pass = read_passphrase("Passphrase: ");
  if (pass.empty()) {
    std::fprintf(stderr, "[leichfs] empty passphrase\n");
    return -1;
  }

  // Deriving wrapping key (KEK)
  std::fprintf(stderr, "[leichfs] deriving key...\n");
  std::array<uint8_t, enc::KEY_SIZE> wrap_key{};
  if (derive_wrap_key(pass, salt.data(), p, wrap_key) != 0) {
    OPENSSL_cleanse(pass.data(), pass.size());
    return -1;
  }
  OPENSSL_cleanse(pass.data(), pass.size());

  // Decrypt (unwrap) wrapped_key stored in the config file
  int rc = enc::aesgcm_decrypt(wrap_key.data(), wrap_nonce.data(),
                               wrapped_key.data(), enc::KEY_SIZE,
                               WRAP_AAD, sizeof(WRAP_AAD) - 1,
                               wrap_tag.data(),
                               out.data());
  OPENSSL_cleanse(wrap_key.data(), wrap_key.size());

  if (rc != 0) {
    std::fprintf(stderr, "[leichfs] wrong passphrase or corrupted config\n");
    return -1;
  }
  return 0;
}

int leichfs_change_passphrase(const char* dir) {
  std::filesystem::path conf_path = std::filesystem::path{dir} / CONF_FILENAME;

  // Load and parse existing config 
  Argon2Params p{};
  std::array<uint8_t, enc::SALT_SIZE>   salt{};
  std::array<uint8_t, enc::KEY_SIZE>    wrapped_key{};
  std::array<uint8_t, enc::NONCE_SIZE>  wrap_nonce{};
  std::array<uint8_t, enc::TAG_SIZE>    wrap_tag{};

  if (parse_conf(conf_path, p, salt, wrapped_key, wrap_nonce, wrap_tag) != 0)
    return -1;

  // Unwrap master key with current passphrase 
  std::string old_pass = read_passphrase("Current passphrase: ");
  if (old_pass.empty()) {
    std::fprintf(stderr, "[leichfs] empty passphrase\n");
    return -1;
  }

  std::fprintf(stderr, "[leichfs] verifying current passphrase...\n");
  std::array<uint8_t, enc::KEY_SIZE> old_wrap_key{};
  if (derive_wrap_key(old_pass, salt.data(), p, old_wrap_key) != 0) {
    OPENSSL_cleanse(old_pass.data(), old_pass.size());
    return -1;
  }
  OPENSSL_cleanse(old_pass.data(), old_pass.size());

  std::array<uint8_t, enc::KEY_SIZE> master_key{};
  int rc = enc::aesgcm_decrypt(old_wrap_key.data(), wrap_nonce.data(),
                               wrapped_key.data(), enc::KEY_SIZE,
                               WRAP_AAD, sizeof(WRAP_AAD) - 1,
                               wrap_tag.data(),
                               master_key.data());
  OPENSSL_cleanse(old_wrap_key.data(), old_wrap_key.size());

  if (rc != 0) {
    std::fprintf(stderr, "[leichfs] wrong passphrase\n");
    return -1;
  }

  // Prompt new passphrase
  std::string new_pass1 = read_passphrase("New passphrase: ");
  if (new_pass1.empty()) {
    OPENSSL_cleanse(master_key.data(), master_key.size());
    std::fprintf(stderr, "[leichfs] empty passphrase not allowed\n");
    return -1;
  }
  std::string new_pass2 = read_passphrase("Confirm new passphrase: ");
  if (new_pass1 != new_pass2) {
    OPENSSL_cleanse(master_key.data(), master_key.size());
    OPENSSL_cleanse(new_pass1.data(), new_pass1.size());
    OPENSSL_cleanse(new_pass2.data(), new_pass2.size());
    std::fprintf(stderr, "[leichfs] passphrases do not match\n");
    return -1;
  }
  OPENSSL_cleanse(new_pass2.data(), new_pass2.size());

  // Derive new wrapping key and re-wrap master key
  // Generate a fresh salt for the new wrapping key. DONT use the old salt! 
  std::array<uint8_t, enc::SALT_SIZE> new_salt{};
  if (util::enc::fill_rand(new_salt.data(), new_salt.size()) != 0) {
    OPENSSL_cleanse(master_key.data(), master_key.size());
    OPENSSL_cleanse(new_pass1.data(), new_pass1.size());
    return -1;
  }

  std::fprintf(stderr, "[leichfs] deriving new key (this may take a moment)...\n");
  std::array<uint8_t, enc::KEY_SIZE> new_wrap_key{};
  if (derive_wrap_key(new_pass1, new_salt.data(), p, new_wrap_key) != 0) {
    OPENSSL_cleanse(master_key.data(), master_key.size());
    OPENSSL_cleanse(new_pass1.data(), new_pass1.size());
    return -1;
  }
  OPENSSL_cleanse(new_pass1.data(), new_pass1.size());

  std::array<uint8_t, enc::NONCE_SIZE> new_nonce{};
  std::array<uint8_t, enc::KEY_SIZE>   new_wrapped{};
  std::array<uint8_t, enc::TAG_SIZE>   new_tag{};

  if (util::enc::fill_rand(new_nonce.data(), new_nonce.size()) != 0) {
    OPENSSL_cleanse(master_key.data(), master_key.size());
    OPENSSL_cleanse(new_wrap_key.data(), new_wrap_key.size());
    return -1;
  }

  if (enc::aesgcm_encrypt(new_wrap_key.data(), new_nonce.data(),
                          master_key.data(), enc::KEY_SIZE,
                          WRAP_AAD, sizeof(WRAP_AAD) - 1,
                          new_wrapped.data(),
                          new_tag.data()) != 0) {
    OPENSSL_cleanse(master_key.data(), master_key.size());
    OPENSSL_cleanse(new_wrap_key.data(), new_wrap_key.size());
    std::fprintf(stderr, "[leichfs] key wrap failed\n");
    return -1;
  }

  OPENSSL_cleanse(master_key.data(), master_key.size());
  OPENSSL_cleanse(new_wrap_key.data(), new_wrap_key.size());

  // Write new config 
  // Only salt, wrapped_key, nonce, tag changed.
  if (write_conf(conf_path, p,
                 new_salt.data(),
                 new_wrapped.data(),
                 new_nonce.data(),
                 new_tag.data()) != 0) {
    std::fprintf(stderr, "[leichfs] failed to write updated config\n");
    return -1;
  }

  std::fprintf(stderr, "[leichfs] passphrase changed successfully\n");
  return 0;
}

} // namespace leichfs
