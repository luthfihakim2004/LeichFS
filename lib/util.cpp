#include "util.hpp"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <linux/openat2.h>
#include <pwd.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include "enc/header.hpp"
#include "enc/params.hpp"


// ────────────────────────────────────────────────────────────────────────────
// util
// ────────────────────────────────────────────────────────────────────────────
namespace util {

// Validate the requirements of the backing dir
unique_fd validate_root_path(const char* path) {
  struct open_how how{};
  how.flags   = O_PATH | O_DIRECTORY | O_CLOEXEC;
  how.resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
  int fd = static_cast<int>(::syscall(SYS_openat2, AT_FDCWD, path, &how, sizeof(how)));
  return unique_fd{fd};  // fd is -1 on failure; unique_fd::valid() reflects that
}

} // namespace util


// ────────────────────────────────────────────────────────────────────────────
// util::fs
// ────────────────────────────────────────────────────────────────────────────
namespace util::fs {

// pread() wrapper to guarantee read exactly n bytes 
ssize_t full_pread(int fd, void* buf, size_t n, off_t offset) {
  auto* p = static_cast<uint8_t*>(buf);
  size_t done = 0;
  while (done < n) {
    ssize_t r = ::pread(fd, p + done, n - done, offset + static_cast<off_t>(done));
    if (r < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    if (r == 0) break; // EOF
    done += static_cast<size_t>(r);
  }
  return static_cast<ssize_t>(done);
}

// pwrite() wrapper to guarantee write exactly n bytes 
ssize_t full_pwrite(int fd, const void* buf, size_t n, off_t offset) {
  const auto* p = static_cast<const uint8_t*>(buf);
  size_t done = 0;
  while (done < n) {
    ssize_t w = ::pwrite(fd, p + done, n - done, offset + static_cast<off_t>(done));
    if (w < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    if (w == 0) break;
    done += static_cast<size_t>(w);
  }
  return static_cast<ssize_t>(done);
}

uint64_t chunk_index(uint64_t offset, size_t chunk_sz) {
  return offset / chunk_sz;
}

size_t chunk_off(uint64_t offset, size_t chunk_sz) {
  return static_cast<size_t>(offset % chunk_sz);
}

uint64_t cipher_chunk_off(uint64_t chunk_idx, size_t chunk_sz) {
  // Header || [ NONCE | CT | TAG ] * n
  return ::enc::HEADER_SIZE
       + chunk_idx * static_cast<uint64_t>(::enc::NONCE_SIZE + chunk_sz + ::enc::TAG_SIZE);
}

uint64_t cipher_tail_off(uint64_t chunk_idx, size_t plain_tail, size_t chunk_sz) {
  return cipher_chunk_off(chunk_idx, chunk_sz)
       + static_cast<uint64_t>(::enc::NONCE_SIZE + plain_tail + ::enc::TAG_SIZE);
}

// For updating plain_len inside header safely and improve durability with fdatasync()
int update_plain_len(int fd, uint64_t new_plain_len_host) {
  static_assert(::enc::HEADER_SIZE == 64,                          "Header size unexpected");
  static_assert(offsetof(::enc::Header, plain_len_be) == 56,       "plain_len offset mismatch");

  const off_t    off = static_cast<off_t>(offsetof(::enc::Header, plain_len_be));
  const uint64_t be  = util::enc::htobe_u64(new_plain_len_host);

  if (full_pwrite(fd, &be, sizeof(be), off) != static_cast<ssize_t>(sizeof(be)))
    return -1;

  // May be expensive for write-heavy workloads
  if (::fdatasync(fd) == -1)
    return -1;

  return 0;
}

// Split an absolute FUSE path into its components, rejecting "." and "..".
static std::vector<std::string> split_components(const char* path) {
  std::vector<std::string> out;
  const char* p = path;
  if (*p == '/') ++p;
  while (*p) {
    const char* start = p;
    while (*p && *p != '/') ++p;
    if (p > start) out.emplace_back(start, p - start);
    if (*p == '/') ++p;
  }
  return out;
}

int walk_parent(int rootfd, const char* path, util::parent_path& out) {
  if (!path || !*path) return -EINVAL;

  auto parts = split_components(path);

  // Reject path traversal components.
  for (const auto& s : parts)
    if (s == "." || s == ".." || s.empty()) return -EINVAL;

  // Duplicate rootfd so we can walk without consuming it.
  int raw = ::dup(rootfd);
  if (raw == -1) return -errno;
  util::unique_fd dirfd{raw};

  // Descend through all but the last component.
  for (size_t i = 0; i + 1 < parts.size(); ++i) {
    int next = ::openat(dirfd.get(), parts[i].c_str(),
                        O_NOFOLLOW | O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (next == -1) return -errno;
    dirfd.reset(next); // closes previous, adopts new
  }

  out.dirfd = std::move(dirfd);
  out.leaf  = parts.empty() ? std::string{} : parts.back();
  return 0;
}

// Safe leaf opener for dirfd-based traversal
util::unique_fd leaf_nofollow(int dirfd, const char* name, int oflags) {
  const char* n = (name && *name) ? name : ".";
  return util::unique_fd{::openat(dirfd, n, oflags | O_CLOEXEC | O_NOFOLLOW)};
}

} // namespace util::fs


// ────────────────────────────────────────────────────────────────────────────
// util::enc
// ────────────────────────────────────────────────────────────────────────────
namespace util::enc {

// Random filler wrapper to guarantee full buffer is filled
int fill_rand(void* p, size_t n) {
  auto* out = static_cast<uint8_t*>(p);
  size_t off = 0;
  while (off < n) {
    ssize_t m = ::getrandom(out + off, n - off, 0);
    if (m < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    off += static_cast<size_t>(m);
  }
  return 0;
}

uint64_t htobe_u64(uint64_t x) noexcept {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return __builtin_bswap64(x);
#else
  return x;
#endif
}

uint32_t htobe_u32(uint32_t x) noexcept {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return __builtin_bswap32(x);
#else
  return x;
#endif
}

uint64_t be64toh_u64(uint64_t x) noexcept {
  return htobe_u64(x); // self-inverse
}

// AAD[40] layout:
// magic[8] || be32(version)[4] || be32(chunk_sz)[4] || salt[32] || be64(chunk_idx)[8]
void build_aad(std::span<uint8_t, ::enc::AAD_PREFIX_LEN + 8> out, 
               const std::array<uint8_t,
               ::enc::AAD_PREFIX_LEN>& prefix, uint64_t chunk_idx) noexcept {
  std::memcpy(out.data(), prefix.data(), ::enc::AAD_PREFIX_LEN);
  // chunk_idx in big-endian (canonical counter encoding)
  for (int i = 0; i < 8; ++i)
    out[::enc::AAD_PREFIX_LEN + i] = static_cast<uint8_t>(chunk_idx >> (56 - 8 * i));
}

int load_master_key_from_file(const char* path,
                              std::array<uint8_t, ::enc::KEY_SIZE>& out) {
  // Open with O_NOFOLLOW to refuse symlinks — a symlink attack could
  // redirect to a different key if the keyfile path is user-controlled.
  int fd = ::open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd == -1) {
    std::fprintf(stderr, "[leichfs] cannot open keyfile '%s': %s\n",
                 path, std::strerror(errno));
    return -1;
  }

  // Enforce strict permissions: keyfile must be owner-read-only (0400 or 0600).
  struct stat st{};
  if (::fstat(fd, &st) == -1 || !S_ISREG(st.st_mode)) {
    std::fprintf(stderr, "[leichfs] keyfile '%s' is not a regular file\n", path);
    ::close(fd); return -1;
  }
  if (st.st_mode & (S_IRWXG | S_IRWXO)) {
    std::fprintf(stderr,
        "[leichfs] keyfile '%s' is group/world readable — refusing (chmod 400)\n",
        path);
    ::close(fd); return -1;
  }

  // Try reading 64 hex chars first, fall back to 32 raw bytes.
  uint8_t buf[65]{};
  ssize_t n = ::read(fd, buf, sizeof(buf));
  ::close(fd);

  if (n == ::enc::KEY_SIZE) {
    // Raw binary key.
    std::memcpy(out.data(), buf, ::enc::KEY_SIZE);
    OPENSSL_cleanse(buf, sizeof(buf));
    return 0;
  }

  // Strip optional trailing newline.
  if (n == ::enc::KEY_SIZE * 2 + 1 && buf[n - 1] == '\n') --n;

  if (n == ::enc::KEY_SIZE * 2) {
    auto hex2nibble = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return 10 + c - 'a';
      if (c >= 'A' && c <= 'F') return 10 + c - 'A';
      return -1;
    };
    for (size_t i = 0; i < ::enc::KEY_SIZE; ++i) {
      int hi = hex2nibble(static_cast<char>(buf[2 * i]));
      int lo = hex2nibble(static_cast<char>(buf[2 * i + 1]));
      if (hi < 0 || lo < 0) {
        std::fprintf(stderr, "[leichfs] keyfile: invalid hex char\n");
        OPENSSL_cleanse(buf, sizeof(buf));
        return -1;
      }
      out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    OPENSSL_cleanse(buf, sizeof(buf));
    return 0;
  }

  std::fprintf(stderr,
      "[leichfs] keyfile must be 32 raw bytes or 64 hex chars (got %zd bytes)\n", n);
  OPENSSL_cleanse(buf, sizeof(buf));
  return -1;
}

int build_nonce(uint8_t nonce[::enc::NONCE_SIZE], uint64_t chunk_idx) noexcept {
  // nonce = random[8] || be32(chunk_idx & 0xFFFFFFFF)
  // Using the low 32 bits of chunk_idx is safe: a single file can hold at
  // most 2^32 * CHUNK_SIZE = 256 TiB of data before the index wraps.
  if (fill_rand(nonce, 8) != 0) return -1;
  const uint32_t idx32 = static_cast<uint32_t>(chunk_idx & 0xFFFFFFFFu);
  nonce[8]  = static_cast<uint8_t>(idx32 >> 24);
  nonce[9]  = static_cast<uint8_t>(idx32 >> 16);
  nonce[10] = static_cast<uint8_t>(idx32 >>  8);
  nonce[11] = static_cast<uint8_t>(idx32);
  return 0;
}

void build_aad_prefix(std::array<uint8_t, ::enc::AAD_PREFIX_LEN>& out,
                      const ::enc::Header& h) noexcept {
  // AAD prefix layout:
  // magic[8] || le32(version) as BE32 || le32(chunk_sz) as BE32 || salt[SALT_SIZE]
  std::memcpy(out.data(), h.magic, 8);
  const uint32_t v_be  = htobe_u32(h.version);
  const uint32_t sz_be = htobe_u32(h.chunk_sz);
  std::memcpy(out.data() +  8, &v_be,  4);
  std::memcpy(out.data() + 12, &sz_be, 4);
  std::memcpy(out.data() + 16, h.salt, ::enc::SALT_SIZE);
}

} // namespace util::enc
