#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include <filesystem>

#include "fs/core.hpp"
#include "leichfs/dispatch.hpp"
#include "leichfs/init.hpp"
#include "util.hpp"

static void usage(const char* prog) {
  std::fprintf(stderr,
    "Usage:\n"
    "  %s --init <backing-dir>          initialise a new encrypted directory\n"
    "  %s --change-passphrase <backing-dir>  change the mount passphrase\n"
    "  %s <backing-dir> <mountpoint>    mount an encrypted directory\n"
    "\n"
    "Mount options:\n"
    "  --key=<file>    override: load master key from a raw/hex keyfile\n"
    "  --key-fd=<n>    override: read master key from file descriptor n\n"
    "  If neither is given, leichfs reads the passphrase from the terminal\n"
    "  and derives the key from %s in the backing directory.\n"
    "\n"
    "  Any remaining arguments are passed through to FUSE (e.g. -f, -d).\n",
    prog, prog, prog, leichfs::CONF_FILENAME);
}

int main(int argc, char* argv[]) {
  if (argc < 2) { usage(argv[0]); return 1; }

  // ── --init mode ───────────────────────────────────────────────────────
  if (std::strcmp(argv[1], "--init") == 0) {
    if (argc < 3) {
      std::fprintf(stderr, "leichfs: --init requires a backing directory\n");
      usage(argv[0]);
      return 1;
    }
    std::filesystem::path dir = std::filesystem::path(argv[2]);

    leichfs::Argon2Params kdf{};
    for (int i = 3; i < argc; ++i) {
      if (std::strncmp(argv[i], "--argon2-m=", 11) == 0)
        kdf.m_cost = static_cast<uint32_t>(std::atoi(argv[i] + 11));
      else if (std::strncmp(argv[i], "--argon2-t=", 11) == 0)
        kdf.t_cost = static_cast<uint32_t>(std::atoi(argv[i] + 11));
    }

    return leichfs::leichfs_init(dir.c_str(), kdf) == 0 ? 0 : 1;
  }

  // ── --change-passphrase mode ──────────────────────────────────────────
  if (std::strcmp(argv[1], "--change-passphrase") == 0) {
    if (argc < 3) {
      std::fprintf(stderr,
                   "leichfs: --change-passphrase requires a backing directory\n");
      usage(argv[0]);
      return 1;
    }
    std::filesystem::path dir = std::filesystem::path(argv[2]);
    return leichfs::leichfs_change_passphrase(dir.c_str()) == 0 ? 0 : 1;
  }


  // ── Mount mode ────────────────────────────────────────────────────────
  if (argc < 3) { usage(argv[0]); return 1; }

  std::filesystem::path backing    = std::filesystem::path(argv[1]);
  std::string           mountpoint = argv[2];
  std::string           keyfile;
  int                   key_fd     = -1;
  std::vector<char*>    fuse_argv;
  fuse_argv.reserve(static_cast<size_t>(argc));
  fuse_argv.push_back(argv[0]);
  fuse_argv.push_back(argv[2]);

  for (int i = 3; i < argc; ++i) {
    if (std::strncmp(argv[i], "--key=", 6) == 0)
      keyfile = argv[i] + 6;
    else if (std::strcmp(argv[i], "--key") == 0 && i + 1 < argc)
      keyfile = argv[++i];
    else if (std::strncmp(argv[i], "--key-fd=", 9) == 0)
      key_fd = std::atoi(argv[i] + 9);
    else
      fuse_argv.push_back(argv[i]);
  }

  util::unique_fd rootfd = util::validate_root_path(backing.c_str());
  if (!rootfd) { std::perror("leichfs: open backing dir"); return 1; }

  auto fuse_ctx    = std::make_unique<fs::FSCtx>();
  fuse_ctx->rootfd = std::move(rootfd);

  int key_rc = -1;

  // If user specify the keyfile, it's considered still safe
  // since the process runs with user's privileges
  if (!keyfile.empty()) {
    key_rc = util::enc::load_master_key_from_file(keyfile.c_str(),
                                                  fuse_ctx->master_key.raw());
  } else if (key_fd >= 0) {
    char fdpath[64];
    std::snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", key_fd);
    key_rc = util::enc::load_master_key_from_file(fdpath,
                                                  fuse_ctx->master_key.raw());
    ::close(key_fd);
  } else {
    std::filesystem::path conf = backing / leichfs::CONF_FILENAME;
    if (::access(conf.c_str(), F_OK) == 0) {
      key_rc = leichfs::load_master_key_from_conf(backing.c_str(),
                                                  fuse_ctx->master_key.raw());
    } else {
      std::fprintf(stderr,
                  "leichfs: '%s' has not been initialised.\n"
                  "  Run: %s --init %s\n",
                  backing.c_str(), argv[0], backing.c_str());
      return 1;
    }
  }

  if (key_rc != 0) return 1;

  fuse_argv.push_back(const_cast<char*>("-o"));
  fuse_argv.push_back(const_cast<char*>("default_permissions"));
  fuse_argv.push_back(nullptr);

  const fuse_operations* ops = leichfs::leichfs_ops();
  return ::fuse_main(static_cast<int>(fuse_argv.size()) - 1,
                     fuse_argv.data(), ops, fuse_ctx.get());
}
