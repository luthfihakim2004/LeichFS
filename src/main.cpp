#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "util.hpp"     // util::expand_args, etc.
#include "fs/core.hpp"  // leichfs::core::FSCtx, leichfs_operations()
#include "leichfs/dispatch.hpp"

// If your destroy() frees the context (recommended), we won't double-free here.

static std::string rstrip_slash(std::string s) {
  if (s.size() > 1 && s.back() == '/') s.pop_back();
  return s;
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    std::fprintf(stderr,
      "Usage: %s <mountpoint> [FUSE opts...] --root=<dir>|--root <dir>\n", argv[0]);
    return 1;
  }

  std::string root;
  std::vector<char*> fuse_args;
  fuse_args.reserve(static_cast<size_t>(argc) + 1);
  fuse_args.push_back(argv[0]);

  // Parse args: keep normal FUSE args; extract --root
  for (int i = 1; i < argc; ++i) {
    if (std::strncmp(argv[i], "--root=", 7) == 0) {
      std::string raw = argv[i] + 7;
      root = rstrip_slash(util::expand_args(raw));
    } else if (std::strcmp(argv[i], "--root") == 0 && i + 1 < argc) {
      std::string raw = argv[++i];
      root = rstrip_slash(util::expand_args(raw));
    } else {
      fuse_args.push_back(argv[i]);
    }
  }

  if (root.empty()) {
    std::fprintf(stderr, "Missing --root\n");
    return 1;
  }

  struct stat st{};
  if (stat(root.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
    std::fprintf(stderr, "Invalid --root: '%s' is not a directory\n", root.c_str());
    return 1;
  }

  // Prepare user data for FUSE
  auto *ctx = new FSCtx{};
  ctx->rootfd = open(root.c_str(), O_PATH | O_DIRECTORY);
  if (ctx->rootfd == -1) {
    std::perror("open --root failed");
    delete ctx;
    return 1;
  }
  //ctx->root_path = root; // if your FSCtx tracks the path; otherwise remove

  fuse_args.push_back(nullptr); // fuse_main expects argv-style NUL-terminated list

  // Dispatch to lib's ops table
  const fuse_operations* ops = leichfs::leichfs_ops();
  int ret = fuse_main(static_cast<int>(fuse_args.size()) - 1, fuse_args.data(), ops, ctx);

  // If your destroy() already freed ctx, do nothing here.
  // If not, uncomment:
  // if (ctx) {
  //   if (ctx->rootfd >= 0) close(ctx->rootfd);
  //   delete ctx;
  // }

  return ret;
}
