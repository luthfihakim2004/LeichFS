#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "util.hpp"     
#include "fs/core.hpp"  
#include "leichfs/dispatch.hpp"

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

  if (root.empty()) {
    std::fprintf(stderr, "Missing --root\n");
    return 1;
  }
  
  // Parse args: keep normal FUSE args; extract --root
  int i = 1;
  while (i < argc) {
    if (std::strncmp(argv[i], "--root=", 7) == 0) {
      std::string raw = argv[i] + 7;
      root = rstrip_slash(util::expand_args(raw));
      ++i;
    } else if (std::strcmp(argv[i], "--root") == 0 && i + 1 < argc) {
      std::string raw = argv[i + 1];
      root = rstrip_slash(util::expand_args(raw));
      i += 2;
    } else {
      fuse_args.push_back(argv[i]);
      ++i;
    }
  }

  struct stat lst{};
  if (lstat(root.c_str(), &lst) != 0 || !S_ISDIR(lst.st_mode)) {
    std::fprintf(stderr, "Invalid --root: '%s' is not a directory\n", root.c_str());
    return 1;
  }
  if (S_ISLNK(lst.st_mode)) {
    std::fprintf(stderr, "Refusing symlink for --root: '%s'\n", root.c_str());
    return 1;
  }

  // Prepare FUSE Context 
  auto *ctx = new FSCtx{};
  ctx->rootfd = util::validate_path(root.c_str());
  if (ctx->rootfd == -1) {
    std::perror("open --root failed");
    delete ctx;
    return 1;
  }

  fuse_args.push_back(nullptr); // fuse_main expects argv-style NUL-terminated list

  // Dispatch to lib's ops table
  const fuse_operations* ops = leichfs::leichfs_ops();
  int ret = fuse_main(static_cast<int>(fuse_args.size()) - 1, fuse_args.data(), ops, ctx);

  return ret;
}
