#include "fs_ops.hpp"
#include "util.hpp"
#include <cstdio>
#include <cstring>
#include <fuse3/fuse.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <pwd.h>

static struct fuse_operations test_ops = {
  .getattr = test_getattr,
  .open    = test_open,
  .read    = test_read,
  .release = test_release,
  .readdir = test_readdir,
};

int main(int argc, char* argv[]) {
  if (argc < 3){
    fprintf(stderr, "Usage: %s <mountpoint> --root=<dir>\n", argv[0]);
    return 1;
  }

  std::string root;
  std::vector<char*> args;
  args.push_back(argv[0]);

  for (int i = 1; i < argc; ++i){
    if (strncmp(argv[i], "--root=", 7) == 0){
      std::string raw = argv[i] + 7;
      root = fsutil::expand_args(raw);

      if (root.size() > 1 && root.back() == '/') root.pop_back();
    } else if (std::strcmp(argv[i], "--root") == 0 && i + 1 < argc){
      std::string raw = argv[++i];
      root = fsutil::expand_args(raw);
      if (root.size() > 1 && root.back() == '/') root.pop_back();
    }
    else args.push_back(argv[i]);
  }

  if (root.empty()){
    fprintf(stderr, "Missing arguments");
    return 1;
  }

  struct stat st{};
  if (stat(root.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)){
    std::fprintf(stderr, "Invalid --root: '%s' is not a directory\n", root.c_str());
    return 1;
  }

  g_root = root;

  int ret = fuse_main(static_cast<int>(args.size()), args.data(), &test_ops, nullptr);
  return ret;
}
