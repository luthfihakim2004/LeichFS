#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <pwd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <fuse3/fuse.h>

#include "leichfs/util.hpp"        // ctx(), FSCtx, fsutil::expand_args
#include "leichfs/fs/ops_meta.hpp" // gent_init/gent_destroy need ctx()
#include "fuse/dispatch.cpp"     // gent_operations()
#include "leichfs/fs/core.hpp"

// Expose g_root if you still use it elsewhere; or remove if no longer needed.
extern std::string g_root;

int main(int argc, char* argv[]) {
  if (argc < 3){
    std::fprintf(stderr, "Usage: %s <mountpoint> --root=<dir>\n", argv[0]);
    return 1;
  }

  std::string root;
  std::vector<char*> args;
  args.push_back(argv[0]);

  for (int i = 1; i < argc; ++i){
    if (std::strncmp(argv[i], "--root=", 7) == 0){
      std::string raw = argv[i] + 7;
      root = fsutil::expand_args(raw);
      if (root.size() > 1 && root.back() == '/') root.pop_back();
    } else if (std::strcmp(argv[i], "--root") == 0 && i + 1 < argc){
      std::string raw = argv[++i];
      root = fsutil::expand_args(raw);
      if (root.size() > 1 && root.back() == '/') root.pop_back();
    } else {
      args.push_back(argv[i]);
    }
  }

  if (root.empty()){
    std::fprintf(stderr, "Missing arguments\n");
    return 1;
  }

  struct stat st{};
  if (stat(root.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)){
    std::fprintf(stderr, "Invalid --root: '%s' is not a directory\n", root.c_str());
    return 1;
  }

  g_root = root; // keep if used elsewhere

  auto *c = new leichfs::core::FSCtx{};
  c->rootfd = open(root.c_str(), O_PATH | O_DIRECTORY);
  if (c->rootfd == -1){
    std::perror("open --root failed");
    delete c;
    return 1;
  }

  args.push_back(nullptr);

  const fuse_operations& ops = leichfs_operations();
  int ret = fuse_main(static_cast<int>(args.size()) - 1, args.data(), &ops, c);

  if (ret != 0) {
    if (c){
      if (c->rootfd >= 0) close(c->rootfd);
      delete c;
      c = nullptr;
    }
  }
  return ret;
}
