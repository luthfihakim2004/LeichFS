#include "fs_ops.hpp"
#include "util.hpp"
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fuse3/fuse.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <pwd.h>

static struct fuse_operations gent_ops = {
  .getattr     = gent_getattr,
  .readlink    = gent_readlink,
  .mkdir       = gent_mkdir,
  .unlink      = gent_unlink,
  .rmdir       = gent_rmdir,
  .symlink     = gent_symlink,
  .rename      = gent_rename,
  .chmod       = gent_chmod,
  .chown       = gent_chown,
  .truncate    = gent_truncate,
  .open        = gent_open,
  .read        = gent_read,
  .write       = gent_write,
  .flush       = gent_flush,
  .release     = gent_release,
  .fsync       = gent_fsync,
  .setxattr    = gent_setxattr,
  .getxattr    = gent_getxattr,
  .listxattr   = gent_listxattr,
  .removexattr = gent_removexattr,
  .readdir     = gent_readdir,
  .fsyncdir    = gent_fsyncdir,
  .init        = gent_init,
  .destroy     = gent_destroy,
  .create      = gent_create,
  .utimens     = gent_utimens,
  //.link        = gent_link,
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

  auto *ctx = new FSCtx{};
  ctx->rootfd = open(root.c_str(), O_PATH | O_DIRECTORY);
  if (ctx->rootfd == -1){
    std::perror("open --root failed");
    delete ctx;
    return 1;
  }

  args.push_back(nullptr);

  int ret = fuse_main(static_cast<int>(args.size()) -1, args.data(), &gent_ops, ctx);
  if(ret != 0){
    if (ctx){
      if (ctx->rootfd >= 0) close(ctx->rootfd);
      delete ctx;
      ctx = nullptr;
    }
  }
  return ret;
}
