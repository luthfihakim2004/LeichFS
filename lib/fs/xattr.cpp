#include <sys/xattr.h>
#include <cerrno>
#include <string>

#include "fs/core.hpp"
#include "util.hpp"

using namespace util::fs;
using namespace util::enc;

namespace fs {

int fs_getxattr(const char *path, const char *name, char *value, size_t size){
  int pdir; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, pdir, leaf);
  if (rc) return rc;

  int fd = leaf_nofollow(pdir, leaf.empty() ? "." : leaf.c_str());
  close(pdir);
  if (fd == -1) return -errno;

  ssize_t n = fgetxattr(fd, name, value, size);
  close(fd);
  return n == -1 ? -errno : static_cast<int>(n);
}

int fs_listxattr(const char *path, char *list, size_t size){
  int pdir; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, pdir, leaf);
  if (rc) return rc;

  int fd = leaf_nofollow(pdir, leaf.empty() ? "." : leaf.c_str());
  close(pdir);
  if (fd == -1) return -errno;

  ssize_t n = flistxattr(fd, list, size);
  close(fd);
  return n == -1 ? -errno : static_cast<int>(n);
}

int fs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags){
  int pdir; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, pdir, leaf);
  if (rc) return rc;

  int fd = leaf_nofollow(pdir, leaf.empty() ? "." : leaf.c_str());
  close(pdir);
  if (fd == -1) return -errno;

  ssize_t n = fsetxattr(fd, name, value, size, flags);
  close(fd);
  return n == -1 ? -errno : static_cast<int>(n);
}

int fs_removexattr(const char *path, const char *name){
  int pdir; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, pdir, leaf);
  if (rc) return rc;

  int fd = leaf_nofollow(pdir, leaf.empty() ? "." : leaf.c_str());
  close(pdir);
  if (fd == -1) return -errno;

  ssize_t n = fremovexattr(fd, name);
  close(fd);
  return n == -1 ? -errno : static_cast<int>(n);
}


}

