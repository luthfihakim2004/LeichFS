#include <cerrno>
#include <sys/xattr.h>

#include "fs/core.hpp"
#include "fs/xattr.hpp"
#include "util.hpp"

namespace fs {

// All xattr operations follow the same shape:
//  1. walk_parent → unique_fd dirfd  (RAII)
//  2. leaf_nofollow → unique_fd fd   (RAII)
//  3. call the f*xattr syscall on fd (safer)
// Both fds are closed automatically on every exit path.

int fs_getxattr(const char* path, const char* name, char* value, size_t size) {
  util::parent_path pp;
  if (int rc = util::fs::walk_parent(ctx()->rootfd.get(), path, pp); rc != 0)
    return rc;

  util::unique_fd fd = util::fs::leaf_nofollow(
    pp.dirfd.get(), pp.leaf.empty() ? "." : pp.leaf.c_str());
  if (!fd) return -errno;

  ssize_t n = ::fgetxattr(fd.get(), name, value, size);
  return n == -1 ? -errno : static_cast<int>(n);
}

int fs_listxattr(const char* path, char* list, size_t size) {
  util::parent_path pp;
  if (int rc = util::fs::walk_parent(ctx()->rootfd.get(), path, pp); rc != 0)
    return rc;

  util::unique_fd fd = util::fs::leaf_nofollow(
      pp.dirfd.get(), pp.leaf.empty() ? "." : pp.leaf.c_str());
  if (!fd) return -errno;

  ssize_t n = ::flistxattr(fd.get(), list, size);
  return n == -1 ? -errno : static_cast<int>(n);
}

int fs_setxattr(const char* path, const char* name,
                const char* value, size_t size, int flags) {
  util::parent_path pp;
  if (int rc = util::fs::walk_parent(ctx()->rootfd.get(), path, pp); rc != 0)
    return rc;

  util::unique_fd fd = util::fs::leaf_nofollow(
    pp.dirfd.get(), pp.leaf.empty() ? "." : pp.leaf.c_str());
  if (!fd) return -errno;

  return ::fsetxattr(fd.get(), name, value, size, flags) == -1 ? -errno : 0;
}

int fs_removexattr(const char* path, const char* name) {
  util::parent_path pp;
  if (int rc = util::fs::walk_parent(ctx()->rootfd.get(), path, pp); rc != 0)
    return rc;

  util::unique_fd fd = util::fs::leaf_nofollow(
      pp.dirfd.get(), pp.leaf.empty() ? "." : pp.leaf.c_str());
  if (!fd) return -errno;

  return ::fremovexattr(fd.get(), name) == -1 ? -errno : 0;
}

} // namespace fs
