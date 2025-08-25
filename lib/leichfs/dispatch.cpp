#include "leichfs/dispatch.hpp"
#include "fs/dir.hpp"
#include "fs/io.hpp"
#include "fs/lc.hpp"
#include "fs/meta.hpp"
#include "fs/xattr.hpp"

using namespace fs;

namespace leichfs {
const fuse_operations* leichfs_ops() noexcept {
  static fuse_operations op{}; // zero-initialize

  // lifecycle
  op.init        = fs_init;
  op.destroy     = fs_destroy;

  // meta
  op.getattr     = fs_getattr;
  op.readlink    = fs_readlink;
  op.readdir     = fs_readdir;
  op.mknod       = nullptr;       // if not supported
  op.mkdir       = fs_mkdir;
  op.unlink      = fs_unlink;
  op.rmdir       = fs_rmdir;
  op.symlink     = fs_symlink;
  op.rename      = fs_rename;
  //op.link        = fs_link;
  op.chmod       = fs_chmod;
  op.chown       = fs_chown;
  op.truncate    = fs_truncate;
  op.utimens     = fs_utimens;

  // xattr
  op.setxattr    = fs_setxattr;
  op.getxattr    = fs_getxattr;
  op.listxattr   = fs_listxattr;
  op.removexattr = fs_removexattr;

  // file I/O
  op.create      = fs_create;
  op.open        = fs_open;
  op.read        = fs_read;
  op.write       = fs_write;
  op.flush       = fs_flush;
  op.release     = fs_release;
  op.fsync       = fs_fsync;

  // dirs
  //op.opendir     = fs_opendir;
  //op.releasedir  = fs_releasedir;
  op.fsyncdir    = fs_fsyncdir;

  // leave others nullptr unless implemented
  return &op;
}
} // namespace
