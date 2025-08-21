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
  op.init        = gent_init;
  op.destroy     = gent_destroy;

  // meta
  op.getattr     = gent_getattr;
  op.readlink    = gent_readlink;
  op.readdir     = gent_readdir;
  op.mknod       = nullptr;       // if not supported
  op.mkdir       = gent_mkdir;
  op.unlink      = gent_unlink;
  op.rmdir       = gent_rmdir;
  op.symlink     = gent_symlink;
  op.rename      = gent_rename;
  //op.link        = gent_link;
  op.chmod       = gent_chmod;
  op.chown       = gent_chown;
  op.truncate    = gent_truncate;
  op.utimens     = gent_utimens;

  // xattr
  op.setxattr    = gent_setxattr;
  op.getxattr    = gent_getxattr;
  op.listxattr   = gent_listxattr;
  op.removexattr = gent_removexattr;

  // file I/O
  op.create      = gent_create;
  op.open        = gent_open;
  op.read        = gent_read;
  op.write       = gent_write;
  op.flush       = gent_flush;
  op.release     = gent_release;
  op.fsync       = gent_fsync;

  // dirs
  //op.opendir     = gent_opendir;
  //op.releasedir  = gent_releasedir;
  op.fsyncdir    = gent_fsyncdir;

  // leave others nullptr unless implemented
  return &op;
}
} // namespace
