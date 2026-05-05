#include "leichfs/dispatch.hpp"
#include "fs/dir.hpp"
#include "fs/io.hpp"
#include "fs/lc.hpp"
#include "fs/meta.hpp"
#include "fs/xattr.hpp"

namespace leichfs {

const fuse_operations* leichfs_ops() noexcept {
  static fuse_operations op{};  // zero-initialised; unset pointers remain nullptr

  // ── Lifecycle ──────────────────────────────────────────────────────────
  op.init    = fs::fs_init;
  op.destroy = nullptr; // FSCtx is handled by unique_ptr in main.cpp

  // ── Metadata ───────────────────────────────────────────────────────────
  op.getattr  = fs::fs_getattr;
  op.readlink = fs::fs_readlink;
  op.readdir  = fs::fs_readdir;
  op.mkdir    = fs::fs_mkdir;
  op.unlink   = fs::fs_unlink;
  op.rmdir    = fs::fs_rmdir;
  op.symlink  = fs::fs_symlink;
  op.rename   = fs::fs_rename;
  op.chmod    = fs::fs_chmod;
  op.chown    = fs::fs_chown;
  op.truncate = fs::fs_truncate;
  op.utimens  = fs::fs_utimens;
  op.statfs   = fs::fs_statfs;
  op.access   = fs::fs_access;

  // ── Extended attributes ────────────────────────────────────────────────
  op.setxattr    = fs::fs_setxattr;
  op.getxattr    = fs::fs_getxattr;
  op.listxattr   = fs::fs_listxattr;
  op.removexattr = fs::fs_removexattr;

  // ── File I/O ───────────────────────────────────────────────────────────
  op.create  = fs::fs_create;
  op.open    = fs::fs_open;
  op.read    = fs::fs_read;
  op.write   = fs::fs_write;
  op.flush   = fs::fs_flush;
  op.release = fs::fs_release;
  op.fsync   = fs::fs_fsync;
  op.lseek   = fs::fs_lseek;
  op.fallocate = fs::fs_fallocate;

  // ── Directories ────────────────────────────────────────────────────────
  op.fsyncdir = fs::fs_fsyncdir;

  // Not yet implemented (leave nullptr):
  //   mknod, link, opendir, releasedir,
  //   lock, bmap, ioctl, poll,
  //   write_buf, read_buf, flock,
  //   copy_file_range

  return &op;
}

} // namespace leichfs
