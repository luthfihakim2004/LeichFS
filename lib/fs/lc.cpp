#include "fs/core.hpp"
#include "fs/lc.hpp"

namespace fs {

void* fs_init(struct fuse_conn_info* conn, struct fuse_config* cfg) {
  // default_permissions: let the kernel enforce uid/gid/mode checks using
  // the stat results from fs_getattr.  This is the correct approach for a
  // passthrough-style filesystem so no need to reimplement access() logic.
  cfg->kernel_cache     = 1;
  cfg->attr_timeout     = 1.0;
  cfg->entry_timeout    = 1.0;
  cfg->negative_timeout = 1.0;
  cfg->use_ino          = 1;
  //for benchmarking
  // note that since FUSE 3.+ big_writes is enabled by default
  cfg->direct_io        = 0;
  conn->want            |= FUSE_CAP_WRITEBACK_CACHE | FUSE_CAP_ASYNC_READ;
  return fuse_get_context()->private_data;
}

void fs_destroy(void* data) {
  // Don't destroy, destructor handled by unique_ptr
}

} // namespace fs
