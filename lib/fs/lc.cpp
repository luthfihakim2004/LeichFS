#include "fs/core.hpp"
#include "fs/lc.hpp"

namespace fs {

void* fs_init(struct fuse_conn_info* /*conn*/, struct fuse_config* cfg) {
  // default_permissions: let the kernel enforce uid/gid/mode checks using
  // the stat results from fs_getattr.  This is the correct approach for a
  // passthrough-style filesystem so no need to reimplement access() logic.
  cfg->kernel_cache     = 1;
  cfg->attr_timeout     = 1.0;
  cfg->entry_timeout    = 1.0;
  cfg->negative_timeout = 1.0;
  cfg->use_ino          = 1;
  return fuse_get_context()->private_data;
}

void fs_destroy(void* data) {
  // FSCtx owns rootfd via unique_fd — destructor closes it automatically.
  delete static_cast<FSCtx*>(data);
}

} // namespace fs
