#include <unistd.h>

#include "fs/core.hpp"

namespace fs {

void* fs_init(struct fuse_conn_info *conn, struct fuse_config *cfg){
  (void)conn;
  cfg->kernel_cache = 1;
  cfg->use_ino = 1;
  return fuse_get_context()->private_data;
}

void fs_destroy(void *data){
  auto* c = static_cast<FSCtx*>(data);
  if (c){
    if (c->rootfd >= 0) close(c->rootfd);
    delete c;
  }
}

}

