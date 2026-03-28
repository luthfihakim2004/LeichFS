#pragma once
#define FUSE_USE_VERSION 35
#include <fuse3/fuse.h>

namespace fs {

void* fs_init   (struct fuse_conn_info*, struct fuse_config*);
void  fs_destroy(void*);

} // namespace fs
