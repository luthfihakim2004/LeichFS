#include <cstddef>
#include <sys/types.h>

#include "fs/core.hpp"

namespace fs {

int fs_create(const char*, mode_t, struct fuse_file_info*);
int fs_open(const char*, struct fuse_file_info*);
int fs_read(const char*, char*, size_t, off_t, struct fuse_file_info*);
int fs_write(const char*, const char*, size_t, off_t, struct fuse_file_info*);
int fs_flush(const char*, struct fuse_file_info*);
int fs_release(const char*, struct fuse_file_info*);
int fs_fsync(const char*, int, struct fuse_file_info*);

}

