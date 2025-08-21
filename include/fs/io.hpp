#include <cstddef>
#include <sys/types.h>

#include "fs/core.hpp"

namespace fs {

int gent_create(const char*, mode_t, struct fuse_file_info*);
int gent_open(const char*, struct fuse_file_info*);
int gent_read(const char*, char*, size_t, off_t, struct fuse_file_info*);
int gent_write(const char*, const char*, size_t, off_t, struct fuse_file_info*);
int gent_flush(const char*, struct fuse_file_info*);
int gent_release(const char*, struct fuse_file_info*);
int gent_fsync(const char*, int, struct fuse_file_info*);

}

