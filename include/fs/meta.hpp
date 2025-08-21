#include <cstddef>
#include <sys/types.h>

#include "fs/core.hpp"

namespace fs {

int gent_getattr(const char*, struct stat*, struct fuse_file_info*);
//int gent_setattr(const char*, struct stat*, struct fuse_file_info*, int); 

int gent_readlink(const char*, char*, size_t);
int gent_readdir(const char*, void*, fuse_fill_dir_t, off_t, struct fuse_file_info*, enum fuse_readdir_flags);
int gent_mkdir(const char*, mode_t);
int gent_unlink(const char*);
int gent_rmdir(const char*);
int gent_symlink(const char*, const char*);
int gent_rename(const char*, const char*, unsigned int);
int gent_chmod(const char*, mode_t, struct fuse_file_info*);
int gent_chown(const char*, uid_t, gid_t, struct fuse_file_info*);
int gent_truncate(const char*, off_t, struct fuse_file_info*);
int gent_utimens(const char*, const struct timespec tv[2], struct fuse_file_info*);

}

