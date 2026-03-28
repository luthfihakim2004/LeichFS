#pragma once
#include <sys/statvfs.h>
#include <sys/types.h>
#include "fs/core.hpp"

namespace fs {

int fs_getattr  (const char*, struct stat*, struct fuse_file_info*);
int fs_readlink (const char*, char*, size_t);
int fs_readdir  (const char*, void*, fuse_fill_dir_t, off_t,
                 struct fuse_file_info*, fuse_readdir_flags);
int fs_mkdir    (const char*, mode_t);
int fs_unlink   (const char*);
int fs_rmdir    (const char*);
int fs_symlink  (const char*, const char*);
int fs_rename   (const char*, const char*, unsigned int);
int fs_chmod    (const char*, mode_t, struct fuse_file_info*);
int fs_chown    (const char*, uid_t, gid_t, struct fuse_file_info*);
int fs_truncate (const char*, off_t, struct fuse_file_info*);
int fs_utimens  (const char*, const struct timespec tv[2], struct fuse_file_info*);
int fs_statfs   (const char*, struct statvfs*);
int fs_access   (const char*, int);

} // namespace fs
