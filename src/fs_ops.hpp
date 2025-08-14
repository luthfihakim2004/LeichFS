#include <fcntl.h>
#define FUSE_USE_VERSION 35
#include <fuse3/fuse.h>
#include <string>

extern std::string g_root;

int test_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi);
int test_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags);
int test_open(const char *path, struct fuse_file_info *fi);
int test_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
int test_release(const char *path, struct fuse_file_info *fi);
