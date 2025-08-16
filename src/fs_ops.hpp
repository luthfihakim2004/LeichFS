#include <cstddef>
#include <ctime>
#include <fcntl.h>
#include <sys/types.h>
#define FUSE_USE_VERSION 35
#include <fuse3/fuse.h>
#include <string>

extern std::string g_root;

struct FSCtx{
  int rootfd;
};
static inline FSCtx* ctx(){
  return static_cast<FSCtx*>(fuse_get_context()->private_data);
}

void* gent_init(struct fuse_conn_info*, struct fuse_config*);
void gent_destroy(void*);
int gent_getattr(const char*, struct stat*, struct fuse_file_info*);
//int gent_setattr(const char*, struct stat*, struct fuse_file_info*, int); 
int gent_getxattr(const char*, const char*, char*, size_t);
int gent_setxattr(const char*, const char*, const char*, size_t, int); 
int gent_listxattr(const char*, char*, size_t);
int gent_removexattr(const char*, const char*);
int gent_readdir(const char*, void*, fuse_fill_dir_t, off_t, struct fuse_file_info*, enum fuse_readdir_flags);
int gent_open(const char*, struct fuse_file_info*);
int gent_truncate(const char*, off_t, struct fuse_file_info*);
int gent_read(const char*, char*, size_t, off_t, struct fuse_file_info*);
int gent_write(const char*, const char*, size_t, off_t, struct fuse_file_info*);
int gent_release(const char*, struct fuse_file_info*);
int gent_create(const char*, mode_t, struct fuse_file_info*);
int gent_rename(const char*, const char*, unsigned int);
int gent_flush(const char*, struct fuse_file_info*);
int gent_mkdir(const char*, mode_t);
int gent_chmod(const char*, mode_t, struct fuse_file_info*);
int gent_chown(const char*, uid_t, gid_t, struct fuse_file_info*);
int gent_utimens(const char*, const struct timespec tv[2], struct fuse_file_info*);
int gent_readlink(const char*, char*, size_t);
int gent_symlink(const char*, const char*);
int gent_fsync(const char*, int, struct fuse_file_info*);
int gent_fsyncdir(const char*, int, struct fuse_file_info*);
int gent_rmdir(const char*);
int gent_unlink(const char*);
