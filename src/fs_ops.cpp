#include "fs_ops.hpp"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <fcntl.h>
#include <fuse3/fuse.h>
#include <string>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <fuse_lowlevel.h>

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0)
#endif // !RENAME_NOREPLACE
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1U << 1)
#endif // !RENAME_EXCHANGE

std::string g_root;

static_assert(sizeof(off_t) == 8, "off_t must be 64 bit");

static void resolve_path(const char* in, std::string& out){
  if (!in || !*in) { out = g_root; return; }
  if (in[0] == '/')
    out = g_root + in;
  else
    out = g_root + "/" + in;
}

int gent_getattr(const char *path, struct stat *st, struct fuse_file_info *fi) {
  (void)fi;
  memset(st, 0, sizeof(*st));

  std::string real;
  resolve_path(path, real);

  if(lstat(real.c_str(), st) == -1)
    return -errno;
  return 0;
}

int gent_setattr(const char *path, struct stat *st, struct fuse_file_info *fi, int to) {
  if (to & FUSE_SET_ATTR_SIZE){
    off_t size = st->st_size;
    if(fi && fi->fh){
      int fd = static_cast<int>(fi->fh);
      return (ftruncate(fd, size) == -1) ? -errno : 0;
    } else {
      std::string real; resolve_path(path, real);
      if(truncate(real.c_str(), size) == -1) return -errno;
    }

    return -ENOSYS;
  }

  return 0;
}

int gent_getxattr(const char *path, const char *name, char *value, size_t size){
  std::string real;
  resolve_path(path, real);

  ssize_t n = lgetxattr(real.c_str(), name, value, size);
  return (n == -1) ? -errno : static_cast<int>(n);
}

int gent_listxattr(const char *path, char *list, size_t size){
  std::string real;
  resolve_path(path, real);

  ssize_t n = llistxattr(real.c_str(), list, size);
  return (n == -1) ? -errno : static_cast<int>(n);
}

int gent_setxattr(const char *path, const char *name, const char *value, size_t size, int flags){
  std::string real;
  resolve_path(path, real);
  return (lsetxattr(real.c_str(), name, value, size, flags) == -1) ? -errno : 0;
}

int gent_removexattr(const char *path, const char *name){
  std::string real;
  resolve_path(path, real);
  return (lremovexattr(real.c_str(), name) == -1) ? -errno : 0;
}

int gent_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t off, struct fuse_file_info *fi, enum fuse_readdir_flags) {
  (void)off;
  (void)fi;
  
  std::string real;
  resolve_path(path, real);

  DIR* dp = opendir(real.c_str());
  if (!dp) return -errno;

  filler(buf, ".", nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
  filler(buf, "..", nullptr, 0, static_cast<fuse_fill_dir_flags>(0));

  errno = 0;
  while(auto *de = readdir(dp)){
    struct stat st {};
    std::string child = real + "/" + de->d_name;
    if (lstat(child.c_str(), &st) == -1) continue;
    if (filler(buf, de->d_name, nullptr, 0, static_cast<fuse_fill_dir_flags>(0))){ closedir(dp); return 0; }
  }
  int e = errno;
  closedir(dp);
  return e ? -e : 0;
}

int gent_open(const char *path, struct fuse_file_info *fi) {
  std::string real;
  resolve_path(path, real);

  int oflags =(fi->flags & ~O_CREAT); 
  int fd = open(real.c_str(), oflags | O_CLOEXEC | O_NOFOLLOW );
  if (fd == -1) return -errno;

  // Verification policies
  struct stat st{};
  if (fstat(fd, &st) == -1){ 
    int e = errno;
    close(fd);
    return -e;
  }
  if (!S_ISREG(st.st_mode)){
    close(fd);
    return -EISDIR;
  }

  fi->fh = static_cast<uint64_t>(fd);
  return 0;
}

int gent_create(const char *path, mode_t mode, struct fuse_file_info *fi){
  std::string real;
  resolve_path(path, real);

  int fd = open(real.c_str(),
                (fi->flags | O_CREAT) | O_CLOEXEC | O_NOFOLLOW, mode);
  
  struct stat st{};
  if (fstat(fd, &st) == -1){
    int e = errno;
    close(fd);
    return -e;
  }
  if (!S_ISREG(st.st_mode)){
    close(fd);
    return -EISDIR;
  }

  fi->fh = static_cast<uint64_t>(fd);
  return 0;
}

int gent_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
  (void)path;

  int fd = static_cast<int>(fi->fh);

  for (;;){
    ssize_t n = pwrite(fd, buf, size, offset);
    if (n == -1 && errno == EINTR) continue;
    if (n == -1) return -errno;
    return static_cast<int>(n);
  }
}

int gent_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  (void)path;

  int fd = static_cast<int>(fi->fh);
  for (;;){
    ssize_t res = pread(fd, buf, size, offset);
    if (res == -1 && errno == EINTR) continue;
    if (res == -1) return -errno;
    return static_cast<int>(res);
  }
}

int gent_release(const char *path, struct fuse_file_info *fi){
  (void)path;
  int fd = static_cast<int>(fi->fh);
  if(close(fd) == -1) return -errno;
  return 0;
}

int gent_truncate(const char *path, off_t size, struct fuse_file_info *fi){
  if (fi && fi->fh){
    int fd = static_cast<int>(fi->fh);
    return (ftruncate(fd, size) == -1) ? -errno : 0;
  }

  std::string real;
  resolve_path(path, real);

  return (truncate(real.c_str(),size) == -1) ? -errno : 0;
}

int gent_rename(const char *from, const char *to, unsigned int flags){
  std::string rfrom, rto;
  resolve_path(from, rfrom);
  resolve_path(to, rto);

#if defined (__linux__) && defined (RENAME_NOREPLACE)
  if (flags != 0){
    int rc = syscall(SYS_renameat2, AT_FDCWD, rfrom.c_str(), AT_FDCWD, rto.c_str(), static_cast<unsigned int>(flags));
    if (rc == -1) return -errno;
    return 0;
  }
#endif

  if (flags == 0){
    if(rename(rfrom.c_str(), rto.c_str()) == -1) return -errno;
    return 0;
  }

  return -ENOTSUP;
}

int gent_unlink(const char *path){
  std::string real; resolve_path(path, real);
  if (unlink(real.c_str()) == -1) return -errno;
  return 0;
}

int gent_mkdir(const char *path, mode_t mode){
  std::string real; resolve_path(path, real);
  if (mkdir(real.c_str(), mode) == -1) return -errno;
  return 0;
}

int gent_rmdir(const char *path){
  std::string real; resolve_path(path, real);
  if (rmdir(real.c_str()) == -1) return -errno;
  return 0;
}

int gent_flush(const char *path, struct fuse_file_info *fi){
  (void)path;
  return 0;
}

int gent_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi){
  std::string real;
  resolve_path(path, real);
  return (lchown(real.c_str(), uid, gid) == -1) ? -errno : 0;
}

int gent_chmod(const char *path, mode_t mode, struct fuse_file_info *fi){
  std::string real;
  resolve_path(path, real);
  return (chmod(real.c_str(), mode) == -1) ? -errno : 0;
}

int gent_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi){
  std::string real;
  resolve_path(path, real);
  return (utimensat(AT_FDCWD, real.c_str(), tv, AT_SYMLINK_NOFOLLOW) == -1) ? -errno : 0;
}
