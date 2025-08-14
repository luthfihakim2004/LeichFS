#include "fs_ops.hpp"
#include <cstdint>
#include <cstring>
#include <cerrno>
#include <fcntl.h>
#include <fuse3/fuse.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>

std::string g_root;

static void resolve_path(const char* in, std::string& out){
  if (in[0] == '/')
    out = g_root + in;
  else
    out = g_root + "/" + in;
}

int test_getattr(const char *path, struct stat *st, struct fuse_file_info *fi) {
  (void)fi;
  memset(st, 0, sizeof(*st));

  std::string real;
  resolve_path(path, real);

  if(lstat(real.c_str(), st) == -1)
    return -errno;
  return 0;
}

int test_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t off, struct fuse_file_info *fi, enum fuse_readdir_flags) {
  (void)off;
  (void)fi;
  
  std::string real;
  resolve_path(path, real);

  DIR* dp = opendir(real.c_str());
  if (!dp) return -errno;

  filler(buf, ".", nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
  filler(buf, "..", nullptr, 0, static_cast<fuse_fill_dir_flags>(0));

  struct dirent* de;
  while((de = readdir(dp)) != nullptr){
    struct stat st {};
    st.st_ino = de->d_ino;
    st.st_mode = de->d_type << 12;
    filler(buf, de->d_name, &st, 0, static_cast<fuse_fill_dir_flags>(0));
  }
  closedir(dp);
  return 0;
}

int test_open(const char *path, struct fuse_file_info *fi) {
  std::string real;
  resolve_path(path, real);

  int flags = 0;
  if ((fi->flags & O_ACCMODE) == O_RDONLY) flags = O_RDONLY;
  else if ((fi->flags & O_ACCMODE) == O_WRONLY) flags = O_WRONLY;
  else flags = O_RDWR;

  int fd = open(real.c_str(), flags);
  if (fd == -1) return -errno;

  fi->fh = static_cast<uint64_t>(fd);
  return 0;
}

int test_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  (void)path;

  int fd = static_cast<int>(fi->fh);
  ssize_t res = pread(fd, buf, size, offset);
  if(res == -1) return -errno;

  return static_cast<int>(size);
}

int test_release(const char *path, struct fuse_file_info *fi){
  (void)path;
  int fd = static_cast<int>(fi->fh);
  close(fd);
  return 0;
}
