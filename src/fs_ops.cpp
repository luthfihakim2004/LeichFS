#include "fs_ops.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <fcntl.h>
#include <fuse3/fuse.h>
#include <limits.h>
#include <string>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <fuse_lowlevel.h>
#include <vector>

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0)
#endif // !RENAME_NOREPLACE
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1U << 1)
#endif // !RENAME_EXCHANGE
std::string g_root;

static_assert(sizeof(off_t) == 8, "off_t must be 64-bit");

static void resolve_path(const char* in, std::string& out){
  if (!in || !*in) { out = g_root; return; }
  if (in[0] == '/')
    out = g_root + in;
  else
    out = g_root + "/" + in;
}

static std::vector<std::string> split_components(const char *path){
  std::vector<std::string> out;
  const char *p = path;
  if(*p == '/') ++p;
  while (*p){
    const char *start = p;
    while (*p && *p != '/') ++p;
    if (p > start) out.emplace_back(start, p - start);
    if (*p == '/') ++p;
  }
  return out;
}

static int walk_parent(int rootfd, const char *path, int &out_dirfd, std::string &leaf){
  if (!path || !*path) return -EINVAL;

  auto parts = split_components(path);
  if (parts.empty()){
    out_dirfd = dup(rootfd);
    if (out_dirfd == -1) return -errno;
    leaf.clear();
    return 0;
  }

  for (auto &s : parts){
    if (s == "." || s == ".." || s.empty()) return -EINVAL;
  }

  int dirfd = dup(rootfd);
  if (dirfd == -1) return -errno;

  for (size_t i = 0; i + 1 < parts.size(); ++i){
    int next = openat(dirfd, parts[i].c_str(), O_NOFOLLOW | O_PATH | O_DIRECTORY);
    if (next == -1){
      close(dirfd);
      return -errno;
    }
    close(dirfd);
    dirfd = next;
  }

  out_dirfd = dirfd;
  leaf = parts.back();
  return 0;
}

static int leaf_nofollow(int dirfd, const char *name, int oflags = O_RDONLY){
  return openat(dirfd, (name && *name) ? name : ".", oflags | O_CLOEXEC | O_NOFOLLOW);
}

void* gent_init(struct fuse_conn_info *conn, struct fuse_config *cfg){
  (void)conn;
  cfg->kernel_cache = 0;
  return fuse_get_context()->private_data;
}

void gent_destroy(void *data){
  auto* c = static_cast<FSCtx*>(data);
  if (c){
    if (c->rootfd >= 0) close(c->rootfd);
    delete c;
  }
}

int gent_getattr(const char *path, struct stat *st, struct fuse_file_info *fi) {
  (void)fi;
  memset(st, 0, sizeof(*st));

  int pdir; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, pdir, leaf);
  if (rc != 0) return rc;

  const char *item = leaf.empty() ? "." : leaf.c_str();
  int ok = fstatat(pdir, item, st, AT_SYMLINK_NOFOLLOW);
  close(pdir);
  return ok == 1 ? -errno : 0;
}

int gent_getxattr(const char *path, const char *name, char *value, size_t size){
  int pdir; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, pdir, leaf);
  if (rc) return rc;

  int fd = leaf_nofollow(pdir, leaf.empty() ? "." : leaf.c_str());
  close(pdir);
  if (fd == -1) return -errno;

  ssize_t n = fgetxattr(fd, name, value, size);
  close(fd);
  return n == -1 ? -errno : static_cast<int>(n);
}

int gent_listxattr(const char *path, char *list, size_t size){
  int pdir; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, pdir, leaf);
  if (rc) return rc;

  int fd = leaf_nofollow(pdir, leaf.empty() ? "." : leaf.c_str());
  close(pdir);
  if (fd == -1) return -errno;

  ssize_t n = flistxattr(fd, list, size);
  close(fd);
  return n == -1 ? -errno : static_cast<int>(n);
}

int gent_setxattr(const char *path, const char *name, const char *value, size_t size, int flags){
  int pdir; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, pdir, leaf);
  if (rc) return rc;

  int fd = leaf_nofollow(pdir, leaf.empty() ? "." : leaf.c_str());
  close(pdir);
  if (fd == -1) return -errno;

  ssize_t n = fsetxattr(fd, name, value, size, flags);
  close(fd);
  return n == -1 ? -errno : static_cast<int>(n);
}

int gent_removexattr(const char *path, const char *name){
  int pdir; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, pdir, leaf);
  if (rc) return rc;

  int fd = leaf_nofollow(pdir, leaf.empty() ? "." : leaf.c_str());
  close(pdir);
  if (fd == -1) return -errno;

  ssize_t n = fremovexattr(fd, name);
  close(fd);
  return n == -1 ? -errno : static_cast<int>(n);
}

int gent_symlink(const char *to, const char *from){
  int dirfd; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, from, dirfd, leaf);
  if (rc != 0) return rc;

  int ok = symlinkat(to, dirfd, leaf.c_str());
  close(dirfd);
  return ok == -1 ? -errno : 0;
}

int gent_readlink(const char *path, char *buf, size_t size){
  int dirfd; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, dirfd, leaf);
  if (rc != 0) return rc;

  char tmp[PATH_MAX];
  ssize_t n = readlinkat(dirfd, leaf.c_str(), tmp, sizeof(tmp) - 1);
  close(dirfd);
  if (n == -1) return -errno;
  tmp[n] = '\0';

  if (size == 0) return 0;
  size_t to_cp = std::min<size_t>(n, size -1);
  memcpy(buf, tmp, to_cp);
  buf[to_cp] = '\0';
  return 0;
}

int gent_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t off, struct fuse_file_info *fi, enum fuse_readdir_flags) {
  (void)off; (void)fi;

  int pdirfd; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, pdirfd, leaf);
  if (rc != 0) return rc;

  const char *item = leaf.empty() ? "." : leaf.c_str();
  int dfd = openat(pdirfd, item, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  int saved = errno;
  close(pdirfd);
  if (dfd == -1) return -saved;

  DIR *dp = fdopendir(dfd);
  if (!dp) {
    int e = errno;
    close(dfd);
    return -e;
  }

  filler(buf, ".", nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
  filler(buf, "..", nullptr, 0, static_cast<fuse_fill_dir_flags>(0));

  errno = 0;
  for (;;){
    struct dirent *de = readdir(dp);
    if (!de) break;

    struct stat st{};
    bool has_stat = false;

    st.st_ino = de->d_ino;
    switch (de->d_type) {
      case DT_REG: st.st_mode = S_IFREG; has_stat = true; break;
      case DT_DIR: st.st_mode = S_IFDIR; has_stat = true; break;
      case DT_LNK: st.st_mode = S_IFLNK; has_stat = true; break;
      case DT_CHR: st.st_mode = S_IFCHR; has_stat = true; break;
      case DT_BLK: st.st_mode = S_IFBLK; has_stat = true; break;
      case DT_FIFO: st.st_mode = S_IFIFO; has_stat = true; break;
      case DT_SOCK: st.st_mode = S_IFSOCK; has_stat = true; break;
      case DT_UNKNOWN:
      default:
      if (fstatat(dfd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0) { has_stat = true; }
      else {
          if (errno == ENOENT){ continue; }
          else { has_stat = false; }
        }
      break;
    }

    if (filler(buf, de->d_name, has_stat ? &st : nullptr, 0, static_cast<fuse_fill_dir_flags>(0))){
      closedir(dp);
      return 0;
    }
  }

  int e = errno;
  closedir(dp);
  return e ? -e : 0;
}

int gent_open(const char *path, struct fuse_file_info *fi) {
  int dirfd; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, dirfd, leaf);
  if (rc != 0) return rc;

  // Pre check
  struct stat lst{};
  if (fstatat(dirfd, leaf.c_str(), &lst, AT_SYMLINK_NOFOLLOW) == -1) {
    close(dirfd); 
    return -errno;
  }
  if (S_ISLNK(lst.st_mode)) {
    close(dirfd);
    return -ELOOP;
  }

  // Open
  int oflags =(fi->flags & ~O_CREAT); 
  int fd = openat(dirfd, leaf.c_str(), oflags | O_CLOEXEC | O_NOFOLLOW );
  int saved = errno;
  close(dirfd);
  if (fd == -1) return -saved;
  if (fi->flags & O_TRUNC) ftruncate(fd, 0);

  // Verification n policies
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
  int dirfd; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, dirfd, leaf);
  if (rc != 0) return rc;

  int fd = openat(dirfd, leaf.c_str(),
                (fi->flags | O_CREAT) | O_CLOEXEC | O_NOFOLLOW, mode);
  int saved = errno;
  close(dirfd);
  if(fd == -1) return -saved;

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
  size_t total = 0;

  while (total < size){
    ssize_t n = (fi->flags & O_APPEND) ?
      write(fd, buf + total, size - total) :
      pwrite(fd, buf + total, size - total, offset + total);
    if (n == -1){if (errno == EINTR) continue; return -errno;} 
    if (n == 0) break;;
    total += static_cast<size_t>(n);
  }
  return static_cast<int>(total);
}

// Check for looping as same as write
int gent_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  (void)path;
  int fd = static_cast<int>(fi->fh);
  size_t total = 0;

  while (total < size){
    ssize_t n = pread(fd, buf + total, size - total, offset + total);
    if (n == -1){ if (errno == EINTR) continue; return -errno;}
    if (n == 0) break;
    total += static_cast<size_t>(n);
  }
  return static_cast<int>(total);
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

  int dirfd; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, dirfd, leaf);
  if (rc != 0) return rc;

  int fd = openat(dirfd, leaf.c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
  int e = errno;
  close(dirfd);
  if (fd == -1) return -e;

  int ok = ftruncate(fd, size);
  e = errno;
  close(fd);
  return ok == -1 ? -e : 0;
}

int gent_rename(const char *from, const char *to, unsigned int flags){
  int fdir; std::string fleaf;
  int tdir; std::string tleaf;
  int rc = walk_parent(ctx()->rootfd, from, fdir, fleaf); if (rc != 0) return rc;
  rc = walk_parent(ctx()->rootfd, to, tdir, tleaf); if (rc != 0) return rc;

#if defined (__linux__) && defined (__NR_renameat2)
  int ok = syscall(__NR_renameat2, fdir, fleaf.c_str(), tdir, tleaf.c_str(), static_cast<unsigned int>(flags));  
  close(fdir); close(tdir);
  if (ok == -1) return -errno;
  return 0;
#else 
  if (flags != 0) {
    close(fdir); close(tdir);
    return -ENOTSUP;
  }
  int ok = renameat(fdir, fleaf.c_str(), tdir, tleaf.c_str());
  close(fdir); close(tdir);
  return ok == -1 ? -errno : 0;
#endif
}

int gent_unlink(const char *path){
  int dirfd; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, dirfd, leaf);
  if(rc != 0) return rc;
  int ok = unlinkat(dirfd, leaf.c_str(), 0);
  int e = errno;
  close(dirfd);
  return ok == -1 ? -e : 0;
}

int gent_mkdir(const char *path, mode_t mode){
  int dirfd; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, dirfd, leaf);
  if(rc != 0) return rc;
  int ok = mkdirat(dirfd, leaf.c_str(), mode);
  int e = errno;
  close(dirfd);
  return ok == -1 ? -e : 0;
}

int gent_rmdir(const char *path){
  int dirfd; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, dirfd, leaf);
  if(rc != 0) return rc;
  int ok = unlinkat(dirfd, leaf.c_str(), AT_REMOVEDIR);
  int e = errno;
  close(dirfd);
  return ok == -1 ? -e : 0;
}

int gent_flush(const char *path, struct fuse_file_info *fi){
  (void)path;
  return 0;
}

int gent_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi){
  int pdir; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, pdir, leaf);
  if (rc) return rc;

  const char *item = leaf.empty() ? "." : leaf.c_str();
  int ok = fchownat(pdir, item, uid, gid, AT_SYMLINK_NOFOLLOW);
  close(pdir);
  return ok == -1 ? -errno : 0;
}

int gent_chmod(const char *path, mode_t mode, struct fuse_file_info *fi){
  int pdir; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, pdir, leaf);
  if (rc) return rc;

  const char *item = leaf.empty() ? "." : leaf.c_str();
  int ok = fchmodat(pdir, item, mode, 0);
  close(pdir);
  return ok == -1 ? -errno : 0;
}

int gent_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi){
  int pdir; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, pdir, leaf);
  if (rc) return rc;

  const char *item = leaf.empty() ? "." : leaf.c_str();
  int ok = utimensat(pdir, item, tv, AT_SYMLINK_NOFOLLOW);
  close(pdir);
  return ok == -1 ? -errno : 0;
}

int gent_fsync(const char *, int, struct fuse_file_info *fi){
  return (fsync(static_cast<int>(fi->fh)) == -1) ? -errno : 0;
}

int gent_fsyncdir(const char *, int, struct fuse_file_info *){
  return 0;
}
