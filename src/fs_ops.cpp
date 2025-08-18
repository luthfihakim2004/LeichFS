#include "fs_ops.hpp"
#include "enc.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <fcntl.h>
#include <fuse3/fuse.h>
#include <limits.h>
#include <linux/stat.h>
#include <string>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <fuse_lowlevel.h>
#include <vector>
using namespace enc;

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0)
#endif // !RENAME_NOREPLACE
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1U << 1)
#endif // !RENAME_EXCHANGE
std::string g_root;

static_assert(sizeof(off_t) == 8, "off_t must be 64-bit");

static inline uint64_t chunk_index(uint64_t offset){ return offset / CHUNK_SIZE;}
static inline size_t chunk_off(uint64_t offset){ return static_cast<size_t>(offset % CHUNK_SIZE);}

static inline uint64_t cipher_chunk_off(uint64_t i){
  return HEADER_SIZE + i * static_cast<uint64_t>(CHUNK_SIZE + TAG_SIZE);
}
static inline uint64_t cipher_tail_off(uint64_t full, size_t plain){
  return HEADER_SIZE + full * static_cast<uint64_t>(CHUNK_SIZE + TAG_SIZE) + static_cast<uint64_t>(plain + TAG_SIZE);
}
static inline int update_plain_len(int fd, uint64_t new_plain_len){
  off_t offset = static_cast<off_t>(offsetof(Header, plain_len_be));
  ssize_t n = pwrite(fd, &new_plain_len, sizeof(new_plain_len), offset);
  return (n == static_cast<ssize_t>(sizeof(new_plain_len))) ? 0 : -1;
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
  cfg->kernel_cache = 1;
  cfg->use_ino = 1;
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
  
  if (fstatat(pdir, item, st, AT_SYMLINK_NOFOLLOW) == -1){
    close(pdir);
    return -errno;
  }

  if (S_ISREG(st->st_mode)){
    int fd = openat(pdir, item, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int saved = errno;
    close(pdir);
    if (fd == -1) return -saved;

    Header h{};
    if (read_header(fd, h) == 0)
      st->st_size = static_cast<off_t>(be64toh_u64(h.plain_len_be));
    close(fd);
    return 0;
  }

  close(pdir);
  return 0;
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
  int pdir; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, pdir, leaf);
  if (rc != 0) return rc;

  // needed flags
  int oflags = (fi->flags & ~(O_CREAT | O_EXCL | O_TRUNC)) | O_CLOEXEC | O_NOFOLLOW;
  oflags &= ~O_ACCMODE;
  oflags |= O_RDWR;      // FORCE O_RDWR

  // Pre Check
  int fd = openat(pdir, leaf.empty() ? "." : leaf.c_str(), oflags);
  close(pdir);
  if (fd == -1) return -errno;

  struct stat st{};
  if(fstat(fd, &st) == -1) {
    close(fd);
    return -errno;
  }
  if (!S_ISREG(st.st_mode)){
    close(fd);
    return -EISDIR;
  }

  // Validate header
  Header h{};
  if (read_header(fd, h) != 0){
    close(fd);
    return -EINVAL;
  }

  auto *fh = new FH{};
  fh->fd = fd;
  fh->chunk_sz = h.chunk_sz;
  fh->plain_len = be64toh_u64(h.plain_len_be);

  std::array<uint8_t, KEY_SIZE> master{};
  if (load_master_key_from_env(master) != 0){
    close(fd);
    delete fh;
    return -EACCES;
  }
  if (derive_file_material(master, h.salt, fh->file_key, fh->nonce_base) != 0){
    close(fd);
    delete fh;
    return -EIO;
  }

  fi->fh = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(fh));
  return 0;
}

int gent_create(const char *path, mode_t mode, struct fuse_file_info *fi){
  int dirfd; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, dirfd, leaf);
  if (rc != 0) return rc;

  // needed flags
  int oflags = (fi->flags | O_CREAT) | O_CLOEXEC | O_NOFOLLOW;
  oflags &= ~O_ACCMODE;
  oflags |= O_RDWR;         //FORCE O_RDWR

  int fd = openat(dirfd, leaf.c_str(), oflags, mode);
  int saved = errno;
  close(dirfd);
  if(fd == -1) return -saved;


  // Build header 
  Header h{};
  std::memcpy(h.magic, "GENTOOFS", 8);
  h.version = 1;
  h.chunk_sz = CHUNK_SIZE;

  // Salt
  {
    FILE *ur = std::fopen("/dev/urandom", "rb");
    if (!ur || std::fread(h.salt, 1, SALT_SIZE, ur) != SALT_SIZE){
      if (ur) std::fclose(ur);
      close(fd);
      return -EIO;
    }
    std::fclose(ur);
  }

  h.plain_len_be = htobe_u64(0);

  if (write_header(fd, h) != 0){
    int se = errno;
    close(fd);
    return -se;
  }

  // FH 
  auto *fh = new FH{};
  fh->fd = fd;
  fh->chunk_sz = h.chunk_sz;
  fh->plain_len = 0;

  std::array<uint8_t, KEY_SIZE> master{};
  if (load_master_key_from_env(master) != 0){
    close(fd);
    delete fh;
    return -EACCES;
  }
  if (derive_file_material(master, h.salt, fh->file_key, fh->nonce_base) != 0) {
    close(fd);
    delete fh;
    return -EIO;
  }

  fi->fh = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(fh));
  return 0;
}

int gent_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
  (void)path;
  auto *fh = reinterpret_cast<FH*>(static_cast<uintptr_t>(fi->fh));
  if (!fh) return -EBADF;

  const uint8_t *in = reinterpret_cast<const uint8_t*>(buf);
  size_t l = size;
  uint64_t i = chunk_index(offset);
  size_t o = chunk_off(offset);
  uint64_t cur_offset = offset;

  while (l > 0){
    size_t plain = CHUNK_SIZE;
    
    // Determine length for the chunk
    uint64_t chunk_start = cur_offset - o;
    bool chunk_exist = (chunk_start < fh->plain_len);
    size_t ex_len = 0;
    if (chunk_exist){
      uint64_t remain = fh->plain_len - chunk_start;
      ex_len = (remain >= CHUNK_SIZE) ? CHUNK_SIZE : static_cast<size_t>(remain);
    }

    // Build chunk buffer
    std::vector<uint8_t> pbuf(std::max(ex_len, static_cast<size_t>(CHUNK_SIZE)), 0);
    if (ex_len > 0){
      uint64_t coffset = cipher_chunk_off(i);
      size_t clen = ex_len + TAG_SIZE;
      std::vector<uint8_t> cbuf(clen);
      ssize_t rn = pread(fh->fd, cbuf.data(), clen, static_cast<off_t>(coffset));
      if (rn != static_cast<ssize_t>(clen)) return -EIO;
      uint8_t nonce[NONCE_SIZE];
      make_chunk_nonce(fh->nonce_base, i, nonce);
      if (aesgcm_decrypt(fh->file_key.data(), nonce,
                         cbuf.data(), ex_len,
                         cbuf.data() + ex_len,
                         pbuf.data()) != 0) return -EIO;
    }

    // Copy incoming bytes into the chunk
    size_t can = std::min(l, CHUNK_SIZE - o);
    std::memcpy(pbuf.data() + o, in, can);
    size_t out_plen = std::max(ex_len, o + can);

    // Encrypt n write back
    std::vector<uint8_t> cbuf(out_plen + TAG_SIZE);
    uint8_t nonce[NONCE_SIZE];
    make_chunk_nonce(fh->nonce_base, i, nonce);
    if (aesgcm_encrypt(fh->file_key.data(), nonce,
                       pbuf.data(), out_plen,
                       cbuf.data(), cbuf.data() + out_plen) != 0) return -EIO;
    
    uint64_t coffset = cipher_chunk_off(i);
    if (pwrite(fh->fd, cbuf.data(), cbuf.size(), static_cast<off_t>(coffset)) != static_cast<ssize_t>(cbuf.size())) return -EIO;

    in += can;
    l -= can;
    cur_offset += can;
    i++;
    o = 0;
  }

  // Update plaintext length if extended
  uint64_t new_len = std::max<uint64_t>(fh->plain_len, static_cast<uint64_t>(offset) + size);
  if(new_len != fh->plain_len){
    fh->plain_len = new_len;
    uint64_t be = htobe_u64(fh->plain_len);
    if (update_plain_len(fh->fd, be) != 0) return -EIO;
  }
  return static_cast<int>(size);
}

// Check for looping as same as write
int gent_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  (void)path;
  auto *fh = reinterpret_cast<FH*>(static_cast<uintptr_t>(fi->fh));
  if (!fh) return -EBADF;

  if (static_cast<uint64_t>(offset) >= fh->plain_len) return 0;
  ssize_t to_read = size;
  if (static_cast<uint64_t>(offset) + to_read > fh->plain_len) to_read = static_cast<size_t>(fh->plain_len - static_cast<uint64_t>(offset));

  uint8_t *out = reinterpret_cast<uint8_t*>(buf);
  size_t done = 0;

  uint64_t i0 = chunk_index(offset);
  size_t o0 = chunk_off(offset);
  uint64_t i = i0;

  while (done < to_read) {
    size_t plain = CHUNK_SIZE;
    uint64_t ch_start = (i==i0) ? offset - static_cast<uint64_t>(o0) : static_cast<uint64_t>(i * CHUNK_SIZE);
    uint64_t remain = fh->plain_len - ch_start;
    if (remain < plain) plain = static_cast<size_t>(remain);

    // Read chunk
    uint64_t coffset = cipher_chunk_off(i);
    const size_t clen = plain + TAG_SIZE;
    std::vector<uint8_t> cbuf(clen);
    ssize_t rn = pread(fh->fd, cbuf.data(), clen, static_cast<off_t>(coffset));
    if (rn != static_cast<ssize_t>(clen)) return -EIO;
  
    // Dercypt
    std::vector<uint8_t> pbuf(plain);
    uint8_t nonce[NONCE_SIZE];
    make_chunk_nonce(fh->nonce_base, i, nonce);
    if (aesgcm_decrypt(fh->file_key.data(), nonce,
                       cbuf.data(), plain,
                       cbuf.data() + plain, 
                       pbuf.data()) != 0) return -EIO;

    // Copy requested chunk
    size_t start = (i == i0) ? o0 : 0;
    size_t can = plain - start;
    if (can > (to_read - done)) can = (to_read - done);
    std::memcpy(out + done, pbuf.data() + start, can);
    done += can;
    i++;
  }

  return static_cast<int>(done);
}

int gent_release(const char *path, struct fuse_file_info *fi){
  (void)path;

  auto *fh = reinterpret_cast<FH*>(static_cast<uintptr_t>(fi->fh));
  if (!fh) return 0;
  close(fh->fd);
  delete fh;

  return 0;
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
  auto *fh = reinterpret_cast<FH*>(static_cast<uintptr_t>(fi->fh));
  if (!fh) return -EBADF;
  return (fsync(fh->fd) == -1) ? -errno : 0;
}

int gent_fsyncdir(const char *, int, struct fuse_file_info *){
  return 0;
}

int gent_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
  FH *fh = (fi && fi->fh) ? reinterpret_cast<FH*>(static_cast<uintptr_t>(fi->fh)) : nullptr;

  // If we don't have an FH, open a temporary RDWR handle and derive material
  bool temp_open = false;
  if (!fh) {
    int pdir; std::string leaf;
    int rc = walk_parent(ctx()->rootfd, path, pdir, leaf);
    if (rc) return rc;

    int fd = openat(pdir, leaf.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    int saved = errno;
    close(pdir);
    if (fd == -1) return -saved;

    Header h{};
    if (read_header(fd, h) != 0) { close(fd); return -EINVAL; }

    auto *tfh = new FH{};
    tfh->fd        = fd;
    tfh->chunk_sz  = h.chunk_sz;
    tfh->plain_len = be64toh_u64(h.plain_len_be);

    std::array<uint8_t, KEY_SIZE> master{};
    if (load_master_key_from_env(master) != 0) { close(fd); delete tfh; return -EACCES; }
    if (derive_file_material(master, h.salt, tfh->file_key, tfh->nonce_base) != 0) {
      close(fd); delete tfh; return -EIO;
    }

    fh = tfh;
    temp_open = true;
  }

  const uint64_t old_len = fh->plain_len;
  const uint64_t new_len = static_cast<uint64_t>(size);
  if (new_len == old_len) {
    if (temp_open) { close(fh->fd); delete fh; }
    return 0;
  }

  if (new_len < old_len) {
    // -------- SHRINK --------
    const uint64_t last_full = new_len / CHUNK_SIZE;
    const size_t   tail_len  = static_cast<size_t>(new_len % CHUNK_SIZE);

    if (tail_len > 0) {
      const uint64_t ch_start = last_full * CHUNK_SIZE;
      const size_t ex_len = (old_len - ch_start >= CHUNK_SIZE)
                            ? CHUNK_SIZE
                            : static_cast<size_t>(old_len - ch_start);

      // Read+decrypt the current last chunk
      std::vector<uint8_t> pbuf(ex_len, 0);
      const uint64_t coffset = cipher_chunk_off(last_full);
      std::vector<uint8_t> cbuf(ex_len + TAG_SIZE);
      if (pread(fh->fd, cbuf.data(), cbuf.size(), static_cast<off_t>(coffset)) !=
          static_cast<ssize_t>(cbuf.size())) {
        if (temp_open) { close(fh->fd); delete fh; }
        return -EIO;
      }
      uint8_t nonce[NONCE_SIZE];
      make_chunk_nonce(fh->nonce_base, last_full, nonce);
      if (aesgcm_decrypt(fh->file_key.data(), nonce,
                         cbuf.data(), ex_len,
                         cbuf.data() + ex_len,
                         pbuf.data()) != 0) {
        if (temp_open) { close(fh->fd); delete fh; }
        return -EIO;
      }

      // Re-encrypt only the truncated tail
      pbuf.resize(tail_len);
      std::vector<uint8_t> out(tail_len + TAG_SIZE);
      make_chunk_nonce(fh->nonce_base, last_full, nonce);
      if (aesgcm_encrypt(fh->file_key.data(), nonce,
                         pbuf.data(), tail_len,
                         out.data(), out.data() + tail_len) != 0) {
        if (temp_open) { close(fh->fd); delete fh; }
        return -EIO;
      }
      if (pwrite(fh->fd, out.data(), out.size(), static_cast<off_t>(coffset)) !=
          static_cast<ssize_t>(out.size())) {
        if (temp_open) { close(fh->fd); delete fh; }
        return -EIO;
      }

      // Physically cut ciphertext after the new tail
      const uint64_t cut = cipher_tail_off(last_full, tail_len);
      if (ftruncate(fh->fd, static_cast<off_t>(cut)) == -1) {
        if (temp_open) { close(fh->fd); delete fh; }
        return -errno;
      }
    } else {
      // Exact chunk boundary
      const uint64_t cut = cipher_chunk_off(last_full);
      if (ftruncate(fh->fd, static_cast<off_t>(cut)) == -1) {
        if (temp_open) { close(fh->fd); delete fh; }
        return -errno;
      }
    }

  } else {
    // -------- GROW --------
    uint64_t pos = old_len;
    while (pos < new_len) {
      const uint64_t i = chunk_index(pos);
      const size_t   o = chunk_off(pos);
      const size_t   w = static_cast<size_t>(
                           std::min<uint64_t>(CHUNK_SIZE - o, new_len - pos));

      // Determine how many bytes currently exist in this chunk
      size_t ex_len = 0;
      const uint64_t ch_start = pos - o; // start of this chunk in plaintext space
      if (ch_start < old_len) {
        const uint64_t rem = old_len - ch_start;
        ex_len = (rem >= CHUNK_SIZE) ? CHUNK_SIZE : static_cast<size_t>(rem);
      }

      // Build a full chunk buffer, decrypt existing prefix if present
      std::vector<uint8_t> pbuf(std::max(ex_len, static_cast<size_t>(CHUNK_SIZE)), 0);
      const uint64_t coffset = cipher_chunk_off(i);
      if (ex_len > 0) {
        std::vector<uint8_t> cbuf(ex_len + TAG_SIZE);
        if (pread(fh->fd, cbuf.data(), cbuf.size(), static_cast<off_t>(coffset)) !=
            static_cast<ssize_t>(cbuf.size())) {
          if (temp_open) { close(fh->fd); delete fh; }
          return -EIO;
        }
        uint8_t nonce[NONCE_SIZE];
        make_chunk_nonce(fh->nonce_base, i, nonce);
        if (aesgcm_decrypt(fh->file_key.data(), nonce,
                           cbuf.data(), ex_len,
                           cbuf.data() + ex_len,
                           pbuf.data()) != 0) {
          if (temp_open) { close(fh->fd); delete fh; }
          return -EIO;
        }
      }

      // Zero-extend the requested window inside this chunk
      std::memset(pbuf.data() + o, 0, w);
      const size_t out_len = std::max(ex_len, o + w);

      // Encrypt and write back the (possibly partial) chunk
      std::vector<uint8_t> cbuf(out_len + TAG_SIZE);
      uint8_t nonce[NONCE_SIZE];
      make_chunk_nonce(fh->nonce_base, i, nonce);
      if (aesgcm_encrypt(fh->file_key.data(), nonce,
                         pbuf.data(), out_len,
                         cbuf.data(), cbuf.data() + out_len) != 0) {
        if (temp_open) { close(fh->fd); delete fh; }
        return -EIO;
      }
      if (pwrite(fh->fd, cbuf.data(), cbuf.size(), static_cast<off_t>(coffset)) !=
          static_cast<ssize_t>(cbuf.size())) {
        if (temp_open) { close(fh->fd); delete fh; }
        return -EIO;
      }

      pos += w;
    }
  }

  // -------- Commit new logical length in header (8-byte write) --------
  fh->plain_len = new_len;
  const uint64_t be = htobe_u64(fh->plain_len);
  if (update_plain_len(fh->fd, be) != 0) {
    if (temp_open) { close(fh->fd); delete fh; }
    return -EIO;
  }

  if (temp_open) { close(fh->fd); delete fh; }
  return 0;
}
