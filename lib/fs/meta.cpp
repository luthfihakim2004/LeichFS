#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <unistd.h>

#include "fs/core.hpp"
#include "enc/crypto.hpp"
#include "enc/header.hpp"
#include "util.hpp"

using namespace util::fs;
using namespace util::enc;

namespace fs {

int fs_getattr(const char *path, struct stat *st, struct fuse_file_info *fi) {
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

int fs_readlink(const char *path, char *buf, size_t size){
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

int fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t off, struct fuse_file_info *fi, enum fuse_readdir_flags) {
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

int fs_mkdir(const char *path, mode_t mode){
  int dirfd; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, dirfd, leaf);
  if(rc != 0) return rc;
  int ok = mkdirat(dirfd, leaf.c_str(), mode);
  int e = errno;
  close(dirfd);
  return ok == -1 ? -e : 0;
}

int fs_unlink(const char *path){
  int dirfd; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, dirfd, leaf);
  if(rc != 0) return rc;
  int ok = unlinkat(dirfd, leaf.c_str(), 0);
  int e = errno;
  close(dirfd);
  return ok == -1 ? -e : 0;
}

int fs_rmdir(const char *path){
  int dirfd; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, dirfd, leaf);
  if(rc != 0) return rc;
  int ok = unlinkat(dirfd, leaf.c_str(), AT_REMOVEDIR);
  int e = errno;
  close(dirfd);
  return ok == -1 ? -e : 0;
}

int fs_symlink(const char *to, const char *from){
  int dirfd; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, from, dirfd, leaf);
  if (rc != 0) return rc;

  int ok = symlinkat(to, dirfd, leaf.c_str());
  close(dirfd);
  return ok == -1 ? -errno : 0;
}

int fs_rename(const char *from, const char *to, unsigned int flags){
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

int fs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi){
  int pdir; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, pdir, leaf);
  if (rc) return rc;

  const char *item = leaf.empty() ? "." : leaf.c_str();
  int ok = fchmodat(pdir, item, mode, 0);
  close(pdir);
  return ok == -1 ? -errno : 0;
}

int fs_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi){
  int pdir; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, pdir, leaf);
  if (rc) return rc;

  const char *item = leaf.empty() ? "." : leaf.c_str();
  int ok = fchownat(pdir, item, uid, gid, AT_SYMLINK_NOFOLLOW);
  close(pdir);
  return ok == -1 ? -errno : 0;
}

int fs_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi){
  int pdir; std::string leaf;
  int rc = walk_parent(ctx()->rootfd, path, pdir, leaf);
  if (rc) return rc;

  const char *item = leaf.empty() ? "." : leaf.c_str();
  int ok = utimensat(pdir, item, tv, AT_SYMLINK_NOFOLLOW);
  close(pdir);
  return ok == -1 ? -errno : 0;
}

int fs_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
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
      const uint64_t coffset = cipher_chunk_off(last_full, fh->chunk_sz);
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
      const uint64_t cut = cipher_tail_off(last_full, tail_len, fh->chunk_sz);
      if (ftruncate(fh->fd, static_cast<off_t>(cut)) == -1) {
        if (temp_open) { close(fh->fd); delete fh; }
        return -errno;
      }
    } else {
      // Exact chunk boundary
      const uint64_t cut = cipher_chunk_off(last_full, fh->chunk_sz);
      if (ftruncate(fh->fd, static_cast<off_t>(cut)) == -1) {
        if (temp_open) { close(fh->fd); delete fh; }
        return -errno;
      }
    }

  } else {
    // -------- GROW --------
    uint64_t pos = old_len;
    while (pos < new_len) {
      const uint64_t i = chunk_index(pos, fh->chunk_sz);
      const size_t   o = chunk_off(pos, fh->chunk_sz);
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
      const uint64_t coffset = cipher_chunk_off(i, fh->chunk_sz);
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

}

