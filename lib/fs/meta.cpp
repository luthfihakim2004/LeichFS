#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <unistd.h>
#include <openssl/crypto.h>

#include "enc/params.hpp"
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

  // If FH is missing, open a temporary RDWR handle and derive material (+AAD prefix)
  bool temp_open = false;
  Header h{};
  if (!fh) {
    int pdir; std::string leaf;
    int rc = walk_parent(ctx()->rootfd, path, pdir, leaf);
    if (rc) return rc;

    int fd = openat(pdir, leaf.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    int saved = errno;
    close(pdir);
    if (fd == -1) return -saved;

    if (read_header(fd, h) != 0) { close(fd); return -EINVAL; }

    auto *tfh = new FH{};
    tfh->fd        = fd;
    tfh->chunk_sz  = h.chunk_sz;
    tfh->plain_len = be64toh_u64(h.plain_len_be);

    std::array<uint8_t, KEY_SIZE> master{};
    if (load_master_key_from_env(master) != 0) { OPENSSL_cleanse(master.data(), master.size()); close(fd); delete tfh; return -EACCES; }
    if (derive_file_material(master, h.salt, tfh->file_key, tfh->nonce_base) != 0) { OPENSSL_cleanse(master.data(), master.size()); close(fd); delete tfh; return -EIO; }
    OPENSSL_cleanse(master.data(), master.size());

    // Build AAD prefix: magic[8] || be32(version) || be32(chunk_sz) || salt[SALT_SIZE]
    std::memcpy(tfh->aad_prefix.data(), h.magic, 8);
    uint32_t v_be  = util::enc::htobe_u32(h.version);
    uint32_t sz_be = util::enc::htobe_u32(h.chunk_sz);
    std::memcpy(tfh->aad_prefix.data() + 8,  &v_be,  4);
    std::memcpy(tfh->aad_prefix.data() + 12, &sz_be, 4);
    std::memcpy(tfh->aad_prefix.data() + 16, h.salt, enc::SALT_SIZE);

    fh = tfh;
    temp_open = true;
  }

  const uint32_t csz = fh->chunk_sz;
  const uint64_t old_len = fh->plain_len;
  const uint64_t new_len = static_cast<uint64_t>(size);
  if (new_len == old_len) {
    if (temp_open) { close(fh->fd); delete fh; }
    return 0;
  }

  if (new_len < old_len) {
    // -------- SHRINK --------
    const uint64_t last_full = new_len / csz;
    const size_t   tail_len  = static_cast<size_t>(new_len % csz);

    if (tail_len > 0) {
      // Keep the partial tail of chunk 'last_full'
      const uint64_t ch_start = last_full * csz;

      size_t ex_len = 0;
      if (ch_start < old_len) {
        const uint64_t rem = old_len - ch_start;
        ex_len = (rem >= csz) ? csz : static_cast<size_t>(rem);
      }

      // Read + decrypt existing last chunk (ex_len > 0 is expected)
      std::vector<uint8_t> pbuf(ex_len ? ex_len : tail_len, 0);
      const uint64_t coffset = util::fs::cipher_chunk_off(last_full, csz);

      if (ex_len > 0) {
        const size_t clen = NONCE_SIZE + ex_len + TAG_SIZE;
        std::vector<uint8_t> cbuf(clen);
        ssize_t rn = util::fs::full_pread(fh->fd, cbuf.data(), clen, static_cast<off_t>(coffset));
        if (rn != static_cast<ssize_t>(clen)) { if (temp_open) { close(fh->fd); delete fh; } return -EIO; }

        uint8_t *nonce = cbuf.data();
        uint8_t *ct    = cbuf.data() + NONCE_SIZE;
        uint8_t *tag   = ct + ex_len;

        // AAD = prefix || be64(last_full)
        uint8_t aad[enc::AAD_PREFIX_LEN + 8];
        std::memcpy(aad, fh->aad_prefix.data(), enc::AAD_PREFIX_LEN);
        uint64_t idx_be = util::enc::htobe_u64(last_full);
        std::memcpy(aad + enc::AAD_PREFIX_LEN, &idx_be, 8);

        if (aesgcm_decrypt(fh->file_key.data(), nonce, ct, ex_len,
                           aad, enc::AAD_PREFIX_LEN + 8,
                           tag, pbuf.data()) != 0) {
          if (temp_open) { close(fh->fd); delete fh; }
          return -EBADMSG;
        }
      }

      // Keep only 'tail_len' bytes
      pbuf.resize(tail_len);

      // Re-encrypt tail with a FRESH nonce and write back
      const size_t out_len = tail_len;
      const size_t wlen = NONCE_SIZE + out_len + TAG_SIZE;
      std::vector<uint8_t> out(wlen);
      if (util::enc::fill_rand(out.data(), NONCE_SIZE) != 0) { if (temp_open) { close(fh->fd); delete fh; } return -EIO; }
      uint8_t *nonce2 = out.data();
      uint8_t *ct2    = out.data() + NONCE_SIZE;
      uint8_t *tag2   = ct2 + out_len;

      // AAD again for same index
      uint8_t aad2[enc::AAD_PREFIX_LEN + 8];
      std::memcpy(aad2, fh->aad_prefix.data(), enc::AAD_PREFIX_LEN);
      uint64_t idx2_be = util::enc::htobe_u64(last_full);
      std::memcpy(aad2 + enc::AAD_PREFIX_LEN, &idx2_be, 8);

      if (aesgcm_encrypt(fh->file_key.data(), nonce2,
                         pbuf.data(), out_len,
                         aad2, enc::AAD_PREFIX_LEN + 8,
                         ct2, tag2) != 0) {
        if (temp_open) { close(fh->fd); delete fh; }
        return -EIO;
      }
      if (util::fs::full_pwrite(fh->fd, out.data(), wlen, static_cast<off_t>(coffset)) != static_cast<ssize_t>(wlen)) {
        if (temp_open) { close(fh->fd); delete fh; }
        return -EIO;
      }

      // Physically cut ciphertext after the new tail
      const uint64_t cut = util::fs::cipher_tail_off(last_full, tail_len, csz);
      if (ftruncate(fh->fd, static_cast<off_t>(cut)) == -1) {
        if (temp_open) { close(fh->fd); delete fh; }
        return -errno;
      }

    } else {
      // Exact chunk boundary
      const uint64_t cut = util::fs::cipher_chunk_off(last_full, csz);
      if (ftruncate(fh->fd, static_cast<off_t>(cut)) == -1) {
        if (temp_open) { close(fh->fd); delete fh; }
        return -errno;
      }
    }

  } else {
    // -------- GROW --------
    uint64_t pos = old_len;
    while (pos < new_len) {
      const uint64_t i = util::fs::chunk_index(pos, csz);
      const size_t   o = util::fs::chunk_off(pos, csz);
      const size_t   w = static_cast<size_t>(std::min<uint64_t>(csz - o, new_len - pos));

      // Determine how many bytes currently exist in this chunk
      size_t ex_len = 0;
      const uint64_t ch_start = pos - o; // start of this chunk in plaintext space
      if (ch_start < old_len) {
        const uint64_t rem = old_len - ch_start;
        ex_len = (rem >= csz) ? csz : static_cast<size_t>(rem);
      }

      // Build a full chunk buffer, decrypt existing prefix if present
      std::vector<uint8_t> pbuf(std::max(ex_len, static_cast<size_t>(csz)), 0);
      const uint64_t coffset = util::fs::cipher_chunk_off(i, csz);
      if (ex_len > 0) {
        const size_t clen = NONCE_SIZE + ex_len + TAG_SIZE;
        std::vector<uint8_t> cbuf(clen);
        ssize_t rn = util::fs::full_pread(fh->fd, cbuf.data(), clen, static_cast<off_t>(coffset));
        if (rn != static_cast<ssize_t>(clen)) { if (temp_open) { close(fh->fd); delete fh; } return -EIO; }

        uint8_t *nonce = cbuf.data();
        uint8_t *ct    = cbuf.data() + NONCE_SIZE;
        uint8_t *tag   = ct + ex_len;

        // AAD for index i
        uint8_t aad[enc::AAD_PREFIX_LEN + 8];
        std::memcpy(aad, fh->aad_prefix.data(), enc::AAD_PREFIX_LEN);
        uint64_t idx_be = util::enc::htobe_u64(i);
        std::memcpy(aad + enc::AAD_PREFIX_LEN, &idx_be, 8);

        if (aesgcm_decrypt(fh->file_key.data(), nonce, ct, ex_len,
                           aad, enc::AAD_PREFIX_LEN + 8,
                           tag, pbuf.data()) != 0) {
          if (temp_open) { close(fh->fd); delete fh; }
          return -EBADMSG;
        }
      }

      // Zero-extend the requested window inside this chunk
      std::memset(pbuf.data() + o, 0, w);
      const size_t out_len = std::max(ex_len, o + w);

      // Encrypt and write back the (possibly partial) chunk with a fresh nonce
      const size_t wlen = NONCE_SIZE + out_len + TAG_SIZE;
      std::vector<uint8_t> cbuf(wlen);
      if (util::enc::fill_rand(cbuf.data(), NONCE_SIZE) != 0) { if (temp_open) { close(fh->fd); delete fh; } return -EIO; }
      uint8_t *nonce2 = cbuf.data();
      uint8_t *ct2    = cbuf.data() + NONCE_SIZE;
      uint8_t *tag2   = ct2 + out_len;

      // AAD for index i
      uint8_t aad2[enc::AAD_PREFIX_LEN + 8];
      std::memcpy(aad2, fh->aad_prefix.data(), enc::AAD_PREFIX_LEN);
      uint64_t idx2_be = util::enc::htobe_u64(i);
      std::memcpy(aad2 + enc::AAD_PREFIX_LEN, &idx2_be, 8);

      if (aesgcm_encrypt(fh->file_key.data(), nonce2,
                         pbuf.data(), out_len,
                         aad2, enc::AAD_PREFIX_LEN + 8,
                         ct2, tag2) != 0) {
        if (temp_open) { close(fh->fd); delete fh; }
        return -EIO;
      }
      if (util::fs::full_pwrite(fh->fd, cbuf.data(), wlen, static_cast<off_t>(coffset)) != static_cast<ssize_t>(wlen)) {
        if (temp_open) { close(fh->fd); delete fh; }
        return -EIO;
      }

      pos += w;
    }
  }

  // -------- Commit new logical length in header (8-byte write) --------
  fh->plain_len = new_len;
  const uint64_t be = fh->plain_len;
  if (update_plain_len(fh->fd, be) != 0) {
    if (temp_open) { close(fh->fd); delete fh; }
    return -EIO;
  }

  if (temp_open) { close(fh->fd); delete fh; }
  return 0;
}

}

