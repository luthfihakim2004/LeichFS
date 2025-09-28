#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <vector>
#include <cstring>
#include <sys/random.h>

#include "enc/params.hpp"
#include "util.hpp"
#include "enc/crypto.hpp"
#include "enc/header.hpp"
#include "fs/core.hpp"

namespace fs {

int fs_create(const char *path, mode_t mode, struct fuse_file_info *fi){
  int dirfd; std::string leaf;
  int rc = util::fs::walk_parent(ctx()->rootfd, path, dirfd, leaf);
  if (rc != 0) return rc;

  // needed flags
  int oflags = (fi->flags | O_CREAT) | O_CLOEXEC | O_NOFOLLOW;
  oflags &= ~O_ACCMODE;
  oflags |= O_RDWR;         //FORCE O_RDWR
  if (fi->flags & O_EXCL) oflags |= O_EXCL;

  int fd = openat(dirfd, leaf.c_str(), oflags, mode);
  int saved = errno;
  close(dirfd);
  if(fd == -1) return -saved;


  // Build header 
  Header h{};
  std::memcpy(h.magic, "LEICHFSX", 8);
  h.version = 1;
  h.chunk_sz = CHUNK_SIZE;

  // Salt
  {
    // No file buffer
    if (util::enc::fill_rand(h.salt, SALT_SIZE) != 0){
        close(fd);
      return -EIO;
    }
  }

  h.plain_len_be = util::enc::htobe_u64(0);

  if (enc::write_header(fd, h) != 0){
    int se = errno;
    close(fd);
    return -se;
  }

  // FH 
  auto *fh = new FH{};
  fh->fd = fd;
  fh->wr = true;
  fh->oflags = fi->flags;
  fh->chunk_sz = h.chunk_sz;
  fh->plain_len = 0;
  fh->shared = get_shared(fd, fh->plain_len);
  if(!fh->shared){ close(fd); delete fh; return -EIO; }

  std::array<uint8_t, KEY_SIZE> master{};
  // Obtaining master key (CURRENTLY IS SET ON ENV VAR)
  if (util::enc::load_master_key_from_env(master) != 0){
    OPENSSL_cleanse(master.data(), master.size());
    close(fd);
    delete fh;
    return -EACCES;
  }
  if (derive_file_material(master, h.salt, fh->file_key, fh->nonce_base) != 0) {
    OPENSSL_cleanse(master.data(), master.size());
    close(fd);
    delete fh;
    return -EIO;
  }

  // --- Build AAD prefix: magic[8] || be32(version) || be32(chunk_sz) || salt[SALT_SIZE]
  {
    // magic
    std::memcpy(fh->aad_prefix.data(), h.magic, 8);

    // version (BE u32)
    uint32_t v_be = util::enc::htobe_u32(h.version);
    std::memcpy(fh->aad_prefix.data() + 8, &v_be, 4);

    // chunk_sz (BE u32)
    uint32_t sz_be = util::enc::htobe_u32(h.chunk_sz);
    std::memcpy(fh->aad_prefix.data() + 12, &sz_be, 4);

    // salt
    std::memcpy(fh->aad_prefix.data() + 16, h.salt, enc::SALT_SIZE);
  }

  // Zeroization master buffer
  OPENSSL_cleanse(master.data(), master.size());

  fi->fh = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(fh));
  return 0;
}

int fs_open(const char *path, struct fuse_file_info *fi) {
  int pdir; std::string leaf;
  int rc = util::fs::walk_parent(ctx()->rootfd, path, pdir, leaf);
  if (rc != 0) return rc;

  // Respect kernel access mode for open
  int acc = fi->flags & O_ACCMODE;
  int oflags = O_CLOEXEC | O_NOFOLLOW;
  oflags |= fi->flags & (O_DIRECT | O_SYNC | O_DSYNC
#ifdef O_RSYNC
                        | O_RSYNC
#endif
#ifdef O_NOATIME
                        | O_NOATIME
#endif
                        );
  switch(acc){
    case O_RDONLY: oflags |= O_RDONLY; break;
    case O_WRONLY: oflags |= O_WRONLY; break;
    case O_RDWR: oflags |= O_RDWR; break;
    default: close(pdir); return -EINVAL;
  }

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
  int of = fcntl(fd, F_GETFL);
fprintf(stderr, "[OPEN] fd=%d oflags=0x%x acc=%s%s%s\n", fd, of,
  ((of & O_ACCMODE)==O_RDONLY? "RDONLY" :
   (of & O_ACCMODE)==O_WRONLY? "WRONLY" : "RDWR"),
  (of & O_APPEND) ? " +APPEND" : "",
  (of & O_DIRECT) ? " +DIRECT" : "");

  // Validate header
  Header h{};
  if (enc::read_header(fd, h) != 0){
    close(fd);
    return -EIO;
  }

  auto *fh = new FH{};
  fh->fd = fd;
  fh->chunk_sz = h.chunk_sz;
  fh->plain_len = util::enc::be64toh_u64(h.plain_len_be);
  fh->shared = get_shared(fd, fh->plain_len);
  fh->wr = (acc != O_RDONLY);
  if(!fh->shared){ close(fd); delete fh; return -EIO; }
  {
    std::lock_guard<std::shared_mutex> lk(fh->shared->mtx);
    if (fh->shared->plain_len < fh->plain_len) {
      fh->shared->plain_len = fh->plain_len;
    }
  }
  if (fh->wr && (fi->flags & O_TRUNC)){
    std::lock_guard<std::shared_mutex> lk(fh->shared->mtx);
    fh->shared->plain_len = 0;
    fh->plain_len = 0;
    util::fs::update_plain_len(fd, 0);
    ftruncate(fd, sizeof(Header));
  }

  fprintf(stderr, "[OPEN] header plain_len(be->host)=%llu\n",
        (unsigned long long)fh->plain_len);
  
  std::array<uint8_t, KEY_SIZE> master{};
  if (util::enc::load_master_key_from_env(master) != 0){
    OPENSSL_cleanse(master.data(), master.size());
    close(fd);
    delete fh;
    return -EACCES;
  }
  if (derive_file_material(master, h.salt, fh->file_key, fh->nonce_base) != 0){
    OPENSSL_cleanse(master.data(), master.size());
    close(fd);
    delete fh;
    return -EIO;
  }
  OPENSSL_cleanse(master.data(), master.size());

  // --- Build AAD prefix
  {
    std::memcpy(fh->aad_prefix.data(), h.magic, 8);

    uint32_t v_be = util::enc::htobe_u32(h.version);
    std::memcpy(fh->aad_prefix.data() + 8, &v_be, 4);

    uint32_t sz_be = util::enc::htobe_u32(h.chunk_sz);
    std::memcpy(fh->aad_prefix.data() + 12, &sz_be, 4);

    std::memcpy(fh->aad_prefix.data() + 16, h.salt, enc::SALT_SIZE);
  }

  fi->fh = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(fh));
  return 0;
}

int fs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  (void)path;
  auto *fh = reinterpret_cast<FH*>(static_cast<uintptr_t>(fi->fh));
  if (!fh) return -EBADF;

  std::shared_lock<std::shared_mutex> lk(fh->shared->mtx);
  uint64_t limit = fh->shared->plain_len;

  if (static_cast<uint64_t>(offset) >= limit) return 0;
  size_t to_read = size;
  if (static_cast<uint64_t>(offset) + to_read > limit) to_read = static_cast<size_t>(limit - static_cast<uint64_t>(offset));

  uint8_t *out = reinterpret_cast<uint8_t*>(buf);
  size_t done = 0;

  const uint32_t csz = fh->chunk_sz;
  uint64_t i0 = util::fs::chunk_index(offset, csz);
  size_t o0 = util::fs::chunk_off(offset, csz);
  uint64_t i = i0;

  while (done < to_read) {
    size_t plain = csz;
    uint64_t ch_start = (i==i0) ? static_cast<uint64_t>(offset) - static_cast<uint64_t>(o0) : static_cast<uint64_t>(i * csz);
    uint64_t remain = limit - ch_start;
    if (remain < plain) plain = static_cast<size_t>(remain);

    // Read chunk
    uint64_t coffset = util::fs::cipher_chunk_off(i, csz);
if (coffset < enc::HEADER_SIZE) {
  fprintf(stderr, "[BUG] chunk write would clobber header: coffset=%llu i=%llu\n",
          (unsigned long long)coffset, (unsigned long long)i);
  return -EIO;
}
    const size_t clen = NONCE_SIZE + plain + TAG_SIZE;
    std::vector<uint8_t> cbuf(clen);
    ssize_t rn = util::fs::full_pread(fh->fd, cbuf.data(), clen, static_cast<off_t>(coffset));
    if (rn != static_cast<ssize_t>(clen)) return -EIO;

    uint8_t *nonce = cbuf.data();
    uint8_t *ct = cbuf.data() + NONCE_SIZE;
    uint8_t *tag = ct + plain;

    // Dercypt
    std::vector<uint8_t> pbuf(plain);

    // Build AAD
    uint8_t aad[enc::AAD_PREFIX_LEN + 8];
    std::memcpy(aad, fh->aad_prefix.data(), enc::AAD_PREFIX_LEN);
    uint64_t i_be = util::enc::htobe_u64(i);
    std::memcpy(aad + enc::AAD_PREFIX_LEN, &i_be, 8);

    if (aesgcm_decrypt(fh->file_key.data(), nonce,
                       ct, plain,
                       aad, enc::AAD_PREFIX_LEN + 8,
                       tag, pbuf.data()
                       ) != 0) return -EBADMSG;

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

int fs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
  (void)path;
  auto *fh = reinterpret_cast<FH*>(static_cast<uintptr_t>(fi->fh));
  if (!fh) return -EBADF;
  if (!fh->wr) return -EBADF;

  std::unique_lock<std::shared_mutex> lk(fh->shared->mtx);

  // Honor O_APPEND
  off_t start_off = offset;
  if (fh->oflags & O_APPEND){
    start_off = static_cast<off_t>(fh->shared->plain_len);
  } 
  fprintf(stderr, "[WRITE] start_off=%lld size=%zu shared=%llu header=%llu\n",
        (long long)start_off, size,
        (unsigned long long)fh->shared->plain_len,
        (unsigned long long)fh->plain_len);
  
  const uint8_t *in = reinterpret_cast<const uint8_t*>(buf);
  const uint32_t csz = fh->chunk_sz;
  size_t l = size;
  uint64_t i = util::fs::chunk_index(start_off, csz);
  size_t o = util::fs::chunk_off(start_off, csz);
  uint64_t cur_offset = start_off;

  while (l > 0){
    // Determine length for the chunk
    uint64_t chunk_start = cur_offset - o;
    bool chunk_exist = (chunk_start < fh->shared->plain_len);
    size_t ex_len = 0;
    if (chunk_exist){
      uint64_t remain = fh->shared->plain_len - chunk_start;
      ex_len = (remain >= csz) ? csz : static_cast<size_t>(remain);
    }

    // Build chunk buffer
    std::vector<uint8_t> pbuf(std::max(ex_len, static_cast<size_t>(csz)), 0);
    if (ex_len > 0){
      uint64_t coffset = util::fs::cipher_chunk_off(i, csz);
if (coffset < enc::HEADER_SIZE) {
  fprintf(stderr, "[BUG] chunk write would clobber header: coffset=%llu i=%llu\n",
          (unsigned long long)coffset, (unsigned long long)i);
  return -EIO;
}
      size_t clen = NONCE_SIZE + ex_len + TAG_SIZE;
      std::vector<uint8_t> cbuf(clen);
      ssize_t rn = util::fs::full_pread(fh->fd, cbuf.data(), clen, static_cast<off_t>(coffset));
      if (rn != static_cast<ssize_t>(clen)) return -EIO;

      uint8_t *nonce = cbuf.data();
      uint8_t *ct = cbuf.data() + NONCE_SIZE;
      uint8_t *tag = ct + ex_len;

      // Build AAD
      uint8_t aad[enc::AAD_PREFIX_LEN + 8];
      std::memcpy(aad, fh->aad_prefix.data(), enc::AAD_PREFIX_LEN);
      uint64_t i_be = util::enc::htobe_u64(i);
      std::memcpy(aad + enc::AAD_PREFIX_LEN, &i_be, 8);
      
      if (aesgcm_decrypt(fh->file_key.data(), nonce,
                         ct, ex_len,
                         aad, enc::AAD_PREFIX_LEN + 8,
                         tag, pbuf.data()
                         ) != 0) return -EBADMSG;
    }

    // Copy incoming bytes into the chunk
    size_t can = std::min(l, csz - o);
    std::memcpy(pbuf.data() + o, in, can);
    size_t out_plen = std::max(ex_len, o + can);

    // Generate fresh nonce 
    const size_t clen = NONCE_SIZE + out_plen + TAG_SIZE;
    std::vector<uint8_t>cbuf(clen);
    if (util::enc::fill_rand(cbuf.data(), NONCE_SIZE) != 0) return -EIO;

     uint8_t *nonce = cbuf.data();
     uint8_t *ct = cbuf.data() + NONCE_SIZE;
     uint8_t *tag = ct + out_plen;

    // Encrypt
    uint8_t aad[enc::AAD_PREFIX_LEN + 8];
    std::memcpy(aad, fh->aad_prefix.data(), enc::AAD_PREFIX_LEN);
    uint64_t i_be = util::enc::htobe_u64(i);
    std::memcpy(aad + enc::AAD_PREFIX_LEN, &i_be, 8);
    if (aesgcm_encrypt(fh->file_key.data(), nonce,
                       pbuf.data(), out_plen,
                       aad, enc::AAD_PREFIX_LEN + 8,
                       ct, tag) != 0) return -EIO;
    
    uint64_t coffset = util::fs::cipher_chunk_off(i, csz);
    if (util::fs::full_pwrite(fh->fd, cbuf.data(), clen, static_cast<off_t>(coffset)) != static_cast<ssize_t>(clen)) return -EIO;

    in += can;
    l -= can;
    cur_offset += can;
    i++;
    o = 0;
  }
  // Ensure to sync after writing loop for data durability
  // Performance may overhead 
  if(fdatasync(fh->fd) == -1) return -errno;

  // end position of this write
  const uint64_t end_pos = static_cast<uint64_t>(start_off) + size;

  // Update shared view first
  if (end_pos > fh->shared->plain_len) {
    fh->shared->plain_len = end_pos;
  }

  // Persist header **iff** we extended beyond what the header says we have.
  // (fh->plain_len holds the header value read at fs_open)
  if (end_pos > fh->plain_len) {
    if (util::fs::update_plain_len(fh->fd, end_pos) != 0) return -EIO;
    if (fdatasync(fh->fd) == -1) return -errno;
    fh->plain_len = end_pos;  // keep FH’s cached header length in sync
  }
  fprintf(stderr, "[WRITE-END] end_pos=%llu shared=%llu header(after?)=%llu\n",
        (unsigned long long)end_pos,
        (unsigned long long)fh->shared->plain_len,
        (unsigned long long)fh->plain_len);
  return static_cast<int>(size);
}

int fs_flush(const char *path, struct fuse_file_info *fi){
  (void)path;
  return 0;
}

int fs_release(const char *path, struct fuse_file_info *fi){
  (void)path;

  auto *fh = reinterpret_cast<FH*>(static_cast<uintptr_t>(fi->fh));
  if (!fh) return 0;
  OPENSSL_cleanse(fh->file_key.data(), fh->file_key.size());
  OPENSSL_cleanse(fh->nonce_base.data(), fh->nonce_base.size());
  close(fh->fd);
  delete fh;

  return 0;
}

int fs_fsync(const char *, int, struct fuse_file_info *fi){
  auto *fh = reinterpret_cast<FH*>(static_cast<uintptr_t>(fi->fh));
  if (!fh) return -EBADF;
  return (fsync(fh->fd) == -1) ? -errno : 0;
}

}

