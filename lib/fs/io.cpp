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
  oflags |= fi->flags & (O_APPEND | O_DIRECT | O_SYNC | O_DSYNC
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
  //if (acc == O_RDONLY) { oflags = (oflags & ~O_ACCMODE) | O_RDONLY; }
  //else { oflags = (oflags & ~O_ACCMODE) | O_RDWR; } // otherwise RDWR

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

  if (fh->wr && (fi->flags & O_TRUNC)){
    std::lock_guard<std::shared_mutex> lk(fh->shared->mtx);
    fh->shared->plain_len = 0;
    fh->plain_len = 0;
    util::fs::update_plain_len(fd, util::enc::htobe_u64(0));
    ftruncate(fd, sizeof(Header));
  }
  
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

  fi->fh = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(fh));
  return 0;
}

int fs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  (void)path;
  auto *fh = reinterpret_cast<FH*>(static_cast<uintptr_t>(fi->fh));
  if (!fh) return -EBADF;

  std::shared_lock<std::shared_mutex> lk(fh->shared->mtx);
  uint64_t limit = fh->shared->plain_len;
  fh->plain_len = limit;  // Local cache

  if (static_cast<uint64_t>(offset) >= limit) return 0;
  size_t to_read = size;
  if (static_cast<uint64_t>(offset) + to_read > limit) to_read = static_cast<size_t>(limit - static_cast<uint64_t>(offset));

  uint8_t *out = reinterpret_cast<uint8_t*>(buf);
  size_t done = 0;

  uint64_t i0 = util::fs::chunk_index(offset, fh->chunk_sz);
  size_t o0 = util::fs::chunk_off(offset, fh->chunk_sz);
  uint64_t i = i0;

  while (done < to_read) {
    size_t plain = CHUNK_SIZE;
    uint64_t ch_start = (i==i0) ? static_cast<uint64_t>(offset) - static_cast<uint64_t>(o0) : static_cast<uint64_t>(i * CHUNK_SIZE);
    uint64_t remain = limit - ch_start;
    if (remain < plain) plain = static_cast<size_t>(remain);

    // Read chunk
    uint64_t coffset = util::fs::cipher_chunk_off(i, fh->chunk_sz);
    const size_t clen = NONCE_SIZE + plain + TAG_SIZE;
    std::vector<uint8_t> cbuf(clen);
    ssize_t rn = util::fs::full_pread(fh->fd, cbuf.data(), clen, static_cast<off_t>(coffset));
    if (rn != static_cast<ssize_t>(clen)) return -EIO;

    uint8_t *nonce = cbuf.data();
    uint8_t *ct = cbuf.data() + NONCE_SIZE;
    uint8_t *tag = ct + plain;

    // Dercypt
    std::vector<uint8_t> pbuf(plain);
    //util::enc::make_chunk_nonce(fh->nonce_base, i, nonce);
    if (aesgcm_decrypt(fh->file_key.data(), nonce,
                       ct, plain,
                       tag, pbuf.data()
                       ) != 0) return -EIO;

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
  if (fi->flags & O_APPEND){
    start_off = static_cast<off_t>(fh->shared->plain_len);
  } 
  
  const uint8_t *in = reinterpret_cast<const uint8_t*>(buf);
  size_t l = size;
  uint64_t i = util::fs::chunk_index(start_off, fh->chunk_sz);
  size_t o = util::fs::chunk_off(start_off, fh->chunk_sz);
  uint64_t cur_offset = start_off;

  while (l > 0){
    // Determine length for the chunk
    uint64_t chunk_start = cur_offset - o;
    bool chunk_exist = (chunk_start < fh->shared->plain_len);
    size_t ex_len = 0;
    if (chunk_exist){
      uint64_t remain = fh->shared->plain_len - chunk_start;
      ex_len = (remain >= CHUNK_SIZE) ? CHUNK_SIZE : static_cast<size_t>(remain);
    }

    // Build chunk buffer
    std::vector<uint8_t> pbuf(std::max(ex_len, static_cast<size_t>(CHUNK_SIZE)), 0);
    if (ex_len > 0){
      uint64_t coffset = util::fs::cipher_chunk_off(i, fh->chunk_sz);

      size_t clen = NONCE_SIZE + ex_len + TAG_SIZE;
      std::vector<uint8_t> cbuf(clen);
      ssize_t rn = util::fs::full_pread(fh->fd, cbuf.data(), clen, static_cast<off_t>(coffset));
      if (rn != static_cast<ssize_t>(clen)) return -EIO;

      uint8_t *nonce = cbuf.data();
      uint8_t *ct = cbuf.data() + NONCE_SIZE;
      uint8_t *tag = ct + ex_len;

      if (aesgcm_decrypt(fh->file_key.data(), nonce,
                         ct, ex_len,
                         tag, pbuf.data()
                         ) != 0) return -EIO;
    }

    // Copy incoming bytes into the chunk
    size_t can = std::min(l, CHUNK_SIZE - o);
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
    if (aesgcm_encrypt(fh->file_key.data(), nonce,
                       pbuf.data(), out_plen,
                       ct, tag) != 0) return -EIO;
    
    uint64_t coffset = util::fs::cipher_chunk_off(i, fh->chunk_sz);
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

  // Update length if extended
  uint64_t new_len = std::max<uint64_t>(fh->shared->plain_len, static_cast<uint64_t>(start_off) + size);
  if(new_len != fh->shared->plain_len){
    fh->shared->plain_len = new_len;
    fh->plain_len = new_len;
    uint64_t be = util::enc::htobe_u64(new_len);
    if (util::fs::update_plain_len(fh->fd, be) != 0) return -EIO;
    if(fdatasync(fh->fd) == -1) return -errno;
  }
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

