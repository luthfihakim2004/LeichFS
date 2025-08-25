#include <cstdint>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <string>
#include <vector>
#include <cstring>
#include <sys/random.h>

#include "enc/params.hpp"
#include "util.hpp"
#include "enc/crypto.hpp"
#include "enc/header.hpp"
#include "enc/fhandler.hpp"
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
  fh->chunk_sz = h.chunk_sz;
  fh->plain_len = 0;

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
  int oflags = (fi->flags & ~(O_CREAT|O_EXCL|O_TRUNC)) | O_CLOEXEC | O_NOFOLLOW;
  if (acc == O_RDONLY) { oflags = (oflags & ~O_ACCMODE) | O_RDONLY; }
  else { oflags = (oflags & ~O_ACCMODE) | O_RDWR; } // otherwise RDWR

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
    return -EINVAL;
  }

  auto *fh = new FH{};
  fh->fd = fd;
  fh->chunk_sz = h.chunk_sz;
  fh->plain_len = util::enc::be64toh_u64(h.plain_len_be);

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

  if (static_cast<uint64_t>(offset) >= fh->plain_len) return 0;
  ssize_t to_read = size;
  if (static_cast<uint64_t>(offset) + to_read > fh->plain_len) to_read = static_cast<size_t>(fh->plain_len - static_cast<uint64_t>(offset));

  uint8_t *out = reinterpret_cast<uint8_t*>(buf);
  size_t done = 0;

  uint64_t i0 = util::fs::chunk_index(offset);
  size_t o0 = util::fs::chunk_off(offset);
  uint64_t i = i0;

  while (done < to_read) {
    size_t plain = CHUNK_SIZE;
    uint64_t ch_start = (i==i0) ? offset - static_cast<uint64_t>(o0) : static_cast<uint64_t>(i * CHUNK_SIZE);
    uint64_t remain = fh->plain_len - ch_start;
    if (remain < plain) plain = static_cast<size_t>(remain);

    // Read chunk
    uint64_t coffset = util::fs::cipher_chunk_off(i);
    const size_t clen = plain + TAG_SIZE;
    std::vector<uint8_t> cbuf(clen);
    ssize_t rn = pread(fh->fd, cbuf.data(), clen, static_cast<off_t>(coffset));
    if (rn != static_cast<ssize_t>(clen)) return -EIO;
  
    // Dercypt
    std::vector<uint8_t> pbuf(plain);
    uint8_t nonce[NONCE_SIZE];
    util::enc::make_chunk_nonce(fh->nonce_base, i, nonce);
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

int fs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
  (void)path;
  auto *fh = reinterpret_cast<FH*>(static_cast<uintptr_t>(fi->fh));
  if (!fh) return -EBADF;

  // Honor O_APPEND 
  // Apply per-FH mutex later
  if (fi->flags & O_APPEND) offset = static_cast<off_t>(fh->plain_len);

  const uint8_t *in = reinterpret_cast<const uint8_t*>(buf);
  size_t l = size;
  uint64_t i = util::fs::chunk_index(offset);
  size_t o = util::fs::chunk_off(offset);
  uint64_t cur_offset = offset;

  while (l > 0){
    //size_t plain = CHUNK_SIZE;
    
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
      uint64_t coffset = util::fs::cipher_chunk_off(i);
      size_t clen = ex_len + TAG_SIZE;
      std::vector<uint8_t> cbuf(clen);
      ssize_t rn = pread(fh->fd, cbuf.data(), clen, static_cast<off_t>(coffset));
      if (rn != static_cast<ssize_t>(clen)) return -EIO;
      uint8_t nonce[NONCE_SIZE];
      util::enc::make_chunk_nonce(fh->nonce_base, i, nonce);
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
    util::enc::make_chunk_nonce(fh->nonce_base, i, nonce);
    if (aesgcm_encrypt(fh->file_key.data(), nonce,
                       pbuf.data(), out_plen,
                       cbuf.data(), cbuf.data() + out_plen) != 0) return -EIO;
    
    uint64_t coffset = util::fs::cipher_chunk_off(i);
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
    uint64_t be = util::enc::htobe_u64(fh->plain_len);
    if (util::fs::update_plain_len(fh->fd, be) != 0) return -EIO;
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

