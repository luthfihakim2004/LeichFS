#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <sys/types.h>
#include <vector>

#include "enc/crypto.hpp"
#include "enc/header.hpp"
#include "enc/params.hpp"
#include "fs/core.hpp"
#include "fs/io.hpp"
#include "util.hpp"

namespace fs {

// ── Internal helpers ─────────────────────────────────────────────────────────

// Build and return a fully initialised FH on the heap, or nullptr on any error
// (errno / *out_err set to a negative FUSE errno on failure).
//
// fd_raw    : already-opened O_RDWR fd; ownership transfers into the returned FH.
// h         : validated header read from fd_raw.
// oflags    : the original fi->flags from the FUSE call.
// init_len  : the plaintext length to initialise shared state with.
// out_err   : set to a negative errno on failure.
static std::unique_ptr<FH> make_fh(int         fd_raw,
                                   const enc::Header& h,
                                   int         oflags,
                                   uint64_t    init_len,
                                   int&        out_err) {
  auto fh = std::make_unique<FH>();
  fh->fd      = util::unique_fd{fd_raw};
  fh->oflags  = oflags;
  fh->chunk_sz = h.chunk_sz;
  fh->wr      = (oflags & O_ACCMODE) != O_RDONLY;

  fh->shared = fs::ctx()->registry.acquire(fd_raw, init_len);
  if (!fh->shared) { out_err = -EIO; return nullptr; }

  // Derive per-file key material from the master key (stored in FSCtx)
  // and the per-file salt (stored in the on-disk header).
  // The master key never leaves FSCtx after mount time.
  if (enc::derive_file_material(fs::ctx()->master_key.raw(), h.salt,
                                fh->file_key.raw(), fh->nonce_base) != 0) {
    out_err = -EIO;
    return nullptr;
  }
  // master_key stays in FSCtx — never copied, never zeroed here.

  util::enc::build_aad_prefix(fh->aad_prefix, h);
  out_err = 0;
  return fh;
}

// Build the full 40-byte AAD for chunk_idx and store it in aad_out[].
static inline void make_aad(const FH& fh, uint64_t chunk_idx,
                             uint8_t aad_out[enc::AAD_PREFIX_LEN + 8]) {
  util::enc::build_aad(aad_out, fh.aad_prefix, chunk_idx);
}


// ── fs_create ────────────────────────────────────────────────────────────────

int fs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
  util::parent_path pp;
  if (int rc = util::fs::walk_parent(ctx()->rootfd.get(), path, pp); rc != 0)
    return rc;

  // Build backing-fd flags.
  // O_ACCMODE is cleared and O_RDWR forced to enforce read-modify-write.
  // O_APPEND must be stripped: if set on the backing fd, pwrite(2) ignores its
  // offset argument (Linux semantics) and writes to EOF, corrupting the header
  // and all chunk positions.  FUSE handles append ordering itself by passing the
  // correct offset to fs_write.
  int oflags = fi->flags & ~(O_ACCMODE | O_APPEND | O_TRUNC);
  oflags |= O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW;
  if (fi->flags & O_EXCL) oflags |= O_EXCL;

  util::unique_fd fd{::openat(pp.dirfd.get(),
                              pp.leaf.empty() ? "." : pp.leaf.c_str(),
                              oflags, mode)};
  if (!fd) return -errno;

  // Initialise on-disk header.
  enc::Header h{};
  std::memcpy(h.magic, "LEICHFSX", 8);
  h.version  = enc::ENC_VERSION;
  h.chunk_sz = enc::CHUNK_SIZE;
  if (util::enc::fill_rand(h.salt, enc::SALT_SIZE) != 0) return -EIO;
  h.plain_len_be = util::enc::htobe_u64(0);

  if (enc::write_header(fd.get(), h) != 0) return -EIO;

  int err = 0;
  auto fh = make_fh(fd.get(), h, fi->flags, /*init_len=*/0, err);
  if (!fh) return err;

  (void)fd.release();  // ownership transferred into fh->fd
  fi->fh = reinterpret_cast<uint64_t>(fh.release());
  return 0;
}


// ── fs_open ──────────────────────────────────────────────────────────────────

int fs_open(const char* path, struct fuse_file_info* fi) {
  util::parent_path pp;
  if (int rc = util::fs::walk_parent(ctx()->rootfd.get(), path, pp); rc != 0)
    return rc;

  const int acc = fi->flags & O_ACCMODE;
  int oflags = O_CLOEXEC | O_NOFOLLOW;
  // Propagate safe status flags the caller requested.
  oflags |= fi->flags & (O_DIRECT | O_SYNC | O_DSYNC
#ifdef O_NOATIME
                         | O_NOATIME
#endif
                         );
  switch (acc) {
      case O_RDONLY: oflags |= O_RDONLY; break;
      case O_WRONLY: oflags |= O_RDWR;   break; // force RDWR to force read-modify-write
      case O_RDWR:   oflags |= O_RDWR;   break;
      default:       return -EINVAL;
  }

  util::unique_fd fd{::openat(pp.dirfd.get(),
                              pp.leaf.empty() ? "." : pp.leaf.c_str(),
                              oflags)};
  if (!fd) return -errno;

  // Reject non-regular files before doing any crypto work.
  struct stat st{};
  if (::fstat(fd.get(), &st) == -1)     return -errno;
  if (!S_ISREG(st.st_mode))             return -EISDIR;

  enc::Header h{};
  if (enc::read_header(fd.get(), h) != 0) return -EIO;

  const uint64_t ondisk_len = util::enc::be64toh_u64(h.plain_len_be);

  int err = 0;
  auto fh = make_fh(fd.get(), h, fi->flags, ondisk_len, err);
  if (!fh) return err;

  // Apply O_TRUNC: zero the logical length and punch off ciphertext.
  if (fh->wr && (fi->flags & O_TRUNC)) {
    std::unique_lock lk(fh->shared->mtx_);
    fh->shared->set_plain_len_unlocked(0);
    util::fs::update_plain_len(fd.get(), 0);
    ::ftruncate(fd.get(), static_cast<off_t>(enc::HEADER_SIZE));
  }

  (void)fd.release();
  fi->fh = reinterpret_cast<uint64_t>(fh.release());
  return 0;
}


// ── fs_read ──────────────────────────────────────────────────────────────────

int fs_read(const char* /*path*/, char* buf, size_t size, off_t offset,
            struct fuse_file_info* fi) {
  auto* fh = reinterpret_cast<FH*>(fi->fh);
  if (!fh) return -EBADF;

  std::shared_lock lk(fh->shared->mtx_);
  const uint64_t limit = fh->shared->plain_len_unlocked();
  const uint64_t off   = static_cast<uint64_t>(offset);

  if (off >= limit) return 0;

  const size_t to_read = std::min(size, static_cast<size_t>(limit - off));
  if (to_read == 0)  return 0;

  auto*          out       = reinterpret_cast<uint8_t*>(buf);
  size_t         done      = 0;
  const uint32_t csz       = fh->chunk_sz;
  uint64_t       chunk_idx = util::fs::chunk_index(off, csz);
  const size_t   first_off = util::fs::chunk_off(off, csz);

  while (done < to_read) {
    const uint64_t chunk_start = chunk_idx * static_cast<uint64_t>(csz);
    const size_t   plain_len   = static_cast<size_t>(
            std::min<uint64_t>(csz, limit - chunk_start));

    const uint64_t coff = util::fs::cipher_chunk_off(chunk_idx, csz);
    const size_t   clen = enc::NONCE_SIZE + plain_len + enc::TAG_SIZE;

    std::vector<uint8_t> cbuf(clen);
    if (util::fs::full_pread(fh->fd.get(), cbuf.data(), clen,
                             static_cast<off_t>(coff)) !=
            static_cast<ssize_t>(clen))
      return -EIO;

    uint8_t aad[enc::AAD_PREFIX_LEN + 8];
    make_aad(*fh, chunk_idx, aad);

    std::vector<uint8_t> pbuf(plain_len);
    if (enc::aesgcm_decrypt(
            fh->file_key.data(),
            cbuf.data(),                              // nonce
            cbuf.data() + enc::NONCE_SIZE, plain_len, // ct
            aad, sizeof(aad),
            cbuf.data() + enc::NONCE_SIZE + plain_len, // tag
            pbuf.data()) != 0)
      return -EBADMSG;

    const size_t src_off = (chunk_idx == util::fs::chunk_index(off, csz))
                         ? first_off : 0;
    const size_t want    = std::min(plain_len - src_off, to_read - done);
    std::memcpy(out + done, pbuf.data() + src_off, want);
    done += want;
    ++chunk_idx;
  }

  return static_cast<int>(done);
}


// ── fs_write ─────────────────────────────────────────────────────────────────

int fs_write(const char* /*path*/, const char* buf, size_t size, off_t offset,
             struct fuse_file_info* fi) {
  auto* fh = reinterpret_cast<FH*>(fi->fh);
  if (!fh || !fh->wr) return -EBADF;

  std::unique_lock lk(fh->shared->mtx_);
  const uint64_t cur_len = fh->shared->plain_len_unlocked();

  // O_APPEND: always write at the current end.
  const uint64_t start_off = (fh->oflags & O_APPEND)
                           ? cur_len
                           : static_cast<uint64_t>(offset);

  if (size > std::numeric_limits<uint64_t>::max() - start_off)
    return -EFBIG;

  const auto*    in  = reinterpret_cast<const uint8_t*>(buf);
  const uint32_t csz = fh->chunk_sz;

  size_t   remaining  = size;
  uint64_t cur_offset = start_off;
  uint64_t chunk_idx  = util::fs::chunk_index(cur_offset, csz);
  size_t   chunk_off_ = util::fs::chunk_off(cur_offset, csz);

  while (remaining > 0) {
    const uint64_t chunk_start = cur_offset - chunk_off_;
    const bool     exists      = chunk_start < cur_len;
    const size_t   ex_len      = exists
        ? static_cast<size_t>(std::min<uint64_t>(csz, cur_len - chunk_start))
        : 0;

    // Build plaintext buffer for this chunk (zero-initialised for grow).
    std::vector<uint8_t> pbuf(std::max(ex_len, static_cast<size_t>(csz)), 0);

    // Read-modify: decrypt existing chunk content if present.
    if (ex_len > 0) {
      const uint64_t coffset = util::fs::cipher_chunk_off(chunk_idx, csz);
      const size_t   clen    = enc::NONCE_SIZE + ex_len + enc::TAG_SIZE;
      std::vector<uint8_t> cbuf(clen);

      if (util::fs::full_pread(fh->fd.get(), cbuf.data(), clen,
                               static_cast<off_t>(coffset)) !=
              static_cast<ssize_t>(clen))
        return -EIO;

      uint8_t aad[enc::AAD_PREFIX_LEN + 8];
      make_aad(*fh, chunk_idx, aad);

      if (enc::aesgcm_decrypt(fh->file_key.data(),
                              cbuf.data(),
                              cbuf.data() + enc::NONCE_SIZE, ex_len,
                              aad, sizeof(aad),
                              cbuf.data() + enc::NONCE_SIZE + ex_len,
                              pbuf.data()) != 0)
        return -EBADMSG;
    }

    // Overlay new data.
    const size_t can = std::min(remaining, csz - chunk_off_);
    std::memcpy(pbuf.data() + chunk_off_, in, can);
    const size_t out_plen = std::max(ex_len, chunk_off_ + can);

    // Encrypt with a nonce: random[8] || be32(chunk_idx).
    const size_t             wlen = enc::NONCE_SIZE + out_plen + enc::TAG_SIZE;
    std::vector<uint8_t>     cbuf(wlen);
    if (util::enc::build_nonce(cbuf.data(), chunk_idx) != 0)
      return -EIO;

    uint8_t aad[enc::AAD_PREFIX_LEN + 8];
    make_aad(*fh, chunk_idx, aad);

    if (enc::aesgcm_encrypt(fh->file_key.data(),
                            cbuf.data(),                      // nonce
                            pbuf.data(), out_plen,
                            aad, sizeof(aad),
                            cbuf.data() + enc::NONCE_SIZE,    // ct
                            cbuf.data() + enc::NONCE_SIZE + out_plen) != 0) // tag
      return -EIO;

    const uint64_t coffset = util::fs::cipher_chunk_off(chunk_idx, csz);
    if (util::fs::full_pwrite(fh->fd.get(), cbuf.data(), wlen,
                              static_cast<off_t>(coffset)) !=
            static_cast<ssize_t>(wlen))
      return -EIO;

    in          += can;
    remaining   -= can;
    cur_offset  += can;
    ++chunk_idx;
    chunk_off_ = 0;
  }

  const uint64_t end_pos = start_off + static_cast<uint64_t>(size);
  if (end_pos > cur_len) {
    fh->shared->set_plain_len_unlocked(end_pos);
    if (util::fs::update_plain_len(fh->fd.get(), end_pos) != 0)
      return -EIO;
  }

  return static_cast<int>(size);
}


// ── fs_flush / fs_release / fs_fsync ─────────────────────────────────────────

int fs_flush(const char* /*path*/, struct fuse_file_info* /*fi*/) {
  return 0;
}

int fs_release(const char* /*path*/, struct fuse_file_info* fi) {
  // ~FH() zeroes file_key via ~secure_array() and closes fd via ~unique_fd().
  delete reinterpret_cast<FH*>(fi->fh);
  fi->fh = 0;
  return 0;
}

int fs_fsync(const char* /*path*/, int /*datasync*/, struct fuse_file_info* fi) {
  auto* fh = reinterpret_cast<FH*>(fi->fh);
  if (!fh) return -EBADF;
  return (::fsync(fh->fd.get()) == -1) ? -errno : 0;
}

off_t fs_lseek(const char* /*path*/, off_t off, int whence,
               struct fuse_file_info* fi) {
  auto* fh = reinterpret_cast<FH*>(fi->fh);
  if (!fh) return -EBADF;

  // SEEK_DATA / SEEK_HOLE are not meaningful for an encrypted file whose
  // "holes" are always written as zeroed ciphertext. Handle SEEK_END
  // against the logical (plaintext) length; delegate the rest to the kernel.
  if (whence == SEEK_END) {
    const off_t len    = static_cast<off_t>(fh->shared->plain_len());
    const off_t result = len + off;
    return result < 0 ? static_cast<off_t>(-EINVAL) : result;
  }

  // For SEEK_SET / SEEK_CUR the kernel lseek on the backing fd gives the
  // right answer for the ciphertext file, but callers expect plaintext
  // offsets. Only SEEK_SET is safe to delegate directly (offset is
  // absolute and unambiguous). SEEK_CUR on the backing fd would return a
  // ciphertext position, which is wrong. Implement both manually.
  switch (whence) {
    case SEEK_SET:
      if (off < 0) return static_cast<off_t>(-EINVAL);
      return off;
    case SEEK_CUR:
      // FUSE does not track the logical file position per-open-handle;
      // that is the caller's responsibility. Return ESPIPE to signal
      // that relative seeks are not supported at the FS layer.
      return static_cast<off_t>(-ESPIPE);
    default:
      return static_cast<off_t>(-EINVAL);
  }
}

// ── fs_fallocate ──────────────────────────────────────────────────────────────
//
// Pre-encrypts zero-filled chunks for the range [offset, offset+length) so
// that subsequent writes into that range become overwrites rather than
// appends.  This avoids the read-modify-write overhead on the first write to
// each fresh chunk.
//
// Only mode == 0 (plain preallocation) is supported.  Punch-hole
// (FALLOC_FL_PUNCH_HOLE) and keep-size (FALLOC_FL_KEEP_SIZE) are rejected
// with EOPNOTSUPP since they have no meaningful semantics for an encrypted file.
int fs_fallocate(const char* /*path*/, int mode, off_t offset, off_t length,
                 struct fuse_file_info* fi) {
    if (mode != 0) return -EOPNOTSUPP;
    if (offset < 0 || length <= 0) return -EINVAL;

    auto* fh = reinterpret_cast<FH*>(fi->fh);
    if (!fh || !fh->wr) return -EBADF;

    const uint64_t new_end = static_cast<uint64_t>(offset)
                           + static_cast<uint64_t>(length);

    std::unique_lock lk(fh->shared->mtx_);
    const uint64_t cur_len = fh->shared->plain_len_unlocked();

    // Nothing to do if the region is already within the allocated length.
    if (new_end <= cur_len) return 0;

    const uint32_t csz = fh->chunk_sz;

    // Walk every chunk that needs to be (pre-)allocated.
    // Chunks that already exist are skipped; only chunks beyond cur_len
    // (or partially filled at the boundary) are written.
    uint64_t pos = cur_len;
    while (pos < new_end) {
      const uint64_t idx     = util::fs::chunk_index(pos, csz);
      const size_t   off_in  = util::fs::chunk_off(pos, csz);
      const size_t   fill    = static_cast<size_t>(
          std::min<uint64_t>(csz - off_in, new_end - pos));

      const uint64_t ch_start = pos - off_in;
      const size_t   ex_len   = ch_start < cur_len
          ? static_cast<size_t>(std::min<uint64_t>(csz, cur_len - ch_start))
          : 0;

      // Build plaintext: decrypt existing prefix if present, zero-fill rest.
      std::vector<uint8_t> pbuf(csz, 0);
      if (ex_len > 0) {
        const uint64_t coffset = util::fs::cipher_chunk_off(idx, csz);
        const size_t   clen    = enc::NONCE_SIZE + ex_len + enc::TAG_SIZE;
        std::vector<uint8_t> cbuf(clen);

        if (util::fs::full_pread(fh->fd.get(), cbuf.data(), clen,
                                 static_cast<off_t>(coffset)) !=
                static_cast<ssize_t>(clen))
          return -EIO;

        uint8_t aad[enc::AAD_PREFIX_LEN + 8];
        make_aad(*fh, idx, aad);

        if (enc::aesgcm_decrypt(fh->file_key.data(),
                                cbuf.data(),
                                cbuf.data() + enc::NONCE_SIZE, ex_len,
                                aad, sizeof(aad),
                                cbuf.data() + enc::NONCE_SIZE + ex_len,
                                pbuf.data()) != 0)
          return -EBADMSG;
      }

      const size_t out_len = std::max(ex_len, off_in + fill);

      // Encrypt and write.
      const size_t         wlen = enc::NONCE_SIZE + out_len + enc::TAG_SIZE;
      std::vector<uint8_t> cbuf(wlen);
      if (util::enc::build_nonce(cbuf.data(), idx) != 0) return -EIO;

      uint8_t aad[enc::AAD_PREFIX_LEN + 8];
      make_aad(*fh, idx, aad);

      if (enc::aesgcm_encrypt(fh->file_key.data(),
                              cbuf.data(),
                              pbuf.data(), out_len,
                              aad, sizeof(aad),
                              cbuf.data() + enc::NONCE_SIZE,
                              cbuf.data() + enc::NONCE_SIZE + out_len) != 0)
        return -EIO;

      const uint64_t coffset = util::fs::cipher_chunk_off(idx, csz);
      if (util::fs::full_pwrite(fh->fd.get(), cbuf.data(), wlen,
                                static_cast<off_t>(coffset)) !=
              static_cast<ssize_t>(wlen))
        return -EIO;

      pos += fill;
    }

    fh->shared->set_plain_len_unlocked(new_end);
    if (util::fs::update_plain_len(fh->fd.get(), new_end) != 0)
      return -EIO;

    return 0;
}

} // namespace fs
