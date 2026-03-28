#include <cerrno>
#include <cstdint>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <memory>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <linux/fs.h>
#include <unistd.h>
#include <vector>

#include "enc/crypto.hpp"
#include "enc/header.hpp"
#include "enc/params.hpp"
#include "fs/core.hpp"
#include "fs/meta.hpp"
#include "util.hpp"

namespace fs {

// ── fs_getattr ────────────────────────────────────────────────────────────────

int fs_getattr(const char* path, struct stat* st, struct fuse_file_info* /*fi*/) {
  std::memset(st, 0, sizeof(*st));

  util::parent_path pp;
  if (int rc = util::fs::walk_parent(ctx()->rootfd.get(), path, pp); rc != 0)
    return rc;

  const char* item = pp.leaf.empty() ? "." : pp.leaf.c_str();

  if (::fstatat(pp.dirfd.get(), item, st, AT_SYMLINK_NOFOLLOW) == -1)
    return -errno;

  if (S_ISREG(st->st_mode)) {
    util::unique_fd fd{::openat(pp.dirfd.get(), item,
                                O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (!fd) return -errno;

    enc::Header h{};
    if (enc::read_header(fd.get(), h) == 0)
      st->st_size = static_cast<off_t>(util::enc::be64toh_u64(h.plain_len_be));
    // fd closed automatically by ~unique_fd()
  }

  return 0;
}


// ── fs_readlink ───────────────────────────────────────────────────────────────

int fs_readlink(const char* path, char* buf, size_t size) {
  util::parent_path pp;
  if (int rc = util::fs::walk_parent(ctx()->rootfd.get(), path, pp); rc != 0)
      return rc;

  char tmp[PATH_MAX];
  ssize_t n = ::readlinkat(pp.dirfd.get(), pp.leaf.c_str(), tmp, sizeof(tmp) - 1);
  if (n == -1) return -errno;
  tmp[n] = '\0';

  if (size == 0) return 0;
  const size_t to_cp = std::min<size_t>(static_cast<size_t>(n), size - 1);
  std::memcpy(buf, tmp, to_cp);
  buf[to_cp] = '\0';
  return 0;
}


// ── fs_readdir ────────────────────────────────────────────────────────────────

int fs_readdir(const char* path, void* buf, fuse_fill_dir_t filler,
               off_t /*off*/, struct fuse_file_info* /*fi*/,
               enum fuse_readdir_flags /*flags*/) {
  util::parent_path pp;
  if (int rc = util::fs::walk_parent(ctx()->rootfd.get(), path, pp); rc != 0)
    return rc;

  const char* item = pp.leaf.empty() ? "." : pp.leaf.c_str();
  util::unique_fd dfd{::openat(pp.dirfd.get(), item,
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)};
  if (!dfd) return -errno;

  // fdopendir takes ownership of the fd; wrap in unique_dir so it's closed
  // by closedir when we're done.
  util::unique_dir dp{::fdopendir(dfd.get())};
  if (!dp) return -errno;
  // fdopendir now owns the fd — prevent double-close.
  (void)dfd.release();

  filler(buf, ".",  nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
  filler(buf, "..", nullptr, 0, static_cast<fuse_fill_dir_flags>(0));

  errno = 0;
  for (;;) {
    struct dirent* de = ::readdir(dp.get());
    if (!de) break;

    if (de->d_name[0] == '.' &&
       (de->d_name[1] == '\0' ||
       (de->d_name[1] == '.' && de->d_name[2] == '\0')))
        continue;

    struct stat st{};
    bool has_stat = false;

    st.st_ino = de->d_ino;
    switch (de->d_type) {
        case DT_REG:  st.st_mode = S_IFREG;  has_stat = true; break;
        case DT_DIR:  st.st_mode = S_IFDIR;  has_stat = true; break;
        case DT_LNK:  st.st_mode = S_IFLNK;  has_stat = true; break;
        case DT_CHR:  st.st_mode = S_IFCHR;  has_stat = true; break;
        case DT_BLK:  st.st_mode = S_IFBLK;  has_stat = true; break;
        case DT_FIFO: st.st_mode = S_IFIFO;  has_stat = true; break;
        case DT_SOCK: st.st_mode = S_IFSOCK; has_stat = true; break;
        case DT_UNKNOWN:
        default:
            if (::fstatat(::dirfd(dp.get()), de->d_name,
                          &st, AT_SYMLINK_NOFOLLOW) == 0)
              has_stat = true;
            else if (errno == ENOENT) continue;
            break;
    }

    if (filler(buf, de->d_name,
               has_stat ? &st : nullptr,
               0, static_cast<fuse_fill_dir_flags>(0)))
      return 0;
  }

  return errno ? -errno : 0;
}


// ── Directory / metadata mutations ───────────────────────────────────────────

int fs_mkdir(const char* path, mode_t mode) {
  util::parent_path pp;
  if (int rc = util::fs::walk_parent(ctx()->rootfd.get(), path, pp); rc != 0)
    return rc;
  return ::mkdirat(pp.dirfd.get(), pp.leaf.c_str(), mode) == -1 ? -errno : 0;
}

int fs_unlink(const char* path) {
  util::parent_path pp;
  if (int rc = util::fs::walk_parent(ctx()->rootfd.get(), path, pp); rc != 0)
    return rc;
  return ::unlinkat(pp.dirfd.get(), pp.leaf.c_str(), 0) == -1 ? -errno : 0;
}

int fs_rmdir(const char* path) {
  util::parent_path pp;
  if (int rc = util::fs::walk_parent(ctx()->rootfd.get(), path, pp); rc != 0)
    return rc;
  return ::unlinkat(pp.dirfd.get(), pp.leaf.c_str(), AT_REMOVEDIR) == -1 ? -errno : 0;
}

int fs_symlink(const char* to, const char* from) {
  util::parent_path pp;
  if (int rc = util::fs::walk_parent(ctx()->rootfd.get(), from, pp); rc != 0)
    return rc;
  return ::symlinkat(to, pp.dirfd.get(), pp.leaf.c_str()) == -1 ? -errno : 0;
}

int fs_rename(const char* from, const char* to, unsigned int flags) {
  util::parent_path fpp, tpp;
  if (int rc = util::fs::walk_parent(ctx()->rootfd.get(), from, fpp); rc != 0) return rc;
  if (int rc = util::fs::walk_parent(ctx()->rootfd.get(), to,   tpp); rc != 0) return rc;

#if defined(__linux__) && defined(__NR_renameat2)
  int ok = static_cast<int>(::syscall(__NR_renameat2,
                                       fpp.dirfd.get(), fpp.leaf.c_str(),
                                       tpp.dirfd.get(), tpp.leaf.c_str(),
                                       flags));
  return ok == -1 ? -errno : 0;
#else
  if (flags != 0) return -ENOTSUP;
  return ::renameat(fpp.dirfd.get(), fpp.leaf.c_str(),
                    tpp.dirfd.get(), tpp.leaf.c_str()) == -1 ? -errno : 0;
#endif
}

int fs_chmod(const char* path, mode_t mode, struct fuse_file_info* /*fi*/) {
  util::parent_path pp;
  if (int rc = util::fs::walk_parent(ctx()->rootfd.get(), path, pp); rc != 0)
    return rc;
  const char* item = pp.leaf.empty() ? "." : pp.leaf.c_str();
  return ::fchmodat(pp.dirfd.get(), item, mode, 0) == -1 ? -errno : 0;
}

int fs_chown(const char* path, uid_t uid, gid_t gid, struct fuse_file_info* /*fi*/) {
  util::parent_path pp;
  if (int rc = util::fs::walk_parent(ctx()->rootfd.get(), path, pp); rc != 0)
    return rc;
  const char* item = pp.leaf.empty() ? "." : pp.leaf.c_str();
  return ::fchownat(pp.dirfd.get(), item, uid, gid, AT_SYMLINK_NOFOLLOW) == -1
         ? -errno : 0;
}

int fs_utimens(const char* path, const struct timespec tv[2],
               struct fuse_file_info* /*fi*/) {
  util::parent_path pp;
  if (int rc = util::fs::walk_parent(ctx()->rootfd.get(), path, pp); rc != 0)
    return rc;
  const char* item = pp.leaf.empty() ? "." : pp.leaf.c_str();
  return ::utimensat(pp.dirfd.get(), item, tv, AT_SYMLINK_NOFOLLOW) == -1
         ? -errno : 0;
}


// ── fs_truncate ───────────────────────────────────────────────────────────────
//
// Called with fi->fh set (file is open) or fi == nullptr / fi->fh == 0 (called
// on a path with no open handle, e.g. from ftruncate(2) on a different fd).

int fs_truncate(const char* path, off_t size, struct fuse_file_info* fi) {
  // ── Obtain FH ──────────────────────────────────────────────────────────
  FH* fh = (fi && fi->fh) ? reinterpret_cast<FH*>(fi->fh) : nullptr;

  // If we don't have an open FH, build a temporary one on the stack.
  // unique_ptr so ~FH() runs (zeroes key, closes fd) on every exit path.
  std::unique_ptr<FH> temp_fh;
  if (!fh) {
    util::parent_path pp;
    if (int rc = util::fs::walk_parent(ctx()->rootfd.get(), path, pp); rc != 0)
      return rc;

    util::unique_fd fd{::openat(pp.dirfd.get(),
                                pp.leaf.empty() ? "." : pp.leaf.c_str(),
                                O_RDWR | O_CLOEXEC | O_NOFOLLOW)};
    if (!fd) return -errno;

    enc::Header h{};
    if (enc::read_header(fd.get(), h) != 0) return -EINVAL;

    temp_fh = std::make_unique<FH>();
    temp_fh->fd       = std::move(fd);
    temp_fh->chunk_sz = h.chunk_sz;

    // Derive crypto material.
    if (enc::derive_file_material(fs::ctx()->master_key.raw(), h.salt,
                                  temp_fh->file_key.raw(),
                                  temp_fh->nonce_base) != 0)    return -EIO;

    util::enc::build_aad_prefix(temp_fh->aad_prefix, h);

    // Shared state: use the on-disk length as the initial value.
    const uint64_t ondisk_len = util::enc::be64toh_u64(h.plain_len_be);
    temp_fh->shared = fs::ctx()->registry.acquire(temp_fh->fd.get(), ondisk_len);
    if (!temp_fh->shared) return -EIO;

    fh = temp_fh.get();
  }

  // ── Perform truncation under exclusive lock ────────────────────────────
  std::unique_lock lk(fh->shared->mtx_);

  const uint64_t old_len = fh->shared->plain_len_unlocked();
  const uint64_t new_len = static_cast<uint64_t>(size);
  if (new_len == old_len) return 0;

  const uint32_t csz = fh->chunk_sz;

  // Helper: build AAD for a chunk index.
  auto make_aad = [&](uint64_t idx, uint8_t out[enc::AAD_PREFIX_LEN + 8]) {
    util::enc::build_aad(out, fh->aad_prefix, idx);
  };

  // Helper: read + decrypt one chunk from disk.
  // Returns the plaintext in pbuf (resized to ex_len).  Returns -EIO / -EBADMSG.
  auto read_chunk = [&](uint64_t idx, size_t ex_len,
                        std::vector<uint8_t>& pbuf) -> int {
    const uint64_t coffset = util::fs::cipher_chunk_off(idx, csz);
    const size_t   clen    = enc::NONCE_SIZE + ex_len + enc::TAG_SIZE;
    std::vector<uint8_t> cbuf(clen);

    if (util::fs::full_pread(fh->fd.get(), cbuf.data(), clen,
                             static_cast<off_t>(coffset)) !=
            static_cast<ssize_t>(clen))
      return -EIO;

    pbuf.resize(ex_len);
    uint8_t aad[enc::AAD_PREFIX_LEN + 8];
    make_aad(idx, aad);

    return enc::aesgcm_decrypt(fh->file_key.data(),
                               cbuf.data(),
                               cbuf.data() + enc::NONCE_SIZE, ex_len,
                               aad, sizeof(aad),
                               cbuf.data() + enc::NONCE_SIZE + ex_len,
                               pbuf.data());
  };

  // Helper: encrypt pbuf (plain_len bytes) and write chunk idx back to disk.
  auto write_chunk = [&](uint64_t idx,
                         const std::vector<uint8_t>& pbuf,
                         size_t plain_len) -> int {
    const size_t         wlen = enc::NONCE_SIZE + plain_len + enc::TAG_SIZE;
    std::vector<uint8_t> cbuf(wlen);
    if (util::enc::build_nonce(cbuf.data(), idx) != 0)
      return -EIO;

    uint8_t aad[enc::AAD_PREFIX_LEN + 8];
    make_aad(idx, aad);

    if (enc::aesgcm_encrypt(fh->file_key.data(),
                            cbuf.data(),
                            pbuf.data(), plain_len,
                            aad, sizeof(aad),
                            cbuf.data() + enc::NONCE_SIZE,
                            cbuf.data() + enc::NONCE_SIZE + plain_len) != 0)
      return -EIO;

    const uint64_t coffset = util::fs::cipher_chunk_off(idx, csz);
    if (util::fs::full_pwrite(fh->fd.get(), cbuf.data(), wlen,
                              static_cast<off_t>(coffset)) !=
            static_cast<ssize_t>(wlen))
      return -EIO;
    
    return 0;
  };

  // ── SHRINK ────────────────────────────────────────────────────────────
  if (new_len < old_len) {
    const uint64_t last_chunk = new_len / csz;
    const size_t   tail_len   = static_cast<size_t>(new_len % csz);

    if (tail_len > 0) {
      // The last surviving chunk needs to be re-encrypted at the new size.
      const uint64_t ch_start = last_chunk * static_cast<uint64_t>(csz);
      const size_t   ex_len   = ch_start < old_len
          ? static_cast<size_t>(std::min<uint64_t>(csz, old_len - ch_start))
          : 0;

      std::vector<uint8_t> pbuf;
      if (ex_len > 0) {
        if (int rc = read_chunk(last_chunk, ex_len, pbuf); rc != 0)
          return rc == -1 ? -EIO : -EBADMSG;
      } else {
        pbuf.assign(tail_len, 0);
      }
      pbuf.resize(tail_len); // truncate to new size

      if (int rc = write_chunk(last_chunk, pbuf, tail_len); rc != 0)
        return rc;

      const uint64_t cut = util::fs::cipher_tail_off(last_chunk, tail_len, csz);
      if (::ftruncate(fh->fd.get(), static_cast<off_t>(cut)) == -1)
        return -errno;
    } else {
      // Exact chunk boundary — just punch off ciphertext.
      const uint64_t cut = util::fs::cipher_chunk_off(last_chunk, csz);
      if (::ftruncate(fh->fd.get(), static_cast<off_t>(cut)) == -1)
        return -errno;
    }

  // ── GROW ──────────────────────────────────────────────────────────────
  } else {
    uint64_t pos = old_len;
    while (pos < new_len) {
      const uint64_t idx        = util::fs::chunk_index(pos, csz);
      const size_t   off_in     = util::fs::chunk_off(pos, csz);
      const size_t   fill_bytes = static_cast<size_t>(
          std::min<uint64_t>(csz - off_in, new_len - pos));

      const uint64_t ch_start = pos - off_in;
      const size_t   ex_len   = ch_start < old_len
          ? static_cast<size_t>(std::min<uint64_t>(csz, old_len - ch_start))
          : 0;

      std::vector<uint8_t> pbuf(csz, 0);
      if (ex_len > 0) {
        std::vector<uint8_t> existing;
        if (int rc = read_chunk(idx, ex_len, existing); rc != 0)
          return rc == -1 ? -EIO : -EBADMSG;
        std::memcpy(pbuf.data(), existing.data(), ex_len);
      }
      // New bytes are already zero.

      const size_t out_len = std::max(ex_len, off_in + fill_bytes);
      if (int rc = write_chunk(idx, pbuf, out_len); rc != 0)
        return rc;

      pos += fill_bytes;
    }
  }

  // ── Commit new logical length ─────────────────────────────────────────
  fh->shared->set_plain_len_unlocked(new_len);
  if (util::fs::update_plain_len(fh->fd.get(), new_len) != 0)
    return -EIO;

  return 0;
  // temp_fh (if created) is destroyed here: ~FH() closes fd and zeroes key.
}


// ── fs_statfs ────────────────────────────────────────────────────────────────

int fs_statfs(const char* /*path*/, struct statvfs* st) {
  if (!st) return -EINVAL;
  if (::fstatvfs(ctx()->rootfd.get(), st) == -1) return -errno;
  st->f_namemax = std::min<unsigned long>(st->f_namemax, 255UL);
  return 0;
}


// ── fs_access ────────────────────────────────────────────────────────────────
//
// NOTE: leichfs should be mounted with -o default_permissions.
// When that option is active the kernel performs all access checks itself
// using the uid/gid/mode returned by fs_getattr, and this function is never
// called.  The implementation below is a best-effort fallback for the rare
// case where the caller omits default_permissions.

int fs_access(const char* path, int mask) {
  struct stat st{};
  if (int rc = fs_getattr(path, &st, nullptr); rc != 0) return rc;

  const auto* c = ::fuse_get_context();
  if (!c)          return -EIO;
  if (c->uid == 0) return 0; // bypass root permission check

  if (mask == F_OK) return 0; // existence already confirmed by fs_getattr

  const uid_t  uid = c->uid;
  const gid_t  gid = c->gid;
  const mode_t m   = st.st_mode;

  // Select the permission bits applicable to this caller.
  mode_t applicable;
  if (uid == st.st_uid)      applicable = (m >> 6) & 7;
  else if (gid == st.st_gid) applicable = (m >> 3) & 7;
  else                       applicable = m & 7;

  // R_OK=4, W_OK=2, X_OK=1 map directly onto rwx bits.
  if ((mask & R_OK) && !(applicable & 4)) return -EACCES;
  if ((mask & W_OK) && !(applicable & 2)) return -EACCES;
  if ((mask & X_OK) && !(applicable & 1)) return -EACCES;

  return 0;
}

} // namespace fs
