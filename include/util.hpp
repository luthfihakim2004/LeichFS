#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <string>
#include <unistd.h>

#include "enc/params.hpp"
#include "enc/header.hpp"

// ────────────────────────────────────────────────────────────────────────────
// util — RAII wrappers and free functions
//
// Design rules:
//  • No "using namespace" in headers — callers choose their own pollution level.
//  • Every OS handle is wrapped; raw ints never escape a function scope.
//  • secure_array<N> zeroes its buffer on destruction via OPENSSL_cleanse.
// ────────────────────────────────────────────────────────────────────────────

namespace util {

// ── unique_fd ────────────────────────────────────────────────────────────────
// RAII wrapper for a POSIX file descriptor.
class unique_fd {
public:
  unique_fd() noexcept = default;
  explicit unique_fd(int fd) noexcept : fd_(fd) {}

  ~unique_fd() { reset(); }

  unique_fd(const unique_fd&)            = delete;
  unique_fd& operator=(const unique_fd&) = delete;

  unique_fd(unique_fd&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
  unique_fd& operator=(unique_fd&& o) noexcept {
      if (this != &o) { reset(); fd_ = o.fd_; o.fd_ = -1; }
      return *this;
  }

  int  get()     const noexcept { return fd_; }
  bool valid()   const noexcept { return fd_ >= 0; }
  explicit operator bool() const noexcept { return valid(); }

  // Release ownership without closing. Caller now owns the fd.
  [[nodiscard]] int release() noexcept { int t = fd_; fd_ = -1; return t; }

  // Close current fd and optionally adopt a new one.
  void reset(int newfd = -1) noexcept {
    if (fd_ >= 0) ::close(fd_);
    fd_ = newfd;
  }

private:
  int fd_ = -1;
};

// ── unique_dir ───────────────────────────────────────────────────────────────
// RAII wrapper for a DIR*.
class unique_dir {
public:
  explicit unique_dir(DIR* dp) noexcept : dp_(dp) {}
  ~unique_dir() { if (dp_) ::closedir(dp_); }

  unique_dir(const unique_dir&)            = delete;
  unique_dir& operator=(const unique_dir&) = delete;

  DIR* get() const noexcept { return dp_; }
  explicit operator bool() const noexcept { return dp_ != nullptr; }

private:
  DIR* dp_ = nullptr;
};

// ── secure_array<N> ──────────────────────────────────────────────────────────
// Fixed-size byte array that is zeroed via OPENSSL_cleanse on destruction.
// Prevents key material lingering in freed memory.
template<size_t N>
class secure_array {
public:
  secure_array() noexcept { buf_.fill(0); }
  ~secure_array() { OPENSSL_cleanse(buf_.data(), buf_.size()); }

  secure_array(const secure_array&)            = delete;
  secure_array& operator=(const secure_array&) = delete;

  uint8_t*       data()       noexcept { return buf_.data(); }
  const uint8_t* data() const noexcept { return buf_.data(); }
  constexpr size_t size() const noexcept { return N; }

  std::array<uint8_t, N>&       raw()       noexcept { return buf_; }
  const std::array<uint8_t, N>& raw() const noexcept { return buf_; }

private:
  std::array<uint8_t, N> buf_;
};

// ── parent_path ──────────────────────────────────────────────────────────────
// Result of walk_parent(): an open directory fd and the final path component.
struct parent_path {
  unique_fd   dirfd;
  std::string leaf;
};

// ── Path helpers ─────────────────────────────────────────────────────────────

// Open path as O_PATH|O_DIRECTORY with RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS.
// Returns a valid unique_fd on success, an invalid one on failure (errno set).
unique_fd validate_root_path(const char* path);

} // namespace util


// ────────────────────────────────────────────────────────────────────────────
// util::fs — filesystem helpers
// ────────────────────────────────────────────────────────────────────────────
namespace util::fs {

// Retry-on-EINTR pread/pwrite that treat short results as errors (return < n).
ssize_t full_pread (int fd, void*       buf, size_t n, off_t offset);
ssize_t full_pwrite(int fd, const void* buf, size_t n, off_t offset);

// Chunk arithmetic (all sizes in plaintext bytes).
uint64_t chunk_index    (uint64_t offset, size_t chunk_sz);
size_t   chunk_off      (uint64_t offset, size_t chunk_sz);
uint64_t cipher_chunk_off(uint64_t chunk_idx, size_t chunk_sz);  // byte offset of chunk in ciphertext file
uint64_t cipher_tail_off (uint64_t chunk_idx, size_t plain_tail, size_t chunk_sz); // end of partial last chunk

// Atomically patch the 8-byte plain_len_be field in the on-disk header.
// new_plain_len is in host byte order; the function converts to big-endian.
// Calls fdatasync(fd) before returning.
int update_plain_len(int fd, uint64_t new_plain_len_host);

// Walk all but the last component of an absolute FUSE path starting at rootfd.
// On success, out.dirfd is an open O_PATH fd for the parent directory and
// out.leaf is the final component name (empty string means the root itself).
int walk_parent(int rootfd, const char* path, util::parent_path& out);

// openat(dirfd, name, oflags|O_CLOEXEC|O_NOFOLLOW) — convenience wrapper.
util::unique_fd leaf_nofollow(int dirfd, const char* name, int oflags = O_RDONLY);

} // namespace util::fs


// ────────────────────────────────────────────────────────────────────────────
// util::enc — cryptographic helpers
// ────────────────────────────────────────────────────────────────────────────
namespace util::enc {

// Load a 32-byte master key from a keyfile.
// The file must contain exactly 32 raw binary bytes OR 64 lowercase hex chars.
// The fd is closed by the caller; this function only reads from it.
// Returns 0 on success, -1 on any error.
int load_master_key_from_file(const char* path,
                              std::array<uint8_t, ::enc::KEY_SIZE>& out);

// Fill p[0..n] with cryptographically secure random bytes via getrandom(2).
// Returns 0 on success, -1 on error.
int fill_rand(void* p, size_t n);

// Portable big-endian conversion helpers.
uint64_t htobe_u64(uint64_t x) noexcept;
uint32_t htobe_u32(uint32_t x) noexcept;
uint64_t be64toh_u64(uint64_t x) noexcept;

// Build the 40-byte AAD block:  aad_prefix[AAD_PREFIX_LEN] || be64(chunk_idx).
// out must point to at least AAD_PREFIX_LEN + 8 bytes.
void build_aad(uint8_t* out,
               const std::array<uint8_t, ::enc::AAD_PREFIX_LEN>& prefix,
               uint64_t chunk_idx) noexcept;

// Build a 12-byte GCM nonce: random[8] || be32(chunk_idx).
// The random prefix prevents reuse across rewrites of the same chunk index.
// The chunk_idx suffix prevents reuse within a single file write session.
// Returns 0 on success, -1 on getrandom failure.
int build_nonce(uint8_t nonce[::enc::NONCE_SIZE], uint64_t chunk_idx) noexcept;

// Build the AAD prefix from a validated header and store it in out.
// Call once per open/create; cache result in FH::aad_prefix.
void build_aad_prefix(std::array<uint8_t, ::enc::AAD_PREFIX_LEN>& out,
                      const ::enc::Header& h) noexcept;

} // namespace util::enc
