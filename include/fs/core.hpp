#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <sys/types.h>
#include <unordered_map>

#define FUSE_USE_VERSION 35
#include <fuse3/fuse.h>

#include "enc/params.hpp"
#include "util.hpp"

namespace fs {

// ── FKey — identity key for an open inode ────────────────────────────────────
struct FKey {
  dev_t dev{};
  ino_t ino{};
};

inline bool operator==(const FKey& a, const FKey& b) noexcept {
  return a.dev == b.dev && a.ino == b.ino;
}

struct FKeyHash {
  size_t operator()(const FKey& k) const noexcept {
    // Mix dev and ino into one 64-bit value.
    auto x = (static_cast<unsigned long long>(k.dev) << 32)
           ^  static_cast<unsigned long long>(k.ino);
    return std::hash<unsigned long long>{}(x);
  }
};


// ── SharedResState ────────────────────────────────────────────────────────────
//
// Invariants:
//  1. plain_len_ is the maximum known plaintext length across all open FHs for
//     this inode.  It is always >= the on-disk header plain_len_be.
//  2. Read-only operations (read, fsync) take a shared lock.
//     Mutating operations (write, truncate) take a unique lock.
//  3. plain_len_unlocked() may only be called while the caller already holds
//     a unique_lock on mtx (documented at call-sites).
class SharedResState {
public:
  explicit SharedResState(uint64_t init_len,
                          size_t   chunk_sz = enc::CHUNK_SIZE) noexcept
      : plain_len_(init_len), chunk_sz_(chunk_sz) {}

  // Thread-safe accessors with lock acquired internally.
  uint64_t plain_len() const {
    std::shared_lock lk(mtx_);
    return plain_len_;
  }
  void set_plain_len(uint64_t v) {
    std::unique_lock lk(mtx_);
    plain_len_ = v;
  }

  // Unlocked fast-path. PRECONDITION: caller already holds unique_lock(mtx_).
  uint64_t plain_len_unlocked()  const noexcept { return plain_len_; }
  void     set_plain_len_unlocked(uint64_t v)   noexcept { plain_len_ = v; }

  size_t chunk_size() const noexcept { return chunk_sz_; }

  // Lock exposed for callers that need to hold it across multiple operations
  // (e.g., read-modify-write in fs_write / fs_truncate).
  mutable std::shared_mutex mtx_;

private:
  uint64_t plain_len_;
  size_t   chunk_sz_;
};


// ── SharedResRegistry ─────────────────────────────────────────────────────────
//
// Invariants:
//  1. One SharedResState per (dev, ino) pair.
//  2. The registry does NOT own file descriptors.
//  3. Entry lifetime is tied to the shared_ptr refcount; weak_ptr entries are
//     reaped lazily in sweep(), called at the start of every acquire().
class SharedResRegistry {
public:
  // Return (or create) the SharedResState for the inode behind fd.
  // init_len is the on-disk plain_len at open time; if a shared state
  // already exists and holds a larger value, that value is kept.
  std::shared_ptr<SharedResState> acquire(int fd, uint64_t init_len);

private:
  void sweep();

  std::mutex mtx_;
  std::unordered_map<FKey, std::weak_ptr<SharedResState>, FKeyHash> map_;
};


// ── FSCtx — FUSE private_data ─────────────────────────────────────────────────
//
// Owns the root directory fd, the master key, and the shared-state registry.
// Lifetime: allocated in main(), freed in fs_destroy().
struct FSCtx {
  util::unique_fd                          rootfd;
  util::secure_array<enc::KEY_SIZE>        master_key;  // zeroed in ~FSCtx()
  SharedResRegistry                        registry;
};

// Convenience accessor (only valid inside a FUSE callback)
inline FSCtx* ctx() noexcept {
  return static_cast<FSCtx*>(fuse_get_context()->private_data);
}


// ── FH — per-open-file handle ─────────────────────────────────────────────────
//
// Invariants:
//  1. FH owns fd via unique_fd — no manual close() needed.
//  2. file_key is a secure_array — automatically zeroed on destruction.
//  3. shared is always non-null after a successful open/create.
//  4. ~FH() is sufficient cleanup; no explicit teardown needed.
struct FH {
  util::unique_fd fd;
  int oflags{0};

  uint32_t chunk_sz{enc::CHUNK_SIZE};

  // Per-file cryptographic material. Derived once at open time
  util::secure_array<enc::KEY_SIZE>          file_key;
  std::array<uint8_t, enc::NONCE_SIZE>       nonce_base{};
  std::array<uint8_t, enc::AAD_PREFIX_LEN>   aad_prefix{};

  std::shared_ptr<SharedResState> shared;

  bool wr{false}; // true when opened with write access

  // Convenience: returns current known plaintext length and acquires shared locked
  uint64_t plain_len() const { return shared->plain_len(); }
};

} // namespace fs
