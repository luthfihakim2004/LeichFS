#pragma once 

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <shared_mutex>
#include <sys/types.h>
#define FUSE_USE_VERSION 35
#include <fuse3/fuse.h>
#include <array>

#include "enc/params.hpp"

namespace fs {

// Context
struct FSCtx{
  int rootfd;
};

static inline FSCtx* ctx(){
  return static_cast<FSCtx*>(fuse_get_context()->private_data);
}

struct SharedResState{
  std::shared_mutex mtx;
  uint64_t plain_len = 0;
  size_t chunk_sz = enc::CHUNK_SIZE;
};

// File handler
struct FH {
  int      fd{-1};                             // ciphertext file fd
  uint32_t chunk_sz{enc::CHUNK_SIZE};
  uint64_t plain_len{0};                       // bytes
  std::array<uint8_t,enc::KEY_SIZE>   file_key{};   // derived via HKDF
  std::array<uint8_t,enc::NONCE_SIZE> nonce_base{}; // derived via HKDF
  std::shared_ptr<SharedResState> shared;
  bool wr = true;
};


struct FKey { dev_t dev; ino_t ino; };
struct FKeyHash{
  size_t operator()(const FKey& k) const {
    return std::hash<unsigned long long>()((static_cast<unsigned long long>(k.dev) << 32) ^ static_cast<unsigned long long>(k.ino));
  }
};

inline bool operator==(const FKey& a, const FKey& b){
  return a.dev==b.dev && a.ino==b.ino;
}

std::shared_ptr<SharedResState> get_shared(int fd, uint64_t init_len);

}


