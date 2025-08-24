#pragma once
#include <cstddef>
#include <string>
#include <cstdint>
#include <unistd.h>

#include "enc/params.hpp"
#include "enc/header.hpp"
#include "fs/core.hpp"

using namespace enc;
using namespace fs;

namespace util {

std::string expand_args(const std::string& path);

std::string rstrip_slash(std::string p);

int validate_path(const char* path);

namespace enc {

// Master key handling (TEMPORARY)
// Returns 0 on success; master_key must be 32 bytes (binary).
int load_master_key_from_env(std::array<uint8_t,KEY_SIZE>& out);

// Ensure randomness has enough size
int fill_rand(void* p, size_t n);

// Endian helpers
uint64_t htobe_u64(uint64_t x);
uint64_t be64toh_u64(uint64_t x);


// Nonce for chunk i = nonce_base with last 8 bytes XOR chunk_index (big-endian)
void make_chunk_nonce(const std::array<uint8_t,NONCE_SIZE>& base,
                      uint64_t chunk_idx,
                      uint8_t out[NONCE_SIZE]);

}


namespace fs {

constexpr uint64_t chunk_index(uint64_t offset){ return offset / CHUNK_SIZE;}

constexpr size_t chunk_off(uint64_t offset){ return static_cast<size_t>(offset % CHUNK_SIZE);}

constexpr uint64_t cipher_chunk_off(uint64_t i){
  return HEADER_SIZE + i * static_cast<uint64_t>(CHUNK_SIZE + TAG_SIZE);
}
constexpr uint64_t cipher_tail_off(uint64_t full, size_t plain){
  return HEADER_SIZE + full * static_cast<uint64_t>(CHUNK_SIZE + TAG_SIZE) + static_cast<uint64_t>(plain + TAG_SIZE);
}

int update_plain_len(int fd, uint64_t new_plain_len);

int walk_parent(int rootfd, const char *path, int &out_dirfd, std::string &leaf);

int leaf_nofollow(int dirfd, const char *name, int oflags = O_RDONLY);
}

}
