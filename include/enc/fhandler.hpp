#pragma once
#include <cstdint>
#include <array>

#include "params.hpp"

namespace enc {

struct FH {
  int      fd{-1};                             // ciphertext file fd
  uint32_t chunk_sz{CHUNK_SIZE};
  uint64_t plain_len{0};                       // bytes
  std::array<uint8_t,KEY_SIZE>   file_key{};   // derived via HKDF
  std::array<uint8_t,NONCE_SIZE> nonce_base{}; // derived via HKDF
};

}
