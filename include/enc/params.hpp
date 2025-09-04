#pragma once
#include <cstdint>
#include <cstddef>

namespace enc {
inline constexpr uint32_t ENC_VERSION     = 1;
inline constexpr uint32_t CHUNK_SIZE      = 64 * 1024; // 64 KiB
inline constexpr size_t   TAG_SIZE        = 16;        // GCM tag
inline constexpr size_t   SALT_SIZE       = 16;        // per-file salt
inline constexpr size_t   KEY_SIZE        = 32;        // AES-256
inline constexpr size_t   NONCE_SIZE      = 12;        // GCM standard
inline constexpr size_t   CHUNK_STRIDE    = NONCE_SIZE + CHUNK_SIZE + TAG_SIZE;   // IV | Chunk | Tag
inline constexpr size_t   AAD_PREFIX_LEN  = 8 + 4 + 4 + SALT_SIZE;                // magic | version | chunk | salt 
} // namespace enc
