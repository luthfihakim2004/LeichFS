#pragma once
#include <cstdint>
#include <cstddef>
#include <array>

namespace enc {

// Tunables
static constexpr uint32_t ENC_VERSION = 1;
static constexpr uint32_t CHUNK_SIZE    = 64 * 1024;   // 64 KiB
static constexpr size_t   TAG_SIZE      = 16;          // GCM tag
static constexpr size_t   SALT_SIZE     = 16;          // per-file salt
static constexpr size_t   KEY_SIZE      = 32;          // AES-256
static constexpr size_t   NONCE_SIZE    = 12;          // GCM standard
//static constexpr size_t   HEADER_SIZE   = 64;          // fixed

// 64-byte header at start of each file (plaintext)
#pragma pack(push, 1)
struct Header {
  uint8_t  magic[8];        // "GENTOOFS"
  uint32_t version;         // 1
  uint32_t chunk_sz;        // 65536
  uint8_t  salt[SALT_SIZE]; // random per file
  uint8_t  reserved[24];    // future / alignment
  uint64_t plain_len_be;    // big-endian plaintext size
};
#pragma pack(pop)

static constexpr size_t HEADER_SIZE = sizeof(Header);
static_assert(HEADER_SIZE == 64, "Header layout/size mismatch");

struct FH {
  int      fd{-1};                             // ciphertext file fd
  uint32_t chunk_sz{CHUNK_SIZE};
  uint64_t plain_len{0};                       // bytes
  std::array<uint8_t,KEY_SIZE>   file_key{};   // derived via HKDF
  std::array<uint8_t,NONCE_SIZE> nonce_base{}; // derived via HKDF
};

// Master key handling
// Returns 0 on success; master_key must be 32 bytes (binary).
int load_master_key_from_env(std::array<uint8_t,KEY_SIZE>& out);

// Header I/O
int read_header(int fd, Header& h);
int write_header(int fd, const Header& h);

// Endian helpers
uint64_t htobe_u64(uint64_t x);
uint64_t be64toh_u64(uint64_t x);

// Derivations
int derive_file_material(const std::array<uint8_t,KEY_SIZE>& master_key,
                         const uint8_t salt[SALT_SIZE],
                         std::array<uint8_t,KEY_SIZE>& file_key,
                         std::array<uint8_t,NONCE_SIZE>& nonce_base);

// Nonce for chunk i = nonce_base with last 8 bytes XOR chunk_index (big-endian)
void make_chunk_nonce(const std::array<uint8_t,NONCE_SIZE>& base,
                      uint64_t chunk_idx,
                      uint8_t out[NONCE_SIZE]);

// AES-GCM primitives (bufs may alias)
int aesgcm_encrypt(const uint8_t key[KEY_SIZE],
                   const uint8_t nonce[NONCE_SIZE],
                   const uint8_t* pt, size_t pt_len,
                   uint8_t* ct, uint8_t tag[TAG_SIZE]);

int aesgcm_decrypt(const uint8_t key[KEY_SIZE],
                   const uint8_t nonce[NONCE_SIZE],
                   const uint8_t* ct, size_t ct_len,
                   const uint8_t tag[TAG_SIZE],
                   uint8_t* pt);

} // namespace enc
