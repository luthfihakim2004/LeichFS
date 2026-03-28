#pragma once
#include <cstddef>
#include <cstdint>

#include "enc/params.hpp"

namespace enc {

// On-disk file header — 64 bytes, packed, no padding.
// All multi-byte fields stored in the endianness documented per-field.
#pragma pack(push, 1)
struct Header {
  uint8_t  magic[8];        // "LEICHFSX"
  uint32_t version;         // little-endian; currently 1
  uint32_t chunk_sz;        // little-endian; plaintext bytes per chunk
  uint8_t  salt[SALT_SIZE]; // per-file random salt for HKDF
  uint8_t  reserved[24];    // zeroed; reserved for future use
  uint64_t plain_len_be;    // big-endian; canonical plaintext byte count
};
#pragma pack(pop)

inline constexpr size_t HEADER_SIZE = sizeof(Header);
static_assert(HEADER_SIZE == 64, "Header layout/size mismatch");

// Read and validate header from fd at offset 0.
// Returns  0 on success.
// Returns -1 on short read / IO error.
// Returns -2 on bad magic.
// Returns -3 on unsupported version.
// Returns -4 on implausible chunk_sz.
int read_header(int fd, Header& h);

// Write header to fd at offset 0. Returns 0 on success, -1 on error.
int write_header(int fd, const Header& h);

} // namespace enc
