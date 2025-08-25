#pragma once
#include <cstdint>
#include <cstddef>
#include "params.hpp"

namespace enc {

#pragma pack(push, 1)
struct Header {
  uint8_t  magic[8];        // "LEICHFSX"
  uint32_t version;         // 1
  uint32_t chunk_sz;        // 65536
  uint8_t  salt[SALT_SIZE]; // per-file
  uint8_t  reserved[24];    // future / alignment
  uint64_t plain_len_be;    // big-endian
};
#pragma pack(pop)

inline constexpr size_t HEADER_SIZE = sizeof(Header);
static_assert(HEADER_SIZE == 64, "Header layout/size mismatch");

int read_header(int fd, Header& h);
int write_header(int fd, const Header& h);

} // namespace enc
