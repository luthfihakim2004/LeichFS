#include <cstring>
#include <sys/types.h>
#include <unistd.h>

#include "enc/header.hpp"

namespace enc {

int read_header(int fd, Header& h) {
  ssize_t n = ::pread(fd, &h, sizeof(h), 0);
  if (n != static_cast<ssize_t>(sizeof(h))) return -1;

  static constexpr uint8_t MAGIC[8] = {'L','E','I','C','H','F','S','X'};
  if (std::memcmp(h.magic, MAGIC, 8) != 0)                    return -2;
  if (h.version != ENC_VERSION)                                return -3;
  if (h.chunk_sz == 0 || h.chunk_sz > (8u << 20))             return -4; // safety bound
  if (h.chunk_sz != CHUNK_SIZE)                                return -5;
  return 0;
}

int write_header(int fd, const Header& h) {
  return (::pwrite(fd, &h, sizeof(h), 0) == static_cast<ssize_t>(sizeof(h))) ? 0 : -1;
}

} // namespace enc
