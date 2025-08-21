#include <sys/types.h>
#include <unistd.h>
#include <cstring>

#include "enc/header.hpp"

namespace enc {

int read_header(int fd, Header& h){
  ssize_t n = pread(fd, &h, sizeof(h), 0);
  if (n != (ssize_t)sizeof(h)) return -1;

  static const uint8_t magic[8] = {'L','E','I','C','H','F','S','X'};
  if (std::memcmp(h.magic, magic, 8)!=0) return -2;
  if (h.version != 1) return -3;
  if (h.chunk_sz == 0 || h.chunk_sz > (8u<<20)) return -4; // sanity
  return 0;
};

int write_header(int fd, const Header& h){
  return (pwrite(fd, &h, sizeof(h), 0) == (ssize_t)sizeof(h)) ? 0 : -1;
}

}
