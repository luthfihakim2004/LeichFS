#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>     // std::getenv
#include <fcntl.h>
#include <pwd.h>       // getpwuid, getpwnam
#include <sys/random.h>
#include <sys/types.h>
#include <unistd.h>    // getuid
#include <vector>
#include <array>
#include <cstring>
#include <sys/syscall.h>
#include <linux/openat2.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>

#include "fs/core.hpp"
#include "util.hpp"
#include "enc/params.hpp"
#include "enc/header.hpp"


namespace util {

std::string expand_args(const std::string& path) {
  if (path.empty() || path[0] != '~') return path;

  if (path.size() == 1 || path[1] == '/') {
      const char* h = std::getenv("HOME");
      if (!h) {
          if (auto* pw = getpwuid(getuid())) h = pw->pw_dir;
      }
      return (h ? std::string(h) : std::string()) + path.substr(1);
  }

  size_t slash = path.find('/');
  std::string user = path.substr(1, (slash == std::string::npos ? std::string::npos : slash - 1));
  if (auto* pw = getpwnam(user.c_str())) {
      std::string home = pw->pw_dir;
      return home + (slash == std::string::npos ? "" : path.substr(slash));
  }
  return path;
}

std::string rstrip_slash(std::string p) {
  if (p.size() > 1 && p.back() == '/') p.pop_back();
  return p;
}

int validate_path(const char *path){
  struct open_how how{};
  how.flags   = O_PATH | O_DIRECTORY | O_CLOEXEC;
  how.resolve = 
    //RESOLVE_BENEATH |
    RESOLVE_NO_SYMLINKS |
    RESOLVE_NO_MAGICLINKS;
    //RESOLVE_NO_XDEV;
  int fd = syscall(SYS_openat2, AT_FDCWD, path, &how, sizeof(how));
  return fd;
}

}

namespace util::fs {

ssize_t full_pread(int fd, void *buf, size_t n, off_t offset){
  uint8_t *p = static_cast<uint8_t*>(buf);
  
  size_t done = 0;
  while (done < n){
    ssize_t r = pread(fd, p+done, n-done, offset + (off_t)done);
    if (r < 0){
      if (errno==EINTR) continue;
      return -1;
    }
    if (r == 0) break; // EOF
    done += (size_t)r;
  }
  return (ssize_t)done;
}

ssize_t full_pwrite(int fd, const void *buf, size_t n, off_t offset){
  const uint8_t *p = static_cast<const uint8_t*>(buf);
  
  size_t done = 0;
  while (done < n){
    ssize_t w = pwrite(fd, p+done, n-done, offset + (off_t)done);
    if (w < 0){
      if (errno==EINTR) continue;
      return -1;
    }
    if (w == 0) break; // EOF
    done += (size_t)w;
  }
  return (ssize_t)done;
}

int update_plain_len(int fd, uint64_t new_plain_len){
  off_t offset = static_cast<off_t>(offsetof(Header, plain_len_be));
  ssize_t n = pwrite(fd, &new_plain_len, sizeof(new_plain_len), offset);
  return (n == static_cast<ssize_t>(sizeof(new_plain_len))) ? 0 : -1;
}

std::vector<std::string> split_components(const char *path){
  std::vector<std::string> out;
  const char *p = path;
  if(*p == '/') ++p;
  while (*p){
    const char *start = p;
    while (*p && *p != '/') ++p;
    if (p > start) out.emplace_back(start, p - start);
    if (*p == '/') ++p;
  }
  return out;
}

int walk_parent(int rootfd, const char *path, int &out_dirfd, std::string &leaf){
  if (!path || !*path) return -EINVAL;

  auto parts = split_components(path);
  if (parts.empty()){
    out_dirfd = dup(rootfd);
    if (out_dirfd == -1) return -errno;
    leaf.clear();
    return 0;
  }

  for (auto &s : parts){
    if (s == "." || s == ".." || s.empty()) return -EINVAL;
  }

  int dirfd = dup(rootfd);
  if (dirfd == -1) return -errno;

  for (size_t i = 0; i + 1 < parts.size(); ++i){
    int next = openat(dirfd, parts[i].c_str(), O_NOFOLLOW | O_PATH | O_DIRECTORY);
    if (next == -1){
      close(dirfd);
      return -errno;
    }
    close(dirfd);
    dirfd = next;
  }

  out_dirfd = dirfd;
  leaf = parts.back();
  return 0;
}

int leaf_nofollow(int dirfd, const char *name, int oflags){
  return openat(dirfd, (name && *name) ? name : ".", oflags | O_CLOEXEC | O_NOFOLLOW);
}


}

namespace util::enc {


int load_master_key_from_env(std::array<uint8_t,KEY_SIZE>& out){
  const char* hex = std::getenv("GENTFS_KEY");
  if (!hex) { std::fprintf(stderr, "GENTFS_KEY not set\n"); return -1; }
  // Expect 64 hex chars -> 32 bytes
  size_t n = std::strlen(hex);
  if (n != 64) { std::fprintf(stderr, "GENTFS_KEY must be 64 hex chars\n"); return -1; }
  auto hex2n = [](char c)->int{
    if ('0'<=c && c<='9') return c-'0';
    if ('a'<=c && c<='f') return 10 + c-'a';
    if ('A'<=c && c<='F') return 10 + c-'A';
    return -1;
  };
  for (size_t i=0;i<KEY_SIZE;i++){
    int hi = hex2n(hex[2*i]);
    int lo = hex2n(hex[2*i+1]);
    if (hi<0||lo<0) { std::fprintf(stderr, "GENTFS_KEY invalid hex\n"); return -1; }
    out[i] = (uint8_t)((hi<<4)|lo);
  }
  return 0;

}

int fill_rand(void *p, size_t n){
  uint8_t *out = static_cast<uint8_t*>(p);
  size_t off = 0;
  while(off < n){
    ssize_t m = getrandom(out + off, n - off, 0);
    if (m < 0){
      if (errno == EINTR) continue;
      return -1;
    }
    off += static_cast<size_t>(m);
  }
  return 0;
}


uint64_t htobe_u64(uint64_t x){
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return __builtin_bswap64(x);
#else
  return x;
#endif

}

uint64_t be64toh_u64(uint64_t x){
return htobe_u64(x);
}

void make_chunk_nonce(const std::array<uint8_t,NONCE_SIZE>& base,
                      uint64_t idx,
                      uint8_t out[NONCE_SIZE]){
  // Copy base, XOR the last 8 bytes with big-endian idx
  std::memcpy(out, base.data(), NONCE_SIZE);
  uint64_t be = htobe_u64(idx);
  for (int i=0;i<8;i++) out[NONCE_SIZE-8+i] ^= ((uint8_t*)&be)[i];

}


}

