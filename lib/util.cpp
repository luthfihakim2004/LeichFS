#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fcntl.h>
#include <pwd.h>
#include <sys/random.h>
#include <sys/types.h>
#include <unistd.h>
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

int update_plain_len(int fd, uint64_t new_plain_len_host) {
  // Sanity: make sure we're writing the correct field
  static_assert(HEADER_SIZE == 64, "Header size unexpected");
  static_assert(offsetof(Header, plain_len_be) == 56, "plain_len offset mismatch");

 // // Identify the target file (dev, ino) for debugging
 // struct stat st{};
 // if (fstat(fd, &st) == -1) {
 //   int se = errno;
 //   fprintf(stderr, "[HDRLEN] fstat failed errno=%d (%m)\n", se);
 //   return -1;
 // }
 // const off_t off = static_cast<off_t>(offsetof(Header, plain_len_be));

 // uint64_t be = util::enc::htobe_u64(new_plain_len_host);
 // ssize_t n = pwrite(fd, &be, sizeof(be), off);
 // if (n != (ssize_t)sizeof(be)) {
 //   int se = errno;
 //   fprintf(stderr, "[HDRLEN] pwrite failed n=%zd errno=%d (%m) dev=%ju ino=%ju off=%lld\n",
 //           n, se, (uintmax_t)st.st_dev, (uintmax_t)st.st_ino, (long long)off);
 //   return -1;
 // }

 // // Force it out; if this fails we want to see it.
 // if (fsync(fd) == -1) {
 //   int se = errno;
 //   fprintf(stderr, "[HDRLEN] fsync failed errno=%d (%m) dev=%ju ino=%ju\n",
 //           se, (uintmax_t)st.st_dev, (uintmax_t)st.st_ino);
 //   return -1;
 // }

 // // Read back to confirm the exact bytes on this fd
 // uint64_t rb = 0;
 // ssize_t rn = pread(fd, &rb, sizeof(rb), off);
 // if (rn != (ssize_t)sizeof(rb)) {
 //   int se = errno;
 //   fprintf(stderr, "[HDRLEN] pread failed rn=%zd errno=%d (%m) dev=%ju ino=%ju off=%lld\n",
 //           rn, se, (uintmax_t)st.st_dev, (uintmax_t)st.st_ino, (long long)off);
 //   return -1;
 // }

 // fprintf(stderr,
 //   "[HDRLEN] dev=%ju ino=%ju write host=%llu be=%016llx read_be=%016llx @%lld\n",
 //   (uintmax_t)st.st_dev, (uintmax_t)st.st_ino,
 //   (unsigned long long)new_plain_len_host,
 //   (unsigned long long)be, (unsigned long long)rb, (long long)off);

  Header h{};
  if (read_header(fd, h) != 0) { /* log & return */ }
  h.plain_len_be = util::enc::htobe_u64(new_plain_len_host);

  // write whole header from offset 0
  ssize_t wn = pwrite(fd, &h, sizeof(h), 0);
  if (wn != (ssize_t)sizeof(h)) { fprintf(stderr,"[HDRLEN] full header write failed (%m)\n"); return -1; }
  fsync(fd);

  // read back just the len again
  uint64_t rb=0; pread(fd, &rb, sizeof(rb), 56);
  fprintf(stderr,"[HDRLEN] after full header write read_be=%016llx\n", (unsigned long long)rb);
  return 0;
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

uint64_t chunk_index(uint64_t offset, size_t sz){ return offset / sz;}
size_t chunk_off(uint64_t offset, size_t sz){ return static_cast<size_t>(offset % sz);}
uint64_t cipher_chunk_off(uint64_t i, size_t sz){
  return HEADER_SIZE + i * static_cast<uint64_t>(NONCE_SIZE + sz + TAG_SIZE);
}
uint64_t cipher_tail_off(uint64_t full, size_t plain, size_t sz){
  //return HEADER_SIZE + full * static_cast<uint64_t>(sz + TAG_SIZE) + static_cast<uint64_t>(plain + TAG_SIZE);
  return cipher_chunk_off(full, sz) + (NONCE_SIZE + plain + TAG_SIZE);
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
uint32_t htobe_u32(uint32_t x){
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return __builtin_bswap32(x);
#else
  return x;
#endif

}


uint64_t be64toh_u64(uint64_t x){
return htobe_u64(x);
}

}

