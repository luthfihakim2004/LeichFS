#include "util.hpp"
#include <cstdlib>     // std::getenv
#include <pwd.h>       // getpwuid, getpwnam
#include <unistd.h>    // getuid

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
}
