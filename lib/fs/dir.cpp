#include "fs/dir.hpp"

namespace fs {

int fs_fsyncdir(const char* /*path*/, int /*datasync*/,
                struct fuse_file_info* /*fi*/) {
  return 0;
}

} // namespace fs
