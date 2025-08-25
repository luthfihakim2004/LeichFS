#include "fs/dir.hpp"

namespace fs {

int fs_fsyncdir(const char *, int, struct fuse_file_info *){
  return 0;
}

}

