#pragma once
#include "fs/core.hpp"

namespace fs {

int fs_fsyncdir(const char*, int, struct fuse_file_info*);

}
