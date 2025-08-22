#pragma once
#include "fs/core.hpp"

namespace leichfs {

const fuse_operations* leichfs_ops() noexcept;

}// namespace
