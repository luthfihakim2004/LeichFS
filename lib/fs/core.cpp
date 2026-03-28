#include <memory>
#include <mutex>
#include <sys/stat.h>

#include "fs/core.hpp"

namespace fs {

void SharedResRegistry::sweep() {
  // Caller must NOT hold mtx_
  std::lock_guard lk(mtx_);
  for (auto it = map_.begin(); it != map_.end(); ) {
    if (it->second.expired()) it = map_.erase(it);
    else ++it;
  }
}

std::shared_ptr<SharedResState>
SharedResRegistry::acquire(int fd, uint64_t init_len) {
  sweep(); // Prune dead entries before inserting.

  struct stat st{};
  if (::fstat(fd, &st) == -1) return {};

  FKey key{st.st_dev, st.st_ino};

  std::lock_guard lk(mtx_);

  if (auto it = map_.find(key); it != map_.end()) {
    if (auto sp = it->second.lock()) {
      // Keep the higher of the two lengths.
      if (init_len > sp->plain_len())
        sp->set_plain_len(init_len);
      return sp;
    }
  }

  auto sp = std::make_shared<SharedResState>(init_len);
  map_[key] = sp;
  return sp;
}

} // namespace fs
