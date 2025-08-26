#include <memory>
#include <mutex>
#include <sys/stat.h>
#include <unordered_map>

#include "fs/core.hpp"

namespace fs {

static std::mutex g_map_mtx;
static std::unordered_map<FKey, std::weak_ptr<SharedResState>, FKeyHash> g_map;

std::shared_ptr<SharedResState> get_shared(int fd, uint64_t init_len){
  struct stat st{};
  if(fstat(fd, &st) == -1) return {};

  FKey key(st.st_dev, st.st_ino);

  std::lock_guard<std::mutex> lk(g_map_mtx);
  if (auto it = g_map.find(key); it != g_map.end()){
    if (auto sp = it->second.lock()) return sp;
  }
  auto sp = std::make_shared<SharedResState>();
  sp->plain_len = init_len;
  g_map[key] = sp;
  return sp;
}
}
