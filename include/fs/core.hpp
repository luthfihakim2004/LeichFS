#pragma once 

#define FUSE_USE_VERSION 35
#include <fuse3/fuse.h>


namespace fs {

// Context
struct FSCtx{
  int rootfd;
};

static inline FSCtx* ctx(){
  return static_cast<FSCtx*>(fuse_get_context()->private_data);
}

}
