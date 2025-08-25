#include <cstddef>

namespace fs {

int fs_getxattr(const char*, const char*, char*, size_t);
int fs_setxattr(const char*, const char*, const char*, size_t, int); 
int fs_listxattr(const char*, char*, size_t);
int fs_removexattr(const char*, const char*);

}

