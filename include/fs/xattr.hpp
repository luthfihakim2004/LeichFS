#include <cstddef>

namespace fs {

int gent_getxattr(const char*, const char*, char*, size_t);
int gent_setxattr(const char*, const char*, const char*, size_t, int); 
int gent_listxattr(const char*, char*, size_t);
int gent_removexattr(const char*, const char*);

}

