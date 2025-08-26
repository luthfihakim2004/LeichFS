cmake_minimum_required(VERSION 3.20)
project(gentfs LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Dependencies
find_package(PkgConfig  REQUIRED)
find_package(OpenSSL REQUIRED)
pkg_check_modules(FUSE3 REQUIRED fuse3)

# Library
add_library(leichfs_lib
  lib/util.cpp

  lib/enc/crypto.cpp
  lib/enc/header.cpp

  lib/fs/core.cpp
  lib/fs/dir.cpp
  lib/fs/io.cpp
  lib/fs/lc.cpp
  lib/fs/meta.cpp
  lib/fs/xattr.cpp

  lib/leichfs/dispatch.cpp
)

target_include_directories(leichfs_lib PUBLIC 
  ${FUSE3_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(leichfs_lib PUBLIC
  ${FUSE3_LIBRARIES}
  OpenSSL::Crypto
)

add_executable(leichfs
  src/main.cpp
)

target_link_libraries(leichfs PRIVATE
    leichfs_lib
)

add_compile_options(${FUSE3_CFLAGS_OTHER})
