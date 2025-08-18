cmake_minimum_required(VERSION 3.20)
project(gentfs LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(PkgConfig  REQUIRED)
find_package(OpenSSL REQUIRED)
pkg_check_modules(FUSE3 REQUIRED fuse3)

add_executable(gentfs
  src/main.cpp
  src/fs_ops.cpp
  src/util.cpp
  src/enc.cpp
)

target_include_directories(gentfs PRIVATE
  ${FUSE3_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(gentfs PRIVATE
  ${FUSE3_LIBRARIES}
  OpenSSL::Crypto
)

add_compile_options(${FUSE3_CFLAGS_OTHER})
