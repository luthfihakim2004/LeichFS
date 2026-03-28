cmake_minimum_required(VERSION 3.21)
project(leichfs LANGUAGES CXX)

set(CMAKE_CXX_STANDARD          20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

# ── Dependencies ─────────────────────────────────────────────────────────────
find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE3   REQUIRED IMPORTED_TARGET fuse3)
pkg_check_modules(OPENSSL REQUIRED IMPORTED_TARGET openssl)
pkg_check_modules(ARGON2  REQUIRED IMPORTED_TARGET libargon2)

# ── Shared include path ───────────────────────────────────────────────────────
set(LEICHFS_INCLUDE ${CMAKE_SOURCE_DIR}/include)

# ── Source groups ─────────────────────────────────────────────────────────────
set(SOURCES_ENC
    lib/enc/crypto.cpp
    lib/enc/header.cpp
)

set(SOURCES_FS
    lib/fs/core.cpp
    lib/fs/dir.cpp
    lib/fs/io.cpp
    lib/fs/lc.cpp
    lib/fs/meta.cpp
    lib/fs/xattr.cpp
)

set(SOURCES_LEICHFS
    lib/leichfs/dispatch.cpp
    lib/leichfs/init.cpp
)

set(SOURCES_UTIL
    lib/util.cpp
)

# ── Executable ───────────────────────────────────────────────────────────────
add_executable(leichfs
    src/main.cpp
    ${SOURCES_ENC}
    ${SOURCES_FS}
    ${SOURCES_LEICHFS}
    ${SOURCES_UTIL}
)

target_include_directories(leichfs PRIVATE ${LEICHFS_INCLUDE})

target_link_libraries(leichfs PRIVATE
    PkgConfig::FUSE3
    PkgConfig::OPENSSL
    PkgConfig::ARGON2
)

target_compile_options(leichfs PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wshadow
    -Wno-unused-parameter   # FUSE callbacks have mandatory-but-unused path args
    -fstack-protector-strong
    $<$<CONFIG:Release>:-O2>
    $<$<CONFIG:Debug>:-O0 -g3 -fsanitize=address,undefined>
)

target_link_options(leichfs PRIVATE
    $<$<CONFIG:Debug>:-fsanitize=address,undefined>
)

# ── Install ───────────────────────────────────────────────────────────────────
include(GNUInstallDirs)
install(TARGETS leichfs RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
