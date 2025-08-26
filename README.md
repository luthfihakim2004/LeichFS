# Overview

## Progress

- Implemented op hooks:
  - File operations: open, read, write, release, create, truncate, flush, fsync
  - Directory operations:  readdir, mkdir, rmdir, rename (renameat2 supported)
  - Metadate operations: getattr, chmod, chown, utimens
  - Links: symlink, readlink
  - Extended attributes: getxattr, setxattr, listxattr, removexattr
- Support parallel I/O with shared locking to avoid race condition.

## To Do 

- Resolve nonce reuse risk with per-chunk random nonce.
