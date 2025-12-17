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

- Batching I/O
- Lock Scope Reduction (?)
- Crypto ops optimization (skip on specified case)
- Consider caching a per‑file nonce_base and forming nonce = nonce_base ⊕ encrypt(chunk_index) for speed. Still ensure uniqueness & 96‑bit size.

## AAD

For any file `F` and write of `N` bytes at offset `O`, `AAD(F, O+N)` is unique, authenticated, and collision-free.
