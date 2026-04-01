# Overview
An on-the-fly AES-256-GCM encrypted FUSE filesystem inspired by [gocryptfs](https://github.com/rfjakob/gocryptfs). Implemented in C++20 using RAII to ensure correct resource and key-material lifecycle management.

## Features

- Per-file key isolation
- Authenticated encryption with chunk level AAD
- Clean resource lifecycle management, thanks to RAII
- Passphrase-protected master key, similar to gocryptfs
- Support partial and full backup

## Limitations

- No forward secrecy
- No hard link support
- No metadata encryption
- No deniability features
- Only supported on Linux (FUSE3)

## Security

See [DESIGN.md](Documentation/DESIGN.md)

## Backup

Since each file is independently encrypted with its own key, it is possible to back up a subset of files. The important part is to make sure the config file is still available because it is where the wrapped key (wrapped master key) is stored.

__While creating a backup, you might want to unmount the filesystem first to avoid capturing a mid-write file.__

## Requirements 

- Linux kernel 5.6+ (uses `openat2`, `getrandom`, `renameat2`)
- FUSE 3.10+
- OpenSSL 3.0+
- libargon2

## License

See [LICENSE](LICENSE)
