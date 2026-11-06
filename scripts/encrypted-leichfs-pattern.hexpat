#pragma endian little

#include <std/mem.pat>

struct Header {
    char magic[8];
    u32  version;
    u32  chunk_sz;
    u8   salt[16];
    u8   reserved[24];
    u8   plain_len_be[8];
};
Header header @ 0x00;

struct Chunk {
    u8 nonce[12];
    u8 ciphertext[header.chunk_sz];   // uses the size from the header
    u8 tag[16];
};

// Dynamically creates as many chunks as fit in the file
Chunk chunks[while($ < std::mem::size())] @ 0x40;