#include <sys/types.h>
#include <cstdint>
#include <array>

#include "params.hpp"

namespace enc {

// Derivations
int derive_file_material(const std::array<uint8_t,KEY_SIZE>& master_key,
                         const uint8_t salt[SALT_SIZE],
                         std::array<uint8_t,KEY_SIZE>& file_key,
                         std::array<uint8_t,NONCE_SIZE>& nonce_base);


// AES-GCM primitives (bufs may alias)
int aesgcm_encrypt(const uint8_t key[KEY_SIZE],
                   const uint8_t nonce[NONCE_SIZE],
                   const uint8_t* pt, size_t pt_len,
                   uint8_t* ct, uint8_t tag[TAG_SIZE]);

int aesgcm_decrypt(const uint8_t key[KEY_SIZE],
                   const uint8_t nonce[NONCE_SIZE],
                   const uint8_t* ct, size_t ct_len,
                   const uint8_t tag[TAG_SIZE],
                   uint8_t* pt);

}

