#include <array>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>

#include "enc/params.hpp"

namespace enc {

// HKDF Context
int derive_file_material(const std::array<uint8_t, KEY_SIZE> &master_key, const uint8_t *salt, std::array<uint8_t, KEY_SIZE> &file_key, std::array<uint8_t, NONCE_SIZE> &nonce_base){
  // HKDF-Extract(master, salt) then Expand with labels
  int rc = -1;
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (!pctx) return -1;

  do {
    if (EVP_PKEY_derive_init(pctx) <= 0) break;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) break;
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, SALT_SIZE) <= 0) break;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, master_key.data(), KEY_SIZE) <= 0) break;

    // Expand for file_key
    static const char info_key[] = "leichfs-file-key";
    if (EVP_PKEY_CTX_add1_hkdf_info(
      pctx,
      reinterpret_cast<const unsigned char*>(info_key),
      static_cast<int>(sizeof(info_key))-1) <= 0) break;
    size_t outlen = KEY_SIZE;
    if (EVP_PKEY_derive(pctx, file_key.data(), &outlen) <= 0) break;

    // Reset info for nonce_base
    // Simplest: re-init derive for second expand (new context)
    EVP_PKEY_CTX_free(pctx);
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) break;
    if (EVP_PKEY_derive_init(pctx) <= 0) break;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) break;
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, SALT_SIZE) <= 0) break;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, master_key.data(), KEY_SIZE) <= 0) break;

    static const char info_nonce[] = "leichfs-nonce-base";
    if (EVP_PKEY_CTX_add1_hkdf_info(
      pctx,
      reinterpret_cast<const unsigned char*>(info_nonce),
      static_cast<int>(sizeof(info_nonce))-1) <= 0) break;
    size_t nlen = NONCE_SIZE;
    if (EVP_PKEY_derive(pctx, nonce_base.data(), &nlen) <= 0) break;

    rc = 0;
  } while(0);

  EVP_PKEY_CTX_free(pctx);
  return rc;
}

int aesgcm_encrypt(const uint8_t key[KEY_SIZE],
                   const uint8_t nonce[NONCE_SIZE],
                   const uint8_t* pt, size_t pt_len,
                   const uint8_t* aad, size_t aad_len,
                   uint8_t* ct, uint8_t tag[TAG_SIZE]) {
  int ok=0, outl=0, tmplen=0;
  EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
  if (!c) return -1;
  do {
    // Init new context with key + iv
    if (EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break; // Init a new cipher context for encryption
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr) != 1) break; // Set the IV length based on the NONCE_SIZE
    if (EVP_EncryptInit_ex(c, nullptr, nullptr, key, nonce) != 1) break;

    if (aad_len > 0 && EVP_EncryptUpdate(c, nullptr, &tmplen, aad, (int)aad_len) != 1) break;

    if (EVP_EncryptUpdate(c, ct, &outl, pt, (int)pt_len) != 1) break;
    if (EVP_EncryptFinal_ex(c, ct + outl, &tmplen) != 1) break;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1) break;        // Export the tag per chunk
    ok = outl + tmplen;
  } while(0);
  EVP_CIPHER_CTX_free(c);             // Free the encryption context
  return (ok == (int)pt_len) ? 0 : -1;
}

int aesgcm_decrypt(const uint8_t key[KEY_SIZE],
                   const uint8_t nonce[NONCE_SIZE],
                   const uint8_t* ct, size_t ct_len,
                   const uint8_t* aad, size_t aad_len,
                   const uint8_t tag[TAG_SIZE],
                   uint8_t* pt) {
  int outl=0, tmplen=0, ok=-1;
  EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
  if (!c) return -1;
  do {
    // Init new context
    if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;    // New cipher context
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr) != 1) break;    // Set then IV
    if (EVP_DecryptInit_ex(c, nullptr, nullptr, key, nonce) != 1) break;
    
    if (aad_len > 0 && EVP_DecryptUpdate(c, nullptr, &tmplen, aad, (int)aad_len) != 1) break;
    
    if (EVP_DecryptUpdate(c, pt, &outl, ct, (int)ct_len) != 1) break;                   
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void*)tag) != 1) break;     // Verify the tag per encrypted chunk
    if (EVP_DecryptFinal_ex(c, pt + outl, &tmplen) != 1) break;
    ok = 0;
  } while(0);
  EVP_CIPHER_CTX_free(c);             // Free the decryption context
  return ok;
}

}

