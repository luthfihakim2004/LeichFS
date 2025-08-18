#include "enc.hpp"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>

namespace enc {

static inline uint32_t htobe_u32(uint32_t x){
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return __builtin_bswap32(x);
#else
  return x;
#endif
}
uint64_t htobe_u64(uint64_t x){
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return __builtin_bswap64(x);
#else
  return x;
#endif
}
uint64_t be64toh_u64(uint64_t x){ return htobe_u64(x); }

int load_master_key_from_env(std::array<uint8_t,KEY_SIZE>& out){
  const char* hex = std::getenv("GENTFS_KEY");
  if (!hex) { std::fprintf(stderr, "GENTFS_KEY not set\n"); return -1; }
  // Expect 64 hex chars -> 32 bytes
  size_t n = std::strlen(hex);
  if (n != 64) { std::fprintf(stderr, "GENTFS_KEY must be 64 hex chars\n"); return -1; }
  auto hex2n = [](char c)->int{
    if ('0'<=c && c<='9') return c-'0';
    if ('a'<=c && c<='f') return 10 + c-'a';
    if ('A'<=c && c<='F') return 10 + c-'A';
    return -1;
  };
  for (size_t i=0;i<KEY_SIZE;i++){
    int hi = hex2n(hex[2*i]);
    int lo = hex2n(hex[2*i+1]);
    if (hi<0||lo<0) { std::fprintf(stderr, "GENTFS_KEY invalid hex\n"); return -1; }
    out[i] = (uint8_t)((hi<<4)|lo);
  }
  return 0;
}

int read_header(int fd, Header& h){
  ssize_t n = pread(fd, &h, sizeof(h), 0);
  if (n != (ssize_t)sizeof(h)) return -1;

  static const uint8_t magic[8] = {'G','E','N','T','O','O','F','S'};
  if (std::memcmp(h.magic, magic, 8)!=0) return -2;
  if (h.version != 1) return -3;
  if (h.chunk_sz == 0 || h.chunk_sz > (8u<<20)) return -4; // sanity
  return 0;
}

int write_header(int fd, const Header& h){
  return (pwrite(fd, &h, sizeof(h), 0) == (ssize_t)sizeof(h)) ? 0 : -1;
}

int derive_file_material(const std::array<uint8_t,KEY_SIZE>& master_key,
                         const uint8_t salt[SALT_SIZE],
                         std::array<uint8_t,KEY_SIZE>& file_key,
                         std::array<uint8_t,NONCE_SIZE>& nonce_base) {
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
    static const char info_key[] = "gentfs-file-key";
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

    static const char info_nonce[] = "gentfs-nonce-base";
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

void make_chunk_nonce(const std::array<uint8_t,NONCE_SIZE>& base,
                      uint64_t idx,
                      uint8_t out[NONCE_SIZE]) {
  // Copy base, XOR the last 8 bytes with big-endian idx
  std::memcpy(out, base.data(), NONCE_SIZE);
  uint64_t be = htobe_u64(idx);
  for (int i=0;i<8;i++) out[NONCE_SIZE-8+i] ^= ((uint8_t*)&be)[i];
}

int aesgcm_encrypt(const uint8_t key[KEY_SIZE],
                   const uint8_t nonce[NONCE_SIZE],
                   const uint8_t* pt, size_t pt_len,
                   uint8_t* ct, uint8_t tag[TAG_SIZE]) {
  int ok=0, outl=0, tmplen=0;
  EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
  if (!c) return -1;
  do {
    if (EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr) != 1) break;
    if (EVP_EncryptInit_ex(c, nullptr, nullptr, key, nonce) != 1) break;
    if (EVP_EncryptUpdate(c, ct, &outl, pt, (int)pt_len) != 1) break;
    if (EVP_EncryptFinal_ex(c, ct + outl, &tmplen) != 1) break;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1) break;
    ok = outl + tmplen;
  } while(0);
  EVP_CIPHER_CTX_free(c);
  return (ok == (int)pt_len) ? 0 : -1;
}

int aesgcm_decrypt(const uint8_t key[KEY_SIZE],
                   const uint8_t nonce[NONCE_SIZE],
                   const uint8_t* ct, size_t ct_len,
                   const uint8_t tag[TAG_SIZE],
                   uint8_t* pt) {
  int outl=0, tmplen=0, ok=-1;
  EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
  if (!c) return -1;
  do {
    if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr) != 1) break;
    if (EVP_DecryptInit_ex(c, nullptr, nullptr, key, nonce) != 1) break;
    if (EVP_DecryptUpdate(c, pt, &outl, ct, (int)ct_len) != 1) break;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void*)tag) != 1) break;
    if (EVP_DecryptFinal_ex(c, pt + outl, &tmplen) != 1) break;
    ok = 0;
  } while(0);
  EVP_CIPHER_CTX_free(c);
  return ok;
}

} // namespace enc
