#include <array>
#include <memory>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include "enc/crypto.hpp"
#include "enc/params.hpp"

namespace enc {

// ── RAII deleters for OpenSSL handles ────────────────────────────────────────
namespace {

struct EvpPkeyCtxDeleter {
  void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); }
};
using UniqueEvpPkeyCtx = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;

struct EvpCipherCtxDeleter {
  void operator()(EVP_CIPHER_CTX* p) const noexcept { EVP_CIPHER_CTX_free(p); }
};
using UniqueEvpCipherCtx = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

// Run one HKDF-SHA256 extract+expand into out[0..outlen]).
// Returns 0 on success, -1 on OpenSSL error.
int hkdf_derive(const uint8_t* key,   size_t key_len,
                const uint8_t* salt,  size_t salt_len,
                const char*    info,  size_t info_len,
                uint8_t*       out,   size_t out_len) {
  UniqueEvpPkeyCtx pctx{EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr)};
  if (!pctx)                                                          return -1;
  if (EVP_PKEY_derive_init(pctx.get()) <= 0)                          return -1;
  if (EVP_PKEY_CTX_set_hkdf_md(pctx.get(), EVP_sha256()) <= 0)        return -1;
  if (EVP_PKEY_CTX_set1_hkdf_salt(pctx.get(), salt,
                                   static_cast<int>(salt_len)) <= 0)  return -1;
  if (EVP_PKEY_CTX_set1_hkdf_key(pctx.get(), key,
                                  static_cast<int>(key_len)) <= 0)    return -1;
  if (EVP_PKEY_CTX_add1_hkdf_info(
          pctx.get(),
          reinterpret_cast<const unsigned char*>(info),
          static_cast<int>(info_len)) <= 0)                           return -1;
  size_t len = out_len;
  if (EVP_PKEY_derive(pctx.get(), out, &len) <= 0)                    return -1;
  return 0;
}

} // anonymous namespace


// ── Public API ────────────────────────────────────────────────────────────────

// Derive key & nonce per-file via HKDF-SHA256
int derive_file_material(
        const std::array<uint8_t, KEY_SIZE>& master_key,
        const uint8_t                        salt[SALT_SIZE],
        std::array<uint8_t, KEY_SIZE>&       file_key,
        std::array<uint8_t, NONCE_SIZE>&     nonce_base) {

  static constexpr char INFO_KEY  [] = "leichfs-file-key";
  static constexpr char INFO_NONCE[] = "leichfs-nonce-base";

  if (hkdf_derive(master_key.data(), KEY_SIZE,
                  salt, SALT_SIZE,
                  INFO_KEY,   sizeof(INFO_KEY)   - 1,
                  file_key.data(), KEY_SIZE) != 0)   return -1;

  if (hkdf_derive(master_key.data(), KEY_SIZE,
                  salt, SALT_SIZE,
                  INFO_NONCE, sizeof(INFO_NONCE) - 1,
                  nonce_base.data(), NONCE_SIZE) != 0) return -1;

  return 0;
}

int aesgcm_encrypt(
        const uint8_t  key  [KEY_SIZE],
        const uint8_t  nonce[NONCE_SIZE],
        const uint8_t* pt,   size_t pt_len,
        const uint8_t* aad,  size_t aad_len,
        uint8_t*       ct,
        uint8_t        tag  [TAG_SIZE]) {

  UniqueEvpCipherCtx c{EVP_CIPHER_CTX_new()};
  if (!c) return -1;

  int outl = 0, tmplen = 0;

  if (EVP_EncryptInit_ex(c.get(), EVP_aes_256_gcm(),
                         nullptr, nullptr, nullptr) != 1)              return -1;
  if (EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_IVLEN,
                          static_cast<int>(NONCE_SIZE), nullptr) != 1) return -1;
  if (EVP_EncryptInit_ex(c.get(), nullptr, nullptr, key, nonce) != 1)  return -1;

  if (aad_len > 0 &&
      EVP_EncryptUpdate(c.get(), nullptr, &tmplen,
                        aad, static_cast<int>(aad_len)) != 1)          return -1;

  if (EVP_EncryptUpdate(c.get(), ct, &outl,
                        pt, static_cast<int>(pt_len)) != 1)            return -1;
  if (EVP_EncryptFinal_ex(c.get(), ct + outl, &tmplen) != 1)           return -1;
  if (EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_GET_TAG,
                          static_cast<int>(TAG_SIZE), tag) != 1)       return -1;

  return (outl + tmplen == static_cast<int>(pt_len)) ? 0 : -1;
}

int aesgcm_decrypt(
        const uint8_t  key  [KEY_SIZE],
        const uint8_t  nonce[NONCE_SIZE],
        const uint8_t* ct,   size_t ct_len,
        const uint8_t* aad,  size_t aad_len,
        const uint8_t  tag  [TAG_SIZE],
        uint8_t*       pt) {

  UniqueEvpCipherCtx c{EVP_CIPHER_CTX_new()};
  if (!c) return -1;

  int outl = 0, tmplen = 0;

  if (EVP_DecryptInit_ex(c.get(), EVP_aes_256_gcm(),
                         nullptr, nullptr, nullptr) != 1)              return -1;
  if (EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_IVLEN,
                          static_cast<int>(NONCE_SIZE), nullptr) != 1) return -1;
  if (EVP_DecryptInit_ex(c.get(), nullptr, nullptr, key, nonce) != 1)  return -1;

  if (aad_len > 0 &&
      EVP_DecryptUpdate(c.get(), nullptr, &tmplen,
                        aad, static_cast<int>(aad_len)) != 1)          return -1;

  if (EVP_DecryptUpdate(c.get(), pt, &outl,
                        ct, static_cast<int>(ct_len)) != 1)            return -1;

  // Set the expected tag BEFORE calling Final (OpenSSL requirement).
  if (EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_TAG,
                          static_cast<int>(TAG_SIZE),
                          const_cast<uint8_t*>(tag)) != 1)             return -1;

  // Final returns <= 0 on authentication failure.
  if (EVP_DecryptFinal_ex(c.get(), pt + outl, &tmplen) <= 0)           return -1;

  return 0;
}

} // namespace enc
