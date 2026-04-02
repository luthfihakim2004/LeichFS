#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <openssl/evp.h>

#include "enc/params.hpp"

namespace enc {

// ── Key derivation ───────────────────────────────────────────────────────────
//
// Derives per-file key material from the master key and the per-file salt
// using two independent HKDF-SHA256 expansions:
//
//   file_key   = HKDF-Expand(PRK, "leichfs-file-key",   KEY_SIZE)
//   nonce_base = HKDF-Expand(PRK, "leichfs-nonce-base", NONCE_SIZE)
//
// where  PRK = HKDF-Extract(salt, master_key).
//
// Returns 0 on success, -1 on OpenSSL error.
int derive_file_material(
  const std::array<uint8_t, KEY_SIZE>& master_key,
  const uint8_t                        salt[SALT_SIZE],
  std::array<uint8_t, KEY_SIZE>&       file_key,
  std::array<uint8_t, NONCE_SIZE>&     nonce_base);


// ── AES-256-GCM primitives ───────────────────────────────────────────────────
//
// Both functions operate on a single chunk. The caller is responsible for
// supplying a fresh random nonce per encrypt call.
//
// Buffers must NOT alias across {key,nonce,pt/ct,aad,tag} boundaries.
//
// Returns 0 on success, -1 on error (decrypt also returns -1 on tag mismatch).

int aesgcm_encrypt(
  EVP_CIPHER_CTX* ctx,
  const uint8_t  key  [KEY_SIZE],
  const uint8_t  nonce[NONCE_SIZE],
  const uint8_t* pt,   size_t pt_len,
  const uint8_t* aad,  size_t aad_len,
  uint8_t*       ct,                    // caller allocates pt_len bytes
  uint8_t        tag  [TAG_SIZE]);

int aesgcm_decrypt(
  EVP_CIPHER_CTX* ctx,
  const uint8_t  key  [KEY_SIZE],
  const uint8_t  nonce[NONCE_SIZE],
  const uint8_t* ct,   size_t ct_len,
  const uint8_t* aad,  size_t aad_len,
  const uint8_t  tag  [TAG_SIZE],
  uint8_t*       pt);                   // caller allocates ct_len bytes

} // namespace enc
