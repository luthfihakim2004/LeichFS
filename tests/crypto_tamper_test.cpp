// Tamper-detection tests for LeichFS's AES-256-GCM chunk construction.
//
// These tests deliberately change one authenticated input at a time. An
// untouched record must decrypt; each modified record must be rejected.

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

#include "enc/crypto.hpp"
#include "enc/params.hpp"

namespace {

constexpr size_t AAD_SIZE = enc::AAD_PREFIX_LEN + sizeof(uint64_t);

struct CipherCtxDeleter {
  void operator()(EVP_CIPHER_CTX* ctx) const noexcept { EVP_CIPHER_CTX_free(ctx); }
};
using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;

void store_be32(uint8_t* out, uint32_t value) {
  out[0] = static_cast<uint8_t>(value >> 24U);
  out[1] = static_cast<uint8_t>(value >> 16U);
  out[2] = static_cast<uint8_t>(value >> 8U);
  out[3] = static_cast<uint8_t>(value);
}

void store_be64(uint8_t* out, uint64_t value) {
  for (unsigned i = 0; i < 8; ++i)
    out[i] = static_cast<uint8_t>(value >> (56U - (i * 8U)));
}

std::array<uint8_t, AAD_SIZE> make_aad(uint64_t chunk_index) {
  std::array<uint8_t, AAD_SIZE> aad{};
  std::memcpy(aad.data(), "LEICHFSX", 8);
  store_be32(aad.data() + 8, enc::ENC_VERSION);
  store_be32(aad.data() + 12, enc::CHUNK_SIZE);

  // Fixed test-only per-file salt. Production reads this from the header.
  for (size_t i = 0; i < enc::SALT_SIZE; ++i)
    aad[16 + i] = static_cast<uint8_t>(0xA0U + i);

  store_be64(aad.data() + enc::AAD_PREFIX_LEN, chunk_index);
  return aad;
}

bool decrypt_succeeds(const std::array<uint8_t, enc::KEY_SIZE>& key,
                      const std::array<uint8_t, enc::NONCE_SIZE>& nonce,
                      const std::vector<uint8_t>& ciphertext,
                      const std::array<uint8_t, AAD_SIZE>& aad,
                      const std::array<uint8_t, enc::TAG_SIZE>& tag,
                      std::vector<uint8_t>& plaintext) {
  CipherCtx ctx{EVP_CIPHER_CTX_new()};
  if (!ctx) return false;
  plaintext.assign(ciphertext.size(), 0);
  return enc::aesgcm_decrypt(ctx.get(), key.data(), nonce.data(),
                             ciphertext.data(), ciphertext.size(),
                             aad.data(), aad.size(), tag.data(),
                             plaintext.data()) == 0;
}

bool expect_rejected(std::string_view name,
                     const std::array<uint8_t, enc::KEY_SIZE>& key,
                     const std::array<uint8_t, enc::NONCE_SIZE>& nonce,
                     const std::vector<uint8_t>& ciphertext,
                     const std::array<uint8_t, AAD_SIZE>& aad,
                     const std::array<uint8_t, enc::TAG_SIZE>& tag) {
  std::vector<uint8_t> output;
  if (decrypt_succeeds(key, nonce, ciphertext, aad, tag, output)) {
    std::cerr << "FAIL: " << name << " was accepted\n";
    return false;
  }
  std::cout << "PASS: " << name << " was rejected\n";
  return true;
}

}  // namespace

int main() {
  std::array<uint8_t, enc::KEY_SIZE> key{};
  std::array<uint8_t, enc::NONCE_SIZE> nonce{};
  for (size_t i = 0; i < key.size(); ++i) key[i] = static_cast<uint8_t>(i);
  for (size_t i = 0; i < nonce.size(); ++i) nonce[i] = static_cast<uint8_t>(0x80U + i);

  const std::vector<uint8_t> original{
      'L', 'e', 'i', 'c', 'h', 'F', 'S', ' ', 't', 'a', 'm', 'p', 'e', 'r', ' ',
      't', 'e', 's', 't'};
  const auto aad_for_chunk_zero = make_aad(0);

  CipherCtx encrypt_ctx{EVP_CIPHER_CTX_new()};
  if (!encrypt_ctx) {
    std::cerr << "FAIL: could not allocate OpenSSL encryption context\n";
    return 1;
  }

  std::vector<uint8_t> ciphertext(original.size());
  std::array<uint8_t, enc::TAG_SIZE> tag{};
  if (enc::aesgcm_encrypt(encrypt_ctx.get(), key.data(), nonce.data(),
                          original.data(), original.size(),
                          aad_for_chunk_zero.data(), aad_for_chunk_zero.size(),
                          ciphertext.data(), tag.data()) != 0) {
    std::cerr << "FAIL: encryption failed\n";
    return 1;
  }

  std::vector<uint8_t> recovered;
  if (!decrypt_succeeds(key, nonce, ciphertext, aad_for_chunk_zero, tag, recovered) ||
      recovered != original) {
    std::cerr << "FAIL: an untouched record did not decrypt to its original plaintext\n";
    return 1;
  }
  std::cout << "PASS: untouched record decrypts successfully\n";

  bool passed = true;

  auto changed_ciphertext = ciphertext;
  changed_ciphertext[0] ^= 0x01U;
  passed &= expect_rejected("ciphertext-byte tampering", key, nonce,
                            changed_ciphertext, aad_for_chunk_zero, tag);

  auto changed_tag = tag;
  changed_tag[0] ^= 0x01U;
  passed &= expect_rejected("authentication-tag tampering", key, nonce,
                            ciphertext, aad_for_chunk_zero, changed_tag);

  auto changed_nonce = nonce;
  changed_nonce[0] ^= 0x01U;
  passed &= expect_rejected("nonce tampering", key, changed_nonce,
                            ciphertext, aad_for_chunk_zero, tag);

  const auto aad_for_chunk_one = make_aad(1);
  passed &= expect_rejected("chunk relocation (different chunk index in AAD)", key, nonce,
                            ciphertext, aad_for_chunk_one, tag);

  auto changed_header_aad = aad_for_chunk_zero;
  changed_header_aad[16] ^= 0x01U;  // Per-file salt is authenticated AAD.
  passed &= expect_rejected("authenticated header-field tampering", key, nonce,
                            ciphertext, changed_header_aad, tag);

  if (!passed) return 1;
  std::cout << "All tamper-detection tests passed.\n";
  return 0;
}
