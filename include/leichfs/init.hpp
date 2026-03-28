#pragma once
#include <array>
#include <cstdint>
#include <string>

#include "enc/params.hpp"

namespace leichfs {

// Name of the config file stored in the backing directory root.
inline constexpr const char* CONF_FILENAME = ".leichfs.conf";

// Argon2id parameters stored in the config file.
struct Argon2Params {
    uint32_t m_cost{65536};  // memory in KiB  (64 MiB)
    uint32_t t_cost{3};      // iterations
    uint32_t parallelism{1};
};

// ── Init ────────────────────────────────────────────────────────────────────
//
// Create a new leichfs backing directory at `dir`:
//  1. Prompts for a passphrase (twice, with confirmation).
//  2. Generates a random 32-byte master key and 16-byte salt.
//  3. Derives a wrapping key via Argon2id(passphrase, salt, params).
//  4. Wraps the master key with AES-256-GCM.
//  5. Writes CONF_FILENAME into dir.
//
// Returns 0 on success, -1 on any error (message printed to stderr).
int leichfs_init(const char* dir, const Argon2Params& params = {});


// ── Key loading ─────────────────────────────────────────────────────────────
//
// Read CONF_FILENAME from `dir`, prompt for passphrase, derive wrapping key,
// unwrap and return the master key in `out` (NOT stored a.k.a ephemeral)
//
// Returns 0 on success, -1 on error (bad passphrase returns -1 with message).
int load_master_key_from_conf(const char*                        dir,
                              std::array<uint8_t, enc::KEY_SIZE>& out);

// ── Passphrase change ────────────────────────────────────────────────────────
//
// Re-wrap the master key with a new passphrase without touching any file data.
// Prompts for the current passphrase (to unwrap), then the new passphrase
// (twice, with confirmation).  Writes the updated config atomically.
//
// Returns 0 on success, -1 on error.
int leichfs_change_passphrase(const char* dir);

} // namespace leichfs
