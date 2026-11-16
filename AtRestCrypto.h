/*
 * AtRestCrypto.h
 *
 * At-rest wrapping for the TLS material.
 *
 */

#ifndef ATRESTCRYPTO_H
#define ATRESTCRYPTO_H

#include <stdint.h>
#include <stddef.h>

// Record layout:
//   [0..3] "PKW1"  [4] format  [5..16] nonce  [17..17+n) ciphertext  [+16] tag
#define ATREST_OVERHEAD   33
#define ATREST_FMT_PLAIN  1
#define ATREST_FMT_SEALED 2

// Role labels: used for key derivation AND as GCM AAD.
#define ATREST_LABEL_CERT "PoE-Passkey PEM wrap cert v1"
#define ATREST_LABEL_KEY  "PoE-Passkey PEM wrap key v1"

// The wrapping key lives in eFuse BLK_KEY5 (HMAC_KEY5) with purpose HMAC_UP.
#define ATREST_BLOCK_NAME "BLK_KEY5"

typedef enum {
    ATREST_NO_KEY = 0,   // slot is free (purpose USER)
    ATREST_KEY_OK,       // slot holds an HMAC_UP key
    ATREST_KEY_ERROR,    // slot is owned by something else, or slot out of range
} AtRestKeyState;

// State of the configured eFuse slot.
AtRestKeyState atrest_key_state();

// Derive a 32-byte subkey for `label`. False when no usable eFuse key exists.
bool atrest_derive(const char* label, uint8_t out[32]);

// Wrap `pt[0..n)` into a complete record in `out`. Returns bytes written, or 0.
size_t atrest_seal(const char* label, const uint8_t* pt, size_t n,
                   uint8_t* out, size_t cap);

// Unwrap a record produced by atrest_seal(). Returns payload length, or 0 on failure.
size_t atrest_open(const uint8_t* rec, size_t recLen, const char* label,
                   uint8_t* pt, size_t cap);

// Does this buffer begin with the sealed-record magic?
bool atrest_is_sealed(const uint8_t* rec, size_t len);

// Burn a fresh random key into the configured slot. Verifies by a
// seal/open round trip before reporting success.
bool atrest_provision(char* msg, size_t msgCap);

#endif // ATRESTCRYPTO_H
