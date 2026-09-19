/*
 * Crypto.h
 *
 * Cryptographic primitives for PoE-Passkey, built on mbedTLS (bundled with
 * the esp32 core). SHA-256, cryptographically secure RNG, base64url, and
 * ES256 (P-256 ECDSA) signature verification.
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

// Fill `out` with cryptographically secure random bytes (esp_fill_random).
void crypto_random(uint8_t* out, size_t n);

// SHA-256 digest of `data` into `out` (32 bytes).
void crypto_sha256(const uint8_t* data, size_t len, uint8_t out[32]);

// Constant-time byte-equality over `n` bytes.
bool crypto_const_eq(const uint8_t* a, const uint8_t* b, size_t n);

// Constant-time string equality (length-safe: does not short-circuit on a
// length mismatch, to avoid leaking the length via timing).
bool crypto_const_eq_str(const char* a, size_t aLen, const char* b, size_t bLen);

// base64url (RFC 4648, no padding) encode. Returns output length, or 0 if
// `outCap` is too small. Does not NUL-terminate.
size_t b64url_encode(const uint8_t* in, size_t inLen, char* out, size_t outCap);

// base64url decode (tolerates missing padding; stops at '='). Returns bytes
// written, or -1 on invalid character or output overflow.
int b64url_decode(const char* in, size_t inLen, uint8_t* out, size_t outCap);

// Verify an ES256 (P-256 ECDSA) signature.
//   pubX/pubY : the 32-byte big-endian public key coordinates.
//   msg/mLen  : the signed bytes (SHA-256(clientDataJSON) || authenticatorData).
//   derSig    : the ASN.1 DER-encoded ECDSA signature (as produced by WebAuthn).
bool crypto_verify_es256(const uint8_t pubX[32], const uint8_t pubY[32],
                         const uint8_t* msg, size_t mLen,
                         const uint8_t* derSig, size_t sigLen);

#endif // CRYPTO_H
