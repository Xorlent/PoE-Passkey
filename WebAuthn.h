/*
 * WebAuthn.h
 *
 * The two FIDO2 ceremonies: registration (attestation, fmt "none") and
 * authentication (assertion, usernameless). Implemented in terms of the
 * Crypto/CborLite/PasskeyStore modules.
 */

#ifndef WEBAUTHN_H
#define WEBAUTHN_H

#include <stdint.h>
#include <stddef.h>

// Build PublicKeyCredentialCreationOptions JSON into `out` (cap `outCap`). Starts a
// registration ceremony bound to `email` and `peerIp` (network byte order, 0 = unknown).
//
// The address is not checked against an allowlist here: enrollment is gated by the caller's
// source IP (Config.h kAdminIPs) plus the one-time challenge binding.
//
// Returns output length (>= 0), or a negative error code:
//   -2 malformed email, -3 registration store full, -4 encode error, -5 truncation.
int webauthn_register_start(const char* email, char* out, size_t outCap, uint32_t peerIp);

// Verify the attestation response (JSON body) and store the credential.
bool webauthn_register_finish(const char* body, size_t bodyLen);

// Build PublicKeyCredentialRequestOptions JSON (usernameless) into `out`. Starts an auth
// ceremony for `peerIp` (network byte order, 0 = unknown); the per-IP cap
// (kMaxSessionsPerIP) is what keeps this public endpoint from holding every auth slot.
// Returns length (>=0) or negative error.
int webauthn_auth_start(char* out, size_t outCap, uint32_t peerIp);

// Verify the assertion response; on success records `srcIp` as authorized.
bool webauthn_auth_finish(const char* body, size_t bodyLen, uint32_t srcIp);

#endif // WEBAUTHN_H
