/*
 * CertStore.h
 *
 * NVS storage for the TLS certificate and private key, imported at runtime over
 * the serial console. This is the only source of TLS material (no compile-time
 * fallback); a device with nothing imported halts into the console at boot.
 */

#ifndef CERTSTORE_H
#define CERTSTORE_H

#include <stddef.h>

// Per-blob size cap (NVS single-entry limit is ~4 KB). Sized for an ECDSA P-256
// identity plus a chain. ECDSA is the supported key type; a large RSA key + chain
// will not fit.
#define MAX_CERT_PEM_LEN 3500
#define MAX_KEY_PEM_LEN  3500

// Load cert/key from NVS into RAM buffers. Call once at boot.
void certstore_begin();

// Accessors (valid after certstore_begin). Return nullptr if not present.
const char* certstore_cert(size_t* outLen);
const char* certstore_key(size_t* outLen);

bool certstore_has_cert();
bool certstore_has_key();

// Persist (from serial import). `pem` need not be NUL-terminated.
bool certstore_save_cert(const char* pem, size_t len);
bool certstore_save_key(const char* pem, size_t len);

// Remove imported material. The device then has no TLS identity and halts at boot
// until `import` runs again.
bool certstore_clear_cert();
bool certstore_clear_key();

// SHA-1 fingerprint of `pem` into `out` as uppercase colon-separated hex
// ("3F:...:9A"). `pem` must be NUL-terminated at `len`. False on parse error or
// a too-small `out` (untouched).
bool certstore_cert_fingerprint(const char* pem, size_t len, char* out, size_t cap);

#endif // CERTSTORE_H
