/*
 * CertStore.h
 *
 * NVS storage for the TLS certificate and private key, imported at runtime over
 * the serial console. This is the only source of TLS material (no compile-time
 * fallback); a device with nothing imported halts into the console at boot.
 *
 * Records are stored as a raw PEM or as a sealed AtRestCrypto record; both load.
 */

#ifndef CERTSTORE_H
#define CERTSTORE_H

#include <stddef.h>

// Per-blob size cap (NVS single-entry limit is ~4 KB). Sized for an ECDSA P-256
// identity plus a chain. ECDSA is the supported key type; a large RSA key + chain
// will not fit.
#define MAX_CERT_PEM_LEN 3500
#define MAX_KEY_PEM_LEN  3500

typedef enum {
    CERT_MATERIAL_NONE = 0,    // nothing stored
    CERT_MATERIAL_PLAIN,       // raw PEM
    CERT_MATERIAL_SEALED,      // unwrapped successfully from a sealed record
    CERT_MATERIAL_UNREADABLE,  // sealed but could not be unwrapped (no/wrong key)
} CertMaterial;

// Load cert/key from NVS into RAM buffers. Call once at boot.
void certstore_begin();

// Accessors (valid after certstore_begin). Return nullptr if not present.
const char* certstore_cert(size_t* outLen);
const char* certstore_key(size_t* outLen);

bool certstore_has_cert();
bool certstore_has_key();

// How each entry was stored, for the console's status output.
CertMaterial certstore_cert_material();
CertMaterial certstore_key_material();

// Persist (from serial import). `pem` need not be NUL-terminated. Sealed when an
// eFuse wrapping key is present; plaintext otherwise unless kAtRestWrapRequired.
bool certstore_save_cert(const char* pem, size_t len);
bool certstore_save_key(const char* pem, size_t len);

// Seal any stored plaintext entry; true when every present entry ends up sealed.
bool certstore_reseal(char* msg, size_t cap);

// Set when an eFuse burn fails: no boot-time retry, and no sealing with a key that
// may be incomplete.
bool certstore_burn_latched();
void certstore_clear_burn_latch();

// Erase and re-open the TLS partition; the caller must already hold the material in RAM.
bool certstore_wipe_partition();

// Remove imported material. The device then has no TLS identity and halts at boot
// until `import` runs again.
bool certstore_clear_cert();
bool certstore_clear_key();

// SHA-1 fingerprint of `pem` into `out` as uppercase colon-separated hex
// ("3F:...:9A"). `pem` must be NUL-terminated at `len`. False on parse error or
// a too-small `out` (untouched).
bool certstore_cert_fingerprint(const char* pem, size_t len, char* out, size_t cap);

#endif // CERTSTORE_H
