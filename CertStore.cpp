/*
 * CertStore.cpp
 */

#include "CertStore.h"
#include <Preferences.h>
#include <mbedtls/sha1.h>
#include <mbedtls/x509_crt.h>
#include <string.h>

static Preferences s_tls;
static const char* TLS_NS = "tls";

static char s_cert[MAX_CERT_PEM_LEN + 1];
static size_t s_certLen = 0;
static char s_key[MAX_KEY_PEM_LEN + 1];
static size_t s_keyLen = 0;

void certstore_begin() {
    s_tls.begin(TLS_NS, false);

    size_t n = s_tls.getBytes("cert", s_cert, MAX_CERT_PEM_LEN);
    if (n > 0) { s_certLen = n; s_cert[n] = 0; } else { s_certLen = 0; s_cert[0] = 0; }

    n = s_tls.getBytes("key", s_key, MAX_KEY_PEM_LEN);
    if (n > 0) { s_keyLen = n; s_key[n] = 0; } else { s_keyLen = 0; s_key[0] = 0; }
}

const char* certstore_cert(size_t* outLen) {
    if (outLen) *outLen = s_certLen;
    return s_certLen ? s_cert : nullptr;
}

const char* certstore_key(size_t* outLen) {
    if (outLen) *outLen = s_keyLen;
    return s_keyLen ? s_key : nullptr;
}

bool certstore_has_cert() { return s_certLen > 0; }
bool certstore_has_key()  { return s_keyLen > 0; }

bool certstore_save_cert(const char* pem, size_t len) {
    if (len == 0 || len > MAX_CERT_PEM_LEN) return false;
    bool ok = s_tls.putBytes("cert", pem, len) == len;
    if (ok) { memcpy(s_cert, pem, len); s_certLen = len; s_cert[len] = 0; }
    return ok;
}

bool certstore_save_key(const char* pem, size_t len) {
    if (len == 0 || len > MAX_KEY_PEM_LEN) return false;
    bool ok = s_tls.putBytes("key", pem, len) == len;
    if (ok) { memcpy(s_key, pem, len); s_keyLen = len; s_key[len] = 0; }
    return ok;
}

bool certstore_clear_cert() {
    bool ok = s_tls.remove("cert");
    s_certLen = 0;
    s_cert[0] = 0;
    return ok;
}

bool certstore_clear_key() {
    bool ok = s_tls.remove("key");
    s_keyLen = 0;
    s_key[0] = 0;
    return ok;
}

bool certstore_cert_fingerprint(const char* pem, size_t len, char* out, size_t cap) {
    if (!pem || len == 0 || !out || cap == 0) {
        return false;
    }

    // len + 1: mbedTLS detects PEM-vs-DER by the trailing NUL.
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    const int rc = mbedtls_x509_crt_parse(&crt, (const unsigned char*)pem, len + 1);
    if (rc != 0) {
        mbedtls_x509_crt_free(&crt);
        return false;
    }

    // Hash the leaf DER (what a browser fingerprints) - field is `raw`, its `p`/`len`.
    unsigned char digest[20];
    const bool hashed = mbedtls_sha1(crt.raw.p, crt.raw.len, digest) == 0;
    mbedtls_x509_crt_free(&crt);
    if (!hashed) {
        return false;
    }

    static const char kHex[] = "0123456789ABCDEF";
    size_t off = 0;
    for (size_t i = 0; i < sizeof(digest); ++i) {
        const size_t need = (i ? 1 : 0) + 2 + 1; // ':' + two hex + NUL
        if (off + need > cap) {
            return false;                    // fail, leaving `out` untouched
        }
        if (i) {
            out[off++] = ':';
        }
        out[off++] = kHex[digest[i] >> 4];
        out[off++] = kHex[digest[i] & 0x0F];
    }
    out[off] = 0;
    return true;
}
