/*
 * Crypto.cpp
 */

#include "Crypto.h"
#include <string.h>

#include <esp_random.h>

#include <mbedtls/sha256.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/bignum.h>

void crypto_random(uint8_t* out, size_t n) {
    esp_fill_random(out, n);
}

void crypto_sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    mbedtls_sha256(data, len, out, 0 /* SHA-256, not SHA-224 */);
}

bool crypto_const_eq(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

bool crypto_const_eq_str(const char* a, size_t aLen, const char* b, size_t bLen) {
    size_t n = (aLen > bLen) ? aLen : bLen;
    uint8_t diff = (uint8_t)(aLen != bLen);
    for (size_t i = 0; i < n; ++i) {
        uint8_t ca = (i < aLen) ? (uint8_t)a[i] : 0;
        uint8_t cb = (i < bLen) ? (uint8_t)b[i] : 0;
        diff |= (uint8_t)(ca ^ cb);
    }
    return diff == 0;
}

static const char kBase64Url[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

size_t b64url_encode(const uint8_t* in, size_t inLen, char* out, size_t outCap) {
    size_t o = 0;
    for (size_t i = 0; i < inLen; i += 3) {
        uint32_t a = in[i];
        uint32_t b = (i + 1 < inLen) ? in[i + 1] : 0;
        uint32_t c = (i + 2 < inLen) ? in[i + 2] : 0;
        uint32_t w = (a << 16) | (b << 8) | c;
        char block[4] = {
            kBase64Url[(w >> 18) & 0x3F],
            kBase64Url[(w >> 12) & 0x3F],
            kBase64Url[(w >> 6) & 0x3F],
            kBase64Url[w & 0x3F],
        };
        size_t take = (i + 2 < inLen) ? 4 : (i + 1 < inLen) ? 3 : 2;
        if (o + take > outCap) {
            return 0;
        }
        for (size_t k = 0; k < take; ++k) {
            out[o++] = block[k];
        }
    }
    return o;
}

static int8_t b64url_val(char c) {
    if (c >= 'A' && c <= 'Z') return (int8_t)(c - 'A');
    if (c >= 'a' && c <= 'z') return (int8_t)(c - 'a' + 26);
    if (c >= '0' && c <= '9') return (int8_t)(c - '0' + 52);
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

int b64url_decode(const char* in, size_t inLen, uint8_t* out, size_t outCap) {
    size_t o = 0;
    uint32_t val = 0;
    int valb = 0; // decoded bits held in `val`
    for (size_t i = 0; i < inLen; ++i) {
        char c = in[i];
        if (c == '=') {
            break; // tolerate trailing padding
        }
        int8_t v = b64url_val(c);
        if (v < 0) {
            return -1;
        }
        val = (val << 6) | (uint32_t)v;
        valb += 6;
        if (valb >= 8) {
            valb -= 8;
            if (o >= outCap) {
                return -1;
            }
            out[o++] = (uint8_t)((val >> valb) & 0xFF);
        }
    }
    return (int)o;
}

// Parse a DER ECDSA signature (SEQUENCE { INTEGER r, INTEGER s }) into 32-byte
// big-endian r and s. Strict and bounds-checked (caller-controlled bytes).
static bool der_sig_to_rs(const uint8_t* der, size_t len, uint8_t r[32], uint8_t s[32]) {
    if (len < 8 || len > 72) return false;
    if (der[0] != 0x30) return false;                  // SEQUENCE
    const size_t seqLen = der[1];
    if (seqLen != len - 2) return false;               // single top-level value

    size_t pos = 2;

    // r
    if (pos + 2 > len || der[pos] != 0x02) return false;
    const size_t rLen = der[pos + 1];
    pos += 2;
    // r must fit in what remains; length 33 is the DER sign byte.
    if (rLen == 0 || rLen > 33 || rLen > len - pos) return false;
    uint8_t rbuf[33];
    memcpy(rbuf, der + pos, rLen);
    pos += rLen;
    size_t rUse = rLen;
    if (rUse == 33) {
        if (rbuf[0] != 0) return false;                // must be a sign byte
        memmove(rbuf, rbuf + 1, 32);
        rUse = 32;
    }
    memset(r, 0, 32);
    memcpy(r + (32 - rUse), rbuf, rUse);

    // s
    if (pos + 2 > len || der[pos] != 0x02) return false;
    const size_t sLen = der[pos + 1];
    pos += 2;
    // `s` is last; `pos == len` at the end rejects trailing bytes.
    if (sLen == 0 || sLen > 33 || sLen > len - pos) return false;
    uint8_t sbuf[33];
    memcpy(sbuf, der + pos, sLen);
    pos += sLen;
    size_t sUse = sLen;
    if (sUse == 33) {
        if (sbuf[0] != 0) return false;
        memmove(sbuf, sbuf + 1, 32);
        sUse = 32;
    }
    memset(s, 0, 32);
    memcpy(s + (32 - sUse), sbuf, sUse);

    return pos == len; // no trailing bytes
}

// Is (x, y) a valid P-256 public key? Rejects the identity element, zero
// coordinates, out-of-range values, and off-curve points. mbedtls_ecp_point_read_binary()
// does NOT check curve membership (documented in ecp.h), and mbedtls_ecdsa_verify()
// does not either, so this must run before a key is stored or a signature accepted.
bool crypto_p256_pubkey_valid(const uint8_t x[32], const uint8_t y[32]) {
    // Fast, reviewable reject of the identity element: (0,0) is off-curve because
    // P-256's curve constant b != 0. Short-circuits before any MPI work.
    bool anyX = false, anyY = false;
    for (size_t i = 0; i < 32; ++i) {
        anyX = anyX || (x[i] != 0);
        anyY = anyY || (y[i] != 0);
    }
    if (!anyX || !anyY) return false;

    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);

    bool ok = false;
    uint8_t point[65];
    point[0] = 0x04;                 // uncompressed
    memcpy(point + 1, x, 32);
    memcpy(point + 33, y, 32);

    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) goto done;
    if (mbedtls_ecp_point_read_binary(&grp, &Q, point, sizeof(point)) != 0) goto done;
    // Range (0 <= x,y < p) AND the curve equation y^2 = x^3 - 3x + b.
    if (mbedtls_ecp_check_pubkey(&grp, &Q) != 0) goto done;
    ok = true;

done:
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);
    return ok;
}

bool crypto_verify_es256(const uint8_t pubX[32], const uint8_t pubY[32],
                         const uint8_t* msg, size_t mLen,
                         const uint8_t* derSig, size_t sigLen) {
    // S2: reject a public key that is not a valid P-256 point before any
    // signature work. Enrollment also validates, but a credential stored by a
    // pre-fix firmware (or restored from a backup) still reaches this path.
    if (!crypto_p256_pubkey_valid(pubX, pubY)) return false;

    uint8_t hash[32];
    crypto_sha256(msg, mLen, hash);

    uint8_t r[32], s[32];
    uint8_t point[65];

    mbedtls_mpi mr, ms;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;

    if (!der_sig_to_rs(derSig, sigLen, r, s)) return false;

    mbedtls_mpi_init(&mr);
    mbedtls_mpi_init(&ms);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);

    bool ok = false;

    if (mbedtls_mpi_read_binary(&mr, r, 32) != 0) goto done;
    if (mbedtls_mpi_read_binary(&ms, s, 32) != 0) goto done;
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) goto done;

    // Public point, uncompressed: 0x04 || x || y.
    point[0] = 0x04;
    memcpy(point + 1, pubX, 32);
    memcpy(point + 33, pubY, 32);
    if (mbedtls_ecp_point_read_binary(&grp, &Q, point, sizeof(point)) != 0) goto done;

    // 0 == signature valid.
    if (mbedtls_ecdsa_verify(&grp, hash, sizeof(hash), &Q, &mr, &ms) != 0) goto done;

    ok = true;

done:
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&mr);
    mbedtls_mpi_free(&ms);
    return ok;
}
