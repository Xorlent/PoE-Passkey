/*
 * CborLite.h
 *
 * A minimal, strictly bounds-checked CBOR reader. Only what PoE-Passkey
 * needs to parse an attestation object and a COSE public key. Every function
 * returns false on any malformed or out-of-bounds input (fail closed).
 */

#ifndef CBORLITE_H
#define CBORLITE_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Maximum number of map/array elements we will iterate (DoS guard).
#define CBOR_MAX_ITEMS 64

// Read one CBOR "header" (initial byte + any length/argument extension).
// Sets *major (0..7) and *arg (the value, or length/count/float-bits).
static bool cborHeader(const uint8_t* b, size_t n, size_t* pos,
                       uint8_t* major, uint64_t* arg) {
    if (*pos >= n) return false;
    uint8_t ib = b[*pos];
    *major = ib >> 5;
    uint8_t ai = ib & 0x1F;
    uint64_t extra = 0;
    *pos += 1;

    if (ai < 24) {
        extra = ai;
    } else if (ai == 24) {
        if (*pos >= n) return false;
        extra = b[*pos];
        *pos += 1;
    } else if (ai == 25) {
        if (*pos + 1 >= n) return false;
        extra = ((uint64_t)b[*pos] << 8) | b[*pos + 1];
        *pos += 2;
    } else if (ai == 26) {
        if (*pos + 3 >= n) return false;
        extra = ((uint64_t)b[*pos] << 24) | ((uint64_t)b[*pos + 1] << 16) |
                ((uint64_t)b[*pos + 2] << 8) | b[*pos + 3];
        *pos += 4;
    } else if (ai == 27) {
        if (*pos + 7 >= n) return false;
        extra = 0;
        for (int i = 0; i < 8; ++i) {
            extra = (extra << 8) | b[*pos + i];
        }
        *pos += 8;
    } else {
        // ai == 31 (indefinite) or 28..30 (reserved): unsupported here.
        return false;
    }
    *arg = extra;
    return true;
}

// Skip one complete CBOR value beginning at *pos.
static bool cborSkip(const uint8_t* b, size_t n, size_t* pos, int depth) {
    if (depth > 16) return false;
    uint8_t major;
    uint64_t arg;
    if (!cborHeader(b, n, pos, &major, &arg)) return false;

    switch (major) {
        case 0:  // unsigned int
        case 1:  // negative int
            return true;
        case 7:  // simple / float: header consumes the whole value
            return true;
        case 2:  // byte string
        case 3:  // text string
            if (arg > (uint64_t)(n - *pos)) return false;
            *pos += (size_t)arg;
            return true;
        case 4:  // array
            if (arg > CBOR_MAX_ITEMS) return false;
            for (uint64_t i = 0; i < arg; ++i) {
                if (!cborSkip(b, n, pos, depth + 1)) return false;
            }
            return true;
        case 5: {  // map: pairs of key/value
            if (arg > CBOR_MAX_ITEMS) return false;
            for (uint64_t i = 0; i < arg; ++i) {
                if (!cborSkip(b, n, pos, depth + 1)) return false;
                if (!cborSkip(b, n, pos, depth + 1)) return false;
            }
            return true;
        }
        case 6:  // tag: skip the tagged value
            return cborSkip(b, n, pos, depth + 1);
        default:
            return false;
    }
}

// Read an integer value (unsigned or negative) at *pos.
static bool cborReadInt(const uint8_t* b, size_t n, size_t* pos, int64_t* out) {
    uint8_t major;
    uint64_t arg;
    if (!cborHeader(b, n, pos, &major, &arg)) return false;
    if (major == 0) { *out = (int64_t)arg; return true; }
    if (major == 1) { *out = -1 - (int64_t)arg; return true; }
    return false;
}

// Read a byte string at *pos, returning a pointer/length into b.
static bool cborReadBytes(const uint8_t* b, size_t n, size_t* pos,
                          const uint8_t** out, size_t* outLen) {
    uint8_t major;
    uint64_t len;
    if (!cborHeader(b, n, pos, &major, &len)) return false;
    if (major != 2) return false;
    if (len > (uint64_t)(n - *pos)) return false;
    *out = b + *pos;
    *outLen = (size_t)len;
    *pos += (size_t)len;
    return true;
}

// Read a text (UTF-8) string at *pos, returning a pointer/length into b.
static bool cborReadText(const uint8_t* b, size_t n, size_t* pos,
                         const uint8_t** out, size_t* outLen) {
    uint8_t major;
    uint64_t len;
    if (!cborHeader(b, n, pos, &major, &len)) return false;
    if (major != 3) return false;
    if (len > (uint64_t)(n - *pos)) return false;
    *out = b + *pos;
    *outLen = (size_t)len;
    *pos += (size_t)len;
    return true;
}

#endif // CBORLITE_H
