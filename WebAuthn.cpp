/*
 * WebAuthn.cpp
 *
 * Registration and authentication ceremony implementation. All parsing is
 * strictly bounds-checked and fails closed.
 */

#include "Config.h"
#include "WebAuthn.h"
#include "Crypto.h"
#include "CborLite.h"
#include "PasskeyStore.h"
#include "SafePrint.h"
#include "Log.h"

#include <Arduino.h>
#include <string.h>
#include <stdlib.h>
#include <esp_heap_caps.h>
#include <esp_log.h>

// Log the reason a ceremony check failed, to the console only (the client gets a generic
// 400/401). Set false to go quiet.
static const bool kWebAuthnFailureLog = true;

// Fail a check and name which one (macro so __func__ names the ceremony).
#define WA_FAIL(stage)                                                     \
    do {                                                                   \
        if (kWebAuthnFailureLog) {                                         \
            Log.printf("[webauthn] %s: %s\n", __func__, (stage));       \
        }                                                                  \
        return false;                                                      \
    } while (0)

// ---------------------------------------------------------------------------
// Scratch arena (avoids large stack buffers and many small mallocs)
// ---------------------------------------------------------------------------

// Per-request arena for the ceremony buffers, from PSRAM with internal RAM fallback.
struct Scratch {
    uint8_t* mem;
    size_t   used;
    size_t   cap;
    explicit Scratch(size_t c) : mem((uint8_t*)heap_caps_malloc(c, MALLOC_CAP_SPIRAM)), used(0), cap(c) {
        if (mem == nullptr) {
            static bool reported = false;
            if (!reported) {
                reported = true;
                Log.printf("[webauthn] PSRAM unavailable for the %u B scratch arena; using internal RAM\n",
                              (unsigned)c);
            }
            mem = (uint8_t*)malloc(c);
        }
    }
    ~Scratch() { if (mem) free(mem); }
};

// Ceremony buffer caps, in allocation order. Each cap serves BOTH the arena reservation
// and the parser that fills it, so they can't describe different buffers.
static const size_t kClientDataB64Cap = 768;              // -> 576 decoded (768 chars for 576 B)
static const size_t kAttObjB64Cap     = 1024;             // -> 768 decoded (1024 chars for 768 B)
static const size_t kAuthDataB64Cap   = 768;              // -> 512 decoded (684 chars for 512 B)
static const size_t kSigB64Cap        = 256;              // -> 256 decoded (text is the binding limit)
static const size_t kIdB64Cap         = 512;              // -> MAX_CRED_ID_LEN (344 chars for 256 B)
static const size_t kClientDataCap    = 576;
static const size_t kAttObjCap        = 768;
static const size_t kAuthDataCap      = 512;
static const size_t kSigCap           = 256;
static const size_t kCredIdCap        = MAX_CRED_ID_LEN;
static const size_t kSignedDataCap    = 32 + kAuthDataCap;
static const size_t kTypeCap          = 32;               // "webauthn.create" / "webauthn.get"
static const size_t kChB64Cap         = 64;               // 32-byte challenge -> 43 chars
static const size_t kOriginCap        = 128;

// Arena size, checked at compile time against the summed needs below (exhaustion fails
// every ceremony).
#define SCRATCH_CAP 5120
static const size_t kScratchRegisterNeed = kClientDataB64Cap + kAttObjB64Cap + kIdB64Cap +
                                          kClientDataCap + kAttObjCap + kCredIdCap +
                                          kTypeCap + kChB64Cap + kOriginCap;
static const size_t kScratchAuthNeed     = kClientDataB64Cap + kAuthDataB64Cap + kSigB64Cap + kIdB64Cap +
                                          kClientDataCap + kAuthDataCap + kSigCap + kCredIdCap +
                                          kSignedDataCap + kTypeCap + kChB64Cap + kOriginCap;
static_assert(kScratchRegisterNeed <= SCRATCH_CAP, "scratch arena too small for register_finish");
static_assert(kScratchAuthNeed <= SCRATCH_CAP, "scratch arena too small for auth_finish");

static void* scratch_take(Scratch& s, size_t n) {
    if (s.mem == nullptr || s.used + n > s.cap) {
        // Undersized arena looks like a credential problem; log it once.
        static bool logged = false;
        if (!logged) {
            logged = true;
            Log.printf("[webauthn] scratch arena exhausted (%u + %u > %u); ceremony refused\n",
                          (unsigned)s.used, (unsigned)n, (unsigned)s.cap);
        }
        return nullptr;
    }
    void* p = s.mem + s.used;
    s.used += n;
    return p;
}

// ---------------------------------------------------------------------------
// Minimal JSON string extractor (fail closed). Finds "key":"value" and copies the
// unescaped value to `out`. Returns bytes written, or -1 if absent, malformed, or
// longer than outCap (never truncates).
// ---------------------------------------------------------------------------

static int json_get_str(const uint8_t* s, size_t n, const char* key,
                        char* out, size_t outCap) {
    size_t keyLen = strlen(key);
    if (keyLen + 2 > n) return -1;

    for (size_t i = 0; i + keyLen + 2 <= n; ++i) {
        if (s[i] == '"' &&
            memcmp(&s[i + 1], key, keyLen) == 0 &&
            s[i + 1 + keyLen] == '"') {
            size_t j = i + keyLen + 2;
            while (j < n && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r' || s[j] == '\n')) ++j;
            if (j >= n || s[j] != ':') return -1;
            ++j;
            while (j < n && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r' || s[j] == '\n')) ++j;
            if (j >= n || s[j] != '"') return -1;
            ++j;

            size_t o = 0;
            while (j < n && s[j] != '"') {
                uint8_t c = s[j];
                if (c == '\\' && j + 1 < n) {
                    ++j;
                    uint8_t e = s[j];
                    uint8_t outc = e;
                    switch (e) {
                        case 'b': outc = '\b'; break;
                        case 'f': outc = '\f'; break;
                        case 'n': outc = '\n'; break;
                        case 'r': outc = '\r'; break;
                        case 't': outc = '\t'; break;
                        case 'u': outc = '?'; if (j + 4 < n) j += 4; break;
                        default:  outc = e; break;
                    }
                    // Fail closed rather than truncate: the returned length indexes the buffer.
                    if (o >= outCap) return -1;
                    out[o++] = (char)outc;
                } else {
                    if (o >= outCap) return -1;
                    out[o++] = (char)c;
                }
                ++j;
            }
            if (j >= n) return -1; // unterminated string value -> fail closed
            if (o < outCap) out[o] = 0;
            return (int)o;
        }
    }
    return -1;
}

// ---------------------------------------------------------------------------
// Email normalization + validation (+ seeding the display name)
// ---------------------------------------------------------------------------

static void normalize_email(const char* in, char* out, size_t cap) {
    size_t i = 0, o = 0;
    while (in[i] == ' ' || in[i] == '\t' || in[i] == '\r' || in[i] == '\n') ++i;
    while (in[i] && o + 1 < cap) {
        char c = in[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        out[o++] = c;
        ++i;
    }
    while (o > 0 && (out[o - 1] == ' ' || out[o - 1] == '\t')) --o;
    out[o] = 0;
}

// Is `email` a usable identity? Called on the output of normalize_email(). The narrow
// character set also keeps it safe to echo into hand-built JSON (no quotes/backslashes/
// control chars).
static bool email_is_usable(const char* email) {
    if (!email || !email[0]) {
        return false;
    }

    const char* at = nullptr;
    size_t len = 0;
    for (const char* p = email; *p; ++p, ++len) {
        const char c = *p;
        if (c == '@') {
            if (at) return false; // exactly one '@'
            at = p;
            continue;
        }
        const bool plain = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                           c == '.' || c == '_' || c == '-' || c == '+' || c == '%';
        if (!plain) return false;
    }

    if (!at) return false;                        // no domain part
    if (at == email) return false;                // empty local part
    if ((size_t)(at - email) > 64) return false;  // local-part limit

    // The domain needs a dot with labels on both sides of it: that keeps an obvious
    // typo ("user@host") from becoming an identity. The address is only ever a label
    // - nothing is delivered to it - so this is about catching mistakes, not routing.
    const char* domain = at + 1;
    if (domain[0] == '.') return false;           // ".example.com"
    const char* lastDot = nullptr;
    for (const char* p = domain; *p; ++p) {
        if (*p == '.') lastDot = p;
    }
    if (!lastDot) return false;                   // "user@host"
    if (lastDot[1] == 0) return false;            // "example.com."
    if (strstr(domain, "..")) return false;       // "example..com"
    return true;
}

// Enrollment is gated by the caller's source IP; the address typed there is the identity the
// authenticator's UI shows (there is no separate display-name table).

// ---------------------------------------------------------------------------
// CBOR structure parsers built on CborLite.h
// ---------------------------------------------------------------------------

// Parse an attestation object: { "fmt", "attStmt", "authData" }.
static bool parse_attestation(const uint8_t* d, size_t n, bool* fmtNone,
                              const uint8_t** authData, size_t* authDataLen) {
    size_t pos = 0;
    uint8_t major;
    uint64_t count;
    if (!cborHeader(d, n, &pos, &major, &count)) return false;
    if (major != 5 || count > CBOR_MAX_ITEMS) return false;

    bool haveFmt = false, haveAuth = false;
    for (uint64_t i = 0; i < count; ++i) {
        const uint8_t* k;
        size_t kl;
        if (!cborReadText(d, n, &pos, &k, &kl)) return false;

        if (kl == 3 && memcmp(k, "fmt", 3) == 0) {
            const uint8_t* v;
            size_t vl;
            if (!cborReadText(d, n, &pos, &v, &vl)) return false;
            *fmtNone = (vl == 4 && memcmp(v, "none", 4) == 0);
            haveFmt = true;
        } else if (kl == 7 && memcmp(k, "attStmt", 7) == 0) {
            if (!cborSkip(d, n, &pos, 0)) return false;
        } else if (kl == 8 && memcmp(k, "authData", 8) == 0) {
            if (!cborReadBytes(d, n, &pos, authData, authDataLen)) return false;
            haveAuth = true;
        } else {
            if (!cborSkip(d, n, &pos, 0)) return false;
        }
    }
    return haveFmt && haveAuth;
}

// Parse authenticatorData for registration (requires the AT flag + attested
// credential data: AAGUID, credentialId, COSE key).
static bool parse_authdata_reg(const uint8_t* d, size_t n,
                               const uint8_t** rpIdHash, uint8_t* flags, uint32_t* signCount,
                               const uint8_t** credId, size_t* credIdLen,
                               const uint8_t** coseKey, size_t* coseKeyLen) {
    if (n < 37) return false;
    *rpIdHash = d;
    *flags = d[32];
    *signCount = ((uint32_t)d[33] << 24) | ((uint32_t)d[34] << 16) |
                 ((uint32_t)d[35] << 8) | d[36];
    size_t pos = 37;
    *credId = nullptr;
    *credIdLen = 0;
    *coseKey = nullptr;
    *coseKeyLen = 0;

    if (!(*flags & 0x40)) return false; // AT flag required for registration
    if (n - pos < 18) return false;
    pos += 16; // AAGUID
    size_t cidLen = ((size_t)d[pos] << 8) | d[pos + 1];
    pos += 2;
    if (cidLen == 0 || cidLen > (size_t)(n - pos)) return false;
    *credId = d + pos;
    *credIdLen = cidLen;
    pos += cidLen;
    *coseKey = d + pos;
    *coseKeyLen = n - pos;
    return true;
}

// Parse authenticatorData for assertion (rpIdHash + flags + signCount only).
static bool parse_authdata_assert(const uint8_t* d, size_t n,
                                  const uint8_t** rpIdHash, uint8_t* flags, uint32_t* signCount) {
    if (n < 37) return false;
    *rpIdHash = d;
    *flags = d[32];
    *signCount = ((uint32_t)d[33] << 24) | ((uint32_t)d[34] << 16) |
                 ((uint32_t)d[35] << 8) | d[36];
    return true;
}

// Parse a COSE_Key map, extracting the P-256 x/y coordinates. Enforces
// kty=EC2(2), alg=ES256(-7), crv=P-256(1).
static bool parse_cose_key(const uint8_t* d, size_t n, uint8_t x[32], uint8_t y[32]) {
    size_t pos = 0;
    uint8_t major;
    uint64_t count;
    if (!cborHeader(d, n, &pos, &major, &count)) return false;
    if (major != 5 || count > CBOR_MAX_ITEMS) return false;

    bool haveKty = false, haveAlg = false, haveCrv = false, haveX = false, haveY = false;
    int64_t kty = 0, alg = 0, crv = 0;

    for (uint64_t i = 0; i < count; ++i) {
        int64_t key;
        if (!cborReadInt(d, n, &pos, &key)) return false;

        if (key == 1) {
            if (haveKty) return false;  // duplicate kty: fail closed
            if (!cborReadInt(d, n, &pos, &kty)) return false;
            haveKty = true;
        } else if (key == 3) {
            if (haveAlg) return false;  // duplicate alg
            if (!cborReadInt(d, n, &pos, &alg)) return false;
            haveAlg = true;
        } else if (key == -1) {
            if (haveCrv) return false;  // duplicate crv
            if (!cborReadInt(d, n, &pos, &crv)) return false;
            haveCrv = true;
        } else if (key == -2) {
            if (haveX) return false;     // duplicate x
            const uint8_t* v;
            size_t vl;
            if (!cborReadBytes(d, n, &pos, &v, &vl)) return false;
            if (vl != 32) return false;
            memcpy(x, v, 32);
            haveX = true;
        } else if (key == -3) {
            if (haveY) return false;     // duplicate y
            const uint8_t* v;
            size_t vl;
            if (!cborReadBytes(d, n, &pos, &v, &vl)) return false;
            if (vl != 32) return false;
            memcpy(y, v, 32);
            haveY = true;
        } else {
            if (!cborSkip(d, n, &pos, 0)) return false;
        }
    }

    if (!haveKty || !haveAlg || !haveCrv || !haveX || !haveY) return false;
    // The buffer handed here is "everything after the credential ID" in authData; when
    // the ED (extension) flag is set it legitimately carries extension data after the
    // COSE map, so we deliberately do NOT require the map to consume the whole buffer.
    return (kty == 2 && alg == -7 && crv == 1);
}

// ---------------------------------------------------------------------------
// Registration: start
// ---------------------------------------------------------------------------

int webauthn_register_start(const char* email, char* out, size_t outCap, uint32_t peerIp) {
    if (!email) return -1;

    char norm[MAX_EMAIL_LEN];
    normalize_email(email, norm, sizeof(norm));
    if (!email_is_usable(norm)) return -2;

    // name and displayName are both the address itself: there is no separate label table
    // (Config.h kAuthorizedUsers was removed), so the authenticator's UI names the
    // identity that will actually authorize this source IP.

    uint8_t challenge[32];
    crypto_random(challenge, sizeof(challenge));
    uint8_t userHandle[USER_HANDLE_LEN];
    crypto_random(userHandle, sizeof(userHandle));

    if (!registration_create(challenge, peerIp, norm, userHandle, sizeof(userHandle))) {
        return -3;
    }

    char b64Challenge[64];
    size_t cl = b64url_encode(challenge, sizeof(challenge), b64Challenge, sizeof(b64Challenge));
    char b64User[USER_HANDLE_LEN * 2 + 2];
    size_t ul = b64url_encode(userHandle, sizeof(userHandle), b64User, sizeof(b64User));
    if (cl == 0 || ul == 0) return -4;

    int n = snprintf(out, outCap,
        "{\"rp\":{\"name\":\"PoE-Passkey\",\"id\":\"%s\"},"
        "\"user\":{\"id\":\"%.*s\",\"name\":\"%s\",\"displayName\":\"%s\"},"
        "\"challenge\":\"%.*s\","
        "\"pubKeyCredParams\":[{\"type\":\"public-key\",\"alg\":-7}],"
        "\"timeout\":60000,\"attestation\":\"none\","
        "\"authenticatorSelection\":{\"residentKey\":\"required\","
        "\"requireResidentKey\":true,\"userVerification\":\"discouraged\"},"
        "\"excludeCredentials\":[]}",
        kRpId,
        (int)ul, b64User, norm, norm,
        (int)cl, b64Challenge);

    if (n < 0 || (size_t)n >= outCap) return -5;
    return n;
}

// ---------------------------------------------------------------------------
// Authentication: start
// ---------------------------------------------------------------------------

int webauthn_auth_start(char* out, size_t outCap, uint32_t peerIp) {
    uint8_t challenge[32];
    crypto_random(challenge, sizeof(challenge));

    if (!session_create(challenge, peerIp)) return -1;

    char b64[64];
    size_t cl = b64url_encode(challenge, sizeof(challenge), b64, sizeof(b64));
    if (cl == 0) return -2;

    int n = snprintf(out, outCap,
        "{\"challenge\":\"%.*s\",\"rpId\":\"%s\",\"timeout\":60000,"
        "\"userVerification\":\"discouraged\"}",
        (int)cl, b64, kRpId);

    if (n < 0 || (size_t)n >= outCap) return -3;
    return n;
}

// ---------------------------------------------------------------------------
// Registration: finish (verify attestation, store credential)
// ---------------------------------------------------------------------------

bool webauthn_register_finish(const char* body, size_t bodyLen) {
    const uint8_t* b = (const uint8_t*)body;

    Scratch s(SCRATCH_CAP);
    if (!s.mem) WA_FAIL("no memory for the scratch arena");

    char*    cdb        = (char*)scratch_take(s, kClientDataB64Cap);
    char*    aob        = (char*)scratch_take(s, kAttObjB64Cap);
    char*    idb        = (char*)scratch_take(s, kIdB64Cap);
    uint8_t* clientData = (uint8_t*)scratch_take(s, kClientDataCap);
    uint8_t* attObj     = (uint8_t*)scratch_take(s, kAttObjCap);
    uint8_t* credId     = (uint8_t*)scratch_take(s, kCredIdCap);
    char*    typeStr    = (char*)scratch_take(s, kTypeCap);
    char*    chB64      = (char*)scratch_take(s, kChB64Cap);
    char*    originStr  = (char*)scratch_take(s, kOriginCap);

    if (!cdb || !aob || !idb || !clientData || !attObj || !credId ||
        !typeStr || !chB64 || !originStr) {
        WA_FAIL("the scratch arena cannot hold the attestation (see the take call above)");
    }

    int cdbL = json_get_str(b, bodyLen, "clientDataJSON", cdb, kClientDataB64Cap);
    int aobL = json_get_str(b, bodyLen, "attestationObject", aob, kAttObjB64Cap);
    int idbL = json_get_str(b, bodyLen, "id", idb, kIdB64Cap);
    if (cdbL < 0 || aobL < 0 || idbL < 0) {
        if (kWebAuthnFailureLog) {
            Log.printf("[webauthn] %s: JSON field missing or oversized "
                          "(clientDataJSON=%d attestationObject=%d id=%d; "
                          "-1 = absent or longer than its cap)\n", __func__, cdbL, aobL, idbL);
        }
        return false;
    }

    int cdLen = b64url_decode(cdb, cdbL, clientData, kClientDataCap);
    int attLen = b64url_decode(aob, aobL, attObj, kAttObjCap);
    int idLen = b64url_decode(idb, idbL, credId, kCredIdCap);
    // The stored credential records its ID length in a uint8_t, so an ID longer
    // than 255 bytes could not be recorded faithfully (it would wrap): refuse it.
    if (cdLen < 0 || attLen < 0 || idLen <= 0 || idLen > MAX_STORED_CRED_ID_LEN) {
        if (kWebAuthnFailureLog) {
            Log.printf("[webauthn] %s: base64url decode failed "
                          "(clientData=%d attestationObject=%d id=%d; id must be 1..%d)\n",
                          __func__, cdLen, attLen, idLen, (int)MAX_STORED_CRED_ID_LEN);
        }
        return false;
    }

    int tl = json_get_str(clientData, cdLen, "type", typeStr, kTypeCap);
    int chl = json_get_str(clientData, cdLen, "challenge", chB64, kChB64Cap);
    int ol = json_get_str(clientData, cdLen, "origin", originStr, kOriginCap);
    if (tl < 0 || chl < 0 || ol < 0) {
        WA_FAIL("clientDataJSON lacks type / challenge / origin");
    }
    static const char kTypeCreate[] = "webauthn.create";
    if (tl != (int)(sizeof(kTypeCreate) - 1) ||
        memcmp(typeStr, kTypeCreate, sizeof(kTypeCreate) - 1) != 0) {
        if (kWebAuthnFailureLog) {
            // Both of these are attacker-chosen bytes: whatever the client put in
            // clientDataJSON, printed for the operator. They go through safe_print() so a
            // terminal escape or an embedded newline cannot rewrite the console (the values
            // themselves are already bounded by json_get_str's caps).
            Log.printf("[webauthn] %s: clientDataJSON.type is not \"webauthn.create\" ('",
                          __func__);
            safe_print((tl > 0) ? typeStr : "", 32);
            Log.printf("')\n");
        }
        return false;
    }
    if (ol != (int)strlen(kOrigin) || memcmp(originStr, kOrigin, ol) != 0) {
        if (kWebAuthnFailureLog) {
            Log.printf("[webauthn] %s: clientDataJSON.origin '", __func__);
            safe_print((ol > 0) ? originStr : "", 64);
            Log.printf("' != kOrigin '%s'\n", kOrigin);
        }
        return false;
    }

    uint8_t challenge[32];
    if (b64url_decode(chB64, chl, challenge, sizeof(challenge)) != 32) {
        WA_FAIL("the challenge in clientDataJSON is not 32 bytes");
    }

    RegistrationSession rec;
    if (!registration_consume(challenge, &rec)) {
        if (kWebAuthnFailureLog) {
            Log.printf("[webauthn] %s: no live registration for this challenge "
                          "(never issued, already consumed, or older than %u ms)\n",
                          __func__, (unsigned)kSessionTtlMs);
        }
        return false;
    }

    bool fmtNone = false;
    const uint8_t* authData;
    size_t authDataLen;
    if (!parse_attestation(attObj, attLen, &fmtNone, &authData, &authDataLen)) {
        if (kWebAuthnFailureLog) {
            Log.printf("[webauthn] %s: could not parse the attestationObject (%d bytes) - "
                          "expected a CBOR map with fmt/attStmt/authData\n", __func__, attLen);
        }
        return false;
    }
    if (!fmtNone) {
        WA_FAIL("attestation fmt is not \"none\" (this RP does not verify attestation statements)");
    }

    const uint8_t* rpIdHash;
    uint8_t flags;
    uint32_t signCount;
    const uint8_t* aCredId;
    size_t aCredIdLen;
    const uint8_t* coseKey;
    size_t coseKeyLen;
    if (!parse_authdata_reg(authData, authDataLen, &rpIdHash, &flags, &signCount,
                            &aCredId, &aCredIdLen, &coseKey, &coseKeyLen)) {
        if (kWebAuthnFailureLog) {
            Log.printf("[webauthn] %s: authenticatorData is malformed or has no attested "
                          "credential data (%u bytes; AT flag + AAGUID/credId/COSE key)\n",
                          __func__, (unsigned)authDataLen);
        }
        return false;
    }

    uint8_t expectRp[32];
    crypto_sha256((const uint8_t*)kRpId, strlen(kRpId), expectRp);
    if (!crypto_const_eq(rpIdHash, expectRp, 32)) {
        if (kWebAuthnFailureLog) {
            Log.printf("[webauthn] %s: rpIdHash mismatch - the authenticator attested for "
                          "RP ID %02x%02x%02x%02x..., SHA-256(kRpId='%s') is %02x%02x%02x%02x...\n",
                          __func__, rpIdHash[0], rpIdHash[1], rpIdHash[2], rpIdHash[3],
                          kRpId, expectRp[0], expectRp[1], expectRp[2], expectRp[3]);
        }
        return false;
    }
    if (!(flags & 0x01)) WA_FAIL("user presence flag is not set"); // UP required

    if (aCredIdLen != (size_t)idLen || !crypto_const_eq(aCredId, credId, idLen)) {
        if (kWebAuthnFailureLog) {
            Log.printf("[webauthn] %s: the credential id inside authenticatorData (%u bytes) "
                          "differs from the id in the response (%d bytes)\n",
                          __func__, (unsigned)aCredIdLen, idLen);
        }
        return false;
    }

    uint8_t x[32], y[32];
    if (!parse_cose_key(coseKey, coseKeyLen, x, y)) {
        if (kWebAuthnFailureLog) {
            Log.printf("[webauthn] %s: the COSE public key (%u bytes) is malformed or not "
                          "ES256/P-256 (kty 2, crv 1)\n", __func__, (unsigned)coseKeyLen);
        }
        return false;
    }

    // S2: reject keys that are not valid P-256 points before persisting them. An
    // off-curve or identity-element key would otherwise make the assertion's
    // signature forgeable without any private key.
    if (!crypto_p256_pubkey_valid(x, y)) {
        if (kWebAuthnFailureLog) {
            Log.printf("[webauthn] %s: the COSE public key is not a valid P-256 point "
                          "(off-curve or the identity element)\n", __func__);
        }
        return false;
    }

    StoredCredential sc;
    memset(&sc, 0, sizeof(sc));
    sc.magic = PASSKEY_CRED_MAGIC;
    memcpy(sc.credId, credId, idLen);
    sc.credIdLen = (uint8_t)idLen;
    memcpy(sc.pubX, x, 32);
    memcpy(sc.pubY, y, 32);
    sc.signCount = signCount;
    if (rec.userHandleLen <= USER_HANDLE_LEN) {
        memcpy(sc.userHandle, rec.userHandle, rec.userHandleLen);
        sc.userHandleLen = rec.userHandleLen;
    }
    strncpy(sc.email, rec.email, MAX_EMAIL_LEN - 1);
    sc.createdAtMs = millis();
    sc.lastUsedAtMs = sc.createdAtMs;

    if (!cred_store(&sc)) {
        if (kWebAuthnFailureLog) {
            Log.printf("[webauthn] %s: could not store the credential - the store is full "
                          "(kMaxCredentials=%u) or the NVS write failed\n",
                          __func__, (unsigned)kMaxCredentials);
        }
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Authentication: finish (verify assertion, record source IP)
// ---------------------------------------------------------------------------

bool webauthn_auth_finish(const char* body, size_t bodyLen, uint32_t srcIp) {
    const uint8_t* b = (const uint8_t*)body;

    Scratch s(SCRATCH_CAP);
    if (!s.mem) WA_FAIL("no memory for the scratch arena");

    char*    cdb        = (char*)scratch_take(s, kClientDataB64Cap);
    char*    adb        = (char*)scratch_take(s, kAuthDataB64Cap);
    char*    sgb        = (char*)scratch_take(s, kSigB64Cap);
    char*    idb        = (char*)scratch_take(s, kIdB64Cap);
    uint8_t* clientData = (uint8_t*)scratch_take(s, kClientDataCap);
    uint8_t* authData   = (uint8_t*)scratch_take(s, kAuthDataCap);
    uint8_t* sig        = (uint8_t*)scratch_take(s, kSigCap);
    uint8_t* credId     = (uint8_t*)scratch_take(s, kCredIdCap);
    uint8_t* signedData = (uint8_t*)scratch_take(s, kSignedDataCap);
    char*    typeStr    = (char*)scratch_take(s, kTypeCap);
    char*    chB64      = (char*)scratch_take(s, kChB64Cap);
    char*    originStr  = (char*)scratch_take(s, kOriginCap);

    if (!cdb || !adb || !sgb || !idb || !clientData || !authData || !sig || !credId ||
        !signedData || !typeStr || !chB64 || !originStr) {
        WA_FAIL("the scratch arena cannot hold the assertion (see the take call above)");
    }

    int cdbL = json_get_str(b, bodyLen, "clientDataJSON", cdb, kClientDataB64Cap);
    int adbL = json_get_str(b, bodyLen, "authenticatorData", adb, kAuthDataB64Cap);
    int sgbL = json_get_str(b, bodyLen, "signature", sgb, kSigB64Cap);
    int idbL = json_get_str(b, bodyLen, "id", idb, kIdB64Cap);
    if (cdbL < 0 || adbL < 0 || sgbL < 0 || idbL < 0) {
        if (kWebAuthnFailureLog) {
            Log.printf("[webauthn] %s: JSON field missing or oversized "
                          "(clientDataJSON=%d authenticatorData=%d signature=%d id=%d; "
                          "-1 = absent or longer than its cap)\n",
                          __func__, cdbL, adbL, sgbL, idbL);
        }
        return false;
    }

    int cdLen = b64url_decode(cdb, cdbL, clientData, kClientDataCap);
    int adLen = b64url_decode(adb, adbL, authData, kAuthDataCap);
    int sgLen = b64url_decode(sgb, sgbL, sig, kSigCap);
    int idLen = b64url_decode(idb, idbL, credId, kCredIdCap);
    // See register_finish: the stored length field is a uint8_t.
    if (cdLen < 0 || adLen < 0 || sgLen < 0 || idLen <= 0 || idLen > MAX_STORED_CRED_ID_LEN) {
        if (kWebAuthnFailureLog) {
            Log.printf("[webauthn] %s: base64url decode failed "
                          "(clientData=%d authData=%d sig=%d id=%d; id must be 1..%d)\n",
                          __func__, cdLen, adLen, sgLen, idLen, (int)MAX_STORED_CRED_ID_LEN);
        }
        return false;
    }

    int tl = json_get_str(clientData, cdLen, "type", typeStr, kTypeCap);
    int chl = json_get_str(clientData, cdLen, "challenge", chB64, kChB64Cap);
    int ol = json_get_str(clientData, cdLen, "origin", originStr, kOriginCap);
    if (tl < 0 || chl < 0 || ol < 0) {
        WA_FAIL("clientDataJSON lacks type / challenge / origin");
    }
    static const char kTypeGet[] = "webauthn.get";
    if (tl != (int)(sizeof(kTypeGet) - 1) ||
        memcmp(typeStr, kTypeGet, sizeof(kTypeGet) - 1) != 0) {
        if (kWebAuthnFailureLog) {
            // Sanitized for the same reason as the register path (see there).
            Log.printf("[webauthn] %s: clientDataJSON.type is not \"webauthn.get\" ('",
                          __func__);
            safe_print((tl > 0) ? typeStr : "", 32);
            Log.printf("')\n");
        }
        return false;
    }
    if (ol != (int)strlen(kOrigin) || memcmp(originStr, kOrigin, ol) != 0) {
        if (kWebAuthnFailureLog) {
            Log.printf("[webauthn] %s: clientDataJSON.origin '", __func__);
            safe_print((ol > 0) ? originStr : "", 64);
            Log.printf("' != kOrigin '%s'\n", kOrigin);
        }
        return false;
    }

    uint8_t challenge[32];
    if (b64url_decode(chB64, chl, challenge, sizeof(challenge)) != 32) {
        WA_FAIL("the challenge in clientDataJSON is not 32 bytes");
    }

    // Consuming the session is also the one-time replay guard: a challenge that was
    // never issued by this device, was already used, or has aged past kSessionTtlMs
    // fails here. This is the check that a stale page (or a second tab that consumed
    // the challenge) trips.
    if (!session_consume(challenge)) {
        if (kWebAuthnFailureLog) {
            Log.printf("[webauthn] %s: no live session for this challenge "
                          "(never issued, already consumed, or older than %u ms)\n",
                          __func__, (unsigned)kSessionTtlMs);
        }
        return false;
    }

    const uint8_t* rpIdHash;
    uint8_t flags;
    uint32_t signCount;
    if (!parse_authdata_assert(authData, adLen, &rpIdHash, &flags, &signCount)) {
        if (kWebAuthnFailureLog) {
            Log.printf("[webauthn] %s: authenticatorData is too short or malformed (%d bytes; "
                          "needs at least 37)\n", __func__, adLen);
        }
        return false;
    }

    uint8_t expectRp[32];
    crypto_sha256((const uint8_t*)kRpId, strlen(kRpId), expectRp);
    if (!crypto_const_eq(rpIdHash, expectRp, 32)) {
        if (kWebAuthnFailureLog) {
            Log.printf("[webauthn] %s: rpIdHash mismatch - the authenticator signed for "
                          "RP ID %02x%02x%02x%02x..., SHA-256(kRpId='%s') is %02x%02x%02x%02x...\n",
                          __func__, rpIdHash[0], rpIdHash[1], rpIdHash[2], rpIdHash[3],
                          kRpId, expectRp[0], expectRp[1], expectRp[2], expectRp[3]);
        }
        return false;
    }
    if (!(flags & 0x01)) WA_FAIL("user presence flag is not set"); // UP required

    StoredCredential cred;
    CredRuntime rt;
    // `credSlot` is the credential's slot: the identity the authorized-IP attribution is keyed
    // on (see authzips_note_user), so it comes out of the lookup that is already happening
    // rather than from a second search.
    uint16_t credSlot = 0;
    if (!cred_lookup_ex(credId, idLen, &cred, &rt, &credSlot)) {
        if (kWebAuthnFailureLog) {
            Log.printf("[webauthn] %s: no stored credential matches this id (%d bytes) - "
                          "is it revoked, or stored under a different id?\n", __func__, idLen);
        }
        return false;
    }

    // A disabled key fails before the signature check (no counter update / authorized IP).
    if (rt.disabled) {
        if (kWebAuthnFailureLog) {
            Log.printf("[webauthn] %s: this credential is DISABLED - an administrator "
                          "disabled it (re-enable it on the admin console, or revoke it)\n",
                          __func__);
        }
        return false;
    }

    // signedData = authenticatorData || SHA-256(clientDataJSON), per the spec (order matters).
    memcpy(signedData, authData, adLen);
    crypto_sha256(clientData, cdLen, signedData + adLen);

    if (!crypto_verify_es256(cred.pubX, cred.pubY, signedData, adLen + 32, sig, sgLen)) {
        if (kWebAuthnFailureLog) {
            Log.printf("[webauthn] %s: ES256 signature verification failed "
                          "(sig %d bytes, authData %d bytes)\n", __func__, sgLen, adLen);
        }
        return false;
    }

    // Clone detection: signCount must strictly increase (when both non-zero).
    if (cred.signCount != 0 && signCount != 0 && signCount <= cred.signCount) {
        if (kWebAuthnFailureLog) {
            Log.printf("[webauthn] %s: sign counter did not increase (%u <= stored %u)\n",
                          __func__, (unsigned)signCount, (unsigned)cred.signCount);
        }
        return false;
    }
    uint32_t newCounter = (signCount > cred.signCount) ? signCount : cred.signCount;
    if (!cred_update_counter(credId, idLen, newCounter, millis())) {
        WA_FAIL("could not persist the new sign counter (NVS write failed)");
    }

    authzips_add(srcIp, kAuthorizedIPTtlMs);
    // Record which key is behind this address (admin listing only; bookkeeping, can't fail).
    authzips_note_user(srcIp, credSlot);
    return true;
}




