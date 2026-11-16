/*
 * CertStore.cpp
 */

#include "CertStore.h"
#include "AtRestCrypto.h"
#include "Config.h"
#include "Log.h"

#include <Preferences.h>
#include <nvs_flash.h>
#include <stdio.h>
#include <string.h>
#include <mbedtls/sha1.h>
#include <mbedtls/x509_crt.h>

static Preferences s_tls;
static const char* TLS_NS = "tls";

// TLS material has its own partition so it can be erased wholesale when sealing.
static const char* NVS_TLS_PART = "nvs_tls";

static char s_cert[MAX_CERT_PEM_LEN + 1];
static size_t s_certLen = 0;
static char s_key[MAX_KEY_PEM_LEN + 1];
static size_t s_keyLen = 0;

static CertMaterial s_certMat = CERT_MATERIAL_NONE;
static CertMaterial s_keyMat  = CERT_MATERIAL_NONE;
static bool s_burnLatched = false;

// Scratch record buffer; a sealed record must still fit one NVS blob.
static uint8_t s_rec[MAX_CERT_PEM_LEN + ATREST_OVERHEAD + 1];
static_assert(MAX_CERT_PEM_LEN + ATREST_OVERHEAD <= 4000,
              "sealed record would exceed the NVS single-blob limit");

// Mount the TLS partition, recovering the two "needs formatting" errors.
static bool tls_partition_mount() {
    esp_err_t err = nvs_flash_init_partition(NVS_TLS_PART);
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        Log.printf("[tls] partition %s must be formatted (%s): erasing\n",
                      NVS_TLS_PART, esp_err_to_name(err));
        nvs_flash_erase_partition(NVS_TLS_PART);
        err = nvs_flash_init_partition(NVS_TLS_PART);
    }
    if (err != ESP_OK) {
        Log.printf("[tls] FATAL: partition %s is unavailable (%s). The flashed "
                      "partitions.csv needs an entry named %s.\n",
                      NVS_TLS_PART, esp_err_to_name(err), NVS_TLS_PART);
        return false;
    }
    return true;
}

bool certstore_wipe_partition() {
    s_tls.end();
    const esp_err_t err = nvs_flash_erase_partition(NVS_TLS_PART);
    if (err != ESP_OK) {
        Log.printf("[tls] erase of %s failed: %s\n", NVS_TLS_PART, esp_err_to_name(err));
        return false;
    }
    if (!tls_partition_mount()) {
        return false;
    }
    if (!s_tls.begin(TLS_NS, false, NVS_TLS_PART)) {
        Log.println("[tls] could not re-open the TLS namespace after erase");
        return false;
    }
    // The latch lived in the partition we just erased.
    s_burnLatched = false;
    return true;
}

// Load one entry into `dst`; false only when it exists but cannot be interpreted.
static bool load_entry(const char* nvsKey, const char* label,
                       char* dst, size_t dstCap, size_t* outLen, CertMaterial* mat) {
    dst[0] = 0;
    *outLen = 0;
    *mat = CERT_MATERIAL_NONE;

    const size_t got = s_tls.getBytes(nvsKey, s_rec, sizeof(s_rec));
    if (got == 0) {
        return true; // nothing stored
    }

    if (atrest_is_sealed(s_rec, got)) {
        const size_t n = atrest_open(s_rec, got, label, (uint8_t*)dst, dstCap - 1);
        if (n == 0) {
            *mat = CERT_MATERIAL_UNREADABLE;
            return false;
        }
        dst[n] = 0;
        *outLen = n;
        *mat = CERT_MATERIAL_SEALED;
        return true;
    }

    if (got >= dstCap) {
        *mat = CERT_MATERIAL_UNREADABLE;
        return false;
    }
    memcpy(dst, s_rec, got);
    dst[got] = 0;
    *outLen = got;
    *mat = CERT_MATERIAL_PLAIN;
    return true;
}

// Write one entry, sealed when a wrapping key is available.
static bool store_entry(const char* nvsKey, const char* label,
                        const char* pem, size_t len) {
    const AtRestKeyState keyState = atrest_key_state();
    const bool haveKey = (keyState == ATREST_KEY_OK);

    if (!haveKey && kAtRestWrapRequired) {
        Log.printf("[tls] refusing to store plaintext: kAtRestWrapRequired is set and "
                      "eFuse " ATREST_BLOCK_NAME " has no wrapping key\n");
        return false;
    }

    size_t recLen = 0;
    if (haveKey) {
        recLen = atrest_seal(label, (const uint8_t*)pem, len, s_rec, sizeof(s_rec));
        if (recLen == 0) {
            Log.printf("[tls] sealing failed; nothing written\n");
            return false;
        }
    } else {
        if (len > sizeof(s_rec)) {
            return false;
        }
        memcpy(s_rec, pem, len);
        recLen = len;
    }

    if (s_tls.putBytes(nvsKey, s_rec, recLen) != recLen) {
        return false;
    }
    return true;
}

void certstore_begin() {
    if (!tls_partition_mount()) {
        return;   // no partition: report as "no material" so the console stays usable
    }
    if (!s_tls.begin(TLS_NS, false, NVS_TLS_PART)) {
        Log.printf("[tls] could not open the TLS namespace on %s\n", NVS_TLS_PART);
        return;
    }
    s_burnLatched = (s_tls.getUChar("bfail", 0) != 0);

    const bool certOk = load_entry("cert", ATREST_LABEL_CERT,
                                   s_cert, sizeof(s_cert), &s_certLen, &s_certMat);
    const bool keyOk  = load_entry("key", ATREST_LABEL_KEY,
                                   s_key, sizeof(s_key), &s_keyLen, &s_keyMat);

    if (!certOk || !keyOk) {
        Log.printf("[tls] TLS material present but unreadable (sealed record could not be "
                      "opened; check eFuse " ATREST_BLOCK_NAME "). Run `import` to replace it.\n");
        return;
    }

    const bool haveBoth = (s_certLen > 0 && s_keyLen > 0);
    const bool anyPlain = (s_certMat == CERT_MATERIAL_PLAIN || s_keyMat == CERT_MATERIAL_PLAIN);
    if (!haveBoth || !anyPlain) {
        return;
    }

    const AtRestKeyState st = atrest_key_state();
    char msg[96];

    if (st == ATREST_KEY_OK) {
        if (s_burnLatched) {
            Log.println("[tls] WARNING: a previous eFuse burn failed; not sealing with a key "
                        "that may be incomplete. Material stays plaintext (see `wrap-status`).");
            return;
        }
        if (!certstore_reseal(msg, sizeof(msg))) {
            Log.printf("[tls] could not seal stored material: %s\n", msg);
        } else {
            Log.println("[tls] stored TLS material sealed with the eFuse key.");
        }
        return;
    }

    if (!kAtRestWrapRequired) {
        Log.println("[tls] TLS material is stored plaintext (kAtRestWrapRequired is false).");
        return;
    }

    if (st == ATREST_KEY_ERROR) {
        Log.println("[tls] WARNING: kAtRestWrapRequired is set but eFuse " ATREST_BLOCK_NAME
                    " is owned by another purpose. Material stays plaintext.");
        return;
    }

    // Policy requires wrapping, material is present, BLK_KEY5 is free: burn now.
    if (s_burnLatched) {
        Log.println("[tls] WARNING: kAtRestWrapRequired is set but a previous burn failed; "
                    "not retrying. Material stays plaintext (see `wrap-status`).");
        return;
    }

    if (!atrest_provision(msg, sizeof(msg))) {
        s_tls.putUChar("bfail", 1);
        s_burnLatched = true;
        Log.printf("[tls] ERROR: could not burn " ATREST_BLOCK_NAME ": %s\n", msg);
        Log.println("[tls] Material stays plaintext. Check `wrap-status` and use `wrap-key`.");
        return;
    }
    s_tls.remove("bfail");
    s_burnLatched = false;
    Log.println("[tls] burned eFuse " ATREST_BLOCK_NAME " and sealed the stored material.");

    if (!certstore_reseal(msg, sizeof(msg))) {
        Log.printf("[tls] WARNING: sealing after the burn failed: %s\n", msg);
    }
}

bool certstore_burn_latched() { return s_burnLatched; }

void certstore_clear_burn_latch() {
    s_burnLatched = false;
    s_tls.remove("bfail");
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

CertMaterial certstore_cert_material() { return s_certMat; }
CertMaterial certstore_key_material()  { return s_keyMat; }

bool certstore_save_cert(const char* pem, size_t len) {
    if (len == 0 || len > MAX_CERT_PEM_LEN) return false;
    if (!store_entry("cert", ATREST_LABEL_CERT, pem, len)) return false;
    memcpy(s_cert, pem, len);
    s_cert[len] = 0;
    s_certLen = len;
    s_certMat = (atrest_key_state() == ATREST_KEY_OK) ? CERT_MATERIAL_SEALED
                                                      : CERT_MATERIAL_PLAIN;
    return true;
}

bool certstore_save_key(const char* pem, size_t len) {
    if (len == 0 || len > MAX_KEY_PEM_LEN) return false;
    if (!store_entry("key", ATREST_LABEL_KEY, pem, len)) return false;
    memcpy(s_key, pem, len);
    s_key[len] = 0;
    s_keyLen = len;
    s_keyMat = (atrest_key_state() == ATREST_KEY_OK) ? CERT_MATERIAL_SEALED
                                                     : CERT_MATERIAL_PLAIN;
    return true;
}

bool certstore_reseal(char* msg, size_t cap) {
    if (msg && cap) {
        msg[0] = 0;
    }
    if (atrest_key_state() != ATREST_KEY_OK) {
        snprintf(msg, cap, "no eFuse wrapping key in " ATREST_BLOCK_NAME);
        return false;
    }

    const bool anyPlain = (s_certMat == CERT_MATERIAL_PLAIN || s_keyMat == CERT_MATERIAL_PLAIN);
    if (!anyPlain) {
        snprintf(msg, cap, "already sealed");
        return true;
    }

    // Wipe first: an obsolete plaintext record would otherwise survive in flash.
    if (!certstore_wipe_partition()) {
        snprintf(msg, cap, "partition erase failed");
        return false;
    }
    s_certMat = CERT_MATERIAL_NONE;
    s_keyMat  = CERT_MATERIAL_NONE;

    bool ok = true;
    if (s_certLen > 0) {
        ok = certstore_save_cert(s_cert, s_certLen) && ok;
    }
    if (s_keyLen > 0) {
        ok = certstore_save_key(s_key, s_keyLen) && ok;
    }
    snprintf(msg, cap, "%s", ok ? "material re-sealed" : "re-seal FAILED");
    return ok;
}

bool certstore_clear_cert() {
    const bool ok = s_tls.remove("cert");
    s_certLen = 0;
    s_cert[0] = 0;
    s_certMat = CERT_MATERIAL_NONE;
    return ok;
}

bool certstore_clear_key() {
    const bool ok = s_tls.remove("key");
    s_keyLen = 0;
    s_key[0] = 0;
    s_keyMat = CERT_MATERIAL_NONE;
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
