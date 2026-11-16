/*
 * AtRestCrypto.cpp - see AtRestCrypto.h.
 */

#include "AtRestCrypto.h"
#include "Config.h"
#include "Crypto.h"
#include "Log.h"

#include <string.h>
#include <stdio.h>
#include <esp_efuse.h>
#include <esp_hmac.h>
#include <mbedtls/gcm.h>

// Volatile: memset on a dead buffer can be elided.
static void wipe(void* p, size_t n) {
    volatile uint8_t* v = (volatile uint8_t*)p;
    while (n--) {
        *v++ = 0;
    }
}

static esp_efuse_block_t efuse_block() {
    return EFUSE_BLK_KEY5;
}

static hmac_key_id_t hmac_key() {
    return HMAC_KEY5;
}

AtRestKeyState atrest_key_state() {
    const esp_efuse_purpose_t p = esp_efuse_get_key_purpose(EFUSE_BLK_KEY5);
    if (p == ESP_EFUSE_KEY_PURPOSE_HMAC_UP) {
        return ATREST_KEY_OK;
    }
    if (p == ESP_EFUSE_KEY_PURPOSE_USER) {
        return ATREST_NO_KEY;
    }
    return ATREST_KEY_ERROR;
}

bool atrest_derive(const char* label, uint8_t out[32]) {
    if (!label || !out || atrest_key_state() != ATREST_KEY_OK) {
        return false;
    }
    return esp_hmac_calculate(hmac_key(), label, strlen(label), out) == ESP_OK;
}

bool atrest_is_sealed(const uint8_t* rec, size_t len) {
    return rec && len >= ATREST_OVERHEAD &&
           rec[0] == 'P' && rec[1] == 'K' && rec[2] == 'W' && rec[3] == '1' &&
           rec[4] == ATREST_FMT_SEALED;
}

size_t atrest_seal(const char* label, const uint8_t* pt, size_t n,
                   uint8_t* out, size_t cap) {
    if (!label || !out || (!pt && n != 0)) {
        return 0;
    }
    const size_t total = ATREST_OVERHEAD + n;
    if (total > cap) {
        return 0;
    }

    uint8_t k[32];
    if (!atrest_derive(label, k)) {
        return 0;
    }

    uint8_t* nonce = out + 5;
    uint8_t* ct    = out + 17;
    uint8_t* tag   = ct + n;
    crypto_random(nonce, 12);

    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    int r = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, k, 256);
    if (r == 0) {
        r = mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, n,
                                      nonce, 12,
                                      (const uint8_t*)label, strlen(label),
                                      pt, ct, 16, tag);
    }
    mbedtls_gcm_free(&g);
    wipe(k, sizeof(k));
    if (r != 0) {
        return 0;
    }

    out[0] = 'P';
    out[1] = 'K';
    out[2] = 'W';
    out[3] = '1';
    out[4] = (uint8_t)ATREST_FMT_SEALED;
    return total;
}

size_t atrest_open(const uint8_t* rec, size_t recLen, const char* label,
                   uint8_t* pt, size_t cap) {
    if (!rec || !label || !pt || !atrest_is_sealed(rec, recLen)) {
        return 0;
    }
    const size_t n = recLen - ATREST_OVERHEAD;
    if (n > cap) {
        return 0;
    }

    const uint8_t* nonce = rec + 5;
    const uint8_t* ct    = rec + 17;
    const uint8_t* tag   = ct + n;

    uint8_t k[32];
    if (!atrest_derive(label, k)) {
        return 0;
    }

    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    int r = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, k, 256);
    if (r == 0) {
        r = mbedtls_gcm_auth_decrypt(&g, n, nonce, 12,
                                     (const uint8_t*)label, strlen(label),
                                     tag, 16, ct, pt);
    }
    mbedtls_gcm_free(&g);
    wipe(k, sizeof(k));
    return (r == 0) ? n : 0;
}

bool atrest_provision(char* msg, size_t msgCap) {
    if (msg && msgCap) {
        msg[0] = 0;
    }
    const AtRestKeyState before = atrest_key_state();
    if (before == ATREST_KEY_OK) {
        snprintf(msg, msgCap, ATREST_BLOCK_NAME " already holds an HMAC key");
        return false;
    }
    if (before == ATREST_KEY_ERROR) {
        snprintf(msg, msgCap, ATREST_BLOCK_NAME " is owned by another purpose; refusing to touch it");
        return false;
    }

    // One wrapping key per device: refuse if any other block already holds one.
    esp_efuse_block_t other = EFUSE_BLK_KEY0;
    if (esp_efuse_find_purpose(ESP_EFUSE_KEY_PURPOSE_HMAC_UP, &other)) {
        snprintf(msg, msgCap,
                 "an HMAC_UP key already exists in BLK_KEY%d; refusing to burn a second one",
                 (int)other - (int)EFUSE_BLK_KEY0);
        return false;
    }

    uint8_t key[32];
    crypto_random(key, sizeof(key));

    esp_efuse_batch_write_begin();
    const esp_err_t err = esp_efuse_write_key(efuse_block(), ESP_EFUSE_KEY_PURPOSE_HMAC_UP,
                                              key, sizeof(key));
    if (err == ESP_OK) {
        esp_efuse_batch_write_commit();
    } else {
        esp_efuse_batch_write_cancel();
    }
    wipe(key, sizeof(key));

    if (err != ESP_OK) {
        snprintf(msg, msgCap, "write failed: %s", esp_err_to_name(err));
        return false;
    }
    if (atrest_key_state() != ATREST_KEY_OK) {
        snprintf(msg, msgCap, "block written but purpose does not read back as HMAC_UP");
        return false;
    }

    // The block is read-protected, so verify by a seal/open round trip.
    uint8_t pt[32];
    uint8_t back[32];
    uint8_t rec[ATREST_OVERHEAD + sizeof(pt)];
    crypto_random(pt, sizeof(pt));
    const size_t rl = atrest_seal(ATREST_LABEL_KEY, pt, sizeof(pt), rec, sizeof(rec));
    const size_t bl = rl ? atrest_open(rec, rl, ATREST_LABEL_KEY, back, sizeof(back)) : 0;
    const bool ok = (bl == sizeof(pt)) && (memcmp(pt, back, sizeof(pt)) == 0);
    wipe(pt, sizeof(pt));
    wipe(back, sizeof(back));
    if (!ok) {
        snprintf(msg, msgCap, "derived key self-test failed");
        return false;
    }

    snprintf(msg, msgCap, "key burned and verified");
    return true;
}
