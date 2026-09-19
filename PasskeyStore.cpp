/*
 * PasskeyStore.cpp
 */

#include "Config.h"
#include "PasskeyStore.h"
#include "Crypto.h"
#include "Clock.h"

#include <Arduino.h>
#include <Preferences.h>
#include <nvs.h>
#include <nvs_flash.h>
#include <esp_partition.h>
#include <string.h>
#include <stdio.h>
#include <freertos/FreeRTOS.h>
#include <freertos/portmacro.h>

// ---------------------------------------------------------------------------
// Credentials (NVS via Preferences)
// ---------------------------------------------------------------------------

static Preferences s_nvs;
static const char* NVS_NS = "creds";

// Credentials live in their own `nvs_creds` partition (see partitions.csv): the default
// 20 KB `nvs` partition holds ~30 records - fewer than kMaxCredentials - and also holds the
// TLS material, so a full credential store must not crowd it out. store_begin() mounts it.
static const char* NVS_PART = "nvs_creds";

static void cred_key(char* out, size_t cap, uint16_t idx) {
    snprintf(out, cap, "c%u", idx);
}

// Is an NVS blob safe to use? Nothing is assumed: check the magic, ID length,
// user-handle length, and that `email` is NUL-terminated (handlers print it with %s).
static bool cred_blob_valid(const StoredCredential* c) {
    if (c->magic != PASSKEY_CRED_MAGIC) return false;
    if (c->credIdLen == 0) return false;
    if (c->userHandleLen > USER_HANDLE_LEN) return false;
    if (memchr(c->email, 0, sizeof(c->email)) == nullptr) return false;
    return true;
}

// ---------------------------------------------------------------------------
// Credential index (PSRAM). NVS is the source of truth; this is only an accelerator
// that turns a lookup into ONE blob read instead of scanning every slot. A hit is always
// confirmed against the blob, and a mismatch/missing index falls back to a full scan, so
// a wrong index can only make a lookup slower, never wrong. Stores an FNV-1a digest
// (16 B/slot; digest 0 = no entry) rather than the full id.
// ---------------------------------------------------------------------------

struct CredIndexEntry {
    uint64_t digest; // FNV-1a over the credential id; 0 = no entry for this slot
    uint8_t  idLen;
    uint8_t  usedThisBoot; // authenticated since this boot (RAM-only; reset at boot)
};

// The used-flag lives in padding, so the entry stays 16 B.
static_assert(sizeof(CredIndexEntry) == 16, "CredIndexEntry must stay 16 B (the used-flag lives in its padding)");

static CredIndexEntry* s_index = nullptr; // kMaxCredentials entries, or nullptr

// Guards the index (httpd vs loop()); NVS reads/writes stay outside the critical section.
static portMUX_TYPE s_indexLock = portMUX_INITIALIZER_UNLOCKED;

static uint64_t cred_digest(const uint8_t* id, size_t len) {
    uint64_t h = 1469598103934665603ull; // FNV-1a 64 offset basis
    for (size_t i = 0; i < len; ++i) {
        h ^= (uint64_t)id[i];
        h *= 1099511628211ull;           // FNV-1a 64 prime
    }
    return h;
}

// LOCKED internally (short, no I/O).
static void index_set(uint16_t slot, const uint8_t* id, size_t idLen) {
    if (idLen == 0 || idLen > MAX_STORED_CRED_ID_LEN) return;
    const uint64_t d = cred_digest(id, idLen);
    portENTER_CRITICAL(&s_indexLock);
    if (s_index && slot < kMaxCredentials) {
        s_index[slot].digest = d;
        s_index[slot].idLen = (uint8_t)idLen;
    }
    portEXIT_CRITICAL(&s_indexLock);
}

// LOCKED internally.
static void index_clear(uint16_t slot) {
    portENTER_CRITICAL(&s_indexLock);
    if (s_index && slot < kMaxCredentials) {
        s_index[slot].digest = 0;
        s_index[slot].idLen = 0;
        s_index[slot].usedThisBoot = 0; // a free slot has no boot history
    }
    portEXIT_CRITICAL(&s_indexLock);
}

// Has `slot` authenticated since boot? 1/0, or -1 when the index is missing (unknown).
static int8_t index_used(uint16_t slot) {
    int8_t used = -1;
    portENTER_CRITICAL(&s_indexLock);
    if (s_index && slot < kMaxCredentials) {
        used = s_index[slot].usedThisBoot ? 1 : 0;
    }
    portEXIT_CRITICAL(&s_indexLock);
    return used;
}

// Set the boot-used flag (auth path = true, new credential = false).
static void index_set_used(uint16_t slot, bool used) {
    portENTER_CRITICAL(&s_indexLock);
    if (s_index && slot < kMaxCredentials) {
        s_index[slot].usedThisBoot = used ? 1 : 0;
    }
    portEXIT_CRITICAL(&s_indexLock);
}

// Slot the index believes holds `credId`, or -1. The caller MUST confirm with the blob.
static int index_find(const uint8_t* credId, size_t credIdLen) {
    if (!s_index || credIdLen == 0 || credIdLen > MAX_STORED_CRED_ID_LEN) return -1;
    const uint64_t d = cred_digest(credId, credIdLen);
    if (d == 0) return -1;
    int found = -1;
    portENTER_CRITICAL(&s_indexLock);
    for (uint16_t i = 0; i < kMaxCredentials; ++i) {
        if (s_index[i].digest == d && s_index[i].idLen == credIdLen) {
            found = (int)i;
            break;
        }
    }
    portEXIT_CRITICAL(&s_indexLock);
    return found;
}

// Rebuild the whole index from NVS. Boot-time only.
static void index_rebuild() {
    if (!s_index) return;
    StoredCredential tmp;
    for (uint16_t i = 0; i < kMaxCredentials; ++i) {
        index_clear(i);
        char key[16];
        cred_key(key, sizeof(key), i);
        size_t got = s_nvs.getBytes(key, &tmp, sizeof(tmp));
        if (got == sizeof(tmp) && cred_blob_valid(&tmp)) {
            index_set(i, tmp.credId, tmp.credIdLen);
        }
    }
}
// Locate the slot holding `credId`. On success fills `out` (if non-null),
// `idxOut` (if non-null), and `keyOut` (if non-null).
static bool cred_find_slot(const uint8_t* credId, size_t credIdLen,
                           StoredCredential* out, uint16_t* idxOut,
                           char* keyOut, size_t keyCap) {
    // Fast path: the index names one slot, so one blob is read instead of every blob. That
    // read is also the confirmation - if the ids do not match, the entry was stale (or a
    // digest collision) and we drop it and fall through to the scan.
    const int guess = index_find(credId, credIdLen);
    if (guess >= 0) {
        char key[16];
        cred_key(key, sizeof(key), (uint16_t)guess);
        StoredCredential tmp;
        size_t got = s_nvs.getBytes(key, &tmp, sizeof(tmp));
        if (got == sizeof(tmp) && cred_blob_valid(&tmp) &&
            tmp.credIdLen == credIdLen && crypto_const_eq(tmp.credId, credId, credIdLen)) {
            if (out) memcpy(out, &tmp, sizeof(tmp));
            if (idxOut) *idxOut = (uint16_t)guess;
            if (keyOut) { strncpy(keyOut, key, keyCap - 1); keyOut[keyCap - 1] = 0; }
            return true;
        }
        index_clear((uint16_t)guess);
    }

    StoredCredential tmp;
    for (uint16_t i = 0; i < kMaxCredentials; ++i) {
        char key[16];
        cred_key(key, sizeof(key), i);
        size_t got = s_nvs.getBytes(key, &tmp, sizeof(tmp));
        if (got != sizeof(tmp) || !cred_blob_valid(&tmp)) {
            index_clear(i); // nothing usable here: make sure the index agrees
            continue;
        }
        index_set(i, tmp.credId, tmp.credIdLen); // keep the index in step while scanning
        if (tmp.credIdLen == credIdLen && crypto_const_eq(tmp.credId, credId, credIdLen)) {
            if (out) memcpy(out, &tmp, sizeof(tmp));
            if (idxOut) *idxOut = i;
            if (keyOut) { strncpy(keyOut, key, keyCap - 1); keyOut[keyCap - 1] = 0; }
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Per-credential state (NVS `s<N>`). Kept separate from the record so it can grow without
// invalidating every stored credential; disabling rewrites 12 bytes, not the whole record.
// An absent entry means "enabled, never seen".
// ---------------------------------------------------------------------------

#define PASSKEY_STATE_MAGIC    0x53544154U // "STAT"
#define PASSKEY_STATE_DISABLED 0x01

struct CredState {
    uint32_t magic;
    uint8_t  flags;
    uint8_t  reserved[3];
    uint32_t lastSeenUnix; // 0 = unknown: the device had no clock when the key was used
};

static void state_key(char* out, size_t cap, uint16_t idx) {
    snprintf(out, cap, "s%u", idx);
}

// Absent/malformed state reads as the default (enabled, unknown time) - never an error.
static void state_read(uint16_t slot, CredState* out) {
    memset(out, 0, sizeof(*out));
    out->magic = PASSKEY_STATE_MAGIC;
    char key[16];
    state_key(key, sizeof(key), slot);
    CredState tmp;
    if (s_nvs.getBytes(key, &tmp, sizeof(tmp)) == sizeof(tmp) && tmp.magic == PASSKEY_STATE_MAGIC) {
        *out = tmp;
    }
}

static bool state_write(uint16_t slot, const CredState* st) {
    char key[16];
    state_key(key, sizeof(key), slot);
    return s_nvs.putBytes(key, st, sizeof(*st)) == sizeof(*st);
}

// Defined with the authorized-IP store at the bottom of this file. Declared here because a slot
// whose occupant changes (or whose key is revoked/disabled) must not keep an attribution that
// belonged to the previous key - see the invariant in PasskeyStore.h.
static void authz_forget_slot(uint16_t slot);
static void authz_drop_ip_if_unvouched(uint16_t slot);

bool cred_store(const StoredCredential* c) {
    // credIdLen is a uint8_t, so it cannot exceed the 256-byte array it indexes;
    // only 0 is invalid (see MAX_STORED_CRED_ID_LEN for the caller-side rule).
    if (c->credIdLen == 0) return false;
    if (memchr(c->email, 0, sizeof(c->email)) == nullptr) return false;

    // The scan starts at slot 0 and stops at the first slot that is free, unusable, or
    // already holding THIS credential, so storing is idempotent: a re-registration rewrites
    // the credential in place and can never produce a second copy of the same id.
    //
    // The index is deliberately NOT used to pick the slot, only refreshed as the scan walks
    // past it. For a lookup the index is safe to trust because the blob it names is read
    // back and compared; but a *miss* could mean "not here" when the credential is in fact
    // present (it takes only one stale entry), and writing on that basis would duplicate
    // the credential instead of rewriting it. Registration is a rare, user-initiated
    // action, so it keeps its original cost - one blob read per slot up to the first free
    // one under the usual fill-from-slot-0 pattern - and its original semantics exactly.
    // The hot path the index exists for is authentication, which now reads one blob per
    // assertion instead of every blob in the store.
    for (uint16_t i = 0; i < kMaxCredentials; ++i) {
        char key[16];
        cred_key(key, sizeof(key), i);
        StoredCredential probe;
        size_t got = s_nvs.getBytes(key, &probe, sizeof(probe));

        bool absent = (got == 0);
        // Present but unusable (wrong size, bad magic, out-of-range lengths,
        // non-terminated email): treat the slot as free so the store heals
        // instead of keeping garbage forever.
        bool unusable = (got > 0 && (got != sizeof(probe) || !cred_blob_valid(&probe)));
        bool sameCred = (got == sizeof(probe) && cred_blob_valid(&probe) &&
                         probe.credIdLen == c->credIdLen &&
                         crypto_const_eq(probe.credId, c->credId, c->credIdLen));

        if (absent || unusable || sameCred) {
            bool ok = s_nvs.putBytes(key, c, sizeof(*c)) == sizeof(*c);
            if (ok) {
                index_set(i, c->credId, c->credIdLen);
                if (!sameCred) {
                    // A NEW occupant of this slot must not inherit the previous one's state
                    // (its disable flag, its last-used date, or the authorized IP it was
                    // attributed to), and it has not authenticated yet.
                    char skey[16];
                    state_key(skey, sizeof(skey), i);
                    s_nvs.remove(skey);
                    index_set_used(i, false);
                    authz_forget_slot(i);
                }
            }
            return ok;
        }
        index_set(i, probe.credId, probe.credIdLen); // a real credential: record it
    }
    return false; // credential store full
}

bool cred_lookup(const uint8_t* credId, size_t credIdLen, StoredCredential* out) {
    return cred_lookup_ex(credId, credIdLen, out, nullptr, nullptr);
}

// Auth-path lookup: record + state (disabled/last-used), and `slotOut` = the slot (what IP
// attribution is keyed on).
bool cred_lookup_ex(const uint8_t* credId, size_t credIdLen, StoredCredential* out,
                    CredRuntime* rt, uint16_t* slotOut) {
    if (credIdLen == 0 || credIdLen > MAX_STORED_CRED_ID_LEN) return false;
    uint16_t idx;
    if (!cred_find_slot(credId, credIdLen, out, &idx, nullptr, 0)) return false;
    if (slotOut) *slotOut = idx;
    if (rt) {
        CredState st;
        state_read(idx, &st);
        rt->usedThisBoot = index_used(idx);
        rt->disabled = (st.flags & PASSKEY_STATE_DISABLED) != 0;
        rt->lastSeenUnix = st.lastSeenUnix;
    }
    return true;
}

bool cred_set_disabled(const uint8_t* credId, size_t credIdLen, bool disabled) {
    if (credIdLen == 0 || credIdLen > MAX_STORED_CRED_ID_LEN) return false;
    uint16_t idx;
    if (!cred_find_slot(credId, credIdLen, nullptr, &idx, nullptr, 0)) return false;

    CredState st;
    state_read(idx, &st);   // keeps any last-used date
    if (disabled) {
        st.flags |= PASSKEY_STATE_DISABLED;
    } else {
        st.flags &= (uint8_t)~PASSKEY_STATE_DISABLED;
    }
    st.magic = PASSKEY_STATE_MAGIC;
    const bool ok = state_write(idx, &st);
    // Disabling: drop the attribution (and the address if no other enabled key vouches).
    if (ok && disabled) authz_drop_ip_if_unvouched(idx);
    return ok;
}

bool cred_update_counter(const uint8_t* credId, size_t credIdLen,
                         uint32_t newSignCount, uint32_t lastUsedAtMs) {
    StoredCredential tmp;
    char key[16];
    uint16_t idx;
    if (!cred_find_slot(credId, credIdLen, &tmp, &idx, key, sizeof(key))) return false;
    tmp.signCount = newSignCount;
    tmp.lastUsedAtMs = lastUsedAtMs;
    const bool ok = s_nvs.putBytes(key, &tmp, sizeof(tmp)) == sizeof(tmp);
    // Only if the record made it to flash mark it "used this boot".
    if (ok) {
        index_set_used(idx, true);
        // Date the use (when the clock is known); leave an existing date alone otherwise.
        uint32_t unixNow;
        if (clock_now(&unixNow)) {
            CredState st;
            state_read(idx, &st);
            st.magic = PASSKEY_STATE_MAGIC;
            st.lastSeenUnix = unixNow;
            state_write(idx, &st);
        }
    }
    return ok;
}

size_t cred_foreach(cred_sink_t sink, void* ctx) {
    size_t n = 0;
    StoredCredential tmp;
    // Read every slot (not the index), so the listing is complete even if the index is empty.
    for (uint16_t i = 0; i < kMaxCredentials; ++i) {
        char key[16];
        cred_key(key, sizeof(key), i);
        size_t got = s_nvs.getBytes(key, &tmp, sizeof(tmp));
        if (got != sizeof(tmp) || !cred_blob_valid(&tmp)) {
            index_clear(i);
            continue;
        }
        index_set(i, tmp.credId, tmp.credIdLen);
        ++n;
        if (sink) {
            CredState st;
            state_read(i, &st);
            CredRuntime rt;
            rt.usedThisBoot = index_used(i);
            rt.disabled = (st.flags & PASSKEY_STATE_DISABLED) != 0;
            rt.lastSeenUnix = st.lastSeenUnix;
            if (!sink(&tmp, &rt, ctx)) break; // early stop (e.g. the client hung up)
        }
    }
    return n;
}

size_t cred_count() {
    return cred_foreach(nullptr, nullptr);
}

// Resolve a slot to the person behind it (one NVS read, no enumeration).
bool cred_email_at(uint16_t slot, char* out, size_t cap) {
    if (!out || cap == 0 || slot >= kMaxCredentials) return false;
    char key[16];
    cred_key(key, sizeof(key), slot);
    StoredCredential tmp;
    const size_t got = s_nvs.getBytes(key, &tmp, sizeof(tmp));
    if (got != sizeof(tmp) || !cred_blob_valid(&tmp)) return false;
    strncpy(out, tmp.email, cap - 1);
    out[cap - 1] = 0;
    return true;
}

bool cred_delete(const uint8_t* credId, size_t credIdLen) {
    if (credIdLen == 0 || credIdLen > MAX_STORED_CRED_ID_LEN) return false;
    char key[16];
    uint16_t idx;
    if (!cred_find_slot(credId, credIdLen, nullptr, &idx, key, sizeof(key))) return false;
    bool ok = s_nvs.remove(key);
    if (ok) {
        // State dies with the credential (a reused slot must not inherit it).
        char skey[16];
        state_key(skey, sizeof(skey), idx);
        s_nvs.remove(skey);
        index_clear(idx);
        authz_drop_ip_if_unvouched(idx);
    }
    return ok;
}

// ---------------------------------------------------------------------------
// Sessions (RAM)
// ---------------------------------------------------------------------------

static AuthSession s_sessions[kMaxSessions];
static RegistrationSession s_registrations[kMaxRegistrations];

// The per-IP cap protects the (public) auth store: 0 would refuse every auth, and a cap above
// the store size could never bind.
static_assert(kMaxSessionsPerIP > 0, "kMaxSessionsPerIP of 0 would refuse every ceremony");
static_assert(kMaxSessionsPerIP <= kMaxSessions,
              "kMaxSessionsPerIP above kMaxSessions can never bind (the store is smaller)");

// Past kSessionTtlMs? Signed compare (millis() wraps every ~49 days).
static bool session_expired(uint32_t createdAtMs, uint32_t now) {
    return (int32_t)(now - createdAtMs) > (int32_t)kSessionTtlMs;
}

bool session_create(const uint8_t challenge[32], uint32_t peerIp) {
    const uint32_t now = millis();

    // Find a free slot, and (for this peer) how many / which is oldest. Dead entries are
    // released here so they don't count toward the peer's cap.
    int freeSlot = -1;
    int peerOldest = -1;
    uint16_t peerCount = 0;
    for (uint16_t i = 0; i < kMaxSessions; ++i) {
        if (s_sessions[i].active && session_expired(s_sessions[i].createdAtMs, now)) {
            s_sessions[i].active = false;
        }
        if (!s_sessions[i].active) {
            if (freeSlot < 0) freeSlot = (int)i;
            continue;
        }
        if (peerIp != 0 && s_sessions[i].peerIp == peerIp) {
            ++peerCount;
            if (peerOldest < 0 ||
                s_sessions[i].createdAtMs < s_sessions[peerOldest].createdAtMs) {
                peerOldest = (int)i;
            }
        }
    }

    // Over the cap, a peer takes back its own oldest slot (never another client's).
    int slot = freeSlot;
    if (peerIp != 0 && peerCount >= kMaxSessionsPerIP && peerOldest >= 0) {
        slot = peerOldest;
    }
    if (slot < 0) {
        return false;
    }

    AuthSession& rec = s_sessions[slot];
    memset(&rec, 0, sizeof(rec));
    memcpy(rec.challenge, challenge, 32);
    rec.peerIp = peerIp;
    rec.active = true;
    rec.createdAtMs = now;
    return true;
}

bool registration_create(const uint8_t challenge[32], uint32_t peerIp,
                         const char* email, const uint8_t* userHandle, uint8_t uhl) {
    const uint32_t now = millis();

    // Small and admin-gated: one pass to reclaim expired entries and find a free slot.
    int freeSlot = -1;
    for (uint16_t i = 0; i < kMaxRegistrations; ++i) {
        if (s_registrations[i].active &&
            session_expired(s_registrations[i].createdAtMs, now)) {
            s_registrations[i].active = false;
        }
        if (!s_registrations[i].active && freeSlot < 0) {
            freeSlot = (int)i;
        }
    }
    if (freeSlot < 0) {
        return false;
    }

    RegistrationSession& rec = s_registrations[freeSlot];
    memset(&rec, 0, sizeof(rec));
    memcpy(rec.challenge, challenge, 32);
    rec.peerIp = peerIp;
    rec.active = true;
    rec.createdAtMs = now;
    if (email) strncpy(rec.email, email, MAX_EMAIL_LEN - 1);
    if (userHandle && uhl <= USER_HANDLE_LEN) {
        memcpy(rec.userHandle, userHandle, uhl);
        rec.userHandleLen = uhl;
    }
    return true;
}

bool session_consume(const uint8_t challenge[32]) {
    const uint32_t now = millis();
    for (uint16_t i = 0; i < kMaxSessions; ++i) {
        if (s_sessions[i].active && crypto_const_eq(s_sessions[i].challenge, challenge, 32)) {
            if (session_expired(s_sessions[i].createdAtMs, now)) {
                s_sessions[i].active = false;
                return false;
            }
            s_sessions[i].active = false; // one-time consumption
            return true;
        }
    }
    return false;
}

bool registration_consume(const uint8_t challenge[32], RegistrationSession* out) {
    const uint32_t now = millis();
    for (uint16_t i = 0; i < kMaxRegistrations; ++i) {
        if (s_registrations[i].active &&
            crypto_const_eq(s_registrations[i].challenge, challenge, 32)) {
            if (session_expired(s_registrations[i].createdAtMs, now)) {
                s_registrations[i].active = false;
                return false;
            }
            if (out) memcpy(out, &s_registrations[i], sizeof(*out));
            s_registrations[i].active = false; // one-time consumption
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Authorized IPs (RAM, TTL)
// ---------------------------------------------------------------------------

struct AuthzIP {
    uint32_t ip;
    uint32_t expiresMs;
    bool     used;
};

static AuthzIP s_authz[kMaxAuthorizedIPs];

// The authorized IP each slot last authenticated from (0 = none), by value (not an index,
// since s_authz recycles slots). One row per key makes NAT free.
static uint32_t s_credAuthzIp[kMaxCredentials];

// Guards s_authz + s_credAuthzIp (touched by httpd handlers and loop()); sections are tiny,
// no formatting/logging inside.
static portMUX_TYPE s_authzLock = portMUX_INITIALIZER_UNLOCKED;

bool authzips_add(uint32_t ip, uint32_t ttlMs) {
    uint32_t now = millis();
    bool ok = false;

    portENTER_CRITICAL(&s_authzLock);
    // Refresh an existing entry (the same peer authenticating again extends its TTL)...
    for (uint16_t i = 0; i < kMaxAuthorizedIPs; ++i) {
        if (s_authz[i].used && s_authz[i].ip == ip) {
            s_authz[i].expiresMs = now + ttlMs;
            ok = true;
            break;
        }
    }
    // ...otherwise claim a free slot.
    if (!ok) {
        for (uint16_t i = 0; i < kMaxAuthorizedIPs; ++i) {
            if (!s_authz[i].used) {
                s_authz[i].used = true;
                s_authz[i].ip = ip;
                s_authz[i].expiresMs = now + ttlMs;
                ok = true;
                break;
            }
        }
    }
    portEXIT_CRITICAL(&s_authzLock);
    return ok;
}

// ---------------------------------------------------------------------------
// Attribution: which key was last seen behind an authorized IP
// ---------------------------------------------------------------------------

// Clear every attribution row naming `ip` (keeps the "row <=> authorized address" invariant).
// LOCKED: caller holds s_authzLock.
static void authz_clear_rows_locked(uint32_t ip) {
    for (uint16_t s = 0; s < kMaxCredentials; ++s) {
        if (s_credAuthzIp[s] == ip) s_credAuthzIp[s] = 0;
    }
}

// Forget one credential's attribution (defined early; used by cred_store).
static void authz_forget_slot(uint16_t slot) {
    if (slot >= kMaxCredentials) return;
    portENTER_CRITICAL(&s_authzLock);
    s_credAuthzIp[slot] = 0;
    portEXIT_CRITICAL(&s_authzLock);
}

void authzips_note_user(uint32_t ip, uint16_t slot) {
    if (ip == 0 || slot >= kMaxCredentials) return;
    portENTER_CRITICAL(&s_authzLock);
    // Record only if the address is authorized right now (preserves the invariant).
    bool authorized = false;
    for (uint16_t i = 0; i < kMaxAuthorizedIPs; ++i) {
        if (s_authz[i].used && s_authz[i].ip == ip) { authorized = true; break; }
    }
    if (authorized) s_credAuthzIp[slot] = ip;
    portEXIT_CRITICAL(&s_authzLock);
}

bool authzips_user_next(uint32_t ip, uint16_t* cursor, uint16_t* slotOut) {
    if (!cursor || !slotOut || ip == 0) return false;
    bool found = false;
    portENTER_CRITICAL(&s_authzLock);
    for (uint16_t s = *cursor; s < kMaxCredentials; ++s) {
        if (s_credAuthzIp[s] == ip) {
            *slotOut = s;
            *cursor = (uint16_t)(s + 1);
            found = true;
            break;
        }
    }
    // Leave the cursor past the end once the walk is over, so asking again is O(1) rather than
    // another scan (a caller restarts by passing cursor = 0).
    if (!found) *cursor = kMaxCredentials;
    portEXIT_CRITICAL(&s_authzLock);
    return found;
}

// Is some other *enabled* credential attributed to `ip`? The lock is re-taken per row so NVS
// reads stay outside the critical section (a concurrent prune is benign here).
static bool authz_other_enabled_user_behind(uint32_t ip, uint16_t exceptSlot) {
    for (uint16_t s = 0; s < kMaxCredentials; ++s) {
        if (s == exceptSlot) continue;
        bool attributed;
        portENTER_CRITICAL(&s_authzLock);
        attributed = (s_credAuthzIp[s] == ip);
        portEXIT_CRITICAL(&s_authzLock);
        if (!attributed) continue;
        CredState st;
        state_read(s, &st);
        if ((st.flags & PASSKEY_STATE_DISABLED) == 0) return true; // still vouched for
    }
    return false;
}

// Key revoked/disabled: drop its attribution, and revoke the address when no other ENABLED
// key is behind it (the NAT case - don't cut off other users behind the same address). Called
// after the credential's state change is written.
static void authz_drop_ip_if_unvouched(uint16_t slot) {
    if (slot >= kMaxCredentials) return;
    uint32_t ip;
    portENTER_CRITICAL(&s_authzLock);
    ip = s_credAuthzIp[slot];
    s_credAuthzIp[slot] = 0;   // this key no longer vouches for anything
    portEXIT_CRITICAL(&s_authzLock);
    if (ip == 0) return;                                   // it was not behind an address
    if (authz_other_enabled_user_behind(ip, slot)) return;  // somebody else still is
    authzips_remove(ip);   // the last voucher is gone: the authorization dies, and with it
                           // every remaining row naming that address
}

size_t authzips_prune(uint32_t nowMs) {
    size_t removed = 0;
    portENTER_CRITICAL(&s_authzLock);
    for (uint16_t i = 0; i < kMaxAuthorizedIPs; ++i) {
        if (s_authz[i].used && (int32_t)(nowMs - s_authz[i].expiresMs) >= 0) {
            // The address leaves the authorized set, so nothing may stay attributed to it.
            authz_clear_rows_locked(s_authz[i].ip);
            s_authz[i].used = false;
            ++removed;
        }
    }
    portEXIT_CRITICAL(&s_authzLock);
    return removed;
}

size_t authzips_collect(uint32_t* out, size_t cap) {
    uint32_t now = millis();
    size_t n = 0;

    portENTER_CRITICAL(&s_authzLock);
    for (uint16_t i = 0; i < kMaxAuthorizedIPs; ++i) {
        if (!s_authz[i].used) continue;
        if ((int32_t)(now - s_authz[i].expiresMs) >= 0) {
            authz_clear_rows_locked(s_authz[i].ip); // attribution goes with the authorization
            s_authz[i].used = false; // lazily prune
            continue;
        }
        if (n < cap) out[n] = s_authz[i].ip;
        ++n;
    }
    portEXIT_CRITICAL(&s_authzLock);
    return n;
}

bool authzips_remove(uint32_t ip) {
    bool removed = false;
    portENTER_CRITICAL(&s_authzLock);
    for (uint16_t i = 0; i < kMaxAuthorizedIPs; ++i) {
        if (s_authz[i].used && s_authz[i].ip == ip) {
            authz_clear_rows_locked(ip); // a revoked address keeps no attribution
            s_authz[i].used = false;
            removed = true;
            break;
        }
    }
    portEXIT_CRITICAL(&s_authzLock);
    return removed;
}

// ---------------------------------------------------------------------------

void store_begin() {
    memset(s_sessions, 0, sizeof(s_sessions));
    memset(s_registrations, 0, sizeof(s_registrations));
    memset(s_authz, 0, sizeof(s_authz));
    // The attribution rows name the addresses in s_authz, so they are cleared with it: after a
    // reboot no address is authorized, therefore no key is behind one.
    memset(s_credAuthzIp, 0, sizeof(s_credAuthzIp));

    // Mount the credential partition; recover the two "needs formatting" errors, and name the
    // failure (otherwise it's invisible until an enrollment fails).
    esp_err_t err = nvs_flash_init_partition(NVS_PART);
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        Serial.printf("[store] credential partition %s must be formatted (%s): erasing\n",
                      NVS_PART, esp_err_to_name(err));
        nvs_flash_erase_partition(NVS_PART);
        err = nvs_flash_init_partition(NVS_PART);
    }
    if (err != ESP_OK) {
        Serial.printf("[store] FATAL: credential partition %s is not available (%s). Enrollment "
                      "and authentication will fail until this build's partitions.csv is flashed "
                      "(the table needs an entry named %s).\n",
                      NVS_PART, esp_err_to_name(err), NVS_PART);
    } else if (!s_nvs.begin(NVS_NS, false, NVS_PART)) {
        Serial.printf("[store] FATAL: could not open namespace %s on partition %s.\n",
                      NVS_NS, NVS_PART);
    } else {
        const esp_partition_t* part = esp_partition_find_first(
            ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, NVS_PART);
        Serial.printf("[store] credentials live on NVS partition %s (%u KB)\n",
                      NVS_PART, part ? (unsigned)(part->size / 1024) : 0);
    }

    // The index is an accelerator: if it can't be allocated, lookups fall back to scanning.
    const size_t indexBytes = (size_t)kMaxCredentials * sizeof(CredIndexEntry);
    bool indexInPsram = true;
    s_index = (CredIndexEntry*)heap_caps_malloc(indexBytes, MALLOC_CAP_SPIRAM);
    if (s_index == nullptr) {
        indexInPsram = false;
        Serial.printf("[store] PSRAM unavailable for the credential index (%u B); falling back "
                      "to internal RAM\n", (unsigned)indexBytes);
        s_index = (CredIndexEntry*)malloc(indexBytes);
    }

    if (s_index == nullptr) {
        Serial.printf("[store] no memory for the credential index (%u B): every credential "
                      "lookup will scan all %u slots\n",
                      (unsigned)indexBytes, (unsigned)kMaxCredentials);
    } else {
        index_rebuild();
        size_t used = 0;
        portENTER_CRITICAL(&s_indexLock);
        for (uint16_t i = 0; i < kMaxCredentials; ++i) {
            if (s_index[i].digest != 0) ++used;
        }
        portEXIT_CRITICAL(&s_indexLock);
        Serial.printf("[store] credential index ready: %u of %u slots used (%u B in %s)\n",
                      (unsigned)used, (unsigned)kMaxCredentials, (unsigned)indexBytes,
                      indexInPsram ? "PSRAM" : "internal RAM");
    }
}

