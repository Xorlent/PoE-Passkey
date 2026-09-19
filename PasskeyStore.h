/*
 * PasskeyStore.h
 *
 * Stores: credentials (NVS, persistent), sessions (RAM, one-time challenges),
 * authorized IPs (RAM, TTL).
 */

#ifndef PASSKEYSTORE_H
#define PASSKEYSTORE_H

#include <stdint.h>
#include <stddef.h>

#define MAX_CRED_ID_LEN 256
#define MAX_STORED_CRED_ID_LEN 255 // credIdLen is a uint8_t; anything longer would wrap
#define MAX_EMAIL_LEN   128
#define USER_HANDLE_LEN 32
#define PASSKEY_CRED_MAGIC 0x50415353U  // "PASS"

// Per-credential state kept OUTSIDE the persisted record (so it can change size):
//   usedThisBoot  1/0/-1 = authenticated since boot / not / unknown.
//   disabled      admin disabled this key (persisted; fails auth until re-enabled).
//   lastSeenUnix  Unix time of last successful auth, or 0 if the clock was unknown.
struct CredRuntime {
    int8_t   usedThisBoot;
    bool     disabled;
    uint32_t lastSeenUnix;
};
struct StoredCredential {
    uint32_t magic;
    uint8_t  credId[MAX_CRED_ID_LEN];
    uint8_t  credIdLen;
    uint8_t  pubX[32];
    uint8_t  pubY[32];
    uint32_t signCount;
    uint8_t  userHandle[USER_HANDLE_LEN];
    uint8_t  userHandleLen;
    char     email[MAX_EMAIL_LEN];
    uint32_t createdAtMs;
    // millis() at last successful auth, or 0 if never used (uptime, not wall-clock).
    uint32_t lastUsedAtMs;
};

void store_begin();

// ---- Credentials (NVS) ----
bool   cred_store(const StoredCredential* c);
bool   cred_lookup(const uint8_t* credId, size_t credIdLen, StoredCredential* out);
// Same lookup, plus `rt` (disabled/last-used) and `slotOut` (the credential's slot); both
// may be null when only the record is wanted.
bool   cred_lookup_ex(const uint8_t* credId, size_t credIdLen, StoredCredential* out,
                      CredRuntime* rt, uint16_t* slotOut);
// Disable / re-enable a credential (reversible counterpart of cred_delete). Re-enrollment
// does not clear this.
bool   cred_set_disabled(const uint8_t* credId, size_t credIdLen, bool disabled);
bool   cred_update_counter(const uint8_t* credId, size_t credIdLen,
                           uint32_t newSignCount, uint32_t lastUsedAtMs);
// Number of stored credentials.
size_t cred_count();
// Revoke a credential by ID. True if removed.
bool   cred_delete(const uint8_t* credId, size_t credIdLen);
// Visit each credential in slot order; `sink` returns false to stop early. Streams (never
// materializes the whole store in RAM). A null sink just counts.
typedef bool (*cred_sink_t)(const StoredCredential* c, const CredRuntime* rt, void* ctx);
size_t cred_foreach(cred_sink_t sink, void* ctx);

// Email of the credential in `slot`, or false when empty/unusable (one NVS read).
bool   cred_email_at(uint16_t slot, char* out, size_t cap);

// ---- Sessions (RAM) ----

// Authentication sessions: one slim record per in-flight assertion (44 B). The public
// /auth/start path fills this store, so it carries nothing beyond the challenge it needs.
struct AuthSession {
    bool        active;
    uint8_t     challenge[32];
    uint32_t    peerIp;       // network byte order, 0 = unknown (bounds kMaxSessionsPerIP)
    uint32_t    createdAtMs;
};

// Registration carries the identity being enrolled (email + user handle), so it lives in its
// own small admin-gated store instead of padding every auth slot.
struct RegistrationSession {
    bool        active;
    uint8_t     challenge[32];
    uint32_t    peerIp;       // network byte order, 0 = unknown
    char        email[MAX_EMAIL_LEN];
    uint8_t     userHandle[USER_HANDLE_LEN];
    uint8_t     userHandleLen;
    uint32_t    createdAtMs;
};

// Start an authentication ceremony. Expired slots are reclaimed first. False only when full.
bool session_create(const uint8_t challenge[32], uint32_t peerIp);

// Start a registration ceremony (admin-gated). Expired slots are reclaimed first.
bool registration_create(const uint8_t challenge[32], uint32_t peerIp,
                         const char* email, const uint8_t* userHandle, uint8_t uhl);

// Consume (one-time) and clear the auth session matching `challenge`; enforces TTL.
bool session_consume(const uint8_t challenge[32]);

// Consume (one-time) and clear the registration matching `challenge`, copying the identity
// into `out`; enforces TTL.
bool registration_consume(const uint8_t challenge[32], RegistrationSession* out);

// ---- Authorized IPs (RAM, TTL) ----
bool   authzips_add(uint32_t ip, uint32_t ttlMs);
size_t authzips_prune(uint32_t nowMs);
// Copy up to `cap` valid authorized IPs into `out`; returns the total (may exceed `cap`).
size_t authzips_collect(uint32_t* out, size_t cap);
// Revoke an authorized IP. True if removed (its attribution rows are cleared too).
bool   authzips_remove(uint32_t ip);

// ---- Attribution: which key was last seen behind an authorized IP ----
//
// One row per credential SLOT (4 bytes each = 1 KB), storing the ADDRESS by value (the
// authorized-IP array recycles slots, so an index would re-point elsewhere). NAT costs
// nothing: two users behind one address hold two rows naming it.
//
// Invariant: a row is non-zero only while its address is authorized. Cleared wherever either
// side changes (note_user only records authorized addresses; prune/remove/collect clear rows;
// cred_store clears a slot's old row; cred_delete/disable drop it and revoke the address when
// no other ENABLED key is behind it).
void   authzips_note_user(uint32_t ip, uint16_t slot);
// Iterate the slots attributed to `ip`. Start with *cursor = 0; false when none left.
bool   authzips_user_next(uint32_t ip, uint16_t* cursor, uint16_t* slotOut);

#endif // PASSKEYSTORE_H
