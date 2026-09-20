/*
 * FrontDoor.cpp
 *
 * Implementation of the pre-payload connection gate.
 */

#include "Config.h"
#include "FrontDoor.h"
#include "Log.h"
#include "Acl.h"
#include <Arduino.h>
#include <esp_log.h>
#include <esp_heap_caps.h>
#include <lwip/sockets.h>
#include <freertos/FreeRTOS.h>
#include <freertos/portmacro.h>
#include <string.h>

static const char* TAG = "frontdoor";

// ---------------------------------------------------------------------------
// Rate limiter (circular ring in internal RAM)
// ---------------------------------------------------------------------------

struct ThrottleSlot {
    uint32_t ip;            // network byte order; 0 => empty
    uint32_t windowStartMs; // start of the current window (millis())
    uint16_t count;         // charges seen in the current window
    uint16_t credits;       // charged SYNs not yet claimed by an accepted connection
    bool overBudget;        // budget was exceeded in this window -> frozen
};

static ThrottleSlot s_ring[kThrottleRingSize];
static uint16_t s_ringHead = 0;

// ---------------------------------------------------------------------------
// Locking - stores are read from httpd/loop AND the Ethernet RX task, so all
// access runs under this short spinlock. Keep critical sections tiny; never log.
// ---------------------------------------------------------------------------

static portMUX_TYPE s_gateLock = portMUX_INITIALIZER_UNLOCKED;

// Connections accepted / torn down since boot (diagnostics). Plain words: a race
// only misses a count on a read.
static volatile uint32_t s_connOpens = 0;
static volatile uint32_t s_connCloses = 0;

// Locate (or round-robin claim) the slot for `ip`; a window past expiry restarts fresh.
// LOCKED: caller holds s_gateLock.
static ThrottleSlot* throttle_slot_locked(uint32_t ip) {
    uint32_t now = millis();

    for (uint16_t i = 0; i < kThrottleRingSize; ++i) {
        if (s_ring[i].ip == ip) {
            if (now - s_ring[i].windowStartMs >= kThrottleWindowMs) {
                // Window rolled over; the budget resets. An unspent SYN credit is
                // simply charged at accept time.
                s_ring[i].windowStartMs = now;
                s_ring[i].count = 0;
                s_ring[i].credits = 0;
                s_ring[i].overBudget = false;
            }
            return &s_ring[i];
        }
    }

    // No slot: claim one (round-robin eviction).
    ThrottleSlot* slot = &s_ring[s_ringHead];
    s_ringHead = (uint16_t)((s_ringHead + 1) % kThrottleRingSize);
    slot->ip = ip;
    slot->windowStartMs = now;
    slot->count = 0;
    slot->credits = 0;
    slot->overBudget = false;
    return slot;
}

// Charge one SYN. False when over budget (drop it). Over-budget peers are not
// frozen here - their already-paid-for connections still work.
// LOCKED: caller holds s_gateLock.
static bool throttle_charge_syn_locked(uint32_t ip) {
    ThrottleSlot* slot = throttle_slot_locked(ip);

    if (slot->count >= kMaxConnPerWindowPerIP) {
        return false;
    }

    ++slot->count;
    // Credit for the accept-time accounting to spend (credits <= count).
    ++slot->credits;
    return true;
}

// Account one accepted connection. False when over budget.
// LOCKED: caller holds s_gateLock.
static bool throttle_admit_locked(uint32_t ip) {
    ThrottleSlot* slot = throttle_slot_locked(ip);

    if (slot->credits > 0) {
        // This connection's SYN was already charged at L2.
        --slot->credits;
        return true;
    }

    if (slot->count >= kMaxConnPerWindowPerIP) {
        // Over budget (gate inactive, or the SYN predates it): freeze this window.
        slot->overBudget = true;
        return false;
    }

    ++slot->count;
    return true;
}

// ---------------------------------------------------------------------------
// Blocklist (PSRAM): open-addressing hash set, O(1) membership. Membership is
// tested for every SYN in the RX task under the gate lock, so it must not scan.
//   0 = empty (never a real peer);
//   delete = backward-shift (no tombstones, no rehash);
//   at capacity the victim is chosen by a cursor, so it holds the most recent offenders.
// ---------------------------------------------------------------------------

// The table must be a power of two (index = hash & (slots - 1)) and 2x it must
// still fit the uint16_t slot index.
static const uint16_t kBlocklistSlots = (uint16_t)(kBlocklistMaxEntries * 2);
static_assert(kBlocklistMaxEntries > 0, "kBlocklistMaxEntries must be > 0");
static_assert((kBlocklistMaxEntries & (kBlocklistMaxEntries - 1)) == 0,
              "kBlocklistMaxEntries must be a power of two (the blocklist is a hash table)");
static_assert(kBlocklistMaxEntries <= 16384,
              "kBlocklistMaxEntries above 16384 would overflow the uint16_t slot index (2x table)");

static uint32_t* s_blocklist = nullptr;   // kBlocklistSlots entries; 0 = empty
static uint16_t s_blocklistCount = 0;     // occupied slots (never above kBlocklistMaxEntries)
static uint16_t s_blocklistCursor = 0;    // where the next eviction starts looking

// Knuth multiply + murmur3 fmix32. The finalizer spreads sequential peers (10.0.0.1,
// 10.0.0.2, ...) that a bare multiply would leave clustered; ~1-2 probes per lookup.
// Reads only its input, allocates nothing: safe on the RX path.
static inline uint16_t blocklist_slot(uint32_t ip) {
    uint32_t h = ip * 2654435761u;  // Knuth multiplicative
    h ^= h >> 16;                   // murmur3 fmix32
    h *= 0x85EBCA6Bu;
    h ^= h >> 13;
    h *= 0xC2B2AE35u;
    h ^= h >> 16;
    return (uint16_t)(h & (uint32_t)(kBlocklistSlots - 1));
}

// LOCKED: caller must hold s_gateLock. Locate `ip`; returns false when absent.
static bool blocklist_find_locked(uint32_t ip, uint16_t* idxOut) {
    if (ip == 0) {
        return false; // never a key (see the header note)
    }
    uint16_t idx = blocklist_slot(ip);
    for (uint16_t probes = 0; probes < kBlocklistSlots; ++probes) {
        const uint32_t key = s_blocklist[idx];
        if (key == 0) {
            return false; // empty slot: the probe chain ends here
        }
        if (key == ip) {
            if (idxOut) *idxOut = idx;
            return true;
        }
        idx = (uint16_t)((idx + 1) & (uint16_t)(kBlocklistSlots - 1));
    }
    return false; // unreachable while the load factor is <= 0.5 (kept as a bound)
}

// LOCKED: caller must hold s_gateLock.
static bool blocklist_contains_locked(uint32_t ip) {
    return blocklist_find_locked(ip, nullptr);
}

// Remove the entry at `idx` with backward-shift deletion (no tombstones, no rehash).
// LOCKED: caller holds s_gateLock.
static void blocklist_erase_at_locked(uint16_t idx) {
    const uint16_t mask = (uint16_t)(kBlocklistSlots - 1);
    uint16_t hole = idx;
    uint16_t j = hole;
    for (;;) {
        j = (uint16_t)((j + 1) & mask);
        const uint32_t key = s_blocklist[j];
        if (key == 0) {
            break; // end of the cluster
        }
        const uint16_t home = blocklist_slot(key);
        // Move the key down into the hole if the hole is on its probe path.
        const uint16_t toHole = (uint16_t)((hole - home) & mask);
        const uint16_t toSelf = (uint16_t)((j - home) & mask);
        if (toHole <= toSelf) {
            s_blocklist[hole] = key;
            hole = j;
        }
    }
    s_blocklist[hole] = 0;
    --s_blocklistCount;
}

// Free one slot at capacity; the cursor spreads victims around the table.
// LOCKED: caller holds s_gateLock.
static void blocklist_evict_one_locked() {
    const uint16_t mask = (uint16_t)(kBlocklistSlots - 1);
    for (uint16_t n = 0; n < kBlocklistSlots; ++n) {
        s_blocklistCursor = (uint16_t)((s_blocklistCursor + 1) & mask);
        if (s_blocklist[s_blocklistCursor] != 0) {
            blocklist_erase_at_locked(s_blocklistCursor);
            return;
        }
    }
    // Unreachable: this is only called with s_blocklistCount >= 1.
}

// Public query; fails closed (reports "blocked" while uninitialized).
bool frontdoor_blocked(uint32_t ip) {
    portENTER_CRITICAL(&s_gateLock);
    bool blocked = (s_blocklist == nullptr) ? true : blocklist_contains_locked(ip);
    portEXIT_CRITICAL(&s_gateLock);
    return blocked;
}

// True once the blocklist store exists (the RX filter won't install before this).
bool frontdoor_ready() {
    portENTER_CRITICAL(&s_gateLock);
    bool ready = (s_blocklist != nullptr);
    portEXIT_CRITICAL(&s_gateLock);
    return ready;
}

// Insert `ip` (ignoring duplicates, evicting at capacity).
// LOCKED: caller holds s_gateLock.
static void blocklist_add_locked(uint32_t ip) {
    if (ip == 0) {
        return; // never a key (see the header note)
    }
    if (blocklist_contains_locked(ip)) {
        return; // already blocked
    }
    if (s_blocklistCount >= kBlocklistMaxEntries) {
        blocklist_evict_one_locked();
    }
    // A free slot is guaranteed (2x capacity, <= 0.5 load), so this probe terminates.
    uint16_t idx = blocklist_slot(ip);
    while (s_blocklist[idx] != 0) {
        idx = (uint16_t)((idx + 1) & (uint16_t)(kBlocklistSlots - 1));
    }
    s_blocklist[idx] = ip;
    ++s_blocklistCount;
}

// ---------------------------------------------------------------------------
// Failure accounting (small RAM map) -> feeds the blocklist
// ---------------------------------------------------------------------------

struct FailureSlot {
    uint32_t ip;
    uint16_t count;
};

static FailureSlot s_failures[32];
static uint16_t s_failureCount = 0;

void frontdoor_record_failure(uint32_t ip) {
    bool block = false;

    portENTER_CRITICAL(&s_gateLock);
    bool found = false;
    for (uint16_t i = 0; i < s_failureCount; ++i) {
        if (s_failures[i].ip == ip) {
            found = true;
            ++s_failures[i].count;
            if (s_failures[i].count >= kFailuresBeforeBlock) {
                block = true;
                s_failures[i] = s_failures[--s_failureCount]; // remove
            }
            break;
        }
    }
    if (!found && s_failureCount < 32) {
        s_failures[s_failureCount].ip = ip;
        s_failures[s_failureCount].count = 1;
        ++s_failureCount;
    }
    portEXIT_CRITICAL(&s_gateLock);

    if (block) {
        // Deferred: frontdoor_block_ip() logs, and logging can't run in the critical section.
        frontdoor_block_ip(ip);
    }
}

// Clear the failure streak for `ip` (a successful authentication resets it).
void frontdoor_clear_failures(uint32_t ip) {
    portENTER_CRITICAL(&s_gateLock);
    for (uint16_t i = 0; i < s_failureCount; ++i) {
        if (s_failures[i].ip == ip) {
            s_failures[i] = s_failures[--s_failureCount]; // swap-remove
            break;
        }
    }
    portEXIT_CRITICAL(&s_gateLock);
}

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

// Boot-time setup (before any task consults the gate, and before eth_gate_begin).
// No lock needed.
void frontdoor_begin() {
    memset(s_ring, 0, sizeof(s_ring));
    s_ringHead = 0;

    // Blocklist in PSRAM; a failed allocation makes frontdoor_blocked() fail closed.
    const size_t blocklistBytes = (size_t)kBlocklistSlots * sizeof(uint32_t);
    bool blocklistInPsram = true;
    s_blocklist = (uint32_t*)heap_caps_malloc(blocklistBytes, MALLOC_CAP_SPIRAM);
    if (s_blocklist == nullptr) {
        blocklistInPsram = false;
        Log.printf("[gate] PSRAM unavailable for the blocklist (%u B); falling back to internal RAM\n",
                      (unsigned)blocklistBytes);
        s_blocklist = (uint32_t*)malloc(blocklistBytes);
    }

    if (s_blocklist == nullptr) {
        Log.printf("[gate] FATAL: no memory for the blocklist (%u B) - every request will be "
                      "refused, because frontdoor_blocked() fails closed\n", (unsigned)blocklistBytes);
    } else {
        memset(s_blocklist, 0, blocklistBytes); // 0 = EMPTY slot
        Log.printf("[gate] blocklist ready: %u slots, up to %u blocked IPs (%u B in %s)\n",
                      (unsigned)kBlocklistSlots, (unsigned)kBlocklistMaxEntries,
                      (unsigned)blocklistBytes, blocklistInPsram ? "PSRAM" : "internal RAM");
    }
    s_blocklistCount = 0;
    s_blocklistCursor = 0;

    memset(s_failures, 0, sizeof(s_failures));
    s_failureCount = 0;
}

FrontDoorSynVerdict frontdoor_gate_syn(uint32_t ip) {
    // 0 is the ring's "empty" sentinel, never a peer.
    if (ip == 0) {
        return FRONTDOOR_SYN_DROP;
    }

    // One lock for blocklist + budget + charge, so verdict and accounting agree.
    portENTER_CRITICAL(&s_gateLock);
    bool allow = (s_blocklist != nullptr) &&
                 !blocklist_contains_locked(ip) &&
                 throttle_charge_syn_locked(ip);
    portEXIT_CRITICAL(&s_gateLock);

    return allow ? FRONTDOOR_SYN_FORWARD : FRONTDOOR_SYN_DROP;
}

bool frontdoor_admit(uint32_t ip) {
    if (frontdoor_blocked(ip)) {
        return false;
    }

    portENTER_CRITICAL(&s_gateLock);
    bool admitted = throttle_admit_locked(ip);
    portEXIT_CRITICAL(&s_gateLock);
    return admitted;
}

static bool throttle_over_locked(uint32_t ip) {
    uint32_t now = millis();

    for (uint16_t i = 0; i < kThrottleRingSize; ++i) {
        if (s_ring[i].ip == ip) {
            if (now - s_ring[i].windowStartMs >= kThrottleWindowMs) {
                return false; // window rolled over -> the budget is fresh again
            }
            return s_ring[i].overBudget;
        }
    }
    return false; // no slot: this IP has not connected in the current window
}

bool frontdoor_throttle_over(uint32_t ip) {
    portENTER_CRITICAL(&s_gateLock);
    bool over = throttle_over_locked(ip);
    portEXIT_CRITICAL(&s_gateLock);
    return over;
}

// Admin IPs are never hard-blocked, whatever the trigger (the runtime allowlist).
static bool frontdoor_ip_is_admin(uint32_t ip) {
    return acl_is_admin(ip);
}

void frontdoor_block_ip_reason(uint32_t ip, const char* why) {
    // 0 is the ring's "empty" sentinel, never a peer.
    if (ip == 0) {
        return;
    }
    // Never block an admin source IP.
    if (frontdoor_ip_is_admin(ip)) {
        return;
    }

    portENTER_CRITICAL(&s_gateLock);
    blocklist_add_locked(ip);
    portEXIT_CRITICAL(&s_gateLock);

    // Log outside the critical section.
    IPAddress a(ip);
    if (why) {
        Log.printf("[block] %s: %s\n", a.toString().c_str(), why);
    } else {
        Log.printf("[block] %s\n", a.toString().c_str());
    }
}

void frontdoor_block_ip(uint32_t ip) {
    frontdoor_block_ip_reason(ip, nullptr);
}

bool frontdoor_unblock_ip(uint32_t ip) {
    bool removed = false;
    portENTER_CRITICAL(&s_gateLock);
    if (s_blocklist != nullptr) {
        uint16_t idx = 0;
        if (blocklist_find_locked(ip, &idx)) {
            blocklist_erase_at_locked(idx);
            removed = true;
        }
    }
    portEXIT_CRITICAL(&s_gateLock);

    if (removed) {
        IPAddress a(ip);
        Log.printf("[block] unblocked %s\n", a.toString().c_str());
    }
    return removed;
}

void frontdoor_clear_blocklist() {
    // One locked wipe (operator action; chunking would let a probe chain be observed torn).
    portENTER_CRITICAL(&s_gateLock);
    if (s_blocklist != nullptr) {
        memset(s_blocklist, 0, (size_t)kBlocklistSlots * sizeof(uint32_t)); // 0 = EMPTY
    }
    s_blocklistCount = 0;
    s_blocklistCursor = 0;
    portEXIT_CRITICAL(&s_gateLock);

    Log.println("[block] blocklist cleared");
}

uint16_t frontdoor_blocklist_count() {
    portENTER_CRITICAL(&s_gateLock);
    uint16_t count = s_blocklistCount;
    portEXIT_CRITICAL(&s_gateLock);
    return count;
}

uint16_t frontdoor_blocklist_snapshot(uint32_t* out, uint16_t cap) {
    if (!out || cap == 0) {
        return 0;
    }

    // Walks every slot under the lock (console `blocks` command only; order is arbitrary).
    portENTER_CRITICAL(&s_gateLock);
    uint16_t n = 0;
    if (s_blocklist != nullptr) {
        for (uint16_t i = 0; i < kBlocklistSlots && n < cap; ++i) {
            if (s_blocklist[i] != 0) {
                out[n++] = s_blocklist[i];
            }
        }
    }
    portEXIT_CRITICAL(&s_gateLock);
    return n;
}

// ---------------------------------------------------------------------------
// Peer address
// ---------------------------------------------------------------------------

uint32_t frontdoor_peer_ipv4(int sockfd) {
    if (sockfd < 0) {
        return 0;
    }

    // sockaddr_storage is big enough for any family, so lwIP won't truncate.
    struct sockaddr_storage peer;
    socklen_t peerLen = sizeof(peer);
    if (getpeername(sockfd, (struct sockaddr*)&peer, &peerLen) != 0) {
        // Can't identify the peer -> fail closed.
        return 0;
    }

    if (peer.ss_family == AF_INET) {
        return ((struct sockaddr_in*)&peer)->sin_addr.s_addr; // network byte order
    }

#if LWIP_IPV6
    if (peer.ss_family == AF_INET6) {
        const struct sockaddr_in6* peer6 = (const struct sockaddr_in6*)&peer;
        const uint8_t* addr = (const uint8_t*)&peer6->sin6_addr; // 16 bytes

        // IPv4-mapped (::ffff:a.b.c.d): the IPv4 address is the last four bytes.
        static const uint8_t kV4MappedPrefix[12] = {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF
        };
        if (memcmp(addr, kV4MappedPrefix, sizeof(kV4MappedPrefix)) == 0) {
            uint32_t ip;
            memcpy(&ip, addr + sizeof(kV4MappedPrefix), sizeof(ip));
            return ip;
        }
    }
#endif

    return 0;
}

// ---------------------------------------------------------------------------
// Request gate (authoritative) + httpd callbacks
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Request provenance: a page the operator is visiting could make their browser
// send a request here (e.g. <img src=".../admin">). Those requests are refused
// WITHOUT recording a failure or blocking, so a drive-by page can't lock out the
// operator. Both checks fail open when the header is absent (scripts send none).
// ---------------------------------------------------------------------------

// Is `val` equal to `want`, ignoring case (HTTP header syntax is case-insensitive)?
static bool header_value_is(const char* val, const char* want) {
    size_t i = 0;
    for (; val[i] && want[i]; ++i) {
        char a = val[i], b = want[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return false;
    }
    return val[i] == 0 && want[i] == 0;
}

// Did the browser label this request cross-site / same-site? (Fetch metadata.)
static bool request_is_cross_site(httpd_req_t* req) {
    char v[16];
    if (httpd_req_get_hdr_value_str(req, "Sec-Fetch-Site", v, sizeof(v)) != ESP_OK) {
        return false; // no fetch metadata: a script or a browser too old to send it
    }
    return header_value_is(v, "cross-site") || header_value_is(v, "same-site");
}

// Only our own pages POST JSON; requiring the header also covers bodyless POSTs
// (a cross-origin form can't produce application/json, and no preflight is answered).
static bool request_is_json(httpd_req_t* req) {
    char v[64];
    if (httpd_req_get_hdr_value_str(req, "Content-Type", v, sizeof(v)) != ESP_OK) {
        return false;
    }
    // Trim, then compare the media type up to any ';' parameters, so both "application/json"
    // and "application/json; charset=utf-8" pass.
    size_t i = 0;
    while (v[i] == ' ' || v[i] == '\t') ++i;
    char mt[32];
    size_t o = 0;
    while (v[i] && v[i] != ';' && o + 1 < sizeof(mt)) {
        mt[o++] = v[i++];
    }
    mt[o] = 0;
    while (o > 0 && (mt[o - 1] == ' ' || mt[o - 1] == '\t')) {
        mt[--o] = 0;
    }
    return header_value_is(mt, "application/json");
}

bool frontdoor_admit_request(httpd_req_t* req) {
    uint32_t ip = frontdoor_peer_ipv4(httpd_req_to_sockfd(req));

    // Headers every response carries, set here so even the gate's own refusals have
    // them. String literals: httpd stores pointers, not copies.
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(req, "Referrer-Policy", "no-referrer");

    // Every rejection path fails closed: the caller drops the connection after
    // this returns false.
    const char* status;
    const char* body;

    if (request_is_cross_site(req)) {
        // Refused, not blocked: the browser is acting for another page.
        status = "403 Forbidden";
        body = "{\"error\":\"cross_site\"}";
        if (ip == 0) {
            Log.println("[gate] refused a cross-site request from an unidentified peer");
        } else {
            IPAddress a(ip);
            Log.printf("[gate] refused a cross-site request from %s (not blocked: a browser "
                          "acted for another origin)\n", a.toString().c_str());
        }
    } else if (req->method == HTTP_POST && !request_is_json(req)) {
        status = "415 Unsupported Media Type";
        body = "{\"error\":\"json_required\"}";
        if (ip == 0) {
            Log.println("[gate] refused a non-JSON POST from an unidentified peer");
        } else {
            IPAddress a(ip);
            Log.printf("[gate] refused a non-JSON POST from %s\n", a.toString().c_str());
        }
    } else if (ip == 0) {
        status = "403 Forbidden";
        body = "{\"error\":\"forbidden\"}";
        Log.println("[gate] refused a request from an unidentified peer");
    } else if (frontdoor_blocked(ip)) {
        status = "403 Forbidden";
        body = "{\"error\":\"forbidden\"}";
        IPAddress a(ip);
        Log.printf("[gate] refused a request from blocklisted IP %s\n", a.toString().c_str());
    } else if (frontdoor_throttle_over(ip)) {
        status = "429 Too Many Requests";
        body = "{\"error\":\"rate_limited\"}";
        IPAddress a(ip);
        Log.printf("[gate] refused a request from %s (over the connection budget)\n",
                      a.toString().c_str());
    } else {
        return true;
    }

    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, body);
    return false;
}

esp_err_t frontdoor_on_open(httpd_handle_t hd, int sockfd) {
    (void)hd;

    // Half of the L2 gate's "SYNs charged" pair.
    ++s_connOpens;

    // Disable Nagle: a short body would otherwise wait for the peer's delayed ACK.
    // Set per-socket once here (covers keep-alive reuse); log the failure once.
    if (sockfd >= 0) {
        const int one = 1;
        if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) != 0) {
            static bool loggedNoDelay = false;
            if (!loggedNoDelay) {
                loggedNoDelay = true;
                Log.println("[gate] TCP_NODELAY could not be set on a connection; short "
                               "responses may wait out the peer's delayed ACK");
            }
        }
    }

    // One accepted connection. Under HTTPS the return value is DISCARDED, so this
    // only accounts (blocklist + throttle) and logs; enforcement is per-request.
    uint32_t ip = frontdoor_peer_ipv4(sockfd);
    if (ip == 0) {
        // Unidentifiable peer -> fail closed.
        Log.println("[gate] connection from an unidentified peer; its requests will be refused");
        return ESP_FAIL;
    }

    IPAddress a(ip);
    if (!frontdoor_admit(ip)) {
        Log.printf("[gate] connection from %s is blocklisted or over budget; its requests will be refused\n",
                      a.toString().c_str());
        return ESP_FAIL;
    }

    ESP_LOGD(TAG, "Accepted connection from %s", a.toString().c_str());
    return ESP_OK;
}

uint32_t frontdoor_connections_opened() {
    return s_connOpens;
}

uint32_t frontdoor_connections_closed() {
    return s_connCloses;
}

void frontdoor_on_close(httpd_handle_t hd, int sockfd) {
    (void)hd;

    ++s_connCloses;

    // close_fn REPLACES httpd's default close(), so this hook must close the socket.
    if (sockfd >= 0) {
        close(sockfd);
    }
}
