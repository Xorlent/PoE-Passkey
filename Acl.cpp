/*
 * Acl.cpp - see Acl.h. Each list lives in a small RAM array (rebuilt from NVS at
 * boot); add/remove mutate the array under a short spinlock and then persist the
 * whole list. The lock is held only for the array mutation, never for the NVS write.
 */

#include "Acl.h"
#include "Config.h"

#include <Preferences.h>
#include <freertos/FreeRTOS.h>
#include <freertos/portmacro.h>
#include <string.h>

static const char* ACL_NS        = "acl";
static const char* ACL_ADMIN_KEY = "admin";
static const char* ACL_CONS_KEY  = "consumer";

static uint32_t s_admin[kAllowlistMaxEntries];
static uint8_t  s_adminN = 0;
static uint32_t s_consumer[kAllowlistMaxEntries];
static uint8_t  s_consumerN = 0;

static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;

static uint32_t* list_base(acl_list_t list) {
    return (list == ACL_ADMIN) ? s_admin : s_consumer;
}
static uint8_t& list_count(acl_list_t list) {
    return (list == ACL_ADMIN) ? s_adminN : s_consumerN;
}

bool acl_is_non_public(uint32_t ip) {
    // Octet order matches EthGate.cpp's logging: the low byte is the first octet.
    const uint32_t a = ip & 0xFF;
    const uint32_t b = (ip >> 8) & 0xFF;
    if (a == 10) return true;                       // 10/8
    if (a == 127) return true;                      // loopback
    if (a == 169 && b == 254) return true;          // link-local
    if (a == 172 && b >= 16 && b <= 31) return true;// 172.16/12
    if (a == 192 && b == 168) return true;          // 192.168/16
    return false;
}

// LOCKED: caller holds s_lock.
static bool contains_locked(acl_list_t list, uint32_t ip) {
    for (uint8_t i = 0; i < list_count(list); ++i) {
        if (list_base(list)[i] == ip) return true;
    }
    return false;
}

// Persist a list (its whole array) to NVS. Best-effort: RAM is authoritative this boot.
static bool persist(acl_list_t list) {
    Preferences p;
    if (!p.begin(ACL_NS, false)) return false;
    const uint32_t* base = list_base(list);
    const size_t n = (size_t)list_count(list) * sizeof(uint32_t);
    const bool ok = p.putBytes((list == ACL_ADMIN) ? ACL_ADMIN_KEY : ACL_CONS_KEY, base, n) == n;
    p.end();
    return ok;
}

static void seed_from_config() {
    s_adminN = 0;
    for (uint32_t i = 0; i < kAdminIPCount && s_adminN < kAllowlistMaxEntries; ++i) {
        s_admin[s_adminN++] = (uint32_t)kAdminIPs[i];
    }
    s_consumerN = 0;
    for (uint32_t i = 0; i < kConsumerAllowlistCount && s_consumerN < kAllowlistMaxEntries; ++i) {
        s_consumer[s_consumerN++] = (uint32_t)kConsumerAllowlist[i];
    }
}

void acl_begin() {
    Preferences p;
    if (!p.begin(ACL_NS, false)) {
        seed_from_config();          // NVS unavailable: RAM-only seeds this boot
        return;
    }
    if (!p.isKey(ACL_ADMIN_KEY) || !p.isKey(ACL_CONS_KEY)) {
        seed_from_config();          // first boot (or partial store): seed + persist
        p.putBytes(ACL_ADMIN_KEY, s_admin, (size_t)s_adminN * sizeof(uint32_t));
        p.putBytes(ACL_CONS_KEY, s_consumer, (size_t)s_consumerN * sizeof(uint32_t));
        p.end();
        return;
    }
    uint8_t buf[kAllowlistMaxEntries * sizeof(uint32_t)];
    size_t len = p.getBytes(ACL_ADMIN_KEY, buf, sizeof(buf));
    s_adminN = (uint8_t)((len / sizeof(uint32_t)) > kAllowlistMaxEntries ? kAllowlistMaxEntries : (len / sizeof(uint32_t)));
    memcpy(s_admin, buf, (size_t)s_adminN * sizeof(uint32_t));
    len = p.getBytes(ACL_CONS_KEY, buf, sizeof(buf));
    s_consumerN = (uint8_t)((len / sizeof(uint32_t)) > kAllowlistMaxEntries ? kAllowlistMaxEntries : (len / sizeof(uint32_t)));
    memcpy(s_consumer, buf, (size_t)s_consumerN * sizeof(uint32_t));
    p.end();
}

bool acl_is_admin(uint32_t ip) {
    portENTER_CRITICAL(&s_lock);
    const bool found = contains_locked(ACL_ADMIN, ip);
    portEXIT_CRITICAL(&s_lock);
    return found;
}

bool acl_is_consumer(uint32_t ip) {
    portENTER_CRITICAL(&s_lock);
    const bool found = contains_locked(ACL_CONSUMER, ip);
    portEXIT_CRITICAL(&s_lock);
    return found;
}

size_t acl_count(acl_list_t list) {
    portENTER_CRITICAL(&s_lock);
    const size_t n = (size_t)list_count(list);
    portEXIT_CRITICAL(&s_lock);
    return n;
}

size_t acl_snapshot(acl_list_t list, uint32_t* out, size_t cap) {
    if (out == nullptr || cap == 0) return 0;
    portENTER_CRITICAL(&s_lock);
    const size_t n = (size_t)list_count(list);
    for (size_t i = 0; i < n && i < cap; ++i) {
        out[i] = list_base(list)[i];
    }
    portEXIT_CRITICAL(&s_lock);
    return n;
}

bool acl_add(acl_list_t list, uint32_t ip) {
    if (!kRuntimeAllowlistEdits) return false;
    if (list == ACL_ADMIN && kAdminIPsNonPublicOnly && !acl_is_non_public(ip)) {
        return false;
    }
    bool ok = false;
    portENTER_CRITICAL(&s_lock);
    if (list_count(list) < kAllowlistMaxEntries && !contains_locked(list, ip)) {
        list_base(list)[list_count(list)] = ip;
        ++list_count(list);
        ok = true;
    }
    portEXIT_CRITICAL(&s_lock);
    if (ok) persist(list);
    return ok;
}

bool acl_remove(acl_list_t list, uint32_t ip) {
    if (!kRuntimeAllowlistEdits) return false;
    bool removed = false;
    portENTER_CRITICAL(&s_lock);
    const uint8_t n = list_count(list);
    for (uint8_t i = 0; i < n; ++i) {
        if (list_base(list)[i] == ip) {
            for (uint8_t j = i; j + 1 < n; ++j) list_base(list)[j] = list_base(list)[j + 1];
            list_count(list) = n - 1;
            removed = true;
            break;
        }
    }
    portEXIT_CRITICAL(&s_lock);
    if (removed) persist(list);
    return removed;
}
