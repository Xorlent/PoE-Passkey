/*
 * Acl.h
 *
 * Runtime-editable IP allowlists (admin + consumer), persisted in NVS. Config.h
 * kAdminIPs / kConsumerAllowlist are the SEED values copied on first boot; the NVS
 * copy is authoritative thereafter. Per-request checks go through a locked RAM copy
 * so they stay cheap and safe from any task.
 */

#ifndef ACL_H
#define ACL_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    ACL_ADMIN = 0,
    ACL_CONSUMER = 1,
} acl_list_t;

// Load the lists from NVS (seeding from Config.h the first time). Call once at boot.
void acl_begin();

bool acl_is_admin(uint32_t ip);      // ip in network byte order
bool acl_is_consumer(uint32_t ip);

// Number of entries currently in a list.
size_t acl_count(acl_list_t list);

// Copy `list` entries (network byte order) into `out`; returns the count (never > cap).
size_t acl_snapshot(acl_list_t list, uint32_t* out, size_t cap);

// Add one address. Fails if edits are disabled (kRuntimeAllowlistEdits), the list is
// full (kAllowlistMaxEntries), the address is already present, or (admin only) it is
// public while kAdminIPsNonPublicOnly. Persists on success.
bool acl_add(acl_list_t list, uint32_t ip);

// Remove one address. Fails if edits are disabled or the address is absent. Persists.
bool acl_remove(acl_list_t list, uint32_t ip);

// Is `ip` (network byte order) non-public (RFC 1918 10/8, 172.16/12, 192.168/16,
// plus 127/8 loopback and 169.254/16 link-local)? Enforces kAdminIPsNonPublicOnly.
bool acl_is_non_public(uint32_t ip);

#endif // ACL_H
