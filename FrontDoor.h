/*
 * FrontDoor.h
 *
 * The security gate, in three layers, earliest first:
 *   1. EthGate (optional) drops blocked/over-budget SYNs in the Ethernet RX path
 *      and charges an allowed SYN (credited at accept time).
 *   2. frontdoor_on_open() accounts each accepted connection (httpd's open_fn;
 *      its verdict is discarded under HTTPS).
 *   3. frontdoor_admit_request() runs first in every handler and enforces 403/429.
 *
 * Stores: a throttle ring (RAM) and a blocklist (PSRAM). Both are read from the
 * RX task and httpd, so all access is lock-protected.
 */

#ifndef FRONTDOOR_H
#define FRONTDOOR_H

#include <stdint.h>
#include <esp_http_server.h>

// Verdict of frontdoor_gate_syn().
enum FrontDoorSynVerdict {
    FRONTDOOR_SYN_FORWARD = 0,  // charged; deliver the frame
    FRONTDOOR_SYN_DROP    = 1   // blocked, over budget, or unusable
};

// Allocate the throttle ring (RAM) and blocklist (PSRAM). Must run before the
// EthGate RX filter is installed (see frontdoor_ready()).
void frontdoor_begin();

// Gate one TCP SYN from `ip` (network byte order). Blocked/over-budget peers are
// refused; every other SYN is charged and remembered as an accept-time credit.
// Called from the RX task: lock once, no allocation, non-blocking. Refuses 0.
// Fails closed while the stores are missing.
FrontDoorSynVerdict frontdoor_gate_syn(uint32_t ip);

// Account one accepted connection (blocklist + throttle). False if blocked or
// over budget. Spends the SYN credit if one was charged (see frontdoor_gate_syn).
bool frontdoor_admit(uint32_t ip);

// Is `ip` on the blocklist? Fails closed (reports true while uninitialized).
bool frontdoor_blocked(uint32_t ip);

// Are the gate stores allocated? False until frontdoor_begin().
bool frontdoor_ready();

// Has `ip` exhausted its connection budget this window? Non-mutating; false again
// once the window rolls over.
bool frontdoor_throttle_over(uint32_t ip);

// Hard-block `ip` and log why (`why` may be null). No timeout - stays blocked until
// unblocked/cleared. `ip == 0` is ignored.
void frontdoor_block_ip_reason(uint32_t ip, const char* why);

// Hard-block an IP.
void frontdoor_block_ip(uint32_t ip);

// Remove one IP from the blocklist. False if it wasn't blocked.
bool frontdoor_unblock_ip(uint32_t ip);

// Remove every entry from the blocklist.
void frontdoor_clear_blocklist();

// How many IPs are currently blocked.
uint16_t frontdoor_blocklist_count();

// Copy up to `cap` blocked IPs (network byte order) into `out`. Order is arbitrary.
uint16_t frontdoor_blocklist_snapshot(uint32_t* out, uint16_t cap);

// Record one failed auth attempt; blocks the IP after kFailuresBeforeBlock.
void frontdoor_record_failure(uint32_t ip);
// Clear the failure streak for `ip` (called on a successful authentication).
void frontdoor_clear_failures(uint32_t ip);

// IPv4 address (network byte order) of the peer of `sockfd`, or 0 on failure / a
// non-IPv4 peer. Uses a sockaddr_storage and unwraps IPv4-mapped IPv6 (::ffff:a.b.c.d).
uint32_t frontdoor_peer_ipv4(int sockfd);

// Connections accepted and torn down since boot (diagnostics for the `stats` command).
uint32_t frontdoor_connections_opened();
uint32_t frontdoor_connections_closed();

// Authoritative per-request gate; call first in every handler. Sends the 403/429
// itself and returns false (then drop the connection):
//
//     if (!frontdoor_admit_request(req)) { return ESP_FAIL; }
//
// Also refuses cross-site / non-JSON requests without counting a failure or blocking
// (a browser can be made to send those on behalf of some page the operator is viewing).
bool frontdoor_admit_request(httpd_req_t* req);

// httpd connection callbacks. on_open only accounts + logs (its verdict is discarded
// under HTTPS). on_close also closes the socket: httpd's close_fn REPLACES its default
// close(), so failing to close would leak a socket per connection.
esp_err_t frontdoor_on_open(httpd_handle_t hd, int sockfd);
void frontdoor_on_close(httpd_handle_t hd, int sockfd);

#endif // FRONTDOOR_H
