/*
 * Config.h
 *
 * Everything provisioned at flash time. Edit the values below for your site.
 * Network identity, the WebAuthn Relying Party identity (RP ID / origin), the
 * admin and consumer allowlists and shared secret, and the security gate.
 * 
 * TLS cert + key are imported at runtime over the serial console (`import`).
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <IPAddress.h>

////////------------------------------------------- CONFIGURATION SETTINGS AREA -------------------------------------------////////

// Log one line per admitted request (refusals are always logged).
static const bool kLogHttpRequests = true;

////////// Network configuration //////////

// Ethernet hardware pins for the M5Stack Unit-PoE-P4 (TLK110 PHY):
#define ETH_TYPE        ETH_PHY_TLK110
#define ETH_ADDR        1
#define ETH_PHY_MDC     31
#define ETH_PHY_MDIO    52
#define ETH_POWER_PIN   51
#define ETH_CLK_MODE    EMAC_CLK_EXT_IN

static const IPAddress ip(192, 168, 1, 25);       // Device IP address
static const IPAddress gateway(192, 168, 1, 1);   // Default gateway
static const IPAddress subnet(255, 255, 255, 0);  // Subnet mask
static const IPAddress dns1(9, 9, 9, 9);          // Primary DNS
static const IPAddress dns2(149, 112, 112, 112);  // Secondary DNS

////////// WebAuthn Relying Party identity //////////

// RP ID: the domain credentials are bound to. Must be a real domain that
// resolves to this device (browsers reject IPs and mDNS names).
static const char* kRpId = "passkey.vuln.plc.local";

// Origin: "https://" + a host equal to kRpId (or a subdomain of it).
static const char* kOrigin = "https://passkey.vuln.plc.local";

////////// Clock (NTP) //////////
const IPAddress ntpSvr(192, 168, 1, 5);       // Set internal NTP server IP address.
//const char* const ntpSvr = "pool.ntp.org";  // Or set a NTP DNS server hostname.

// The oldest epoch accepted as "the time is set"
static const uint32_t kClockMinValidEpoch = 1789000000u;

////////// Admin internal IP allowlist //////////

// IPs allowed to enroll and revoke (the /register/* and /admin routes).
static const IPAddress kAdminIPs[] = {
    IPAddress(192, 168, 1, 5),
};

////////// Security gate: rate limiting (per-IP throttle, circular RAM ring) //////////

// Time window (milliseconds) over which connection attempts are counted.
static const uint32_t kThrottleWindowMs = 1000;

// Connection charges per IP per window (one per TCP connection). Due to browser
// behavior, do not reduce below 5; excess SYNs are dropped until the window
// rolls over (or 429s, if the L2 gate is off).
static const uint16_t kMaxConnPerWindowPerIP = 5;

// Number of slots in the circular throttle ring (RAM).
static const uint16_t kThrottleRingSize = 64;

////////// Security gate: blocklist (PSRAM) //////////

// Max blocked IPs (16384 is the practical limit).
static const uint16_t kBlocklistMaxEntries = 16384;

// Number of failed authentication attempts before an IP is blocked.
static const uint16_t kFailuresBeforeBlock = 3;

// Block any non-admin IP that touches an admin route (GET /admin, /register/*, /admin/*)
static const bool kBlockNonAdminIPOnAdminRoute = true;

////////// Security gate: Ethernet-driver (L2) drop //////////

// Drop over-budget / blocked SYNs in the Ethernet RX path before TLS (EthGate.h).
static const bool kEthL2GateEnable = true;

////////// Session + TTL //////////

// One-time challenge validity (ms). Matches the browser's 60 s ceremony timeout.
static const uint32_t kSessionTtlMs = 60000;

// How long a successful authentication keeps its egress IP "authorized" (ms).
static const uint32_t kAuthorizedIPTtlMs = 36000000;

////////// Consumer endpoint (/authorized-ips) //////////

// Shared secret for ?key=... on the consumer endpoint. Change before deploying.
static const char* kConsumerSecret = "CHANGE_ME";

// Source IPs permitted to read the authorized-IP list.
static const IPAddress kConsumerAllowlist[] = {
    IPAddress(192, 168, 1, 5),
};

////////--------------------------------------- END OF CONFIGURATION SETTINGS ---------------------------------------////////

// Max POST body bytes accepted (fail closed).
static const uint16_t kMaxBodySize = 4096;

////////// Store capacity //////////

// Max registered hardware keys (one NVS blob each). Do not increase beyond 256.
static const uint16_t kMaxCredentials = 256;

// Max in-flight client authentication ceremonies.
static const uint16_t kMaxSessions = 32;

// Max in-flight registration ceremonies (admin key registrations).
static const uint16_t kMaxRegistrations = 4;

// Max in-flight auth ceremonies per source IP. /auth/start is public, so this caps one
// client from holding every slot; over the cap, a peer takes back its own oldest slot.
static const uint16_t kMaxSessionsPerIP = 1;

// Max concurrent "authorized IP" entries. Ideally, match the value of kMaxCredentials.
static const uint16_t kMaxAuthorizedIPs = 256;

////////// Calculated counts (do not edit) //////////

static const uint32_t kAdminIPCount            = sizeof(kAdminIPs) / sizeof(kAdminIPs[0]);
static const uint32_t kConsumerAllowlistCount  = sizeof(kConsumerAllowlist) / sizeof(kConsumerAllowlist[0]);

#endif // CONFIG_H