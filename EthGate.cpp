/*
 * EthGate.cpp - the Ethernet RX filter (see EthGate.h). We replace the netif
 * glue's input hook after ETH.begin(), register both the plain and *_info forms
 * (the P4 EMAC calls the latter), and release a dropped frame with free().
 */

#include "EthGate.h"
#include "FrontDoor.h"
#include "Log.h"

#include <Arduino.h>
#include <esp_log.h>
#include <esp_netif.h>
#include <stdlib.h>
#include <string.h>

static const char* TAG = "ethgate";

// Written by eth_gate_begin() before the filter goes live, then read-only.
static esp_netif_t* s_netif = nullptr;
static uint16_t s_port = 0;
static bool s_active = false;

// Telemetry: single-word counters, incremented only from the RX task.
static volatile uint32_t s_frames = 0;
static volatile uint32_t s_synsCharged = 0;
static volatile uint32_t s_synsRefused = 0;          // refused SYNs (blocked / over budget)
static volatile uint32_t s_refusedIpv6 = 0;
static volatile uint32_t s_refusedFragment = 0;
static volatile uint32_t s_refusedUnsupported = 0;   // unsupported ethertype / malformed frame
// Log budget: first three log lines per reason.
static uint8_t s_budgetIpv6 = 0, s_budgetFragment = 0, s_budgetUnsupported = 0, s_budgetGate = 0;

// Frame layout (Ethernet II; only IPv4 is parsed). Default-deny: only ARP, 802.3
// MAC Control and unfragmented IPv4 pass; everything else is refused before lwIP.
static const uint32_t kEthHeaderLen = 14; // dst MAC(6) + src MAC(6) + ethertype(2)
static const uint16_t kEtherTypeArp        = 0x0806;
static const uint16_t kEtherTypeIPv4       = 0x0800;
static const uint16_t kEtherTypeIPv6       = 0x86DD;
static const uint16_t kEtherTypeMacControl = 0x8808; // 802.3x pause
static const uint32_t kMinIpHeaderLen = 20;
static const uint32_t kMinTcpHeaderLen = 20;
static const uint8_t kIpProtoTcp = 6;
static const uint8_t kTcpFlagSyn = 0x02;
static const uint8_t kTcpFlagAck = 0x10;

// Verdict per frame: PASS = not ours (give it to lwIP), SYN = connection request for
// `port` (frontdoor_gate_syn() decides), REFUSE = default-deny.
enum FrameVerdict { FRAME_PASS = 0, FRAME_SYN, FRAME_REFUSE };

// Why a frame was refused (telemetry).
enum RefuseReason { REFUSE_NONE = 0, REFUSE_IPV6, REFUSE_FRAGMENT, REFUSE_UNSUPPORTED };

// Classify one frame (bytes in, verdict out; RX-task safe). `srcIpOut`/`reasonOut`
// receive the sender's IPv4 (network byte order) and the refusal, if any.
static FrameVerdict classify_frame(const uint8_t* frame, uint32_t len, uint16_t port,
                                   uint32_t* srcIpOut, RefuseReason* reasonOut) {
    *srcIpOut = 0;
    *reasonOut = REFUSE_NONE;

    if (len < kEthHeaderLen + 2) {
        *reasonOut = REFUSE_UNSUPPORTED; // runt: not even a complete ethertype
        return FRAME_REFUSE;
    }

    const uint16_t ethType = (uint16_t)(((uint16_t)frame[12] << 8) | frame[13]);

    // Allowlist (default-deny): ARP and MAC control keep the link alive. Every other
    // ethertype - EAPOL, LLDP, VLAN-tagged, unknown - is refused.
    if (ethType == kEtherTypeArp || ethType == kEtherTypeMacControl) {
        return FRAME_PASS;
    }

    // IPv6 refused wholesale: an IPv4-only device has no use for it, and its
    // extension headers could hide a SYN from this parser anyway.
    if (ethType == kEtherTypeIPv6) {
        *reasonOut = REFUSE_IPV6;
        return FRAME_REFUSE;
    }

    const uint8_t* ip = frame + kEthHeaderLen;
    if (ethType != kEtherTypeIPv4 || len < kEthHeaderLen + kMinIpHeaderLen ||
        (ip[0] >> 4) != 4) {
        *reasonOut = REFUSE_UNSUPPORTED; // unknown ethertype, or a truncated/bogus IPv4 header
        return FRAME_REFUSE;
    }

    const uint32_t ihl = (uint32_t)(ip[0] & 0x0F) * 4;
    if (ihl < kMinIpHeaderLen) {
        *reasonOut = REFUSE_UNSUPPORTED;
        return FRAME_REFUSE;
    }
    memcpy(srcIpOut, ip + 12, sizeof(*srcIpOut));

    // The device never reassembles IP: no legitimate inbound flow fragments, and
    // a split SYN hides in the first fragment. Refused for every protocol.
    const uint16_t frag = (uint16_t)(((uint16_t)ip[6] << 8) | ip[7]);
    if ((frag & 0x3FFF) != 0) { // MF or a non-zero fragment offset; DF (0x4000) is fine
        *reasonOut = REFUSE_FRAGMENT;
        return FRAME_REFUSE;
    }

    if (ip[9] != kIpProtoTcp) {
        return FRAME_PASS; // UDP (NTP/DNS replies), ICMP (ops pings), ...
    }

    // TCP: the header must be fully present to clear the frame of hiding a SYN.
    if (len < kEthHeaderLen + ihl + kMinTcpHeaderLen) {
        *reasonOut = REFUSE_UNSUPPORTED;
        return FRAME_REFUSE;
    }
    const uint8_t* tcp = ip + ihl;
    const uint16_t dstPort = (uint16_t)(((uint16_t)tcp[2] << 8) | tcp[3]);
    const uint8_t flags = tcp[13];
    if (dstPort == port && (flags & kTcpFlagSyn) != 0 && (flags & kTcpFlagAck) == 0) {
        return FRAME_SYN;
    }
    return FRAME_PASS; // anything else (established flows, other ports): lwIP's business
}

// Count one refusal, log the first three per reason (a flood must not log-flood).
// RX task: raw octets only - IPAddress/String would allocate here.
static void note_refusal(RefuseReason reason, uint32_t srcIp, uint16_t ethType) {
    volatile uint32_t* count;
    uint8_t* budget;
    switch (reason) {
        case REFUSE_IPV6:     count = &s_refusedIpv6;        budget = &s_budgetIpv6;        break;
        case REFUSE_FRAGMENT: count = &s_refusedFragment;    budget = &s_budgetFragment;    break;
        default:              count = &s_refusedUnsupported; budget = &s_budgetUnsupported; break;
    }
    *count = *count + 1; // volatile word; ++/-- on volatile is deprecated (C++20)
    if (*budget >= 3) {
        return;
    }
    ++(*budget);
    if (reason == REFUSE_IPV6) {
        ESP_LOGW(TAG, "Refused IPv6 frame at L2 (the device is IPv4-only)");
    } else if (reason == REFUSE_FRAGMENT) {
        ESP_LOGW(TAG, "Refused fragmented IPv4 frame from %u.%u.%u.%u at L2 "
                      "(the device never reassembles IP)",
                 (unsigned)(srcIp & 0xFF), (unsigned)((srcIp >> 8) & 0xFF),
                 (unsigned)((srcIp >> 16) & 0xFF), (unsigned)((srcIp >> 24) & 0xFF));
    } else {
        ESP_LOGW(TAG, "Refused frame at L2 (ethertype 0x%04x: unsupported or malformed)",
                 (unsigned)ethType);
    }
}

// The MAC's input path. Forwarding mirrors esp_eth_netif_glue.c's
// eth_input_to_netif() exactly; refusing releases the frame the way the stack
// releases every frame it consumes (see the ownership note in EthGate.h).
static esp_err_t eth_gate_input_info(esp_eth_handle_t ethHandle, uint8_t* buffer,
                                     uint32_t length, void* priv, void* info) {
    (void)ethHandle;
    (void)priv;
    (void)info;

    s_frames = s_frames + 1;

    const uint16_t ethType = (length >= kEthHeaderLen + 2)
        ? (uint16_t)(((uint16_t)buffer[12] << 8) | buffer[13]) : 0;
    uint32_t srcIp = 0;
    RefuseReason reason = REFUSE_NONE;
    const FrameVerdict verdict = classify_frame(buffer, length, s_port, &srcIp, &reason);

    if (verdict == FRAME_REFUSE) {
        note_refusal(reason, srcIp, ethType);
        free(buffer);
        return ESP_OK;
    }

    if (verdict == FRAME_SYN) {
        // Charge before lwIP answers; an allowed SYN is credited at accept time.
        if (frontdoor_gate_syn(srcIp) == FRONTDOOR_SYN_DROP) {
            s_synsRefused = s_synsRefused + 1;
            if (s_budgetGate < 3) {
                // First three only; raw octets because IPAddress would allocate here.
                ++s_budgetGate;
                ESP_LOGW(TAG, "Refused SYN from %u.%u.%u.%u at L2 (no TCP handshake)",
                         (unsigned)(srcIp & 0xFF), (unsigned)((srcIp >> 8) & 0xFF),
                         (unsigned)((srcIp >> 16) & 0xFF), (unsigned)((srcIp >> 24) & 0xFF));
            }
            free(buffer);
            return ESP_OK;
        }
        s_synsCharged = s_synsCharged + 1;
    }

    return esp_netif_receive(s_netif, buffer, length, NULL) == ESP_OK ? ESP_OK : ESP_FAIL;
}

// Same filter for a MAC without frame info; both forms are registered so the hook
// survives a driver change in either direction.
static esp_err_t eth_gate_input(esp_eth_handle_t ethHandle, uint8_t* buffer,
                                uint32_t length, void* priv) {
    return eth_gate_input_info(ethHandle, buffer, length, priv, nullptr);
}

bool eth_gate_begin(esp_eth_handle_t ethHandle, esp_netif_t* netif, uint16_t protectedPort) {
    if (s_active) {
        return true;
    }
    if (ethHandle == nullptr || netif == nullptr || protectedPort == 0) {
        ESP_LOGE(TAG, "Refusing to install: bad handle, netif or port");
        return false;
    }
    if (!frontdoor_ready()) {
        // The blocklist fails closed, so an early install would black-hole the link.
        ESP_LOGE(TAG, "Refusing to install: the FrontDoor stores are not ready");
        return false;
    }

    s_netif = netif;
    s_port = protectedPort;

    // Plain form first, *_info form last (the one this MAC invokes; it must stay).
    esp_err_t err = esp_eth_update_input_path(ethHandle, eth_gate_input, nullptr);
    if (err != ESP_OK) {
        Log.printf("[gate] esp_eth_update_input_path failed: %d\n", (int)err);
    }
    err = esp_eth_update_input_path_info(ethHandle, eth_gate_input_info, nullptr);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_eth_update_input_path_info failed: %d", (int)err);
        s_netif = nullptr;
        s_port = 0;
        return false;
    }

    s_active = true;
    ESP_LOGI(TAG, "RX filter installed: TCP SYNs to port %u are gated at L2", (unsigned)protectedPort);
    return true;
}

bool eth_gate_active() {
    return s_active;
}

void eth_gate_stats(uint32_t* frames, uint32_t* synsCharged, uint32_t* synsRefused,
                    uint32_t* refusedIpv6, uint32_t* refusedFragment,
                    uint32_t* refusedUnsupported) {
    if (frames) {
        *frames = s_frames;
    }
    if (synsCharged) {
        *synsCharged = s_synsCharged;
    }
    if (synsRefused) {
        *synsRefused = s_synsRefused;
    }
    if (refusedIpv6) {
        *refusedIpv6 = s_refusedIpv6;
    }
    if (refusedFragment) {
        *refusedFragment = s_refusedFragment;
    }
    if (refusedUnsupported) {
        *refusedUnsupported = s_refusedUnsupported;
    }
}

// ---------------------------------------------------------------------------
// Self-test: crafted-frame vectors for the default-deny classifier.
// ---------------------------------------------------------------------------

// All vectors share one buffer (nothing here runs concurrently).
static uint8_t s_stFrame[96];

// Ethernet II header with `ethType`, zeroed payload area.
static void st_frame(uint16_t ethType) {
    memset(s_stFrame, 0, sizeof(s_stFrame));
    s_stFrame[12] = (uint8_t)(ethType >> 8);
    s_stFrame[13] = (uint8_t)ethType;
}

// Fill a 20-byte IPv4 header + TCP stub. frag: bits 0-12 offset, 13 MF, 14 DF.
static void st_ipv4(uint8_t proto, uint16_t frag, uint16_t dport, uint8_t tcpFlags) {
    s_stFrame[14] = 0x45;                       // v4, IHL = 20
    s_stFrame[20] = (uint8_t)(frag >> 8);
    s_stFrame[21] = (uint8_t)frag;
    s_stFrame[23] = proto;
    s_stFrame[26] = 10;
    s_stFrame[29] = 1;                          // src 10.0.0.1
    s_stFrame[14 + 20 + 2] = (uint8_t)(dport >> 8);
    s_stFrame[14 + 20 + 3] = (uint8_t)dport;
    s_stFrame[14 + 20 + 13] = tcpFlags;
}

// classify_frame() must yield exactly `wantVerdict` / `wantReason`.
static bool st_expect(uint32_t len, FrameVerdict wantVerdict, RefuseReason wantReason) {
    static const uint16_t kPort = 443;
    uint32_t srcIp = 0;
    RefuseReason reason = REFUSE_NONE;
    return classify_frame(s_stFrame, len, kPort, &srcIp, &reason) == wantVerdict &&
           reason == wantReason;
}

bool eth_gate_selftest() {
    int failures = 0;

    // 1. Plain IPv4 TCP SYN to :443.
    st_frame(kEtherTypeIPv4); st_ipv4(kIpProtoTcp, 0x4000, 443, kTcpFlagSyn);
    if (!st_expect(54, FRAME_SYN, REFUSE_NONE)) ++failures;

    // 2. The same SYN across fragments (MF set) -> refused.
    st_frame(kEtherTypeIPv4); st_ipv4(kIpProtoTcp, 0x2000, 443, kTcpFlagSyn);
    if (!st_expect(54, FRAME_REFUSE, REFUSE_FRAGMENT)) ++failures;

    // 3. Non-first fragment, any protocol -> refused.
    st_frame(kEtherTypeIPv4); st_ipv4(17 /* UDP */, 0x000B, 0, 0);
    if (!st_expect(54, FRAME_REFUSE, REFUSE_FRAGMENT)) ++failures;

    // 4. Unfragmented UDP (NTP/DNS reply) -> PASS.
    st_frame(kEtherTypeIPv4); st_ipv4(17, 0x4000, 0, 0);
    if (!st_expect(42, FRAME_PASS, REFUSE_NONE)) ++failures;

    // 5. TCP that is not a SYN -> PASS (lwIP's business).
    st_frame(kEtherTypeIPv4); st_ipv4(kIpProtoTcp, 0x4000, 443, kTcpFlagAck);
    if (!st_expect(54, FRAME_PASS, REFUSE_NONE)) ++failures;

    // 6. SYN to another port -> PASS (not gated).
    st_frame(kEtherTypeIPv4); st_ipv4(kIpProtoTcp, 0x4000, 80, kTcpFlagSyn);
    if (!st_expect(54, FRAME_PASS, REFUSE_NONE)) ++failures;

    // 7+8. IPv6, whatever its next-header byte claims.
    st_frame(kEtherTypeIPv6);
    if (!st_expect(74, FRAME_REFUSE, REFUSE_IPV6)) ++failures;
    s_stFrame[20] = 6; // claims TCP next-header
    if (!st_expect(74, FRAME_REFUSE, REFUSE_IPV6)) ++failures;

    // 9. ARP -> PASS.
    st_frame(kEtherTypeArp);
    if (!st_expect(60, FRAME_PASS, REFUSE_NONE)) ++failures;

    // 10. 802.3 MAC Control (pause) -> PASS.
    st_frame(kEtherTypeMacControl);
    if (!st_expect(64, FRAME_PASS, REFUSE_NONE)) ++failures;

    // 11-14. EAPOL, LLDP, VLAN-tagged, unknown ethertype -> refused (default-deny).
    st_frame(0x888E);
    if (!st_expect(60, FRAME_REFUSE, REFUSE_UNSUPPORTED)) ++failures;
    st_frame(0x88CC);
    if (!st_expect(60, FRAME_REFUSE, REFUSE_UNSUPPORTED)) ++failures;
    st_frame(0x8100);
    if (!st_expect(64, FRAME_REFUSE, REFUSE_UNSUPPORTED)) ++failures;
    st_frame(0x88B5);
    if (!st_expect(60, FRAME_REFUSE, REFUSE_UNSUPPORTED)) ++failures;

    // 15. Truncated IPv4/TCP -> refused (fail closed).
    st_frame(kEtherTypeIPv4); st_ipv4(kIpProtoTcp, 0x4000, 443, kTcpFlagSyn);
    if (!st_expect(14 + 20 + 8, FRAME_REFUSE, REFUSE_UNSUPPORTED)) ++failures;

    // 16. Runt frame -> refused.
    if (!st_expect(10, FRAME_REFUSE, REFUSE_UNSUPPORTED)) ++failures;

    return failures == 0;
}