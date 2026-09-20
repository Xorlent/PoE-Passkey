/*
 * EthGate.cpp - the Ethernet RX filter (see EthGate.h). We replace the netif
 * glue's input hook after ETH.begin(), register both the plain and *_info forms
 * (the P4 EMAC calls the latter), and release a dropped frame with free().
 */

#include "EthGate.h"
#include "FrontDoor.h"

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
static volatile uint32_t s_synsRefused = 0;
static uint8_t s_refusalLogs = 0;

// Frame layout (Ethernet II + IPv4 + TCP). Anything unexpected is forwarded untouched.
static const uint32_t kEthHeaderLen = 14; // dst MAC(6) + src MAC(6) + ethertype(2)
static const uint8_t kEtherTypeIPv4Hi = 0x08;
static const uint8_t kEtherTypeIPv4Lo = 0x00;
static const uint32_t kMinIpHeaderLen = 20;
static const uint32_t kMinTcpHeaderLen = 20;
static const uint8_t kIpProtoTcp = 6;
static const uint8_t kTcpFlagSyn = 0x02;
static const uint8_t kTcpFlagAck = 0x10;
static const uint8_t kEtherTypeIPv6Hi = 0x86;
static const uint8_t kEtherTypeIPv6Lo = 0xDD;
static const uint32_t kMinIp6HeaderLen = 40; // fixed IPv6 header (no extension headers)

// Is `frame` a TCP connection request (SYN set, ACK clear) for `port`? On true,
// *srcIp receives the sender's address in network byte order.
static bool is_syn_to_port(const uint8_t* frame, uint32_t len, uint16_t port, uint32_t* srcIp) {
    if (len < kEthHeaderLen + kMinIpHeaderLen + kMinTcpHeaderLen) {
        return false;
    }
    if (frame[12] != kEtherTypeIPv4Hi || frame[13] != kEtherTypeIPv4Lo) {
        return false;
    }

    const uint8_t* ip = frame + kEthHeaderLen;
    if ((ip[0] >> 4) != 4) {
        return false; // not IPv4
    }
    const uint32_t ihl = (uint32_t)(ip[0] & 0x0F) * 4;
    if (ihl < kMinIpHeaderLen || len < kEthHeaderLen + ihl + kMinTcpHeaderLen) {
        return false; // truncated or bogus header
    }
    if (ip[9] != kIpProtoTcp) {
        return false; // not TCP
    }
    // Only a first, unfragmented datagram carries a usable TCP header.
    const uint16_t frag = (uint16_t)((ip[6] << 8) | ip[7]);
    if ((frag & 0x3FFF) != 0) {
        return false;
    }

    const uint8_t* tcp = ip + ihl;
    const uint16_t dstPort = (uint16_t)((tcp[2] << 8) | tcp[3]);
    if (dstPort != port) {
        return false;
    }
    const uint8_t flags = tcp[13];
    if ((flags & kTcpFlagSyn) == 0 || (flags & kTcpFlagAck) != 0) {
        return false; // not a connection request
    }

    memcpy(srcIp, ip + 12, sizeof(*srcIp));
    return true;
}

// Is `frame` an IPv6 packet addressed to TCP port `port`? The device is IPv4-only
// (Config.h), so IPv6 has no legitimate use; refusing it here keeps IPv6 SYNs from
// reaching the (expensive) TLS handshake that the IPv4-keyed gate cannot account for
// (I6). Extension headers are not followed: a connection request does not carry them,
// and an unparsed frame is simply forwarded (still refused at the request level).
static bool is_ipv6_to_port(const uint8_t* frame, uint32_t len, uint16_t port) {
    if (len < kEthHeaderLen + kMinIp6HeaderLen + kMinTcpHeaderLen) {
        return false;
    }
    if (frame[12] != kEtherTypeIPv6Hi || frame[13] != kEtherTypeIPv6Lo) {
        return false;
    }

    const uint8_t* ip6 = frame + kEthHeaderLen;
    if ((ip6[0] >> 4) != 6) {
        return false; // not IPv6
    }
    if (ip6[6] != kIpProtoTcp) {
        return false; // next header is not TCP (extension headers are not followed)
    }

    const uint8_t* tcp = ip6 + kMinIp6HeaderLen;
    const uint16_t dstPort = (uint16_t)((tcp[2] << 8) | tcp[3]);
    return dstPort == port;
}

// The MAC's input path. Forwarding mirrors esp_eth_netif_glue.c's
// eth_input_to_netif() exactly; refusing releases the frame the way the stack
// releases every frame it consumes (see the ownership note in EthGate.h).
static esp_err_t eth_gate_input_info(esp_eth_handle_t ethHandle, uint8_t* buffer,
                                     uint32_t length, void* priv, void* info) {
    (void)ethHandle;
    (void)priv;
    (void)info;

    ++s_frames;

    // IPv6: refuse outright (the device is IPv4-only; see is_ipv6_to_port).
    if (is_ipv6_to_port(buffer, length, s_port)) {
        ++s_synsRefused;
        if (s_refusalLogs < 3) {
            ++s_refusalLogs;
            ESP_LOGW(TAG, "Refused IPv6 frame to port %u at L2 (IPv4-only device)", (unsigned)s_port);
        }
        free(buffer);
        return ESP_OK;
    }

    uint32_t srcIp = 0;
    if (is_syn_to_port(buffer, length, s_port, &srcIp)) {
        // Charge before lwIP answers; an allowed SYN is credited at accept time.
        if (frontdoor_gate_syn(srcIp) == FRONTDOOR_SYN_DROP) {
            ++s_synsRefused;
            if (s_refusalLogs < 3) {
                // First three only; raw octets because IPAddress would allocate here.
                ++s_refusalLogs;
                ESP_LOGW(TAG, "Refused SYN from %u.%u.%u.%u at L2 (no TCP handshake)",
                         (unsigned)(srcIp & 0xFF), (unsigned)((srcIp >> 8) & 0xFF),
                         (unsigned)((srcIp >> 16) & 0xFF), (unsigned)((srcIp >> 24) & 0xFF));
            }
            free(buffer);
            return ESP_OK;
        }
        ++s_synsCharged;
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
        Serial.printf("[gate] esp_eth_update_input_path failed: %d\n", (int)err);
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

void eth_gate_stats(uint32_t* frames, uint32_t* synsCharged, uint32_t* synsRefused) {
    if (frames) {
        *frames = s_frames;
    }
    if (synsCharged) {
        *synsCharged = s_synsCharged;
    }
    if (synsRefused) {
        *synsRefused = s_synsRefused;
    }
}