/*
 * EthGate.h
 *
 * Optional L2 drop: a filter on the Ethernet driver's receive path. Blocked or
 * over-budget peers' SYNs are freed before lwIP ever sees them, so they can't
 * even complete a TCP (let alone TLS) handshake. frontdoor_gate_syn() both gives
 * the verdict and charges an allowed SYN (credited at accept time). Dropped or
 * forwarded frames are freed/consumed exactly as the netif glue does. Runs in
 * the EMAC RX task: allocation-free, non-blocking.
 */

#ifndef ETHGATE_H
#define ETHGATE_H

#include <stdint.h>
#include <esp_eth_driver.h>
#include <esp_netif.h>

// Install the filter; only TCP SYNs for `protectedPort` are inspected. Call once,
// after ETH.begin() and frontdoor_begin(). False = not installed (bad args, or the
// FrontDoor stores aren't ready - the blocklist fails closed and would drop every frame).
bool eth_gate_begin(esp_eth_handle_t ethHandle, esp_netif_t* netif, uint16_t protectedPort);

// Is the filter installed?
bool eth_gate_active();

// Telemetry: frames seen, SYNs charged/delivered, SYNs refused. Any pointer may be null.
void eth_gate_stats(uint32_t* frames, uint32_t* synsCharged, uint32_t* synsRefused);

#endif // ETHGATE_H