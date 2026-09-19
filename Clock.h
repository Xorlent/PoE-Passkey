/*
 * Clock.h
 *
 * Wall clock used only to stamp the "last used" date on credentials. It never
 * authorizes anything. Time comes from NTP (Config.h ntpSvr), synced at boot
 * and refreshed by the core on its own schedule. A plausibility floor
 * (kClockMinValidEpoch) is what tells "set" from "unknown".
 */
#ifndef CLOCK_H
#define CLOCK_H

#include <stdint.h>

// Start the NTP client. Call once after the network is up. False = couldn't start.
bool clock_begin();

// Is the time plausible (>= kClockMinValidEpoch)? False means "unknown".
bool clock_is_set();

// Current Unix time into `out`. False (writing nothing) while the time is unknown.
bool clock_now(uint32_t* out);

// millis() at the last completed sync, or 0 if none yet this boot.
uint32_t clock_last_sync_ms();

#endif // CLOCK_H