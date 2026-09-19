/*
 * Clock.cpp - configures the core's SNTP client and answers whether the time is usable.
 */

#include "Config.h"
#include "Clock.h"

#include <Arduino.h>
#include <time.h>
#include <esp_netif_sntp.h>
#include <esp_sntp.h>

// Latest sync time; word-sized, no lock needed (a race only reports the prior sync).
static volatile uint32_t s_lastSyncMs = 0;

// Log what was corrected, in UTC.
static void on_sntp_sync(struct timeval* tv) {
    s_lastSyncMs = millis();
    const time_t when = (time_t)tv->tv_sec;
    struct tm tmv;
    char text[32];
    if (gmtime_r(&when, &tmv) && strftime(text, sizeof(text), "%Y-%m-%d %H:%M:%SZ", &tmv)) {
        Serial.printf("[clock] NTP synced: %s\n", text);
    } else {
        Serial.printf("[clock] NTP synced: %lu\n", (unsigned long)tv->tv_sec);
    }
}

// ntpSvr is either an IPAddress or a hostname; these overloads pick one at compile time.
static bool ntp_server_ok(const IPAddress& ip) {
    return (uint32_t)ip != 0; // 0.0.0.0 means nobody set it
}
static bool ntp_server_ok(const char* const& name) {
    return name != nullptr && name[0] != 0;
}
static void ntp_server_text(const IPAddress& ip, char* out, size_t cap) {
    snprintf(out, cap, "%u.%u.%u.%u", (unsigned)ip[0], (unsigned)ip[1],
             (unsigned)ip[2], (unsigned)ip[3]);
}
static void ntp_server_text(const char* const& name, char* out, size_t cap) {
    snprintf(out, cap, "%s", name);
}

// File-scope: esp_netif keeps the pointer, so the string must outlive the call.
static char s_ntpServer[64];

bool clock_begin() {
    if (!ntp_server_ok(ntpSvr)) {
        Serial.println("[clock] FATAL: Config.h ntpSvr is not set (0.0.0.0 or empty) - there will "
                       "be no sync, so last-used dates stay unknown");
        return false;
    }
    ntp_server_text(ntpSvr, s_ntpServer, sizeof(s_ntpServer));

    // One server, non-blocking: setup() finishes before the first sync lands.
    esp_sntp_config_t cfg = {
        .smooth_sync = false,        // step to the right time; slewing only delays it
        .server_from_dhcp = false,   // Config.h decides the server, not the DHCP lease
        .wait_for_sync = false,
        .start = true,
        .sync_cb = on_sntp_sync,
        .renew_servers_after_new_IP = false,
        .num_of_servers = 1,
    };
    cfg.servers[0] = s_ntpServer;

    const esp_err_t err = esp_netif_sntp_init(&cfg);
    if (err != ESP_OK) {
        Serial.printf("[clock] FATAL: could not start the NTP client (%s); last-used dates "
                      "will stay unknown until this is fixed\n", esp_err_to_name(err));
        return false;
    }

    Serial.printf("[clock] NTP: syncing from %s, re-syncing every %u s\n",
                  s_ntpServer, (unsigned)(esp_sntp_get_sync_interval() / 1000));
    return true;
}

bool clock_is_set() {
    return time(nullptr) >= (time_t)kClockMinValidEpoch;
}

bool clock_now(uint32_t* out) {
    const time_t now = time(nullptr);
    if (now < (time_t)kClockMinValidEpoch) {
        return false; // clock not set yet
    }
    if (out) {
        *out = (uint32_t)now;
    }
    return true;
}

uint32_t clock_last_sync_ms() {
    return s_lastSyncMs;
}