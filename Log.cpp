/*
 * Log.cpp - see Log.h. The ring is a fixed array of LogEntry; s_head is the next
 * write slot, so the newest entry is s_head-1 and the oldest is s_head-s_count.
 * Diagnostics are written from the httpd tasks, the loop task, and the SNTP sync
 * callback, so every ring access runs under a short spinlock (no logging inside).
 */

#include "Log.h"
#include "Clock.h"

#include <Arduino.h>
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/portmacro.h>
#include <stdlib.h>
#include <string.h>

static LogEntry* s_ring  = nullptr;   // LOG_RING_SIZE slots; nullptr until log_begin()
static uint16_t  s_head  = 0;         // next write slot
static uint16_t  s_count = 0;         // valid entries (0..LOG_RING_SIZE)

static char   s_line[LOG_LINE_CAP];   // line assembler
static size_t s_len = 0;

static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;

// The global tee every translation unit writes diagnostics through.
LogSink Log;

// Commit s_line[0..s_len) as a ring entry. LOCKED: caller holds s_lock. A no-op
// (the line is discarded) while the ring is unallocated.
static void commit_locked(uint32_t unix) {
    if (s_ring == nullptr) {
        s_len = 0;
        return;
    }
    LogEntry* slot = &s_ring[s_head];
    slot->unix = unix;
    memcpy(slot->line, s_line, s_len);
    slot->line[s_len] = 0;
    s_head = (uint16_t)((s_head + 1) % LOG_RING_SIZE);
    if (s_count < LOG_RING_SIZE) {
        ++s_count;
    }
    s_len = 0;
}

size_t LogSink::write(const uint8_t* buf, size_t n) {
    Serial.write(buf, n);             // console output unchanged (outside our lock)
    if (n == 0) {
        return 0;
    }
    uint32_t unix = 0;
    clock_now(&unix);                 // stays 0 while the clock is unknown

    portENTER_CRITICAL(&s_lock);
    for (size_t i = 0; i < n; ++i) {
        const char c = (char)buf[i];
        if (c == '\n') {
            commit_locked(unix);
        } else if (c != '\r') {
            // Truncate over-long lines: drop bytes beyond the buffer.
            if (s_len < LOG_LINE_CAP - 1) {
                s_line[s_len++] = c;
            }
        }
    }
    portEXIT_CRITICAL(&s_lock);
    return n;
}

size_t LogSink::write(uint8_t c) {
    return write(&c, 1);
}

void log_begin() {
    const size_t bytes = (size_t)LOG_RING_SIZE * sizeof(LogEntry);
    s_ring = (LogEntry*)heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM);
    if (s_ring == nullptr) {
        // Same fallback the blocklist uses (see FrontDoor.cpp).
        s_ring = (LogEntry*)malloc(bytes);
        if (s_ring != nullptr) {
            Serial.printf("[log] PSRAM unavailable for the %u-entry ring; using internal RAM\n",
                          (unsigned)LOG_RING_SIZE);
        }
    }
    if (s_ring == nullptr) {
        Serial.println("[log] no memory for the ring; diagnostics will not be recorded");
    } else {
        memset(s_ring, 0, bytes);
        s_head = 0;
        s_count = 0;
        s_len = 0;
    }
}

size_t log_snapshot(LogEntry* out, size_t cap) {
    if (out == nullptr || cap == 0 || s_ring == nullptr) {
        return 0;
    }
    size_t n = 0;
    portENTER_CRITICAL(&s_lock);
    const uint16_t count = s_count;
    for (uint16_t i = 0; i < count && n < cap; ++i) {
        // The oldest entry is `count` slots behind the head; walk forward.
        const uint16_t idx = (uint16_t)((s_head + LOG_RING_SIZE - count + i) % LOG_RING_SIZE);
        out[n++] = s_ring[idx];
    }
    portEXIT_CRITICAL(&s_lock);
    return n;
}
