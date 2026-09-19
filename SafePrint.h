/*
 * SafePrint.h
 *
 * Serial is the only diagnostic channel on this device, and attacker-supplied
 * text (URIs, query strings, emails, clientDataJSON) can carry terminal escapes
 * or forged newlines. These helpers print such text safely: printable ASCII as
 * itself, everything else as \xHH, capped at `maxChars` printed characters.
 * Use only for caller-derived strings, not for values the firmware built itself.
 */
#ifndef SAFEPRINT_H
#define SAFEPRINT_H

#include <Arduino.h>
#include <stddef.h>
#include <string.h>

// Print exactly `n` bytes (need not be NUL-terminated), capped at `maxChars` printed chars.
static void safe_print_range(const char* s, size_t n, size_t maxChars) {
    size_t used = 0;
    size_t i = 0;
    for (; i < n && used < maxChars; ++i) {
        const unsigned char c = (unsigned char)s[i];
        if (c >= 0x20 && c < 0x7F) {
            Serial.print((char)c);
            ++used;
        } else {
            Serial.printf("\\x%02X", (unsigned)c);
            used += 4;
        }
    }
    if (i < n) {
        Serial.print("[...]");
    }
}

// Same, for a NUL-terminated string.
static void safe_print(const char* s, size_t maxChars) {
    if (s == nullptr) {
        return;
    }
    safe_print_range(s, strlen(s), maxChars);
}

#endif // SAFEPRINT_H