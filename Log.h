/*
 * Log.h
 *
 * A Print-compatible tee that mirrors every diagnostic byte to `Serial` while also
 * recording it, line by line, into a fixed 256-entry ring in PSRAM. The admin console
 * surfaces the ring via GET /admin/logs; ordering (newest vs oldest) is left to the
 * client so the controller does no reordering work.
 *
 * Use `Log` where the code previously wrote diagnostics with `Serial`:
 *     Log.printf(...), Log.println(...), Log.print(...)
 * `Serial` remains for the console's input/control side (begin / setRxBufferSize /
 * available / read / readStringUntil).
 */

#ifndef LOG_H
#define LOG_H

#include <Arduino.h>    // Print
#include <stdint.h>
#include <stddef.h>

// One captured console line. Longer lines are truncated to fit.
#define LOG_LINE_CAP   160
#define LOG_RING_SIZE  256

struct LogEntry {
    uint32_t unix;                // device clock time (0 while unknown); see Clock.h
    char     line[LOG_LINE_CAP];  // NUL-terminated
};

// The tee: forwards bytes to Serial AND assembles them into timestamped lines in the
// ring. Safe to call from any task (the ring is spinlock-guarded).
class LogSink : public Print {
public:
    size_t write(uint8_t c) override;
    size_t write(const uint8_t* buf, size_t n) override;
};

extern LogSink Log;

// Allocate the ring (PSRAM, internal-RAM fallback). Call once at boot, before any
// logging. If it cannot allocate, logging degrades to console-only (no history).
void log_begin();

// Copy up to `cap` ring entries into `out` oldest-first and return the count.
// Reverse the result for newest-first display.
size_t log_snapshot(LogEntry* out, size_t cap);

#endif // LOG_H
