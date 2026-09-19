/*
 * SerialConsole.h
 *
 * Interactive serial console for importing the TLS certificate/private key at
 * runtime (stored in NVS), plus status/clear/reboot commands.
 */

#ifndef SERIALCONSOLE_H
#define SERIALCONSOLE_H

// Poll for a serial command. Call from loop().
void serial_console_poll();

// Print heap + PSRAM headroom to Serial, labelled with `when`. Called at boot
// (before/after the TLS server starts) and by the `stats` command.
//
// Each open TLS session holds an mbedTLS context plus TLS record buffers
// (CONFIG_MBEDTLS_SSL_MAX_CONTENT_LEN = 16384), so this is what to watch when
// kMaxOpenSockets or the httpd stack size changes.
void memory_report(const char* when);

// Socket-table telemetry, printed by the `stats` command after memory_report().
//
// Defined in PoE-Passkey.ino (where the httpd handle lives). Reports free BSD socket slots and
// open httpd sessions.
void server_socket_report();

#endif // SERIALCONSOLE_H
