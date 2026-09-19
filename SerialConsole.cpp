/*
 * SerialConsole.cpp
 *
 * SECURITY: the TLS private key is WRITE-ONLY by design. There is intentionally
 * no command to view or dump it; `status` reports only presence/absence. The
 * certificate (public, served to every TLS client) is likewise never dumped.
 */

#include "Config.h"
#include "SerialConsole.h"
#include "CertStore.h"
#include "Clock.h"
#include "EthGate.h"
#include "FrontDoor.h"
#include "PasskeyStore.h"
#include "SafePrint.h"

#include <Arduino.h>
#include <string.h>
#include <time.h>
#include <esp_heap_caps.h>

// Static buffers (not on the 8 KB loopTask stack); the console is single-threaded.
static char s_pem_raw[MAX_CERT_PEM_LEN + 1];
static char s_pem_out[MAX_CERT_PEM_LEN + 1];

// How long a certificate paste must be silent before it is finished (a chain arrives in one
// paste, so the first "-----END " can't end it). The key prompt passes 0 (one block only).
static const uint32_t kPemQuietMs = 500;

static void print_help() {
    Serial.println("Commands:");
    Serial.println("  import        import the TLS certificate and private key (prompts for both)");
    Serial.println("  status        show TLS material status");
    Serial.println("  clear-cert    remove the imported certificate");
    Serial.println("  clear-key     remove the imported private key");
    Serial.println("  stats         show heap, socket table and L2 gate telemetry");
    Serial.println("  creds         list stored passkeys (and how full the store is)");
    Serial.println("  blocks        list blocked IPs (each block also logs its reason)");
    Serial.println("  unblock <ip>  remove one IP from the blocklist");
    Serial.println("  clear-blocks  remove every blocked IP");
    Serial.println("  reboot        restart the device");
    Serial.println("  help          this list");
}

// Heap headroom, labelled with the moment it was sampled. Internal RAM is what
// the TLS sessions and the httpd stack come out of; PSRAM holds the blocklist.
void memory_report(const char* when) {
    // PSRAM is optional for correctness but assumed by the buffer placements (blocklist,
    // page buffer, ceremony arena), so say plainly when it is missing instead of leaving
    // the reader to notice that "0 / 0 B" is not a reading.
    const size_t psramTotal = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);
    Serial.printf(
        "Memory [%s]: internal free %u B (low-water %u B), PSRAM free %u / %u B%s\n",
        when ? when : "now",
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
        (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL),
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
        (unsigned)psramTotal,
        (psramTotal == 0) ? "  <-- PSRAM NOT AVAILABLE (buffers fall back to internal RAM)" : ""
    );
}

// Read a PEM from Serial until BEGIN + END markers are present. `quietMs`: 0 = stop at the
// first complete block (key); >0 = stop once quiet, so a chain arrives in one paste.
static int read_pem(char* buf, size_t cap, uint32_t quietMs) {
    size_t len = 0;
    uint32_t start = millis();
    uint32_t lastReport = millis();
    uint32_t lastByteMs = 0;

    Serial.println("Reading... (paste the PEM now)");

    // The bound is checked inside the drain (a fast USB burst would otherwise overrun `buf`).
    while (len < cap - 1) {
        bool gotBytes = false;
        while (len < cap - 1 && Serial.available()) {
            char c = (char)Serial.read();
            if (c == '\r') continue; // normalize CRLF -> LF
            buf[len++] = c;
            gotBytes = true;
        }
        buf[len] = 0;
        if (gotBytes) {
            lastByteMs = millis();
        }

        // Progress so the user can see the firmware is still receiving.
        if (len > 0 && (millis() - lastReport) > 2000) {
            Serial.printf("  (%u bytes received so far)\n", (unsigned)len);
            lastReport = millis();
        }

        const char* end = strstr(buf, "-----END ");
        if (strstr(buf, "-----BEGIN ") && end && strstr(end + 9, "-----")) {
            // One complete block is present. Either that is the whole paste (quietMs == 0),
            // or the paste has gone quiet - which is how a chain's later blocks join it.
            if (quietMs == 0 || (lastByteMs != 0 && (millis() - lastByteMs) >= quietMs)) {
                Serial.printf("Received %u bytes.\n", (unsigned)len);
                return (int)len;
            }
        }
        if (millis() - start > 60000) { // 60-second timeout
            Serial.printf("Timed out after %u bytes. BEGIN marker: %s, END marker: %s\n",
                          (unsigned)len,
                          strstr(buf, "-----BEGIN ") ? "found" : "MISSING",
                          strstr(buf, "-----END ") ? "found" : "MISSING");
            return -1;
        }
        delay(5);
    }

    // Buffer full (a complete PEM already returned): report it, and drain the rest so the tail
    // can't be read back as a console command.
    while (Serial.available()) {
        Serial.read();
    }
    Serial.printf("PEM too large: %u bytes is the most this buffer holds (one certificate or "
                  "key). Paste a shorter chain, or put the PEM in Config.h instead.\n",
                  (unsigned)(cap - 1));
    return -1;
}

// Rebuild multi-line PEM (input may be one line). Strips whitespace, wraps base64 at 64.
// Fails (0) rather than truncating. `keepAll`: false keeps the first block only (key);
// true concatenates all blocks (a certificate chain).
static size_t normalize_pem(const char* in, size_t inLen, char* out, size_t outCap,
                            bool keepAll) {
    (void)inLen;
    if (out == nullptr || outCap == 0) return 0;

    size_t o = 0;
    bool any = false;
    const char* p = in;
    for (;;) {
        const char* begin = strstr(p, "-----BEGIN ");
        if (!begin) break;
        const char* end = strstr(begin, "-----END ");
        if (!end) break;

        const char* headerClose = strstr(begin + 11, "-----");
        if (!headerClose || headerClose >= end) break;
        headerClose += 5;
        const char* footerClose = strstr(end + 9, "-----");
        if (!footerClose) break;
        footerClose += 5;

        size_t headerLen = (size_t)(headerClose - begin);
        if (o + headerLen + 1 > outCap) return 0;
        memcpy(out + o, begin, headerLen);
        o += headerLen;
        out[o++] = '\n';

        size_t col = 0;
        for (const char* q = headerClose; q < end; ++q) {
            char c = *q;
            if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
            // Room for this character, a possible line break and the NUL.
            if (o + 3 > outCap) return 0;
            out[o++] = c;
            if (++col == 64) { out[o++] = '\n'; col = 0; }
        }
        if (col != 0) out[o++] = '\n';

        size_t footerLen = (size_t)(footerClose - end);
        if (o + footerLen + 2 > outCap) return 0;   // footer + '\n' + NUL
        memcpy(out + o, end, footerLen);
        o += footerLen;
        out[o++] = '\n';

        any = true;
        if (!keepAll) break;
        p = footerClose;
    }

    if (!any || o + 1 > outCap) return 0;
    out[o] = 0;
    return o;
}

// Guided import: prompt for the certificate (a chain is fine), then the private key, then
// reboot.
static void do_import() {
    // 1. Certificate. One paste may carry the whole chain - leaf first, then any
    // intermediates - because that is what a client needs when the leaf is not signed by a
    // directly-trusted root. The read finishes when the paste goes quiet (kPemQuietMs).
    Serial.println("Paste the certificate PEM (leaf first; intermediates after it, if any):");
    int n = read_pem(s_pem_raw, MAX_CERT_PEM_LEN, kPemQuietMs);
    if (n < 0) {
        Serial.println("Import aborted (timeout or too large).");
        return;
    }
    size_t pl = normalize_pem(s_pem_raw, (size_t)n, s_pem_out, MAX_CERT_PEM_LEN, true);
    if (pl == 0) {
        Serial.println("Invalid certificate PEM (missing BEGIN/END markers). Import aborted.");
        return;
    }
    // Refuse the wrong KIND of PEM here, rather than storing it and letting the server fail to
    // start: the realistic way to get it wrong is pasting a chain in two steps, which leaves
    // the intermediate in the input buffer for the KEY prompt below.
    if (strstr(s_pem_out, "CERTIFICATE-----") == nullptr) {
        Serial.println("That is not a certificate PEM (expected -----BEGIN CERTIFICATE-----). "
                       "Import aborted.");
        return;
    }
    if (!certstore_save_cert(s_pem_out, pl)) {
        Serial.println("Failed to save certificate. Import aborted.");
        return;
    }
    // Say how much was stored, not just that it worked: a chain that arrived incomplete
    // looks exactly like a chain that arrived whole until a browser refuses the handshake.
    size_t blocks = 0;
    for (const char* q = s_pem_out; (q = strstr(q, "-----BEGIN ")) != nullptr; q += 11) {
        ++blocks;
    }
    Serial.printf("Certificate saved: %u PEM block(s), %u bytes.\n",
                  (unsigned)blocks, (unsigned)pl);

    // 2. Private key. One block, and the read finishes at its END marker (quietMs 0) so a
    // second block in the paste - the EC PARAMETERS an `openssl ecparam -genkey` key file
    // carries - cannot be swallowed into the key.
    Serial.println("Paste the private key PEM and press Enter:");
    n = read_pem(s_pem_raw, MAX_KEY_PEM_LEN, 0);
    if (n < 0) {
        Serial.println("Import aborted (timeout or too large). Certificate was saved.");
        return;
    }
    pl = normalize_pem(s_pem_raw, (size_t)n, s_pem_out, MAX_KEY_PEM_LEN, false);
    if (pl == 0) {
        Serial.println("Invalid private key PEM (missing BEGIN/END markers). Import aborted.");
        return;
    }
    // Matches PKCS#8 ("BEGIN PRIVATE KEY"), SEC1 ("BEGIN EC PRIVATE KEY") and the legacy RSA
    // form - but not a certificate, which is what a chain pasted in two steps would leave here.
    if (strstr(s_pem_out, "PRIVATE KEY-----") == nullptr) {
        Serial.println("That is not a private key PEM (expected -----BEGIN PRIVATE KEY----- or "
                       "-----BEGIN EC PRIVATE KEY-----). Import aborted.");
        return;
    }
    if (!certstore_save_key(s_pem_out, pl)) {
        Serial.println("Failed to save private key. Import aborted.");
        return;
    }
    Serial.printf("Private key saved: %u bytes.\n", (unsigned)pl);

    // 3. Done -> reboot.
    Serial.println("All TLS material imported. Rebooting in 3 seconds...");
    delay(3000);
    ESP.restart();
}

// One line per credential, streamed via cred_foreach. Shows "ever used" vs "used this boot"
// (a healthy key can be "never this boot" after a reboot; "NEVER used" after weeks is stale).
struct CredListing {
    size_t shown;
};

static bool print_credential(const StoredCredential* c, const CredRuntime* rt, void* raw) {
    CredListing* st = (CredListing*)raw;
    const char* ever = c->lastUsedAtMs ? "used" : "NEVER used";
    const char* boot = (rt->usedThisBoot < 0) ? "boot state unknown"
                                              : (rt->usedThisBoot ? "used this boot" : "not used this boot");
    // Sanitized: a corrupt/foreign blob need not obey the enrollment whitelist.
    Serial.printf("  %u: ", (unsigned)++st->shown);
    safe_print(c->email, MAX_EMAIL_LEN);
    Serial.printf(" (%s, %s", ever, boot);

    // Last-used date in UTC (the device has no timezone).
    if (rt->lastSeenUnix) {
        const time_t when = (time_t)rt->lastSeenUnix;
        struct tm tmv;
        char text[32];
        if (gmtime_r(&when, &tmv) && strftime(text, sizeof(text), "%Y-%m-%d %H:%MZ", &tmv)) {
            Serial.printf(", last %s", text);
        }
    }
    Serial.printf("%s)\n", rt->disabled ? ", DISABLED" : "");
    return true;
}

static void print_credentials() {
    CredListing st = { 0 };
    Serial.printf("Credentials: %u of %u slots used\n", (unsigned)cred_count(),
                  (unsigned)kMaxCredentials);
    cred_foreach(print_credential, &st);
    if (st.shown == 0) {
        Serial.println("  (none - open the admin page and register a passkey)");
    }
}

void serial_console_poll() {
    if (!Serial.available()) return;

    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    if (cmd.length() == 0) return;

    if (cmd == "help") {
        print_help();
    } else if (cmd == "import") {
        do_import();
    } else if (cmd == "status") {
        Serial.printf("Certificate (NVS):     %s\n", certstore_has_cert() ? "present" : "absent");
        Serial.printf("Private key (NVS):     %s\n", certstore_has_key() ? "present" : "absent");

        // The clock, because every "last used" date in the credential store is only as good as
        // this: say whether the device knows the time, what it believes it is, and where that
        // came from. An UNKNOWN clock is exactly why the admin page would be showing dots
        // instead of dates.
        uint32_t unixNow = 0;
        if (!clock_now(&unixNow)) {
            Serial.println("Device time:           UNKNOWN (no NTP sync, nothing in the RTC) - "
                           "last-used dates are NOT being recorded");
        } else {
            const time_t when = (time_t)unixNow;
            struct tm tmv;
            char text[32] = "?";
            if (gmtime_r(&when, &tmv)) {
                strftime(text, sizeof(text), "%Y-%m-%d %H:%M:%SZ", &tmv);
            }
            const uint32_t lastSyncMs = clock_last_sync_ms();
            if (lastSyncMs) {
                Serial.printf("Device time (NTP):     %s (%u s since the last sync)\n", text,
                              (unsigned)((millis() - lastSyncMs) / 1000));
            } else {
                Serial.printf("Device time (RTC):     %s (NTP has not answered yet this boot)\n",
                              text);
            }
        }

        // The certificate that is actually served (the NVS store is the only source), and its
        // fingerprint - the value to compare against the browser's trust store (README:
        // "Trusting the certificate in the browser").
        size_t cl = 0;
        const char* pem = certstore_cert(&cl);
        if (pem && cl) {
            char fp[64];
            Serial.printf("Serving:               cert %u B, SHA-1 %s\n", (unsigned)cl,
                          certstore_cert_fingerprint(pem, cl, fp, sizeof(fp)) ? fp : "(unparseable)");
        } else {
            Serial.println("Serving:               no certificate (httpd_ssl will not start)");
        }
    } else if (cmd == "creds") {
        print_credentials();
    } else if (cmd == "stats") {
        memory_report("stats");
        // Socket-table telemetry: free socket slots vs open sessions.
        server_socket_report();
        // L2 gate telemetry: proof that the Ethernet RX filter is doing work.
        // "charged" counts the connection requests it accounted and delivered;
        // "refused" counts the SYNs it dropped before lwIP (blocklisted or over
        // the per-window budget).
        if (eth_gate_active()) {
            uint32_t frames = 0, charged = 0, refused = 0;
            eth_gate_stats(&frames, &charged, &refused);
            Serial.printf("L2 gate:        active, %u frames seen, %u SYNs charged, %u SYNs refused\n",
                          (unsigned)frames, (unsigned)charged, (unsigned)refused);
        } else {
            Serial.println("L2 gate:        inactive (request-level gate only)");
        }
        Serial.printf("Blocklist:      %u of %u IP(s) blocked (see 'blocks')\n",
                      (unsigned)frontdoor_blocklist_count(),
                      (unsigned)kBlocklistMaxEntries);
    } else if (cmd == "blocks") {
        const uint16_t total = frontdoor_blocklist_count();
        if (total == 0) {
            Serial.println("Blocklist is empty.");
        } else {
            // Static, not on the loopTask stack (see the note above the PEM buffers);
            // the list is capped for display - `total` still reports the real count.
            static uint32_t ips[32];
            const uint16_t shown = frontdoor_blocklist_snapshot(ips, 32);
            Serial.printf("Blocked IPs (%u):\n", (unsigned)total);
            for (uint16_t i = 0; i < shown; ++i) {
                IPAddress a(ips[i]);
                Serial.printf("  %s\n", a.toString().c_str());
            }
            if (total > shown) {
                Serial.printf("  ... and %u more\n", (unsigned)(total - shown));
            }
            Serial.println("Remove one with 'unblock <ip>', all with 'clear-blocks'.");
        }
    } else if (cmd.startsWith("unblock ")) {
        String arg = cmd.substring(8);
        arg.trim();
        IPAddress addr;
        if (!addr.fromString(arg)) {
            Serial.println("Usage: unblock <ipv4 address>   (list them with 'blocks')");
        } else if (frontdoor_unblock_ip((uint32_t)addr)) {
            Serial.println("Unblocked. That host can reconnect now.");
        } else {
            Serial.println("That IP is not on the blocklist.");
        }
    } else if (cmd == "clear-blocks") {
        frontdoor_clear_blocklist();
        Serial.println("Blocklist cleared. Every previously blocked host can reconnect.");
    } else if (cmd == "clear-cert") {
        Serial.println(certstore_clear_cert() ? "Certificate cleared." : "No certificate to clear.");
    } else if (cmd == "clear-key") {
        Serial.println(certstore_clear_key() ? "Private key cleared." : "No key to clear.");
    } else if (cmd == "reboot") {
        Serial.println("Rebooting...");
        delay(100);
        ESP.restart();
    } else {
        Serial.println("Unknown command. Type 'help'.");
    }
}
