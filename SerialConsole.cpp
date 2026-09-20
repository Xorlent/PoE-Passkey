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
#include "Crypto.h"
#include "EthGate.h"
#include "FrontDoor.h"
#include "PasskeyStore.h"
#include "SafePrint.h"
#include "Log.h"

#include <Arduino.h>
#include <string.h>
#include <time.h>
#include <esp_heap_caps.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>

// Static buffers (not on the 8 KB loopTask stack); the console is single-threaded.
static char s_pem_raw[MAX_CERT_PEM_LEN + 1];
static char s_pem_out[MAX_CERT_PEM_LEN + 1];

// How long a certificate paste must be silent before it is finished (a chain arrives in one
// paste, so the first "-----END " can't end it). The key prompt passes 0 (one block only).
static const uint32_t kPemQuietMs = 500;

static void print_help() {
    Log.println("Commands:");
    Log.println("  import        import the TLS certificate and private key (prompts for both)");
    Log.println("  status        show TLS material status");
    Log.println("  clear-cert    remove the imported certificate");
    Log.println("  clear-key     remove the imported private key");
    Log.println("  stats         show heap, socket table and L2 gate telemetry");
    Log.println("  selftest      run the crypto self-test (P-256 point validation + ES256)");
    Log.println("  creds         list stored passkeys (and how full the store is)");
    Log.println("  blocks        list blocked IPs (each block also logs its reason)");
    Log.println("  unblock <ip>  remove one IP from the blocklist");
    Log.println("  clear-blocks  remove every blocked IP");
    Log.println("  reboot        restart the device");
    Log.println("  help          this list");
}

// Heap headroom, labelled with the moment it was sampled. Internal RAM is what
// the TLS sessions and the httpd stack come out of; PSRAM holds the blocklist.
void memory_report(const char* when) {
    // PSRAM is optional for correctness but assumed by the buffer placements (blocklist,
    // page buffer, ceremony arena), so say plainly when it is missing instead of leaving
    // the reader to notice that "0 / 0 B" is not a reading.
    const size_t psramTotal = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);
    Log.printf(
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

    Log.println("Reading... (paste the PEM now)");

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
            Log.printf("  (%u bytes received so far)\n", (unsigned)len);
            lastReport = millis();
        }

        const char* end = strstr(buf, "-----END ");
        if (strstr(buf, "-----BEGIN ") && end && strstr(end + 9, "-----")) {
            // One complete block is present. Either that is the whole paste (quietMs == 0),
            // or the paste has gone quiet - which is how a chain's later blocks join it.
            if (quietMs == 0 || (lastByteMs != 0 && (millis() - lastByteMs) >= quietMs)) {
                Log.printf("Received %u bytes.\n", (unsigned)len);
                return (int)len;
            }
        }
        if (millis() - start > 60000) { // 60-second timeout
            Log.printf("Timed out after %u bytes. BEGIN marker: %s, END marker: %s\n",
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
    Log.printf("PEM too large: %u bytes is the most this buffer holds (one certificate or "
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
    Log.println("Paste the certificate PEM (leaf first; intermediates after it, if any):");
    int n = read_pem(s_pem_raw, MAX_CERT_PEM_LEN, kPemQuietMs);
    if (n < 0) {
        Log.println("Import aborted (timeout or too large).");
        return;
    }
    size_t pl = normalize_pem(s_pem_raw, (size_t)n, s_pem_out, MAX_CERT_PEM_LEN, true);
    if (pl == 0) {
        Log.println("Invalid certificate PEM (missing BEGIN/END markers). Import aborted.");
        return;
    }
    // Refuse the wrong KIND of PEM here, rather than storing it and letting the server fail to
    // start: the realistic way to get it wrong is pasting a chain in two steps, which leaves
    // the intermediate in the input buffer for the KEY prompt below.
    if (strstr(s_pem_out, "CERTIFICATE-----") == nullptr) {
        Log.println("That is not a certificate PEM (expected -----BEGIN CERTIFICATE-----). "
                       "Import aborted.");
        return;
    }
    if (!certstore_save_cert(s_pem_out, pl)) {
        Log.println("Failed to save certificate. Import aborted.");
        return;
    }
    // Say how much was stored, not just that it worked: a chain that arrived incomplete
    // looks exactly like a chain that arrived whole until a browser refuses the handshake.
    size_t blocks = 0;
    for (const char* q = s_pem_out; (q = strstr(q, "-----BEGIN ")) != nullptr; q += 11) {
        ++blocks;
    }
    Log.printf("Certificate saved: %u PEM block(s), %u bytes.\n",
                  (unsigned)blocks, (unsigned)pl);

    // 2. Private key. One block, and the read finishes at its END marker (quietMs 0) so a
    // second block in the paste - the EC PARAMETERS an `openssl ecparam -genkey` key file
    // carries - cannot be swallowed into the key.
    Log.println("Paste the private key PEM and press Enter:");
    n = read_pem(s_pem_raw, MAX_KEY_PEM_LEN, 0);
    if (n < 0) {
        Log.println("Import aborted (timeout or too large). Certificate was saved.");
        return;
    }
    pl = normalize_pem(s_pem_raw, (size_t)n, s_pem_out, MAX_KEY_PEM_LEN, false);
    if (pl == 0) {
        Log.println("Invalid private key PEM (missing BEGIN/END markers). Import aborted.");
        return;
    }
    // Matches PKCS#8 ("BEGIN PRIVATE KEY"), SEC1 ("BEGIN EC PRIVATE KEY") and the legacy RSA
    // form - but not a certificate, which is what a chain pasted in two steps would leave here.
    if (strstr(s_pem_out, "PRIVATE KEY-----") == nullptr) {
        Log.println("That is not a private key PEM (expected -----BEGIN PRIVATE KEY----- or "
                       "-----BEGIN EC PRIVATE KEY-----). Import aborted.");
        return;
    }
    if (!certstore_save_key(s_pem_out, pl)) {
        Log.println("Failed to save private key. Import aborted.");
        return;
    }
    Log.printf("Private key saved: %u bytes.\n", (unsigned)pl);

    // 3. Done -> reboot.
    Log.println("All TLS material imported. Rebooting in 3 seconds...");
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
    Log.printf("  %u: ", (unsigned)++st->shown);
    safe_print(c->email, MAX_EMAIL_LEN);
    Log.printf(" (%s, %s", ever, boot);

    // Last-used date in UTC (the device has no timezone).
    if (rt->lastSeenUnix) {
        const time_t when = (time_t)rt->lastSeenUnix;
        struct tm tmv;
        char text[32];
        if (gmtime_r(&when, &tmv) && strftime(text, sizeof(text), "%Y-%m-%d %H:%MZ", &tmv)) {
            Log.printf(", last %s", text);
        }
    }
    Log.printf("%s)\n", rt->disabled ? ", DISABLED" : "");
    return true;
}

static void print_credentials() {
    CredListing st = { 0 };
    Log.printf("Credentials: %u of %u slots used\n", (unsigned)cred_count(),
                  (unsigned)kMaxCredentials);
    cred_foreach(print_credential, &st);
    if (st.shown == 0) {
        Log.println("  (none - open the admin page and register a passkey)");
    }
}

// ---------------------------------------------------------------------------
// selftest: exercise the S2 fix (P-256 point validation) and the ES256 path.
// ---------------------------------------------------------------------------

// mbedTLS RNG callback, backed by the ESP32 hardware RNG (via crypto_random).
static int selftest_rng(void* ctx, unsigned char* out, size_t len) {
    (void)ctx;
    crypto_random((uint8_t*)out, len);
    return 0;
}

// Minimal DER SEQUENCE { INTEGER r, INTEGER s } encoder (the inverse of
// der_sig_to_rs in Crypto.cpp). Returns the encoded length, or 0 on overflow.
static size_t der_encode_int(const uint8_t* v, size_t n, uint8_t* out) {
    size_t i = 0;
    while (i < n - 1 && v[i] == 0) ++i;          // strip leading zeros
    const size_t len = n - i;
    const uint8_t pad = (v[i] & 0x80) ? 1 : 0;   // sign byte for a high bit
    out[0] = 0x02;
    out[1] = (uint8_t)(len + pad);
    if (pad) out[2] = 0x00;
    memcpy(out + 2 + pad, v + i, len);
    return 2 + pad + len;
}

static size_t rs_to_der(const uint8_t r[32], const uint8_t s[32], uint8_t* out, size_t cap) {
    uint8_t ri[35], si[35];
    const size_t rl = der_encode_int(r, 32, ri);
    const size_t sl = der_encode_int(s, 32, si);
    const size_t body = rl + sl;
    if (2 + body > cap) return 0;
    out[0] = 0x30;
    out[1] = (uint8_t)body;
    memcpy(out + 2, ri, rl);
    memcpy(out + 2 + rl, si, sl);
    return 2 + body;
}

bool run_selftest() {
    int failures = 0;

    // Generator point G (a known-valid P-256 point).
    static const uint8_t gx[32] = { 0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96 };
    static const uint8_t gy[32] = { 0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5 };
    static const uint8_t zero[32] = { 0 };
    // p - 1 (the P-256 prime minus one).
    static const uint8_t pm1[32] = { 0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe };
    static const uint8_t one[32] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };

    if (!crypto_p256_pubkey_valid(gx, gy)) ++failures;
    if (crypto_p256_pubkey_valid(zero, zero)) ++failures;
    if (crypto_p256_pubkey_valid(pm1, zero)) ++failures;
    if (crypto_p256_pubkey_valid(one, one)) ++failures;

    // S2 regression: a degenerate key must fail verification regardless of the
    // signature (the guard runs before any signature parsing).
    {
        static const uint8_t msg[] = "PoE-Passkey selftest";
        uint8_t junk[8] = { 0 };
        if (crypto_verify_es256(zero, zero, msg, sizeof(msg) - 1, junk, sizeof(junk))) ++failures;
    }

    // End-to-end positive: generate a key, sign, and verify through the real path.
    {
        static const uint8_t msg[] = "PoE-Passkey selftest";
        mbedtls_ecp_group grp;
        mbedtls_ecp_point Q;
        mbedtls_mpi d, r, s;
        mbedtls_ecp_group_init(&grp);
        mbedtls_ecp_point_init(&Q);
        mbedtls_mpi_init(&d);
        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);

        // All buffers are declared (and initialized) up front so no `goto` below
        // crosses an initialization.
        bool ok = false;
        uint8_t hash[32] = { 0 };
        uint8_t pub[65] = { 0 };
        size_t pubLen = 0;
        uint8_t rbuf[32] = { 0 }, sbuf[32] = { 0 };
        uint8_t der[72] = { 0 };
        size_t derLen = 0;

        if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) goto pos_done;
        if (mbedtls_ecp_gen_keypair(&grp, &d, &Q, selftest_rng, nullptr) != 0) goto pos_done;

        crypto_sha256(msg, sizeof(msg) - 1, hash);
        if (mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, sizeof(hash), selftest_rng, nullptr) != 0) goto pos_done;

        if (mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &pubLen, pub, sizeof(pub)) != 0) goto pos_done;
        if (pubLen != 65 || pub[0] != 0x04) goto pos_done;

        if (mbedtls_mpi_write_binary(&r, rbuf, sizeof(rbuf)) != 0) goto pos_done;
        if (mbedtls_mpi_write_binary(&s, sbuf, sizeof(sbuf)) != 0) goto pos_done;

        derLen = rs_to_der(rbuf, sbuf, der, sizeof(der));
        if (derLen == 0) goto pos_done;

        if (!crypto_verify_es256(pub + 1, pub + 33, msg, sizeof(msg) - 1, der, derLen)) goto pos_done;
        ok = true;

    pos_done:
        mbedtls_ecp_point_free(&Q);
        mbedtls_ecp_group_free(&grp);
        mbedtls_mpi_free(&d);
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        if (!ok) ++failures;
    }

    if (failures == 0) {
        Log.println("[selftest] elliptic curve test: PASS");
        return true;
    }
    Log.println("[selftest] elliptic curve test: FAIL");
    return false;
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
        Log.printf("Certificate (NVS):     %s\n", certstore_has_cert() ? "present" : "absent");
        Log.printf("Private key (NVS):     %s\n", certstore_has_key() ? "present" : "absent");

        // The clock, because every "last used" date in the credential store is only as good as
        // this: say whether the device knows the time, what it believes it is, and where that
        // came from. An UNKNOWN clock is exactly why the admin page would be showing dots
        // instead of dates.
        uint32_t unixNow = 0;
        if (!clock_now(&unixNow)) {
            Log.println("Device time:           UNKNOWN (no NTP sync, nothing in the RTC) - "
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
                Log.printf("Device time (NTP):     %s (%u s since the last sync)\n", text,
                              (unsigned)((millis() - lastSyncMs) / 1000));
            } else {
                Log.printf("Device time (RTC):     %s (NTP has not answered yet this boot)\n",
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
            Log.printf("Serving:               cert %u B, SHA-1 %s\n", (unsigned)cl,
                          certstore_cert_fingerprint(pem, cl, fp, sizeof(fp)) ? fp : "(unparseable)");
        } else {
            Log.println("Serving:               no certificate (httpd_ssl will not start)");
        }
    } else if (cmd == "creds") {
        print_credentials();
    } else if (cmd == "selftest") {
        run_selftest();
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
            Log.printf("L2 gate:        active, %u frames seen, %u SYNs charged, %u SYNs refused\n",
                          (unsigned)frames, (unsigned)charged, (unsigned)refused);
        } else {
            Log.println("L2 gate:        inactive (request-level gate only)");
        }
        Log.printf("Blocklist:      %u of %u IP(s) blocked (see 'blocks')\n",
                      (unsigned)frontdoor_blocklist_count(),
                      (unsigned)kBlocklistMaxEntries);
    } else if (cmd == "blocks") {
        const uint16_t total = frontdoor_blocklist_count();
        if (total == 0) {
            Log.println("Blocklist is empty.");
        } else {
            // Static, not on the loopTask stack (see the note above the PEM buffers);
            // the list is capped for display - `total` still reports the real count.
            static uint32_t ips[32];
            const uint16_t shown = frontdoor_blocklist_snapshot(ips, 32);
            Log.printf("Blocked IPs (%u):\n", (unsigned)total);
            for (uint16_t i = 0; i < shown; ++i) {
                IPAddress a(ips[i]);
                Log.printf("  %s\n", a.toString().c_str());
            }
            if (total > shown) {
                Log.printf("  ... and %u more\n", (unsigned)(total - shown));
            }
            Log.println("Remove one with 'unblock <ip>', all with 'clear-blocks'.");
        }
    } else if (cmd.startsWith("unblock ")) {
        String arg = cmd.substring(8);
        arg.trim();
        IPAddress addr;
        if (!addr.fromString(arg)) {
            Log.println("Usage: unblock <ipv4 address>   (list them with 'blocks')");
        } else if (frontdoor_unblock_ip((uint32_t)addr)) {
            Log.println("Unblocked. That host can reconnect now.");
        } else {
            Log.println("That IP is not on the blocklist.");
        }
    } else if (cmd == "clear-blocks") {
        frontdoor_clear_blocklist();
        Log.println("Blocklist cleared. Every previously blocked host can reconnect.");
    } else if (cmd == "clear-cert") {
        Log.println(certstore_clear_cert() ? "Certificate cleared." : "No certificate to clear.");
    } else if (cmd == "clear-key") {
        Log.println(certstore_clear_key() ? "Private key cleared." : "No key to clear.");
    } else if (cmd == "reboot") {
        Log.println("Rebooting...");
        delay(100);
        ESP.restart();
    } else {
        Log.println("Unknown command. Type 'help'.");
    }
}
