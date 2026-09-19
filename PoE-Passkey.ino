/*
 * PoE-Passkey.ino
 *
 * FIDO2 / WebAuthn IP Gateway on an ESP32-P4 (Unit-PoE-P4): turns possession of a
 * hardware key into a short-lived list of authorized source IP addresses.
 *
 * CONFIGURATION: all user-configurable settings are in Config.h.
 */

#include "Config.h"

////////--------------------------------------- DO NOT EDIT ANYTHING BELOW THIS LINE ---------------------------------------////////

#include <ETH.h>
#include <esp_heap_caps.h>
#include <esp_log.h>
#include <esp_https_server.h>
#include <lwip/sockets.h>
#include <string.h>
#include <stdlib.h>
#include "ConfigValidation.h"
#include "FrontDoor.h"
#include "EthGate.h"
#include "PasskeyStore.h"
#include "WebAuthn.h"
#include "Crypto.h"
#include "IndexHtml.h"
#include "AdminHtml.h"
#include "CertStore.h"
#include "SerialConsole.h"
#include "Clock.h"
#include "SafePrint.h"

////////---------------------------------------        Runtime objects        ---------------------------------------////////

static const char* TAG = "passkey";
static httpd_handle_t s_httpsServer = nullptr;

// httpd's own session cap, remembered for the `stats` telemetry (see server_socket_report).
static uint16_t s_maxOpenSockets = 0;

////////---------------------------------------        Helpers        ---------------------------------------////////

// Return the client's source IP (network byte order), or 0 on failure.
// Delegates to frontdoor_peer_ipv4() so IPv4-mapped IPv6 peers - what httpd
// reports for IPv4 clients while listening on its dual-stack IPv6 socket - are
// unwrapped correctly instead of showing up as 0.0.0.0.
static uint32_t req_client_ip(httpd_req_t* req) {
    return frontdoor_peer_ipv4(httpd_req_to_sockfd(req));
}

// Is `ip` (network byte order) present in an IPv4 list?
static bool ip_in_list(uint32_t ip, const IPAddress* list, uint32_t count) {
    for (uint32_t i = 0; i < count; ++i) {
        if ((uint32_t)list[i] == ip) {
            return true;
        }
    }
    return false;
}

// Read the whole body into `buf` (NUL-terminated). Returns length, or -1 on error.
// content_len is hostile input; the size test is wrap-proof and every read is bounded.
static int read_body(httpd_req_t* req, char* buf, size_t cap) {
    size_t total = req->content_len;
    if (cap == 0 || total >= cap) {
        return -1;
    }
    size_t got = 0;
    while (got < total) {
        // Never ask the stack for more than the buffer can still hold, whatever
        // the header claimed.
        size_t want = total - got;
        if (want > cap - 1 - got) {
            want = cap - 1 - got;
        }
        if (want == 0) {
            return -1; // body longer than the buffer: refuse it
        }
        int r = httpd_req_recv(req, buf + got, want);
        if (r <= 0) {
            return -1;
        }
        got += (size_t)r;
    }
    buf[got] = 0;
    return (int)got;
}

// Send a fixed JSON object with an HTTP status code.
static esp_err_t send_json_status(httpd_req_t* req, const char* status, const char* body) {
    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, body);
    return ESP_OK;
}

// Send a JSON success/error response.
static esp_err_t send_json(httpd_req_t* req, const char* body) {
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, body);
    return ESP_OK;
}

// HTTP method name for the access log.
static const char* method_name(httpd_method_t method) {
    switch (method) {
        case HTTP_GET:  return "GET";
        case HTTP_POST: return "POST";
        default:        return "?";
    }
}

// Print `uri` with the value of any ?key= parameter masked (the consumer secret). Everything
// else is printed sanitized (SafePrint.h), so nothing can inject escape sequences.
static bool param_name_is_key(const char* p, size_t len) {
    // Case-insensitive on purpose: a client that sends Key= or KEY= must not get its value
    // echoed here just because it spelled the name differently. (It also cannot
    // authenticate, which is the handler's business, not this printer's.)
    return len == 3 && (p[0] | 0x20) == 'k' && (p[1] | 0x20) == 'e' && (p[2] | 0x20) == 'y';
}

static void print_uri_masked(const char* uri) {
    const char* q = strchr(uri, '?');
    if (!q) {
        safe_print(uri, 128); // URI length is capped by httpd (max_uri_len), so 128 shows it
        return;
    }
    // The path is caller-supplied too (a request line can carry raw bytes), so it goes
    // through the same printer as everything else.
    safe_print_range(uri, (size_t)(q - uri), 128);
    Serial.print('?');

    const char* p = q + 1;
    bool first = true;
    while (*p) {
        const char* amp = strchr(p, '&');
        const char* end = amp ? amp : p + strlen(p);
        if (!first) {
            Serial.print('&');
        }
        first = false;

        const char* eq = (const char*)memchr(p, '=', (size_t)(end - p));
        if (!eq) {
            safe_print_range(p, (size_t)(end - p), 64);          // a valueless flag
        } else if (param_name_is_key(p, (size_t)(eq - p))) {
            safe_print_range(p, (size_t)(eq - p), 64);
            Serial.print("=***");                                // the secret's value
        } else {
            safe_print_range(p, (size_t)(eq - p), 64);
            Serial.print('=');
            safe_print_range(eq + 1, (size_t)(end - eq - 1), 64);
        }
        p = amp ? amp + 1 : end;
    }
}

// Caller-influenced text is printed via SafePrint.h (shared by the HTTP handlers, the
// ceremony code, and the serial console).

// One line per ADMITTED request (Config.h: kLogHttpRequests). Call it first in
// every handler, immediately after frontdoor_admit_request(), so the console
// shows exactly what a client asked for - one page load is one line, not five -
// while the gate keeps logging its own 403/429 refusals.
//
// Serial rather than ESP_LOGI: this core is built with CONFIG_LOG_DEFAULT_LEVEL and
// CONFIG_LOG_MAXIMUM_LEVEL = ERROR and without CONFIG_LOG_MASTER_LEVEL, so every
// ESP_LOGW/ESP_LOGI in the project is compiled out (see the serial-console notes in
// README). Serial is the only channel that reaches the operator here. This runs in the
// httpd task, never in the Ethernet RX path, so a (mutex-protected) Serial write cannot
// cost received frames.
static void log_request(httpd_req_t* req) {
    if (!kLogHttpRequests) return;
    IPAddress ip(req_client_ip(req));
    // req->method is an int in this IDF's httpd_req, so the cast is required (it was
    // never checked before: the previous ESP_LOGI call was compiled out, which is how
    // this hid).
    Serial.printf("[req] %s ", method_name((httpd_method_t)req->method));
    print_uri_masked(req->uri);
    Serial.printf(" from %s\n", ip.toString().c_str());
}

// Page render buffer, allocated once at boot (PSRAM, internal RAM fallback). Size is the
// larger template plus 64 B of slack for the __CLIENT_IP__ / __CSP_NONCE__ substitutions.
static char* s_pageBuf = nullptr;
static size_t s_pageBufCap = 0;

static const size_t kPageBufCap =
    (sizeof(kIndexHtml) > sizeof(kAdminHtml) ? sizeof(kIndexHtml) : sizeof(kAdminHtml)) + 64;

// One-time allocation for s_pageBuf. Returns false when no memory is available.
static bool page_buffer_begin() {
    s_pageBufCap = kPageBufCap;
    s_pageBuf = (char*)heap_caps_malloc(s_pageBufCap, MALLOC_CAP_SPIRAM);
    if (!s_pageBuf) {
        // Report the fallback: internal RAM is exactly what the TLS record buffers come
        // out of, so losing ~6 KB of it to the page buffer is worth knowing about.
        Serial.printf("[page] PSRAM unavailable for the %u B render buffer; using internal RAM\n",
                      (unsigned)s_pageBufCap);
        s_pageBuf = (char*)malloc(s_pageBufCap);
    }
    if (!s_pageBuf) {
        s_pageBufCap = 0;
        return false;
    }
    return true;
}

// Fill `out` with the template `tpl`, substituting the placeholders a page may use:
// __CLIENT_IP__ and __CSP_NONCE__. Returns the rendered length, or 0 if `out` cannot hold
// the result.
//
// There is deliberately no admin-link placeholder: nothing the server sends names the
// admin console, because a browser can read every byte of every document it is given
// (View Source, devtools). A link that was merely hidden - display:none plus a
// data-admin flag for the page's script - was readable there, so it was removed rather
// than substituted conditionally. The console is documented in the README.
//
// __CSP_NONCE__ is the per-response nonce that also goes into the Content-Security-Policy
// header (send_page below). It must be the SAME string in both places or the page's own
// <style>/<script> are refused and the document does nothing.
//
// Token-order agnostic: it walks the template and replaces whichever placeholder
// comes next, so a page may declare them in any order. A page that uses only some of
// them is fine.
//
// If `out` cannot hold the result the caller serves the raw template instead: the
// placeholders are then visible as inert text to whoever got that page - no link and no
// URL, just the literal token names - and, because the nonce in its <style>/<script> is
// then the literal placeholder rather than the response's nonce, the browser refuses those
// too. That path is unreachable with the shipping templates (kPageBufCap is sized from them
// plus the largest substitution; see its comment).
//
// The token/value tables are locals on purpose: a file-scope struct declared here
// would sit after the first function definition, i.e. after the point where the
// Arduino builder inserts its generated prototypes, and the type would not be
// visible to them.
static size_t render_page(const char* tpl, char* out, size_t cap,
                          const char* ip, const char* nonce) {
    static const char* const kTokens[] = { "__CLIENT_IP__", "__CSP_NONCE__" };
    const char* const kValues[] = { ip ? ip : "", nonce ? nonce : "" };
    const size_t kTokenCount = sizeof(kTokens) / sizeof(kTokens[0]);

    size_t off = 0;      // write position in `out`
    const char* p = tpl; // read position in the template

    while (*p) {
        const char* bestTok = nullptr;
        size_t bestIdx = 0;
        for (size_t i = 0; i < kTokenCount; ++i) {
            const char* tok = strstr(p, kTokens[i]);
            if (tok && (!bestTok || tok < bestTok)) {
                bestTok = tok;
                bestIdx = i;
            }
        }
        if (!bestTok) {
            break; // no placeholder left: the rest is copied as-is below
        }

        const char* repl = kValues[bestIdx];
        const size_t replLen = strlen(repl);
        const size_t segLen = (size_t)(bestTok - p);
        if (off + segLen + replLen + 1 > cap) return 0;

        memcpy(out + off, p, segLen);     off += segLen;
        memcpy(out + off, repl, replLen); off += replLen;
        p = bestTok + strlen(kTokens[bestIdx]);
    }

    const size_t tailLen = strlen(p);
    if (off + tailLen + 1 > cap) return 0;
    memcpy(out + off, p, tailLen + 1); // includes the NUL
    return off + tailLen;
}

// ---------------------------------------------------------------------------
// Page responses: one CSP nonce per response, and the header that carries it
// ---------------------------------------------------------------------------

// 16 random bytes (128 bits) is the usual nonce size, and guessing it is what the policy
// rests on. Hex rather than base64url keeps the value a plain token for both the header and
// the attribute: no escaping, no +/ or = to misquote.
static const size_t kCspNonceBytes = 16;
static const size_t kCspNonceLen = kCspNonceBytes * 2; // 32 hex characters

// Fill `out` (kCspNonceLen + 1 bytes) with a fresh, unpredictable nonce.
static void make_csp_nonce(char* out) {
    static const char kHex[] = "0123456789abcdef";
    uint8_t raw[kCspNonceBytes];
    crypto_random(raw, sizeof(raw));
    for (size_t i = 0; i < kCspNonceBytes; ++i) {
        out[i * 2]     = kHex[raw[i] >> 4];
        out[i * 2 + 1] = kHex[raw[i] & 0x0F];
    }
    out[kCspNonceLen] = 0;
}

// Policy both pages use: only their own nonce'd inline <style>/<script> may run; no other
// origins, inline handlers, or eval(). Any new tag/attribute belongs here (reviewed), not in
// a template. ~218 chars with a 32-char nonce, so it fits the 256 B buffer below.
#define POE_CSP_FORMAT \
    "default-src 'none'; script-src 'nonce-%s'; style-src 'nonce-%s'; img-src data:; " \
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// Render `tpl` and send with its security headers. httpd_resp_set_hdr() stores the value
// pointer (not a copy), so the nonce/body/CSP all live in this frame until the send.
static esp_err_t send_page(httpd_req_t* req, const char* tpl, const char* ipStr) {
    char nonce[kCspNonceLen + 1];
    make_csp_nonce(nonce);

    char csp[256];
    const int cspLen = snprintf(csp, sizeof(csp), POE_CSP_FORMAT, nonce, nonce);
    if (cspLen <= 0 || (size_t)cspLen >= sizeof(csp)) {
        // Only if POE_CSP_FORMAT outgrew its buffer; say so (a truncated policy is weaker).
        Serial.printf("[page] CSP does not fit its %u B buffer: check POE_CSP_FORMAT\n",
                      (unsigned)sizeof(csp));
    }

    size_t len = 0;
    if (s_pageBuf) {
        len = render_page(tpl, s_pageBuf, s_pageBufCap, ipStr, nonce);
    }

    httpd_resp_set_hdr(req, "Content-Security-Policy", csp);
    httpd_resp_set_type(req, "text/html");
    // The document embeds THIS peer's address, so it must never be reused by a browser or
    // proxy for somebody else.
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");

    if (len == 0) {
        // Fallback: serve the raw template (placeholders inert, scripts refused by the nonce).
        return httpd_resp_send(req, tpl, strlen(tpl));
    }
    return httpd_resp_send(req, s_pageBuf, (ssize_t)len);
}

// Refuse a non-admin IP (and block it, if kBlockNonAdminIPOnAdminRoute). Single choke point
// every admin route calls.
static esp_err_t admin_denied(httpd_req_t* req, const char* what) {
    const uint32_t peer = req_client_ip(req);
    IPAddress ip(peer);
    const String ipStr = ip.toString();
    char body[80];
    snprintf(body, sizeof(body), "{\"error\":\"not_admin_ip\",\"ip\":\"%s\"}", ipStr.c_str());
    Serial.printf("[admin] %s refused: %s is not in kAdminIPs (Config.h)\n", what, ipStr.c_str());

    if (kBlockNonAdminIPOnAdminRoute) {
        if (peer == 0) {
            Serial.println("[admin] not blocking the peer: it has no usable IPv4 address");
        } else if (ip_in_list(peer, kAdminIPs, kAdminIPCount) ||
                   ip_in_list(peer, kConsumerAllowlist, kConsumerAllowlistCount)) {
            // Guard: never block a host in either allowlist.
            Serial.printf("[admin] not blocking %s: it is in a configured allowlist\n", ipStr.c_str());
        } else {
            frontdoor_block_ip_reason(peer, "admin route request from a non-admin source IP");
            Serial.printf("[admin] recover that host with the serial console: 'unblock %s' or 'clear-blocks'\n",
                          ipStr.c_str());
        }
    }

    return send_json_status(req, "403 Forbidden", body);
}

////////---------------------------------------        HTTP handlers        ---------------------------------------////////

// GET / - the public page (authenticate, i.e. authorize this source IP). One page load =
// one request; /admin is never named in any served document.
static esp_err_t handler_root(httpd_req_t* req) {
    if (!frontdoor_admit_request(req)) {
        return ESP_FAIL; // rejection response already sent; drop the connection
    }
    log_request(req);

    const uint32_t peer = req_client_ip(req);
    IPAddress ip(peer);
    // No admin flag is computed here: nothing in this page depends on the caller being
    // an admin any more (see the handler note above and kIndexHtml).
    const String ipStr = ip.toString();

    // send_page() renders the template with a fresh CSP nonce and sends the matching policy
    // header - see its comment for why the nonce, the body and the header all live in that
    // one frame.
    return send_page(req, kIndexHtml, ipStr.c_str());
}

// GET /favicon.ico - empty 200 (the page declares an empty data: icon, so this is rarely
// hit). Not 204: httpd_resp_send() always emits Content-Length, which is illegal on a 204.
static esp_err_t handler_favicon(httpd_req_t* req) {
    if (!frontdoor_admit_request(req)) {
        return ESP_FAIL; // rejection response already sent; drop the connection
    }
    log_request(req);

    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, nullptr, 0); // 200 OK, Content-Length: 0
    return ESP_OK;
}

// GET /admin - the admin console (enrollment + revocation). Its own route so a non-admin
// gets a 403 before any admin markup reaches them; the endpoints re-check the IP anyway.
static esp_err_t handler_admin_page(httpd_req_t* req) {
    if (!frontdoor_admit_request(req)) {
        return ESP_FAIL; // rejection response already sent; drop the connection
    }
    log_request(req);

    const uint32_t peer = req_client_ip(req);
    if (!ip_in_list(peer, kAdminIPs, kAdminIPCount)) {
        return admin_denied(req, "GET /admin");
    }

    IPAddress ip(peer);
    const String ipStr = ip.toString();

    // send_page() renders the template with a fresh CSP nonce and sends the matching policy
    // header. Nothing here is reusable by another caller (it embeds the peer address), which
    // send_page() marks with Cache-Control: no-store.
    return send_page(req, kAdminHtml, ipStr.c_str());
}

// GET /whoami - the caller's IP (polled by the page to spot an address change).
static esp_err_t handler_whoami(httpd_req_t* req) {
    if (!frontdoor_admit_request(req)) {
        return ESP_FAIL; // rejection response already sent; drop the connection
    }
    log_request(req);

    IPAddress ip(req_client_ip(req));
    char buf[64];
    snprintf(buf, sizeof(buf), "{\"ip\":\"%s\"}", ip.toString().c_str());
    httpd_resp_set_type(req, "application/json");
    // Polled by the page to notice that the caller's address changed; a cached
    // copy would hide exactly that.
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_sendstr(req, buf);
    return ESP_OK;
}

// Extract a string field from a JSON object (no escape handling; fits the
// simple fields we accept here, e.g. "email").
static int extract_field(const char* body, size_t len, const char* key,
                         char* out, size_t cap) {
    size_t klen = strlen(key);
    if (klen + 2 > len) return -1;
    for (size_t i = 0; i + klen + 2 <= len; ++i) {
        if (body[i] == '"' && memcmp(body + i + 1, key, klen) == 0 && body[i + 1 + klen] == '"') {
            size_t j = i + klen + 2;
            while (j < len && body[j] != ':') ++j;
            if (j >= len || body[j] != ':') return -1;
            ++j;
            while (j < len && body[j] != '"') ++j;
            if (j >= len) return -1;
            ++j;
            size_t o = 0;
            while (j < len && body[j] != '"' && o + 1 < cap) out[o++] = body[j++];
            if (j >= len) return -1; // unterminated string value -> fail closed
            out[o] = 0;
            return (int)o;
        }
    }
    return -1;
}

// Extract a JSON boolean field ("key":true / false, also accepting 1 / 0). Fails closed:
// a missing field is NOT "false", because the caller has to tell those apart (enable is
// spelled disabled=false). Same reach as extract_field: it finds the key it expects, it is
// not a parser.
static bool extract_bool(const char* body, size_t len, const char* key, bool* out) {
    size_t klen = strlen(key);
    if (klen + 2 > len) return false;
    for (size_t i = 0; i + klen + 2 <= len; ++i) {
        if (body[i] == '"' && memcmp(body + i + 1, key, klen) == 0 && body[i + 1 + klen] == '"') {
            size_t j = i + klen + 2;
            while (j < len && body[j] != ':') ++j;
            if (j >= len) return false;
            ++j;
            while (j < len && (body[j] == ' ' || body[j] == '\t')) ++j;
            if (j + 4 <= len && memcmp(body + j, "true", 4) == 0) { *out = true; return true; }
            if (j + 5 <= len && memcmp(body + j, "false", 5) == 0) { *out = false; return true; }
            if (j < len && (body[j] == '1' || body[j] == '0')) { *out = (body[j] == '1'); return true; }
            return false;
        }
    }
    return false;
}

// POST /register/start - enrollment options. Admin-IP gated: the source IP is the
// only gate, and the identity becomes whatever well-formed address is posted (it is
// used as both name and displayName - see WebAuthn.h).
static esp_err_t handler_register_start(httpd_req_t* req) {
    if (!frontdoor_admit_request(req)) {
        return ESP_FAIL; // rejection response already sent; drop the connection
    }
    log_request(req);

    if (!ip_in_list(req_client_ip(req), kAdminIPs, kAdminIPCount)) {
        return admin_denied(req, "POST /register/start");
    }

    char* body = (char*)malloc(kMaxBodySize + 1);
    if (!body) return send_json_status(req, "500 Internal Server Error", "{\"error\":\"oom\"}");

    char email[MAX_EMAIL_LEN];
    char out[1024];

    int bl = read_body(req, body, kMaxBodySize + 1);
    if (bl < 0) {
        free(body);
        return send_json_status(req, "413 Payload Too Large", "{\"error\":\"payload\"}");
    }

    int el = extract_field(body, (size_t)bl, "email", email, sizeof(email));
    if (el <= 0) {
        free(body);
        return send_json_status(req, "400 Bad Request", "{\"error\":\"email_required\"}");
    }
    if (el >= (int)sizeof(email) - 1) {
        // extract_field stops at the cap, and a truncated address would silently become
        // a different identity than the one the operator typed - refuse it instead.
        free(body);
        Serial.printf("[admin] POST /register/start refused: the email is longer than %u bytes\n",
                      (unsigned)sizeof(email) - 1);
        return send_json_status(req, "400 Bad Request", "{\"error\":\"invalid_email\"}");
    }

    int n = webauthn_register_start(email, out, sizeof(out), req_client_ip(req));
    if (n == -2) {
        // Unusable address (email_is_usable() in WebAuthn.cpp). No allowlist is
        // involved: enrollment is gated by the source IP checked above, so the identity
        // is whatever the operator typed - and a typo becomes a wrong identity, which
        // is why the address is logged.
        free(body);
        // The address is caller-supplied AND reached this line by failing validation, so it
        // may contain anything: print it sanitized (SafePrint.h) rather than raw.
        Serial.printf("[admin] POST /register/start refused: '");
        safe_print(email, 64);
        Serial.printf("' is not a usable email address\n");
        return send_json_status(req, "400 Bad Request", "{\"error\":\"invalid_email\"}");
    }
    if (n == -3) {
        free(body);
        Serial.println("[admin] POST /register/start: the session store is full (kMaxSessions)");
        return send_json_status(req, "429 Too Many Requests", "{\"error\":\"busy\"}");
    }
    if (n < 0) {
        free(body);
        Serial.printf("[admin] POST /register/start: could not build the options (error %d)\n", n);
        return send_json_status(req, "500 Internal Server Error", "{\"error\":\"encode_error\"}");
    }

    esp_err_t rc = send_json(req, out);
    free(body);
    return rc;
}

// POST /register/finish - admin-gated; verifies attestation, stores credential.
static esp_err_t handler_register_finish(httpd_req_t* req) {
    if (!frontdoor_admit_request(req)) {
        return ESP_FAIL; // rejection response already sent; drop the connection
    }
    log_request(req);

    if (!ip_in_list(req_client_ip(req), kAdminIPs, kAdminIPCount)) {
        return admin_denied(req, "POST /register/finish");
    }

    char* body = (char*)malloc(kMaxBodySize + 1);
    if (!body) return send_json_status(req, "500 Internal Server Error", "{\"error\":\"oom\"}");

    int bl = read_body(req, body, kMaxBodySize + 1);
    if (bl < 0) {
        free(body);
        return send_json_status(req, "413 Payload Too Large", "{\"error\":\"payload\"}");
    }

    if (!webauthn_register_finish(body, (size_t)bl)) {
        free(body);
        return send_json_status(req, "400 Bad Request", "{\"error\":\"registration_failed\"}");
    }

    esp_err_t rc = send_json(req, "{\"ok\":true}");
    free(body);
    return rc;
}

// POST /auth/start - usernameless assertion options.
static esp_err_t handler_auth_start(httpd_req_t* req) {
    if (!frontdoor_admit_request(req)) {
        return ESP_FAIL; // rejection response already sent; drop the connection
    }
    log_request(req);

    char out[1024];
    // The caller's address goes in so the session store can cap how many in-flight
    // ceremonies one source IP holds (kMaxSessionsPerIP): this route is public, and each
    // call claims a slot for kSessionTtlMs.
    int n = webauthn_auth_start(out, sizeof(out), req_client_ip(req));
    if (n < 0) {
        return send_json_status(req, "429 Too Many Requests", "{\"error\":\"busy\"}");
    }
    return send_json(req, out);
}

// POST /auth/finish - verifies assertion, records source IP as authorized.
static esp_err_t handler_auth_finish(httpd_req_t* req) {
    if (!frontdoor_admit_request(req)) {
        return ESP_FAIL; // rejection response already sent; drop the connection
    }
    log_request(req);

    uint32_t ip = req_client_ip(req);

    char* body = (char*)malloc(kMaxBodySize + 1);
    if (!body) return send_json_status(req, "500 Internal Server Error", "{\"error\":\"oom\"}");

    int bl = read_body(req, body, kMaxBodySize + 1);
    if (bl < 0) {
        free(body);
        return send_json_status(req, "413 Payload Too Large", "{\"error\":\"payload\"}");
    }

    if (!webauthn_auth_finish(body, (size_t)bl, ip)) {
        frontdoor_record_failure(ip);
        free(body);
        return send_json_status(req, "401 Unauthorized", "{\"error\":\"authentication_failed\"}");
    }

    // A successful authentication resets this IP's failure streak.
    frontdoor_clear_failures(ip);

    esp_err_t rc = send_json(req, "{\"ok\":true}");
    free(body);
    return rc;
}

// POST /auth/cancel - the page reports that the user cancelled/aborted the WebAuthn
// prompt. Counts a failure toward kFailuresBeforeBlock; admin IPs are never blocked.
static esp_err_t handler_auth_cancel(httpd_req_t* req) {
    if (!frontdoor_admit_request(req)) {
        return ESP_FAIL; // rejection response already sent; drop the connection
    }
    log_request(req);

    frontdoor_record_failure(req_client_ip(req));
    return send_json(req, "{\"ok\":true}");
}

// GET /authorized-ips?key=<secret> - consumer endpoint (plain text, one IP per
// line). Guarded by source-IP allowlist + constant-time static-secret check.
static esp_err_t handler_authorized_ips(httpd_req_t* req) {
    if (!frontdoor_admit_request(req)) {
        return ESP_FAIL; // rejection response already sent; drop the connection
    }
    log_request(req);

    IPAddress ip(req_client_ip(req));
    if (!ip_in_list((uint32_t)ip, kConsumerAllowlist, kConsumerAllowlistCount)) {
        Serial.printf("[consumer] GET /authorized-ips refused: %s is not in kConsumerAllowlist (Config.h)\n",
                      ip.toString().c_str());
        return send_json_status(req, "403 Forbidden", "{\"error\":\"not_consumer_ip\"}");
    }

    char query[128];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK) {
        // Name the shape the caller has to send: this is a misconfigured consumer, and
        // "key_required" alone does not say whether the key was missing or malformed.
        Serial.printf("[consumer] GET /authorized-ips refused: no query string (expected ?key=<secret>) from %s\n",
                      ip.toString().c_str());
        return send_json_status(req, "403 Forbidden", "{\"error\":\"key_required\"}");
    }
    char key[128];
    if (httpd_query_key_value(query, "key", key, sizeof(key)) != ESP_OK) {
        // The query string is caller-supplied: print it sanitized (see
        // print_untrusted_text) so it cannot inject terminal escapes into the console.
        Serial.printf("[consumer] GET /authorized-ips refused: query '");
        safe_print(query, 64);
        Serial.printf("' has no key= parameter from %s\n", ip.toString().c_str());
        return send_json_status(req, "403 Forbidden", "{\"error\":\"key_required\"}");
    }
    if (!crypto_const_eq_str(key, strlen(key), kConsumerSecret, strlen(kConsumerSecret))) {
        // Deliberately vague to the caller: an allowlisted peer with the wrong secret
        // is either misconfigured or guessing.
        //
        // The console gets the SUPPLIED value in full - sanitized, and never compared or
        // shown against the real secret - because a rejected key is the one thing that
        // cannot be debugged from the client side, and the common causes are typos: a
        // trailing space, the wrong case, a stale copy of the secret. This is the single
        // deliberate exception to the masking in print_uri_masked(), and it only applies
        // to requests that FAILED: a successful poll shows '***'.
        Serial.print("[consumer] GET /authorized-ips refused: bad ?key= value '");
        safe_print(key, 64);
        Serial.printf("' (%u bytes, supplied) from %s\n",
                      (unsigned)strlen(key), ip.toString().c_str());
        return send_json_status(req, "403 Forbidden", "{\"error\":\"bad_key\"}");
    }

    // Buffers sized from kMaxAuthorizedIPs go on the HEAP, not on the httpd task's
    // 10 KB stack: at 256 entries that would be 1 KB (addresses) + 4 KB (the body), and
    // exhausting the stack here is a panic rather than a failed request.
    const size_t bufCap = (size_t)kMaxAuthorizedIPs * 16 + 1;
    uint32_t* ips = (uint32_t*)malloc((size_t)kMaxAuthorizedIPs * sizeof(uint32_t));
    char* buf = (char*)malloc(bufCap);
    if (!ips || !buf) {
        free(ips);
        free(buf);
        return send_json_status(req, "500 Internal Server Error", "{\"error\":\"oom\"}");
    }

    size_t n = authzips_collect(ips, kMaxAuthorizedIPs);
    size_t off = 0;
    for (size_t i = 0; i < n; ++i) {
        IPAddress a(ips[i]);
        // Copy into a local buffer: a.toString().c_str() dangles once its temporary String ends.
        char ipText[16]; // an IPv4 literal is at most "255.255.255.255" + NUL
        a.toString().toCharArray(ipText, sizeof(ipText));
        const size_t l = strlen(ipText);
        if (off + l + 2 > bufCap) break;
        memcpy(buf + off, ipText, l);
        off += l;
        buf[off++] = '\n';
    }
    buf[off] = 0;

    // Say what was produced, not just that a request arrived: the body is a bare list, so
    // "served 0 IP(s)" is otherwise indistinguishable from a mangled response.
    if (kLogHttpRequests) {
        Serial.printf("[consumer] GET /authorized-ips: served %u IP(s), %u bytes\n",
                      (unsigned)n, (unsigned)off);
    }

    httpd_resp_set_type(req, "text/plain");
    httpd_resp_sendstr(req, buf);
    free(buf);
    free(ips);
    return ESP_OK;
}

////////---------------------------------------        Admin revocation handlers        ---------------------------------------////////

// GET /admin/credentials - list registered credentials (admin IP only).
//
// STREAMED (chunked) rather than assembled into one buffer. The old shape copied every
// record out of NVS into a kMaxCredentials-sized array and rendered that into a fixed 4 KB
// JSON buffer whose overflow check silently truncated the array - and a truncated array has
// no closing bracket, so the admin page could only show "Error:" with no hint of why.
// Streaming removes both limits: one credential at a time, ~700 B of stack, no heap.
struct CredStream {
    httpd_req_t* req;
    bool first;
    bool failed;
};

static bool stream_credential(const StoredCredential* c, const CredRuntime* rt, void* raw) {
    CredStream* st = (CredStream*)raw;

    char idB64[MAX_CRED_ID_LEN * 2 + 4];
    size_t il = b64url_encode(c->credId, c->credIdLen, idB64, sizeof(idB64));

    // Sized from the same constants as the record; the fit is re-checked below so a larger
    // field fails the stream rather than truncating. No JSON escaping needed (id is base64url,
    // email was whitelisted before storage).
    char item[MAX_CRED_ID_LEN * 2 + 4 + MAX_EMAIL_LEN + 64];

    // usedThisBoot is omitted entirely when the store cannot tell (-1), rather than reported
    // as false: "unknown" and "not used since boot" are different answers, and the page
    // draws nothing for the first. lastSeenUnix has its own sentinel (0 = the device had no
    // clock at the time), and disabled is always known.
    char usedFlag[32];
    usedFlag[0] = 0;
    if (rt->usedThisBoot >= 0) {
        snprintf(usedFlag, sizeof(usedFlag), ",\"usedThisBoot\":%s", rt->usedThisBoot ? "true" : "false");
    }

    int n = snprintf(item, sizeof(item),
                     "%s{\"id\":\"%.*s\",\"email\":\"%s\",\"lastUsedMs\":%lu%s,"
                     "\"disabled\":%s,\"lastSeenUnix\":%lu}",
                     st->first ? "" : ",", (int)il, idB64, c->email,
                     (unsigned long)c->lastUsedAtMs, usedFlag,
                     rt->disabled ? "true" : "false", (unsigned long)rt->lastSeenUnix);
    if (n <= 0 || (size_t)n >= sizeof(item)) { st->failed = true; return false; }
    st->first = false;

    if (httpd_resp_send_chunk(st->req, item, (ssize_t)n) != ESP_OK) {
        st->failed = true;
        return false; // client went away: stop walking the store
    }
    return true;
}

static esp_err_t handler_admin_credentials(httpd_req_t* req) {
    if (!frontdoor_admit_request(req)) {
        return ESP_FAIL; // rejection response already sent; drop the connection
    }
    log_request(req);

    if (!ip_in_list(req_client_ip(req), kAdminIPs, kAdminIPCount)) {
        return admin_denied(req, "GET /admin/credentials");
    }

    httpd_resp_set_type(req, "application/json");
    if (httpd_resp_send_chunk(req, "[", 1) != ESP_OK) return ESP_FAIL;

    CredStream st = { req, true, false };
    size_t n = cred_foreach(stream_credential, &st);

    if (!st.failed && httpd_resp_send_chunk(req, "]", 1) != ESP_OK) st.failed = true;

    // Terminate the chunked body even after a send error: an unterminated chunked response
    // leaves the client waiting on a connection that is already dead.
    httpd_resp_send_chunk(req, nullptr, 0);

    if (kLogHttpRequests) {
        Serial.printf("[admin] GET /admin/credentials: %u credential(s)%s\n",
                      (unsigned)n, st.failed ? " (incomplete: send failed)" : "");
    }
    return st.failed ? ESP_FAIL : ESP_OK;
}

// POST /admin/revoke-credential - { "id": "<base64url credentialId>" }
static esp_err_t handler_admin_revoke_credential(httpd_req_t* req) {
    if (!frontdoor_admit_request(req)) {
        return ESP_FAIL; // rejection response already sent; drop the connection
    }
    log_request(req);

    if (!ip_in_list(req_client_ip(req), kAdminIPs, kAdminIPCount)) {
        return admin_denied(req, "POST /admin/revoke-credential");
    }

    char* body = (char*)malloc(kMaxBodySize + 1);
    if (!body) return send_json_status(req, "500 Internal Server Error", "{\"error\":\"oom\"}");

    int bl = read_body(req, body, kMaxBodySize + 1);
    if (bl < 0) { free(body); return send_json_status(req, "413 Payload Too Large", "{\"error\":\"payload\"}"); }

    char idB64[MAX_CRED_ID_LEN * 2 + 4];
    int il = extract_field(body, (size_t)bl, "id", idB64, sizeof(idB64));
    if (il <= 0) { free(body); return send_json_status(req, "400 Bad Request", "{\"error\":\"id_required\"}"); }

    uint8_t credId[MAX_CRED_ID_LEN];
    int idLen = b64url_decode(idB64, il, credId, sizeof(credId));
    bool ok = (idLen > 0) && cred_delete(credId, (size_t)idLen);

    free(body);
    return send_json(req, ok ? "{\"ok\":true}" : "{\"ok\":false}");
}

// POST /admin/set-credential-disabled - { "id": "<base64url>", "disabled": true|false }
//
// The REVERSIBLE counterpart of /admin/revoke-credential: the credential keeps its record
// (identity, signature counter, last-used date) and simply fails authentication until it is
// enabled again. Disabling writes only the 12-byte state entry, never the credential.
static esp_err_t handler_admin_set_credential_disabled(httpd_req_t* req) {
    if (!frontdoor_admit_request(req)) {
        return ESP_FAIL; // rejection response already sent; drop the connection
    }
    log_request(req);

    const uint32_t peer = req_client_ip(req);
    if (!ip_in_list(peer, kAdminIPs, kAdminIPCount)) {
        return admin_denied(req, "POST /admin/set-credential-disabled");
    }

    char* body = (char*)malloc(kMaxBodySize + 1);
    if (!body) return send_json_status(req, "500 Internal Server Error", "{\"error\":\"oom\"}");

    int bl = read_body(req, body, kMaxBodySize + 1);
    if (bl < 0) { free(body); return send_json_status(req, "413 Payload Too Large", "{\"error\":\"payload\"}"); }

    char idB64[MAX_CRED_ID_LEN * 2 + 4];
    int il = extract_field(body, (size_t)bl, "id", idB64, sizeof(idB64));
    bool disabled = false;
    if (il <= 0 || !extract_bool(body, (size_t)bl, "disabled", &disabled)) {
        free(body);
        return send_json_status(req, "400 Bad Request", "{\"error\":\"id_and_disabled_required\"}");
    }

    uint8_t credId[MAX_CRED_ID_LEN];
    int idLen = b64url_decode(idB64, il, credId, sizeof(credId));
    bool ok = (idLen > 0) && cred_set_disabled(credId, (size_t)idLen, disabled);
    free(body);

    IPAddress from(peer);
    const String fromStr = from.toString();
    if (ok) {
        Serial.printf("[admin] %s a credential from %s\n",
                      disabled ? "DISABLED" : "re-enabled", fromStr.c_str());
    } else {
        Serial.printf("[admin] set-credential-disabled from %s: no credential matched that id\n",
                      fromStr.c_str());
    }
    return send_json(req, ok ? "{\"ok\":true}" : "{\"ok\":false}");
}

// POST /admin/time is deliberately absent: the device takes its time from NTP (Config.h
// ntpSvr, Clock.h), not from whoever opens the console. A browser-supplied time would be
// exactly as trustworthy as the machine that sent it, and the whole point of the last-used
// column is that an operator can act on it - so the one source is the one that is synced.

// GET /admin/authorized-ips - the currently-valid authorized IPs AND who is behind each one.
//
// Streamed (chunked): the response grows with (addresses x users), so one address and one
// email are sent at a time instead of assembling a fixed buffer that could truncate.
//
// Response: [{"ip":"192.168.1.5","users":["a@b.c"]}, ...]. `users` is empty for an address that
// nobody is attributed to (authorized before this was recorded, or its key was revoked since).
static esp_err_t handler_admin_authorized_ips(httpd_req_t* req) {
    if (!frontdoor_admit_request(req)) {
        return ESP_FAIL; // rejection response already sent; drop the connection
    }
    log_request(req);

    if (!ip_in_list(req_client_ip(req), kAdminIPs, kAdminIPCount)) {
        return admin_denied(req, "GET /admin/authorized-ips");
    }

    // The address list is a fixed size (the store's), so it goes on the heap rather than the
    // httpd task's 10 KB stack, exactly as before. Everything else is streamed.
    uint32_t* ips = (uint32_t*)malloc((size_t)kMaxAuthorizedIPs * sizeof(uint32_t));
    if (!ips) {
        return send_json_status(req, "500 Internal Server Error", "{\"error\":\"oom\"}");
    }
    const size_t n = authzips_collect(ips, kMaxAuthorizedIPs);

    httpd_resp_set_type(req, "application/json");
    bool failed = httpd_resp_send_chunk(req, "[", 1) != ESP_OK;
    size_t userCount = 0;

    for (size_t i = 0; !failed && i < n; ++i) {
        char addr[16]; // an IPv4 literal is at most "255.255.255.255" + NUL
        IPAddress(ips[i]).toString().toCharArray(addr, sizeof(addr));

        char head[64];
        const int hl = snprintf(head, sizeof(head), "%s{\"ip\":\"%s\",\"users\":[",
                                i ? "," : "", addr);
        if (hl <= 0 || (size_t)hl >= sizeof(head) ||
            httpd_resp_send_chunk(req, head, (ssize_t)hl) != ESP_OK) {
            failed = true;
            break;
        }

        // One attributed key at a time. The email needs no JSON escaping: email_is_usable()
        // rejected quotes, backslashes and control characters before it was ever stored - the
        // same guarantee /admin/credentials relies on for the same field.
        uint16_t cursor = 0;
        uint16_t slot = 0;
        bool firstUser = true;
        char email[MAX_EMAIL_LEN];
        char item[MAX_EMAIL_LEN + 8];
        while (authzips_user_next(ips[i], &cursor, &slot)) {
            ++userCount;
            // A slot whose credential vanished between the revoke and this read: skip it rather
            // than emit an empty user. (A revoke clears the row too, so this is a window of
            // microseconds, not a case that can persist.)
            if (!cred_email_at(slot, email, sizeof(email))) continue;
            const int il = snprintf(item, sizeof(item), "%s\"%s\"", firstUser ? "" : ",", email);
            if (il <= 0 || (size_t)il >= sizeof(item) ||
                httpd_resp_send_chunk(req, item, (ssize_t)il) != ESP_OK) {
                failed = true;
                break;
            }
            firstUser = false;
        }
        if (!failed && httpd_resp_send_chunk(req, "]}", 2) != ESP_OK) failed = true;
    }

    if (!failed && httpd_resp_send_chunk(req, "]", 1) != ESP_OK) failed = true;

    // Terminate the chunked body even after a send error: an unterminated chunked response
    // leaves the client waiting on a connection that is already dead.
    httpd_resp_send_chunk(req, nullptr, 0);
    free(ips);

    if (kLogHttpRequests) {
        Serial.printf("[admin] GET /admin/authorized-ips: %u IP(s), %u attributed key(s)%s\n",
                      (unsigned)n, (unsigned)userCount,
                      failed ? " (incomplete: send failed)" : "");
    }
    return failed ? ESP_FAIL : ESP_OK;
}

// POST /admin/revoke-ip - { "ip": "x.x.x.x" }
static esp_err_t handler_admin_revoke_ip(httpd_req_t* req) {
    if (!frontdoor_admit_request(req)) {
        return ESP_FAIL; // rejection response already sent; drop the connection
    }
    log_request(req);

    if (!ip_in_list(req_client_ip(req), kAdminIPs, kAdminIPCount)) {
        return admin_denied(req, "POST /admin/revoke-ip");
    }

    char* body = (char*)malloc(kMaxBodySize + 1);
    if (!body) return send_json_status(req, "500 Internal Server Error", "{\"error\":\"oom\"}");

    int bl = read_body(req, body, kMaxBodySize + 1);
    if (bl < 0) { free(body); return send_json_status(req, "413 Payload Too Large", "{\"error\":\"payload\"}"); }

    char ipStr[64];
    int sl = extract_field(body, (size_t)bl, "ip", ipStr, sizeof(ipStr));
    if (sl <= 0) { free(body); return send_json_status(req, "400 Bad Request", "{\"error\":\"ip_required\"}"); }

    IPAddress addr;
    bool ok = addr.fromString(ipStr) && authzips_remove((uint32_t)addr);

    free(body);
    return send_json(req, ok ? "{\"ok\":true}" : "{\"ok\":false}");
}

////////---------------------------------------        URI registration        ---------------------------------------////////

static const httpd_uri_t uri_root = {
    .uri = "/", .method = HTTP_GET, .handler = handler_root, .user_ctx = nullptr
};
static const httpd_uri_t uri_whoami = {
    .uri = "/whoami", .method = HTTP_GET, .handler = handler_whoami, .user_ctx = nullptr
};
static const httpd_uri_t uri_favicon = {
    .uri = "/favicon.ico", .method = HTTP_GET, .handler = handler_favicon, .user_ctx = nullptr
};
static const httpd_uri_t uri_admin_page = {
    .uri = "/admin", .method = HTTP_GET, .handler = handler_admin_page, .user_ctx = nullptr
};

static const httpd_uri_t uri_register_start = {
    .uri = "/register/start", .method = HTTP_POST, .handler = handler_register_start, .user_ctx = nullptr
};
static const httpd_uri_t uri_register_finish = {
    .uri = "/register/finish", .method = HTTP_POST, .handler = handler_register_finish, .user_ctx = nullptr
};
static const httpd_uri_t uri_auth_start = {
    .uri = "/auth/start", .method = HTTP_POST, .handler = handler_auth_start, .user_ctx = nullptr
};
static const httpd_uri_t uri_auth_finish = {
    .uri = "/auth/finish", .method = HTTP_POST, .handler = handler_auth_finish, .user_ctx = nullptr
};
static const httpd_uri_t uri_auth_cancel = {
    .uri = "/auth/cancel", .method = HTTP_POST, .handler = handler_auth_cancel, .user_ctx = nullptr
};
static const httpd_uri_t uri_authorized_ips = {
    .uri = "/authorized-ips", .method = HTTP_GET, .handler = handler_authorized_ips, .user_ctx = nullptr
};
static const httpd_uri_t uri_admin_credentials = {
    .uri = "/admin/credentials", .method = HTTP_GET, .handler = handler_admin_credentials, .user_ctx = nullptr
};
static const httpd_uri_t uri_admin_revoke_credential = {
    .uri = "/admin/revoke-credential", .method = HTTP_POST, .handler = handler_admin_revoke_credential, .user_ctx = nullptr
};
static const httpd_uri_t uri_admin_authorized_ips = {
    .uri = "/admin/authorized-ips", .method = HTTP_GET, .handler = handler_admin_authorized_ips, .user_ctx = nullptr
};
static const httpd_uri_t uri_admin_revoke_ip = {
    .uri = "/admin/revoke-ip", .method = HTTP_POST, .handler = handler_admin_revoke_ip, .user_ctx = nullptr
};
static const httpd_uri_t uri_admin_set_credential_disabled = {
    .uri = "/admin/set-credential-disabled", .method = HTTP_POST, .handler = handler_admin_set_credential_disabled, .user_ctx = nullptr
};

// Register one route and SAY SO if it fails. httpd_register_uri_handler() returns an error
// when the handler table is full (cfg.httpd.max_uri_handlers), and a route that silently
// does not exist is invisible until a client gets a 404 - which is a bad way to discover
// that one line of the table below was added without growing the limit.
static void register_one(httpd_handle_t server, const httpd_uri_t* uri) {
    const esp_err_t err = httpd_register_uri_handler(server, uri);
    if (err != ESP_OK) {
        Serial.printf("[httpd] FATAL: could not register %s (%s). The route does not exist; "
                      "raise cfg.httpd.max_uri_handlers (currently 16) and rebuild.\n",
                      uri->uri, esp_err_to_name(err));
    }
}

static void register_handlers(httpd_handle_t server) {
    register_one(server, &uri_root);
    register_one(server, &uri_whoami);
    register_one(server, &uri_favicon);
    register_one(server, &uri_admin_page);
    register_one(server, &uri_register_start);
    register_one(server, &uri_register_finish);
    register_one(server, &uri_auth_start);
    register_one(server, &uri_auth_finish);
    register_one(server, &uri_auth_cancel);
    register_one(server, &uri_authorized_ips);
    register_one(server, &uri_admin_credentials);
    register_one(server, &uri_admin_revoke_credential);
    register_one(server, &uri_admin_authorized_ips);
    register_one(server, &uri_admin_revoke_ip);
    register_one(server, &uri_admin_set_credential_disabled);
}

////////---------------------------------------        setup / loop        ---------------------------------------////////

// One compact line per TLS blob. The SHA-1 fingerprint is what you compare against the
// browser's trust store; the private key is never echoed.
static void print_tls_material(const char* certPem, size_t certLen, size_t keyLen) {
    char fp[64];
    if (certstore_cert_fingerprint(certPem, certLen, fp, sizeof(fp))) {
        Serial.printf("  cert %u Bytes, SHA-1 %s\n", (unsigned)certLen, fp);
    } else {
        Serial.printf("  cert %u Bytes, UNPARSEABLE - httpd_ssl will refuse to start\n",
                      (unsigned)certLen);
    }
    Serial.printf("  key  %u Bytes\n", (unsigned)keyLen);
}

// The only TLS source is the NVS store (filled by the console's `import`). False when either
// half is missing; the caller halts into the console.
static bool resolve_tls(const uint8_t** cert, size_t* certLen,
                        const uint8_t** key, size_t* keyLen) {
    size_t cl = 0, kl = 0;
    const char* c = certstore_cert(&cl);
    const char* k = certstore_key(&kl);
    if (!c || !k) {
        return false;
    }
    *cert = (const uint8_t*)c; *certLen = cl;
    *key  = (const uint8_t*)k; *keyLen  = kl;
    Serial.println("Using TLS material imported via serial console (NVS).");
    print_tls_material(c, cl, kl);
    ESP_LOGI(TAG, "Using TLS material imported via serial console (NVS).");
    return true;
}

// Socket-table telemetry (declared in SerialConsole.h): free socket slots vs open sessions.
void server_socket_report() {
    int held[32];
    int freeSlots = 0;
    for (; freeSlots < (int)(sizeof(held) / sizeof(held[0])); ++freeSlots) {
        const int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            break;
        }
        held[freeSlots] = fd;
    }
    for (int i = 0; i < freeSlots; ++i) {
        close(held[i]);
    }
    Serial.printf("Socket slots:   %d free (0 = accept fails with ENFILE)\n", freeSlots);

    // What httpd itself holds. -1 = unknown (no handle, or the call failed).
    int sessions = -1;
    if (s_httpsServer != nullptr) {
        int fds[8];
        size_t nfds = sizeof(fds) / sizeof(fds[0]);
        if (httpd_get_client_list(s_httpsServer, &nfds, fds) == ESP_OK) {
            sessions = (int)nfds;
            Serial.printf("HTTP sessions:  %d open (cap %u)\n", sessions,
                          (unsigned)s_maxOpenSockets);
        } else {
            Serial.println("HTTP sessions:  unavailable (httpd_get_client_list failed)");
        }
    } else {
        Serial.println("HTTP sessions:  no server handle");
    }

    uint32_t charged = 0;
    eth_gate_stats(nullptr, &charged, nullptr);
    const uint32_t opened = frontdoor_connections_opened();
    const uint32_t closed = frontdoor_connections_closed();
    const uint32_t inFlight = opened - closed;   // unsigned: opened >= closed always
    Serial.printf("Connections:    %u SYNs charged at L2, %u accepted, %u closed (%u in flight)\n",
                  (unsigned)charged, (unsigned)opened, (unsigned)closed, (unsigned)inFlight);
    if (charged > opened) {
        Serial.printf("                %u SYN(s) never became a session (accept/TLS failure)\n",
                      (unsigned)(charged - opened));
    }

    // Warn when more connections are in flight than httpd holds and no socket slot is free
    // (a transient +1 is normal right after a connection is accepted).
    if (freeSlots == 0 && sessions >= 0 && inFlight > (uint32_t)sessions) {
        Serial.printf("                <-- %u in flight but not held by httpd, with no slot free:"
                      " socket leak (frontdoor_on_close must close its fd)\n",
                      (unsigned)(inFlight - (uint32_t)sessions));
    }
}

// Halt but keep the serial console alive so the user can import TLS material
// and reboot. Without this, a device with no cert could never be provisioned.
static void halt_with_console(const char* msg) {
    Serial.println();
    Serial.printf("*** %s ***\n", msg);
    Serial.println("Serial console is active: use 'import' to load the certificate + key.");
    ESP_LOGE(TAG, "%s", msg);
    while (1) {
        serial_console_poll();
        delay(10);
    }
}

void setup() {
    // Enlarge the serial RX buffer so a pasted PEM (cert/key) isn't truncated
    // by the default 256-byte ring buffer during a fast USB CDC burst.
    Serial.setRxBufferSize(8192);
    Serial.begin(115200);
    while (!Serial) {
        delay(100);
    }
    Serial.println("PoE-Passkey: starting...");

    // Report PSRAM before anything else can report a fallback. The verdict comes from
    // the heap (an absent or failed PSRAM has no MALLOC_CAP_SPIRAM total - the same
    // source memory_report() uses), with psramFound() shown alongside it: the blocklist,
    // the page render buffer and the ceremony scratch arena all prefer PSRAM, so this
    // line is the context for any "[gate]/[page]/[webauthn] ... falling back" message
    // that follows.
    const size_t psramTotal = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);
    Serial.printf("PSRAM: %s - %u B total, %u B free (psramFound()=%s)\n",
                  psramTotal ? "usable" : "NOT USABLE",
                  (unsigned)psramTotal,
                  (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
                  psramFound() ? "true" : "false");

    // Fail closed on any configuration error.
    if (!validateConfiguration()) {
        Serial.println("HALTED: fix configuration errors in Config.h, recompile and reflash.");
        while (1) {
            delay(1000);
        }
    }

    // Ethernet bring-up (Unit-PoE-P4).
    ESP_LOGI(TAG, "Initializing Ethernet...");
    ETH.begin(ETH_TYPE, ETH_ADDR, ETH_PHY_MDC, ETH_PHY_MDIO, ETH_POWER_PIN, ETH_CLK_MODE);
    ETH.config(ip, gateway, subnet, dns1, dns2);
    while (!ETH.linkUp()) {
        delay(1000);
        Serial.println("Waiting for Ethernet...");
    }
    Serial.print("Ethernet connected, IP: ");
    Serial.println(ETH.localIP());

    // Wall clock (NTP). Started here because a sync needs DNS (for a hostname) and a route;
    // it never blocks - see Clock.h - so the listener below comes up regardless and the first
    // sync lands a few seconds later. Until then the device dates nothing rather than dating
    // it wrong, and authentication is unaffected: the clock never authorizes anything.
    clock_begin();

    // Pre-payload gate stores (throttle ring + PSRAM blocklist).
    frontdoor_begin();

    // Persistent + ephemeral stores (credentials in NVS, sessions + IPs in RAM).
    store_begin();

    // TLS material (cert + key) from the NVS store, filled by `import` on the console.
    certstore_begin();

    const uint8_t* certPem;
    size_t certLen;
    const uint8_t* keyPem;
    size_t keyLen;
    if (!resolve_tls(&certPem, &certLen, &keyPem, &keyLen)) {
        // Name which half is missing: the two situations have different causes (a wrong or
        // half-finished `import`), and the console is where it gets fixed.
        const bool haveCert = certstore_has_cert();
        const bool haveKey  = certstore_has_key();
        const char* msg;
        if (!haveCert && !haveKey) msg = "No TLS certificate or private key imported.";
        else if (!haveCert)       msg = "TLS certificate missing (private key present).";
        else                      msg = "TLS private key missing (certificate present).";
        halt_with_console(msg);
    }

    // TLS server with the gate wired into open_fn.
    Serial.println("Starting HTTPS server on port 443...");
    ESP_LOGI(TAG, "Starting HTTPS server on port 443...");
    httpd_ssl_config_t cfg = HTTPD_SSL_CONFIG_DEFAULT();
    cfg.httpd.max_uri_handlers = 16;
    // 6 = Chrome's per-origin socket pool, so a page load's connections all get a
    // session slot instead of being closed by lru_purge and retried. Each open
    // session costs heap: watch it with log_memory_report().
    //
    // NOT a fix for handshake errors: in a log full of
    // "mbedtls_ssl_handshake returned", -0x7780 is
    // MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE ("a fatal alert message was received
    // from our peer") - the CLIENT aborting the handshake over the certificate -
    // and -0x7280 is a bare connection EOF, what a browser does to a pre-connect
    // socket it decided not to use. Both are the client's verdict on the
    // certificate (see README, "Trusting the certificate in the browser"), not
    // socket-pool exhaustion on this side.
    cfg.httpd.max_open_sockets = 6;
    s_maxOpenSockets = cfg.httpd.max_open_sockets;
    // LRU purge: when all max_open_sockets slots are in use, accept the new connection anyway
    // and close the least recently used one (httpd_accept_conn -> httpd_sess_close_lru). Keep it
    // ON: the appliance has 6 slots, and without it httpd_servers' `if (lru_purge_enable ||
    // httpd_is_sess_available(hd))` removes the LISTENING socket from the select set entirely
    // while the slots are full, so abandoned sessions (a crashed tab, a machine that moved to
    // Wi-Fi) lock everyone out until TCP keep-alive reaps them (~14 s here).
    //
    // WHAT IT IS NOT: the eviction trigger is httpd's OWN session count (`httpd_is_sess_available`,
    // i.e. max_open_sockets) - NOT the lwIP socket table. It cannot help when the socket table is
    // exhausted (that was "Socket slots: 0 free, HTTP sessions: 2 open": free session slots, none
    // free to accept into), and it is not an anti-flood control: a purge gives the slot straight to
    // whoever connects next. The L2 gate + blocklist are the flood control; this is availability.
    // The eviction is also asynchronous (queued over the ctrl socket, best-effort with a retry),
    // and it can evict a session whose request arrived but was not read yet (the LRU filter skips
    // only for_async_req sessions, not pending data).
    cfg.httpd.lru_purge_enable = true;
    cfg.httpd.backlog_conn = 8;
    // Per-socket SO_RCVTIMEO/SO_SNDTIMEO, applied by httpd_accept_conn to every accepted
    // connection BEFORE the open_fn that completes the TLS handshake - so they cover the
    // handshake, the request read and the response write, and bound how long a peer making NO
    // progress can hold the ONE httpd task (the same single-task exposure as the accept-loop note
    // in FrontDoor.cpp).
    //
    // A STALL TIMER, NOT A TRANSFER DEADLINE - which is why the size of /admin cannot trip it:
    // each send()/recv() waits at most this long for PROGRESS, and lwIP re-waits per refill
    // (netconn_write_partly -> sys_arch_sem_wait), so a slow but steady client is never cut off
    // however large the body is. The bodies fit regardless: the largest single send here is
    // /authorized-ips at ~4 KB (kMaxAuthorizedIPs * 16 + 1); both admin listings STREAM instead
    // (one credential per chunk, one address + one email per chunk),
    // and this build's socket send buffer is 64 KB (CONFIG_LWIP_TCP_SND_BUF_DEFAULT = 65534).
    // 2 s is >10x the TLS handshake time, so it never trips on a slow-but-normal handshake.
    //
    // WHAT HAPPENS WHEN IT FIRES: lwip_send() returns -1 rather than a partial count, so
    // httpd_send_all aborts the response and the session is deleted - a truncated page the client
    // reloads, which is the right outcome for a peer that has stopped reading.
    //
    // Idle keep-alive sessions are NOT affected (an idle socket is never selected, so no read ever
    // waits on it); they are reaped by TCP keep-alive below.
    cfg.httpd.recv_wait_timeout = 2;
    cfg.httpd.send_wait_timeout = 2;
    // The TLS handshake runs on this task (httpd's accept loop), so it needs
    // esp_https_server's default of 10240, not a plain-HTTP size.
    cfg.httpd.stack_size = 10240;
    // Keep-alive: one TLS session serves a whole page load. Without it every
    // response closes the connection, so every resource costs a fresh handshake
    // and the browser abandons its surplus sockets mid-handshake.
    cfg.httpd.keep_alive_enable = true;
    // TCP keep-alive (TCP_KEEPIDLE/INTVL/CNT). A DEAD-PEER probe, NOT an HTTP idle timeout: it
    // is the only thing that reaps a peer that vanished silently (pulled cable, slept laptop,
    // dropped Wi-Fi), because an idle session is never selected and so never reaches the
    // SO_RCVTIMEO above. 5 + 3x3 = ~14 s until the probes give up, against 2 h+ for the OS
    // defaults. A LIVE idle peer answers them: a browser's keep-alive connection is not closed
    // by this, it stays open (holding its ~32 KB of TLS buffers) until the browser closes it or
    // LRU purge makes room for the next connection.
    cfg.httpd.keep_alive_idle = 5;       // seconds of no traffic before the first probe
    cfg.httpd.keep_alive_interval = 3;   // seconds between probes
    cfg.httpd.keep_alive_count = 3;      // unanswered probes before lwIP aborts the connection
    cfg.httpd.open_fn = frontdoor_on_open;   // pre-payload throttle + blocklist gate
    // close_fn REPLACES httpd's socket close, so frontdoor_on_close() must close the socket.
    cfg.httpd.close_fn = frontdoor_on_close;
    cfg.transport_mode = HTTPD_SSL_TRANSPORT_SECURE;
    cfg.port_secure = 443;
    // NOTE: PEM lengths MUST include the terminating NUL byte ("+ 1").
    // mbedTLS 3.x (esp-tls uses 3.6.6 here) picks PEM-vs-DER by testing
    // buf[buflen - 1] == '\0' (see mbedtls_x509_crt_parse and
    // mbedtls_pk_parse_key). esp-tls forwards this length unchanged, and
    // esp_https_server memcpy's exactly this many bytes - so a PEM whose
    // length excludes the NUL is handed to the DER parser, which rejects the
    // ASCII text with MBEDTLS_ERR_X509_INVALID_FORMAT (-0x2180) and makes
    // httpd_ssl fail ("Failed to set server pki context"). The NVS store
    // (certstore_*) is the only source and it keeps the material NUL-terminated
    // (both the imported blob and the RAM copy), so counting that byte is safe.
    cfg.prvtkey_pem = keyPem;
    cfg.prvtkey_len = keyLen + 1;
    cfg.servercert = certPem;
    cfg.servercert_len = certLen + 1;

    // Allocate the GET / render buffer (PSRAM) before the baseline report, so the
    // report below already accounts for it.
    if (!page_buffer_begin()) {
        Serial.println("No memory for the page buffer; GET / will serve the raw template.");
    }

    // Baseline before the TLS context (certificate parsing + listeners) exists.
    memory_report("before TLS server start");

    if (httpd_ssl_start(&s_httpsServer, &cfg) != ESP_OK) {
        halt_with_console("Failed to start HTTPS server (invalid TLS material?).");
    }

    register_handlers(s_httpsServer);

    // L2 gate (optional, Config.h): install the Ethernet-driver RX filter LAST, so
    // the gate stores and the listener are already up before a frame can be dropped.
    if (kEthL2GateEnable) {
        if (eth_gate_begin(ETH.handle(), ETH.netif(), (uint16_t)cfg.port_secure)) {
            Serial.println("L2 gate: active - blocked / over-budget SYNs are dropped in the Ethernet RX path.");
        } else {
            Serial.println("L2 gate: NOT active - the request-level gate is still enforced.");
        }
    }

    memory_report("after TLS server start");

    Serial.printf("PoE-Passkey ready: https://%s\n", kRpId);
    ESP_LOGI(TAG, "PoE-Passkey ready: https://%s", kRpId);
}

void loop() {
    // Prune expired AUTHORIZED_IPS entries (TTL-governed).
    authzips_prune(millis());

    // Serial console (cert/key import, status, clear, reboot).
    serial_console_poll();

    delay(100);
}

