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

#include "Log.h"
#include "Acl.h"
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

// JSON-encode `src` into `dst` (cap bytes, incl. NUL). Escapes `"`, `\` and control
// bytes (as \u00XX); returns the encoded length (excl. NUL), or 0 on overflow. Log
// lines carry caller-influenced text, so unlike the credential listing this must
// escape rather than assume the field is already JSON-safe.
static size_t json_escape(const char* src, char* dst, size_t cap) {
    static const char kHex[] = "0123456789abcdef";
    size_t o = 0;
    for (const char* p = src; *p; ++p) {
        const unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') {
            if (o + 2 >= cap) return 0;
            dst[o++] = '\\';
            dst[o++] = (char)c;
        } else if (c < 0x20) {
            if (o + 6 >= cap) return 0;
            dst[o++] = '\\'; dst[o++] = 'u'; dst[o++] = '0'; dst[o++] = '0';
            dst[o++] = kHex[(c >> 4) & 0xF];
            dst[o++] = kHex[c & 0xF];
        } else {
            if (o + 1 >= cap) return 0;
            dst[o++] = (char)c;
        }
    }
    if (o >= cap) return 0;
    dst[o] = 0;
    return o;
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
    Log.print('?');

    const char* p = q + 1;
    bool first = true;
    while (*p) {
        const char* amp = strchr(p, '&');
        const char* end = amp ? amp : p + strlen(p);
        if (!first) {
            Log.print('&');
        }
        first = false;

        const char* eq = (const char*)memchr(p, '=', (size_t)(end - p));
        if (!eq) {
            safe_print_range(p, (size_t)(end - p), 64);          // a valueless flag
        } else if (param_name_is_key(p, (size_t)(eq - p))) {
            safe_print_range(p, (size_t)(eq - p), 64);
            Log.print("=***");                                // the secret's value
        } else {
            safe_print_range(p, (size_t)(eq - p), 64);
            Log.print('=');
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
    Log.printf("[req] %s ", method_name((httpd_method_t)req->method));
    print_uri_masked(req->uri);
    Log.printf(" from %s\n", ip.toString().c_str());
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
        Log.printf("[page] PSRAM unavailable for the %u B render buffer; using internal RAM\n",
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

// 16 random bytes (128 bits)
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
        Log.printf("[page] CSP does not fit its %u B buffer: check POE_CSP_FORMAT\n",
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
    Log.printf("[admin] %s refused: %s is not in kAdminIPs (Config.h)\n", what, ipStr.c_str());

    if (kBlockNonAdminIPOnAdminRoute) {
        if (peer == 0) {
            Log.println("[admin] not blocking the peer: it has no usable IPv4 address");
        } else if (acl_is_admin(peer) ||
                   acl_is_consumer(peer)) {
            // Guard: never block a host in either allowlist.
            Log.printf("[admin] not blocking %s: it is in a configured allowlist\n", ipStr.c_str());
        } else {
            frontdoor_block_ip_reason(peer, "admin route request from a non-admin source IP");
            Log.printf("[admin] recover that host with the serial console: 'unblock %s' or 'clear-blocks'\n",
                          ipStr.c_str());
        }
    }

    // 404, not 403: from a non-admin IP this is indistinguishable from a route that
    // does not exist, so the caller learns nothing about which routes the device has.
    return send_json_status(req, "404 Not Found", "{\"error\":\"not_found\"}");
}

// A request for a URI no route handles: treat as a scanner probe and block the peer
// (when kBlockScanners), then answer 404. Mirrors admin_denied()'s allowlist guard.
static esp_err_t handler_not_found(httpd_req_t* req, httpd_err_code_t error) {
    (void)error;
    const uint32_t peer = req_client_ip(req);
    if (kBlockScanners && peer != 0 &&
        !acl_is_admin(peer) &&
        !acl_is_consumer(peer)) {
        frontdoor_block_ip_reason(peer, "scanner probe: non-existent route");
    }
    return send_json_status(req, "404 Not Found", "{\"error\":\"not_found\"}");
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
    if (!acl_is_admin(peer)) {
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

// Extract a JSON boolean field ("key":true / false, also accepting 1 / 0). Fails closed
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
// only gate, and the identity becomes the entered email address
static esp_err_t handler_register_start(httpd_req_t* req) {
    if (!frontdoor_admit_request(req)) {
        return ESP_FAIL; // rejection response already sent; drop the connection
    }
    log_request(req);

    if (!acl_is_admin(req_client_ip(req))) {
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
        Log.printf("[admin] POST /register/start refused: the email is longer than %u bytes\n",
                      (unsigned)sizeof(email) - 1);
        return send_json_status(req, "400 Bad Request", "{\"error\":\"invalid_email\"}");
    }

    int n = webauthn_register_start(email, out, sizeof(out), req_client_ip(req));
    if (n == -2) {
        // Unusable address (email_is_usable() in WebAuthn.cpp).
        free(body);
        // The address is caller-supplied AND reached this line by failing validation, so it
        // may contain anything: print it sanitized
        Log.printf("[admin] POST /register/start refused: '");
        safe_print(email, 64);
        Log.printf("' is not a usable email address\n");
        return send_json_status(req, "400 Bad Request", "{\"error\":\"invalid_email\"}");
    }
    if (n == -3) {
        free(body);
        Log.println("[admin] POST /register/start: the session store is full (kMaxSessions)");
        return send_json_status(req, "429 Too Many Requests", "{\"error\":\"busy\"}");
    }
    if (n < 0) {
        free(body);
        Log.printf("[admin] POST /register/start: could not build the options (error %d)\n", n);
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

    if (!acl_is_admin(req_client_ip(req))) {
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
    if (!acl_is_consumer((uint32_t)ip)) {
        Log.printf("[consumer] GET /authorized-ips refused: %s is not in kConsumerAllowlist (Config.h)\n",
                      ip.toString().c_str());
        return send_json_status(req, "403 Forbidden", "{\"error\":\"not_consumer_ip\"}");
    }

    char query[128];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK) {
        // Name the shape the caller has to send: this is a misconfigured consumer, and
        // "key_required" alone does not say whether the key was missing or malformed.
        Log.printf("[consumer] GET /authorized-ips refused: no query string (expected ?key=<secret>) from %s\n",
                      ip.toString().c_str());
        return send_json_status(req, "403 Forbidden", "{\"error\":\"key_required\"}");
    }
    char key[128];
    if (httpd_query_key_value(query, "key", key, sizeof(key)) != ESP_OK) {
        // The query string is caller-supplied: print it sanitized (see
        // print_untrusted_text) so it cannot inject terminal escapes into the console.
        Log.printf("[consumer] GET /authorized-ips refused: query '");
        safe_print(query, 64);
        Log.printf("' has no key= parameter from %s\n", ip.toString().c_str());
        return send_json_status(req, "403 Forbidden", "{\"error\":\"key_required\"}");
    }
    if (!crypto_const_eq_str(key, strlen(key), kConsumerSecret, strlen(kConsumerSecret))) {
        // Deliberately vague to the caller: an allowlisted peer with the wrong secret
        // is either misconfigured or guessing.
        Log.print("[consumer] GET /authorized-ips refused: bad ?key= value '");
        safe_print(key, 64);
        Log.printf("' (%u bytes, supplied) from %s\n",
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
        Log.printf("[consumer] GET /authorized-ips: served %u IP(s), %u bytes\n",
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

    // usedThisBoot is omitted entirely when the store cannot tell (-1)
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

    if (!acl_is_admin(req_client_ip(req))) {
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
        Log.printf("[admin] GET /admin/credentials: %u credential(s)%s\n",
                      (unsigned)n, st.failed ? " (incomplete: send failed)" : "");
    }
    return st.failed ? ESP_FAIL : ESP_OK;
}

// GET /admin/logs - the last LOG_RING_SIZE diagnostic lines, oldest first (the client
// reverses for newest-first). Streamed like the other admin listings, from a snapshot so
// a concurrent writer cannot skew the view mid-stream.
static esp_err_t handler_admin_logs(httpd_req_t* req) {
    if (!frontdoor_admit_request(req)) {
        return ESP_FAIL; // rejection response already sent; drop the connection
    }
    log_request(req);

    if (!acl_is_admin(req_client_ip(req))) {
        return admin_denied(req, "GET /admin/logs");
    }

    LogEntry* entries = (LogEntry*)heap_caps_malloc(LOG_RING_SIZE * sizeof(LogEntry), MALLOC_CAP_SPIRAM);
    if (entries == nullptr) {
        entries = (LogEntry*)malloc(LOG_RING_SIZE * sizeof(LogEntry));
    }
    // Worst case every byte of a line escapes to "\u00XX" (6 bytes): 6x headroom.
    char* line = (char*)malloc(LOG_LINE_CAP * 6 + 1);
    if (entries == nullptr || line == nullptr) {
        free(entries);
        free(line);
        return send_json_status(req, "500 Internal Server Error", "{\"error\":\"oom\"}");
    }
    const size_t n = log_snapshot(entries, LOG_RING_SIZE);

    httpd_resp_set_type(req, "application/json");
    bool failed = httpd_resp_send_chunk(req, "[", 1) != ESP_OK;
    for (size_t i = 0; i < n && !failed; ++i) {
        const size_t elen = json_escape(entries[i].line, line, LOG_LINE_CAP * 6 + 1);
        char head[40];
        const int hl = snprintf(head, sizeof(head), "%s{\"t\":%lu,\"line\":\"",
                                i ? "," : "", (unsigned long)entries[i].unix);
        if (hl <= 0 || (size_t)hl >= sizeof(head) ||
            httpd_resp_send_chunk(req, head, (ssize_t)hl) != ESP_OK ||
            httpd_resp_send_chunk(req, line, (ssize_t)elen) != ESP_OK ||
            httpd_resp_send_chunk(req, "\"}", 2) != ESP_OK) {
            failed = true;
            break;
        }
    }
    if (!failed && httpd_resp_send_chunk(req, "]", 1) != ESP_OK) failed = true;

    // Terminate the chunked body even after a send error (see handler_admin_credentials).
    httpd_resp_send_chunk(req, nullptr, 0);

    free(line);
    free(entries);
    return failed ? ESP_FAIL : ESP_OK;
}

// GET /admin/acl - the admin + consumer allowlists and the runtime-edit flag.
static esp_err_t handler_admin_acl(httpd_req_t* req) {
    if (!frontdoor_admit_request(req)) {
        return ESP_FAIL;
    }
    log_request(req);

    if (!acl_is_admin(req_client_ip(req))) {
        return admin_denied(req, "GET /admin/acl");
    }

    uint32_t admin[kAllowlistMaxEntries], consumer[kAllowlistMaxEntries];
    const size_t an = acl_snapshot(ACL_ADMIN, admin, kAllowlistMaxEntries);
    const size_t cn = acl_snapshot(ACL_CONSUMER, consumer, kAllowlistMaxEntries);

    // 8 IPs * ~18 chars per list + overhead; 512 is ample for the capped lists.
    char body[512];
    size_t o = (size_t)snprintf(body, sizeof(body), "{\"edits\":%s,\"admin\":[",
                                kRuntimeAllowlistEdits ? "true" : "false");
    for (size_t i = 0; i < an; ++i) {
        IPAddress a(admin[i]);
        o += (size_t)snprintf(body + o, sizeof(body) - o, "%s\"%s\"", i ? "," : "", a.toString().c_str());
    }
    o += (size_t)snprintf(body + o, sizeof(body) - o, "],\"consumer\":[");
    for (size_t i = 0; i < cn; ++i) {
        IPAddress a(consumer[i]);
        o += (size_t)snprintf(body + o, sizeof(body) - o, "%s\"%s\"", i ? "," : "", a.toString().c_str());
    }
    snprintf(body + o, sizeof(body) - o, "]}");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, body);
    return ESP_OK;
}

// Parse an editing body { "list":"admin"|"consumer", "ip":"a.b.c.d" }. Returns nullptr
// on success (filling *list / *ipOut); otherwise an error code for a 400 response.
static const char* acl_parse_req(const char* body, size_t len, acl_list_t* list, uint32_t* ipOut) {
    char listBuf[16], ipBuf[64];
    if (extract_field(body, len, "list", listBuf, sizeof(listBuf)) <= 0 ||
        extract_field(body, len, "ip", ipBuf, sizeof(ipBuf)) <= 0) {
        return "list_and_ip_required";
    }
    if (strcmp(listBuf, "admin") == 0) {
        *list = ACL_ADMIN;
    } else if (strcmp(listBuf, "consumer") == 0) {
        *list = ACL_CONSUMER;
    } else {
        return "invalid_list";
    }
    IPAddress a;
    if (!a.fromString(ipBuf)) {
        return "invalid_ip";
    }
    *ipOut = (uint32_t)a;
    return nullptr;
}

// POST /admin/acl-add - { "list":"admin"|"consumer", "ip":"a.b.c.d" }
static esp_err_t handler_admin_acl_add(httpd_req_t* req) {
    if (!frontdoor_admit_request(req)) {
        return ESP_FAIL;
    }
    log_request(req);
    if (!acl_is_admin(req_client_ip(req))) {
        return admin_denied(req, "POST /admin/acl-add");
    }
    if (!kRuntimeAllowlistEdits) {
        return send_json_status(req, "403 Forbidden", "{\"error\":\"edits_disabled\"}");
    }

    char* body = (char*)malloc(kMaxBodySize + 1);
    if (!body) return send_json_status(req, "500 Internal Server Error", "{\"error\":\"oom\"}");
    int bl = read_body(req, body, kMaxBodySize + 1);
    if (bl < 0) {
        free(body);
        return send_json_status(req, "413 Payload Too Large", "{\"error\":\"payload\"}");
    }

    acl_list_t list;
    uint32_t ip;
    const char* err = acl_parse_req(body, (size_t)bl, &list, &ip);
    if (err) {
        free(body);
        char msg[64];
        snprintf(msg, sizeof(msg), "{\"error\":\"%s\"}", err);
        return send_json_status(req, "400 Bad Request", msg);
    }

    if (list == ACL_ADMIN && kAdminIPsNonPublicOnly && !acl_is_non_public(ip)) {
        free(body);
        return send_json_status(req, "400 Bad Request", "{\"error\":\"routable_not_allowed\"}");
    }
    const bool full = acl_count(list) >= kAllowlistMaxEntries;
    const bool dup  = (list == ACL_ADMIN) ? acl_is_admin(ip) : acl_is_consumer(ip);
    free(body);
    if (full) return send_json_status(req, "400 Bad Request", "{\"error\":\"allowlist_full\"}");
    if (dup)  return send_json_status(req, "400 Bad Request", "{\"error\":\"duplicate\"}");
    if (!acl_add(list, ip)) {
        return send_json_status(req, "400 Bad Request", "{\"error\":\"add_failed\"}");
    }
    return send_json(req, "{\"ok\":true}");
}

// POST /admin/acl-remove - { "list":"admin"|"consumer", "ip":"a.b.c.d" }. Refuses to
// remove the caller's own source IP from the admin list (self-lockout guard).
static esp_err_t handler_admin_acl_remove(httpd_req_t* req) {
    if (!frontdoor_admit_request(req)) {
        return ESP_FAIL;
    }
    log_request(req);
    if (!acl_is_admin(req_client_ip(req))) {
        return admin_denied(req, "POST /admin/acl-remove");
    }
    if (!kRuntimeAllowlistEdits) {
        return send_json_status(req, "403 Forbidden", "{\"error\":\"edits_disabled\"}");
    }

    char* body = (char*)malloc(kMaxBodySize + 1);
    if (!body) return send_json_status(req, "500 Internal Server Error", "{\"error\":\"oom\"}");
    int bl = read_body(req, body, kMaxBodySize + 1);
    if (bl < 0) {
        free(body);
        return send_json_status(req, "413 Payload Too Large", "{\"error\":\"payload\"}");
    }

    acl_list_t list;
    uint32_t ip;
    const char* err = acl_parse_req(body, (size_t)bl, &list, &ip);
    if (err) {
        free(body);
        char msg[64];
        snprintf(msg, sizeof(msg), "{\"error\":\"%s\"}", err);
        return send_json_status(req, "400 Bad Request", msg);
    }

    if (list == ACL_ADMIN && ip == req_client_ip(req)) {
        free(body);
        return send_json_status(req, "400 Bad Request", "{\"error\":\"cannot_remove_self\"}");
    }
    const bool present = (list == ACL_ADMIN) ? acl_is_admin(ip) : acl_is_consumer(ip);
    free(body);
    if (!present) return send_json_status(req, "400 Bad Request", "{\"error\":\"not_found\"}");
    if (!acl_remove(list, ip)) {
        return send_json_status(req, "400 Bad Request", "{\"error\":\"remove_failed\"}");
    }
    return send_json(req, "{\"ok\":true}");
}

// POST /admin/revoke-credential - { "id": "<base64url credentialId>" }
static esp_err_t handler_admin_revoke_credential(httpd_req_t* req) {
    if (!frontdoor_admit_request(req)) {
        return ESP_FAIL; // rejection response already sent; drop the connection
    }
    log_request(req);

    if (!acl_is_admin(req_client_ip(req))) {
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
// The credential keeps its record (identity, signature counter, last-used date) and 
// simply fails authentication until it is enabled again.
static esp_err_t handler_admin_set_credential_disabled(httpd_req_t* req) {
    if (!frontdoor_admit_request(req)) {
        return ESP_FAIL; // rejection response already sent; drop the connection
    }
    log_request(req);

    const uint32_t peer = req_client_ip(req);
    if (!acl_is_admin(peer)) {
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
        Log.printf("[admin] %s a credential from %s\n",
                      disabled ? "DISABLED" : "re-enabled", fromStr.c_str());
    } else {
        Log.printf("[admin] set-credential-disabled from %s: no credential matched that id\n",
                      fromStr.c_str());
    }
    return send_json(req, ok ? "{\"ok\":true}" : "{\"ok\":false}");
}

// GET /admin/authorized-ips - the currently-valid authorized IPs AND who is behind each one.
static esp_err_t handler_admin_authorized_ips(httpd_req_t* req) {
    if (!frontdoor_admit_request(req)) {
        return ESP_FAIL; // rejection response already sent; drop the connection
    }
    log_request(req);

    if (!acl_is_admin(req_client_ip(req))) {
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

        // One attributed key at a time. The email needs no JSON escaping due to email_is_usable()
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
        Log.printf("[admin] GET /admin/authorized-ips: %u IP(s), %u attributed key(s)%s\n",
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

    if (!acl_is_admin(req_client_ip(req))) {
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
static const httpd_uri_t uri_admin_logs = {
    .uri = "/admin/logs", .method = HTTP_GET, .handler = handler_admin_logs, .user_ctx = nullptr
};
static const httpd_uri_t uri_admin_acl = {
    .uri = "/admin/acl", .method = HTTP_GET, .handler = handler_admin_acl, .user_ctx = nullptr
};
static const httpd_uri_t uri_admin_acl_add = {
    .uri = "/admin/acl-add", .method = HTTP_POST, .handler = handler_admin_acl_add, .user_ctx = nullptr
};
static const httpd_uri_t uri_admin_acl_remove = {
    .uri = "/admin/acl-remove", .method = HTTP_POST, .handler = handler_admin_acl_remove, .user_ctx = nullptr
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

static void register_one(httpd_handle_t server, const httpd_uri_t* uri) {
    const esp_err_t err = httpd_register_uri_handler(server, uri);
    if (err != ESP_OK) {
        Log.printf("[httpd] FATAL: could not register %s (%s). The route does not exist; "
                      "raise cfg.httpd.max_uri_handlers and rebuild.\n",
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
    register_one(server, &uri_admin_logs);
    register_one(server, &uri_admin_acl);
    register_one(server, &uri_admin_acl_add);
    register_one(server, &uri_admin_acl_remove);
    register_one(server, &uri_admin_revoke_credential);
    register_one(server, &uri_admin_authorized_ips);
    register_one(server, &uri_admin_revoke_ip);
    register_one(server, &uri_admin_set_credential_disabled);

    // A request for an unregistered URI (a scanner probe) lands here: the 404 error
    // callback blocks the peer when kBlockScanners and answers 404.
    const esp_err_t err404 = httpd_register_err_handler(server, HTTPD_404_NOT_FOUND, handler_not_found);
    if (err404 != ESP_OK) {
        Log.printf("[httpd] could not register the 404 handler (%s); scanner blocking is off\n",
                      esp_err_to_name(err404));
    }
}

////////---------------------------------------        setup / loop        ---------------------------------------////////

// One compact line per TLS blob. The SHA-1 fingerprint is what you compare against the
// browser's trust store; the private key is never echoed.
static void print_tls_material(const char* certPem, size_t certLen, size_t keyLen) {
    char fp[64];
    if (certstore_cert_fingerprint(certPem, certLen, fp, sizeof(fp))) {
        Log.printf("  cert %u Bytes, SHA-1 %s\n", (unsigned)certLen, fp);
    } else {
        Log.printf("  cert %u Bytes, UNPARSEABLE - httpd_ssl will refuse to start\n",
                      (unsigned)certLen);
    }
    Log.printf("  key  %u Bytes\n", (unsigned)keyLen);
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
    Log.println("Using TLS material imported via serial console (NVS).");
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
    Log.printf("Socket slots:   %d free (0 = accept fails with ENFILE)\n", freeSlots);

    // What httpd itself holds. -1 = unknown (no handle, or the call failed).
    int sessions = -1;
    if (s_httpsServer != nullptr) {
        int fds[8];
        size_t nfds = sizeof(fds) / sizeof(fds[0]);
        if (httpd_get_client_list(s_httpsServer, &nfds, fds) == ESP_OK) {
            sessions = (int)nfds;
            Log.printf("HTTP sessions:  %d open (cap %u)\n", sessions,
                          (unsigned)s_maxOpenSockets);
        } else {
            Log.println("HTTP sessions:  unavailable (httpd_get_client_list failed)");
        }
    } else {
        Log.println("HTTP sessions:  no server handle");
    }

    uint32_t charged = 0;
    eth_gate_stats(nullptr, &charged, nullptr);
    const uint32_t opened = frontdoor_connections_opened();
    const uint32_t closed = frontdoor_connections_closed();
    const uint32_t inFlight = opened - closed;   // unsigned: opened >= closed always
    Log.printf("Connections:    %u SYNs charged at L2, %u accepted, %u closed (%u in flight)\n",
                  (unsigned)charged, (unsigned)opened, (unsigned)closed, (unsigned)inFlight);
    if (charged > opened) {
        Log.printf("                %u SYN(s) never became a session (accept/TLS failure)\n",
                      (unsigned)(charged - opened));
    }

    // Warn when more connections are in flight than httpd holds and no socket slot is free
    // (a transient +1 is normal right after a connection is accepted).
    if (freeSlots == 0 && sessions >= 0 && inFlight > (uint32_t)sessions) {
        Log.printf("                <-- %u in flight but not held by httpd, with no slot free:"
                      " socket leak (frontdoor_on_close must close its fd)\n",
                      (unsigned)(inFlight - (uint32_t)sessions));
    }
}

// Halt but keep the serial console alive so the user can import TLS material
// and reboot. Without this, a device with no cert could never be provisioned.
static void halt_with_console(const char* msg) {
    Log.println();
    Log.printf("*** %s ***\n", msg);
    Log.println("Serial console is active: use 'import' to load the certificate + key.");
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

    // Allocate the PSRAM log ring before the first diagnostic line, so it is captured.
    log_begin();

    Log.println("PoE-Passkey: starting...");

    // Report PSRAM before anything else can report a fallback.
    const size_t psramTotal = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);
    Log.printf("PSRAM: %s - %u B total, %u B free (psramFound()=%s)\n",
                  psramTotal ? "usable" : "NOT USABLE",
                  (unsigned)psramTotal,
                  (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
                  psramFound() ? "true" : "false");

    // Fail closed on any configuration error.
    if (!validateConfiguration()) {
        Log.println("HALTED: fix configuration errors in Config.h, recompile and reflash.");
        while (1) {
            delay(1000);
        }
    }

    // Crypto self-test: prove the P-256 point validation (S2) and the ES256 verify
    // path work before anything depends on them. Pass/fail only.
    run_selftest();

    // Ethernet bring-up (Unit-PoE-P4).
    ESP_LOGI(TAG, "Initializing Ethernet...");
    ETH.begin(ETH_TYPE, ETH_ADDR, ETH_PHY_MDC, ETH_PHY_MDIO, ETH_POWER_PIN, ETH_CLK_MODE);
    ETH.config(ip, gateway, subnet, dns1, dns2);
    while (!ETH.linkUp()) {
        delay(1000);
        Log.println("Waiting for Ethernet...");
    }
    Log.print("Ethernet connected, IP: ");
    Log.println(ETH.localIP());

    // Start NTP client
    clock_begin();

    // Pre-payload gate stores (throttle ring + PSRAM blocklist).
    frontdoor_begin();

    // Persistent + ephemeral stores (credentials in NVS, sessions + IPs in RAM).
    store_begin();

    // Runtime-editable IP allowlists (NVS-backed, seeded from Config.h on first boot).
    acl_begin();

    // TLS material (cert + key) from the NVS store, filled by `import` on the console.
    certstore_begin();

    const uint8_t* certPem;
    size_t certLen;
    const uint8_t* keyPem;
    size_t keyLen;
    if (!resolve_tls(&certPem, &certLen, &keyPem, &keyLen)) {
        const bool haveCert = certstore_has_cert();
        const bool haveKey  = certstore_has_key();
        const char* msg;
        if (!haveCert && !haveKey) msg = "No TLS certificate or private key imported.";
        else if (!haveCert)       msg = "TLS certificate missing (private key present).";
        else                      msg = "TLS private key missing (certificate present).";
        halt_with_console(msg);
    }

    // TLS server with the gate wired into open_fn.
    Log.println("Starting HTTPS server on port 443...");
    ESP_LOGI(TAG, "Starting HTTPS server on port 443...");
    httpd_ssl_config_t cfg = HTTPD_SSL_CONFIG_DEFAULT();
    cfg.httpd.max_uri_handlers = 20;
    cfg.httpd.max_open_sockets = 6;
    s_maxOpenSockets = cfg.httpd.max_open_sockets;
    cfg.httpd.lru_purge_enable = true;
    cfg.httpd.backlog_conn = 8;
    cfg.httpd.recv_wait_timeout = 2;
    cfg.httpd.send_wait_timeout = 2;
    cfg.httpd.stack_size = 10240;
    cfg.httpd.keep_alive_enable = true;
    cfg.httpd.keep_alive_idle = 5;       // seconds of no traffic before the first probe
    cfg.httpd.keep_alive_interval = 3;   // seconds between probes
    cfg.httpd.keep_alive_count = 3;      // unanswered probes before lwIP aborts the connection
    cfg.httpd.open_fn = frontdoor_on_open;   // pre-payload throttle + blocklist gate
    // close_fn REPLACES httpd's socket close, so frontdoor_on_close() must close the socket.
    cfg.httpd.close_fn = frontdoor_on_close;
    cfg.transport_mode = HTTPD_SSL_TRANSPORT_SECURE;
    cfg.port_secure = 443;
    cfg.prvtkey_pem = keyPem;
    cfg.prvtkey_len = keyLen + 1;
    cfg.servercert = certPem;
    cfg.servercert_len = certLen + 1;

    // Allocate the GET / render buffer (PSRAM) before the baseline report, so the
    // report below already accounts for it.
    if (!page_buffer_begin()) {
        Log.println("No memory for the page buffer; GET / will serve the raw template.");
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
            Log.println("L2 gate: active - blocked / over-budget SYNs are dropped in the Ethernet RX path.");
        } else {
            Log.println("L2 gate: NOT active - the request-level gate is still enforced.");
        }
    }

    memory_report("after TLS server start");

    Log.printf("PoE-Passkey ready: https://%s\n", kRpId);
    ESP_LOGI(TAG, "PoE-Passkey ready: https://%s", kRpId);
}

void loop() {
    // Prune expired AUTHORIZED_IPS entries (TTL-governed).
    authzips_prune(millis());

    // Serial console (cert/key import, status, clear, reboot).
    serial_console_poll();

    delay(100);
}