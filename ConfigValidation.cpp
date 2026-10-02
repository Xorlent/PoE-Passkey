/*
 * ConfigValidation.cpp - fails startup on a critical Config.h misconfiguration.
 */

#include "Config.h"
#include "ConfigValidation.h"
#include "Log.h"
#include <Arduino.h>
#include <string.h>

static bool s_halted = false;

static void fail(const char* msg) {
    Log.printf("[CONFIG ERROR] %s\n", msg);
    s_halted = true;
}

bool fqdn_is_valid(const char* s) {
    if (!s || !*s) {
        return false;
    }
    const size_t len = strlen(s);
    if (len > 253) {
        return false;
    }
    bool sawDot = false;
    size_t label = 0;
    for (size_t i = 0; i <= len; ++i) {
        const char c = s[i];
        if (c == '.' || c == '\0') {
            if (label == 0 || label > 63) {
                return false;
            }
            if (s[i - 1] == '-') {
                return false;
            }
            if (c == '.') {
                sawDot = true;
            }
            label = 0;
        } else {
            const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                            (c >= '0' && c <= '9') || c == '-';
            if (!ok) {
                return false;
            }
            if (c == '-' && label == 0) {
                return false;
            }
            ++label;
        }
    }
    return sawDot;
}

bool validateConfiguration() {
    // ---- WebAuthn identity ----
    if (kRpId == nullptr || kRpId[0] == '\0') {
        fail("kRpId must be a non-empty domain (e.g. auth.example.com).");
    }

    if (kOrigin == nullptr) {
        fail("kOrigin must not be NULL.");
    } else {
        // Origin must be https and equal (or be a subdomain of) the RP ID.
        const char* https = "https://";
        if (strncmp(kOrigin, https, strlen(https)) != 0) {
            fail("kOrigin must begin with 'https://'.");
        } else {
            const char* host = kOrigin + strlen(https);
            size_t rpLen = strlen(kRpId);
            size_t hostLen = strlen(host);
            bool exact = (hostLen == rpLen && strcmp(host, kRpId) == 0);
            bool sub   = (hostLen > rpLen + 1 &&
                          host[hostLen - rpLen - 1] == '.' &&
                          strcmp(host + hostLen - rpLen, kRpId) == 0);
            if (!exact && !sub) {
                fail("kOrigin host must equal (or be a subdomain of) kRpId.");
            }
        }
    }

    // ---- TLS identity ----
    // Nothing to check here: cert + key are imported at runtime. Boot (resolve_tls())
    // names what is missing and halts into the console.

    // ---- Admin IP allowlist ----
    if (kAdminIPCount == 0) {
        fail("kAdminIPs must contain at least one authorized internal IP.");
    }

    // ---- Rate limiting ----
    if (kThrottleWindowMs == 0) {
        fail("kThrottleWindowMs must be > 0.");
    }
    if (kMaxConnPerWindowPerIP == 0) {
        fail("kMaxConnPerWindowPerIP must be > 0.");
    }
    if (kThrottleRingSize == 0) {
        fail("kThrottleRingSize must be > 0.");
    }

    // ---- Blocklist ----
    if (kBlocklistMaxEntries == 0) {
        fail("kBlocklistMaxEntries must be > 0.");
    }

    // ---- Failure streaks ----
    if (kFailureSlots == 0) {
        fail("kFailureSlots must be > 0.");
    }
    if (kFailureWindowMs == 0) {
        fail("kFailureWindowMs must be > 0.");
    }

    // ---- TTLs ----
    if (kSessionTtlMs == 0) {
        fail("kSessionTtlMs must be > 0.");
    }
    if (kMaxSessionsPerIP == 0) {
        fail("kMaxSessionsPerIP must be > 0 (a cap of 0 refuses every ceremony).");
    }
    if (kAuthorizedIPTtlMs == 0) {
        fail("kAuthorizedIPTtlMs must be > 0.");
    }

    // ---- Consumer endpoint ----
    if (kConsumerSecret == nullptr || kConsumerSecret[0] == '\0') {
        fail("kConsumerSecret must not be empty.");
    } else if (strcmp(kConsumerSecret, "CHANGE_ME") == 0) {
        fail("kConsumerSecret is still the default - set a real secret.");
    }
    if (kConsumerAllowlistCount == 0) {
        fail("kConsumerAllowlist must contain at least one consumer IP.");
    }

    // ---- Referer gate ----
    if (strcmp(kAuthorizedReferrerURIHost, "NotEnforced") != 0 &&
        !fqdn_is_valid(kAuthorizedReferrerURIHost)) {
        fail("kAuthorizedReferrerURIHost must be either \"NotEnforced\" or a valid FQDN "
             "(e.g. auth.example.com).");
    }
    if (s_halted) {
        return false;
    }

    Log.printf("Configuration validated: RP ID '%s', %u admin IP(s), %u consumer IP(s).\n",
                  kRpId, (unsigned)kAdminIPCount, (unsigned)kConsumerAllowlistCount);
    return true;
}
