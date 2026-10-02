/*
 * ConfigValidation.h
 *
 * Configuration validation for PoE-Passkey.
 * Validates all settings from Config.h at startup (fail-closed).
 */

#ifndef CONFIG_VALIDATION_H
#define CONFIG_VALIDATION_H

// Validate configuration at startup.
// Returns false if any critical error is found, true otherwise.
bool validateConfiguration();

// True when `s` is a well-formed FQDN (labels of [A-Za-z0-9-], >=1 dot, <=253 chars).
// "NotEnforced" is not an FQDN, so the referrer gate is inert by default.
bool fqdn_is_valid(const char* s);

#endif // CONFIG_VALIDATION_H
