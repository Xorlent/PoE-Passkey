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

#endif // CONFIG_VALIDATION_H
