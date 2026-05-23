package main

import (
	"fmt"
	"os"
	"strings"
)

// Environment variables that drive the webhook's verification policy.
//
// These are the only knobs the webhook honors. There is no default value:
// each must be set explicitly so that the operator cannot accidentally ship
// a permissive configuration.
const (
	// EnvTrustedKernelKeys is a comma-separated list of ed25519 issuer
	// public keys (hex) whose capability signatures the webhook trusts.
	// Required: empty -> fail closed.
	EnvTrustedKernelKeys = "CHIO_WEBHOOK_TRUSTED_KERNEL_KEYS"

	// EnvRequiredScopes is a comma-separated list of canonical scopes the
	// webhook requires every admitted capability to cover.
	// Required: empty -> fail closed.
	EnvRequiredScopes = "CHIO_WEBHOOK_REQUIRED_SCOPES"
)

// LoadVerifierConfigFromEnv reads the webhook policy from environment
// variables. It returns a typed error if any required field is missing or
// invalid; the webhook caller must NOT fall back to a permissive default.
func LoadVerifierConfigFromEnv() (VerifierConfig, error) {
	trusted, err := splitCSV(os.Getenv(EnvTrustedKernelKeys), EnvTrustedKernelKeys)
	if err != nil {
		return VerifierConfig{}, err
	}
	if len(trusted) == 0 {
		return VerifierConfig{}, fmt.Errorf(
			"webhook configuration: %s is required (no default trusted keys)",
			EnvTrustedKernelKeys,
		)
	}

	scopes, err := splitCSV(os.Getenv(EnvRequiredScopes), EnvRequiredScopes)
	if err != nil {
		return VerifierConfig{}, err
	}
	if len(scopes) == 0 {
		return VerifierConfig{}, fmt.Errorf(
			"webhook configuration: %s is required (no default required scopes)",
			EnvRequiredScopes,
		)
	}

	return NewVerifierConfig(trusted, scopes)
}

func splitCSV(raw, name string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	out := make([]string, 0, 4)
	for _, part := range strings.Split(raw, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			return nil, fmt.Errorf("webhook configuration: empty entry in %s", name)
		}
		out = append(out, trimmed)
	}
	return out, nil
}
