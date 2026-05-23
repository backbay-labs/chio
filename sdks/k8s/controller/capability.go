package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	envTrustedIssuerKey  = "CHIO_TRUSTED_ISSUER_KEY"
	envTrustedIssuerKeys = "CHIO_TRUSTED_ISSUER_KEYS"
	envRequiredScopes    = "CHIO_REQUIRED_SCOPES"
)

type capabilityValidationConfig struct {
	trustedIssuers map[string]struct{}
}

type capabilityToken struct {
	ID              string          `json:"id"`
	Issuer          string          `json:"issuer"`
	Subject         string          `json:"subject"`
	Scope           capabilityScope `json:"scope"`
	IssuedAt        uint64          `json:"issued_at"`
	ExpiresAt       uint64          `json:"expires_at"`
	DelegationChain []any           `json:"delegation_chain,omitempty"`
	Signature       string          `json:"signature"`
}

type capabilityScope struct {
	Grants         []toolGrant     `json:"grants,omitempty"`
	ResourceGrants []resourceGrant `json:"resource_grants,omitempty"`
	PromptGrants   []promptGrant   `json:"prompt_grants,omitempty"`
}

type toolGrant struct {
	ServerID   string   `json:"server_id"`
	ToolName   string   `json:"tool_name"`
	Operations []string `json:"operations"`
}

type resourceGrant struct {
	URIPattern string   `json:"uri_pattern"`
	Operations []string `json:"operations"`
}

type promptGrant struct {
	PromptName string   `json:"prompt_name"`
	Operations []string `json:"operations"`
}

type requiredScopeKind string

const (
	requiredScopeTool     requiredScopeKind = "tool"
	requiredScopeResource requiredScopeKind = "resource"
	requiredScopePrompt   requiredScopeKind = "prompt"
)

type requiredScope struct {
	kind      requiredScopeKind
	serverID  string
	name      string
	operation string
	shorthand bool
}

func validateCapabilityToken(raw string, requiredScopes []string, now time.Time) error {
	config, err := loadCapabilityValidationConfigFromEnv()
	if err != nil {
		return err
	}

	return validateCapabilityTokenWithConfig(raw, requiredScopes, now, config)
}

func validateCapabilityTokenWithConfig(
	raw string,
	requiredScopes []string,
	now time.Time,
	config capabilityValidationConfig,
) error {
	if len(config.trustedIssuers) == 0 {
		return fmt.Errorf(
			"capability validation requires %s or %s to be configured",
			envTrustedIssuerKey,
			envTrustedIssuerKeys,
		)
	}
	if len(requiredScopes) == 0 {
		return fmt.Errorf("capability validation requires %s to be configured", envRequiredScopes)
	}

	token, err := parseCapabilityToken(raw)
	if err != nil {
		return err
	}
	issuer, err := normalizePublicKeyHex(token.Issuer)
	if err != nil {
		return fmt.Errorf("capability issuer is invalid: %w", err)
	}
	if !config.trustsIssuer(issuer) {
		return fmt.Errorf("capability issuer is not trusted by controller configuration")
	}
	if err := verifyCapabilitySignature(raw, token.Issuer, token.Signature); err != nil {
		return err
	}

	nowUnix := uint64(now.Unix())
	if nowUnix < token.IssuedAt {
		return fmt.Errorf("capability token is not yet valid")
	}
	if nowUnix >= token.ExpiresAt {
		return fmt.Errorf("capability token is expired")
	}

	for _, scope := range requiredScopes {
		parsed, err := parseRequiredScope(scope)
		if err != nil {
			return err
		}
		if !token.Scope.covers(parsed) {
			return fmt.Errorf("capability token does not cover required scope %q", scope)
		}
	}

	return nil
}

func loadCapabilityValidationConfigFromEnv() (capabilityValidationConfig, error) {
	config := capabilityValidationConfig{
		trustedIssuers: make(map[string]struct{}),
	}

	rawValues := []string{
		os.Getenv(envTrustedIssuerKey),
		os.Getenv(envTrustedIssuerKeys),
	}

	for _, raw := range rawValues {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		for _, part := range strings.Split(raw, ",") {
			key := strings.TrimSpace(part)
			if key == "" {
				return capabilityValidationConfig{}, fmt.Errorf(
					"invalid empty trusted issuer in controller configuration",
				)
			}
			normalized, err := normalizePublicKeyHex(key)
			if err != nil {
				return capabilityValidationConfig{}, fmt.Errorf(
					"invalid trusted issuer in controller configuration: %w",
					err,
				)
			}
			config.trustedIssuers[normalized] = struct{}{}
		}
	}

	return config, nil
}

func (config capabilityValidationConfig) trustsIssuer(issuer string) bool {
	_, ok := config.trustedIssuers[issuer]
	return ok
}

func parseCapabilityToken(raw string) (capabilityToken, error) {
	var token capabilityToken
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&token); err != nil {
		return capabilityToken{}, fmt.Errorf("invalid capability token: %w", err)
	}
	if token.ID == "" || token.Issuer == "" || token.Signature == "" {
		return capabilityToken{}, fmt.Errorf("invalid capability token: missing required fields")
	}
	return token, nil
}

func verifyCapabilitySignature(raw, issuerHex, signatureHex string) error {
	var parsed map[string]any
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&parsed); err != nil {
		return fmt.Errorf("invalid capability token: %w", err)
	}
	delete(parsed, "signature")

	canonical, err := canonicalJSON(parsed)
	if err != nil {
		return fmt.Errorf("invalid capability token: %w", err)
	}

	publicKey, err := decodeFixedHex(issuerHex, ed25519.PublicKeySize)
	if err != nil {
		return fmt.Errorf("capability signature verification failed: %w", err)
	}
	signature, err := decodeFixedHex(signatureHex, ed25519.SignatureSize)
	if err != nil {
		return fmt.Errorf("capability signature verification failed: %w", err)
	}

	if !ed25519.Verify(ed25519.PublicKey(publicKey), canonical, signature) {
		return fmt.Errorf("capability signature verification failed")
	}

	return nil
}

func parseRequiredScopes(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}

	parts := strings.Split(raw, ",")
	scopes := make([]string, 0, len(parts))
	for _, part := range parts {
		scope := strings.TrimSpace(part)
		if scope == "" {
			return nil, fmt.Errorf("invalid empty scope in %s", AnnotationRequiredScopes)
		}
		scopes = append(scopes, scope)
	}
	return scopes, nil
}

func loadRequiredScopesFromEnv() ([]string, error) {
	raw := os.Getenv(envRequiredScopes)
	scopes, err := parseRequiredScopes(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", envRequiredScopes, err)
	}
	if len(scopes) == 0 {
		return nil, fmt.Errorf("capability validation requires %s to be configured", envRequiredScopes)
	}
	return scopes, nil
}

func parseRequiredScope(raw string) (requiredScope, error) {
	parts := strings.Split(raw, ":")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
		if parts[i] == "" {
			return requiredScope{}, fmt.Errorf("invalid scope %q in %s", raw, AnnotationRequiredScopes)
		}
	}

	switch len(parts) {
	case 2:
		operation, err := normalizeScopeOperation(parts[1], true)
		if err != nil {
			return requiredScope{}, fmt.Errorf("invalid scope %q in %s: %w", raw, AnnotationRequiredScopes, err)
		}
		return requiredScope{
			kind:      requiredScopeTool,
			serverID:  "*",
			name:      parts[0],
			operation: operation,
			shorthand: true,
		}, nil
	case 3:
		kind := requiredScopeKind(parts[0])
		operation, err := normalizeScopeOperation(parts[2], false)
		if err != nil {
			return requiredScope{}, fmt.Errorf("invalid scope %q in %s: %w", raw, AnnotationRequiredScopes, err)
		}
		if kind != requiredScopeResource && kind != requiredScopePrompt {
			return requiredScope{}, fmt.Errorf("invalid scope %q in %s", raw, AnnotationRequiredScopes)
		}
		return requiredScope{
			kind:      kind,
			name:      parts[1],
			operation: operation,
		}, nil
	case 4:
		if parts[0] != string(requiredScopeTool) {
			return requiredScope{}, fmt.Errorf("invalid scope %q in %s", raw, AnnotationRequiredScopes)
		}
		operation, err := normalizeScopeOperation(parts[3], false)
		if err != nil {
			return requiredScope{}, fmt.Errorf("invalid scope %q in %s: %w", raw, AnnotationRequiredScopes, err)
		}
		return requiredScope{
			kind:      requiredScopeTool,
			serverID:  parts[1],
			name:      parts[2],
			operation: operation,
		}, nil
	default:
		return requiredScope{}, fmt.Errorf("invalid scope %q in %s", raw, AnnotationRequiredScopes)
	}
}

func normalizeScopeOperation(raw string, shorthand bool) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "invoke", "call", "exec", "execute":
		return "invoke", nil
	case "write":
		if shorthand {
			return "invoke", nil
		}
	case "read_result", "result":
		return "read_result", nil
	case "read":
		if shorthand {
			return "invoke", nil
		}
		return "read", nil
	case "subscribe", "watch":
		return "subscribe", nil
	case "get":
		return "get", nil
	case "delegate":
		return "delegate", nil
	}
	return "", fmt.Errorf("unsupported operation %q", raw)
}

func (scope capabilityScope) covers(required requiredScope) bool {
	switch required.kind {
	case requiredScopeTool:
		for _, grant := range scope.Grants {
			if !patternCovers(grant.ServerID, required.serverID) {
				continue
			}
			if !patternCovers(grant.ToolName, required.name) {
				continue
			}
			if operationsContain(grant.Operations, required.operation) {
				return true
			}
		}
	case requiredScopeResource:
		for _, grant := range scope.ResourceGrants {
			if patternCovers(grant.URIPattern, required.name) &&
				operationsContain(grant.Operations, required.operation) {
				return true
			}
		}
	case requiredScopePrompt:
		for _, grant := range scope.PromptGrants {
			if patternCovers(grant.PromptName, required.name) &&
				operationsContain(grant.Operations, required.operation) {
				return true
			}
		}
	}
	return false
}

func operationsContain(operations []string, target string) bool {
	for _, operation := range operations {
		if strings.EqualFold(operation, target) {
			return true
		}
	}
	return false
}

func patternCovers(parent, child string) bool {
	if parent == "*" {
		return true
	}
	if strings.HasSuffix(parent, "*") {
		return strings.HasPrefix(child, strings.TrimSuffix(parent, "*"))
	}
	return parent == child
}

func decodeFixedHex(raw string, size int) ([]byte, error) {
	trimmed := strings.TrimPrefix(raw, "0x")
	decoded, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, err
	}
	if len(decoded) != size {
		return nil, fmt.Errorf("expected %d bytes, got %d", size, len(decoded))
	}
	return decoded, nil
}

func normalizePublicKeyHex(raw string) (string, error) {
	decoded, err := decodeFixedHex(raw, ed25519.PublicKeySize)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(decoded), nil
}

func canonicalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonicalJSON(&buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonicalJSON(buf *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if typed {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return err
		}
		buf.Write(encoded)
	case json.Number:
		buf.WriteString(typed.String())
	case float64:
		buf.WriteString(strconv.FormatFloat(typed, 'g', -1, 64))
	case []any:
		buf.WriteByte('[')
		for i, item := range typed {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalJSON(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			encodedKey, err := json.Marshal(key)
			if err != nil {
				return err
			}
			buf.Write(encodedKey)
			buf.WriteByte(':')
			if err := writeCanonicalJSON(buf, typed[key]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return err
		}
		var reparsed any
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.UseNumber()
		if err := decoder.Decode(&reparsed); err != nil {
			return err
		}
		return writeCanonicalJSON(buf, reparsed)
	}
	return nil
}
