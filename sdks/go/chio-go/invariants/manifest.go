package invariants

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"unicode"
)

var requiredPermissionFields = map[string]struct{}{
	"read_paths":            {},
	"write_paths":           {},
	"network_hosts":         {},
	"environment_variables": {},
}

var pricingModels = map[string]struct{}{
	"flat":           {},
	"per_invocation": {},
	"per_unit":       {},
	"hybrid":         {},
}

var signedManifestFields = map[string]struct{}{
	"manifest":   {},
	"signature":  {},
	"signer_key": {},
}

var manifestFields = map[string]struct{}{
	"schema":               {},
	"server_id":            {},
	"name":                 {},
	"description":          {},
	"version":              {},
	"tools":                {},
	"server_tools":         {},
	"required_permissions": {},
	"public_key":           {},
}

var toolFields = map[string]struct{}{
	"name":             {},
	"description":      {},
	"input_schema":     {},
	"output_schema":    {},
	"pricing":          {},
	"has_side_effects": {},
	"latency_hint":     {},
}

var pricingFields = map[string]struct{}{
	"pricing_model": {},
	"base_price":    {},
	"unit_price":    {},
	"billing_unit":  {},
}

var serverTools = map[string]struct{}{
	"computer_use": {},
	"bash":         {},
	"text_editor":  {},
}

var latencyHints = map[string]struct{}{
	"instant":  {},
	"fast":     {},
	"moderate": {},
	"slow":     {},
}

const maxUint64ExclusiveAsFloat = 18446744073709551616.0

type ManifestVerification struct {
	EmbeddedPublicKeyMatchesSigner bool `json:"embedded_public_key_matches_signer"`
	EmbeddedPublicKeyValid         bool `json:"embedded_public_key_valid"`
	SignatureValid                 bool `json:"signature_valid"`
	StructureValid                 bool `json:"structure_valid"`
}

func ParseSignedManifestJSON(input string) (map[string]any, error) {
	value, err := ParseJSONText(input)
	if err != nil {
		return nil, err
	}
	signedManifest, ok := value.(map[string]any)
	if !ok {
		return nil, newInvariantError("json", "signed manifest must be a JSON object")
	}
	return signedManifest, nil
}

func SignedManifestBodyCanonicalJSON(signedManifest map[string]any) (string, error) {
	manifest, err := mapField(signedManifest, "manifest")
	if err != nil {
		return "", err
	}
	return CanonicalizeJSON(manifest)
}

func VerifySignedManifest(signedManifest map[string]any) (ManifestVerification, error) {
	envelopeValid := validateSignedManifestEnvelope(signedManifest)
	manifest, manifestValid := signedManifest["manifest"].(map[string]any)
	signature, signatureValidShape := signedManifest["signature"].(string)
	signerKey, signerKeyValidShape := signedManifest["signer_key"].(string)
	embeddedPublicKey, embeddedPublicKeyShapeValid := manifest["public_key"].(string)
	embeddedPublicKeyValid := IsValidEd25519PublicKeyHex(embeddedPublicKey)
	signatureValid := false
	if envelopeValid && manifestValid && signatureValidShape && signerKeyValidShape {
		body, err := CanonicalizeJSON(manifest)
		if err == nil {
			signatureValid, _ = VerifyUTF8MessageEd25519(body, signerKey, signature)
		}
	}
	return ManifestVerification{
		EmbeddedPublicKeyMatchesSigner: embeddedPublicKeyValid && signerKeyValidShape && PublicKeyHexMatches(embeddedPublicKey, signerKey),
		EmbeddedPublicKeyValid:         embeddedPublicKeyShapeValid && embeddedPublicKeyValid,
		SignatureValid:                 signatureValid,
		StructureValid:                 envelopeValid && validateManifestStructure(manifest),
	}, nil
}

func VerifySignedManifestJSON(input string) (ManifestVerification, error) {
	signedManifest, err := ParseSignedManifestJSON(input)
	if err != nil {
		return ManifestVerification{}, err
	}
	return VerifySignedManifest(signedManifest)
}

func validateManifestStructure(manifest map[string]any) bool {
	if !hasOnlyKnownKeys(manifest, manifestFields) {
		return false
	}
	schema, ok := manifest["schema"].(string)
	if !ok || schema != "chio.manifest.v1" {
		return false
	}
	if !isValidManifestTextField(manifest["server_id"]) ||
		!isValidManifestTextField(manifest["name"]) ||
		!isValidManifestTextField(manifest["version"]) {
		return false
	}
	tools, ok := manifest["tools"].([]any)
	if !ok || len(tools) == 0 {
		return false
	}
	if _, ok := manifest["public_key"].(string); !ok {
		return false
	}
	if !validateServerTools(manifest["server_tools"]) {
		return false
	}
	seen := make(map[string]struct{}, len(tools))
	for _, entry := range tools {
		tool, ok := entry.(map[string]any)
		if !ok {
			return false
		}
		if !hasOnlyKnownKeys(tool, toolFields) {
			return false
		}
		name, ok := tool["name"].(string)
		if !ok || !isValidToolName(name) {
			return false
		}
		if _, exists := seen[name]; exists {
			return false
		}
		seen[name] = struct{}{}
		if !isJSONObject(tool["input_schema"]) {
			return false
		}
		if _, ok := tool["description"].(string); !ok {
			return false
		}
		if _, ok := tool["has_side_effects"].(bool); !ok {
			return false
		}
		if outputSchema, exists := tool["output_schema"]; exists && outputSchema != nil && !isJSONObject(outputSchema) {
			return false
		}
		if !validateToolPricing(tool["pricing"]) {
			return false
		}
		if latencyHint, exists := tool["latency_hint"]; exists && latencyHint != nil {
			text, ok := latencyHint.(string)
			if !ok {
				return false
			}
			if _, ok := latencyHints[text]; !ok {
				return false
			}
		}
	}
	return validateRequiredPermissions(manifest["required_permissions"])
}

func validateSignedManifestEnvelope(signedManifest map[string]any) bool {
	if signedManifest == nil {
		return false
	}
	if len(signedManifest) != len(signedManifestFields) {
		return false
	}
	for field := range signedManifest {
		if _, ok := signedManifestFields[field]; !ok {
			return false
		}
	}
	return true
}

func hasOnlyKnownKeys(value map[string]any, knownKeys map[string]struct{}) bool {
	if value == nil {
		return false
	}
	for field := range value {
		if _, ok := knownKeys[field]; !ok {
			return false
		}
	}
	return true
}

func isValidManifestTextField(value any) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	trimmed := strings.TrimSpace(text)
	return trimmed != "" && trimmed == text && !strings.ContainsFunc(text, unicode.IsControl)
}

func isValidToolName(name string) bool {
	return isValidManifestTextField(name)
}

func isJSONObject(value any) bool {
	_, ok := value.(map[string]any)
	return ok
}

func validateToolPricing(value any) bool {
	if value == nil {
		return true
	}
	pricing, ok := value.(map[string]any)
	if !ok {
		return false
	}
	if !hasOnlyKnownKeys(pricing, pricingFields) {
		return false
	}
	model, ok := pricing["pricing_model"].(string)
	if !ok {
		return false
	}
	if _, ok := pricingModels[model]; !ok {
		return false
	}
	switch model {
	case "flat":
		if !requirePricingAmount(pricing["base_price"]) {
			return false
		}
	case "per_invocation", "per_unit":
		if !requirePricingAmount(pricing["unit_price"]) ||
			!isValidManifestTextField(pricing["billing_unit"]) {
			return false
		}
	case "hybrid":
		if !requirePricingAmount(pricing["base_price"]) ||
			!requirePricingAmount(pricing["unit_price"]) ||
			!isValidManifestTextField(pricing["billing_unit"]) {
			return false
		}
	}
	if !validateOptionalPricingAmount(pricing["base_price"]) {
		return false
	}
	if !validateOptionalPricingAmount(pricing["unit_price"]) {
		return false
	}
	if billingUnit, exists := pricing["billing_unit"]; exists && billingUnit != nil && !isValidManifestTextField(billingUnit) {
		return false
	}
	return true
}

func validateServerTools(value any) bool {
	if value == nil {
		return true
	}
	values, ok := value.([]any)
	if !ok {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, entry := range values {
		text, ok := entry.(string)
		if !ok {
			return false
		}
		if _, ok := serverTools[text]; !ok {
			return false
		}
		if _, exists := seen[text]; exists {
			return false
		}
		seen[text] = struct{}{}
	}
	return true
}

func requirePricingAmount(value any) bool {
	return value != nil && validatePricingAmount(value)
}

func validateOptionalPricingAmount(value any) bool {
	if value == nil {
		return true
	}
	return validatePricingAmount(value)
}

func validatePricingAmount(value any) bool {
	amount, ok := value.(map[string]any)
	if !ok {
		return false
	}
	if !isNonNegativeInteger(amount["units"]) {
		return false
	}
	currency, ok := amount["currency"].(string)
	return ok && isISO4217CurrencyCode(currency)
}

func isNonNegativeInteger(value any) bool {
	switch units := value.(type) {
	case int:
		return units >= 0
	case int64:
		return units >= 0
	case float64:
		return units >= 0 && math.Trunc(units) == units && units < maxUint64ExclusiveAsFloat
	case json.Number:
		_, err := strconv.ParseUint(units.String(), 10, 64)
		return err == nil
	default:
		return false
	}
}

func isISO4217CurrencyCode(currency string) bool {
	if len(currency) != 3 {
		return false
	}
	for _, char := range currency {
		if char < 'A' || char > 'Z' {
			return false
		}
	}
	return true
}

func validateRequiredPermissions(value any) bool {
	if value == nil {
		return true
	}
	permissions, ok := value.(map[string]any)
	if !ok {
		return false
	}
	for field := range permissions {
		if _, ok := requiredPermissionFields[field]; !ok {
			return false
		}
	}
	for field := range requiredPermissionFields {
		if !validateRequiredPermissionValues(permissions[field]) {
			return false
		}
	}
	return true
}

func validateRequiredPermissionValues(value any) bool {
	if value == nil {
		return true
	}
	values, ok := value.([]any)
	if !ok {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, entry := range values {
		text, ok := entry.(string)
		if !ok || !isValidManifestTextField(text) {
			return false
		}
		if _, exists := seen[text]; exists {
			return false
		}
		seen[text] = struct{}{}
	}
	return true
}
