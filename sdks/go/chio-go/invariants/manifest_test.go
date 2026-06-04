package invariants_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/backbay-labs/chio/sdks/go/chio-go/invariants"
)

func pricedSignedManifest() map[string]any {
	return map[string]any{
		"manifest": map[string]any{
			"schema":    "chio.manifest.v1",
			"server_id": "srv-priced",
			"name":      "Priced Server",
			"version":   "1.0.0",
			"tools": []any{
				map[string]any{
					"name":         "greet",
					"description":  "Returns a greeting",
					"input_schema": map[string]any{"type": "object"},
					"pricing": map[string]any{
						"pricing_model": "per_invocation",
						"unit_price": map[string]any{
							"units":    float64(25),
							"currency": "USD",
						},
						"billing_unit": "invocation",
					},
					"has_side_effects": false,
				},
			},
			"public_key": strings.Repeat("22", 32),
		},
		"signature":  strings.Repeat("33", 64),
		"signer_key": strings.Repeat("11", 32),
	}
}

func TestManifestStructureDoesNotIncludeEmbeddedPublicKeyValidity(t *testing.T) {
	signedManifest := pricedSignedManifest()
	signedManifest["manifest"].(map[string]any)["public_key"] = "demo-placeholder"

	verification, err := invariants.VerifySignedManifest(signedManifest)
	if err != nil {
		t.Fatalf("VerifySignedManifest returned error: %v", err)
	}
	if !verification.StructureValid {
		t.Fatalf("malformed embedded public key must not invalidate manifest structure")
	}
	if verification.EmbeddedPublicKeyValid {
		t.Fatalf("malformed embedded public key must be reported separately")
	}
	if verification.EmbeddedPublicKeyMatchesSigner {
		t.Fatalf("malformed embedded public key must not match signer")
	}
}

func TestManifestStructureRejectsEmptyOrPaddedIdentityFields(t *testing.T) {
	cases := []struct {
		field string
		value string
	}{
		{"server_id", ""},
		{"server_id", " srv-priced"},
		{"server_id", "srv-priced "},
		{"server_id", "srv\npriced"},
		{"name", ""},
		{"name", " Priced Server"},
		{"name", "Priced Server "},
		{"version", ""},
		{"version", " 1.0.0"},
		{"version", "1.0.0 "},
	}
	for _, tc := range cases {
		t.Run(tc.field+"="+tc.value, func(t *testing.T) {
			signedManifest := pricedSignedManifest()
			signedManifest["manifest"].(map[string]any)[tc.field] = tc.value

			verification, err := invariants.VerifySignedManifest(signedManifest)
			if err != nil {
				t.Fatalf("VerifySignedManifest returned error: %v", err)
			}
			if verification.StructureValid {
				t.Fatalf("%s value %q must be structurally invalid", tc.field, tc.value)
			}
			if verification.SignatureValid {
				t.Fatalf("mutated identity field should invalidate the signature")
			}
			if !verification.EmbeddedPublicKeyValid {
				t.Fatalf("embedded public key validity must remain independent")
			}
		})
	}
}

func TestManifestStructureRejectsEmptyOrPaddedToolNames(t *testing.T) {
	for _, name := range []string{"", " greet", "greet "} {
		t.Run(name, func(t *testing.T) {
			signedManifest := pricedSignedManifest()
			tool := signedManifest["manifest"].(map[string]any)["tools"].([]any)[0].(map[string]any)
			tool["name"] = name

			verification, err := invariants.VerifySignedManifest(signedManifest)
			if err != nil {
				t.Fatalf("VerifySignedManifest returned error: %v", err)
			}
			if verification.StructureValid {
				t.Fatalf("name %q must be structurally invalid", name)
			}
		})
	}
}

func TestManifestStructureRejectsNonObjectToolSchemas(t *testing.T) {
	badInputSchema := pricedSignedManifest()
	badInputSchema["manifest"].(map[string]any)["tools"].([]any)[0].(map[string]any)["input_schema"] = []any{}
	inputVerification, err := invariants.VerifySignedManifest(badInputSchema)
	if err != nil {
		t.Fatalf("VerifySignedManifest returned error for input schema: %v", err)
	}
	if inputVerification.StructureValid {
		t.Fatalf("array input_schema must be structurally invalid")
	}

	badOutputSchema := pricedSignedManifest()
	badOutputSchema["manifest"].(map[string]any)["tools"].([]any)[0].(map[string]any)["output_schema"] = "not an object"
	outputVerification, err := invariants.VerifySignedManifest(badOutputSchema)
	if err != nil {
		t.Fatalf("VerifySignedManifest returned error for output schema: %v", err)
	}
	if outputVerification.StructureValid {
		t.Fatalf("string output_schema must be structurally invalid")
	}
}

func TestManifestStructureRejectsMalformedPricingMetadata(t *testing.T) {
	cases := []struct {
		label   string
		pricing map[string]any
	}{
		{
			"per_invocation missing unit_price",
			map[string]any{"pricing_model": "per_invocation", "billing_unit": "invocation"},
		},
		{
			"per_unit missing billing_unit",
			map[string]any{
				"pricing_model": "per_unit",
				"unit_price": map[string]any{
					"units":    float64(25),
					"currency": "USD",
				},
			},
		},
		{
			"hybrid missing base_price",
			map[string]any{
				"pricing_model": "hybrid",
				"unit_price": map[string]any{
					"units":    float64(25),
					"currency": "USD",
				},
				"billing_unit": "document",
			},
		},
		{
			"padded billing_unit",
			map[string]any{
				"pricing_model": "per_invocation",
				"unit_price": map[string]any{
					"units":    float64(25),
					"currency": "USD",
				},
				"billing_unit": " invocation",
			},
		},
		{
			"invalid currency",
			map[string]any{
				"pricing_model": "per_invocation",
				"unit_price": map[string]any{
					"units":    float64(25),
					"currency": "usd",
				},
				"billing_unit": "invocation",
			},
		},
		{
			"units above u64 max",
			map[string]any{
				"pricing_model": "per_invocation",
				"unit_price": map[string]any{
					"units":    json.Number("18446744073709551616"),
					"currency": "USD",
				},
				"billing_unit": "invocation",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			signedManifest := pricedSignedManifest()
			tool := signedManifest["manifest"].(map[string]any)["tools"].([]any)[0].(map[string]any)
			tool["pricing"] = tc.pricing

			verification, err := invariants.VerifySignedManifest(signedManifest)
			if err != nil {
				t.Fatalf("VerifySignedManifest returned error: %v", err)
			}
			if verification.StructureValid {
				t.Fatalf("%s pricing must be structurally invalid", tc.label)
			}
		})
	}
}

func TestManifestStructureAcceptsRustU64PricingUnits(t *testing.T) {
	signedManifest := pricedSignedManifest()
	tool := signedManifest["manifest"].(map[string]any)["tools"].([]any)[0].(map[string]any)
	pricing := tool["pricing"].(map[string]any)
	unitPrice := pricing["unit_price"].(map[string]any)
	unitPrice["units"] = json.Number("9223372036854775808")

	verification, err := invariants.VerifySignedManifest(signedManifest)
	if err != nil {
		t.Fatalf("VerifySignedManifest returned error: %v", err)
	}
	if !verification.StructureValid {
		t.Fatalf("Rust-valid u64 pricing units above int64 max must be structurally valid")
	}
}

func TestSignedManifestEnvelopeRejectsUnknownTopLevelFields(t *testing.T) {
	signedManifest := pricedSignedManifest()
	signedManifest["unsigned_policy_hint"] = map[string]any{"allow": true}

	verification, err := invariants.VerifySignedManifest(signedManifest)
	if err != nil {
		t.Fatalf("VerifySignedManifest returned error: %v", err)
	}
	if verification.StructureValid {
		t.Fatalf("signed manifest envelope with unknown top-level fields must be structurally invalid")
	}
}

func TestManifestStructureAcceptsValidRequiredPermissions(t *testing.T) {
	signedManifest := pricedSignedManifest()
	signedManifest["manifest"].(map[string]any)["required_permissions"] = map[string]any{
		"read_paths":            []any{"/tmp/in"},
		"write_paths":           []any{"/tmp/out"},
		"network_hosts":         []any{"api.example.com"},
		"environment_variables": []any{"TOKEN"},
	}

	verification, err := invariants.VerifySignedManifest(signedManifest)
	if err != nil {
		t.Fatalf("VerifySignedManifest returned error: %v", err)
	}
	if !verification.StructureValid {
		t.Fatalf("valid required_permissions must remain structurally valid")
	}
	if verification.SignatureValid {
		t.Fatalf("mutated required_permissions should invalidate the signature")
	}
	if !verification.EmbeddedPublicKeyValid {
		t.Fatalf("embedded public key validity must remain independent")
	}
}

func TestManifestStructureRejectsInvalidRequiredPermissions(t *testing.T) {
	cases := []struct {
		field  string
		values []any
	}{
		{"read_paths", []any{""}},
		{"write_paths", []any{" /tmp/out"}},
		{"network_hosts", []any{"api.example.com "}},
		{"environment_variables", []any{"TOKEN", "TOKEN"}},
		{"read_paths", []any{"/tmp/in\nbad"}},
		{"read_paths", []any{123}},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			signedManifest := pricedSignedManifest()
			signedManifest["manifest"].(map[string]any)["required_permissions"] = map[string]any{
				tc.field: tc.values,
			}

			verification, err := invariants.VerifySignedManifest(signedManifest)
			if err != nil {
				t.Fatalf("VerifySignedManifest returned error: %v", err)
			}
			if verification.StructureValid {
				t.Fatalf("%s values %#v must be structurally invalid", tc.field, tc.values)
			}
			if verification.SignatureValid {
				t.Fatalf("mutated required_permissions should invalidate the signature")
			}
			if !verification.EmbeddedPublicKeyValid {
				t.Fatalf("embedded public key validity must remain independent")
			}
		})
	}
}

func TestManifestStructureRejectsMalformedRequiredPermissionsObject(t *testing.T) {
	unknownField := pricedSignedManifest()
	unknownField["manifest"].(map[string]any)["required_permissions"] = map[string]any{
		"unknown": []any{"/tmp"},
	}
	unknownVerification, err := invariants.VerifySignedManifest(unknownField)
	if err != nil {
		t.Fatalf("VerifySignedManifest returned error for unknown field: %v", err)
	}
	if unknownVerification.StructureValid {
		t.Fatalf("unknown required_permissions field must be structurally invalid")
	}

	nonArrayValues := pricedSignedManifest()
	nonArrayValues["manifest"].(map[string]any)["required_permissions"] = map[string]any{
		"read_paths": "/tmp",
	}
	nonArrayVerification, err := invariants.VerifySignedManifest(nonArrayValues)
	if err != nil {
		t.Fatalf("VerifySignedManifest returned error for non-array value: %v", err)
	}
	if nonArrayVerification.StructureValid {
		t.Fatalf("non-array required_permissions value must be structurally invalid")
	}
}

func TestSignedManifestVerificationIsFailSoftForMalformedEnvelopes(t *testing.T) {
	for _, signedManifest := range []map[string]any{
		{},
		{"manifest": nil, "signature": "", "signer_key": ""},
	} {
		verification, err := invariants.VerifySignedManifest(signedManifest)
		if err != nil {
			t.Fatalf("VerifySignedManifest returned error: %v", err)
		}
		if verification.StructureValid {
			t.Fatalf("malformed envelope must be structurally invalid")
		}
		if verification.SignatureValid {
			t.Fatalf("malformed envelope must not verify signature")
		}
		if verification.EmbeddedPublicKeyValid {
			t.Fatalf("malformed envelope must not report a valid embedded public key")
		}
		if verification.EmbeddedPublicKeyMatchesSigner {
			t.Fatalf("malformed envelope must not report public key match")
		}
	}
}

func TestManifestStructureRejectsMissingRequiredToolFieldsAndUnknownNestedFields(t *testing.T) {
	missingDescription := pricedSignedManifest()
	delete(missingDescription["manifest"].(map[string]any)["tools"].([]any)[0].(map[string]any), "description")
	missingDescriptionVerification, err := invariants.VerifySignedManifest(missingDescription)
	if err != nil {
		t.Fatalf("VerifySignedManifest returned error for missing description: %v", err)
	}
	if missingDescriptionVerification.StructureValid {
		t.Fatalf("missing description must be structurally invalid")
	}

	missingSideEffects := pricedSignedManifest()
	delete(missingSideEffects["manifest"].(map[string]any)["tools"].([]any)[0].(map[string]any), "has_side_effects")
	missingSideEffectsVerification, err := invariants.VerifySignedManifest(missingSideEffects)
	if err != nil {
		t.Fatalf("VerifySignedManifest returned error for missing has_side_effects: %v", err)
	}
	if missingSideEffectsVerification.StructureValid {
		t.Fatalf("missing has_side_effects must be structurally invalid")
	}

	unknownManifestField := pricedSignedManifest()
	unknownManifestField["manifest"].(map[string]any)["unsigned_policy_hint"] = true
	unknownManifestVerification, err := invariants.VerifySignedManifest(unknownManifestField)
	if err != nil {
		t.Fatalf("VerifySignedManifest returned error for unknown manifest field: %v", err)
	}
	if unknownManifestVerification.StructureValid {
		t.Fatalf("unknown manifest field must be structurally invalid")
	}

	unknownToolField := pricedSignedManifest()
	unknownToolField["manifest"].(map[string]any)["tools"].([]any)[0].(map[string]any)["annotations"] = map[string]any{}
	unknownToolVerification, err := invariants.VerifySignedManifest(unknownToolField)
	if err != nil {
		t.Fatalf("VerifySignedManifest returned error for unknown tool field: %v", err)
	}
	if unknownToolVerification.StructureValid {
		t.Fatalf("unknown tool field must be structurally invalid")
	}

	unknownPricingField := pricedSignedManifest()
	unknownPricingField["manifest"].(map[string]any)["tools"].([]any)[0].(map[string]any)["pricing"].(map[string]any)["experimental_discount"] = 10
	unknownPricingVerification, err := invariants.VerifySignedManifest(unknownPricingField)
	if err != nil {
		t.Fatalf("VerifySignedManifest returned error for unknown pricing field: %v", err)
	}
	if unknownPricingVerification.StructureValid {
		t.Fatalf("unknown pricing field must be structurally invalid")
	}
}

func TestManifestStructureValidatesServerToolsAndLatencyHintValues(t *testing.T) {
	valid := pricedSignedManifest()
	valid["manifest"].(map[string]any)["server_tools"] = []any{"bash", "text_editor"}
	valid["manifest"].(map[string]any)["tools"].([]any)[0].(map[string]any)["latency_hint"] = "fast"
	validVerification, err := invariants.VerifySignedManifest(valid)
	if err != nil {
		t.Fatalf("VerifySignedManifest returned error for valid server_tools: %v", err)
	}
	if !validVerification.StructureValid {
		t.Fatalf("valid server_tools and latency_hint must be structurally valid")
	}

	duplicateServerTool := pricedSignedManifest()
	duplicateServerTool["manifest"].(map[string]any)["server_tools"] = []any{"bash", "bash"}
	duplicateVerification, err := invariants.VerifySignedManifest(duplicateServerTool)
	if err != nil {
		t.Fatalf("VerifySignedManifest returned error for duplicate server_tools: %v", err)
	}
	if duplicateVerification.StructureValid {
		t.Fatalf("duplicate server_tools must be structurally invalid")
	}

	unknownServerTool := pricedSignedManifest()
	unknownServerTool["manifest"].(map[string]any)["server_tools"] = []any{"database"}
	unknownVerification, err := invariants.VerifySignedManifest(unknownServerTool)
	if err != nil {
		t.Fatalf("VerifySignedManifest returned error for unknown server_tool: %v", err)
	}
	if unknownVerification.StructureValid {
		t.Fatalf("unknown server_tool must be structurally invalid")
	}

	invalidLatencyHint := pricedSignedManifest()
	invalidLatencyHint["manifest"].(map[string]any)["tools"].([]any)[0].(map[string]any)["latency_hint"] = "immediate"
	invalidLatencyVerification, err := invariants.VerifySignedManifest(invalidLatencyHint)
	if err != nil {
		t.Fatalf("VerifySignedManifest returned error for invalid latency_hint: %v", err)
	}
	if invalidLatencyVerification.StructureValid {
		t.Fatalf("invalid latency_hint must be structurally invalid")
	}
}
