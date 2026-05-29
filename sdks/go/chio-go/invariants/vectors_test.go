package invariants_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/backbay-labs/chio/sdks/go/chio-go/invariants"
)

const vectorRoot = "../../../../tests/bindings/vectors"

type canonicalVectors struct {
	Cases []struct {
		CanonicalJSON string `json:"canonical_json"`
		ID            string `json:"id"`
		InputJSON     string `json:"input_json"`
	} `json:"cases"`
}

type hashingVectors struct {
	Cases []struct {
		ID        string `json:"id"`
		InputUTF8 string `json:"input_utf8"`
		SHA256Hex string `json:"sha256_hex"`
	} `json:"cases"`
}

type signingVectors struct {
	JSONCases []struct {
		CanonicalJSON  string `json:"canonical_json"`
		ExpectedVerify bool   `json:"expected_verify"`
		ID             string `json:"id"`
		InputJSON      string `json:"input_json"`
		PublicKeyHex   string `json:"public_key_hex"`
		SignatureHex   string `json:"signature_hex"`
	} `json:"json_cases"`
	SigningKeySeedHex string `json:"signing_key_seed_hex"`
	UTF8Cases         []struct {
		ExpectedVerify bool   `json:"expected_verify"`
		ID             string `json:"id"`
		InputUTF8      string `json:"input_utf8"`
		PublicKeyHex   string `json:"public_key_hex"`
		SignatureHex   string `json:"signature_hex"`
	} `json:"utf8_cases"`
}

type receiptVectors struct {
	Cases []struct {
		Expected                 invariants.ReceiptVerification `json:"expected"`
		ID                       string                         `json:"id"`
		Receipt                  map[string]any                 `json:"receipt"`
		ReceiptBodyCanonicalJSON string                         `json:"receipt_body_canonical_json"`
	} `json:"cases"`
	SigningKeySeedHex string `json:"signing_key_seed_hex"`
}

type capabilityVectors struct {
	Cases []struct {
		Capability                  map[string]any                    `json:"capability"`
		CapabilityBodyCanonicalJSON string                            `json:"capability_body_canonical_json"`
		Expected                    invariants.CapabilityVerification `json:"expected"`
		ID                          string                            `json:"id"`
		VerifyAt                    int64                             `json:"verify_at"`
	} `json:"cases"`
}

type manifestVectors struct {
	Cases []struct {
		Expected                  invariants.ManifestVerification `json:"expected"`
		ID                        string                          `json:"id"`
		ManifestBodyCanonicalJSON string                          `json:"manifest_body_canonical_json"`
		SignedManifest            map[string]any                  `json:"signed_manifest"`
	} `json:"cases"`
}

func TestCanonicalVectors(t *testing.T) {
	var vectors canonicalVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "canonical", "v1.json"), &vectors)
	for _, testCase := range vectors.Cases {
		t.Run(testCase.ID, func(t *testing.T) {
			rendered, err := invariants.CanonicalizeJSONString(testCase.InputJSON)
			if err != nil {
				t.Fatalf("CanonicalizeJSONString returned error: %v", err)
			}
			if rendered != testCase.CanonicalJSON {
				t.Fatalf("unexpected canonical json: %s", rendered)
			}
		})
	}
}

func TestHashingVectors(t *testing.T) {
	var vectors hashingVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "hashing", "v1.json"), &vectors)
	for _, testCase := range vectors.Cases {
		t.Run(testCase.ID, func(t *testing.T) {
			rendered := invariants.SHA256HexUTF8(testCase.InputUTF8)
			if rendered != testCase.SHA256Hex {
				t.Fatalf("unexpected sha256: %s", rendered)
			}
		})
	}
}

func TestSigningVectors(t *testing.T) {
	var vectors signingVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "signing", "v1.json"), &vectors)
	for _, testCase := range vectors.UTF8Cases {
		t.Run(testCase.ID, func(t *testing.T) {
			verified, err := invariants.VerifyUTF8MessageEd25519(
				testCase.InputUTF8,
				testCase.PublicKeyHex,
				testCase.SignatureHex,
			)
			if err != nil {
				t.Fatalf("VerifyUTF8MessageEd25519 returned error: %v", err)
			}
			if verified != testCase.ExpectedVerify {
				t.Fatalf("unexpected utf8 verification result: %v", verified)
			}
		})
	}
	for _, testCase := range vectors.JSONCases {
		t.Run(testCase.ID, func(t *testing.T) {
			rendered, err := invariants.CanonicalizeJSONString(testCase.InputJSON)
			if err != nil {
				t.Fatalf("CanonicalizeJSONString returned error: %v", err)
			}
			if rendered != testCase.CanonicalJSON {
				t.Fatalf("unexpected canonical json: %s", rendered)
			}
			verified, err := invariants.VerifyJSONStringSignatureEd25519(
				testCase.InputJSON,
				testCase.PublicKeyHex,
				testCase.SignatureHex,
			)
			if err != nil {
				t.Fatalf("VerifyJSONStringSignatureEd25519 returned error: %v", err)
			}
			if verified != testCase.ExpectedVerify {
				t.Fatalf("unexpected json verification result: %v", verified)
			}
		})
	}
	signedUTF8, err := invariants.SignUTF8MessageEd25519("hello chio", vectors.SigningKeySeedHex)
	if err != nil {
		t.Fatalf("SignUTF8MessageEd25519 returned error: %v", err)
	}
	if signedUTF8.PublicKeyHex != vectors.UTF8Cases[0].PublicKeyHex || signedUTF8.SignatureHex != vectors.UTF8Cases[0].SignatureHex {
		t.Fatalf("unexpected utf8 signing output: %#v", signedUTF8)
	}
	signedJSON, err := invariants.SignJSONStringEd25519(vectors.JSONCases[0].InputJSON, vectors.SigningKeySeedHex)
	if err != nil {
		t.Fatalf("SignJSONStringEd25519 returned error: %v", err)
	}
	if signedJSON.CanonicalJSON != vectors.JSONCases[0].CanonicalJSON || signedJSON.PublicKeyHex != vectors.JSONCases[0].PublicKeyHex || signedJSON.SignatureHex != vectors.JSONCases[0].SignatureHex {
		t.Fatalf("unexpected json signing output: %#v", signedJSON)
	}
}

func TestReceiptVectors(t *testing.T) {
	var vectors receiptVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "receipt", "v1.json"), &vectors)
	for _, testCase := range vectors.Cases {
		t.Run(testCase.ID, func(t *testing.T) {
			renderedBody, err := invariants.ReceiptBodyCanonicalJSON(testCase.Receipt)
			if err != nil {
				t.Fatalf("ReceiptBodyCanonicalJSON returned error: %v", err)
			}
			if renderedBody != testCase.ReceiptBodyCanonicalJSON {
				t.Fatalf("unexpected receipt body: %s", renderedBody)
			}
			verification, err := invariants.VerifyReceipt(testCase.Receipt)
			if err != nil {
				t.Fatalf("VerifyReceipt returned error: %v", err)
			}
			var verificationJSON map[string]any
			verificationBytes, err := json.Marshal(verification)
			if err != nil {
				t.Fatalf("Marshal receipt verification returned error: %v", err)
			}
			if err := json.Unmarshal(verificationBytes, &verificationJSON); err != nil {
				t.Fatalf("Unmarshal receipt verification returned error: %v", err)
			}
			if verificationJSON["trust_level"] != testCase.Receipt["trust_level"] {
				t.Fatalf("unexpected receipt trust level: %#v", verificationJSON)
			}
			if verification != testCase.Expected {
				t.Fatalf("unexpected receipt verification: %#v", verification)
			}
		})
	}
}

func TestReceiptVectorsSupportTrustedSigners(t *testing.T) {
	var vectors receiptVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "receipt", "v1.json"), &vectors)
	for _, testCase := range vectors.Cases {
		if testCase.ID != "allow_receipt" {
			continue
		}
		kernelKey, ok := testCase.Receipt["kernel_key"].(string)
		if !ok {
			t.Fatalf("allow receipt missing kernel_key")
		}
		verification, err := invariants.VerifyReceiptWithTrustedSigners(testCase.Receipt, []string{kernelKey})
		if err != nil {
			t.Fatalf("VerifyReceiptWithTrustedSigners returned error: %v", err)
		}
		if !verification.SignerTrusted || !verification.Ok || !verification.Authorized {
			t.Fatalf("trusted signer verification did not authorize: %#v", verification)
		}
		return
	}
	t.Fatalf("allow_receipt vector not found")
}

func TestReceiptSemanticsIgnoreLegacyMetadataPayloads(t *testing.T) {
	var vectors receiptVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "receipt", "v1.json"), &vectors)
	for _, testCase := range vectors.Cases {
		if testCase.ID != "allow_receipt" {
			continue
		}
		receipt := cloneMap(t, testCase.Receipt)
		receipt["metadata"] = map[string]any{
			"receipt_semantics": map[string]any{
				"receiptKind":   "trace_observation",
				"boundaryClass": "detect_only",
			},
		}
		kernelKey, ok := receipt["kernel_key"].(string)
		if !ok {
			t.Fatalf("allow receipt missing kernel_key")
		}
		verification, err := invariants.VerifyReceiptWithTrustedSigners(receipt, []string{kernelKey})
		if err != nil {
			t.Fatalf("VerifyReceipt returned error: %v", err)
		}
		if verification.ReceiptKind != "mediated_decision" || verification.BoundaryClass != "prevent" {
			t.Fatalf("legacy metadata semantics affected verification: %#v", verification)
		}
		if verification.ReceiptIDValid || verification.SignatureValid || verification.Authorized {
			t.Fatalf("mutated signed metadata unexpectedly remained authoritative: %#v", verification)
		}
		return
	}
	t.Fatalf("allow_receipt vector not found")
}

func TestReceiptSignatureValidFailsWhenContentAddressedIDMismatches(t *testing.T) {
	var vectors receiptVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "receipt", "v1.json"), &vectors)
	for _, testCase := range vectors.Cases {
		if testCase.ID != "allow_receipt" {
			continue
		}
		receipt := cloneMap(t, testCase.Receipt)
		receipt["id"] = "0000000000000000000000000000000000000000000000000000000000000000"
		body, err := invariants.ReceiptSigningBodyCanonicalJSON(receipt)
		if err != nil {
			t.Fatalf("ReceiptSigningBodyCanonicalJSON returned error: %v", err)
		}
		signed, err := invariants.SignJSONStringEd25519(body, vectors.SigningKeySeedHex)
		if err != nil {
			t.Fatalf("SignJSONStringEd25519 returned error: %v", err)
		}
		receipt["signature"] = signed.SignatureHex
		verification, err := invariants.VerifyReceipt(receipt)
		if err != nil {
			t.Fatalf("VerifyReceipt returned error: %v", err)
		}
		if verification.ReceiptIDValid || verification.SignatureValid || verification.Ok {
			t.Fatalf("mismatched receipt id must invalidate signature status: %#v", verification)
		}
		return
	}
	t.Fatalf("allow_receipt vector not found")
}

func TestCapabilityVectors(t *testing.T) {
	var vectors capabilityVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "capability", "v1.json"), &vectors)
	for _, testCase := range vectors.Cases {
		t.Run(testCase.ID, func(t *testing.T) {
			renderedBody, err := invariants.CapabilityBodyCanonicalJSON(testCase.Capability)
			if err != nil {
				t.Fatalf("CapabilityBodyCanonicalJSON returned error: %v", err)
			}
			if renderedBody != testCase.CapabilityBodyCanonicalJSON {
				t.Fatalf("unexpected capability body: %s", renderedBody)
			}
			verification, err := invariants.VerifyCapability(testCase.Capability, testCase.VerifyAt)
			if err != nil {
				t.Fatalf("VerifyCapability returned error: %v", err)
			}
			if verification != testCase.Expected {
				t.Fatalf("unexpected capability verification: %#v", verification)
			}
		})
	}
}

func TestManifestVectors(t *testing.T) {
	var vectors manifestVectors
	loadVectorFile(t, filepath.Join(vectorRoot, "manifest", "v1.json"), &vectors)
	for _, testCase := range vectors.Cases {
		t.Run(testCase.ID, func(t *testing.T) {
			renderedBody, err := invariants.SignedManifestBodyCanonicalJSON(testCase.SignedManifest)
			if err != nil {
				t.Fatalf("SignedManifestBodyCanonicalJSON returned error: %v", err)
			}
			if renderedBody != testCase.ManifestBodyCanonicalJSON {
				t.Fatalf("unexpected manifest body: %s", renderedBody)
			}
			verification, err := invariants.VerifySignedManifest(testCase.SignedManifest)
			if err != nil {
				t.Fatalf("VerifySignedManifest returned error: %v", err)
			}
			if verification != testCase.Expected {
				t.Fatalf("unexpected manifest verification: %#v", verification)
			}
		})
	}
}

func cloneMap(t *testing.T, input map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("failed to marshal clone input: %v", err)
	}
	var output map[string]any
	if err := json.Unmarshal(encoded, &output); err != nil {
		t.Fatalf("failed to unmarshal clone output: %v", err)
	}
	return output
}

func loadVectorFile(t *testing.T, path string, target any) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open %s: %v", path, err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("failed to decode %s: %v", path, err)
	}
}
