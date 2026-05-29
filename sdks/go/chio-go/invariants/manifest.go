package invariants

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
	manifest, err := mapField(signedManifest, "manifest")
	if err != nil {
		return ManifestVerification{}, err
	}
	signature, err := stringField(signedManifest, "signature")
	if err != nil {
		return ManifestVerification{}, err
	}
	signerKey, err := stringField(signedManifest, "signer_key")
	if err != nil {
		return ManifestVerification{}, err
	}
	body, err := SignedManifestBodyCanonicalJSON(signedManifest)
	if err != nil {
		return ManifestVerification{}, err
	}
	signatureValid, err := VerifyUTF8MessageEd25519(body, signerKey, signature)
	if err != nil {
		return ManifestVerification{}, err
	}
	embeddedPublicKey, err := stringField(manifest, "public_key")
	if err != nil {
		return ManifestVerification{}, err
	}
	embeddedPublicKeyValid := IsValidEd25519PublicKeyHex(embeddedPublicKey)
	return ManifestVerification{
		EmbeddedPublicKeyMatchesSigner: embeddedPublicKeyValid && PublicKeyHexMatches(embeddedPublicKey, signerKey),
		EmbeddedPublicKeyValid:         embeddedPublicKeyValid,
		SignatureValid:                 signatureValid,
		StructureValid:                 validateManifestStructure(manifest),
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
	schema, ok := manifest["schema"].(string)
	if !ok || schema != "chio.manifest.v1" {
		return false
	}
	tools, ok := manifest["tools"].([]any)
	if !ok || len(tools) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(tools))
	for _, entry := range tools {
		tool, ok := entry.(map[string]any)
		if !ok {
			return false
		}
		name, ok := tool["name"].(string)
		if !ok || name == "" {
			return false
		}
		if _, exists := seen[name]; exists {
			return false
		}
		seen[name] = struct{}{}
	}
	return true
}
