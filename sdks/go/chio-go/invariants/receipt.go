package invariants

type ReceiptVerification struct {
	Decision           string `json:"decision"`
	Authorized         bool   `json:"authorized"`
	BoundaryClass      string `json:"boundary_class"`
	Ok                 bool   `json:"ok"`
	ParameterHashValid bool   `json:"parameter_hash_valid"`
	ReceiptIDValid     bool   `json:"receipt_id_valid"`
	ReceiptKind        string `json:"receipt_kind"`
	Result             string `json:"result"`
	SignerKeyHex       string `json:"signer_key_hex"`
	SignerTrusted      bool   `json:"signer_trusted"`
	SignatureValid     bool   `json:"signature_valid"`
	TrustLevel         string `json:"trust_level"`
}

func ParseReceiptJSON(input string) (map[string]any, error) {
	value, err := ParseJSONText(input)
	if err != nil {
		return nil, err
	}
	receipt, ok := value.(map[string]any)
	if !ok {
		return nil, newInvariantError("json", "receipt must be a JSON object")
	}
	return receipt, nil
}

func ReceiptBodyCanonicalJSON(receipt map[string]any) (string, error) {
	body := make(map[string]any, len(receipt))
	for key, value := range receipt {
		if key == "algorithm" || key == "signature" {
			continue
		}
		body[key] = value
	}
	return CanonicalizeJSON(body)
}

func ReceiptSigningBodyCanonicalJSON(receipt map[string]any) (string, error) {
	receiptID, err := stringField(receipt, "id")
	if err != nil {
		return "", err
	}
	idInput, err := receiptIDInput(receipt)
	if err != nil {
		return "", err
	}
	return CanonicalizeJSON(map[string]any{
		"id":   receiptID,
		"body": idInput,
	})
}

func VerifyReceipt(receipt map[string]any) (ReceiptVerification, error) {
	return VerifyReceiptWithTrustedSigners(receipt, nil)
}

func VerifyReceiptWithTrustedSigners(
	receipt map[string]any,
	trustedSigners []string,
) (ReceiptVerification, error) {
	body, err := ReceiptSigningBodyCanonicalJSON(receipt)
	if err != nil {
		return ReceiptVerification{}, err
	}
	kernelKey, err := stringField(receipt, "kernel_key")
	if err != nil {
		return ReceiptVerification{}, err
	}
	signature, err := stringField(receipt, "signature")
	if err != nil {
		return ReceiptVerification{}, err
	}
	signatureValid, err := VerifyUTF8MessageEd25519(body, kernelKey, signature)
	if err != nil {
		return ReceiptVerification{}, err
	}
	receiptID, err := stringField(receipt, "id")
	if err != nil {
		return ReceiptVerification{}, err
	}
	computedReceiptID, err := contentAddressedReceiptID(receipt)
	if err != nil {
		return ReceiptVerification{}, err
	}
	receiptIDValid := receiptID == computedReceiptID
	if !receiptIDValid {
		signatureValid = false
	}
	action, err := mapField(receipt, "action")
	if err != nil {
		return ReceiptVerification{}, err
	}
	parameters, ok := action["parameters"]
	if !ok {
		return ReceiptVerification{}, newInvariantError("receipt", "missing field parameters")
	}
	renderedParameters, err := CanonicalizeJSON(parameters)
	if err != nil {
		return ReceiptVerification{}, err
	}
	expectedParameterHash := SHA256HexUTF8(renderedParameters)
	actualParameterHash, err := stringField(action, "parameter_hash")
	if err != nil {
		return ReceiptVerification{}, err
	}
	verdict := "none"
	if decision, ok := receipt["decision"]; ok && decision != nil {
		decisionMap, ok := decision.(map[string]any)
		if !ok {
			return ReceiptVerification{}, newInvariantError("receipt", "field decision must be an object")
		}
		var err error
		verdict, err = stringField(decisionMap, "verdict")
		if err != nil {
			return ReceiptVerification{}, err
		}
	}
	receiptKind, boundaryClass := receiptSemantics(receipt)
	trustLevel, _ := receipt["trust_level"].(string)
	if !semanticallySignable(receipt, verdict) {
		signatureValid = false
	}
	semanticAuthorized := receiptKind == "mediated_decision" && boundaryClass == "prevent" && verdict == "allow"
	signerTrusted := false
	if len(trustedSigners) > 0 {
		for _, signer := range trustedSigners {
			if PublicKeyHexMatches(signer, kernelKey) {
				signerTrusted = true
				break
			}
		}
	}
	parameterHashValid := actualParameterHash == expectedParameterHash
	authorized := semanticAuthorized && signatureValid && parameterHashValid && receiptIDValid && signerTrusted
	return ReceiptVerification{
		Decision:           verdict,
		Authorized:         authorized,
		BoundaryClass:      boundaryClass,
		Ok:                 signatureValid && parameterHashValid && receiptIDValid && signerTrusted,
		ParameterHashValid: parameterHashValid,
		ReceiptIDValid:     receiptIDValid,
		ReceiptKind:        receiptKind,
		Result:             resultLabel(receiptKind, boundaryClass, verdict),
		SignerKeyHex:       kernelKey,
		SignerTrusted:      signerTrusted,
		SignatureValid:     signatureValid,
		TrustLevel:         trustLevel,
	}, nil
}

func VerifyReceiptJSON(input string) (ReceiptVerification, error) {
	receipt, err := ParseReceiptJSON(input)
	if err != nil {
		return ReceiptVerification{}, err
	}
	return VerifyReceipt(receipt)
}

func contentAddressedReceiptID(receipt map[string]any) (string, error) {
	input, err := receiptIDInput(receipt)
	if err != nil {
		return "", err
	}
	canonical, err := CanonicalizeJSON(input)
	if err != nil {
		return "", err
	}
	return SHA256HexUTF8(canonical), nil
}

func receiptIDInput(receipt map[string]any) (map[string]any, error) {
	input := map[string]any{}
	for _, key := range []string{
		"timestamp",
		"capability_id",
		"tool_server",
		"tool_name",
		"action",
		"receipt_kind",
		"boundary_class",
		"tool_origin",
		"redaction_mode",
		"content_hash",
		"policy_hash",
		"kernel_key",
	} {
		value, ok := receipt[key]
		if !ok {
			return nil, newInvariantError("receipt_id", "missing field "+key)
		}
		input[key] = value
	}
	if decision, ok := receipt["decision"]; ok && decision != nil {
		input["decision"] = decision
	}
	if observationOutcome, ok := receipt["observation_outcome"]; ok && observationOutcome != nil {
		input["observation_outcome"] = observationOutcome
	}
	if actorChain, ok := receipt["actor_chain"]; ok {
		if values, ok := actorChain.([]any); ok && len(values) > 0 {
			input["actor_chain"] = actorChain
		}
	}
	if evidence, ok := receipt["evidence"]; ok {
		if values, ok := evidence.([]any); ok && len(values) > 0 {
			input["evidence"] = evidence
		}
	}
	if metadata, ok := receipt["metadata"]; ok && metadata != nil {
		input["metadata"] = metadata
	}
	input["trust_level"] = receipt["trust_level"]
	if tenantID, ok := receipt["tenant_id"]; ok && tenantID != nil {
		input["tenant_id"] = tenantID
	}
	return input, nil
}

func receiptSemantics(receipt map[string]any) (string, string) {
	receiptKind, _ := receipt["receipt_kind"].(string)
	boundaryClass, _ := receipt["boundary_class"].(string)
	return receiptKind, boundaryClass
}

func resultLabel(receiptKind string, boundaryClass string, decision string) string {
	if receiptKind == "mediated_decision" && boundaryClass == "prevent" && decision == "allow" {
		return "Authorized"
	}
	switch receiptKind {
	case "trace_observation":
		return "Observed"
	case "advisory_evaluation":
		return "Advisory"
	}
	switch decision {
	case "allow":
		return "Allowed"
	case "deny":
		return "Denied"
	case "cancelled":
		return "Cancelled"
	case "none":
		return "Invalid"
	default:
		return "Incomplete"
	}
}

func validObservationOutcome(value any) bool {
	outcome, ok := value.(string)
	if !ok {
		return false
	}
	switch outcome {
	case "observed", "evaluated", "dropped":
		return true
	default:
		return false
	}
}

func semanticallySignable(receipt map[string]any, decision string) bool {
	receiptKind, boundaryClass := receiptSemantics(receipt)
	trustLevel, _ := receipt["trust_level"].(string)
	observationOutcome := receipt["observation_outcome"]
	switch receiptKind {
	case "mediated_decision":
		return boundaryClass == "prevent" &&
			trustLevel == "mediated" &&
			decision != "none" &&
			observationOutcome == nil
	case "trace_observation":
		return boundaryClass == "detect_only" &&
			trustLevel == "verified" &&
			decision == "none" &&
			validObservationOutcome(observationOutcome)
	case "advisory_evaluation":
		return boundaryClass == "advisory_only" &&
			trustLevel == "advisory" &&
			decision == "none" &&
			validObservationOutcome(observationOutcome)
	default:
		return false
	}
}
