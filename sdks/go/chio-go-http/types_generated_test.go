package chio

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type protocolPrimitiveFixtureCase struct {
	Name       string          `json:"name"`
	SchemaFile string          `json:"schema_file"`
	Valid      bool            `json:"valid"`
	Instance   json.RawMessage `json:"instance"`
}

func decodeProtocolPrimitive(schemaFile string, payload []byte) (any, error) {
	var target any
	switch schemaFile {
	case "capability/token.schema.json":
		target = &CapabilityToken{}
	case "capability/aggregate-invocation-budget.schema.json":
		var discriminator struct {
			Scope string `json:"scope"`
		}
		if err := json.Unmarshal(payload, &discriminator); err != nil {
			return nil, err
		}
		switch discriminator.Scope {
		case "capability":
			target = &CapabilityAggregateInvocationBudget0{}
		case "delegation_family":
			target = &CapabilityAggregateInvocationBudget1{}
		default:
			return nil, fmt.Errorf("unknown aggregate budget scope %q", discriminator.Scope)
		}
	case "capability/threshold-approval-proposal.schema.json":
		target = &CapabilityThresholdApprovalProposal{}
	case "capability/governed-approval-token.schema.json":
		target = &CapabilityGovernedApprovalToken{}
	case "agent/active-response-governed-intent.schema.json":
		target = &AgentActiveResponseGovernedIntent{}
	case "kernel/combined-capture-metadata.schema.json":
		target = &KernelCombinedCaptureMetadata{}
	case "capability/supplemental-authorization.schema.json":
		target = &CapabilitySupplementalAuthorization{}
	default:
		return nil, fmt.Errorf("unmapped protocol-primitives fixture schema %q", schemaFile)
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON after protocol primitive: %w", err)
	}
	return target, nil
}

func TestGeneratedProtocolPrimitivesConsumeSharedFixtures(t *testing.T) {
	corpusPath := filepath.Join("..", "..", "..", "tests", "bindings", "fixtures", "protocol-primitives-v1.json")
	corpusBytes, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("read protocol-primitives fixture corpus: %v", err)
	}
	var corpus struct {
		Cases []protocolPrimitiveFixtureCase `json:"cases"`
	}
	if err := json.Unmarshal(corpusBytes, &corpus); err != nil {
		t.Fatalf("parse protocol-primitives fixture corpus: %v", err)
	}

	for _, fixture := range corpus.Cases {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			parsed, err := decodeProtocolPrimitive(fixture.SchemaFile, fixture.Instance)
			if (err == nil) != fixture.Valid {
				t.Fatalf("generated Go fixture result mismatch: %v", err)
			}
			if !fixture.Valid {
				return
			}
			roundTrip, err := json.Marshal(parsed)
			if err != nil {
				t.Fatalf("marshal generated Go primitive: %v", err)
			}
			var want, got any
			if err := json.Unmarshal(fixture.Instance, &want); err != nil {
				t.Fatalf("parse expected fixture: %v", err)
			}
			if err := json.Unmarshal(roundTrip, &got); err != nil {
				t.Fatalf("parse round-trip fixture: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("generated Go round trip changed fixture\nwant: %#v\ngot:  %#v", want, got)
			}
		})
	}
}

func TestGeneratedCapabilityTokenUsesFixedWidthIntegers(t *testing.T) {
	maxInvocations := int64(1 << 40)
	token := CapabilityToken{
		Id:        "tok-1",
		Issuer:    "issuer",
		Subject:   "subject",
		IssuedAt:  1 << 40,
		ExpiresAt: 1<<40 + 60,
		Scope: CapabilityTokenChioScope{
			Grants: &[]CapabilityTokenToolGrant{
				{
					ServerId:       "srv",
					ToolName:       "tool",
					Operations:     []CapabilityTokenOperation{CapabilityTokenOperationInvoke},
					MaxInvocations: &maxInvocations,
				},
			},
		},
		Signature: "sig",
	}

	data, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("marshal token: %v", err)
	}
	jsonStr := string(data)
	for _, want := range []string{
		`"issued_at":1099511627776`,
		`"expires_at":1099511627836`,
		`"max_invocations":1099511627776`,
		`"operations":["invoke"]`,
	} {
		if !strings.Contains(jsonStr, want) {
			t.Fatalf("expected JSON to contain %s, got %s", want, jsonStr)
		}
	}

	var decoded CapabilityToken
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal token: %v", err)
	}
	if decoded.IssuedAt != token.IssuedAt || decoded.ExpiresAt != token.ExpiresAt {
		t.Fatalf("timestamp round-trip mismatch: got %d/%d", decoded.IssuedAt, decoded.ExpiresAt)
	}
	if decoded.Scope.Grants == nil || len(*decoded.Scope.Grants) != 1 {
		t.Fatalf("expected one decoded grant")
	}
	gotGrant := (*decoded.Scope.Grants)[0]
	if gotGrant.MaxInvocations == nil || *gotGrant.MaxInvocations != maxInvocations {
		t.Fatalf("max_invocations round-trip mismatch: got %v", gotGrant.MaxInvocations)
	}
}

func TestGeneratedCapabilityConstraintsPreserveValuePayload(t *testing.T) {
	value := interface{}("/safe")
	var constraint CapabilityTokenConstraint
	if err := constraint.FromCapabilityTokenGenericConstraint(CapabilityTokenGenericConstraint{
		Type:  "path_prefix",
		Value: &value,
	}); err != nil {
		t.Fatalf("construct generic constraint: %v", err)
	}
	token := CapabilityToken{
		Id:        "tok-constraint",
		Issuer:    "issuer",
		Subject:   "subject",
		IssuedAt:  1,
		ExpiresAt: 2,
		Scope: CapabilityTokenChioScope{
			Grants: &[]CapabilityTokenToolGrant{
				{
					ServerId:   "srv",
					ToolName:   "tool",
					Operations: []CapabilityTokenOperation{CapabilityTokenOperationInvoke},
					Constraints: &[]CapabilityTokenConstraint{
						constraint,
					},
				},
			},
		},
		Signature: "sig",
	}

	data, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("marshal token: %v", err)
	}
	if !strings.Contains(string(data), `"value":"/safe"`) {
		t.Fatalf("constraint value was not serialized: %s", data)
	}

	var decoded CapabilityToken
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal token: %v", err)
	}
	grants := *decoded.Scope.Grants
	if grants[0].Constraints == nil {
		t.Fatalf("expected decoded constraints")
	}
	constraints := *grants[0].Constraints
	if len(constraints) != 1 {
		t.Fatalf("expected one value-carrying constraint")
	}
	generic, err := constraints[0].AsCapabilityTokenGenericConstraint()
	if err != nil || generic.Value == nil {
		t.Fatalf("decode generic constraint: %v", err)
	}
	if got, ok := (*generic.Value).(string); !ok || got != "/safe" {
		t.Fatalf("constraint value round-trip mismatch: %#v", *generic.Value)
	}
}

func TestGeneratedDiscriminatorFieldsAreTypedStrings(t *testing.T) {
	heartbeat := KernelHeartbeat{Type: KernelHeartbeatTypeHeartbeat}
	heartbeatJSON, err := json.Marshal(heartbeat)
	if err != nil {
		t.Fatalf("marshal heartbeat: %v", err)
	}
	if string(heartbeatJSON) != `{"type":"heartbeat"}` {
		t.Fatalf("unexpected heartbeat JSON: %s", heartbeatJSON)
	}

	decision := ReceiptRecordDecision1{
		Verdict: ReceiptRecordDecision1VerdictDeny,
		Reason:  "blocked",
		Guard:   "Guard",
	}
	decisionJSON, err := json.Marshal(decision)
	if err != nil {
		t.Fatalf("marshal decision: %v", err)
	}
	for _, want := range []string{
		`"verdict":"deny"`,
		`"reason":"blocked"`,
		`"guard":"Guard"`,
	} {
		if !strings.Contains(string(decisionJSON), want) {
			t.Fatalf("expected decision JSON to contain %s, got %s", want, decisionJSON)
		}
	}

	result := ResultStreamComplete{
		Status:      ResultStreamCompleteStatusStreamComplete,
		TotalChunks: 1 << 40,
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	if !strings.Contains(string(resultJSON), `"status":"stream_complete"`) {
		t.Fatalf("unexpected result JSON: %s", resultJSON)
	}

	errPayload := ResultErrError0{
		Code:   ResultErrError0CodeCapabilityDenied,
		Detail: "missing capability",
	}
	errJSON, err := json.Marshal(errPayload)
	if err != nil {
		t.Fatalf("marshal error payload: %v", err)
	}
	if !strings.Contains(string(errJSON), `"code":"capability_denied"`) {
		t.Fatalf("unexpected error JSON: %s", errJSON)
	}
}

func TestGeneratedProvenanceVerdictLinkVariantsPreserveRequiredPayload(t *testing.T) {
	deny := ProvenanceVerdictLink1{
		Verdict: ProvenanceVerdictLink1VerdictDeny,
		Reason:  "policy denied",
		Guard:   "pii_guard",
	}
	denyJSON, err := json.Marshal(deny)
	if err != nil {
		t.Fatalf("marshal deny verdict link: %v", err)
	}
	for _, want := range []string{
		`"verdict":"deny"`,
		`"reason":"policy denied"`,
		`"guard":"pii_guard"`,
	} {
		if !strings.Contains(string(denyJSON), want) {
			t.Fatalf("expected deny JSON to contain %s, got %s", want, denyJSON)
		}
	}

	cancel := ProvenanceVerdictLink2{
		Verdict: ProvenanceVerdictLink2VerdictCancel,
		Reason:  "operator cancelled",
	}
	cancelJSON, err := json.Marshal(cancel)
	if err != nil {
		t.Fatalf("marshal cancel verdict link: %v", err)
	}
	if !strings.Contains(string(cancelJSON), `"reason":"operator cancelled"`) {
		t.Fatalf("expected cancel JSON to preserve reason, got %s", cancelJSON)
	}

	incomplete := ProvenanceVerdictLink3{
		Verdict: ProvenanceVerdictLink3VerdictIncomplete,
		Reason:  "upstream interrupted",
	}
	incompleteJSON, err := json.Marshal(incomplete)
	if err != nil {
		t.Fatalf("marshal incomplete verdict link: %v", err)
	}
	if !strings.Contains(string(incompleteJSON), `"reason":"upstream interrupted"`) {
		t.Fatalf("expected incomplete JSON to preserve reason, got %s", incompleteJSON)
	}
}

func TestGeneratedJsonrpcResponseEnforcesOneOf(t *testing.T) {
	var decoded JsonrpcResponse
	err := json.Unmarshal([]byte(`{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {"ok": true},
		"error": {"code": -32603, "message": "internal"}
	}`), &decoded)
	if err == nil {
		t.Fatalf("expected result+error response to be rejected")
	}

	for name, payload := range map[string]string{
		"missing jsonrpc": `{"id":1,"result":{"ok":true}}`,
		"wrong jsonrpc":   `{"jsonrpc":"2.1","id":1,"result":{"ok":true}}`,
		"missing id":      `{"jsonrpc":"2.0","result":{"ok":true}}`,
	} {
		err = json.Unmarshal([]byte(payload), &decoded)
		if err == nil {
			t.Fatalf("expected %s JSON-RPC response to be rejected", name)
		}
	}

	err = json.Unmarshal([]byte(`{
		"jsonrpc": "2.0",
		"id": null,
		"result": {"ok": true}
	}`), &decoded)
	if err != nil {
		t.Fatalf("expected JSON-RPC response with null id to pass: %v", err)
	}

	var result interface{} = map[string]interface{}{"ok": true}
	_, err = json.Marshal(JsonrpcResponse{
		Jsonrpc: JsonrpcResponseJsonrpcN20,
		Result:  &result,
		Error: &struct {
			Code    int64        `json:"code"`
			Data    *interface{} `json:"data,omitempty"`
			Message string       `json:"message"`
		}{
			Code:    -32603,
			Message: "internal",
		},
	})
	if err == nil {
		t.Fatalf("expected marshaling result+error response to fail")
	}
}

func TestGeneratedJsonrpcResponseRejectsMalformedIdAndError(t *testing.T) {
	for name, payload := range map[string]string{
		"object id":        `{"jsonrpc":"2.0","id":{"nested":true},"result":{"ok":true}}`,
		"empty string id":  `{"jsonrpc":"2.0","id":"","result":{"ok":true}}`,
		"fractional id":    `{"jsonrpc":"2.0","id":1.25,"result":{"ok":true}}`,
		"unknown field":    `{"jsonrpc":"2.0","id":1,"result":{"ok":true},"extra":true}`,
		"empty error":      `{"jsonrpc":"2.0","id":1,"error":{}}`,
		"missing code":     `{"jsonrpc":"2.0","id":1,"error":{"message":"internal"}}`,
		"missing message":  `{"jsonrpc":"2.0","id":1,"error":{"code":-32603}}`,
		"empty message":    `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":""}}`,
		"non-integer code": `{"jsonrpc":"2.0","id":1,"error":{"code":-32603.5,"message":"internal"}}`,
		"unknown error field": `{
			"jsonrpc":"2.0",
			"id":1,
			"error":{"code":-32603,"message":"internal","extra":true}
		}`,
	} {
		err := json.Unmarshal([]byte(payload), &JsonrpcResponse{})
		if err == nil {
			t.Fatalf("expected JSON-RPC response with %s to be rejected", name)
		}
	}
}

func TestGeneratedJsonrpcRequestAndNotificationValidation(t *testing.T) {
	requestCases := map[string]string{
		"missing jsonrpc": `{"id":1,"method":"tools/call","params":{}}`,
		"missing id":      `{"jsonrpc":"2.0","method":"tools/call","params":{}}`,
		"object id":       `{"jsonrpc":"2.0","id":{"bad":true},"method":"tools/call","params":{}}`,
		"empty method":    `{"jsonrpc":"2.0","id":1,"method":"","params":{}}`,
		"null params":     `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":null}`,
		"scalar params":   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"bad"}`,
		"unknown field":   `{"jsonrpc":"2.0","id":1,"method":"tools/call","extra":true}`,
	}
	for name, payload := range requestCases {
		err := json.Unmarshal([]byte(payload), &JsonrpcRequest{})
		if err == nil {
			t.Fatalf("expected JSON-RPC request with %s to be rejected", name)
		}
	}

	err := json.Unmarshal(
		[]byte(`{"jsonrpc":"2.0","id":null,"method":"tools/call","params":[]}`),
		&JsonrpcRequest{},
	)
	if err != nil {
		t.Fatalf("expected request with null id and array params to pass: %v", err)
	}
	_, err = json.Marshal(JsonrpcRequest{
		Jsonrpc: JsonrpcRequestJsonrpcN20,
		Method:  "tools/call",
	})
	if err != nil {
		t.Fatalf("expected request with nil id pointer to marshal as null id: %v", err)
	}

	notificationCases := map[string]string{
		"contains id":     `{"jsonrpc":"2.0","id":1,"method":"notifications/initialized"}`,
		"missing jsonrpc": `{"method":"notifications/initialized"}`,
		"empty method":    `{"jsonrpc":"2.0","method":""}`,
		"null params":     `{"jsonrpc":"2.0","method":"notifications/initialized","params":null}`,
		"scalar params":   `{"jsonrpc":"2.0","method":"notifications/initialized","params":true}`,
		"wrong jsonrpc":   `{"jsonrpc":"2.1","method":"notifications/initialized"}`,
		"unknown field":   `{"jsonrpc":"2.0","method":"notifications/initialized","extra":true}`,
	}
	for name, payload := range notificationCases {
		err := json.Unmarshal([]byte(payload), &JsonrpcNotification{})
		if err == nil {
			t.Fatalf("expected JSON-RPC notification with %s to be rejected", name)
		}
	}

	err = json.Unmarshal(
		[]byte(`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`),
		&JsonrpcNotification{},
	)
	if err != nil {
		t.Fatalf("expected valid notification to pass: %v", err)
	}
}

func TestGeneratedProvenanceVerdictLinkEnforcesVerdictFields(t *testing.T) {
	reason := "not allowed"
	guard := "pii_guard"
	_, err := json.Marshal(ProvenanceVerdictLink{
		ChainId:    "chain-1",
		Reason:     &reason,
		RenderedAt: 1,
		RequestId:  "req-1",
		Verdict:    ProvenanceVerdictLinkVerdictAllow,
	})
	if err == nil {
		t.Fatalf("expected allow verdict with reason to fail")
	}

	err = json.Unmarshal([]byte(`{
		"chainId": "chain-1",
		"renderedAt": 1,
		"requestId": "req-1",
		"verdict": "cancel",
		"reason": "operator cancelled",
		"guard": "pii_guard"
	}`), &ProvenanceVerdictLink{})
	if err == nil {
		t.Fatalf("expected cancel verdict with guard to fail")
	}

	for name, payload := range map[string]string{
		"missing chainId": `{
			"renderedAt": 1,
			"requestId": "req-1",
			"verdict": "allow"
		}`,
		"missing requestId": `{
			"chainId": "chain-1",
			"renderedAt": 1,
			"verdict": "allow"
		}`,
		"negative renderedAt": `{
			"chainId": "chain-1",
			"renderedAt": -1,
			"requestId": "req-1",
			"verdict": "allow"
		}`,
	} {
		err = json.Unmarshal([]byte(payload), &ProvenanceVerdictLink{})
		if err == nil {
			t.Fatalf("expected provenance verdict link with %s to fail", name)
		}
	}

	_, err = json.Marshal(ProvenanceVerdictLink{
		ChainId:    "chain-1",
		Guard:      &guard,
		Reason:     &reason,
		RenderedAt: 1,
		RequestId:  "req-1",
		Verdict:    ProvenanceVerdictLinkVerdictDeny,
	})
	if err != nil {
		t.Fatalf("expected deny verdict with reason and guard to pass: %v", err)
	}
}

func TestGeneratedProvenanceVerdictLinkConstrainsOptionalFields(t *testing.T) {
	for name, payload := range map[string]string{
		"empty receiptId": `{
			"chainId": "chain-1",
			"renderedAt": 1,
			"requestId": "req-1",
			"receiptId": "",
			"verdict": "allow"
		}`,
		"unknown evidenceClass": `{
			"chainId": "chain-1",
			"evidenceClass": "trusted",
			"renderedAt": 1,
			"requestId": "req-1",
			"verdict": "allow"
		}`,
	} {
		err := json.Unmarshal([]byte(payload), &ProvenanceVerdictLink{})
		if err == nil {
			t.Fatalf("expected provenance verdict link with %s to fail", name)
		}
	}

	receiptID := "rcpt-1"
	evidenceClass := ProvenanceVerdictLinkEvidenceClassVerified
	_, err := json.Marshal(ProvenanceVerdictLink{
		ChainId:       "chain-1",
		EvidenceClass: &evidenceClass,
		ReceiptId:     &receiptID,
		RenderedAt:    1,
		RequestId:     "req-1",
		Verdict:       ProvenanceVerdictLinkVerdictAllow,
	})
	if err != nil {
		t.Fatalf("expected non-empty receiptId and known evidenceClass to pass: %v", err)
	}
}
