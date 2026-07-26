package chio

import (
	"encoding/json"
	"fmt"
)

// Hand-written companion to types.go.
//
// types.go holds generated wire types; this file holds the hand-written
// Go shapes for the localhost contract between chio-go-http middleware
// and the Chio sidecar kernel.

// CallerIdentity represents the identity of the caller as extracted from
// the HTTP request. This is protocol-agnostic.
type CallerIdentity struct {
	// Stable identifier for the caller (e.g., user ID, service account).
	Subject string `json:"subject"`

	// How the caller authenticated.
	AuthMethod AuthMethod `json:"auth_method"`

	// Whether this identity has been cryptographically verified.
	Verified bool `json:"verified"`

	// Optional tenant or organization.
	Tenant string `json:"tenant,omitempty"`

	// Optional agent identifier when the caller is an AI agent.
	AgentID string `json:"agent_id,omitempty"`
}

// AuthMethod represents how a caller authenticated. Uses a tagged union
// matching the Rust serde format.
type AuthMethod struct {
	Method string `json:"method"`

	// Bearer fields
	TokenHash string `json:"token_hash,omitempty"`

	// API key fields
	KeyName string `json:"key_name,omitempty"`
	KeyHash string `json:"key_hash,omitempty"`

	// Cookie fields
	CookieName string `json:"cookie_name,omitempty"`
	CookieHash string `json:"cookie_hash,omitempty"`

	// mTLS fields
	SubjectDN   string `json:"subject_dn,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// AnonymousIdentity returns an anonymous caller identity.
func AnonymousIdentity() CallerIdentity {
	return CallerIdentity{
		Subject:    "anonymous",
		AuthMethod: AuthMethod{Method: "anonymous"},
		Verified:   false,
	}
}

// ChioHTTPRequest is the request model sent to the Chio sidecar for evaluation.
type ChioHTTPRequest struct {
	RequestID    string            `json:"request_id"`
	Method       string            `json:"method"`
	RoutePattern string            `json:"route_pattern"`
	Path         string            `json:"path"`
	Query        map[string]string `json:"query,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Caller       CallerIdentity    `json:"caller"`
	BodyHash     string            `json:"body_hash,omitempty"`
	BodyLength   int64             `json:"body_length"`
	SessionID    string            `json:"session_id,omitempty"`
	CapabilityID string            `json:"capability_id,omitempty"`
	Timestamp    int64             `json:"timestamp"`
}

// ChioToolCallRequest is the strongly typed native tool-call envelope.
//
// The generated OpenAPI alias for the JSON Schema union remains intentionally
// broad, so this SDK-owned model preserves the security-sensitive Chio fields
// without selecting one approval or interpreting supplemental bytes.
type ChioToolCallRequest struct {
	Type                      string                               `json:"type"`
	ID                        string                               `json:"id"`
	CapabilityToken           CapabilityToken                      `json:"capability_token"`
	ServerID                  string                               `json:"server_id"`
	Tool                      string                               `json:"tool"`
	Params                    json.RawMessage                      `json:"params"`
	GovernedIntent            *AgentGovernedTransactionIntent      `json:"governed_intent,omitempty"`
	ApprovalToken             *CapabilityGovernedApprovalToken     `json:"approval_token,omitempty"`
	ApprovalTokens            []CapabilityGovernedApprovalToken    `json:"approval_tokens,omitempty"`
	ThresholdApprovalProposal *CapabilityThresholdApprovalProposal `json:"threshold_approval_proposal,omitempty"`
	SupplementalAuthorization *CapabilitySupplementalAuthorization `json:"supplemental_authorization,omitempty"`
}

// Verdict represents the kernel's evaluation decision.
type Verdict struct {
	Verdict    string `json:"verdict"`
	Reason     string `json:"reason,omitempty"`
	Guard      string `json:"guard,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

// IsAllowed returns true if the verdict allows the request.
func (v Verdict) IsAllowed() bool {
	return v.Verdict == "allow"
}

// IsDenied returns true if the verdict denies the request.
func (v Verdict) IsDenied() bool {
	return v.Verdict == "deny"
}

// GuardEvidence records per-guard evaluation evidence.
type GuardEvidence struct {
	GuardName string `json:"guard_name"`
	Verdict   bool   `json:"verdict"`
	Details   string `json:"details,omitempty"`
}

// HTTPReceipt is a signed proof that an HTTP request was evaluated by Chio.
type HTTPReceipt struct {
	ID                 string           `json:"id"`
	RequestID          string           `json:"request_id"`
	RoutePattern       string           `json:"route_pattern"`
	Method             string           `json:"method"`
	CallerIdentityHash string           `json:"caller_identity_hash"`
	SessionID          string           `json:"session_id,omitempty"`
	Verdict            Verdict          `json:"verdict"`
	ReceiptKind        string           `json:"receipt_kind"`
	BoundaryClass      string           `json:"boundary_class"`
	ObservationOutcome string           `json:"observation_outcome,omitempty"`
	ToolOrigin         string           `json:"tool_origin"`
	RedactionMode      string           `json:"redaction_mode"`
	ActorChain         []map[string]any `json:"actor_chain,omitempty"`
	Evidence           []GuardEvidence  `json:"evidence,omitempty"`
	ResponseStatus     int              `json:"response_status"`
	Timestamp          int64            `json:"timestamp"`
	ContentHash        string           `json:"content_hash"`
	PolicyHash         string           `json:"policy_hash"`
	TrustLevel         string           `json:"trust_level"`
	CapabilityID       string           `json:"capability_id,omitempty"`
	Metadata           interface{}      `json:"metadata,omitempty"`
	KernelKey          string           `json:"kernel_key"`
	Signature          string           `json:"signature"`
}

// IsAuthorized returns true only for a structurally mediated v1 allow receipt.
func (r HTTPReceipt) IsAuthorized() bool {
	return r.ReceiptKind == "mediated_decision" &&
		r.BoundaryClass == "prevent" &&
		r.ObservationOutcome == "" &&
		r.TrustLevel == "mediated" &&
		r.Verdict.IsAllowed()
}

// IsAuthorizedFor reports whether a sidecar verifier result authorizes this
// receipt. The raw receipt shape is not enough: authorization also requires a
// trusted signer, a valid content-addressed id, a valid parameter hash binding,
// and a verified signature.
func (v VerifyReceiptResponse) IsAuthorizedFor(receipt HTTPReceipt) bool {
	return v.OK &&
		v.Authorized &&
		v.SignatureValid &&
		v.SignerTrusted &&
		v.ReceiptIDValid &&
		v.ParameterHashValid &&
		v.ReceiptKind == "mediated_decision" &&
		v.BoundaryClass == "prevent" &&
		v.TrustLevel == "mediated" &&
		v.Result == "allow" &&
		receipt.IsAuthorized() &&
		isLowerHex64(receipt.ID) &&
		isLowerHex64(receipt.ContentHash) &&
		receipt.Signature != ""
}

// VerifyReceiptResponse is the structured authority result returned by /chio/verify.
type VerifyReceiptResponse struct {
	SignatureValid     bool   `json:"signature_valid"`
	SignerTrusted      bool   `json:"signer_trusted"`
	ReceiptIDValid     bool   `json:"receipt_id_valid"`
	ParameterHashValid bool   `json:"parameter_hash_valid"`
	ReceiptKind        string `json:"receipt_kind"`
	BoundaryClass      string `json:"boundary_class"`
	TrustLevel         string `json:"trust_level"`
	Result             string `json:"result"`
	Authorized         bool   `json:"authorized"`
	SignerKeyHex       string `json:"signer_key_hex"`
	OK                 bool   `json:"ok"`
}

// EvaluateResponse is the sidecar's response to an evaluation request.
type EvaluateResponse struct {
	Verdict  Verdict         `json:"verdict"`
	Receipt  HTTPReceipt     `json:"receipt"`
	Evidence []GuardEvidence `json:"evidence"`
}

// Error codes for Chio HTTP responses.
const (
	ErrAccessDenied       = "chio_access_denied"
	ErrSidecarUnreachable = "chio_sidecar_unreachable"
	ErrSidecarUnavailable = "chio_sidecar_unavailable"
	ErrEvaluationFailed   = "chio_evaluation_failed"
	ErrInvalidReceipt     = "chio_invalid_receipt"
)

// ErrorResponse is the structured error body returned by Chio middleware.
type ErrorResponse struct {
	Error      string `json:"error"`
	Message    string `json:"message"`
	ReceiptID  string `json:"receipt_id,omitempty"`
	Suggestion string `json:"suggestion,omitempty"`
}

// UnmarshalJSON rejects receipt-kind and decision combinations that the
// generated field types alone cannot express.
func (r *ReceiptRecord) UnmarshalJSON(data []byte) error {
	type receiptRecordAlias ReceiptRecord
	var decoded receiptRecordAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	record := ReceiptRecord(decoded)
	if err := record.ValidateSemantics(); err != nil {
		return err
	}
	*r = record
	return nil
}

// ValidateSemantics enforces the current v1 receipt semantic contract.
func (r ReceiptRecord) ValidateSemantics() error {
	if !isLowerHex64(r.Id) {
		return fmt.Errorf("receipt.id must be a 64-character lowercase hex content-addressed id")
	}
	if !isLowerHex64(r.Action.ParameterHash) {
		return fmt.Errorf("receipt.action.parameter_hash must be a 64-character lowercase hex string")
	}
	if !isLowerHex64(r.ContentHash) {
		return fmt.Errorf("receipt.content_hash must be a 64-character lowercase hex string")
	}
	if r.Signature == "" {
		return fmt.Errorf("receipt.signature must be non-empty")
	}

	decisionPresent := receiptRecordDecisionPresent(r.Decision)
	switch r.ReceiptKind {
	case ReceiptRecordReceiptKindMediatedDecision:
		if !decisionPresent {
			return fmt.Errorf("mediated_decision receipts must include decision")
		}
		if r.BoundaryClass != ReceiptRecordBoundaryClassPrevent {
			return fmt.Errorf("mediated_decision receipts must use boundary_class prevent")
		}
		if r.TrustLevel != ReceiptRecordTrustLevelMediated {
			return fmt.Errorf("mediated_decision receipts must use trust_level mediated")
		}
		if r.ObservationOutcome != nil {
			return fmt.Errorf("mediated_decision receipts must omit observation_outcome")
		}
	case ReceiptRecordReceiptKindTraceObservation:
		if decisionPresent {
			return fmt.Errorf("trace_observation receipts must omit decision")
		}
		if r.BoundaryClass != ReceiptRecordBoundaryClassDetectOnly {
			return fmt.Errorf("trace_observation receipts must use boundary_class detect_only")
		}
		if r.TrustLevel != ReceiptRecordTrustLevelVerified {
			return fmt.Errorf("trace_observation receipts must use trust_level verified")
		}
		if r.ObservationOutcome == nil {
			return fmt.Errorf("trace_observation receipts must include observation_outcome")
		}
	case ReceiptRecordReceiptKindAdvisoryEvaluation:
		if decisionPresent {
			return fmt.Errorf("advisory_evaluation receipts must omit decision")
		}
		if r.BoundaryClass != ReceiptRecordBoundaryClassAdvisoryOnly {
			return fmt.Errorf("advisory_evaluation receipts must use boundary_class advisory_only")
		}
		if r.TrustLevel != ReceiptRecordTrustLevelAdvisory {
			return fmt.Errorf("advisory_evaluation receipts must use trust_level advisory")
		}
		if r.ObservationOutcome == nil {
			return fmt.Errorf("advisory_evaluation receipts must include observation_outcome")
		}
	default:
		return fmt.Errorf("receipt_kind must be a current v1 receipt kind")
	}
	return nil
}

// IsAuthorized returns true only for a validated generated receipt with an
// allow decision under mediated/prevent semantics. It does not replace
// signature or trust-root verification.
func (r ReceiptRecord) IsAuthorized() bool {
	if err := r.ValidateSemantics(); err != nil {
		return false
	}
	return r.ReceiptKind == ReceiptRecordReceiptKindMediatedDecision &&
		r.BoundaryClass == ReceiptRecordBoundaryClassPrevent &&
		r.TrustLevel == ReceiptRecordTrustLevelMediated &&
		r.ObservationOutcome == nil &&
		r.DecisionVerdict() == "allow"
}

// DecisionVerdict extracts the internally tagged decision verdict.
func (r ReceiptRecord) DecisionVerdict() string {
	if r.Decision == nil || !receiptRecordDecisionPresent(r.Decision) {
		return ""
	}
	var body struct {
		Verdict string `json:"verdict"`
	}
	if err := json.Unmarshal(r.Decision.union, &body); err != nil {
		return ""
	}
	return body.Verdict
}

func receiptRecordDecisionPresent(decision *ReceiptRecordDecision) bool {
	if decision == nil {
		return false
	}
	return len(decision.union) > 0 && string(decision.union) != "null"
}

func isLowerHex64(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}
