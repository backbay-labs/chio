package chio

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
	ID                 string          `json:"id"`
	RequestID          string          `json:"request_id"`
	RoutePattern       string          `json:"route_pattern"`
	Method             string          `json:"method"`
	CallerIdentityHash string          `json:"caller_identity_hash"`
	SessionID          string          `json:"session_id,omitempty"`
	Verdict            Verdict         `json:"verdict"`
	Evidence           []GuardEvidence `json:"evidence,omitempty"`
	ResponseStatus     int             `json:"response_status"`
	Timestamp          int64           `json:"timestamp"`
	ContentHash        string          `json:"content_hash"`
	PolicyHash         string          `json:"policy_hash"`
	CapabilityID       string          `json:"capability_id,omitempty"`
	Metadata           interface{}     `json:"metadata,omitempty"`
	KernelKey          string          `json:"kernel_key"`
	Signature          string          `json:"signature"`
}

// EvaluateResponse is the sidecar's response to an evaluation request.
type EvaluateResponse struct {
	Verdict  Verdict         `json:"verdict"`
	Receipt  HTTPReceipt     `json:"receipt"`
	Evidence []GuardEvidence `json:"evidence"`
}

// ChioPassthrough describes an explicit fail-open degraded state where the
// request was forwarded without a signed Chio receipt.
type ChioPassthrough struct {
	Mode    string `json:"mode"`
	Error   string `json:"error"`
	Message string `json:"message"`
}

// Error codes for Chio HTTP responses.
const (
	ErrAccessDenied       = "chio_access_denied"
	ErrSidecarUnreachable = "chio_sidecar_unreachable"
	ErrEvaluationFailed   = "chio_evaluation_failed"
	ErrInvalidReceipt     = "chio_invalid_receipt"
	ErrTimeout            = "chio_timeout"
)

// ErrorResponse is the structured error body returned by Chio middleware.
type ErrorResponse struct {
	Error      string `json:"error"`
	Message    string `json:"message"`
	ReceiptID  string `json:"receipt_id,omitempty"`
	Suggestion string `json:"suggestion,omitempty"`
}
