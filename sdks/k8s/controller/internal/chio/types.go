// Package chio provides data structures and an HTTP client for interacting
// with the Chio sidecar from the Kubernetes Job controller.
//
// The controller talks to the Chio sidecar over HTTP to mint capability
// grants at Job creation, release them at Job completion, and submit
// aggregated JobReceipts to the Chio receipt store.
package chio

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// CapabilityToken is a Chio capability token minted by the sidecar.
//
// The wire format matches the canonical Chio capability token JSON shape.
// The controller additionally keeps the raw serialized token bytes so the
// exact artifact can be stored on the pod template as a bearer annotation.
type CapabilityToken struct {
	// ID is the unique identifier of the capability grant.
	ID string
	// Token is the serialized capability token stored on the pod template.
	Token string
	// Issuer is the public key of the issuing Chio authority.
	Issuer string
	// Subject is the public key identifying the token subject.
	Subject string
	// Scope is the canonical Chio scope carried by the token.
	Scope capabilityScope
	// IssuedAt is the time the capability was issued.
	IssuedAt time.Time
	// ExpiresAt is the time the capability expires.
	ExpiresAt time.Time
	// Signature is the detached Chio capability signature.
	Signature string
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

type capabilityTokenWire struct {
	ID        string          `json:"id"`
	Issuer    string          `json:"issuer"`
	Subject   string          `json:"subject"`
	Scope     capabilityScope `json:"scope"`
	IssuedAt  uint64          `json:"issued_at"`
	ExpiresAt uint64          `json:"expires_at"`
	Signature string          `json:"signature"`
}

// UnmarshalJSON decodes the canonical Chio token shape and preserves the raw
// token bytes so the reconciler can persist the exact bearer artifact.
func (c *CapabilityToken) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	var wire capabilityTokenWire
	if err := decoder.Decode(&wire); err != nil {
		return fmt.Errorf("decode capability token: %w", err)
	}
	if wire.ID == "" || wire.Issuer == "" || wire.Signature == "" {
		return fmt.Errorf("decode capability token: missing required fields")
	}

	c.ID = wire.ID
	c.Token = string(data)
	c.Issuer = wire.Issuer
	c.Subject = wire.Subject
	c.Scope = wire.Scope
	c.IssuedAt = time.Unix(int64(wire.IssuedAt), 0).UTC()
	c.ExpiresAt = time.Unix(int64(wire.ExpiresAt), 0).UTC()
	c.Signature = wire.Signature
	return nil
}

// MarshalJSON emits the canonical Chio token shape used by the sidecar.
func (c CapabilityToken) MarshalJSON() ([]byte, error) {
	if c.Token != "" {
		var raw json.RawMessage
		if err := json.Unmarshal([]byte(c.Token), &raw); err == nil {
			return raw, nil
		}
	}

	return json.Marshal(capabilityTokenWire{
		ID:        c.ID,
		Issuer:    c.Issuer,
		Subject:   c.Subject,
		Scope:     c.Scope,
		IssuedAt:  unixSeconds(c.IssuedAt),
		ExpiresAt: unixSeconds(c.ExpiresAt),
		Signature: c.Signature,
	})
}

func unixSeconds(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	return uint64(t.UTC().Unix())
}

// MintRequest requests a capability grant for a Kubernetes Job.
type MintRequest struct {
	// Subject is typically "job/<namespace>/<name>".
	Subject string `json:"subject"`
	// Scopes requested by the Job (drawn from the Job's annotations).
	Scopes []string `json:"scopes"`
	// Labels mirrors the governed Job's labels (for audit).
	Labels map[string]string `json:"labels,omitempty"`
	// TTL is an optional time-to-live for the grant.
	TTL time.Duration `json:"-"`
	// JobUID is the Kubernetes UID of the Job (for idempotency).
	JobUID string `json:"job_uid"`
}

type mintRequestWire struct {
	Subject    string            `json:"subject"`
	Scopes     []string          `json:"scopes"`
	Labels     map[string]string `json:"labels,omitempty"`
	TTLNanos   *uint64           `json:"ttl_nanos,omitempty"`
	TTLSeconds *uint64           `json:"ttl_seconds,omitempty"`
	JobUID     string            `json:"job_uid"`
}

// MarshalJSON emits an explicit TTL unit so the sidecar never has to guess
// whether a small integer came from seconds or nanoseconds.
func (r MintRequest) MarshalJSON() ([]byte, error) {
	wire := mintRequestWire{
		Subject: r.Subject,
		Scopes:  r.Scopes,
		Labels:  r.Labels,
		JobUID:  r.JobUID,
	}
	if r.TTL > 0 {
		ttlNanos := uint64(r.TTL)
		wire.TTLNanos = &ttlNanos
	}
	return json.Marshal(wire)
}

// ReleaseRequest asks the Chio sidecar to revoke an outstanding capability.
type ReleaseRequest struct {
	// CapabilityID identifies the grant to release.
	CapabilityID string `json:"capability_id"`
	// JobUID is the UID of the governed Job.
	JobUID string `json:"job_uid"`
	// Reason is a free-form reason (e.g., "completed", "failed", "deleted").
	Reason string `json:"reason"`
}

// AdvisoryPodAnnotationSource is the canonical source label applied to
// receipt content harvested from a pod annotation. Pod annotations are
// user-owned (anyone with create-pod rights can set them) so the controller
// surfaces them strictly as advisory, never as authoritative receipt content.
const AdvisoryPodAnnotationSource = "pod_annotation_unverified"

// AdvisoryPodAnnotationMaxBytes is the upper bound the controller will copy
// from a pod's receipt annotation into a StepReceipt. Anything beyond this
// is truncated and the Truncated flag is set so downstream consumers can
// detect the cap.
const AdvisoryPodAnnotationMaxBytes = 32 * 1024

// AdvisoryPodAnnotation wraps the bytes the controller harvested from a
// pod's `chio.world/receipt` annotation.
//
// Trust model: the wrapping payload, including every field below, is
// user-owned content. Any actor with create-pod rights in the governed
// namespace can write arbitrary bytes here, including fabricated decisions,
// rationales, or substituted identifiers. Mediators MUST NOT treat any
// AdvisoryPodAnnotation content as authoritative; it is surfaced only so
// downstream tooling can correlate what the workload claimed with what the
// controller authoritatively observed. The Source field is fixed at
// AdvisoryPodAnnotationSource to make the trust boundary explicit on the
// wire.
type AdvisoryPodAnnotation struct {
	// Source is always AdvisoryPodAnnotationSource. It exists on the wire
	// so receipt consumers cannot miss the trust boundary.
	Source string `json:"source"`
	// AnnotationKey records which pod annotation produced the payload.
	AnnotationKey string `json:"annotation_key"`
	// Payload is the (possibly truncated) raw annotation value.
	Payload string `json:"payload"`
	// Truncated is true when Payload was shortened to fit
	// AdvisoryPodAnnotationMaxBytes.
	Truncated bool `json:"truncated"`
}

// StepReceipt is a single receipt observation the controller produces for a
// Pod step within a governed Job.
//
// Trust model: the controller mints every authoritative field on this
// receipt (PodName, Phase, ObservedAt). The AdvisoryPodAnnotation field is
// the only path by which workload-supplied bytes reach the aggregate
// JobReceipt, and it is explicitly tagged as unverified. Mediators relying
// on JobReceipt content for capability decisions, audit, or enforcement
// MUST ignore AdvisoryPodAnnotation. It exists for human / tool review
// only.
type StepReceipt struct {
	// PodName is the name of the Pod that emitted the observation.
	// Controller-owned.
	PodName string `json:"pod_name"`
	// Phase mirrors the Pod phase at the time of observation.
	// Controller-owned.
	Phase string `json:"phase"`
	// AdvisoryPodAnnotation carries any payload the workload wrote to its
	// own `chio.world/receipt` annotation. The contents are
	// user-controlled and MUST be treated as advisory only; see the
	// AdvisoryPodAnnotation doc-comment. Nil when the pod did not set a
	// receipt annotation.
	AdvisoryPodAnnotation *AdvisoryPodAnnotation `json:"advisory_pod_annotation,omitempty"`
	// ObservedAt is the time the controller recorded the observation.
	// Controller-owned.
	ObservedAt time.Time `json:"observed_at"`
}

// JobReceipt is the aggregate receipt emitted when a governed Job terminates.
type JobReceipt struct {
	// JobName is the Kubernetes Job name.
	JobName string `json:"job_name"`
	// Namespace is the Job namespace.
	Namespace string `json:"namespace"`
	// JobUID is the Job UID.
	JobUID string `json:"job_uid"`
	// CapabilityID is the grant that governed the Job, if any.
	CapabilityID string `json:"capability_id,omitempty"`
	// Outcome is one of "succeeded" or "failed".
	Outcome string `json:"outcome"`
	// StartedAt is when the Job started.
	StartedAt time.Time `json:"started_at"`
	// CompletedAt is when the Job reached a terminal state.
	CompletedAt time.Time `json:"completed_at"`
	// Steps are the aggregated pod receipts.
	Steps []StepReceipt `json:"steps"`
}

// MintResponse wraps the mint endpoint response.
type MintResponse struct {
	Capability CapabilityToken `json:"capability"`
}

// ReleaseResponse wraps the release endpoint response.
type ReleaseResponse struct {
	Released bool `json:"released"`
}

// SubmitReceiptResponse wraps the submit-receipt endpoint response.
type SubmitReceiptResponse struct {
	ReceiptID string `json:"receipt_id"`
	Accepted  bool   `json:"accepted"`
}
