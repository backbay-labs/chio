// Package main implements the Chio Kubernetes admission webhooks.
//
// The webhooks validate admission requests against authoritative capability
// tokens issued by a configured set of trusted kernel keys. They fail closed:
// any request without a verifiable capability bound to the admission
// parameters (operation, namespace, resource) is denied.
package main

import "encoding/json"

// Chio annotation keys used to carry capability material on admission.
const (
	// AnnotationCapabilityToken is the pod annotation carrying the Chio
	// capability token bytes (canonical JSON).
	AnnotationCapabilityToken = "chio.world/capability-token"

	// AnnotationRequiredScopes is a pod-supplied annotation that the
	// webhook does not trust. Required scopes are read from webhook
	// configuration only.
	AnnotationRequiredScopes = "chio.world/required-scopes"

	// AnnotationExempt is a pod-supplied annotation that the webhook
	// does not trust. The webhook never honors self-asserted exemptions.
	AnnotationExempt = "chio.world/exempt"
)

// AdmissionReview wraps an admission request and response.
//
// This is the v1 admission.k8s.io shape but encoded with minimal types so
// the webhook binary does not need a full client-go runtime dependency.
type AdmissionReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Request    AdmissionRequest   `json:"request"`
	Response   *AdmissionResponse `json:"response,omitempty"`
}

// AdmissionRequest is the incoming admission review request.
type AdmissionRequest struct {
	UID         string    `json:"uid"`
	Kind        GroupKind `json:"kind"`
	Resource    GroupKind `json:"resource"`
	Namespace   string    `json:"namespace"`
	Name        string    `json:"name"`
	Operation   string    `json:"operation"`
	Object      RawObject `json:"object"`
	UserInfo    UserInfo  `json:"userInfo"`
	RequestKind GroupKind `json:"requestKind,omitempty"`
}

// GroupKind identifies the resource type.
type GroupKind struct {
	Group    string `json:"group"`
	Version  string `json:"version"`
	Kind     string `json:"kind,omitempty"`
	Resource string `json:"resource,omitempty"`
}

// UserInfo describes the user making the admission request.
type UserInfo struct {
	Username string   `json:"username"`
	UID      string   `json:"uid"`
	Groups   []string `json:"groups,omitempty"`
}

// RawObject holds the raw JSON of the Kubernetes object.
type RawObject struct {
	Raw json.RawMessage `json:"raw,omitempty"`
}

// UnmarshalJSON implements custom unmarshaling so the raw object survives
// untouched into Raw.
func (r *RawObject) UnmarshalJSON(data []byte) error {
	r.Raw = data
	return nil
}

// MarshalJSON implements custom marshaling for the raw object field.
func (r RawObject) MarshalJSON() ([]byte, error) {
	if r.Raw == nil {
		return []byte("null"), nil
	}
	return r.Raw, nil
}

// AdmissionResponse is the admission review response.
type AdmissionResponse struct {
	UID       string        `json:"uid"`
	Allowed   bool          `json:"allowed"`
	Result    *StatusResult `json:"status,omitempty"`
	PatchType *string       `json:"patchType,omitempty"`
	Patch     []byte        `json:"patch,omitempty"`
}

// StatusResult provides additional status information.
type StatusResult struct {
	Message string `json:"message"`
	Code    int    `json:"code,omitempty"`
}

// PodSpec is a minimal pod representation for annotation extraction.
type PodSpec struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Metadata   Metadata `json:"metadata"`
	Spec       struct {
		Containers []Container `json:"containers"`
	} `json:"spec"`
}

// Metadata holds pod metadata.
type Metadata struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// Container is a minimal Kubernetes container spec.
type Container struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}

func allowResponse(message string) AdmissionResponse {
	return AdmissionResponse{
		Allowed: true,
		Result: &StatusResult{
			Message: message,
		},
	}
}

func denyResponse(message string) AdmissionResponse {
	return AdmissionResponse{
		Allowed: false,
		Result: &StatusResult{
			Message: message,
			Code:    403,
		},
	}
}
