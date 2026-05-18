package main

import "encoding/json"

// Kubernetes admission webhook types.
// These are minimal types sufficient for the Chio admission controller
// without pulling in the full k8s.io/api dependency at runtime.

// Chio annotation keys for pod configuration.
const (
	// AnnotationCapabilityToken is the pod annotation containing the Chio
	// capability token.
	AnnotationCapabilityToken = "chio.protocol/capability-token"

	// AnnotationRequiredScopes is a legacy pod annotation name. The admission
	// webhook does not trust pod-supplied scope requirements.
	AnnotationRequiredScopes = "chio.backbay.io/required-scopes"

	// AnnotationExempt is a legacy pod annotation name. The admission webhook
	// does not trust pod-supplied exemptions.
	AnnotationExempt = "chio.backbay.io/exempt"

	// AnnotationInject triggers sidecar injection when set to "true".
	AnnotationInject = "chio.backbay.io/inject"

	// AnnotationSidecarImage overrides the default sidecar container image.
	AnnotationSidecarImage = "chio.backbay.io/sidecar-image"

	// AnnotationUpstream sets the upstream URL the sidecar proxies to.
	AnnotationUpstream = "chio.backbay.io/upstream"

	// AnnotationSpecPath sets the path to the OpenAPI spec file in the pod.
	AnnotationSpecPath = "chio.backbay.io/spec-path"

	// AnnotationReceiptStore sets the receipt storage backend for the sidecar.
	AnnotationReceiptStore = "chio.backbay.io/receipt-store"

	// DefaultSidecarImage is the default container image for the Chio sidecar.
	DefaultSidecarImage = "ghcr.io/backbay/chio-sidecar:latest"
)

// AdmissionReview wraps an admission request and response.
type AdmissionReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Request    AdmissionRequest   `json:"request"`
	Response   *AdmissionResponse `json:"response,omitempty"`
}

// AdmissionRequest is the incoming admission review request.
type AdmissionRequest struct {
	UID       string    `json:"uid"`
	Kind      GroupKind `json:"kind"`
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
	Object    RawObject `json:"object"`
}

// GroupKind identifies the resource type.
type GroupKind struct {
	Group   string `json:"group"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

// RawObject holds the raw JSON of the Kubernetes object.
type RawObject struct {
	Raw json.RawMessage `json:"raw,omitempty"`
}

// UnmarshalJSON implements custom unmarshaling to handle the raw object field.
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
	Name           string               `json:"name"`
	Image          string               `json:"image"`
	Args           []string             `json:"args,omitempty"`
	Ports          []ContainerPort      `json:"ports,omitempty"`
	ReadinessProbe *Probe               `json:"readinessProbe,omitempty"`
	Resources      ResourceRequirements `json:"resources,omitempty"`
}

// ContainerPort defines a port on a container.
type ContainerPort struct {
	Name          string `json:"name"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol"`
}

// Probe defines a readiness/liveness probe.
type Probe struct {
	HTTPGet             *HTTPGetAction `json:"httpGet,omitempty"`
	InitialDelaySeconds int            `json:"initialDelaySeconds"`
	PeriodSeconds       int            `json:"periodSeconds"`
}

// HTTPGetAction describes an HTTP GET probe action.
type HTTPGetAction struct {
	Path string `json:"path"`
	Port int    `json:"port"`
}

// ResourceRequirements defines container resource limits and requests.
type ResourceRequirements struct {
	Limits   ResourceList `json:"limits,omitempty"`
	Requests ResourceList `json:"requests,omitempty"`
}

// ResourceList maps resource names to quantities.
type ResourceList struct {
	CPU    string `json:"cpu,omitempty"`
	Memory string `json:"memory,omitempty"`
}

// PatchOperation is a single JSON Patch operation.
type PatchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}
