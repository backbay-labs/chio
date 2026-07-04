package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// kernelSigner emulates an authoritative Chio kernel that issues capability
// tokens for testing. Tests instantiate a kernelSigner per scenario.
type kernelSigner struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	issuerHex  string
}

func newKernelSigner(t *testing.T) kernelSigner {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate kernel signer key: %v", err)
	}

	return kernelSigner{
		publicKey:  publicKey,
		privateKey: privateKey,
		issuerHex:  hex.EncodeToString(publicKey),
	}
}

// signedTokenWith builds and signs a capability token with the given scope and
// validity window. Any optional parameter binding can be supplied through
// the binding argument.
func signedTokenWith(
	t *testing.T,
	signer kernelSigner,
	scope CapabilityScope,
	issuedAt, expiresAt time.Time,
	binding *ParameterBinding,
) string {
	t.Helper()

	body := map[string]any{
		"id":         "cap-webhook-test",
		"issuer":     signer.issuerHex,
		"subject":    signer.issuerHex,
		"scope":      scope,
		"issued_at":  issuedAt.Unix(),
		"expires_at": expiresAt.Unix(),
	}
	if binding != nil {
		body["parameter_binding"] = binding
	}

	canonical, err := canonicalJSON(body)
	if err != nil {
		t.Fatalf("failed to canonicalize token: %v", err)
	}

	body["signature"] = hex.EncodeToString(ed25519.Sign(signer.privateKey, canonical))

	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("failed to marshal token: %v", err)
	}
	return string(encoded)
}

// signedToolToken builds a tool-scoped capability with a fresh validity window
// and no parameter binding.
func signedToolToken(t *testing.T, signer kernelSigner, tool string, ops ...string) string {
	t.Helper()
	now := time.Now().UTC()
	return signedTokenWith(t,
		signer,
		CapabilityScope{
			Grants: []ToolGrant{
				{ServerID: "*", ToolName: tool, Operations: ops},
			},
		},
		now.Add(-1*time.Minute),
		now.Add(1*time.Hour),
		nil,
	)
}

// trustingConfig returns a verifier config that trusts the given signer and
// requires the given scopes.
func trustingConfig(t *testing.T, signer kernelSigner, scopes ...string) VerifierConfig {
	t.Helper()
	config, err := NewVerifierConfig([]string{signer.issuerHex}, scopes)
	if err != nil {
		t.Fatalf("failed to build verifier config: %v", err)
	}
	return config
}

// buildPodReview returns an AdmissionReview wire payload for a pod with the
// given annotations and admission context.
func buildPodReview(t *testing.T, annotations map[string]string, operation, namespace string) []byte {
	t.Helper()

	pod := PodSpec{
		APIVersion: "v1",
		Kind:       "Pod",
		Metadata: Metadata{
			Name:        "test-pod",
			Namespace:   namespace,
			Annotations: annotations,
		},
	}
	pod.Spec.Containers = []Container{{Name: "app", Image: "myapp:latest"}}

	podBytes, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("failed to marshal pod: %v", err)
	}

	review := AdmissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Request: AdmissionRequest{
			UID:       "test-uid-001",
			Kind:      GroupKind{Group: "", Version: "v1", Kind: "Pod"},
			Resource:  GroupKind{Group: "", Version: "v1", Resource: "pods"},
			Namespace: namespace,
			Name:      "test-pod",
			Operation: operation,
			Object:    RawObject{Raw: podBytes},
		},
	}
	reviewBytes, err := json.Marshal(review)
	if err != nil {
		t.Fatalf("failed to marshal review: %v", err)
	}
	return reviewBytes
}

func decodeResponse(t *testing.T, rec *httptest.ResponseRecorder) AdmissionReview {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if review.Response == nil {
		t.Fatal("expected response in admission review")
	}
	return review
}

// TestAdmissionFailsClosedWithoutCapability covers the case where a pod has no
// capability annotation at all. The webhook must deny.
func TestAdmissionFailsClosedWithoutCapability(t *testing.T) {
	signer := newKernelSigner(t)
	server := NewServer(trustingConfig(t, signer, "db:invoke"), nil)

	body := buildPodReview(t, map[string]string{}, "CREATE", "default")
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.HandleValidate(rec, req)
	review := decodeResponse(t, rec)

	if review.Response.Allowed {
		t.Fatal("expected admission to be denied when capability is missing")
	}
	if !strings.Contains(review.Response.Result.Message, "missing capability token") {
		t.Fatalf("expected missing-capability denial, got %q", review.Response.Result.Message)
	}
	if review.Response.UID != "test-uid-001" {
		t.Fatalf("expected UID to be echoed, got %q", review.Response.UID)
	}
}

// TestAdmissionFailsClosedWithUnsignedCapability covers a token whose
// signature does not verify. The webhook must deny.
func TestAdmissionFailsClosedWithUnsignedCapability(t *testing.T) {
	signer := newKernelSigner(t)
	server := NewServer(trustingConfig(t, signer, "db:invoke"), nil)

	// Build a token with a real shape but a tampered signature.
	token := signedToolToken(t, signer, "db", "invoke")
	var parsed map[string]any
	if err := json.Unmarshal([]byte(token), &parsed); err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	parsed["signature"] = strings.Repeat("0", ed25519.SignatureSize*2)
	tampered, err := json.Marshal(parsed)
	if err != nil {
		t.Fatalf("failed to marshal tampered token: %v", err)
	}

	body := buildPodReview(t,
		map[string]string{AnnotationCapabilityToken: string(tampered)},
		"CREATE",
		"default",
	)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.HandleValidate(rec, req)
	review := decodeResponse(t, rec)

	if review.Response.Allowed {
		t.Fatal("expected admission to be denied for tampered signature")
	}
	if !strings.Contains(review.Response.Result.Message, "signature verification failed") {
		t.Fatalf("expected signature-failure denial, got %q", review.Response.Result.Message)
	}
}

// TestAdmissionFailsClosedWithUntrustedSigner covers a token signed by a
// well-formed but untrusted key. The webhook must deny.
func TestAdmissionFailsClosedWithUntrustedSigner(t *testing.T) {
	trusted := newKernelSigner(t)
	untrusted := newKernelSigner(t)

	server := NewServer(trustingConfig(t, trusted, "db:invoke"), nil)

	token := signedToolToken(t, untrusted, "db", "invoke")
	body := buildPodReview(t,
		map[string]string{AnnotationCapabilityToken: token},
		"CREATE",
		"default",
	)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.HandleValidate(rec, req)
	review := decodeResponse(t, rec)

	if review.Response.Allowed {
		t.Fatal("expected admission to be denied for untrusted signer")
	}
	if !strings.Contains(review.Response.Result.Message, "trusted kernel key set") {
		t.Fatalf("expected untrusted-signer denial, got %q", review.Response.Result.Message)
	}
}

// TestAdmissionAdmitsWithVerifiedCapability is the happy path: signature
// verifies, signer is trusted, parameter binding matches, scopes cover the
// requirement. The webhook must allow.
func TestAdmissionAdmitsWithVerifiedCapability(t *testing.T) {
	signer := newKernelSigner(t)
	server := NewServer(trustingConfig(t, signer, "db:invoke"), nil)

	now := time.Now().UTC()
	token := signedTokenWith(t,
		signer,
		CapabilityScope{
			Grants: []ToolGrant{
				{ServerID: "*", ToolName: "db", Operations: []string{"invoke"}},
			},
		},
		now.Add(-1*time.Minute),
		now.Add(1*time.Hour),
		&ParameterBinding{
			Operations: []string{"CREATE"},
			Namespaces: []string{"default"},
			Resources:  []string{"pods"},
		},
	)

	body := buildPodReview(t,
		map[string]string{AnnotationCapabilityToken: token},
		"CREATE",
		"default",
	)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.HandleValidate(rec, req)
	review := decodeResponse(t, rec)

	if !review.Response.Allowed {
		t.Fatalf("expected admission to be allowed, got denial %q", review.Response.Result.Message)
	}
}

// TestAdmissionFailsClosedWhenTrustedKeysMissing ensures that an empty trust
// set is not silently treated as permissive.
func TestAdmissionFailsClosedWhenTrustedKeysMissing(t *testing.T) {
	signer := newKernelSigner(t)
	emptyConfig := VerifierConfig{
		TrustedKernelKeys: map[string]struct{}{},
		RequiredScopes:    []string{"db:invoke"},
	}
	server := NewServer(emptyConfig, nil)

	token := signedToolToken(t, signer, "db", "invoke")
	body := buildPodReview(t,
		map[string]string{AnnotationCapabilityToken: token},
		"CREATE",
		"default",
	)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.HandleValidate(rec, req)
	review := decodeResponse(t, rec)

	if review.Response.Allowed {
		t.Fatal("expected admission to be denied with empty trust set")
	}
	if !strings.Contains(review.Response.Result.Message, "no trusted kernel keys") {
		t.Fatalf("expected empty-trust-set denial, got %q", review.Response.Result.Message)
	}
}

// TestAdmissionFailsClosedWithExpiredCapability verifies that expired tokens
// are denied even when the signature and signer are valid.
func TestAdmissionFailsClosedWithExpiredCapability(t *testing.T) {
	signer := newKernelSigner(t)
	server := NewServer(trustingConfig(t, signer, "db:invoke"), nil)

	now := time.Now().UTC()
	token := signedTokenWith(t,
		signer,
		CapabilityScope{
			Grants: []ToolGrant{
				{ServerID: "*", ToolName: "db", Operations: []string{"invoke"}},
			},
		},
		now.Add(-2*time.Hour),
		now.Add(-1*time.Hour),
		nil,
	)

	body := buildPodReview(t,
		map[string]string{AnnotationCapabilityToken: token},
		"CREATE",
		"default",
	)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.HandleValidate(rec, req)
	review := decodeResponse(t, rec)

	if review.Response.Allowed {
		t.Fatal("expected admission to be denied for expired capability")
	}
	if !strings.Contains(review.Response.Result.Message, "expired") {
		t.Fatalf("expected expired-token denial, got %q", review.Response.Result.Message)
	}
}

// TestAdmissionFailsClosedWhenBindingMismatches ensures parameter bindings are
// enforced: a token bound to namespace "system" must not authorize admission
// into namespace "default".
func TestAdmissionFailsClosedWhenBindingMismatches(t *testing.T) {
	signer := newKernelSigner(t)
	server := NewServer(trustingConfig(t, signer, "db:invoke"), nil)

	now := time.Now().UTC()
	token := signedTokenWith(t,
		signer,
		CapabilityScope{
			Grants: []ToolGrant{
				{ServerID: "*", ToolName: "db", Operations: []string{"invoke"}},
			},
		},
		now.Add(-1*time.Minute),
		now.Add(1*time.Hour),
		&ParameterBinding{
			Namespaces: []string{"system"},
		},
	)

	body := buildPodReview(t,
		map[string]string{AnnotationCapabilityToken: token},
		"CREATE",
		"default",
	)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.HandleValidate(rec, req)
	review := decodeResponse(t, rec)

	if review.Response.Allowed {
		t.Fatal("expected admission to be denied for namespace binding mismatch")
	}
	if !strings.Contains(review.Response.Result.Message, "namespace") {
		t.Fatalf("expected binding-mismatch denial, got %q", review.Response.Result.Message)
	}
}

// TestAdmissionRejectsPodSuppliedRequiredScopes guards against scope policy
// being controlled by the workload itself.
func TestAdmissionRejectsPodSuppliedRequiredScopes(t *testing.T) {
	signer := newKernelSigner(t)
	server := NewServer(trustingConfig(t, signer, "db:invoke"), nil)

	token := signedToolToken(t, signer, "db", "invoke")
	body := buildPodReview(t,
		map[string]string{
			AnnotationCapabilityToken: token,
			AnnotationRequiredScopes:  "db:invoke",
		},
		"CREATE",
		"default",
	)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.HandleValidate(rec, req)
	review := decodeResponse(t, rec)

	if review.Response.Allowed {
		t.Fatal("expected pod-supplied scope override to be rejected")
	}
	if !strings.Contains(review.Response.Result.Message, EnvRequiredScopes) {
		t.Fatalf("expected denial to reference webhook config env, got %q", review.Response.Result.Message)
	}
}

// TestAdmissionRejectsSelfAssertedExemption guards against exemption being
// declared by the workload.
func TestAdmissionRejectsSelfAssertedExemption(t *testing.T) {
	signer := newKernelSigner(t)
	server := NewServer(trustingConfig(t, signer, "db:invoke"), nil)

	body := buildPodReview(t,
		map[string]string{AnnotationExempt: "true"},
		"CREATE",
		"default",
	)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.HandleValidate(rec, req)
	review := decodeResponse(t, rec)

	if review.Response.Allowed {
		t.Fatal("expected self-asserted exemption to be denied")
	}
	if !strings.Contains(review.Response.Result.Message, "exemptions") {
		t.Fatalf("expected exemption denial, got %q", review.Response.Result.Message)
	}
}

// TestMutateDeniesWhenValidationFails ensures the mutating webhook does not
// silently permit pods that the validating webhook would reject.
func TestMutateDeniesWhenValidationFails(t *testing.T) {
	signer := newKernelSigner(t)
	server := NewServer(trustingConfig(t, signer, "db:invoke"), nil)

	body := buildPodReview(t, map[string]string{}, "CREATE", "default")
	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.HandleMutate(rec, req)
	review := decodeResponse(t, rec)

	if review.Response.Allowed {
		t.Fatal("expected mutation to be denied without a verified capability")
	}
}

// TestHealthz verifies the readiness endpoint.
func TestHealthz(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handleHealthz(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

// TestLoadVerifierConfigFromEnvRejectsEmptyTrust ensures the config loader
// requires explicit trusted keys.
func TestLoadVerifierConfigFromEnvRejectsEmptyTrust(t *testing.T) {
	t.Setenv(EnvTrustedKernelKeys, "")
	t.Setenv(EnvRequiredScopes, "db:invoke")

	if _, err := LoadVerifierConfigFromEnv(); err == nil {
		t.Fatal("expected loader to reject empty trusted-key configuration")
	}
}

// TestLoadVerifierConfigFromEnvRejectsEmptyScopes ensures the config loader
// requires explicit required scopes.
func TestLoadVerifierConfigFromEnvRejectsEmptyScopes(t *testing.T) {
	signer := newKernelSigner(t)
	t.Setenv(EnvTrustedKernelKeys, signer.issuerHex)
	t.Setenv(EnvRequiredScopes, "")

	if _, err := LoadVerifierConfigFromEnv(); err == nil {
		t.Fatal("expected loader to reject empty required-scopes configuration")
	}
}

// TestLoadVerifierConfigFromEnvAcceptsValid covers the success path of the
// config loader.
func TestLoadVerifierConfigFromEnvAcceptsValid(t *testing.T) {
	signer := newKernelSigner(t)
	t.Setenv(EnvTrustedKernelKeys, signer.issuerHex)
	t.Setenv(EnvRequiredScopes, "db:invoke")

	config, err := LoadVerifierConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(config.TrustedKernelKeys) != 1 {
		t.Fatalf("expected 1 trusted key, got %d", len(config.TrustedKernelKeys))
	}
	if len(config.RequiredScopes) != 1 {
		t.Fatalf("expected 1 required scope, got %d", len(config.RequiredScopes))
	}
}
