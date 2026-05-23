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

type capabilitySigner struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	issuerHex  string
}

func newCapabilitySigner(t *testing.T) capabilitySigner {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	return capabilitySigner{
		publicKey:  publicKey,
		privateKey: privateKey,
		issuerHex:  hex.EncodeToString(publicKey),
	}
}

func trustCapabilitySigner(t *testing.T, signer capabilitySigner) {
	t.Helper()
	t.Setenv(envTrustedIssuerKey, signer.issuerHex)
	t.Setenv(envTrustedIssuerKeys, "")
}

func requireControllerScopes(t *testing.T, scopes string) {
	t.Helper()
	t.Setenv(envRequiredScopes, scopes)
}

func signedCapabilityTokenJSON(
	t *testing.T,
	signer capabilitySigner,
	scope capabilityScope,
	issuedAt,
	expiresAt time.Time,
) string {
	t.Helper()

	body := map[string]any{
		"id":         "cap-test-123",
		"issuer":     signer.issuerHex,
		"subject":    signer.issuerHex,
		"scope":      scope,
		"issued_at":  issuedAt.Unix(),
		"expires_at": expiresAt.Unix(),
	}

	canonical, err := canonicalJSON(body)
	if err != nil {
		t.Fatalf("failed to canonicalize token body: %v", err)
	}

	token := body
	token["signature"] = hex.EncodeToString(ed25519.Sign(signer.privateKey, canonical))

	encoded, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("failed to marshal token: %v", err)
	}

	return string(encoded)
}

func validToolCapabilityTokenJSON(
	t *testing.T,
	signer capabilitySigner,
	toolName string,
	operations ...string,
) string {
	t.Helper()
	now := time.Now().UTC()
	return signedCapabilityTokenJSON(
		t,
		signer,
		capabilityScope{
			Grants: []toolGrant{
				{
					ServerID:   "*",
					ToolName:   toolName,
					Operations: operations,
				},
			},
		},
		now.Add(-1*time.Minute),
		now.Add(1*time.Hour),
	)
}

// buildAdmissionReview creates an AdmissionReview with a pod having the given annotations.
func buildAdmissionReview(t *testing.T, annotations map[string]string) []byte {
	t.Helper()

	pod := PodSpec{
		APIVersion: "v1",
		Kind:       "Pod",
		Metadata: Metadata{
			Name:        "test-pod",
			Namespace:   "default",
			Annotations: annotations,
		},
	}
	pod.Spec.Containers = []Container{
		{
			Name:  "app",
			Image: "myapp:latest",
		},
	}

	podBytes, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("failed to marshal pod: %v", err)
	}

	review := AdmissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Request: AdmissionRequest{
			UID: "test-uid-001",
			Kind: GroupKind{
				Group:   "",
				Version: "v1",
				Kind:    "Pod",
			},
			Namespace: "default",
			Name:      "test-pod",
			Object:    RawObject{Raw: podBytes},
		},
	}

	reviewBytes, err := json.Marshal(review)
	if err != nil {
		t.Fatalf("failed to marshal review: %v", err)
	}
	return reviewBytes
}

func TestValidate_RejectWithoutCapability(t *testing.T) {
	body := buildAdmissionReview(t, map[string]string{})

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleValidate(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if review.Response == nil {
		t.Fatal("expected response")
	}
	if review.Response.Allowed {
		t.Fatal("expected pod to be rejected without capability token")
	}
	if strings.Contains(review.Response.Result.Message, AnnotationExempt) {
		t.Fatalf("missing-token denial must not advertise self-exemption, got %q", review.Response.Result.Message)
	}
	if review.Response.UID != "test-uid-001" {
		t.Fatalf("expected UID test-uid-001, got %s", review.Response.UID)
	}
}

func TestValidate_AllowWithCapability(t *testing.T) {
	signer := newCapabilitySigner(t)
	trustCapabilitySigner(t, signer)
	requireControllerScopes(t, "db:invoke")
	body := buildAdmissionReview(t, map[string]string{
		AnnotationCapabilityToken: validToolCapabilityTokenJSON(t, signer, "db", "invoke"),
	})

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleValidate(rec, req)

	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !review.Response.Allowed {
		t.Fatal("expected pod to be allowed with capability token")
	}
}

func TestValidate_AllowWithProtocolCapabilityToken(t *testing.T) {
	signer := newCapabilitySigner(t)
	trustCapabilitySigner(t, signer)
	requireControllerScopes(t, "db:invoke")
	body := buildAdmissionReview(t, map[string]string{
		"chio.protocol/capability-token": validToolCapabilityTokenJSON(t, signer, "db", "invoke"),
	})

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleValidate(rec, req)

	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !review.Response.Allowed {
		t.Fatal("expected pod to be allowed with protocol capability token")
	}
}

func TestValidate_RejectSelfAssertedExemptAnnotation(t *testing.T) {
	body := buildAdmissionReview(t, map[string]string{
		AnnotationExempt: "true",
	})

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleValidate(rec, req)

	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if review.Response.Allowed {
		t.Fatal("expected self-asserted exempt pod to be rejected")
	}
	if strings.Contains(review.Response.Result.Message, AnnotationExempt) {
		t.Fatalf("self-asserted exemption denial must not advertise pod exemption, got %q", review.Response.Result.Message)
	}
}

func TestValidate_RejectPodSuppliedRequiredScopes(t *testing.T) {
	signer := newCapabilitySigner(t)
	trustCapabilitySigner(t, signer)
	requireControllerScopes(t, "db:invoke")
	body := buildAdmissionReview(t, map[string]string{
		AnnotationCapabilityToken: validToolCapabilityTokenJSON(t, signer, "db", "invoke"),
		AnnotationRequiredScopes:  "db:invoke",
	})

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleValidate(rec, req)

	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if review.Response.Allowed {
		t.Fatal("expected pod-controlled scope policy to be rejected")
	}
	if !strings.Contains(review.Response.Result.Message, envRequiredScopes) {
		t.Fatalf("expected denial to reference controller scope configuration, got %q", review.Response.Result.Message)
	}
}

func TestValidate_RejectInvalidCapabilitySignature(t *testing.T) {
	signer := newCapabilitySigner(t)
	trustCapabilitySigner(t, signer)
	requireControllerScopes(t, "db:invoke")
	token := validToolCapabilityTokenJSON(t, signer, "db", "invoke")
	var parsed map[string]any
	if err := json.Unmarshal([]byte(token), &parsed); err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	parsed["signature"] = strings.Repeat("0", ed25519.SignatureSize*2)
	tampered, err := json.Marshal(parsed)
	if err != nil {
		t.Fatalf("failed to marshal tampered token: %v", err)
	}

	body := buildAdmissionReview(t, map[string]string{
		AnnotationCapabilityToken: string(tampered),
	})

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleValidate(rec, req)

	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if review.Response.Allowed {
		t.Fatal("expected invalid-signature token to be rejected")
	}
}

func TestValidate_RejectExpiredCapability(t *testing.T) {
	now := time.Now().UTC()
	signer := newCapabilitySigner(t)
	trustCapabilitySigner(t, signer)
	requireControllerScopes(t, "db:invoke")
	body := buildAdmissionReview(t, map[string]string{
		AnnotationCapabilityToken: signedCapabilityTokenJSON(
			t,
			signer,
			capabilityScope{
				Grants: []toolGrant{{ServerID: "*", ToolName: "db", Operations: []string{"invoke"}}},
			},
			now.Add(-2*time.Hour),
			now.Add(-1*time.Hour),
		),
	})

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleValidate(rec, req)

	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if review.Response.Allowed {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestValidate_AllowWithMatchingRequiredScope(t *testing.T) {
	signer := newCapabilitySigner(t)
	trustCapabilitySigner(t, signer)
	requireControllerScopes(t, "db:write")
	body := buildAdmissionReview(t, map[string]string{
		AnnotationCapabilityToken: validToolCapabilityTokenJSON(t, signer, "db", "invoke"),
	})

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleValidate(rec, req)

	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !review.Response.Allowed {
		t.Fatal("expected matching scope to be allowed")
	}
}

func TestValidate_RejectOutOfScopeCapability(t *testing.T) {
	signer := newCapabilitySigner(t)
	trustCapabilitySigner(t, signer)
	requireControllerScopes(t, "tool:*:admin:invoke")
	body := buildAdmissionReview(t, map[string]string{
		AnnotationCapabilityToken: validToolCapabilityTokenJSON(t, signer, "db", "invoke"),
	})

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleValidate(rec, req)

	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if review.Response.Allowed {
		t.Fatal("expected out-of-scope token to be rejected")
	}
}

func TestValidate_RejectUntrustedIssuer(t *testing.T) {
	trustedSigner := newCapabilitySigner(t)
	untrustedSigner := newCapabilitySigner(t)
	trustCapabilitySigner(t, trustedSigner)
	requireControllerScopes(t, "db:invoke")

	body := buildAdmissionReview(t, map[string]string{
		AnnotationCapabilityToken: validToolCapabilityTokenJSON(t, untrustedSigner, "db", "invoke"),
	})

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleValidate(rec, req)

	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if review.Response.Allowed {
		t.Fatal("expected untrusted issuer token to be rejected")
	}
}

func TestValidate_RejectWhenTrustedIssuerConfigMissing(t *testing.T) {
	signer := newCapabilitySigner(t)
	t.Setenv(envTrustedIssuerKey, "")
	t.Setenv(envTrustedIssuerKeys, "")
	requireControllerScopes(t, "db:invoke")

	body := buildAdmissionReview(t, map[string]string{
		AnnotationCapabilityToken: validToolCapabilityTokenJSON(t, signer, "db", "invoke"),
	})

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleValidate(rec, req)

	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if review.Response.Allowed {
		t.Fatal("expected validation to fail closed without trusted issuer configuration")
	}
}

func TestValidate_RejectWhenControllerRequiredScopesMissing(t *testing.T) {
	signer := newCapabilitySigner(t)
	trustCapabilitySigner(t, signer)
	t.Setenv(envRequiredScopes, "")

	body := buildAdmissionReview(t, map[string]string{
		AnnotationCapabilityToken: validToolCapabilityTokenJSON(t, signer, "db", "invoke"),
	})

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleValidate(rec, req)

	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if review.Response.Allowed {
		t.Fatal("expected validation to fail closed without controller required scopes")
	}
	if !strings.Contains(review.Response.Result.Message, envRequiredScopes) {
		t.Fatalf("expected denial to reference controller required scopes, got %q", review.Response.Result.Message)
	}
}

func TestMutate_NoInjectionWithoutAnnotation(t *testing.T) {
	signer := newCapabilitySigner(t)
	body := buildAdmissionReview(t, map[string]string{
		AnnotationCapabilityToken: validToolCapabilityTokenJSON(t, signer, "db", "invoke"),
	})

	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleMutate(rec, req)

	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !review.Response.Allowed {
		t.Fatal("expected allowed response")
	}
	if review.Response.Patch != nil {
		t.Fatal("expected no patch when injection not requested")
	}
}

func TestMutate_InjectSidecar(t *testing.T) {
	signer := newCapabilitySigner(t)
	body := buildAdmissionReview(t, map[string]string{
		AnnotationCapabilityToken: validToolCapabilityTokenJSON(t, signer, "db", "invoke"),
		AnnotationInject:          "true",
		AnnotationUpstream:        "http://127.0.0.1:3000",
		AnnotationSpecPath:        "/etc/chio/openapi.yaml",
	})

	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleMutate(rec, req)

	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !review.Response.Allowed {
		t.Fatal("expected allowed response with injection")
	}
	if review.Response.PatchType == nil || *review.Response.PatchType != "JSONPatch" {
		t.Fatal("expected JSONPatch patch type")
	}
	if review.Response.Patch == nil {
		t.Fatal("expected patch data")
	}

	// Verify patch content.
	var patches []PatchOperation
	if err := json.Unmarshal(review.Response.Patch, &patches); err != nil {
		t.Fatalf("failed to parse patch: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("expected 1 patch operation, got %d", len(patches))
	}
	if patches[0].Op != "add" {
		t.Fatalf("expected add operation, got %s", patches[0].Op)
	}
	if patches[0].Path != "/spec/containers/-" {
		t.Fatalf("expected path /spec/containers/-, got %s", patches[0].Path)
	}

	// Verify sidecar container.
	containerBytes, err := json.Marshal(patches[0].Value)
	if err != nil {
		t.Fatalf("failed to marshal container: %v", err)
	}
	var container Container
	if err := json.Unmarshal(containerBytes, &container); err != nil {
		t.Fatalf("failed to unmarshal container: %v", err)
	}
	if container.Name != "chio-sidecar" {
		t.Fatalf("expected container name chio-sidecar, got %s", container.Name)
	}
	if container.Image != DefaultSidecarImage {
		t.Fatalf("expected image %s, got %s", DefaultSidecarImage, container.Image)
	}
}

func TestMutate_CustomSidecarImage(t *testing.T) {
	body := buildAdmissionReview(t, map[string]string{
		AnnotationInject:       "true",
		AnnotationSidecarImage: "myregistry/chio-sidecar:v1.0",
	})

	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleMutate(rec, req)

	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	var patches []PatchOperation
	if err := json.Unmarshal(review.Response.Patch, &patches); err != nil {
		t.Fatalf("failed to parse patch: %v", err)
	}

	containerBytes, _ := json.Marshal(patches[0].Value)
	var container Container
	_ = json.Unmarshal(containerBytes, &container)

	if container.Image != "myregistry/chio-sidecar:v1.0" {
		t.Fatalf("expected custom image, got %s", container.Image)
	}
}

func TestHealthz(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	handleHealthz(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestBuildSidecarContainer_Defaults(t *testing.T) {
	container := buildSidecarContainer(map[string]string{})

	if container.Name != "chio-sidecar" {
		t.Fatalf("expected chio-sidecar, got %s", container.Name)
	}
	if container.Image != DefaultSidecarImage {
		t.Fatalf("expected default image, got %s", container.Image)
	}
	if len(container.Ports) != 1 || container.Ports[0].ContainerPort != 9090 {
		t.Fatal("expected port 9090")
	}
	if container.ReadinessProbe == nil {
		t.Fatal("expected readiness probe")
	}
}

func TestBuildSidecarContainer_WithAnnotations(t *testing.T) {
	annotations := map[string]string{
		AnnotationSidecarImage: "custom:v2",
		AnnotationUpstream:     "http://127.0.0.1:5000",
		AnnotationSpecPath:     "/app/spec.yaml",
		AnnotationReceiptStore: "sqlite:///data/receipts.db",
	}

	container := buildSidecarContainer(annotations)

	if container.Image != "custom:v2" {
		t.Fatalf("expected custom:v2, got %s", container.Image)
	}

	// Verify args contain upstream, spec, and receipt-store.
	argsStr := ""
	for _, arg := range container.Args {
		argsStr += arg + " "
	}
	if !contains(container.Args, "--upstream") {
		t.Fatal("expected --upstream in args")
	}
	if !contains(container.Args, "--spec") {
		t.Fatal("expected --spec in args")
	}
	if !contains(container.Args, "--receipt-store") {
		t.Fatal("expected --receipt-store in args")
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
