package chio

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type failingReadCloser struct{}

func (failingReadCloser) Read(_ []byte) (int, error) {
	return 0, errors.New("body read failed")
}

func (failingReadCloser) Close() error {
	return nil
}

// mockSidecar creates a test HTTP server that simulates the Chio sidecar kernel.
func mockSidecar(t *testing.T, verdict Verdict) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/chio/evaluate":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read request body: %v", err)
			}
			var req ChioHTTPRequest
			if err := json.Unmarshal(body, &req); err != nil {
				t.Fatalf("failed to unmarshal request: %v", err)
			}

			responseStatus := 200
			if verdict.IsDenied() {
				responseStatus = 403
			}

			resp := EvaluateResponse{
				Verdict: verdict,
				Receipt: HTTPReceipt{
					ID:                 authorizedReceiptID,
					RequestID:          req.RequestID,
					RoutePattern:       req.RoutePattern,
					Method:             req.Method,
					CallerIdentityHash: "test-hash",
					Verdict:            verdict,
					ReceiptKind:        "mediated_decision",
					BoundaryClass:      "prevent",
					ToolOrigin:         "caller_executed",
					RedactionMode:      "none",
					TrustLevel:         "mediated",
					Evidence:           []GuardEvidence{},
					ResponseStatus:     responseStatus,
					Timestamp:          req.Timestamp,
					ContentHash:        authorizedContentHash,
					PolicyHash:         "test-policy-hash",
					KernelKey:          "test-kernel-key",
					Signature:          "test-signature",
				},
				Evidence: []GuardEvidence{},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)

		case "/chio/verify":
			writeVerifyResponse(w, true)

		case "/chio/health":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok"}`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func writeVerifyResponse(w http.ResponseWriter, valid bool) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(verifyReceiptBody(valid, valid))
}

func TestProtect_AllowedGET(t *testing.T) {
	sidecar := mockSidecar(t, Verdict{Verdict: "allow"})
	defer sidecar.Close()

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	handler := Protect(inner, WithSidecarURL(sidecar.URL))

	req := httptest.NewRequest(http.MethodGet, "/pets", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	receiptID := rec.Header().Get("X-Chio-Receipt-Id")
	if receiptID == "" {
		t.Fatal("expected X-Chio-Receipt-Id header")
	}
	if receiptID != authorizedReceiptID {
		t.Fatalf("expected %s, got %s", authorizedReceiptID, receiptID)
	}
}

func TestProtect_DeniedPOST(t *testing.T) {
	sidecar := mockSidecar(t, Verdict{
		Verdict:    "deny",
		Reason:     "side-effect route requires a capability token",
		Guard:      "CapabilityGuard",
		HTTPStatus: 403,
	})
	defer sidecar.Close()

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("inner handler should not be called for denied requests")
	})

	handler := Protect(inner, WithSidecarURL(sidecar.URL))

	req := httptest.NewRequest(http.MethodPost, "/pets", strings.NewReader(`{"name":"Fido"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Error != ErrAccessDenied {
		t.Fatalf("expected error code %s, got %s", ErrAccessDenied, errResp.Error)
	}
	if errResp.ReceiptID != authorizedReceiptID {
		t.Fatalf("expected receipt_id %s, got %s", authorizedReceiptID, errResp.ReceiptID)
	}
}

func TestProtect_IncompleteFailsClosed(t *testing.T) {
	sidecar := mockSidecar(t, Verdict{
		Verdict:    "incomplete",
		Reason:     "sidecar could not finish evaluation",
		HTTPStatus: http.StatusServiceUnavailable,
	})
	defer sidecar.Close()

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("inner handler should not be called for incomplete evaluation")
	})

	handler := Protect(inner, WithSidecarURL(sidecar.URL))

	req := httptest.NewRequest(http.MethodGet, "/pets", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
	var errResp ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Error != ErrAccessDenied {
		t.Fatalf("expected error code %s, got %s", ErrAccessDenied, errResp.Error)
	}
}

func TestProtect_UnverifiedAllowFailsClosed(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/chio/evaluate":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read request body: %v", err)
			}
			var req ChioHTTPRequest
			if err := json.Unmarshal(body, &req); err != nil {
				t.Fatalf("failed to unmarshal request: %v", err)
			}
			resp := EvaluateResponse{
				Verdict: Verdict{Verdict: "allow"},
				Receipt: HTTPReceipt{
					ID:             "receipt-unverified",
					RequestID:      req.RequestID,
					RoutePattern:   req.RoutePattern,
					Method:         req.Method,
					Verdict:        Verdict{Verdict: "allow"},
					ReceiptKind:    "mediated_decision",
					BoundaryClass:  "prevent",
					ToolOrigin:     "caller_executed",
					RedactionMode:  "none",
					TrustLevel:     "mediated",
					ResponseStatus: 200,
					ContentHash:    authorizedContentHash,
					KernelKey:      "test-kernel-key",
					Signature:      "bad-signature",
				},
				Evidence: []GuardEvidence{},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		case "/chio/verify":
			writeVerifyResponse(w, false)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer sidecar.Close()

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("inner handler should not be called for unverified allow")
	})

	handler := Protect(inner, WithSidecarURL(sidecar.URL))

	req := httptest.NewRequest(http.MethodGet, "/pets", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Chio-Receipt-Id"); got != "" {
		t.Fatalf("expected no verified receipt header, got %q", got)
	}
	var errResp ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Error != ErrInvalidReceipt {
		t.Fatalf("expected error code %s, got %s", ErrInvalidReceipt, errResp.Error)
	}
}

func TestProtect_VerifierWithoutFullAuthorityTupleFailsClosed(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/chio/evaluate":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("failed to read request body: %v", err)
			}
			var req ChioHTTPRequest
			if err := json.Unmarshal(body, &req); err != nil {
				t.Fatalf("failed to unmarshal request: %v", err)
			}
			resp := EvaluateResponse{
				Verdict: Verdict{Verdict: "allow"},
				Receipt: HTTPReceipt{
					ID:             authorizedReceiptID,
					RequestID:      req.RequestID,
					RoutePattern:   req.RoutePattern,
					Method:         req.Method,
					Verdict:        Verdict{Verdict: "allow"},
					ReceiptKind:    "mediated_decision",
					BoundaryClass:  "prevent",
					ToolOrigin:     "caller_executed",
					RedactionMode:  "none",
					TrustLevel:     "mediated",
					ResponseStatus: 200,
					ContentHash:    authorizedContentHash,
					KernelKey:      "test-kernel-key",
					Signature:      "test-signature",
				},
				Evidence: []GuardEvidence{},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		case "/chio/verify":
			body := verifyReceiptBody(true, true)
			body.ReceiptIDValid = false
			_ = json.NewEncoder(w).Encode(body)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer sidecar.Close()

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("inner handler should not be called for verifier authority mismatch")
	})

	handler := Protect(inner, WithSidecarURL(sidecar.URL))
	req := httptest.NewRequest(http.MethodGet, "/pets", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Chio-Receipt-Id"); got != "" {
		t.Fatalf("expected no verified receipt header, got %q", got)
	}
}

func TestProtect_UnsupportedMethod(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("inner handler should not be called")
	})

	handler := Protect(inner, WithSidecarURL("http://127.0.0.1:1"))

	req := httptest.NewRequest("FOOBAR", "/pets", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestProtect_BodyReadFailureFailsClosed(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("inner handler should not be called when request body cannot be read")
	})

	handler := Protect(inner, WithSidecarURL("http://127.0.0.1:1"))

	req := httptest.NewRequest(http.MethodPost, "/pets", nil)
	req.Body = failingReadCloser{}
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	var errResp ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Error != ErrEvaluationFailed {
		t.Fatalf("expected error code %s, got %s", ErrEvaluationFailed, errResp.Error)
	}
}

func TestProtect_SidecarUnreachable_FailClosed(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("inner handler should not be called when sidecar is down and fail-closed")
	})

	handler := Protect(inner, WithSidecarURL("http://127.0.0.1:1"))

	req := httptest.NewRequest(http.MethodGet, "/pets", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rec.Code)
	}
}

func TestProtect_BearerIdentityExtraction(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/chio/verify" {
			writeVerifyResponse(w, true)
			return
		}

		body, _ := io.ReadAll(r.Body)
		var req ChioHTTPRequest
		_ = json.Unmarshal(body, &req)

		if !strings.HasPrefix(req.Caller.Subject, "bearer:") {
			t.Errorf("expected bearer: subject prefix, got %s", req.Caller.Subject)
		}
		if req.Caller.AuthMethod.Method != "bearer" {
			t.Errorf("expected bearer auth method, got %s", req.Caller.AuthMethod.Method)
		}

		resp := EvaluateResponse{
			Verdict: Verdict{Verdict: "allow"},
			Receipt: HTTPReceipt{
				ID:             authorizedReceiptID,
				RequestID:      req.RequestID,
				RoutePattern:   req.RoutePattern,
				Method:         req.Method,
				Verdict:        Verdict{Verdict: "allow"},
				ReceiptKind:    "mediated_decision",
				BoundaryClass:  "prevent",
				ToolOrigin:     "caller_executed",
				RedactionMode:  "none",
				TrustLevel:     "mediated",
				ResponseStatus: 200,
				ContentHash:    authorizedContentHash,
				KernelKey:      "key",
				Signature:      "sig",
			},
			Evidence: []GuardEvidence{},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer sidecar.Close()

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := Protect(inner, WithSidecarURL(sidecar.URL))

	req := httptest.NewRequest(http.MethodGet, "/pets", nil)
	req.Header.Set("Authorization", "Bearer my-secret-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestProtect_CustomRouteResolver(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/chio/verify" {
			writeVerifyResponse(w, true)
			return
		}

		body, _ := io.ReadAll(r.Body)
		var req ChioHTTPRequest
		_ = json.Unmarshal(body, &req)

		if req.RoutePattern != "/pets/{petId}" {
			t.Errorf("expected route pattern /pets/{petId}, got %s", req.RoutePattern)
		}

		resp := EvaluateResponse{
			Verdict: Verdict{Verdict: "allow"},
			Receipt: HTTPReceipt{
				ID:             authorizedReceiptID,
				RequestID:      req.RequestID,
				RoutePattern:   req.RoutePattern,
				Method:         req.Method,
				Verdict:        Verdict{Verdict: "allow"},
				ReceiptKind:    "mediated_decision",
				BoundaryClass:  "prevent",
				ToolOrigin:     "caller_executed",
				RedactionMode:  "none",
				TrustLevel:     "mediated",
				ResponseStatus: 200,
				ContentHash:    authorizedContentHash,
				KernelKey:      "key",
				Signature:      "sig",
			},
			Evidence: []GuardEvidence{},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer sidecar.Close()

	resolver := func(_method, path string) string {
		if strings.HasPrefix(path, "/pets/") && path != "/pets/" {
			return "/pets/{petId}"
		}
		return path
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := Protect(inner,
		WithSidecarURL(sidecar.URL),
		WithRouteResolver(resolver),
	)

	req := httptest.NewRequest(http.MethodGet, "/pets/42", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestProtect_ForwardsQueryCapabilityTokenToSidecar(t *testing.T) {
	observedCapability := ""
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/chio/verify" {
			writeVerifyResponse(w, true)
			return
		}

		observedCapability = r.Header.Get("X-Chio-Capability")

		body, _ := io.ReadAll(r.Body)
		var req ChioHTTPRequest
		_ = json.Unmarshal(body, &req)

		resp := EvaluateResponse{
			Verdict: Verdict{Verdict: "allow"},
			Receipt: HTTPReceipt{
				ID:             authorizedReceiptID,
				RequestID:      req.RequestID,
				RoutePattern:   req.RoutePattern,
				Method:         req.Method,
				Verdict:        Verdict{Verdict: "allow"},
				ReceiptKind:    "mediated_decision",
				BoundaryClass:  "prevent",
				ToolOrigin:     "caller_executed",
				RedactionMode:  "none",
				TrustLevel:     "mediated",
				ResponseStatus: 200,
				ContentHash:    authorizedContentHash,
				KernelKey:      "key",
				Signature:      "sig",
			},
			Evidence: []GuardEvidence{},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer sidecar.Close()

	innerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		innerCalled = true
		w.WriteHeader(http.StatusNoContent)
	})

	handler := Protect(inner, WithSidecarURL(sidecar.URL))

	req := httptest.NewRequest(http.MethodPost, "/pets?chio_capability=query-token", strings.NewReader(`{"name":"Fido"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !innerCalled {
		t.Fatal("inner handler should be called for allowed requests")
	}
	if observedCapability != "query-token" {
		t.Fatalf("expected sidecar to receive query capability token, got %q", observedCapability)
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
}

// Conformance: verify types serialize to the same JSON structure as the
// Rust kernel types (shared test vectors).
func TestConformance_VerdictSerialization(t *testing.T) {
	tests := []struct {
		name     string
		verdict  Verdict
		contains []string
	}{
		{
			name:     "allow",
			verdict:  Verdict{Verdict: "allow"},
			contains: []string{`"verdict":"allow"`},
		},
		{
			name: "deny",
			verdict: Verdict{
				Verdict:    "deny",
				Reason:     "no capability",
				Guard:      "CapabilityGuard",
				HTTPStatus: 403,
			},
			contains: []string{
				`"verdict":"deny"`,
				`"reason":"no capability"`,
				`"guard":"CapabilityGuard"`,
				`"http_status":403`,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.verdict)
			if err != nil {
				t.Fatalf("marshal error: %v", err)
			}
			jsonStr := string(data)
			for _, s := range tc.contains {
				if !strings.Contains(jsonStr, s) {
					t.Errorf("expected JSON to contain %q, got %s", s, jsonStr)
				}
			}
		})
	}
}

func TestConformance_CallerIdentitySerialization(t *testing.T) {
	tests := []struct {
		name     string
		caller   CallerIdentity
		contains []string
	}{
		{
			name:   "anonymous",
			caller: AnonymousIdentity(),
			contains: []string{
				`"subject":"anonymous"`,
				`"method":"anonymous"`,
				`"verified":false`,
			},
		},
		{
			name: "bearer",
			caller: CallerIdentity{
				Subject: "bearer:abc123",
				AuthMethod: AuthMethod{
					Method:    "bearer",
					TokenHash: "abc123def456",
				},
				Verified: false,
			},
			contains: []string{
				`"subject":"bearer:abc123"`,
				`"method":"bearer"`,
				`"token_hash":"abc123def456"`,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.caller)
			if err != nil {
				t.Fatalf("marshal error: %v", err)
			}
			jsonStr := string(data)
			for _, s := range tc.contains {
				if !strings.Contains(jsonStr, s) {
					t.Errorf("expected JSON to contain %q, got %s", s, jsonStr)
				}
			}
		})
	}
}

func TestConformance_ChioHTTPRequestSerialization(t *testing.T) {
	req := ChioHTTPRequest{
		RequestID:    "req-001",
		Method:       "GET",
		RoutePattern: "/pets/{petId}",
		Path:         "/pets/42",
		Query:        map[string]string{"verbose": "true"},
		Caller:       AnonymousIdentity(),
		Timestamp:    1700000000,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	jsonStr := string(data)
	expected := []string{
		`"request_id":"req-001"`,
		`"method":"GET"`,
		`"route_pattern":"/pets/{petId}"`,
		`"path":"/pets/42"`,
		`"timestamp":1700000000`,
	}
	for _, s := range expected {
		if !strings.Contains(jsonStr, s) {
			t.Errorf("expected JSON to contain %q, got %s", s, jsonStr)
		}
	}

	// Verify round-trip deserialization.
	var back ChioHTTPRequest
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if back.RequestID != "req-001" {
		t.Errorf("expected request_id req-001, got %s", back.RequestID)
	}
	if back.RoutePattern != "/pets/{petId}" {
		t.Errorf("expected route_pattern /pets/{petId}, got %s", back.RoutePattern)
	}
}

func TestConformance_HTTPReceiptSerialization(t *testing.T) {
	receipt := HTTPReceipt{
		ID:                 "receipt-001",
		RequestID:          "req-001",
		RoutePattern:       "/pets/{petId}",
		Method:             "GET",
		CallerIdentityHash: "abc123",
		Verdict:            Verdict{Verdict: "allow"},
		ReceiptKind:        "mediated_decision",
		BoundaryClass:      "prevent",
		ToolOrigin:         "caller_executed",
		RedactionMode:      "none",
		TrustLevel:         "mediated",
		Evidence:           []GuardEvidence{},
		ResponseStatus:     200,
		Timestamp:          1700000000,
		ContentHash:        "deadbeef",
		PolicyHash:         "cafebabe",
		KernelKey:          "test-key",
		Signature:          "test-sig",
	}

	data, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var back HTTPReceipt
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if back.ID != "receipt-001" {
		t.Errorf("expected id receipt-001, got %s", back.ID)
	}
	if !back.Verdict.IsAllowed() {
		t.Error("expected verdict to be allowed")
	}
}

func TestIdentity_SHA256Hex(t *testing.T) {
	// Known test vector: SHA-256 of empty string.
	hash := sha256Hex("")
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if hash != expected {
		t.Fatalf("sha256 of empty string: expected %s, got %s", expected, hash)
	}
}

func TestIdentity_DefaultExtractor_Anonymous(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	caller := DefaultIdentityExtractor(req)
	if caller.Subject != "anonymous" {
		t.Fatalf("expected anonymous subject, got %s", caller.Subject)
	}
}

func TestIdentity_DefaultExtractor_Bearer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	caller := DefaultIdentityExtractor(req)
	if !strings.HasPrefix(caller.Subject, "bearer:") {
		t.Fatalf("expected bearer: prefix, got %s", caller.Subject)
	}
	if caller.AuthMethod.Method != "bearer" {
		t.Fatalf("expected bearer method, got %s", caller.AuthMethod.Method)
	}
}

func TestIdentity_DefaultExtractor_APIKey(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-API-Key", "my-api-key")
	caller := DefaultIdentityExtractor(req)
	if !strings.HasPrefix(caller.Subject, "apikey:") {
		t.Fatalf("expected apikey: prefix, got %s", caller.Subject)
	}
	if caller.AuthMethod.Method != "api_key" {
		t.Fatalf("expected api_key method, got %s", caller.AuthMethod.Method)
	}
}
