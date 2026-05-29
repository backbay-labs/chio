// Package chio provides HTTP middleware for the Chio protocol.
//
// Chio secures HTTP APIs with
// cryptographic receipts and capability-based access control. This package
// wraps any net/http Handler, sending evaluation requests to the Chio Rust
// kernel running as a localhost sidecar and attaching signed receipt IDs to
// evaluated responses.
//
// Usage:
//
//	mux := http.NewServeMux()
//	mux.HandleFunc("/pets", handlePets)
//	protected := chio.Protect(mux, chio.ConfigFile("chio.yaml"))
//	http.ListenAndServe(":8080", protected)
package chio

import (
	"errors"
	"net/http"
)

// Protect wraps an http.Handler with Chio capability validation and receipt
// signing. All requests are evaluated against the Chio sidecar kernel before
// being forwarded to the inner handler. Denied requests receive a structured
// JSON error response; allowed requests proceed with a signed receipt ID in
// the X-Chio-Receipt-Id response header when Chio evaluation succeeds.
//
// The middleware fails closed: if the sidecar is unreachable or returns an
// error, the request is denied.
func Protect(handler http.Handler, opts ...Option) http.Handler {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	client := NewSidecarClient(cfg.SidecarURL, cfg.TimeoutSeconds)
	return &chioMiddleware{
		inner:             handler,
		client:            client,
		config:            cfg,
		identityExtractor: cfg.IdentityExtractor,
		routeResolver:     cfg.RouteResolver,
	}
}

// chioMiddleware implements http.Handler with Chio evaluation.
type chioMiddleware struct {
	inner             http.Handler
	client            *SidecarClient
	config            Config
	identityExtractor IdentityExtractorFunc
	routeResolver     RouteResolverFunc
}

func (m *chioMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Normalize method.
	method, ok := normalizeMethod(r.Method)
	if !ok {
		writeJSONError(w, http.StatusMethodNotAllowed, ErrorResponse{
			Error:   ErrEvaluationFailed,
			Message: "unsupported HTTP method: " + r.Method,
		})
		return
	}

	// Extract caller identity from request headers.
	caller := m.identityExtractor(r)

	// Resolve route pattern.
	routePattern := m.routeResolver(method, r.URL.Path)

	// Build Chio HTTP request.
	chioReq, err := buildChioHTTPRequest(r, method, routePattern, caller)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, ErrorResponse{
			Error:   ErrEvaluationFailed,
			Message: "failed to read request body for Chio evaluation: " + err.Error(),
		})
		return
	}
	capabilityToken := extractCapabilityToken(r)

	// Evaluate against sidecar.
	result, err := m.client.Evaluate(r.Context(), chioReq, capabilityToken)
	if err != nil {
		var sidecarErr *SidecarError
		if errors.As(err, &sidecarErr) && sidecarErr.Code == ErrInvalidReceipt {
			writeJSONError(w, http.StatusBadGateway, ErrorResponse{
				Error:   ErrInvalidReceipt,
				Message: "Chio sidecar receipt verification failed: " + err.Error(),
			})
			return
		}
		writeJSONError(w, http.StatusBadGateway, ErrorResponse{
			Error:   ErrSidecarUnreachable,
			Message: "Chio sidecar error: " + err.Error(),
		})
		return
	}

	// Check verdict. Anything other than a mediated allow fails closed.
	if !result.Verdict.IsAllowed() || !result.Receipt.IsAuthorized() {
		status := result.Verdict.HTTPStatus
		if status == 0 {
			status = http.StatusForbidden
		}
		writeJSONError(w, status, ErrorResponse{
			Error:      ErrAccessDenied,
			Message:    result.Verdict.Reason,
			ReceiptID:  result.Receipt.ID,
			Suggestion: "provide a valid capability token in the X-Chio-Capability header or chio_capability query parameter",
		})
		return
	}

	verification, err := m.client.VerifyReceipt(r.Context(), result.Receipt)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, ErrorResponse{
			Error:     ErrInvalidReceipt,
			Message:   "Chio sidecar receipt verification failed: " + err.Error(),
			ReceiptID: result.Receipt.ID,
		})
		return
	}
	if !verification.IsAuthorizedFor(result.Receipt) {
		writeJSONError(w, http.StatusBadGateway, ErrorResponse{
			Error:     ErrInvalidReceipt,
			Message:   "Chio sidecar returned an unverified receipt",
			ReceiptID: result.Receipt.ID,
		})
		return
	}

	// Attach receipt ID only after the receipt verifies.
	w.Header().Set("X-Chio-Receipt-Id", result.Receipt.ID)

	// Request allowed and verified, so forward to inner handler.
	m.inner.ServeHTTP(w, r)
}
