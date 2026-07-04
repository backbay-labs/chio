package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Server hosts the validating and mutating admission webhook handlers.
//
// Verification policy (trusted kernel keys, required scopes) is captured at
// construction time. The server fails closed for every admission request that
// does not bring a verifiable capability bound to the admission context.
type Server struct {
	config VerifierConfig
	now    func() time.Time
}

// NewServer constructs a Server with the given verifier configuration.
// nowFn defaults to time.Now when nil.
func NewServer(config VerifierConfig, nowFn func() time.Time) *Server {
	if nowFn == nil {
		nowFn = time.Now
	}
	return &Server{config: config, now: nowFn}
}

// Routes registers webhook routes on the given mux.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("/validate", s.HandleValidate)
	mux.HandleFunc("/mutate", s.HandleMutate)
	mux.HandleFunc("/healthz", handleHealthz)
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// HandleValidate is the validating admission webhook entrypoint.
//
// Every request is verified against the configured trust set:
//  1. Decode the AdmissionReview envelope.
//  2. Extract the candidate capability token from the pod metadata.
//  3. Run VerifyCapability against the admission context.
//  4. Allow only on success; otherwise deny with a clear reason.
func (s *Server) HandleValidate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var review AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		http.Error(w, "failed to parse AdmissionReview", http.StatusBadRequest)
		return
	}

	response := s.validatePod(review.Request)
	review.Response = &response
	review.Response.UID = review.Request.UID

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(review)
}

// HandleMutate is the mutating admission webhook entrypoint.
//
// The webhook only emits patches when the pod has been verified against the
// trust set. The mutating webhook does NOT relax verification: if the
// validating webhook would deny, the mutating webhook denies as well, so a
// misconfigured pipeline never lets unsigned pods slip past mutation.
func (s *Server) HandleMutate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var review AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		http.Error(w, "failed to parse AdmissionReview", http.StatusBadRequest)
		return
	}

	response := s.mutatePod(review.Request)
	review.Response = &response
	review.Response.UID = review.Request.UID

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(review)
}

// validatePod is the core admission decision. It is split out for testing.
func (s *Server) validatePod(req AdmissionRequest) AdmissionResponse {
	var pod PodSpec
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		return denyResponse(fmt.Sprintf("webhook denies admission: failed to parse pod spec: %v", err))
	}

	annotations := pod.Metadata.Annotations

	// Pod-supplied required-scope or exempt annotations are not honored.
	// Allowing them would let the workload override the operator's policy.
	if _, ok := annotations[AnnotationRequiredScopes]; ok {
		return denyResponse(
			"webhook denies admission: pod-supplied required scopes are not trusted; configure " +
				EnvRequiredScopes + " on the webhook",
		)
	}
	if _, ok := annotations[AnnotationExempt]; ok {
		return denyResponse(
			"webhook denies admission: pod-supplied exemptions are not honored",
		)
	}

	capToken := annotations[AnnotationCapabilityToken]
	ctx := AdmissionContext{
		Operation: strings.ToUpper(req.Operation),
		Namespace: requestNamespace(req, pod),
		Resource:  req.Resource.Resource,
	}

	if err := VerifyCapability(capToken, ctx, s.config, s.now().UTC()); err != nil {
		return denyResponse(err.Error())
	}

	return allowResponse("chio webhook: capability verified against configured trust set")
}

// mutatePod runs the same verification flow before deciding whether to emit a
// mutation. A capability token in the admission request grants only the
// authority the operator has configured; the webhook never relaxes
// verification at mutation time.
func (s *Server) mutatePod(req AdmissionRequest) AdmissionResponse {
	// Defer to validatePod for the verification decision. If that denies,
	// the mutating webhook denies too.
	decision := s.validatePod(req)
	if !decision.Allowed {
		return decision
	}

	// The mutation path emits no patch; sidecar injection is out of scope
	// for this webhook. Returning an allow with no patch is the safe default.
	return allowResponse("chio webhook: no mutation applied")
}

// requestNamespace returns the canonical admission namespace. It prefers the
// AdmissionRequest.Namespace (which Kubernetes always populates for
// namespaced resources) and falls back to the pod metadata.
func requestNamespace(req AdmissionRequest, pod PodSpec) string {
	if req.Namespace != "" {
		return req.Namespace
	}
	return pod.Metadata.Namespace
}

// RunServer is the production entrypoint: load config from env, start an
// HTTPS listener, and serve until the process exits.
func RunServer() error {
	config, err := LoadVerifierConfigFromEnv()
	if err != nil {
		return err
	}

	server := NewServer(config, time.Now)

	mux := http.NewServeMux()
	server.Routes(mux)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8443"
	}
	addr := ":" + port

	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")

	log.Printf("chio admission webhook listening on %s", addr)

	if certFile != "" && keyFile != "" {
		s := &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}
		return s.ListenAndServeTLS(certFile, keyFile)
	}
	log.Println("WARNING: serving without TLS (development mode)")
	s := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s.ListenAndServe()
}
