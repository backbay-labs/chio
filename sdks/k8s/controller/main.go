// Package main implements the Chio Kubernetes admission controller and sidecar injector.
//
// This controller runs as a Kubernetes admission webhook that:
//  1. Rejects pods without valid Chio capability tokens issued by configured Chio
//     trust anchors.
//  2. Injects the chio-api-protect sidecar container into pods that have the
//     chio.backbay.io/inject: "true" annotation.
//
// The sidecar container communicates with the application container over
// localhost, proxying HTTP traffic through the Chio kernel for capability
// validation and receipt signing.
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	port := os.Getenv("PORT")
	if port == "" {
		port = "8443"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/validate", handleValidate)
	mux.HandleFunc("/mutate", handleMutate)
	mux.HandleFunc("/healthz", handleHealthz)

	addr := ":" + port
	log.Printf("Chio admission controller listening on %s", addr)

	if certFile != "" && keyFile != "" {
		server := &http.Server{
			Addr:    addr,
			Handler: mux,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}
		if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
			log.Fatalf("server error: %v", err)
		}
	} else {
		// Non-TLS for development/testing.
		log.Println("WARNING: running without TLS (development mode)")
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Fatalf("server error: %v", err)
		}
	}
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// handleValidate is the validating admission webhook handler.
// It rejects pods that lack the required Chio capability token or whose token
// does not validate against configured Chio trust anchors.
func handleValidate(w http.ResponseWriter, r *http.Request) {
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

	response := validatePod(review.Request)
	review.Response = &response
	review.Response.UID = review.Request.UID

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(review)
}

// handleMutate is the mutating admission webhook handler.
// It injects the chio-api-protect sidecar into annotated pods.
func handleMutate(w http.ResponseWriter, r *http.Request) {
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

	response := mutatePod(review.Request)
	review.Response = &response
	review.Response.UID = review.Request.UID

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(review)
}

// validatePod checks whether a pod has the required Chio annotations.
func validatePod(req AdmissionRequest) AdmissionResponse {
	var pod PodSpec
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		return denyResponse(fmt.Sprintf("failed to parse pod spec: %v", err))
	}

	annotations := pod.Metadata.Annotations

	capToken := annotations[AnnotationCapabilityToken]
	if capToken == "" {
		return denyResponse(
			"pod missing required annotation " + AnnotationCapabilityToken +
				"; provide a valid Chio capability token issued by a configured trusted issuer",
		)
	}

	if annotations[AnnotationRequiredScopes] != "" {
		return denyResponse(
			"pod-supplied required scopes are not trusted; configure " + envRequiredScopes +
				" on the admission controller",
		)
	}

	requiredScopes, err := loadRequiredScopesFromEnv()
	if err != nil {
		return denyResponse(err.Error())
	}

	if err := validateCapabilityToken(capToken, requiredScopes, time.Now().UTC()); err != nil {
		return denyResponse(err.Error())
	}

	return allowResponse("Chio capability token validated against configured trusted issuers")
}

// mutatePod injects the Chio sidecar if the pod has the injection annotation.
func mutatePod(req AdmissionRequest) AdmissionResponse {
	var pod PodSpec
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		return denyResponse(fmt.Sprintf("failed to parse pod spec: %v", err))
	}

	annotations := pod.Metadata.Annotations

	// Only inject if annotation is present.
	if annotations[AnnotationInject] != "true" {
		return allowResponse("no injection requested")
	}

	// Build sidecar container from annotations.
	sidecar := buildSidecarContainer(annotations)

	// Create JSON patch to add the sidecar container.
	patch := buildSidecarPatch(sidecar)

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return denyResponse(fmt.Sprintf("failed to marshal patch: %v", err))
	}

	patchType := "JSONPatch"
	return AdmissionResponse{
		Allowed:   true,
		PatchType: &patchType,
		Patch:     patchBytes,
		Result: &StatusResult{
			Message: "Chio sidecar injected",
		},
	}
}

// buildSidecarContainer creates the Chio sidecar container spec from pod annotations.
func buildSidecarContainer(annotations map[string]string) Container {
	image := annotations[AnnotationSidecarImage]
	if image == "" {
		image = DefaultSidecarImage
	}

	upstream := annotations[AnnotationUpstream]
	if upstream == "" {
		upstream = "http://127.0.0.1:8080"
	}

	specPath := annotations[AnnotationSpecPath]
	receiptStore := annotations[AnnotationReceiptStore]

	args := []string{"api", "protect"}
	args = append(args, "--upstream", upstream)
	if specPath != "" {
		args = append(args, "--spec", specPath)
	}
	if receiptStore != "" {
		args = append(args, "--receipt-store", receiptStore)
	}

	return Container{
		Name:  "chio-sidecar",
		Image: image,
		Args:  args,
		Ports: []ContainerPort{
			{
				Name:          "chio-proxy",
				ContainerPort: 9090,
				Protocol:      "TCP",
			},
		},
		ReadinessProbe: &Probe{
			HTTPGet: &HTTPGetAction{
				Path: "/chio/health",
				Port: 9090,
			},
			InitialDelaySeconds: 2,
			PeriodSeconds:       5,
		},
		Resources: ResourceRequirements{
			Limits: ResourceList{
				CPU:    "100m",
				Memory: "64Mi",
			},
			Requests: ResourceList{
				CPU:    "50m",
				Memory: "32Mi",
			},
		},
	}
}

// buildSidecarPatch creates a JSON Patch to add the sidecar container.
func buildSidecarPatch(sidecar Container) []PatchOperation {
	return []PatchOperation{
		{
			Op:    "add",
			Path:  "/spec/containers/-",
			Value: sidecar,
		},
	}
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
		},
	}
}
