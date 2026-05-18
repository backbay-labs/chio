package chio

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// validMethods maps HTTP method strings to their normalized uppercase forms.
var validMethods = map[string]bool{
	"GET":     true,
	"POST":    true,
	"PUT":     true,
	"PATCH":   true,
	"DELETE":  true,
	"HEAD":    true,
	"OPTIONS": true,
}

// normalizeMethod returns the uppercase HTTP method if valid.
func normalizeMethod(method string) (string, bool) {
	upper := strings.ToUpper(method)
	if validMethods[upper] {
		return upper, true
	}
	return "", false
}

// buildChioHTTPRequest constructs a ChioHTTPRequest from a net/http request.
func buildChioHTTPRequest(r *http.Request, method, routePattern string, caller CallerIdentity) (ChioHTTPRequest, error) {
	// Parse query parameters.
	query := make(map[string]string)
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			query[key] = values[0]
		}
	}

	// Extract selected headers for policy evaluation.
	headers := filterHeaders(r, []string{
		"content-type",
		"content-length",
	})

	// Read and hash body for content binding.
	var bodyHash string
	var bodyLength int64
	if r.Body != nil {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			return ChioHTTPRequest{}, err
		}
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		bodyLength = int64(len(bodyBytes))
		if len(bodyBytes) > 0 {
			h := sha256.Sum256(bodyBytes)
			bodyHash = hex.EncodeToString(h[:])
		}
	}

	capabilityID := capabilityIDFromToken(extractCapabilityToken(r))

	return ChioHTTPRequest{
		RequestID:    uuid.New().String(),
		Method:       method,
		RoutePattern: routePattern,
		Path:         r.URL.Path,
		Query:        query,
		Headers:      headers,
		Caller:       caller,
		BodyHash:     bodyHash,
		BodyLength:   bodyLength,
		SessionID:    "",
		CapabilityID: capabilityID,
		Timestamp:    time.Now().Unix(),
	}, nil
}

func extractCapabilityToken(r *http.Request) string {
	if token := r.Header.Get("X-Chio-Capability"); token != "" {
		return token
	}
	return r.URL.Query().Get("chio_capability")
}

func capabilityIDFromToken(rawToken string) string {
	if rawToken == "" {
		return ""
	}
	var parsed struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(rawToken), &parsed); err != nil {
		return ""
	}
	return parsed.ID
}

// filterHeaders extracts only the allowed headers from the request.
func filterHeaders(r *http.Request, allowed []string) map[string]string {
	result := make(map[string]string)
	for _, name := range allowed {
		value := r.Header.Get(name)
		if value != "" {
			result[strings.ToLower(name)] = value
		}
	}
	return result
}

// writeJSONError sends a structured JSON error response.
func writeJSONError(w http.ResponseWriter, status int, body ErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
