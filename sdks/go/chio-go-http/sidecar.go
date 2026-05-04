package chio

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// SidecarClient communicates with the Chio Rust kernel running as a
// localhost sidecar. It sends evaluation requests over HTTP and returns
// signed receipts.
type SidecarClient struct {
	baseURL string
	client  *http.Client
}

// NewSidecarClient creates a new sidecar client.
func NewSidecarClient(baseURL string, timeoutSeconds int) *SidecarClient {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 5
	}
	return &SidecarClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		client: &http.Client{
			Timeout: time.Duration(timeoutSeconds) * time.Second,
		},
	}
}

// SidecarError represents an error from the Chio sidecar.
type SidecarError struct {
	Code       string
	Message    string
	StatusCode int
}

func (e *SidecarError) Error() string {
	if e.StatusCode > 0 {
		return fmt.Sprintf("chio sidecar %s (HTTP %d): %s", e.Code, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("chio sidecar %s: %s", e.Code, e.Message)
}

// Evaluate sends an HTTP request to the Chio sidecar for evaluation.
// Returns the verdict, signed receipt, and guard evidence.
func (c *SidecarClient) Evaluate(ctx context.Context, req ChioHTTPRequest, capabilityToken string) (*EvaluateResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, &SidecarError{
			Code:    ErrEvaluationFailed,
			Message: "failed to marshal request: " + err.Error(),
		}
	}

	url := c.baseURL + "/chio/evaluate"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, &SidecarError{
			Code:    ErrSidecarUnreachable,
			Message: "failed to create request: " + err.Error(),
		}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if capabilityToken != "" {
		httpReq.Header.Set("X-Chio-Capability", capabilityToken)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, &SidecarError{
			Code:    ErrSidecarUnreachable,
			Message: "failed to reach sidecar at " + c.baseURL + ": " + err.Error(),
		}
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &SidecarError{
			Code:    ErrSidecarUnreachable,
			Message: "failed to read response body: " + err.Error(),
		}
	}

	if resp.StatusCode >= 400 {
		return nil, &SidecarError{
			Code:       ErrEvaluationFailed,
			Message:    "sidecar returned " + resp.Status + ": " + string(respBody),
			StatusCode: resp.StatusCode,
		}
	}

	var result EvaluateResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, &SidecarError{
			Code:    ErrEvaluationFailed,
			Message: "failed to decode response: " + err.Error(),
		}
	}

	return &result, nil
}

// VerifyReceipt asks the sidecar to verify a receipt signature.
// Returns true if valid.
func (c *SidecarClient) VerifyReceipt(ctx context.Context, receipt HTTPReceipt) (bool, error) {
	body, err := json.Marshal(receipt)
	if err != nil {
		return false, &SidecarError{
			Code:    ErrInvalidReceipt,
			Message: "failed to marshal receipt: " + err.Error(),
		}
	}

	url := c.baseURL + "/chio/verify"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return false, &SidecarError{
			Code:    ErrSidecarUnreachable,
			Message: "failed to create request: " + err.Error(),
		}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return false, &SidecarError{
			Code:    ErrSidecarUnreachable,
			Message: "failed to reach sidecar: " + err.Error(),
		}
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		// Fail closed (valid=false) but classify the failure so callers can
		// distinguish "the sidecar definitively rejected this receipt" from
		// "the sidecar itself is unhealthy or unreachable".
		//
		// 4xx with a body that carries a verdict means the sidecar made a
		// decision about the receipt, so we keep ErrInvalidReceipt for those.
		// 5xx (and the 408 request timeout) indicate the verify endpoint or
		// upstream infrastructure is degraded; classifying those as
		// ErrInvalidReceipt would mislead callers into treating a sidecar
		// outage as a definitive "this receipt is invalid".
		code := ErrInvalidReceipt
		if isSidecarTransportFailure(resp.StatusCode) {
			code = ErrSidecarUnavailable
		}
		return false, &SidecarError{
			Code:       code,
			Message:    "sidecar verify returned non-200: " + resp.Status,
			StatusCode: resp.StatusCode,
		}
	}

	var result struct {
		Valid bool `json:"valid"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, &SidecarError{
			Code:    ErrInvalidReceipt,
			Message: "failed to decode verify response: " + err.Error(),
		}
	}
	return result.Valid, nil
}

// isSidecarTransportFailure reports whether the HTTP status indicates a
// sidecar (or upstream) infrastructure failure rather than a verdict about
// the receipt. We treat 5xx and 408 (request timeout) as transport failures.
func isSidecarTransportFailure(status int) bool {
	if status == http.StatusRequestTimeout {
		return true
	}
	return status >= 500 && status <= 599
}

// HealthCheck checks whether the sidecar is running.
func (c *SidecarClient) HealthCheck(ctx context.Context) (bool, error) {
	url := c.baseURL + "/chio/health"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return false, nil
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	return resp.StatusCode == http.StatusOK, nil
}
