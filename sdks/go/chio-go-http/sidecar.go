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

	if result.Verdict.IsAllowed() || result.Receipt.Verdict.IsAllowed() {
		if !result.Verdict.IsAllowed() || !result.Receipt.IsAuthorized() {
			return nil, &SidecarError{
				Code:    ErrInvalidReceipt,
				Message: "sidecar returned an allow-shaped response without mediated receipt authorization",
			}
		}
		verification, err := c.VerifyReceipt(ctx, result.Receipt)
		if err != nil {
			return nil, &SidecarError{
				Code:    ErrInvalidReceipt,
				Message: "sidecar could not verify the returned receipt: " + err.Error(),
			}
		}
		if !verification.IsAuthorizedFor(result.Receipt) {
			return nil, &SidecarError{
				Code:    ErrInvalidReceipt,
				Message: "sidecar returned an unverified receipt",
			}
		}
	}

	return &result, nil
}

// VerifyReceipt asks the sidecar to verify a receipt authority result.
func (c *SidecarClient) VerifyReceipt(ctx context.Context, receipt HTTPReceipt) (VerifyReceiptResponse, error) {
	body, err := json.Marshal(receipt)
	if err != nil {
		return VerifyReceiptResponse{}, &SidecarError{
			Code:    ErrInvalidReceipt,
			Message: "failed to marshal receipt: " + err.Error(),
		}
	}

	url := c.baseURL + "/chio/verify"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return VerifyReceiptResponse{}, &SidecarError{
			Code:    ErrSidecarUnreachable,
			Message: "failed to create request: " + err.Error(),
		}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return VerifyReceiptResponse{}, &SidecarError{
			Code:    ErrSidecarUnreachable,
			Message: "failed to reach sidecar: " + err.Error(),
		}
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return VerifyReceiptResponse{}, &SidecarError{
			Code:    ErrSidecarUnreachable,
			Message: "failed to read verify response body: " + err.Error(),
		}
	}

	if resp.StatusCode != http.StatusOK {
		code := classifyVerifyNonOK(resp.StatusCode, respBody)
		return VerifyReceiptResponse{}, &SidecarError{
			Code:       code,
			Message:    "sidecar verify returned non-200: " + resp.Status,
			StatusCode: resp.StatusCode,
		}
	}

	var result VerifyReceiptResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return VerifyReceiptResponse{}, &SidecarError{
			Code:    ErrEvaluationFailed,
			Message: "failed to decode verify response: " + err.Error(),
		}
	}
	if result.ReceiptKind == "" || result.BoundaryClass == "" || result.TrustLevel == "" {
		return VerifyReceiptResponse{}, &SidecarError{
			Code:    ErrEvaluationFailed,
			Message: "sidecar verify response missing structured authority fields",
		}
	}
	return result, nil
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

func classifyVerifyNonOK(status int, body []byte) string {
	if hasDefinitiveInvalidReceiptVerdict(body) {
		return ErrInvalidReceipt
	}
	if isSidecarTransportFailure(status) || status == http.StatusNotFound || status == http.StatusTooManyRequests {
		return ErrSidecarUnavailable
	}
	return ErrEvaluationFailed
}

func hasDefinitiveInvalidReceiptVerdict(body []byte) bool {
	var result struct {
		Valid      *bool  `json:"valid"`
		OK         *bool  `json:"ok"`
		Authorized *bool  `json:"authorized"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return false
	}
	return (result.Valid != nil && !*result.Valid) ||
		(result.OK != nil && !*result.OK) ||
		(result.Authorized != nil && !*result.Authorized) ||
		result.Error == ErrInvalidReceipt
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
