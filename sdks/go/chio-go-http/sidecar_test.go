package chio

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// verifyServer returns a test server whose /chio/verify endpoint replies with
// the configured status and JSON body.
func verifyServer(t *testing.T, status int, body any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chio/verify" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func TestVerifyReceipt_Success(t *testing.T) {
	srv := verifyServer(t, http.StatusOK, map[string]bool{"valid": true})
	defer srv.Close()

	client := NewSidecarClient(srv.URL, 5)
	ok, err := client.VerifyReceipt(context.Background(), HTTPReceipt{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected valid=true")
	}
}

func TestVerifyReceipt_InvalidReceiptValidFalse(t *testing.T) {
	// Definitive "your receipt is bad" path: sidecar returned 200 with
	// valid=false. Callers should observe ok=false and no error.
	srv := verifyServer(t, http.StatusOK, map[string]bool{"valid": false})
	defer srv.Close()

	client := NewSidecarClient(srv.URL, 5)
	ok, err := client.VerifyReceipt(context.Background(), HTTPReceipt{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatalf("expected valid=false")
	}
}

func TestVerifyReceipt_FourXXClassifiedAsInvalidReceipt(t *testing.T) {
	cases := []int{
		http.StatusBadRequest,    // 400
		http.StatusUnauthorized,  // 401
		http.StatusForbidden,     // 403
		http.StatusUnprocessableEntity,
	}
	for _, status := range cases {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := verifyServer(t, status, map[string]string{"error": "bad receipt"})
			defer srv.Close()

			client := NewSidecarClient(srv.URL, 5)
			ok, err := client.VerifyReceipt(context.Background(), HTTPReceipt{})
			if ok {
				t.Fatalf("expected valid=false on %d", status)
			}
			var sErr *SidecarError
			if !errors.As(err, &sErr) {
				t.Fatalf("expected *SidecarError, got %T: %v", err, err)
			}
			if sErr.Code != ErrInvalidReceipt {
				t.Fatalf("expected %q for status %d, got %q", ErrInvalidReceipt, status, sErr.Code)
			}
			if sErr.StatusCode != status {
				t.Fatalf("expected StatusCode=%d, got %d", status, sErr.StatusCode)
			}
		})
	}
}

func TestVerifyReceipt_FiveXXClassifiedAsSidecarUnavailable(t *testing.T) {
	cases := []int{
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout,      // 504
	}
	for _, status := range cases {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := verifyServer(t, status, nil)
			defer srv.Close()

			client := NewSidecarClient(srv.URL, 5)
			ok, err := client.VerifyReceipt(context.Background(), HTTPReceipt{})
			if ok {
				t.Fatalf("expected valid=false on %d", status)
			}
			var sErr *SidecarError
			if !errors.As(err, &sErr) {
				t.Fatalf("expected *SidecarError, got %T: %v", err, err)
			}
			if sErr.Code != ErrSidecarUnavailable {
				t.Fatalf("expected %q for status %d, got %q", ErrSidecarUnavailable, status, sErr.Code)
			}
			if sErr.StatusCode != status {
				t.Fatalf("expected StatusCode=%d, got %d", status, sErr.StatusCode)
			}
		})
	}
}

func TestVerifyReceipt_RequestTimeout408ClassifiedAsSidecarUnavailable(t *testing.T) {
	srv := verifyServer(t, http.StatusRequestTimeout, nil)
	defer srv.Close()

	client := NewSidecarClient(srv.URL, 5)
	ok, err := client.VerifyReceipt(context.Background(), HTTPReceipt{})
	if ok {
		t.Fatalf("expected valid=false on 408")
	}
	var sErr *SidecarError
	if !errors.As(err, &sErr) {
		t.Fatalf("expected *SidecarError, got %T: %v", err, err)
	}
	if sErr.Code != ErrSidecarUnavailable {
		t.Fatalf("expected %q for 408, got %q", ErrSidecarUnavailable, sErr.Code)
	}
}

func TestVerifyReceipt_TransportError(t *testing.T) {
	// Point the client at an address that is not listening to force a
	// transport-level failure (connection refused).
	client := NewSidecarClient("http://127.0.0.1:1", 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ok, err := client.VerifyReceipt(ctx, HTTPReceipt{})
	if ok {
		t.Fatalf("expected valid=false on transport error")
	}
	var sErr *SidecarError
	if !errors.As(err, &sErr) {
		t.Fatalf("expected *SidecarError, got %T: %v", err, err)
	}
	if sErr.Code != ErrSidecarUnreachable {
		t.Fatalf("expected %q on transport error, got %q", ErrSidecarUnreachable, sErr.Code)
	}
}
