package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthz(t *testing.T) {
	recorder := request(t, http.MethodGet, "/healthz", nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	assertJSON(t, recorder, map[string]any{"status": "ok"})
}

func TestHello(t *testing.T) {
	recorder := request(t, http.MethodGet, "/hello", nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	assertJSON(t, recorder, map[string]any{"message": "hello from chi"})
}

func TestEchoDefaultsCount(t *testing.T) {
	recorder := request(t, http.MethodPost, "/echo", []byte(`{"message":"hello"}`))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	assertJSON(t, recorder, map[string]any{
		"message": "hello",
		"count":   float64(1),
	})
}

func TestEchoRejectsMissingMessage(t *testing.T) {
	recorder := request(t, http.MethodPost, "/echo", []byte(`{"count":1}`))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	assertError(t, recorder, "message must be a non-empty string")
}

func TestEchoRejectsEmptyMessage(t *testing.T) {
	recorder := request(t, http.MethodPost, "/echo", []byte(`{"message":"","count":1}`))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	assertError(t, recorder, "message must be a non-empty string")
}

func TestEchoRejectsZeroCount(t *testing.T) {
	recorder := request(t, http.MethodPost, "/echo", []byte(`{"message":"hello","count":0}`))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	assertError(t, recorder, "count must be an integer greater than or equal to 1")
}

func TestEchoRejectsCoercedCount(t *testing.T) {
	recorder := request(t, http.MethodPost, "/echo", []byte(`{"message":"hello","count":"2"}`))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	assertErrorPresent(t, recorder)
}

func TestEchoRejectsUnknownFields(t *testing.T) {
	recorder := request(t, http.MethodPost, "/echo", []byte(`{"message":"hello","admin":true}`))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	assertErrorPresent(t, recorder)
}

func request(t *testing.T, method string, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()

	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader(body)
	}

	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	recorder := httptest.NewRecorder()
	newRouter().ServeHTTP(recorder, req)
	return recorder
}

func assertJSON(t *testing.T, recorder *httptest.ResponseRecorder, want map[string]any) {
	t.Helper()

	var got map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("response JSON: %v", err)
	}
	for key, wantValue := range want {
		if got[key] != wantValue {
			t.Fatalf("%s = %#v, want %#v; body=%s", key, got[key], wantValue, recorder.Body.String())
		}
	}
}

func assertError(t *testing.T, recorder *httptest.ResponseRecorder, want string) {
	t.Helper()

	var got map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("response JSON: %v", err)
	}
	if got["error"] != want {
		t.Fatalf("error = %q, want %q", got["error"], want)
	}
}

func assertErrorPresent(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()

	var got map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("response JSON: %v", err)
	}
	if got["error"] == "" {
		t.Fatalf("missing error in response body: %s", recorder.Body.String())
	}
}
