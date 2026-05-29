package nested_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/backbay-labs/chio/sdks/go/chio-go/nested"
	"github.com/backbay-labs/chio/sdks/go/chio-go/session"
)

func TestRouterDispatchesAndEmitsTranscript(t *testing.T) {
	transcript := make([]map[string]any, 0)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      42,
			"result":  map[string]any{"ok": true},
		})
	}))
	defer server.Close()

	chioSession := session.New(session.Options{
		AuthToken:       "token",
		BaseURL:         server.URL,
		HTTPClient:      server.Client(),
		ProtocolVersion: "2025-11-25",
		SessionID:       "sess-123",
	})
	router := nested.NewRouter(func(entry map[string]any) {
		transcript = append(transcript, entry)
	}).Register(
		"sampling/createMessage",
		"sampling-response",
		func(message map[string]any, _ *session.Session) map[string]any {
			return nested.SamplingTextResult(message, "sampled by test", "test-model", "")
		},
	)

	response, err := router.Handle(
		context.Background(),
		map[string]any{
			"jsonrpc": "2.0",
			"id":      42,
			"method":  "sampling/createMessage",
		},
		chioSession,
		"nested/sampling",
	)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if response == nil {
		t.Fatalf("expected router response")
	}
	if len(transcript) != 1 || transcript[0]["step"] != "nested/sampling/sampling-response" {
		t.Fatalf("unexpected transcript: %#v", transcript)
	}
}

func TestResponseBuildersCoverElicitationAndRoots(t *testing.T) {
	elicitation := nested.ElicitationAcceptResult(
		map[string]any{"id": 5},
		map[string]any{"answer": "accepted"},
	)
	roots := nested.RootsListResult(
		map[string]any{"id": 6},
		[]map[string]any{{"uri": "file:///workspace", "name": "workspace"}},
	)
	if elicitation["result"].(map[string]any)["action"] != "accept" {
		t.Fatalf("unexpected elicitation response: %#v", elicitation)
	}
	if roots["result"].(map[string]any)["roots"].([]map[string]any)[0]["uri"] != "file:///workspace" {
		t.Fatalf("unexpected roots response: %#v", roots)
	}
}
