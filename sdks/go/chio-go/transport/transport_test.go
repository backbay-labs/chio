package transport_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/backbay-labs/chio/sdks/go/chio-go/transport"
)

func TestPostRPCParsesStreamableHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/mcp" {
			t.Fatalf("unexpected path: %s", request.URL.Path)
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(writer, "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n")
		fmt.Fprint(writer, "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"echo_text\"}]}}\n\n")
	}))
	defer server.Close()

	notifications := 0
	exchange, err := transport.PostRPC(
		context.Background(),
		server.Client(),
		server.URL,
		"token",
		"sess-123",
		"2025-11-25",
		map[string]any{
			"jsonrpc": "2.0",
			"id":      2,
			"method":  "tools/list",
			"params":  map[string]any{},
		},
		func(_ context.Context, message map[string]any) error {
			if message["method"] == "notifications/tools/list_changed" {
				notifications += 1
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("PostRPC returned error: %v", err)
	}
	if exchange.Status != 200 {
		t.Fatalf("unexpected status: %d", exchange.Status)
	}
	if len(exchange.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(exchange.Messages))
	}
	if notifications != 1 {
		t.Fatalf("expected 1 streamed notification, got %d", notifications)
	}
}
