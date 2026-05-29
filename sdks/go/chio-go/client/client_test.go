package client_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/backbay-labs/chio/sdks/go/chio-go/client"
	"github.com/backbay-labs/chio/sdks/go/chio-go/version"
)

func TestClientInitializeReturnsSessionAndMCPCoreHelpers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/mcp" {
			t.Fatalf("unexpected path: %s", request.URL.Path)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		var envelope map[string]any
		if err := json.Unmarshal(body, &envelope); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		method, _ := envelope["method"].(string)
		switch method {
		case "initialize":
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("Mcp-Session-Id", "sess-123")
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"result": map[string]any{
					"protocolVersion": "2025-11-25",
					"serverInfo": map[string]any{
						"name":    "fixture",
						"version": version.ModuleVersion,
					},
				},
			})
		case "notifications/initialized":
			writer.WriteHeader(http.StatusAccepted)
		case "tools/list":
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      envelope["id"],
				"result": map[string]any{
					"tools": []map[string]any{{"name": "echo_text"}},
				},
			})
		case "tools/call":
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      envelope["id"],
				"result": map[string]any{
					"content": []map[string]any{{"type": "text", "text": "hello from go"}},
				},
			})
		case "resources/list":
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      envelope["id"],
				"result": map[string]any{
					"resources": []map[string]any{{"uri": "fixture://docs/alpha"}},
				},
			})
		case "prompts/list":
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      envelope["id"],
				"result": map[string]any{
					"prompts": []map[string]any{{"name": "summarize_fixture"}},
				},
			})
		default:
			t.Fatalf("unexpected method: %s", method)
		}
	}))
	defer server.Close()

	chioClient := client.WithStaticBearer(server.URL, "token", server.Client())
	session, err := chioClient.Initialize(context.Background(), client.InitializeOptions{})
	if err != nil {
		t.Fatalf("Initialize returned error: %v", err)
	}
	if session.SessionID != "sess-123" {
		t.Fatalf("unexpected session id: %s", session.SessionID)
	}
	if session.Handshake == nil {
		t.Fatalf("expected handshake metadata")
	}

	tools, err := session.ListTools(context.Background())
	if err != nil {
		t.Fatalf("ListTools returned error: %v", err)
	}
	entries, ok := tools["tools"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("unexpected tools payload: %#v", tools)
	}

	toolCall, err := session.CallTool(context.Background(), "echo_text", map[string]any{"message": "hello from go"})
	if err != nil {
		t.Fatalf("CallTool returned error: %v", err)
	}
	content, ok := toolCall["content"].([]any)
	if !ok || len(content) != 1 {
		t.Fatalf("unexpected tool call payload: %#v", toolCall)
	}

	resources, err := session.ListResources(context.Background())
	if err != nil {
		t.Fatalf("ListResources returned error: %v", err)
	}
	resourceEntries, ok := resources["resources"].([]any)
	if !ok || len(resourceEntries) != 1 {
		t.Fatalf("unexpected resources payload: %#v", resources)
	}

	prompts, err := session.ListPrompts(context.Background())
	if err != nil {
		t.Fatalf("ListPrompts returned error: %v", err)
	}
	promptEntries, ok := prompts["prompts"].([]any)
	if !ok || len(promptEntries) != 1 {
		t.Fatalf("unexpected prompts payload: %#v", prompts)
	}
}
