package session_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/backbay-labs/chio/sdks/go/chio-go/session"
)

func TestSessionSupportsNotificationsSubscriptionsAndTasks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		var envelope map[string]any
		if err := json.Unmarshal(body, &envelope); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		method, _ := envelope["method"].(string)
		writer.Header().Set("Content-Type", "application/json")
		switch method {
		case "resources/subscribe":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      envelope["id"],
				"result":  map[string]any{"subscribed": true},
			})
		case "resources/unsubscribe":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      envelope["id"],
				"result":  map[string]any{"unsubscribed": true},
			})
		case "resources/templates/list":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      envelope["id"],
				"result": map[string]any{
					"resourceTemplates": []map[string]any{{"uriTemplate": "fixture://docs/{name}"}},
				},
			})
		case "completion/complete":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      envelope["id"],
				"result":  map[string]any{"values": []string{"fixture"}},
			})
		case "logging/setLevel":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      envelope["id"],
				"result":  map[string]any{"level": "debug"},
			})
		case "tasks/list":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      envelope["id"],
				"result":  map[string]any{"tasks": []map[string]any{{"taskId": "task-1"}}},
			})
		case "tasks/get":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      envelope["id"],
				"result":  map[string]any{"taskId": "task-1", "status": "working"},
			})
		case "tasks/result":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      envelope["id"],
				"result": map[string]any{
					"content": []map[string]any{{"type": "text", "text": "task output"}},
				},
			})
		case "tasks/cancel":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      envelope["id"],
				"result":  map[string]any{"cancelled": true},
			})
		case "tools/call":
			writer.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(writer, "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/resources/updated\",\"params\":{\"uri\":\"fixture://docs/alpha\"}}\n\n")
			fmt.Fprintf(writer, "data: {\"jsonrpc\":\"2.0\",\"id\":%v,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}]}}\n\n", envelope["id"])
		default:
			t.Fatalf("unexpected method: %s", method)
		}
	}))
	defer server.Close()

	chioSession := session.New(session.Options{
		AuthToken:       "token",
		BaseURL:         server.URL,
		HTTPClient:      server.Client(),
		ProtocolVersion: "2025-11-25",
		SessionID:       "sess-123",
	})

	subscribed, err := chioSession.SubscribeResource(context.Background(), "fixture://docs/alpha")
	if err != nil || subscribed["subscribed"] != true {
		t.Fatalf("SubscribeResource failed: %#v %v", subscribed, err)
	}
	unsubscribed, err := chioSession.UnsubscribeResource(context.Background(), "fixture://docs/alpha")
	if err != nil || unsubscribed["unsubscribed"] != true {
		t.Fatalf("UnsubscribeResource failed: %#v %v", unsubscribed, err)
	}
	templates, err := chioSession.ListResourceTemplates(context.Background())
	if err != nil {
		t.Fatalf("ListResourceTemplates failed: %v", err)
	}
	templateEntries, ok := templates["resourceTemplates"].([]any)
	if !ok || len(templateEntries) != 1 {
		t.Fatalf("unexpected resource templates payload: %#v", templates)
	}
	completion, err := chioSession.Complete(context.Background(), map[string]any{"argument": "fi"})
	if err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
	completionValues, ok := completion["values"].([]any)
	if !ok || len(completionValues) != 1 {
		t.Fatalf("unexpected completion payload: %#v", completion)
	}
	logLevel, err := chioSession.SetLogLevel(context.Background(), "debug")
	if err != nil || logLevel["level"] != "debug" {
		t.Fatalf("SetLogLevel failed: %#v %v", logLevel, err)
	}
	taskList, err := chioSession.ListTasks(context.Background())
	if err != nil {
		t.Fatalf("ListTasks failed: %v", err)
	}
	taskEntries, ok := taskList["tasks"].([]any)
	if !ok || len(taskEntries) != 1 {
		t.Fatalf("unexpected task list payload: %#v", taskList)
	}
	task, err := chioSession.GetTask(context.Background(), "task-1")
	if err != nil || task["status"] != "working" {
		t.Fatalf("GetTask failed: %#v %v", task, err)
	}
	taskResult, err := chioSession.GetTaskResult(context.Background(), "task-1")
	if err != nil {
		t.Fatalf("GetTaskResult failed: %v", err)
	}
	taskContent, ok := taskResult["content"].([]any)
	if !ok || len(taskContent) != 1 {
		t.Fatalf("unexpected task result payload: %#v", taskResult)
	}
	cancelled, err := chioSession.CancelTask(context.Background(), "task-1")
	if err != nil || cancelled["cancelled"] != true {
		t.Fatalf("CancelTask failed: %#v %v", cancelled, err)
	}

	notifications := 0
	exchange, err := chioSession.Request(
		context.Background(),
		"tools/call",
		map[string]any{
			"name":      "emit_fixture_notifications",
			"arguments": map[string]any{"uri": "fixture://docs/alpha"},
		},
		func(_ context.Context, message map[string]any) error {
			if message["method"] == "notifications/resources/updated" {
				notifications += 1
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if notifications != 1 {
		t.Fatalf("expected 1 streamed notification, got %d", notifications)
	}
	if len(exchange.Messages) != 2 {
		t.Fatalf("expected 2 response messages, got %d", len(exchange.Messages))
	}
}
