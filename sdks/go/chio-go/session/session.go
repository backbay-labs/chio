package session

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/backbay-labs/chio/sdks/go/chio-go/transport"
)

type MessageHandler = transport.MessageHandler
type RPCExchange = transport.RPCExchange
type DeleteSessionResult = transport.DeleteSessionResult

type SessionHandshake struct {
	InitializeResponse  RPCExchange
	InitializedResponse RPCExchange
}

type Session struct {
	AuthToken       string
	BaseURL         string
	Handshake       *SessionHandshake
	HTTPClient      *http.Client
	ProtocolVersion string
	SessionID       string

	nextRequestID atomic.Int64
	onMessage     MessageHandler
}

type Options struct {
	AuthToken       string
	BaseURL         string
	Handshake       *SessionHandshake
	HTTPClient      *http.Client
	OnMessage       MessageHandler
	ProtocolVersion string
	SessionID       string
}

func New(options Options) *Session {
	instance := &Session{
		AuthToken:       options.AuthToken,
		BaseURL:         options.BaseURL,
		Handshake:       options.Handshake,
		HTTPClient:      options.HTTPClient,
		ProtocolVersion: options.ProtocolVersion,
		SessionID:       options.SessionID,
		onMessage:       options.OnMessage,
	}
	instance.nextRequestID.Store(2)
	if instance.onMessage == nil {
		instance.onMessage = func(context.Context, map[string]any) error { return nil }
	}
	return instance
}

func (session *Session) SetMessageHandler(onMessage MessageHandler) {
	if onMessage == nil {
		session.onMessage = func(context.Context, map[string]any) error { return nil }
		return
	}
	session.onMessage = onMessage
}

func (session *Session) SendEnvelope(
	ctx context.Context,
	body map[string]any,
	onMessage MessageHandler,
) (RPCExchange, error) {
	handler := session.onMessage
	if onMessage != nil {
		handler = onMessage
	}
	return transport.PostRPC(
		ctx,
		session.HTTPClient,
		session.BaseURL,
		session.AuthToken,
		session.SessionID,
		session.ProtocolVersion,
		body,
		handler,
	)
}

func (session *Session) Request(
	ctx context.Context,
	method string,
	params map[string]any,
	onMessage MessageHandler,
) (RPCExchange, error) {
	body := map[string]any{
		"jsonrpc": "2.0",
		"id":      session.nextRequestID.Add(1) - 1,
		"method":  method,
	}
	if params != nil {
		body["params"] = params
	}
	return session.SendEnvelope(ctx, body, onMessage)
}

func (session *Session) RequestResult(
	ctx context.Context,
	method string,
	params map[string]any,
	onMessage MessageHandler,
) (map[string]any, error) {
	exchange, err := session.Request(ctx, method, params, onMessage)
	if err != nil {
		return nil, err
	}
	message, err := transport.TerminalMessage(exchange.Messages, exchange.Request["id"])
	if err != nil {
		return nil, err
	}
	result, ok := message["result"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("terminal response did not include an object result")
	}
	return result, nil
}

func (session *Session) Notification(
	ctx context.Context,
	method string,
	params map[string]any,
	onMessage MessageHandler,
) (RPCExchange, error) {
	handler := session.onMessage
	if onMessage != nil {
		handler = onMessage
	}
	body := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
	}
	if params != nil {
		body["params"] = params
	}
	return transport.PostNotification(
		ctx,
		session.HTTPClient,
		session.BaseURL,
		session.AuthToken,
		session.SessionID,
		session.ProtocolVersion,
		body,
		handler,
	)
}

func (session *Session) ListTools(ctx context.Context) (map[string]any, error) {
	return session.RequestResult(ctx, "tools/list", map[string]any{}, nil)
}

func (session *Session) CallTool(ctx context.Context, name string, arguments map[string]any) (map[string]any, error) {
	return session.RequestResult(ctx, "tools/call", map[string]any{
		"name":      name,
		"arguments": arguments,
	}, nil)
}

func (session *Session) ListResources(ctx context.Context) (map[string]any, error) {
	return session.RequestResult(ctx, "resources/list", map[string]any{}, nil)
}

func (session *Session) ReadResource(ctx context.Context, uri string) (map[string]any, error) {
	return session.RequestResult(ctx, "resources/read", map[string]any{"uri": uri}, nil)
}

func (session *Session) SubscribeResource(ctx context.Context, uri string) (map[string]any, error) {
	return session.RequestResult(ctx, "resources/subscribe", map[string]any{"uri": uri}, nil)
}

func (session *Session) UnsubscribeResource(ctx context.Context, uri string) (map[string]any, error) {
	return session.RequestResult(ctx, "resources/unsubscribe", map[string]any{"uri": uri}, nil)
}

func (session *Session) ListResourceTemplates(ctx context.Context) (map[string]any, error) {
	return session.RequestResult(ctx, "resources/templates/list", map[string]any{}, nil)
}

func (session *Session) ListPrompts(ctx context.Context) (map[string]any, error) {
	return session.RequestResult(ctx, "prompts/list", map[string]any{}, nil)
}

func (session *Session) GetPrompt(ctx context.Context, name string, arguments map[string]any) (map[string]any, error) {
	params := map[string]any{"name": name}
	if arguments != nil {
		params["arguments"] = arguments
	}
	return session.RequestResult(ctx, "prompts/get", params, nil)
}

func (session *Session) Complete(ctx context.Context, params map[string]any) (map[string]any, error) {
	return session.RequestResult(ctx, "completion/complete", params, nil)
}

func (session *Session) SetLogLevel(ctx context.Context, level string) (map[string]any, error) {
	return session.RequestResult(ctx, "logging/setLevel", map[string]any{"level": level}, nil)
}

func (session *Session) ListTasks(ctx context.Context) (map[string]any, error) {
	return session.RequestResult(ctx, "tasks/list", map[string]any{}, nil)
}

func (session *Session) GetTask(ctx context.Context, taskID string) (map[string]any, error) {
	return session.RequestResult(ctx, "tasks/get", map[string]any{"taskId": taskID}, nil)
}

func (session *Session) GetTaskResult(ctx context.Context, taskID string) (map[string]any, error) {
	return session.RequestResult(ctx, "tasks/result", map[string]any{"taskId": taskID}, nil)
}

func (session *Session) CancelTask(ctx context.Context, taskID string) (map[string]any, error) {
	return session.RequestResult(ctx, "tasks/cancel", map[string]any{"taskId": taskID}, nil)
}

func (session *Session) Close(ctx context.Context) (DeleteSessionResult, error) {
	return transport.DeleteSession(
		ctx,
		session.HTTPClient,
		session.BaseURL,
		session.AuthToken,
		session.SessionID,
	)
}
