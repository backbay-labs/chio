package client

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/backbay-labs/chio/sdks/go/chio-go/auth"
	"github.com/backbay-labs/chio/sdks/go/chio-go/session"
	"github.com/backbay-labs/chio/sdks/go/chio-go/transport"
	"github.com/backbay-labs/chio/sdks/go/chio-go/version"
)

type MessageHandler func(context.Context, map[string]any, *session.Session) error

type ClientInfo struct {
	Name    string
	Version string
}

type InitializeOptions struct {
	Capabilities    map[string]any
	ClientInfo      ClientInfo
	OnMessage       MessageHandler
	ProtocolVersion string
}

type Client struct {
	AuthToken  string
	BaseURL    string
	HTTPClient *http.Client
}

func New(baseURL string, bearer auth.StaticBearer, httpClient *http.Client) *Client {
	return &Client{
		AuthToken:  bearer.AuthToken,
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTPClient: httpClient,
	}
}

func WithStaticBearer(baseURL string, authToken string, httpClient *http.Client) *Client {
	return New(baseURL, auth.StaticBearerToken(authToken), httpClient)
}

func (client *Client) Initialize(ctx context.Context, options InitializeOptions) (*session.Session, error) {
	protocolVersion := options.ProtocolVersion
	if protocolVersion == "" {
		protocolVersion = "2025-11-25"
	}
	clientInfo := options.ClientInfo
	if clientInfo.Name == "" {
		clientInfo.Name = version.DefaultClientName
	}
	if clientInfo.Version == "" {
		clientInfo.Version = version.ModuleVersion
	}

	initializeResponse, err := transport.PostRPC(
		ctx,
		client.HTTPClient,
		client.BaseURL,
		client.AuthToken,
		"",
		"",
		map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "initialize",
			"params": map[string]any{
				"protocolVersion": protocolVersion,
				"capabilities":    coalesceMap(options.Capabilities),
				"clientInfo": map[string]any{
					"name":    clientInfo.Name,
					"version": clientInfo.Version,
				},
			},
		},
		nil,
	)
	if err != nil {
		return nil, err
	}
	if initializeResponse.Status != http.StatusOK {
		return nil, fmt.Errorf("initialize returned HTTP %d", initializeResponse.Status)
	}

	initializeMessage, err := transport.TerminalMessage(initializeResponse.Messages, 1)
	if err != nil {
		return nil, err
	}
	sessionID := initializeResponse.Headers["mcp-session-id"]
	if sessionID == "" {
		return nil, fmt.Errorf("initialize response did not include MCP-Session-Id")
	}
	result, ok := initializeMessage["result"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("initialize response did not include a result object")
	}
	negotiatedProtocolVersion, ok := result["protocolVersion"].(string)
	if !ok || negotiatedProtocolVersion == "" {
		return nil, fmt.Errorf("initialize response did not include protocolVersion")
	}

	chioSession := session.New(session.Options{
		AuthToken:       client.AuthToken,
		BaseURL:         client.BaseURL,
		HTTPClient:      client.HTTPClient,
		ProtocolVersion: negotiatedProtocolVersion,
		SessionID:       sessionID,
	})
	if options.OnMessage != nil {
		chioSession.SetMessageHandler(func(ctx context.Context, message map[string]any) error {
			return options.OnMessage(ctx, message, chioSession)
		})
	}

	initializedResponse, err := chioSession.Notification(ctx, "notifications/initialized", nil, nil)
	if err != nil {
		return nil, err
	}
	if initializedResponse.Status != http.StatusOK && initializedResponse.Status != http.StatusAccepted {
		return nil, fmt.Errorf("notifications/initialized returned HTTP %d", initializedResponse.Status)
	}
	chioSession.Handshake = &session.SessionHandshake{
		InitializeResponse:  initializeResponse,
		InitializedResponse: initializedResponse,
	}
	return chioSession, nil
}

func coalesceMap(input map[string]any) map[string]any {
	if input == nil {
		return map[string]any{}
	}
	return input
}
