package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type RPCExchange struct {
	Request  map[string]any
	Status   int
	Headers  map[string]string
	Messages []map[string]any
}

type DeleteSessionResult struct {
	Status  int
	Headers map[string]string
}

func BuildRPCHeaders(authToken string, sessionID string, protocolVersion string) map[string]string {
	headers := map[string]string{
		"Authorization": "Bearer " + authToken,
		"Accept":        "application/json, text/event-stream",
		"Content-Type":  "application/json",
	}
	if sessionID != "" {
		headers["MCP-Session-Id"] = sessionID
	}
	if protocolVersion != "" {
		headers["MCP-Protocol-Version"] = protocolVersion
	}
	return headers
}

func BuildSessionDeleteHeaders(authToken string, sessionID string) map[string]string {
	return map[string]string{
		"Authorization":  "Bearer " + authToken,
		"MCP-Session-Id": sessionID,
	}
}

func PostRPC(
	ctx context.Context,
	httpClient *http.Client,
	baseURL string,
	authToken string,
	sessionID string,
	protocolVersion string,
	body map[string]any,
	onMessage MessageHandler,
) (RPCExchange, error) {
	return postEnvelope(ctx, httpClient, baseURL, authToken, sessionID, protocolVersion, body, body["id"], onMessage)
}

func PostNotification(
	ctx context.Context,
	httpClient *http.Client,
	baseURL string,
	authToken string,
	sessionID string,
	protocolVersion string,
	body map[string]any,
	onMessage MessageHandler,
) (RPCExchange, error) {
	return postEnvelope(ctx, httpClient, baseURL, authToken, sessionID, protocolVersion, body, nil, onMessage)
}

func DeleteSession(
	ctx context.Context,
	httpClient *http.Client,
	baseURL string,
	authToken string,
	sessionID string,
) (DeleteSessionResult, error) {
	client := httpClient
	if client == nil {
		client = http.DefaultClient
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, strings.TrimRight(baseURL, "/")+"/mcp", nil)
	if err != nil {
		return DeleteSessionResult{}, err
	}
	for key, value := range BuildSessionDeleteHeaders(authToken, sessionID) {
		request.Header.Set(key, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return DeleteSessionResult{}, err
	}
	defer response.Body.Close()
	return DeleteSessionResult{
		Status:  response.StatusCode,
		Headers: responseHeaders(response.Header),
	}, nil
}

func postEnvelope(
	ctx context.Context,
	httpClient *http.Client,
	baseURL string,
	authToken string,
	sessionID string,
	protocolVersion string,
	body map[string]any,
	expectedID any,
	onMessage MessageHandler,
) (RPCExchange, error) {
	client := httpClient
	if client == nil {
		client = http.DefaultClient
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return RPCExchange{}, err
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		strings.TrimRight(baseURL, "/")+"/mcp",
		bytes.NewReader(payload),
	)
	if err != nil {
		return RPCExchange{}, err
	}
	for key, value := range BuildRPCHeaders(authToken, sessionID, protocolVersion) {
		request.Header.Set(key, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return RPCExchange{}, err
	}
	defer response.Body.Close()

	messages, err := ReadRPCMessagesUntilTerminal(
		ctx,
		response.Body,
		response.Header.Get("Content-Type"),
		expectedID,
		onMessage,
	)
	if err != nil {
		return RPCExchange{}, err
	}
	return RPCExchange{
		Request:  body,
		Status:   response.StatusCode,
		Headers:  responseHeaders(response.Header),
		Messages: messages,
	}, nil
}

func responseHeaders(headers http.Header) map[string]string {
	result := make(map[string]string, len(headers))
	for key, values := range headers {
		if len(values) == 0 {
			continue
		}
		result[strings.ToLower(key)] = values[0]
	}
	return result
}
