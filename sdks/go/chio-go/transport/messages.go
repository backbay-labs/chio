package transport

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type MessageHandler func(context.Context, map[string]any) error

func ParseRPCMessages(rawBody string) ([]map[string]any, error) {
	trimmed := strings.TrimSpace(rawBody)
	if trimmed == "" {
		return []map[string]any{}, nil
	}
	if strings.HasPrefix(trimmed, "{") {
		message, err := parseJSONMessage(trimmed)
		if err != nil {
			return nil, err
		}
		return []map[string]any{message}, nil
	}

	messages := make([]map[string]any, 0)
	buffer := make([]string, 0)
	for _, line := range strings.Split(rawBody, "\n") {
		if strings.TrimSpace(line) == "" {
			if len(buffer) == 0 {
				continue
			}
			message, err := parseJSONMessage(strings.Join(buffer, "\n"))
			if err != nil {
				return nil, err
			}
			messages = append(messages, message)
			buffer = buffer[:0]
			continue
		}
		if strings.HasPrefix(line, "data:") {
			buffer = append(buffer, strings.TrimSpace(line[5:]))
		}
	}
	if len(buffer) > 0 {
		message, err := parseJSONMessage(strings.Join(buffer, "\n"))
		if err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}
	return messages, nil
}

func ReadRPCMessagesUntilTerminal(
	ctx context.Context,
	responseBody io.Reader,
	contentType string,
	expectedID any,
	onMessage MessageHandler,
) ([]map[string]any, error) {
	if onMessage == nil {
		onMessage = func(context.Context, map[string]any) error { return nil }
	}

	if strings.HasPrefix(strings.ToLower(contentType), "text/event-stream") {
		return readStreamMessagesUntilTerminal(ctx, responseBody, expectedID, onMessage)
	}

	rawBody, err := io.ReadAll(responseBody)
	if err != nil {
		return nil, err
	}
	messages, err := ParseRPCMessages(string(rawBody))
	if err != nil {
		return nil, err
	}
	for _, message := range messages {
		if isTerminalMessage(message, expectedID) {
			continue
		}
		if err := onMessage(ctx, message); err != nil {
			return nil, err
		}
	}
	return messages, nil
}

func TerminalMessage(messages []map[string]any, expectedID any) (map[string]any, error) {
	for _, message := range messages {
		if isTerminalMessage(message, expectedID) {
			if rpcErr, ok := message["error"].(map[string]any); ok {
				return nil, fmt.Errorf("json-rpc error: %v", rpcErr["message"])
			}
			return message, nil
		}
	}
	return nil, fmt.Errorf("no terminal response for JSON-RPC id %v", expectedID)
}

func readStreamMessagesUntilTerminal(
	ctx context.Context,
	responseBody io.Reader,
	expectedID any,
	onMessage MessageHandler,
) ([]map[string]any, error) {
	messages := make([]map[string]any, 0)
	buffer := make([]string, 0)
	scanner := bufio.NewScanner(responseBody)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	flush := func() (bool, error) {
		if len(buffer) == 0 {
			return false, nil
		}
		message, err := parseJSONMessage(strings.Join(buffer, "\n"))
		if err != nil {
			return false, err
		}
		messages = append(messages, message)
		buffer = buffer[:0]
		if isTerminalMessage(message, expectedID) {
			return true, nil
		}
		if err := onMessage(ctx, message); err != nil {
			return false, err
		}
		return false, nil
	}

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			terminal, err := flush()
			if err != nil {
				return nil, err
			}
			if terminal {
				return messages, nil
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			buffer = append(buffer, strings.TrimSpace(line[5:]))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if _, err := flush(); err != nil {
		return nil, err
	}
	return messages, nil
}

func parseJSONMessage(input string) (map[string]any, error) {
	decoder := json.NewDecoder(strings.NewReader(input))
	decoder.UseNumber()
	var message map[string]any
	if err := decoder.Decode(&message); err != nil {
		return nil, err
	}
	return message, nil
}

func isTerminalMessage(message map[string]any, expectedID any) bool {
	if expectedID == nil {
		return false
	}
	if _, isNotification := message["method"]; isNotification {
		return false
	}
	return normalizeID(message["id"]) == normalizeID(expectedID)
}

func normalizeID(value any) string {
	switch typed := value.(type) {
	case json.Number:
		return typed.String()
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprint(typed)
	}
}
