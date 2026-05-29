package nested

import (
	"context"

	"github.com/backbay-labs/chio/sdks/go/chio-go/session"
	"github.com/backbay-labs/chio/sdks/go/chio-go/transport"
)

type Builder func(map[string]any, *session.Session) map[string]any
type TranscriptHook func(map[string]any)

type Route struct {
	Builder    Builder
	StepSuffix string
}

type Router struct {
	emit   TranscriptHook
	routes map[string]Route
}

func NewRouter(emit TranscriptHook) *Router {
	return &Router{
		emit:   emit,
		routes: map[string]Route{},
	}
}

func RPCResult(messageID any, result map[string]any) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      messageID,
		"result":  result,
	}
}

func SamplingTextResult(message map[string]any, text string, model string, stopReason string) map[string]any {
	if stopReason == "" {
		stopReason = "end_turn"
	}
	return RPCResult(message["id"], map[string]any{
		"role": "assistant",
		"content": map[string]any{
			"type": "text",
			"text": text,
		},
		"model":      model,
		"stopReason": stopReason,
	})
}

func ElicitationAcceptResult(message map[string]any, content map[string]any) map[string]any {
	result := map[string]any{"action": "accept"}
	if content != nil {
		result["content"] = content
	}
	return RPCResult(message["id"], result)
}

func RootsListResult(message map[string]any, roots []map[string]any) map[string]any {
	return RPCResult(message["id"], map[string]any{"roots": roots})
}

func (router *Router) Register(method string, stepSuffix string, builder Builder) *Router {
	router.routes[method] = Route{
		Builder:    builder,
		StepSuffix: stepSuffix,
	}
	return router
}

func (router *Router) Handle(
	ctx context.Context,
	message map[string]any,
	chioSession *session.Session,
	stepPrefix string,
) (*transport.RPCExchange, error) {
	method, ok := message["method"].(string)
	if !ok {
		return nil, nil
	}
	route, ok := router.routes[method]
	if !ok {
		return nil, nil
	}
	response, err := chioSession.SendEnvelope(ctx, route.Builder(message, chioSession), nil)
	if err != nil {
		return nil, err
	}
	if router.emit != nil {
		step := route.StepSuffix
		if stepPrefix != "" {
			step = stepPrefix + "/" + step
		}
		router.emit(map[string]any{
			"step":       step,
			"request":    response.Request,
			"httpStatus": response.Status,
			"messages":   response.Messages,
		})
	}
	return &response, nil
}
