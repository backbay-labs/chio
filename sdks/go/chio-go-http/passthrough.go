package chio

import (
	"context"
	"net/http"
)

type chioPassthroughContextKey struct{}

// GetChioPassthrough returns a reserved degraded-state marker, if present.
// The middleware always fails closed and does not set this marker.
func GetChioPassthrough(r *http.Request) (*ChioPassthrough, bool) {
	value := r.Context().Value(chioPassthroughContextKey{})
	passthrough, ok := value.(*ChioPassthrough)
	return passthrough, ok
}

func withChioPassthrough(ctx context.Context, passthrough *ChioPassthrough) context.Context {
	return context.WithValue(ctx, chioPassthroughContextKey{}, passthrough)
}
