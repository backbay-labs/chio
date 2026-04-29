// Package chioguardsdkgo provides the Go SDK for writing chio:guard@0.2.0 components.
package chioguardsdkgo

import "errors"

// WITWorld is the canonical guard world targeted by this SDK.
const WITWorld = "chio:guard@0.2.0"

// ErrHostUnavailable is returned when a host import is called outside a component runtime.
var ErrHostUnavailable = errors.New("host import is only available inside a chio:guard@0.2.0 component")

// GuardRequest represents the read-only request context provided to a guard.
type GuardRequest struct {
	ToolName          string
	ServerID          string
	AgentID           string
	Arguments         string
	Scopes            []string
	ActionType        *string
	ExtractedPath     *string
	ExtractedTarget   *string
	FilesystemRoots   []string
	MatchedGrantIndex *uint32
}

// VerdictTag discriminates between allow and deny verdicts.
type VerdictTag int

const (
	// VerdictAllow indicates the guard allows the request to proceed.
	VerdictAllow VerdictTag = iota

	// VerdictDeny indicates the guard denies the request.
	VerdictDeny
)

// Verdict represents the result of a guard evaluation.
type Verdict struct {
	Tag    VerdictTag
	Reason string
}

// Allow returns a Verdict that permits the request to proceed.
func Allow() Verdict {
	return Verdict{Tag: VerdictAllow}
}

// Deny returns a Verdict that blocks the request with the given reason.
func Deny(reason string) Verdict {
	return Verdict{Tag: VerdictDeny, Reason: reason}
}

// Host defines the chio:guard@0.2.0 host import surface.
type Host interface {
	Log(level uint32, msg string)
	GetConfig(key string) (string, bool)
	GetTimeUnixSecs() uint64
	FetchBlob(handle uint32, offset uint64, length uint32) ([]byte, error)
}

// PolicyContext wraps a host-owned policy-context bundle-handle resource.
type PolicyContext struct {
	ID     string
	Handle uint32
	Host   Host
}

// Read reads a byte range from the bundle handle.
func (context PolicyContext) Read(offset uint64, length uint32) ([]byte, error) {
	if context.Host == nil {
		return nil, ErrHostUnavailable
	}
	return context.Host.FetchBlob(context.Handle, offset, length)
}

// Close closes the policy context wrapper.
func (context PolicyContext) Close() {
	_ = context
}
