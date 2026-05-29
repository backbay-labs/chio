//go:build chio_guard_generated

// Example guard: tool-name-based allow/deny.
//
// Mirrors the Rust tool-gate example (examples/guards/tool-gate/src/lib.rs)
// and the TypeScript tool-gate example (chio-guard-ts/examples/tool-gate/).
// Allows all tools except those on a deny list.
//
// Compile with: ./scripts/build-guard.sh
package main

import (
	"github.com/backbay-labs/chio/sdks/guard/chio-guard-go/internal/chio/guard/guard"
	"github.com/backbay-labs/chio/sdks/guard/chio-guard-go/internal/chio/guard/types"
)

// blockedTools is the set of tools that this guard denies.
var blockedTools = map[string]bool{
	"dangerous_tool": true,
	"rm_rf":          true,
	"drop_database":  true,
}

func init() {
	guard.Exports.Evaluate = evaluate
}

// evaluate inspects the tool name and returns deny for blocked tools,
// allow for everything else.
func evaluate(request guard.GuardRequest) guard.Verdict {
	if blockedTools[request.ToolName] {
		return types.VerdictDeny("tool is blocked by policy")
	}
	return types.VerdictAllow()
}

// main is required by TinyGo's wasip2 target but is never called.
func main() {}
