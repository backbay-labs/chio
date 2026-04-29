/**
 * Example guard: tool-name-based allow/deny.
 *
 * Mirrors the Rust tool-gate example (examples/guards/tool-gate/src/lib.rs).
 * Allows all tools except those on a deny list.
 */

import type {
  GuardRequest,
  Verdict,
} from "../../src/index.js";

const BLOCKED_TOOLS: ReadonlySet<string> = new Set([
  "dangerous_tool",
  "rm_rf",
  "drop_database",
]);

/**
 * Evaluate a tool-call request and return a verdict.
 *
 * Exported as the guard world's `evaluate` function.
 */
export function evaluate(request: GuardRequest): Verdict {
  if (BLOCKED_TOOLS.has(request.toolName)) {
    return { tag: "deny", val: "tool is blocked by policy" };
  }
  return { tag: "allow" };
}
