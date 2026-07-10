# Async Kernel Migration

This migration documents the kernel's tool-call evaluation entrypoints. Both a
synchronous (`evaluate_tool_call_blocking`) and asynchronous
(`evaluate_tool_call`) entrypoint are provided.

## Rust Callers

Prefer the async kernel API from an existing Tokio task:

```rust
let response = kernel.evaluate_tool_call(&request).await?;
```

Callers that attach route evidence or other receipt metadata should use the
metadata-preserving async API:

```rust
let response = kernel
    .evaluate_tool_call_with_metadata(&request, Some(route_metadata))
    .await?;
```

Callers that cannot enter an async context can use the blocking entrypoint:

```rust
let response = kernel.evaluate_tool_call_blocking(&request)?;
```

## In-Tree Consumer Matrix

| Consumer | Status | Migration note |
|----------|------------|----------------|
| `chio-cli` | async | CLI session checks call `evaluate_tool_call(...).await`. |
| `chio-mcp-edge` | async bridge available | Use `execute_bridge_mcp_tool_call_async` from async runtimes. The sync bridge wrapper is retained only for synchronous protocol trait adapters. |
| `chio-mcp-adapter` | no direct sync kernel call | Native adapter code implements tool-server traits and does not call `evaluate_tool_call_blocking`. |
| `chio-a2a-edge` | no direct sync kernel call | Kernel-backed paths route through the cross-protocol orchestrator and do not call `evaluate_tool_call_blocking` directly. |
| `chio-acp-edge` | no direct sync kernel call | ACP-Client edge paths do not call the blocking tool-call entrypoint. |
| `chio-acp-proxy` | no direct sync kernel call | Proxy receipt signing uses kernel-backed receipt helpers, not the tool-call shim. |
| Python SDKs under `sdks/python` | async | SDK clients expose `async def evaluate_tool_call(...)` and integrations await it. |

## Operator Checklist

1. Move request handling onto Tokio tasks and call `evaluate_tool_call` where an async context is available.
2. Use `evaluate_tool_call_blocking` only for synchronous host APIs.
3. For bridge code that needs route metadata in receipts, call
   `evaluate_tool_call_with_metadata`.
