# M05 Async Kernel Migration

M05 makes `ChioKernel::evaluate_tool_call` the primary tool-call evaluation
surface. The legacy synchronous shim is still available for one compatibility
window behind the `legacy-sync` Cargo feature, but it is no longer enabled by
default.

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

Only callers that cannot enter an async context should opt back into the
compatibility path:

```toml
chio-kernel = { version = "...", features = ["legacy-sync"] }
```

## In-Tree Consumer Matrix

| Consumer | M05 status | Migration note |
|----------|------------|----------------|
| `chio-cli` | async | CLI session checks call `evaluate_tool_call(...).await`. |
| `chio-mcp-edge` | async bridge available | Use `execute_bridge_mcp_tool_call_async` from async runtimes. The sync bridge wrapper is retained only for synchronous protocol trait adapters. |
| `chio-mcp-adapter` | no direct sync kernel call | Native adapter code implements tool-server traits and does not call `evaluate_tool_call_blocking`. |
| `chio-a2a-edge` | no direct sync kernel call | Kernel-backed paths route through the cross-protocol orchestrator and do not call `evaluate_tool_call_blocking` directly. |
| `chio-acp-edge` | no direct sync kernel call | ACP edge paths do not call the legacy tool-call shim. |
| `chio-acp-proxy` | no direct sync kernel call | Proxy receipt signing uses kernel-backed receipt helpers, not the tool-call shim. |
| Python SDKs under `sdks/python` | async | SDK clients expose `async def evaluate_tool_call(...)` and integrations await it. |

## Operator Checklist

1. Remove implicit reliance on the default `legacy-sync` feature.
2. Move request handling onto Tokio tasks and call `evaluate_tool_call`.
3. For bridge code that needs route metadata in receipts, call
   `evaluate_tool_call_with_metadata`.
4. If a synchronous compatibility path is unavoidable for one release, enable
   `legacy-sync` explicitly and track removal before the next release.
