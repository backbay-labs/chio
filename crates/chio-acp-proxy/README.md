# chio-acp-proxy

Security proxy for the Agent Client Protocol (ACP). Sits between an editor or
IDE client and an ACP coding agent, enforcing Chio capability-based access
control on every JSON-RPC message.

## What it does

`chio-acp-proxy` spawns an ACP agent as a subprocess with stdio transport and
forwards JSON-RPC messages bidirectionally between the client and the agent. It
intercepts the following message classes before forwarding:

- `session/request_permission` -- validates capability tokens.
- `fs/read_text_file` and `fs/write_text_file` -- enforces path-scoped
  capabilities and detects path traversal.
- `terminal/create` -- runs command guards.
- `session/update` (notifications) -- observes `tool_call` events and generates
  unsigned audit entries that a downstream component with key material can
  promote to signed Chio receipts.

The optional `otel` feature (enabled via `chio-kernel/otel`) wires OpenTelemetry
spans into the intercept path.

Public types: `AcpProxy`, `AcpProxyConfig`, `AcpProxyError`.

## Position in the system

```
Editor / IDE (ACP client)
        |  (JSON-RPC, stdio)
  [chio-acp-proxy]  -- capability enforcement, path-guard, receipt audit
        |  (stdio)
  ACP coding agent subprocess
```

`chio-acp-proxy` depends on `chio-kernel` (guard evaluation) and
`chio-cross-protocol` (shared bridge contracts and capability envelope schemas).

## Building

```bash
cargo build -p chio-acp-proxy
cargo build -p chio-acp-proxy --features otel
cargo test -p chio-acp-proxy
```

## House rules

- No em dashes (U+2014) anywhere in code, comments, or documentation.
- Workspace clippy lints `unwrap_used = "deny"` and `expect_used = "deny"` apply.
- Fail-closed: path traversal and missing capability tokens deny the message
  before it reaches the agent subprocess.
