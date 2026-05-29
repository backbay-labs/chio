# chio-ag-ui-proxy

AG-UI proxy for Chio -- capability-validated interception of agent-to-UI event
streams.

## What it does

`chio-ag-ui-proxy` intercepts event streams flowing from an AI agent to a UI
client, validating capability tokens for UI-facing actions and producing signed
receipts that include event type, target UI component, and action
classification.

Supported transport modes:

- SSE (Server-Sent Events) -- unidirectional server-to-client stream.
- WebSocket -- bidirectional communication.

The proxy classifies each `AgUiEvent` into an `EventClassification` and
identifies the `TargetComponent`. `ProxyDecision` describes the outcome (allow,
deny, or require capability). `AgUiReceipt` and `AgUiReceiptBody` carry the
signed audit record.

Public types: `AgUiProxy`, `AgUiProxyConfig`, `ProxyDecision`, `AgUiEvent`,
`EventClassification`, `TargetComponent`, `AgUiReceipt`, `Transport`,
`TransportKind`.

## Position in the system

```
Agent
  |
  v
[chio-ag-ui-proxy]  -- capability validation, receipt signing
  |
  v
UI client
```

Depends on `chio-core` and `chio-kernel-core` (default features disabled to
keep the dependency surface small).

## Building

```bash
cargo build -p chio-ag-ui-proxy
cargo test -p chio-ag-ui-proxy
```
