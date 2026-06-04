# hello-mcp

Minimal MCP example using [`crates/chio-mcp-edge`](../../crates/chio-mcp-edge/).

## What It Demonstrates

- `initialize`, required `notifications/initialized`, then `tools/list` over stdio JSON-RPC
- authoritative `tools/call` execution through the embedded Chio kernel
- a companion bridge call that exposes the underlying Chio receipt id
- direct library-level testing of the same MCP edge lifecycle without spawning stdio

## Files

```text
README.md
Cargo.toml
ARCHITECTURE.md
src/lib.rs
src/main.rs
run-edge.sh
smoke.sh
```

## Run

Start the stdio edge:

```bash
./run-edge.sh serve
```

Run the smoke flow:

```bash
./smoke.sh
```

This example uses the same ready-state contract as the hosted HTTP edge. The
transport difference is only the outer framing: stdio JSON-RPC here, `POST /mcp`
plus `GET /mcp` replay in the hosted guide.

The reusable demo state, stdio loop, bridge-call helper, and direct JSON-RPC
edge construction live in `src/lib.rs`. `src/main.rs` only maps the selected
mode to a process exit code.
