# hello-acp

Minimal ACP example using [`crates/chio-acp-edge`](../../crates/chio-acp-edge/).

## What It Demonstrates

- `session/list_capabilities`
- authoritative `tool/invoke`
- deferred `tool/stream` followed by `tool/resume`
- receipt-bearing metadata on terminal results
- direct library-level tests for the same JSON-RPC lifecycle

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

Start the line-based JSON-RPC edge:

```bash
./run-edge.sh serve
```

Run the smoke flow:

```bash
./smoke.sh
```

The reusable demo state, JSON-RPC serving loop, and mode dispatch live in
`src/lib.rs`. `src/main.rs` only maps the selected mode to a process exit code.
