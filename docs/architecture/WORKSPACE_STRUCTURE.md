# Workspace Structure

The workspace is currently flat, but the layers are not meant to be flat in responsibility.

## Intended Layers

### Domain and protocol core

- `chio-core`
- `chio-manifest`
- `chio-did`
- `chio-guards`
- `chio-policy`
- `chio-reputation`
- `chio-credentials`

These crates should stay free of CLI/server-framework concerns. They can depend
on protocol, crypto, serde, and other pure libraries, but they should not
depend on `chio-cli`, `chio-control-plane`, `chio-hosted-mcp`, or direct
transport/server libraries such as `clap`, `axum`, or `reqwest`.

### Enforcement and persistence

- `chio-kernel`
- `chio-store-sqlite`

`chio-kernel` owns enforcement contracts and runtime behavior. Concrete SQLite
storage belongs in `chio-store-sqlite`, not back in the kernel or the CLI.

### Adapter and edge layer

- `chio-mcp-edge`
- `chio-mcp-adapter`
- `chio-a2a-adapter`

These crates translate external protocols into the Chio runtime surface. They
can depend on runtime and transport libraries, but they should not pull CLI
command parsing inward.

### Service and operator layer

- `chio-control-plane`
- `chio-hosted-mcp`
- `chio-cli`

These crates own HTTP services, admin/runtime orchestration, and command
surfaces. They are allowed to depend on the lower layers; the reverse should
not happen.

## Guardrail

`./scripts/check-workspace-layering.sh` enforces the most important negative
dependency rules for the domain layer and is part of the workspace
qualification path.
