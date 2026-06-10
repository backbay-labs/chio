# chio-egress-contract

Typed HTTP egress contract for Chio substrate adapters.

## What it does

`chio-egress-contract` defines `HttpEgressContract`, the typed policy struct
that all kernel, guard, and adapter code paths must declare before a target URL
is accepted. A missing contract fails closed with `HttpEgressError::MissingContract`.

The contract enforces:

- Allowed HTTP URL schemes (`http` and `https`).
- Explicit authority allowlist (exact normalized host:port pairs).
- Address-class blocks: loopback, link-local, IPv6 ULA, and RFC1918 private
  networks can each be independently denied.
- Redirect chain depth cap (`max_redirect_chain`).
- Response size ceiling (`max_response_bytes`).

The enforcement API has three entry points:

- `enforce_required` -- requires a non-None contract; fails closed otherwise.
- `enforce_url` / `enforce_url_with_dns` -- checks scheme, authority, address
  class, and redirect depth; the DNS variant resolves the hostname and checks
  every returned IP before the caller opens a socket.
- `enforce_response_bytes` -- enforced after headers or streaming counters
  reveal the observed size.

The optional `reqwest-egress` feature adds `send_with_contract` and
`client_builder_with_contract` helpers that wrap `reqwest` dispatch with
`HttpEgressContract` enforcement on the initial URL, on every redirect, and on
observed response size.

## Position in the system

`chio-egress-contract` is a foundational safety crate. It carries no Chio
protocol logic and has no dependency on `chio-kernel` or `chio-core`. It is
depended on by `chio-mcp-remote`, `chio-http-core`, `chio-a2a-adapter`, and
other crates that open outbound HTTP connections.

## Building

```bash
cargo build -p chio-egress-contract
cargo build -p chio-egress-contract --features reqwest-egress
cargo test -p chio-egress-contract --features reqwest-egress
```

## House rules

- No em dashes (U+2014) anywhere in code, comments, or documentation.
- Workspace clippy lints `unwrap_used = "deny"` and `expect_used = "deny"` apply.
- Fail-closed: every enforcement method denies on the first policy violation
  without attempting partial matches.
