# chio-api-protect

Zero-code reverse proxy that protects HTTP APIs with Chio signed receipts.

## What it does

`chio-api-protect` reads an OpenAPI spec (from a file, a URL, or inline
content), generates a default Chio policy, and proxies all requests to the
upstream API. Every request produces a signed `HttpReceipt`. Side-effect routes
(`POST`/`PUT`/`PATCH`/`DELETE`) require a capability token before the request
is forwarded; safe routes (`GET`/`HEAD`/`OPTIONS`) pass with audit receipts. A
built-in SQLite store persists receipts across restarts when a `receipt_db` path
is provided. A sidecar control endpoint lets operators query pending approvals
and inject decisions at runtime without modifying the upstream service.

The crate is the backing library for `chio api protect`. It exposes
`ProtectConfig`, `ProtectProxy` (the running reverse proxy), `RequestEvaluator`
(route-matching and capability enforcement), and `ProtectError`. Spec discovery
(`discover_spec`, `load_spec_from_file`) handles OpenAPI auto-detection and
loading.

## Position in the system

```
Inbound HTTP client
        |
  [chio-api-protect]  -- evaluates capability tokens, signs receipts
        |
  Upstream HTTP API
```

`chio-api-protect` depends on `chio-http-core` (HTTP authority and receipt
types), `chio-kernel` (approval store), and `chio-openapi` (spec parsing and
policy defaults). It sits in front of any existing HTTP API and adds Chio
receipt-signing with no changes to the upstream service.

## Crate layout

```
crates/chio-api-protect/
  Cargo.toml          workspace deps, reqwest-egress feature via chio-http-core
  src/
    lib.rs            public re-exports: ProtectConfig, ProtectProxy, EvaluationResult, RouteEntry
    error.rs          ProtectError
    evaluator.rs      RequestEvaluator -- route matching, capability enforcement, receipt signing
    proxy.rs          ProtectProxy -- Axum server, request routing, sidecar control routes
    spec_discovery.rs OpenAPI spec auto-discovery and loading helpers
```

## Building

```bash
cargo build -p chio-api-protect
cargo test -p chio-api-protect
```

## House rules

- No em dashes (U+2014) anywhere in code, comments, or documentation.
- Workspace clippy lints `unwrap_used = "deny"` and `expect_used = "deny"` apply.
- Fail-closed: missing or invalid capability tokens deny the request and produce
  a deny receipt before any bytes reach the upstream.
