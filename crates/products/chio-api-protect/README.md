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
crates/products/chio-api-protect/
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

## Sidecar routes that are not production authorization paths

The proxy embeds SDK control routes (`/v1/*`, `/chio/*`) beside the upstream
reverse proxy. Only some of them perform kernel-mediated HTTP authorization
(the same evaluation path as mutating upstream requests). The following routes
must not be used as sole allow/deny gates for tool execution in production:

- **`POST /v1/evaluate/advisory`** - tool-call advisory route for SDK
  helpers. Signs an `AdvisoryEvaluation` receipt after local revocation and
  parameter-hash checks only. Responses include `chio-trust-level: advisory`,
  `authorization: false`, `authorizationBasis: "advisory_only"`, and a
  receipt whose `trust_level` is `advisory`. This is not kernel-mediated
  authorization.
- **`POST /v1/evaluate`** - reserved compatibility path. It returns HTTP 410 and
  does not sign a receipt.
- **`POST /v1/capabilities/attenuate`** - returns HTTP 403 with
  `error: "chio_attenuation_requires_subject_signer"` and
  `authorization: false` in the JSON body. Capability delegation requires the
  parent subject's private key, which the sidecar does not hold.
- **`POST /v1/capabilities/validate`** - verifies the capability token
  signature, expiry, and local revocation set only; it does not evaluate policy
  or scope against a concrete tool call.
- **`POST /v1/capabilities`** and **`POST /v1/capabilities/mint`** - mint
  sidecar-signed capability tokens for development and SDK ergonomics; minting
  here is not a substitute for your capability authority in production.
- **`POST /v1/receipts`** - accepts operator-submitted receipts for logging;
  submission does not imply the kernel mediated the original action.

Authoritative mediated evaluation for HTTP-shaped requests remains
**`POST /chio/evaluate`** (and the upstream proxy path that runs the same
evaluator before forwarding). Kernel-driven tool-call evaluation through the
sidecar is not wired in this crate yet.

## House rules

- No em dashes (U+2014) anywhere in code, comments, or documentation.
- Workspace clippy lints `unwrap_used = "deny"` and `expect_used = "deny"` apply.
- Fail-closed: missing or invalid capability tokens deny the request and produce
  a deny receipt before any bytes reach the upstream.
