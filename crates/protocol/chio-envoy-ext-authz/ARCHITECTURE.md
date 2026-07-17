# chio-envoy-ext-authz architecture

## Overview

This crate is an untrusted edge adapter: Envoy delivers `CheckRequest`s built
from live network traffic, and everything the crate emits into a
`ToolCallRequest` has passed through validation or been discarded first. It
speaks the Envoy `ext_authz` gRPC contract on one side and a small
protocol-agnostic `ToolCallRequest` / `Verdict` pair on the other, deliberately
holding no dependency on `chio-kernel` or `chio-http-core` so it can be linked
into any Envoy-fronted service on its own. `#![forbid(unsafe_code)]` and
`#![deny(missing_docs)]` apply crate-wide.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public surface: re-exports, module declarations, and the generated `proto` module tree (mirrors the vendored `.proto` package hierarchy). |
| `src/service.rs` | `EnvoyKernel` trait and `ChioExtAuthzService`, the tonic `Authorization::check` implementation coordinating translate, evaluate, and respond. |
| `src/translate.rs` | Envoy `CheckRequest` to `ToolCallRequest` projection: method/path normalization, tool-identity derivation, caller-identity extraction, header allowlisting, body and bearer-token hashing. |
| `src/response.rs` | `Verdict` to `CheckResponse` construction: OK/Denied HTTP responses, Envoy status-code mapping, header sanitization, dynamic metadata attachment. |
| `src/metadata.rs` | `prost_types::Struct` builders for the `chio.*` dynamic metadata fields. |
| `src/error.rs` | `TranslateError` and `KernelError`, the crate's public error types. |
| `build.rs` | Compiles the vendored `proto/` tree via `tonic-build`, sourcing a vendored `protoc` binary when `PROTOC` is unset. |
| `proto/` | Minimal vendored subset of Envoy's `envoy.service.auth.v3` API; field numbers match upstream so wire compatibility holds. |

## Check request lifecycle

1. Envoy calls `Authorization/Check` with a `CheckRequest` (`service.rs`).
2. `check_request_to_tool_call` projects it into a `ToolCallRequest`: derive
   the `http.<method>.<path>` tool identity, split path from query, allowlist
   policy-relevant headers (stripping `authorization` and
   `x-chio-capability-token`), and extract caller identity in order -
   `x-chio-capability-token`, then `Authorization: Bearer`, then the mTLS peer
   principal, then anonymous. A malformed request returns `TranslateError`
   before the kernel is ever invoked.
3. `ChioExtAuthzService::check` hands the `ToolCallRequest` to the configured
   `EnvoyKernel::evaluate`.
4. `verdict_to_response` maps `Verdict::Allow` to an `OkHttpResponse` and
   `Verdict::Deny` to a `DeniedHttpResponse` carrying the caller-supplied HTTP
   status (mapped to the nearest Envoy `StatusCode`, defaulting to 403) plus
   `x-chio-denial-reason` / `x-chio-denial-guard` headers.
5. Every response carries `dynamic_metadata` under the `chio.*` namespace for
   Envoy's access log. Translation or kernel errors instead produce
   `fail_closed_response()`: a stable 500 with `chio.fail_closed = true` and no
   internal error text.

## Invariants and failure modes

- Fail closed: any `TranslateError` or `EnvoyKernel::evaluate` error yields a
  `Code::Internal` `DeniedHttpResponse` with a fixed, generic reason. The
  actual fault is logged via `tracing::warn`, never returned to the caller.
- Raw secrets never cross the response boundary: `authorization` and
  `x-chio-capability-token` are excluded from the forwarded header map; only a
  SHA-256 hex digest of the bearer token (and, when present, the body) is
  retained.
- Header values written back onto responses (`x-chio-denial-reason`,
  `x-chio-denial-guard`) are sanitized: control characters become spaces and an
  empty result becomes `"unspecified"`, so a guard name or denial reason
  cannot inject control bytes into response headers.
- HTTP method strings must be non-empty, equal to their own trimmed form, and
  free of control or whitespace bytes, or translation rejects with
  `TranslateError::InvalidHttpMethod`.
- `Verdict::Deny.http_status` maps to the nearest representable Envoy
  `StatusCode`, falling back to 403 when unmapped. The same mapped value backs
  both the `DeniedHttpResponse` status and the `chio.http_status` metadata
  field, so the two never disagree.
- `.proto` files under `proto/` vendor only the fields this crate uses, but
  preserve upstream field numbers, so wire compatibility with Envoy holds
  despite the subset.

## Dependencies

Internal: none. The crate depends on no `chio-*` crate; `EnvoyKernel` is the
seam a caller implements to plug in `chio-kernel`, `chio-http-core`'s
`HttpAuthority`, or any other policy engine without this crate depending on
either.

External: `tonic` / `prost` / `prost-types` for the gRPC service and generated
types, `tokio` and `async-trait` for the async trait and service, `thiserror`
for error types, `tracing` for structured logs, `sha2` / `hex` for bearer-token
and body hashing. Build-time only: `tonic-build` compiles `proto/`, and
`protoc-bin-vendored` supplies `protoc` when the `PROTOC` environment variable
is unset.

## Extension points

`EnvoyKernel` is the sole extension point: implement
`async fn evaluate(&self, request: ToolCallRequest) -> Result<Verdict, KernelError>`
and construct `ChioExtAuthzService::new(your_kernel)`. No implementation ships
in this crate; `tests/translate.rs` and the `lib.rs` doc example provide
mock and illustrative implementations only.
