# chio-egress-contract

Typed HTTP egress policy for Chio substrate adapters. Kernel, guard, and
adapter code paths that open outbound HTTP must declare an
`HttpEgressContract` and pass every target through it before dispatch; a
missing or invalid contract fails closed. The crate has no internal `chio-*`
dependencies and, without the `reqwest-egress` feature, no I/O dependencies
at all - it is the workspace's SSRF boundary for outbound HTTP.

## Responsibilities

- Define `HttpEgressContract`: scheme allowlist, exact authority allowlist,
  independent loopback/link-local/IPv6-ULA denial flags, redirect-depth cap,
  and response-byte ceiling.
- Enforce that contract against a target URL's userinfo, scheme, host, and
  normalized authority, denying on the first violation.
- Deny RFC 1918 and other private/special-use IPv4 and IPv6 ranges
  unconditionally, even when the authority is allow-listed.
- Resolve domain-name hosts and re-check every returned address against the
  same policy before a caller opens a socket (`enforce_url_with_dns`).
- Behind `reqwest-egress`, dispatch a `reqwest::Client` request through the
  contract on the initial URL, every redirect hop, and the streamed response
  size.

## Public API

- `HttpEgressContract` - the raw policy. `validate()` checks shape;
  `prepare()` returns an immutable `PreparedHttpEgressContract`.
- `HttpEgressContract::enforce_required` - fail-closed entry point over an
  `Option<&HttpEgressContract>`.
- `enforce_url` (userinfo, scheme, address-class, authority),
  `enforce_url_with_dns` (adds DNS resolution and a per-IP class check),
  `enforce_response_bytes`, `enforce_attempt` (`enforce_url` plus an optional
  byte check) - each available on `HttpEgressContract` (re-validates shape
  through `prepare()` every call) and `PreparedHttpEgressContract` (already
  validated).
- `validate_dispatchable_with_pinned_dns` - confirms every allowed authority
  is usable by the pinned-DNS resolver the `reqwest-egress` dispatch path
  uses.
- `ValidatedHttpEgressTarget` - tenant namespace, scheme, and authority
  returned once enforcement passes.
- `HttpEgressError` - fail-closed reason enum (`thiserror`), one variant per
  denial class.
- `HttpEgressContract::permissive_for_tests` - wildcard-loopback contract for
  tests driving a local server. Not `#[cfg(test)]`-gated; its doc comment
  states production code must not call it.

Behind `reqwest-egress` (re-exported at the crate root from `reqwest_helper`):

- `send_with_contract` - drives a `reqwest::Request` through per-hop contract
  enforcement and a capped, streamed response read.
- `client_builder_with_contract` / `ContractClientBuilder` - builds a
  `reqwest::Client` with redirects and proxying disabled and DNS pinned to
  the contract; the builder exposes only `.timeout()`.
- `ContractResponse` - status/url/headers/body accessors plus async `text()`
  and `json()`.

## Feature flags

| Flag | Effect |
|------|--------|
| `reqwest-egress` | Adds `reqwest` (`rustls`, no default features), `serde_json`, and `tokio` (`net`). Exposes `reqwest_helper` and re-exports `send_with_contract`, `client_builder_with_contract`, `ContractClientBuilder`, `ContractResponse` at the crate root. |

## Testing

```bash
cargo test -p chio-egress-contract
cargo test -p chio-egress-contract --features reqwest-egress
```

## See also

- `chio-http-core` - re-exports `reqwest-egress` as its own feature so
  kernel-adjacent HTTP callers reach this contract via
  `chio_http_core::send_with_contract`.
- `chio-mcp-remote`, `chio-a2a-adapter`, `chio-openapi-mcp-bridge` - protocol
  adapters that dispatch outbound HTTP through this contract directly.
- `chio-guard-registry`, `chio-external-guards` - guard-layer consumers of
  the `reqwest-egress` dispatch path.
- Also depended on directly by `chio-anchor`, `chio-link`, `chio-settle`
  (economy), `chio-siem` (observability), `chio-cli`, `chio-proof-room`
  (products), and `chio-conformance` (tooling).
