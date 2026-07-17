# chio-egress-contract architecture

## Overview

`chio-egress-contract` has no internal `chio-*` dependencies and forbids
`unsafe` (`#![forbid(unsafe_code)]`). It sits below the kernel and every
substrate adapter that opens outbound HTTP, and its only concern is whether a
target URL, its DNS answers, its redirect chain, and its response size
satisfy a tenant's declared `HttpEgressContract`. It knows nothing about Chio
capabilities, receipts, or tool manifests; it is the workspace's SSRF
boundary for outbound HTTP, not a protocol crate.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | `HttpEgressContract`, `PreparedHttpEgressContract`, `ValidatedHttpEgressTarget`, `HttpEgressError`; shape validation, URL/authority/address-class enforcement, synchronous DNS enforcement (`std::net::ToSocketAddrs`), and the `permissive_for_tests` constructor. |
| `src/reqwest_helper.rs` | `reqwest-egress`-gated dispatch: `send_with_contract`, `client_builder_with_contract`, `ContractClientBuilder`, `ContractResponse`, the `ContractDnsResolver` (async DNS via `tokio::net::lookup_host`), redirect replay and header stripping, and capped streamed-body collection. |
| `src/tests.rs` | Root contract enforcement tests, plus a `reqwest_egress_tests` submodule (`cfg(feature = "reqwest-egress")`) that spins up local TCP servers to exercise redirect validation, cross-origin header stripping, and streaming byte caps end to end. |

## Enforcement lifecycle

1. A caller builds a raw `HttpEgressContract` from tenant-scoped config.
   `validate()` checks shape only (non-empty namespace/allowlists, a nonzero
   byte ceiling, canonical scheme and authority tokens). `prepare()` runs
   `validate()` once and returns an immutable `PreparedHttpEgressContract`
   snapshot; mutating the original struct afterward does not affect it.
2. `enforce_url` checks `redirect_chain_len` against `max_redirect_chain`,
   parses the target, denies userinfo, checks the scheme against
   `allowed_schemes`, classifies the host and denies loopback / link-local /
   IPv6-ULA / private-or-special-use addresses per policy - but for a
   domain-name host it only checks the literal `localhost` names, since no
   resolution happens yet. It then checks the normalized authority against
   `allowed_authority_set` (a no-port entry matches the scheme's default-port
   URL and vice versa).
3. `enforce_url_with_dns` runs `enforce_url`, then resolves domain-name hosts
   via `ToSocketAddrs` and applies the same address-class check to every
   returned IP. This is the only `lib.rs` path that protects a domain name
   pointed at a private address; `enforce_url` and `enforce_attempt` alone do
   not resolve DNS.
4. Under `reqwest-egress`, `send_with_contract` calls `enforce_url_with_dns`
   before every hop, executes against a client from
   `client_builder_with_contract` (redirects and proxying disabled, DNS
   pinned to `ContractDnsResolver`), validates and re-authorizes each
   `Location` redirect before following it, strips
   `Authorization`/`Cookie`/`Proxy-Authorization` and denies body-preserving
   methods on cross-origin hops, and streams the response body under a
   running counter checked against `max_response_bytes` after every chunk.

## Invariants and failure modes

- Fail closed: `enforce_required` denies a `None` contract; `validate` and
  `prepare` reject malformed shape before any per-request enforcement runs.
- Address-class denial is two-tier. Loopback, link-local, and IPv6
  unique-local addresses are denied only when their contract flag is set.
  Private/special-use IPv4 and IPv6 ranges are denied unconditionally, even
  for an allow-listed authority.
- DNS resolution and enforcement are implemented twice, deliberately kept in
  sync: `enforce_url_with_dns` resolves synchronously (`ToSocketAddrs`); the
  `reqwest-egress` resolver resolves asynchronously (`tokio::net::lookup_host`)
  and enforces the authority allowlist on the hostname a second time
  (`enforce_resolver_hostname`) before performing the lookup. Both apply
  `enforce_resolved_ip` to every answer, so a rebinding response cannot pass
  the check with one address and connect to another - the check and the
  connect share the same resolution.
- The underlying `reqwest::Client` is built with `redirect::Policy::none()`;
  `send_with_contract` treats a response whose URL differs from the request
  URL as a configuration error rather than trusting reqwest not to have
  followed a redirect internally.
- `HttpEgressContract::permissive_for_tests` is ordinary public API, not
  `#[cfg(test)]`-gated, so dependent crates can build wildcard-loopback
  contracts in their own tests. Its doc comment states production code must
  not call it; nothing in the type system enforces that.
- The default feature set never pulls in `reqwest` or `tokio`; contract
  validation and non-DNS enforcement need only `serde`, `thiserror`, and
  `url`.

## Dependencies

No internal `chio-*` dependencies. Always compiled: `url` for URL and host
parsing, `serde` for `HttpEgressContract`'s `Serialize`/`Deserialize` derive,
`thiserror` for `HttpEgressError`. Only under `reqwest-egress`: `reqwest`
(`rustls` backend, no default features) for dispatch, `serde_json` for
`ContractResponse::json`, `tokio` (`net` feature) for the resolver's
`lookup_host` call.
