# chio-external-guards architecture

## Overview

`chio-external-guards` sits at the untrusted edge of Chio's guard pipeline:
every adapter here issues an outbound HTTP call to a third-party service and
turns the response into a kernel `Verdict`. The kernel's guard pipeline is
synchronous, so the crate's second job is bridging that boundary:
`ScopedAsyncGuard` drives the async HTTP path to completion on a Tokio
runtime chosen at evaluation time. Provider-specific request and response
handling live here; the generic retry/cache/circuit-breaker composition
lives in `chio-guards`, and dispatch-time egress enforcement lives in
`chio-egress-contract`.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | `ScopedAsyncGuard<E>`, the sync `Guard` bridge; tool-name wildcard matching; crate-root re-exports. |
| `src/external/mod.rs` | Re-exports the `chio-guards` async-adapter infrastructure and declares the provider submodules. |
| `src/external/endpoint_security.rs` | Scheme/host allow-deny checks (loopback, link-local, private, multicast, CGNAT, IPv4-mapped IPv6), with and without live DNS resolution. |
| `src/external/http_egress.rs` | Builds a per-endpoint `HttpEgressContract` and a contract-scoped `reqwest::Client`, and dispatches through `chio_egress_contract::send_with_contract`. Crate-private. |
| `src/external/azure_content_safety.rs` | Azure Content Safety `text:analyze` adapter. |
| `src/external/bedrock.rs` | AWS Bedrock `ApplyGuardrail` adapter; also hosts `classify_status_error`, shared by every HTTP adapter. |
| `src/external/vertex_safety.rs` | Vertex AI `generateContent` safety-rating adapter. |
| `src/external/threat_intel/mod.rs` | Threat-intel submodule doc and re-exports. |
| `src/external/threat_intel/safe_browsing.rs` | Google Safe Browsing v4 `threatMatches:find` adapter. |
| `src/external/threat_intel/snyk.rs` | Snyk per-package vulnerability adapter. |
| `src/external/threat_intel/virustotal.rs` | VirusTotal v3 hash/URL reputation adapter. |

## Dispatch path

1. The kernel evaluates a `ScopedAsyncGuard<E>` as an ordinary sync `Guard`.
   A `tool_name` matching none of its (normalized) glob patterns returns
   `Allow` immediately; an empty pattern list matches every tool.
2. Otherwise it builds a `GuardCallContext` from the kernel `GuardContext`
   and calls `block_on`, which drives the async path to completion: via
   `block_in_place` on a multi-thread runtime, on a spawned fallback thread
   for a current-thread runtime, or on a fresh current-thread runtime when
   none is active.
3. `AsyncGuardAdapter` (`chio-guards`) applies caching, rate limiting, the
   circuit breaker, and retry-with-jitter around the wrapped guard's
   single-attempt `ExternalGuard::eval`.
4. `eval` re-validates the endpoint with live DNS resolution
   (`validate_external_guard_url`) and dispatches through the
   `HttpEgressContract` built at guard construction, re-checked on every
   redirect hop.
5. Non-2xx responses are classified by `classify_status_error` into
   transient (5xx, 429; retried by the adapter) or permanent errors; parse
   and header failures are permanent. All surface as `ExternalGuardError`,
   which the adapter maps to `Verdict::Deny`.
6. A parsed response becomes a provider-specific `Verdict` (severity,
   probability, action, or detection-count threshold), and
   `ScopedAsyncGuard` converts it into a `GuardDecision`.

## Invariants and failure modes

- Endpoint validation runs twice: at construction
  (`http_egress::contract_for_url` builds and pins the `HttpEgressContract`)
  and again on every `eval` call (`validate_external_guard_url`, live DNS).
  Address-level checks on a bare hostname are deferred to the per-call
  path, so a target that later resolves to a private, loopback,
  link-local, multicast, or CGNAT (`100.64.0.0/10`) address is rejected
  even though construction succeeded.
- `http://` is accepted only for `localhost` or a loopback IP literal (v4
  or v6); every other target must be `https`. IPv4-mapped IPv6 addresses
  are unwrapped and checked against the same IPv4 rules.
- The per-endpoint `HttpEgressContract` pins the URL's own scheme and
  normalized authority, denies loopback unless the host itself is
  loopback, always denies link-local and IPv6 ULA, and caps redirects (4
  hops) and response size (1 MiB).
- `with_client` constructors discard the passed-in `reqwest::Client` and
  rebuild one scoped to the egress contract, so automatic redirect
  handling can never bypass per-hop contract validation.
- `ScopedAsyncGuard` returns `Allow` outside its configured scope;
  deny-by-default is the composing pipeline's job, not a single scoped
  guard's. Blank and whitespace-only patterns are trimmed and dropped at
  construction, and the resulting empty list matches every tool, not
  none.
- `VirusTotalGuard` alone does not fail closed on a non-2xx status: HTTP
  404 (not indexed) maps to `Allow` so an unseen hash or URL does not
  block traffic.
- `block_on` fails closed (`KernelError::GuardDenied`) on an unrecognized
  runtime flavor or if the current-thread fallback thread panics.

## Dependencies

`chio-guards` supplies the `ExternalGuard` trait and `AsyncGuardAdapter`
(cache, rate limit, circuit breaker, retry) every provider composes with,
re-exported wholesale from `external::mod`. `chio-egress-contract` (feature
`reqwest-egress`) supplies `HttpEgressContract`, `client_builder_with_contract`,
and `send_with_contract`, enforcing scheme/authority pinning and
redirect/response-size bounds at dispatch. `chio-kernel` supplies the
synchronous `Guard`, `GuardContext`, `GuardDecision`, `KernelError`,
`Verdict`, and `ToolCallRequest` contract that `ScopedAsyncGuard` implements
against. `chio-core-types` supplies `receipt::metadata::GuardEvidence`, the
record `evidence_from_decision` produces on each guard.

`reqwest` (`json`, `rustls`), `tokio`, and `async-trait` provide HTTP
transport and the async guard trait. `zeroize` wraps every credential in
`Zeroizing<String>` so it is scrubbed from memory on drop. `sha2`, `base64`,
and `url` support cache-key hashing, VirusTotal URL-lookup ids, and URL and
host parsing.

## Extension points

- A new provider implements `external::ExternalGuard` (`name`, `cache_key`,
  a single-attempt `eval`), reuses `external::validate_external_guard_url`
  for its endpoint pre-flight check, and is wrapped in
  `external::AsyncGuardAdapter::builder(...)` and then
  `ScopedAsyncGuard::new(...)` to join the kernel's `Guard` pipeline.
- `http_egress` (contract construction, client building, contract-scoped
  dispatch) is crate-private. Providers added inside this crate reuse it
  directly; out-of-crate implementers must build their own
  `chio_egress_contract::HttpEgressContract` dispatch.
