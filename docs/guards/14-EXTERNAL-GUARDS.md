# External Guards -- Operator and Policy Reference

> **Depends on**: `docs/guards/01-CURRENT-GUARD-SYSTEM.md` (guard trait
> and pipeline), `docs/standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md`
> (claim boundary)

External guards call out to third-party services (cloud content-safety
APIs, threat-intel feeds) to inform the kernel's allow or deny decision.
The kernel's guard pipeline is synchronous and fail-closed. Every
provider call is wrapped in circuit-breaker, cache, rate-limit, and
retry machinery so a slow or unhealthy external service does not block
the kernel or widen the claim being made.

This page is the operator and policy contract for that surface. It does
not restate per-provider API semantics. It specifies which Chio types
operators configure, which failure modes translate to which kernel
verdicts, and what evidence lands on receipts.

Source of truth:

- `crates/guards/chio-external-guards/src/` -- public API, kernel bridge,
  endpoint-security validation
- `crates/guards/chio-guards/src/external/` -- adapter infrastructure
  (circuit breaker, token bucket, TTL cache, retry)

---

## 1. Provider Catalog

Six providers ship today. Each implements the same
[`ExternalGuard`] trait and composes with the same
[`AsyncGuardAdapter`] infrastructure.

| Provider                 | Chio guard type              | Class            | Evidence struct              |
|--------------------------|------------------------------|------------------|------------------------------|
| AWS Bedrock Guardrails   | `BedrockGuardrailGuard`      | Content safety   | `BedrockDecisionDetails`     |
| Azure AI Content Safety  | `AzureContentSafetyGuard`    | Content safety   | `AzureDecisionDetails`       |
| Google Vertex AI Safety  | `VertexSafetyGuard`          | Content safety   | `VertexDecisionDetails`      |
| Google Safe Browsing     | `SafeBrowsingGuard`          | URL threat intel | `SafeBrowsingEvidence`       |
| VirusTotal               | `VirusTotalGuard`            | URL threat intel | `VirusTotalEvidence`         |
| Snyk                     | `SnykGuard`                  | Vulnerability    | `SnykEvidence`               |

All six are fail-closed by default: a downstream error produces
`Verdict::Deny`. Advisory mode (return `Allow` on degraded states) is
opt-in per adapter and must be enabled explicitly.

---

## 2. Adapter Architecture

The adapter wrapping an `ExternalGuard` composes four pieces in a fixed
order. The order matters: it determines which failure mode returns
which verdict.

```
evaluate(ctx):
    1. CircuitBreaker.allow_call()      -> CircuitOpenVerdict on deny
    2. TtlCache.get(cache_key)          -> cached verdict on hit
    3. TokenBucket.try_acquire()        -> RateLimitedVerdict on empty
    4. retry_with_jitter(inner.eval)    -> Verdict::Deny on permanent failure
                                         -> Verdict on success (also cached)
```

Key invariants (see `crates/guards/chio-guards/src/external/mod.rs`):

- Cache is checked **before** the token bucket. Cache hits do not spend
  rate-limit budget.
- Rate-limited calls do **not** count as circuit-breaker failures. Only
  real attempts at the external service do.
- Permanent errors (4xx, malformed request) short-circuit the retry
  loop. Only `Timeout` and `Transient` errors retry and count against
  the breaker.
- The final fallback on any uncaught error path is `Verdict::Deny` with
  a `tracing::warn!` record.

---

## 3. Fail-Mode Matrix

This is the contract operators should reason about. Each row is one
failure mode; the verdict is what the kernel sees.

| Condition                                   | Default verdict | Configurable?                        |
|---------------------------------------------|-----------------|--------------------------------------|
| Circuit breaker open                        | `Deny`          | `CircuitOpenVerdict::Allow` opt-in   |
| Rate limiter empty                          | `Deny`          | `RateLimitedVerdict::Allow` opt-in   |
| Cache hit                                   | cached verdict  | TTL and capacity                     |
| Transient error (5xx, reset)                | retries         | `RetryConfig` backoff and attempts   |
| Timeout                                     | retries         | `RetryConfig` backoff and attempts   |
| Retries exhausted (still retryable)         | `Deny`          | raise max_attempts to trade latency  |
| Permanent error (4xx, malformed)            | `Deny`          | not configurable                     |
| Provider returns `Allow`                    | `Allow` (cached)| cache TTL                            |
| Provider returns `Deny`                     | `Deny` (cached) | cache TTL                            |
| Tool name does not match scope patterns     | `Allow`         | `ScopedAsyncGuard` tool patterns     |

The advisory `Allow` modes (`CircuitOpenVerdict::Allow`,
`RateLimitedVerdict::Allow`) exist for guards whose outputs inform a
human-review queue rather than gate an action. Do not enable them for
guards that are the last line of defense on a capability.

---

## 4. Endpoint Security (SSRF Posture)

Every external-guard adapter that accepts a configurable endpoint
routes it through
`chio_external_guards::validate_external_guard_url` before any HTTP
call is issued. Rules:

- Scheme must be `https`. The one exception is `http://localhost` or
  `http://127.0.0.1`, which is permitted to support test doubles.
- Host must not resolve to loopback, link-local, or RFC1918 private
  ranges. DNS resolution happens at config-load time by default
  (`validate_external_guard_url`). A no-DNS variant
  (`validate_external_guard_url_without_dns`) exists for environments
  where DNS is unavailable at config time; it still enforces the
  scheme and literal-host checks.
- Validation errors produce `ExternalGuardError::Permanent`, which
  surfaces as an adapter-construction failure rather than a runtime
  `Deny`. Misconfiguration is caught at policy load, not at traffic
  time.

Operators should not reimplement URL validation at a higher layer.
Every provider guard already calls into this module.

---

## 5. Kernel Bridge

The kernel's `Guard` trait is synchronous. The bridge is
`chio_external_guards::ScopedAsyncGuard<E>`, which:

- Wraps an `AsyncGuardAdapter<E>` in a sync `Guard` impl.
- Scopes the guard to a set of wildcard tool-name patterns. Empty
  patterns means the guard applies to every tool. A non-matching tool
  returns `Allow` without calling the external service (and without
  consuming rate-limit or cache budget).
- Bridges async to sync by detecting the current Tokio runtime flavor:
  - `MultiThread` runtime: uses `tokio::task::block_in_place`.
  - `CurrentThread` runtime: spawns a fresh current-thread runtime on
    a scoped thread to avoid deadlocking the caller's executor.
  - No runtime in scope: builds a transient current-thread runtime.

The practical consequence: external guards are safe to use from any of
Chio's edges (stdio, Streamable HTTP, Envoy ext-authz) without
guessing at the caller's runtime topology. If a runtime flavor is
unsupported (e.g. a custom flavor added in a future Tokio), the guard
returns `GuardDenied` with a diagnostic name rather than panicking.

---

## 6. Policy Wiring

External guards are instantiated through the policy-compiler path in
`crates/products/chio-cli`. Authoring lives on the
HushSpec-canonical pipeline (see `E13: Policy and Adoption
Unification`). The shape is the same for every provider:

1. Provider-specific config block (credentials, endpoint, thresholds).
2. `AsyncGuardAdapter` tuning (cache, rate limit, circuit breaker,
   retry).
3. Scope: tool-name patterns the guard applies to.

Canonical wiring tests live alongside the compiler
(`build_pipeline_from_external_guard_policy`). Treat those as the
executable spec for policy shape; this page does not attempt to freeze
the YAML schema in prose.

A minimal HushSpec example (illustrative; see policy tests for the
shipped schema):

```yaml
external_guards:
  azure_content_safety:
    enabled: true
    endpoint: "https://<region>.api.cognitive.microsoft.com"
    api_key_env: "AZURE_CONTENT_SAFETY_KEY"
    severity_threshold: 4
    tool_patterns:
      - "chat.*"
      - "sampling.*"
    adapter:
      cache_ttl_seconds: 60
      rate_per_second: 20
      rate_burst: 20
      circuit:
        failure_threshold: 5
        failure_window_seconds: 60
        reset_timeout_seconds: 30
      retry:
        max_attempts: 3
        base_delay_ms: 50
```

---

## 7. Receipt Evidence

Every provider guard exposes an `evidence_from_decision(...)` method
that returns a structured evidence record. The adapter records this
onto the receipt's guard-evidence block on both allow and deny
outcomes. Do not invent a side-channel for external-guard provenance;
the evidence struct is the authoritative surface and the format is
versioned by the provider crate.

The evidence block preserves at minimum:

- Guard name and provider identity.
- Provider decision label (e.g. Azure severity, Vertex probability,
  VirusTotal detection count).
- Upstream request correlation identity where the provider returns one.
- The cache-or-live flag (so auditors can tell a cached decision from a
  fresh call).

It does **not** embed provider API response bodies verbatim. Operators
who need raw provider telemetry should route that through SIEM export, not through
the receipt log.

---

## 8. Operator Tuning

Defaults (from `AsyncGuardAdapterConfig::default()`):

- Cache capacity: 1024 entries, 60s TTL.
- Rate limit: 20 calls/second, burst 20.
- Circuit breaker: 5 failures per 60s window opens the breaker;
  reset timeout 30s; 1 consecutive success in half-open closes it.
- Retry: configured per guard; see `RetryConfig`.

Guidance:

- Start at defaults. Only widen rate limit or shorten cache TTL if
  production traffic shows real budget pressure or staleness.
- Do not tune the circuit-breaker threshold below 3. A noisy network
  will trip a 1- or 2-failure breaker and the deny-on-open default will
  translate into blanket outage behavior.
- Cache TTL bounds evidence freshness. If your compliance posture
  requires a re-check per call, set TTL to `0` or override `cache_key`
  to return `None`.

---

## 9. Claim Boundary

External guards participate in Chio's fail-closed pipeline but do not
upgrade Chio's outward claims about the external service. Specifically,
per `docs/standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md`:

- An external-guard `Allow` verdict attests that the provider did not
  flag the request, not that the provider's judgment is correct.
- A cached verdict attests to a prior provider decision within the
  cache TTL, not a live one.
- A circuit-open `Deny` attests that the provider was unreachable
  under the configured breaker policy, not that the request was
  semantically unsafe.
- Receipts record the distinction; reports and exports must preserve
  it.

Do not add release-facing language ("content-safety verified",
"threat-intel screened") that collapses these classes. Any stronger
claim requires its own qualification lane, not a documentation change.

---

## 10. References

- `crates/guards/chio-external-guards/src/lib.rs` -- `ScopedAsyncGuard`,
  re-exports.
- `crates/guards/chio-external-guards/src/external/endpoint_security.rs` --
  URL and IP validation.
- `crates/guards/chio-guards/src/external/mod.rs` -- `ExternalGuard`,
  `AsyncGuardAdapter`, `CircuitOpenVerdict`, `RateLimitedVerdict`,
  `AsyncGuardAdapterConfig`.
- `crates/guards/chio-guards/src/external/circuit_breaker.rs` --
  three-state breaker.
- `crates/guards/chio-guards/src/external/cache.rs`,
  `token_bucket.rs`, `retry.rs` -- supporting primitives.
- `crates/products/chio-cli` -- policy-compiler wiring and
  `build_pipeline_from_external_guard_policy` test.
- `docs/standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md` -- canonical
  claim boundary.
