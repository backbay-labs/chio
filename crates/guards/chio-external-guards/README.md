# chio-external-guards

`chio-external-guards` implements the concrete HTTP-backed guards in Chio's
guard pipeline: three cloud content-safety guardrails (Azure Content Safety,
AWS Bedrock, Vertex AI) and three threat-intelligence lookups (Google Safe
Browsing, Snyk, VirusTotal). Each adapter validates its target endpoint,
dispatches through a pinned `HttpEgressContract`, and maps the provider's
response to a `chio_kernel::Verdict`.

The generic async-adapter infrastructure (retry, caching, rate limiting,
circuit breaker) lives in `chio-guards`; this crate supplies the
provider-specific pieces plus `ScopedAsyncGuard`, the synchronous bridge that
lets the kernel's synchronous guard pipeline call an async external guard.

## Responsibilities

- Implement `ExternalGuard` for six providers: Azure Content Safety, AWS
  Bedrock `ApplyGuardrail`, Vertex AI safety ratings, Google Safe Browsing
  v4, Snyk, and VirusTotal v3.
- Validate every target endpoint before dispatch (scheme; loopback,
  link-local, private, multicast, and CGNAT denial; live DNS resolution)
  and pin the validated authority into an `HttpEgressContract` so redirects
  cannot escape it.
- Bridge the kernel's synchronous `Guard` trait to an async
  `AsyncGuardAdapter` via `ScopedAsyncGuard`, with optional tool-name glob
  scoping.
- Build a `GuardEvidence` record from each provider's decision
  (`evidence_from_decision`) for receipt attachment.

## Public API

| Guard | Config | Service |
|-------|--------|---------|
| `AzureContentSafetyGuard` | `AzureContentSafetyConfig` | Azure AI Content Safety `text:analyze` |
| `BedrockGuardrailGuard` | `BedrockGuardrailConfig` | AWS Bedrock `ApplyGuardrail` |
| `VertexSafetyGuard` | `VertexSafetyConfig` | Vertex AI `generateContent` safety ratings |
| `SafeBrowsingGuard` | `SafeBrowsingConfig` | Google Safe Browsing v4 `threatMatches:find` |
| `SnykGuard` | `SnykConfig` | Snyk per-package vulnerability lookup |
| `VirusTotalGuard` | `VirusTotalConfig` | VirusTotal v3 hash/URL reputation |

- `ScopedAsyncGuard<E>` - synchronous `chio_kernel::Guard` wrapping an
  `AsyncGuardAdapter<E>`, scoped to tool-name glob patterns (`*`/`?`).
- Each guard exposes `evidence_from_decision(verdict, details) ->
  GuardEvidence`; provider decision-detail types (`AzureDecisionDetails`,
  `BedrockDecisionDetails`, `VertexDecisionDetails`, and their
  category/probability breakdowns) are re-exported alongside the guard.
- `validate_external_guard_url`, `validate_external_guard_url_with_resolver`,
  `validate_external_guard_url_without_dns`, `denied_external_guard_ip` -
  endpoint allow/deny checks shared by every adapter.
- `external::{AsyncGuardAdapter, ExternalGuard, ExternalGuardError,
  GuardCallContext, CircuitBreaker, TokenBucket, TtlCache, RetryConfig,
  ...}` - generic async-adapter infrastructure re-exported from
  `chio-guards`.

## Testing

`cargo test -p chio-external-guards`

## See also

- `chio-guards` - generic async guard-adapter infrastructure (retry, cache,
  rate limit, circuit breaker) this crate builds on.
- `chio-egress-contract` - the HTTP egress contract enforced on every
  dispatch.
- `chio-kernel` - the synchronous `Guard` pipeline `ScopedAsyncGuard` plugs
  into.
