# chio-guards architecture

## Overview

`chio-guards` runs inside the kernel's trust boundary as policy-enforcement
code, not policy-definition code: `chio-kernel` builds an
already-capability-validated `GuardContext` and calls `Guard::evaluate`, and
every guard here returns a fail-closed `Verdict` (`Allow` / `Deny` /
`PendingApproval`) plus `GuardEvidence`. The crate holds no persistent kernel
state, signs no receipts, and does not itself parse YAML/HushSpec policy
(that is `chio-policy`, which builds instances of these guards from
configuration). Evaluation is synchronous and in-process; the `external`
module supplies async resilience primitives (circuit breaker, TTL cache,
token bucket, retry) for guards that call out to an external service, but
bridging those into the synchronous `Guard` trait is left to the caller.

Most guards are thin classify-then-check wrappers: run
`action::extract_action_checked` to turn `(tool_name, arguments)` into a
typed `ToolAction`, match the one or two variants the guard owns, and
evaluate a narrow, guard-specific policy against the matched fields. A
minority (rate-limiting, session-journal, CUA side-channel, and embedding
guards) key directly off `tool_name` / `arguments` or session-journal state
instead of the shared classifier.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Module declarations, guard re-exports, `RuntimeGuardProfile` + `default_runtime_guard_profile()`. |
| `src/action.rs` (+ `action/extractor.rs`) | `ToolAction`, `MalformedAction`, the fail-closed `extract_action_checked` classifier. |
| `src/path_normalization.rs` | Lexical and filesystem-resolved path normalization shared by path-matching guards. |
| `src/pipeline.rs` | `GuardPipeline`: ordered, fail-closed `Guard` composition. |
| `src/forbidden_path.rs` | `ForbiddenPathGuard`: glob-based sensitive-path denylist. |
| `src/path_allowlist.rs` | `PathAllowlistGuard`: deny-by-default file access/write/patch allowlist + session-root enforcement. |
| `src/secret_leak.rs` | `SecretLeakGuard`: regex secret scan on write/patch content. |
| `src/patch_integrity.rs` | `PatchIntegrityGuard`: diff-size and forbidden-pattern analysis. |
| `src/shell_command.rs` | `ShellCommandGuard`: destructive-command detection with a hand-rolled shlex tokenizer. |
| `src/egress_allowlist.rs` | `EgressAllowlistGuard`: domain allow/block list for network egress. |
| `src/internal_network.rs` | `InternalNetworkGuard`: SSRF protection (private ranges, cloud metadata, DNS rebinding, encoded IPs). |
| `src/mcp_tool.rs` | `McpToolGuard`: generic MCP tool allow/block list + argument-size cap. |
| `src/velocity.rs` | `VelocityGuard`: per-`(capability, grant)` token-bucket invocation/spend limiter. |
| `src/agent_velocity.rs` | `AgentVelocityGuard`: per-agent / per-session token-bucket limiter. |
| `src/data_flow.rs` | `DataFlowGuard`: cumulative session byte-transfer ceiling via `SessionJournal`. |
| `src/behavioral_sequence.rs` | `BehavioralSequenceGuard`: tool-ordering policy via `SessionJournal`. |
| `src/behavioral_profile.rs` | `BehavioralProfileGuard` and `ReceiptFeedSource`: EMA/z-score anomaly detection. |
| `src/text_utils.rs` | Text canonicalization (homoglyph fold, zero-width strip) shared by the two content-safety detectors. |
| `src/prompt_injection.rs` | `PromptInjectionGuard`: 6-signal regex prompt-injection detector. |
| `src/jailbreak.rs` | `JailbreakGuard`: fingerprint-deduped wrapper around the detector below. |
| `src/jailbreak_detector.rs` | `JailbreakDetector`: 3-layer heuristic + statistical + linear-model scoring engine. |
| `src/response_sanitization.rs` (+ `response_sanitization/`) | `OutputSanitizer`, `ResponseSanitizationGuard`, `TokenVault`: detection and redaction. |
| `src/content_review.rs` | `ContentReviewGuard`: PII/profanity detection + monetary approval gate on `ExternalApiCall`. |
| `src/computer_use.rs` | `ComputerUseGuard`: coarse CUA action-type allowlist + navigation + screenshot rate limit. |
| `src/input_injection.rs` | `InputInjectionCapabilityGuard`: fine-grained `input.inject` gate. |
| `src/remote_desktop.rs` | `RemoteDesktopSideChannelGuard`: per-channel remote-desktop toggles. |
| `src/embedding_anomaly.rs` | `EmbeddingAnomalyGuard`: cosine-similarity threat-pattern match. |
| `src/browser_automation.rs` | `BrowserAutomationGuard`: domain/verb gating + credential detection. |
| `src/code_execution.rs` | `CodeExecutionGuard`: language allowlist + dangerous-module + network gate. |
| `src/memory_governance.rs` | `MemoryGovernanceGuard`: agent-memory store/TTL/size/content governance. |
| `src/advisory.rs` | `AdvisoryPipeline`, `AdvisoryGuard`, `PromotionPolicy`, built-in advisory guards. |
| `src/post_invocation.rs` | `SanitizerHook` + `sanitize_json`: post-invocation redaction over `OutputSanitizer`. |
| `src/external/mod.rs` (+ `cache.rs`, `circuit_breaker.rs`, `retry.rs`, `token_bucket.rs`) | `AsyncGuardAdapter`: circuit breaker + TTL cache + token bucket + retry-with-jitter. |

## Guard evaluation lifecycle

1. `chio-kernel` resolves the capability and grant for a `ToolCallRequest`
   and builds a `GuardContext` (request, matched scope, agent/server id,
   optional session filesystem roots, optional matched grant index).
2. Guards that route through the shared classifier call
   `extract_action_checked(&ctx.request.tool_name, &ctx.request.arguments)`.
   `Err(MalformedAction)` (a recognized shape with a missing or mistyped
   primary field) is denied directly, never silently downgraded to
   `ToolAction::Unknown`.
3. The guard matches the resulting `ToolAction`; variants it does not own
   return `Verdict::Allow`, so guards compose without knowing about each
   other.
4. `GuardPipeline::evaluate` (when guards are composed via a pipeline) runs
   guards in registration order, short-circuits on the first `Deny` or `Err`
   (errors are treated as fail-closed denies), and otherwise returns `Allow`
   unless some guard raised a sticky `PendingApproval`.
5. After the tool call executes, `PostInvocationPipeline` (defined in
   `chio-kernel`, driven here by `SanitizerHook`) runs `OutputSanitizer` over
   the JSON result and can `Allow`, `Redact`, `Block`, or `Escalate` before
   the caller sees it.

## Invariants and failure modes

- The classification boundary is fail-closed: filesystem-shaped names
  (canonical, `fs_`-prefixed, and ACP slash-delimited like
  `fs/read_text_file`) all resolve to the same `ToolAction` variants, and a
  malformed primary argument (`path`, `command`, `url`, ...) denies rather
  than falling through to a same-priority alias that might be benign.
- Config constructors that compile operator-supplied regex/glob patterns
  (`ForbiddenPathGuard::with_patterns`, `ShellCommandGuard::try_with_patterns`,
  `SecretLeakGuard::with_config`, `PatchIntegrityGuard::with_config`,
  `EgressAllowlistGuard::with_lists`, `OutputSanitizer::with_config`, ...)
  reject the whole configuration on any invalid pattern instead of silently
  dropping it. Several `::new()` constructors additionally fall back to a
  deny-everything guard if a (supposedly constant) default pattern set
  somehow fails to compile (`ShellCommandGuard::fail_closed`,
  `BrowserAutomationGuard::empty_failclosed`,
  `CodeExecutionGuard::empty_failclosed`).
- `OutputSanitizer` fails closed on a broken constant detector pattern by
  redacting the entire input (`redact_all_finding`) rather than scanning with
  a degraded pattern set.
- `VelocityGuard` and `AgentVelocityGuard` bound their token-bucket maps to a
  configured `bucket_cap` (sourced from `chio_kernel::MemoryBudgetConfig` by
  default) and deny new keys rather than evicting buckets that still hold
  live, non-fully-refilled rate-limit state, closing a reset-by-eviction
  bypass.
- `BehavioralSequenceGuard` reads the `SessionJournal`'s cumulative O(1)
  fields (`current_streak_tool`/`len`, `tool_counts`) instead of its bounded
  `tool_sequence` ring, so policy enforcement survives ring eviction and a
  `journal_entry_cap` of `0`.
- `AdvisoryGuard`s never deny on their own; only `AdvisoryPipeline` combined
  with a configured `PromotionPolicy` turns a signal into `Verdict::Deny`.
- Most guards return `GuardDecision::deny(Vec::new())`: the guard's `name()`
  is the audit trail for a bare deny. Only the advisory guards, the
  sanitizer hook, and `GuardPipeline` itself (which appends a `GuardEvidence`
  explaining a sub-guard's deny or error) attach structured evidence
  explaining *why*.

## Dependencies

Internal: `chio-kernel` supplies the `Guard`, `GuardContext`,
`GuardDecision`, `Verdict`, `KernelError`, `PostInvocationHook` /
`PostInvocationPipeline`, and `MemoryBudgetConfig` types this crate builds
against. `chio-core` supplies capability/scope/receipt types used in guard
logic (`Constraint::RequireApprovalAbove`, `Constraint::MemoryStoreAllowlist`,
...) and throughout the test suites. `chio-http-session` supplies
`SessionJournal`, read by `DataFlowGuard`, `BehavioralSequenceGuard`, and the
built-in advisory guards. `chio-store-sqlite` is a dev-dependency only:
`tests/behavioral_profile.rs` backs `BehavioralProfileGuard` with a
`SqliteReceiptStore`-based `ReceiptFeedSource` to demonstrate the production
shape.

External: `regex` (nearly every pattern-matching guard), `glob` (path and
domain matching), `sha2` (fingerprint hashing for dedup caches and
redaction), `lru` (bounded fingerprint-dedup caches in `JailbreakGuard` /
`PromptInjectionGuard`), `tokio` + `async-trait` (the `external` module's
async adapter), `rand` (retry jitter), `thiserror` (config error types),
`tracing` (structured deny/warn evidence). No aliasing: `chio-core` resolves
to the `chio-core` facade crate, not `chio-core-types`.

## Extension points

- `chio_kernel::Guard` - implement to add a new pre-invocation guard;
  register directly on the kernel or add to a `GuardPipeline`.
- `AdvisoryGuard` - implement to add a non-blocking observation source to
  `AdvisoryPipeline`; wire a `PromotionRule` to let operators turn it into a
  deny later without a code change.
- `chio_kernel::PostInvocationHook` - implement for a custom post-invocation
  transform; `SanitizerHook` is the built-in implementation over
  `OutputSanitizer`.
- `external::ExternalGuard` - implement to wrap a call to an external
  guardrail service; `AsyncGuardAdapter` supplies circuit-breaker, cache,
  rate-limit, and retry behavior around it.
- `behavioral_profile::ReceiptFeedSource` - implement to back
  `BehavioralProfileGuard` with a receipt source other than the in-memory
  default.
- `external::cache::Clock` - override the time source for `TtlCache`,
  `CircuitBreaker`, and `TokenBucket` (used by this crate's own tests to
  drive `tokio::time::pause`).
