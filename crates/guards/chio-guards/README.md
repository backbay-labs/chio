# chio-guards

Native, policy-driven guard implementations for the Chio kernel: filesystem,
shell, network, MCP-tool, patch, rate-limiting, session-behavioral,
prompt-injection/jailbreak, response-sanitization, and computer-use-agent
(CUA) guards, each implementing `chio_kernel::Guard`. It is a supported
public entry point (`public_entrypoint = true`): `chio-policy` compiles
YAML/HushSpec policy into instances of these guards, and `chio-control-plane`
wires in this crate's `default_runtime_guard_profile()`.

Use this crate to add a new built-in guard, tune a guard's Rust-level
defaults, or compose guards directly (bypassing the policy compiler) via
`GuardPipeline`.

## Responsibilities

- Classify a raw `(tool_name, arguments)` tool call into a typed `ToolAction`
  (`action::extract_action_checked`), the shared fail-closed dispatch
  boundary most guards in this crate match against.
- Implement 25+ pre-invocation `Guard`s spanning filesystem, shell, network
  (SSRF/egress), MCP-tool, patch, rate-limiting, session-journal-backed
  behavioral policy, content safety (prompt injection, jailbreak, PII/secret),
  and CUA (browser, computer-use, remote-desktop, code-execution, memory)
  domains.
- Compose guards into a fail-closed `GuardPipeline`, and ship two ready-made
  bundles: `GuardPipeline::default_pipeline()` (7 baseline guards) and
  `default_runtime_guard_profile()` (the control-plane host's pre- and
  post-invocation set).
- Detect and redact secrets/PII/internal data from tool *results* via
  `OutputSanitizer`, wired into the kernel's post-invocation hook chain by
  `SanitizerHook`.
- Provide resilience scaffolding (`external::AsyncGuardAdapter`: circuit
  breaker + TTL cache + token bucket + retry-with-jitter) for guards that call
  out to an async external guardrail service.
- Provide a non-blocking `AdvisoryGuard` / `AdvisoryPipeline` framework so an
  observation can ship as telemetry first and be promoted to a hard deny
  later via `PromotionPolicy`, without a code change.

## Public API

Guards group by the `ToolAction` domain they inspect. Construct via
`Guard::new()` (safe defaults) or `Guard::with_config(...)` (validated,
often fallible).

| Domain | Guard | Purpose |
|---|---|---|
| Filesystem | `ForbiddenPathGuard` | Denies glob-matched sensitive paths (`.ssh`, `.aws`, `.env`, `/etc/shadow`, ...) |
| Filesystem | `PathAllowlistGuard` | Deny-by-default file access/write/patch allowlist; also enforces session filesystem roots |
| Filesystem | `SecretLeakGuard` | Regex secret scan (AWS/GitHub/OpenAI/Slack/Stripe/... keys) on write/patch content |
| Filesystem | `PatchIntegrityGuard` | Diff size ceilings + forbidden-pattern scan (disabled security, backdoors, `eval(`) on added lines |
| Shell/network | `ShellCommandGuard` | Blocks destructive command lines (`rm -rf /`, `curl \| bash`, reverse shells) via a hand-rolled shlex tokenizer |
| Shell/network | `EgressAllowlistGuard` | Domain allow/block list for `NetworkEgress` actions |
| Shell/network | `InternalNetworkGuard` | SSRF guard: private/loopback/link-local ranges, cloud metadata hosts, DNS-rebinding and encoded-IP hostnames |
| Tool/rate | `McpToolGuard` | Allow/block list + max argument size for generic MCP tool calls |
| Tool/rate | `VelocityGuard` | Token-bucket invocation/spend limiter per `(capability_id, grant_index)` |
| Tool/rate | `AgentVelocityGuard` | Token-bucket limiter per agent and per session |
| Session journal | `DataFlowGuard` | Cumulative bytes-read/written ceiling read from `SessionJournal` |
| Session journal | `BehavioralSequenceGuard` | Tool-ordering policy: required predecessors, forbidden transitions, max-consecutive, required-first-tool |
| Session journal | `BehavioralProfileGuard` | EMA/z-score anomaly detector over a `ReceiptFeedSource` (advisory, never blocks) |
| Content safety | `PromptInjectionGuard` | 6-signal regex detector (instruction override, role/delimiter injection, output hijack, tool-chain hijack, exfiltration framing) |
| Content safety | `JailbreakGuard` | 3-layer heuristic + statistical + linear-model detector (`JailbreakDetector`) |
| Content safety | `ResponseSanitizationGuard`, `OutputSanitizer` | Secret/PII/internal-data detection and redaction (Mask/Fingerprint/Drop/Tokenize/Partial/TypeLabel) |
| Content safety | `ContentReviewGuard` | PII/profanity detection + monetary approval gating on `ExternalApiCall`s |
| CUA | `ComputerUseGuard` | Coarse `remote.*`/`input.*` action-type allowlist + navigation domain gate + screenshot rate limit |
| CUA | `InputInjectionCapabilityGuard` | Fine-grained `input.inject` type allowlist + optional postcondition-probe requirement |
| CUA | `RemoteDesktopSideChannelGuard` | Per-channel clipboard/file-transfer/audio/drive/printing/session-share toggles + transfer-size cap |
| CUA | `EmbeddingAnomalyGuard` | Cosine-similarity match against a threat-pattern embedding database |
| CUA | `BrowserAutomationGuard` | Navigation domain gate + verb allowlist + credential detection on `type`/`input` actions |
| CUA | `CodeExecutionGuard` | Language allowlist + dangerous-module detection + network gate + execution-time bound |
| Memory | `MemoryGovernanceGuard` | Store allowlist + retention-TTL ceiling + per-session entry count + content-size + deny-pattern |
| Advisory | `AdvisoryPipeline`, `AnomalyAdvisoryGuard`, `DataTransferAdvisoryGuard` | Non-blocking signals, optionally promoted to `Verdict::Deny` |
| Post-invocation | `SanitizerHook`, `sanitize_json` | Runs `OutputSanitizer` over a tool result after the call returns |
| External | `AsyncGuardAdapter`, `ExternalGuard` | Resilience wrapper for calling out to an async external guardrail |
| Composition | `GuardPipeline` | Ordered, fail-closed composition of `Guard`s |

## Usage

```rust
use chio_guards::{GuardPipeline, JailbreakGuard};

let mut pipeline = GuardPipeline::default_pipeline();
pipeline.add(Box::new(JailbreakGuard::new()));
kernel.add_guard(Box::new(pipeline));
```

## Testing

`cargo test -p chio-guards`

Mutation coverage on the security-critical guards is tracked separately:
`cargo mutants --config crates/guards/chio-guards/mutants.toml --package chio-guards`

## See also

- `chio-kernel` - defines the `Guard`, `GuardContext`, `GuardDecision`, and
  `PostInvocationHook` contracts this crate implements.
- `chio-policy` - policy compiler that builds instances of these guards from
  YAML/HushSpec configuration.
- `chio-control-plane` - hosted runtime that wires in
  `default_runtime_guard_profile()`.
- `chio-http-session` - supplies `SessionJournal`, read by the data-flow and
  behavioral guards.
- `chio-store-sqlite` - dev-dependency; backs `ReceiptFeedSource` for
  `BehavioralProfileGuard` in production (see `tests/behavioral_profile.rs`).
- `chio-data-guards`, `chio-external-guards`, `chio-wasm-guards` - sibling
  guard crates in the same component group (see `AGENTS.md`).
