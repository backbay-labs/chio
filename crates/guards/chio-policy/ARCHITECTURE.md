# chio-policy architecture

## Overview

`chio-policy` is Chio's native HushSpec policy engine: a pure-Rust parser,
validator, evaluator, and compiler for the YAML policy format that governs
AI-agent tool, egress, filesystem, shell, and computer-use actions. It is
marked `public_entrypoint = true` and sits between operator-authored policy
documents and the kernel's runtime enforcement surface (`chio-guards`,
`chio-kernel`): invalid HushSpec documents must reject before any guard or
capability scope is materialized. The crate touches the filesystem only in
`resolve` (walking `extends` chains) and in the detection compiler (loading a
`threat_intel.pattern_db` JSON asset); parsing, validation, merge, and
evaluation are pure in-memory transformations.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Crate root: re-exports the public API, `is_hushspec_format`. |
| `src/models.rs` + `models/{enums,extensions,rules,yaml_safety}.rs` | HushSpec schema (`HushSpec`, `Rules` with 14 blocks, `Extensions` with 5 blocks, governance metadata); `HushSpec::parse` hardens against pathological YAML before delegating to `serde_yml`. |
| `src/validate.rs` | Schema/semantic validation: regex safety, workload-identity shape, posture graphs, detection thresholds, reputation and runtime-assurance tiers. |
| `src/merge.rs` | `extends` inheritance: replace / merge / deep-merge, field by field. |
| `src/resolve.rs` | Filesystem `extends` chain resolution with cycle detection. |
| `src/conditions.rs` | `Condition` predicate tree (`time_window`, `context`, `all_of`/`any_of`/`not`) evaluated against a `RuntimeContext`; gates rule blocks for `evaluate_with_context`. |
| `src/evaluate.rs` + `evaluate/{context,engine,matchers,outcomes,tests}.rs` | Reference evaluator. The four non-test files are `include!`-d into `evaluate.rs`, not declared as `mod`, so they share one module's namespace and `use` imports rather than being independent submodules. |
| `src/compiler.rs` + `compiler/{budgets,detection,patterns,rules,scope,tests}.rs` | HushSpec-to-Chio compiler. Unlike `evaluate`, these are real `mod` submodules reached through `super::`. |
| `src/detection.rs` | Standalone regex content detectors (`DetectorRegistry`) and `evaluate_with_detection`, layered on `evaluate` rather than wired into the guard compiler. |
| `src/receipt.rs` | `evaluate_audited`: wraps `evaluate` with timing, SHA-256 policy hashing, and a `DecisionReceipt`. |
| `src/regex_safety.rs` (private) | Shared regex hardening and a process-wide compiled-pattern cache used by both `validate` and `evaluate`. |
| `src/crypto_floor.rs` | `CryptoFloor`: kernel-wide minimum signing posture, validated against PQ key provisioning at load time. |
| `src/weights.rs` | `WeightsCardRequired` / `WeightsCardConfig`: kernel-wide signed model-card binding enforcement, validated at load time. |
| `src/version.rs` | `HUSHSPEC_VERSION` and the supported-version set `validate` checks against. |
| `src/rulesets/mod.rs` + 7 `.yaml` files | Built-in rulesets embedded via `include_str!`, exposed as `chio:<name>` / `hushspec:<name>` extends targets. |

## Policy lifecycle

1. **Parse.** `HushSpec::parse` runs three hardening pre-checks (non-mapping
   document start, unclosed double-quoted scalars, libyml scalar-join
   whitespace-run overflow risk) over the raw YAML, then parses through
   `serde_yml` inside `catch_unwind` so a parser panic becomes an `Err`
   instead of aborting the process.
2. **Resolve + merge.** If `extends` is set, `resolve_from_path` (or a
   caller-supplied loader via `resolve_with_loader`) walks the chain, rejects
   cycles, and folds each parent into its child with `merge` (`replace`,
   `merge`, or `deep_merge`, chosen by the child's `merge_strategy`).
3. **Validate.** `validate` returns errors and non-fatal warnings.
   `compile_policy` calls it unconditionally before touching guards;
   `evaluate` does not call it and expects an already-valid document.
4. **Evaluate.** `evaluate` (or `evaluate_with_context`, which first filters
   rule blocks through `Condition`s) selects an origin profile, resolves
   posture, checks the posture's capability allowlist, then dispatches on
   `EvaluationAction::action_type` to a per-action evaluator that walks the
   matching rule block(s) to an allow/warn/deny `Decision`. Global panic mode
   (`activate_panic`) short-circuits every call to `Deny` first.
5. **Compile.** `compile_policy` re-validates, then translates `rules` and
   `extensions.detection` / `extensions.origins` into guards plus a default
   `ChioScope` derived from `tool_access`:

   | Guard | HushSpec trigger |
   |---|---|
   | `ForbiddenPathGuard` | `rules.forbidden_paths` |
   | `VelocityGuard` | `rules.velocity` (invocation / spend caps) |
   | `AgentVelocityGuard` | `rules.velocity` (agent / session caps) or `extensions.origins.profiles[].budgets.tool_calls` |
   | `ShellCommandGuard` | `rules.shell_commands` |
   | `EgressAllowlistGuard` + `InternalNetworkGuard` | `rules.egress` (allowlist plus an SSRF / RFC1918 companion) |
   | `McpToolGuard` | `rules.tool_access` |
   | `SecretLeakGuard` + post-invocation `SanitizerHook` | `rules.secret_patterns` (write-path guard, read-path redaction) |
   | `PatchIntegrityGuard` | `rules.patch_integrity` |
   | `PathAllowlistGuard` | `rules.path_allowlist` |
   | `ComputerUseGuard` | `rules.computer_use` |
   | `RemoteDesktopSideChannelGuard` | `rules.remote_desktop_channels` |
   | `InputInjectionCapabilityGuard` | `rules.input_injection` |
   | `BrowserAutomationGuard` | `rules.browser_automation` |
   | `CodeExecutionGuard` | `rules.code_execution` |
   | `PromptInjectionGuard` | `extensions.detection.prompt_injection` |
   | `JailbreakGuard` | `extensions.detection.jailbreak` |
   | `EmbeddingAnomalyGuard` | `extensions.detection.threat_intel` |

   A HushSpec construct a guard or the `ChioScope` model cannot faithfully
   represent (for example workload-identity gating, or selective confirmation
   under a wildcard scope) compiles to an empty or minimal grant rather than
   silently widening access.
6. **Optional wrappers.** `evaluate_audited` wraps step 4 with elapsed-time
   measurement and a SHA-256 hash of the policy's canonical JSON into a
   `DecisionReceipt`. `detection::evaluate_with_detection` wraps step 4 with
   regex content-detector scoring; a detector deny can override an
   allow/warn but never weakens an existing policy deny.

## Invariants and failure modes

- Unsupported `hushspec` version, invalid regex, duplicate secret-pattern
  names, malformed posture graphs, and malformed reputation / runtime-
  assurance blocks are validation errors, not warnings.
- All user-supplied and generated-glob regex route through `regex_safety`:
  capped at 512 characters and a complexity score of 96, built with bounded
  size/DFA limits, and cached process-wide (capped at 4,096 keys, cleared on
  overflow).
- `evaluate`'s default arm for an unrecognized `action_type` denies
  fail-closed rather than allowing an unmodeled action through.
- `compile_policy` refuses to emit a pipeline for an invalid policy
  (`CompileError::Invalid`) rather than compiling a partial one.
- Workload-identity path-prefix matching is segment-bounded: `/payments`
  does not match a sibling path such as `/payments-v2/worker`
  (`evaluate::workload_identity_path_matches_prefix`). `chio-core` owns
  SPIFFE identity parsing; this crate only matches against it.
- `CryptoFloor::AllowHybrid` / `PqRequired` and
  `WeightsCardRequired::RequiredWithPin` reject at load time
  (`validate_with_pq_key`, `WeightsCardConfig::validate`) when their
  required key or regex is not provisioned, before any signing or bind call.
- Panic mode is a process-global `AtomicBool`; every `evaluate` and
  `evaluate_with_context` call checks it before origin or posture
  resolution.
- `resolve_with_loader`'s composite loader rejects `https://` / `http://`
  extends targets (`ResolveError::Http`); only filesystem-backed loaders are
  wired in this crate.

## Dependencies

Internal: `chio-core` supplies the capability-scope, runtime-attestation,
workload-identity, and trust-policy types the schema and evaluator reference;
`chio-guards` supplies `GuardPipeline`, `PostInvocationPipeline`, and every
concrete guard type the compiler emits; `chio-kernel` supplies
`MemoryBudgetConfig` and the `Guard` trait bound used by the pipeline
builder. External: `serde_yml` for YAML (de)serialization, `regex` for
pattern compilation, `sha2` for policy/receipt hashing, `uuid` for receipt
IDs, `chrono` / `chrono-tz` for time-window conditions and receipt
timestamps, `thiserror` for error types.

## Extension points

- `detection::Detector` - implement to register a custom content scanner
  with `DetectorRegistry` alongside the built-in prompt-injection / jailbreak
  / exfiltration detectors.
- `resolve::resolve_with_loader` - supply a custom
  `Fn(&str, Option<&str>) -> Result<LoadedSpec, ResolveError>` loader instead
  of the filesystem-only `create_composite_loader`.
