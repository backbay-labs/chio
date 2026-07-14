# chio-policy

`chio-policy` is Chio's native HushSpec policy engine: it parses, validates,
merges, evaluates, and compiles the HushSpec YAML policy format that governs
AI-agent tool access, egress, filesystem, shell, and computer-use actions.

Invalid HushSpec documents reject at validation and compile time rather than
silently compiling to a permissive default. The crate is a pure translator:
it does not sign receipts, verify capabilities, or hold kernel state; those
belong to `chio-kernel`.

## Responsibilities

- Define the versioned HushSpec YAML schema (`models`): 14 rule blocks, 5
  extension blocks (posture, origins, detection, reputation, runtime
  assurance, plus a Chio-specific passthrough slot), and governance metadata.
- Parse HushSpec YAML with pre-checks that reject pathological input (a
  non-mapping document root, unterminated double-quoted scalars, scalar-join
  whitespace-run overflow) before handing off to `serde_yml`.
- Validate a parsed policy (`validate`): regex safety, workload-identity
  match shape, posture state/transition graphs, detection thresholds,
  reputation tiers, and runtime-assurance tier/verifier bindings.
- Resolve and merge `extends` inheritance chains, from the filesystem or a
  caller-supplied loader, with cycle detection (`resolve`, `merge`).
- Evaluate an action against a policy to an allow/warn/deny `Decision`
  (`evaluate`, `evaluate_with_context`), including origin-profile selection,
  posture transitions, and `when`-style conditional rule activation.
- Compile a validated policy into a `chio_guards` `GuardPipeline`, a
  `PostInvocationPipeline`, and a default `chio_core` capability scope
  (`compiler::compile_policy`).
- Produce timed, hashed audit receipts of evaluation decisions (`receipt`),
  and hold the kernel-wide `crypto_floor` and `weights_card_required`
  fail-closed enforcement enums.
- Ship seven built-in rulesets (`default`, `strict`, `permissive`,
  `ai-agent`, `cicd`, `remote-desktop`, `panic`) embedded at compile time as
  `chio:<name>` extends targets (`rulesets`).

## Public API

- `HushSpec::parse`, `HushSpec::to_yaml`, `OriginMatch` - the policy document
  and origin-match schema; the full schema tree (`Rules`, `Extensions`, every
  rule/extension block) lives in `models`.
- `validate`, `ValidationResult`, `ValidationError` - schema/semantic
  validation.
- `merge`, `resolve_from_path`, `resolve_with_loader`, `LoadedSpec`,
  `ResolveError` - `extends` inheritance and chain resolution.
- `evaluate`, `evaluate_with_context`, `Decision`, `EvaluationAction`,
  `EvaluationResult`, `OriginContext`, `PostureContext`, `PostureResult`,
  `selected_origin_profile_id` - action evaluation.
- `activate_panic`, `deactivate_panic`, `is_panic_active` - process-wide
  emergency deny-all switch consulted by every `evaluate` call.
- `Condition`, `RuntimeContext`, `evaluate_condition` - conditional rule-block
  activation (`conditions`).
- `compile_policy`, `compile_policy_with_source`,
  `compile_policy_with_memory_budget`, `CompiledPolicy`, `CompileError` - the
  HushSpec-to-guard-pipeline compiler.
- `evaluate_audited`, `AuditConfig`, `DecisionReceipt` - timed, hashed
  evaluation receipts.
- `builtin_yaml`, `load_builtin`, `list_builtin_names`, `BUILTIN_RULESETS`,
  `RulesetError` - the embedded rulesets.
- `CryptoFloor`, `CryptoFloorLoadError`, `WeightsCardConfig`,
  `WeightsCardRequired`, `WeightsCardLoadError`, `HUSHSPEC_VERSION` -
  kernel-wide policy enums.
- `is_hushspec_format` - sniff whether a YAML string is a HushSpec document.

Reached via their own module, not re-exported at the crate root:
`detection::{Detector, DetectorRegistry, evaluate_with_detection}` (regex
content scanners, independent of the `extensions.detection`-driven guards).

## Usage

```rust
use chio_policy::{compile_policy, evaluate, validate, Decision, EvaluationAction, HushSpec};

let spec = HushSpec::parse(yaml_source)?;
assert!(validate(&spec).is_valid());

let result = evaluate(&spec, &EvaluationAction {
    action_type: "tool_call".to_string(),
    target: Some("mail.send".to_string()),
    ..EvaluationAction::default()
});
assert_eq!(result.decision, Decision::Allow);

// Or compile directly into a Chio guard pipeline and default capability scope:
let compiled = compile_policy(&spec)?;
```

## Testing

`cargo test -p chio-policy`

Mutation coverage runs against a focused module set:
`cargo mutants --config crates/guards/chio-policy/mutants.toml --package chio-policy`.

## See also

- `chio-guards` - supplies `GuardPipeline`, `PostInvocationPipeline`, and
  every guard type the compiler emits.
- `chio-kernel` - supplies `MemoryBudgetConfig` and the `Guard` trait the
  compiler targets.
- `chio-core` - capability-scope, runtime-attestation, workload-identity, and
  trust-policy types referenced by the schema and evaluator.
