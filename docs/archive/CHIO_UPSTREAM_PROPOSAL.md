# Chio Policy: First-Class Velocity, Human-in-Loop, and Extensions

Status: decisive. Plugin-rewrite agents should code against §5 (migration table) today.

## 0. Constraint recap

- `HushSpec` (`arc/crates/arc-policy/src/models.rs:107-123`) and `Rules` (`models.rs:143-164`) are both `#[serde(deny_unknown_fields)]`. `Rules` closed to 10 keys.
- **`Extensions` (`models.rs:329-342`) is ALSO `deny_unknown_fields`**, closed to `posture|origins|detection|reputation|runtime_assurance`. So "drop under `extensions.chio.*`" is not a zero-change path - still needs one new `Extensions.chio` slot.
- Approval machinery exists capability-side: `Constraint::RequireApprovalAbove { threshold_units }` (`arc/crates/arc-kernel-core/src/normalized.rs:73`), enforced at `arc/crates/arc-kernel/src/approval.rs:526`. HushSpec already emits this for `tool_access.require_confirmation` (compiler at `arc/crates/arc-policy/src/compiler.rs:590`). USD threshold is missing.
- `VelocityGuard` (`arc/crates/arc-guards/src/velocity.rs:126-211`) and `AgentVelocityGuard` (`arc/crates/arc-guards/src/agent_velocity.rs:107-169`) exist and are fully-wired `Guard` impls, but are **not** in `GuardPipeline::default_pipeline()` (`arc/crates/arc-guards/src/pipeline.rs:38-48`) and have **no YAML compiler path**. Dead-coded relative to HushSpec today.

## 1. `velocity` - Option A, first-class `Rules.velocity`

**Decision: first-class.** `VelocityGuard`/`AgentVelocityGuard` already implement the exact semantics (invocations/window, spend/window, burst factor, per-agent/per-capability keying). Missing piece is ~30 lines struct + ~40 lines compiler glue. Extensions path means re-inventing `VelocityConfig` in chio-bridge and leaving the in-tree guard unused forever.

Proposed diff (arc-policy only):

```rust
// Rules struct (models.rs:143-164), add:
#[serde(default, skip_serializing_if = "Option::is_none")]
pub velocity: Option<VelocityRule>,

// New struct (after InputInjectionRule, ~line 323):
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VelocityRule {
    #[serde(default = "default_true")] pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub max_invocations_per_window: Option<u32>,
    /// Integer minor units (e.g. cents) matching ToolGrant::max_cost_per_invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")] pub max_spend_per_window: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub max_requests_per_agent: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub max_requests_per_session: Option<u32>,
    #[serde(default = "default_velocity_window_secs")] pub window_secs: u64,   // default 60
    #[serde(default = "default_burst_factor")] pub burst_factor: f64,          // default 1.0
}
```

Compiler wiring (follow-on work, not this PR): `compile_velocity_rule()` in `arc/crates/arc-policy/src/compiler.rs` returns `(Option<VelocityConfig>, Option<AgentVelocityConfig>)` and the `arc-cli` policy bootstrap pushes matching guards onto the pipeline between `ForbiddenPathGuard` and `ShellCommandGuard`. **No edits to `arc-guards` or `arc-kernel`.**

## 2. `human_in_loop` - Option A, first-class `Rules.human_in_loop`

**Decision: first-class.** Approval is already end-to-end in arc (`GovernedApprovalToken`, `ToolCallRequest.approval_token`, `Constraint::RequireApprovalAbove`). Only gap: USD thresholds and expression gates cannot be expressed in YAML. We fix the gap.

```rust
// Rules struct, add:
#[serde(default, skip_serializing_if = "Option::is_none")]
pub human_in_loop: Option<HumanInLoopRule>,

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanInLoopRule {
    #[serde(default = "default_true")] pub enabled: bool,
    /// Tool-name globs that always need approval (compiles to threshold=0).
    #[serde(default)] pub require_confirmation: Vec<String>,
    /// Integer minor units; compiles to Constraint::RequireApprovalAbove { threshold_units }.
    #[serde(default, skip_serializing_if = "Option::is_none")] pub approve_above: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub approve_above_currency: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub timeout_seconds: Option<u64>,
    #[serde(default)] pub on_timeout: HumanInLoopTimeoutAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HumanInLoopTimeoutAction { #[default] Deny, Defer }
```

**Deferred to `extensions.chio.human_in_loop`** (no kernel analog yet): `approve_when: [expr]` (needs an expression evaluator), `approvers: {n, of}` (quorum lives in OpenClaw, not the kernel).

## 3. Domain-specific keys → `extensions.chio.*`

Shape the chio-ext slot on `Extensions`. One arc-policy edit.

```rust
// Extensions struct (models.rs:329-342), add:
#[serde(default, skip_serializing_if = "Option::is_none")]
pub chio: Option<ChioExtension>,

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ChioExtension {
    pub market_hours: Option<ChioMarketHours>,
    pub signing: Option<ChioSigning>,
    pub k8s_namespaces: Option<ChioK8sNamespaces>,
    pub rollback: Option<ChioRollback>,
    pub human_in_loop: Option<ChioHumanInLoopAdvanced>,
}
// All sub-structs deny_unknown_fields:
//   ChioMarketHours   { tz: String, open: String, close: String, days: Vec<String> }
//   ChioSigning       { algo: String, required: bool = true, key_ref: Option<String> }
//   ChioK8sNamespaces { allow: Vec<String>, human_in_loop: Vec<String>, deny: Vec<String> }
//   ChioRollback      { on_guard_fail: bool, on_timeout: bool, strategy: Option<String> }
//   ChioHumanInLoopAdvanced { approve_when: Vec<String>, approvers: Option<ChioApproverSet> }
//   ChioApproverSet   { n: u32, of: Vec<String>, timeout_seconds: Option<u64> }
```

Arc kernel does **not** interpret `extensions.chio`. Semantics enforced by chio-bridge. Policy still loads and arc guards still fire if consumer ignores the block.

## 4. `shell` and `patch` are renames

- **`rules.shell` → `rules.shell_commands`** (existing). Gotcha: `ShellCommandsRule` has only `enabled` + `forbidden_patterns` - no allow-list. Plugin presets using `shell.allow` must invert to `forbidden_patterns` or migrate allow-listing to `tool_access`.
- **`rules.patch` → `rules.patch_integrity`** (existing). `require_integrity: true` collapses to `enabled: true` (the default). `max_files` does not exist; translate to `max_additions`/`max_deletions` or drop.

## 5. YAML migration table

Every plugin policy preset, one row per offending key. (P) = first-class (§1/§2). (X) = `extensions.chio.*` (§3). (R) = rename (§4). (F) = field-level fix to an existing key. (D) = drop.

| File : line | Current | Target | Class |
|---|---|---|---|
| `chio-claude-code-plugin/examples/hedge.policy.yaml:16-19` | `rules.velocity: {budget_usd: 500, max_invocations: 40, window_seconds: 3600}` | `rules.velocity: {max_invocations_per_window: 40, max_spend_per_window: 50000, window_secs: 3600}` | P |
| `chio-claude-code-plugin/examples/hedge.policy.yaml:21-22` | `rules.human_in_loop.approve_above_usd: 150` | `rules.human_in_loop: {approve_above: 15000, approve_above_currency: "USD"}` | P |
| `chio-codex-plugin/examples/migration.policy.yaml:3` | top-level `version: "0.3.0"` | `metadata.policy_version: 3` or drop | D |
| `chio-codex-plugin/examples/migration.policy.yaml:11-14` | `rules.shell_commands.allow: [...]` | `rules.shell_commands: {enabled: true, forbidden_patterns: []}` (move allow-list to `tool_access` if needed) | F |
| `chio-codex-plugin/examples/migration.policy.yaml:21-23` | `rules.human_in_loop.approve_when: [expr]` | `rules.human_in_loop: {enabled: true}` + `extensions.chio.human_in_loop.approve_when: [expr]` | X |
| `chio-codex-plugin/examples/migration.policy.yaml:25-27` | top-level `budget: {usd: 25, ttl: 30m}` | `rules.velocity: {max_spend_per_window: 2500, window_secs: 1800}` | P |
| `chio-open-code-plugin/templates/presets/trader.yaml:4` | `extends: chio://preset/trader` | `extends: "./presets/trader.yaml"` (or resolvable path/URL) | D |
| `chio-open-code-plugin/templates/presets/trader.yaml:6-9` | top-level `capability: {id, ttl, delegatable}` | drop (capabilities are issued via `arc cert` / trust plane) | D |
| `chio-open-code-plugin/templates/presets/trader.yaml:11-13` | top-level `budget: {cap_usd: 500, window: 24h}` | `rules.velocity: {max_spend_per_window: 50000, window_secs: 86400}` | P |
| `chio-open-code-plugin/templates/presets/trader.yaml:18` | `rules.tool_access.deny: ["*"]` | `rules.tool_access: {default: block, block: []}` | F |
| `chio-open-code-plugin/templates/presets/trader.yaml:19-22` | `rules.market_hours: {tz, open, close}` | `extensions.chio.market_hours: {tz, open, close}` | X |
| `chio-open-code-plugin/templates/presets/trader.yaml:23-25` | `rules.signing: {algo, required}` | `extensions.chio.signing: {algo, required}` | X |
| `chio-open-code-plugin/templates/presets/trader.yaml:28-29` | `rules.velocity.max_calls_per_min: 60` | `rules.velocity: {max_invocations_per_window: 60, window_secs: 60}` | P |
| `chio-open-code-plugin/templates/presets/tool-agent.yaml:4,6-13,21,24-25` | same pattern: `extends chio://`, top-level `capability`, `budget`, `tool_access.deny`, `velocity.max_calls_per_min: 30` | analogous fixes; `velocity → rules.velocity {max_invocations_per_window: 30, window_secs: 60}` | mixed |
| `chio-open-code-plugin/templates/presets/research-agent.yaml:4,6-13,21,26-27` | same pattern; `velocity.max_calls_per_min: 10` | analogous; `rules.velocity {max_invocations_per_window: 10, window_secs: 60}` | mixed |
| `chio-open-code-plugin/templates/presets/support-agent.yaml:4,6-13,20,21-23` | same pattern + `rules.human_in_loop: {when: ticket.refund, approve_above_usd: 100}` | `rules.human_in_loop: {approve_above: 10000, approve_above_currency: "USD"}` + `extensions.chio.human_in_loop.approve_when: ["tool == 'ticket.refund'"]` | P + X |
| `chio-open-code-plugin/templates/presets/release-engineer.yaml:4,6-13,18,19-21,22-23` | same pattern + `rules.k8s_namespaces` + `rules.rollback` | `extensions.chio.k8s_namespaces: {allow, human_in_loop, deny}` + `extensions.chio.rollback: {on_guard_fail: true}` | X |
| `chio-open-code-plugin/templates/presets/code-agent.yaml:4,6-13,23-25,26-27,30` | `rules.shell.{allow,deny}`, `rules.patch.require_integrity`, `tool_access.deny: [*]` | `rules.shell_commands: {forbidden_patterns: ["rm -rf *","curl *"]}` (drop `allow`), `rules.patch_integrity: {enabled: true}`, `tool_access.default: block` | R + F |
| `chio-cursor-plugin/templates/.chio/policy.yaml:9-12` | `rules.forbidden_paths.patterns: [...]` | already valid - no change | - |
| `chio-cursor-plugin/templates/.chio/policy.yaml:13-17` | `rules.shell_commands.allow: [...]` | `rules.shell_commands: {enabled: true, forbidden_patterns: []}` | F |
| `chio-cursor-plugin/templates/.chio/policy.yaml:18-19` | `rules.patch_integrity.max_files: 40` | drop, or `max_additions: <N>` / `max_deletions: <N>` | F |
| `chio-cursor-plugin/templates/.chio/policy.yaml:20-21` | `rules.velocity.budget_minutes: 5` | `rules.velocity: {window_secs: 300, max_invocations_per_window: <N>}` (plugin agent chooses N) | P |

Cross-ref with `/tmp/chio-debate/DEBATER_B_RIGORIST.md` §3: every file cited (hedge, migration, trader, tool-agent, research-agent, support-agent, release-engineer, code-agent) appears above. Added `chio-cursor-plugin/templates/.chio/policy.yaml` which B didn't enumerate but which also fails parse.

## 6. Arc-side implementation plan (Option A paths)

One focused PR against arc. Files (all under the repository root):

1. **`crates/arc-policy/src/models.rs`** - add `Rules.velocity`, `Rules.human_in_loop`, `Extensions.chio`; add 2 new default helpers; add 1 enum + 8 structs per §§1-3. All new fields `Option<T>` - no existing policy breaks.
2. **`crates/arc-policy/src/compiler.rs`** - add `compile_velocity_rule()` returning `(Option<VelocityConfig>, Option<AgentVelocityConfig>)` (mechanical map to existing `arc-guards` types). Extend `compile_tool_constraints` (line 584) to emit `Constraint::RequireApprovalAbove { threshold_units: rule.approve_above.unwrap_or(0) }` when `rules.human_in_loop` matches. `extensions.chio` is passthrough (not compiled).
3. **`crates/arc-cli/src/policy.rs`** - when compiled policy has velocity config, push `VelocityGuard`/`AgentVelocityGuard` onto pipeline between `ForbiddenPathGuard` and `ShellCommandGuard`.
4. **Tests (new):** `crates/arc-policy/tests/velocity.rs`, `human_in_loop.rs`, `chio_extension.rs`. Each includes a `deny_unknown_fields` negative.
5. **Tests (update):** `crates/arc-policy/tests/compile_policy.rs` - assert compile output includes `VelocityGuard` + `RequireApprovalAbove` when HushSpec specifies them.
6. **Docs/fixtures:** `examples/policies/canonical-hushspec.yaml` - add commented `# rules.velocity:` and `# rules.human_in_loop:` stanzas (no behavior change).

**Explicitly NOT touched**: `crates/arc-guards/`, `crates/arc-kernel/`, `crates/arc-kernel-core/`, trust-plane. Enforcement is already in place; we're just teaching YAML how to request it.

## 7. Rust diff status

Not landed in this PR. The minimal-safe edit spans 6 files across 2 crates; `models.rs`-only would add fields that silently do nothing (exactly the failure mode Debater B flags). Recommendation: the arc engineer lands the full patch atomic, with `cargo test -p arc-policy` green. Diffs in §§1-3 are copy-paste ready.

**Plugin agents should code against this now.** If arc-side lands with deltas, chio-bridge absorbs them via its schema normalizer. Presets don't re-rev.

## 8. Cheatsheet for plugin-rewrite agents

- `rules.velocity`: first-class. `{max_invocations_per_window, max_spend_per_window, max_requests_per_agent, max_requests_per_session, window_secs, burst_factor, enabled}`. Spend = integer minor units (cents).
- `rules.human_in_loop`: first-class. `{enabled, require_confirmation: [globs], approve_above: u64, approve_above_currency, timeout_seconds, on_timeout: deny|defer}`.
- `market_hours | signing | k8s_namespaces | rollback | approve_when | approvers` → `extensions.chio.*` per §3.
- `rules.shell → rules.shell_commands`; `rules.patch → rules.patch_integrity`. Re-check §4 field gotchas.
- **Always drop**: top-level `capability:`, `budget:`, `version:`, and `extends: chio://preset/*`.
- **Field gotcha**: `tool_access.deny: [...]` does not exist. Use `tool_access.block: [...]` with `default: block|allow`. Catch-all deny = `default: block`.
