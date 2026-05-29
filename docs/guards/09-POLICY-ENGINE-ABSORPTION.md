# Policy Engine Capability and Porting Plan

Chio is becoming the universal security kernel. A universal kernel needs a
policy engine that compiles declarative YAML into the guard pipeline. Today
that engine lives in the upstream guard suite. This document specifies the plan to absorb
it into Chio.

---

## 1. What the Upstream Policy Engine Does

The HushSpec policy engine is a full YAML-to-guard-instance compiler. It
takes a declarative policy document, validates it, resolves inheritance, and
produces a set of instantiated guard objects. The pipeline has five stages.

### 1.1 Schema format

Upstream policies use a native YAML schema (distinct from but
interoperable with HushSpec). The top-level `Policy` struct
(the upstream policy module) contains:

```rust
pub struct Policy {
    pub version: String,         // schema version, e.g. "1.5.0"
    pub name: String,
    pub description: String,
    pub extends: Option<String>, // base policy reference
    pub merge_strategy: MergeStrategy,
    pub guards: GuardConfigs,    // per-guard configuration blocks
    pub custom_guards: Vec<PolicyCustomGuardSpec>,
    pub settings: PolicySettings,
    pub posture: Option<PostureConfig>,
    pub origins: Option<OriginsConfig>,
    pub broker: Option<BrokerConfig>,
}
```

The `guards` field is a flat struct of `Option<T>` for each guard type:
`forbidden_path`, `path_allowlist`, `egress_allowlist`, `secret_leak`,
`patch_integrity`, `shell_command`, `mcp_tool`, `prompt_injection`,
`jailbreak`, `computer_use`, `remote_desktop_side_channel`,
`input_injection_capability`, plus feature-gated `spider_sense` and a
`custom` vec for plugin guards.

### 1.2 Validation

`Policy::validate()` performs field-level validation with accumulated errors:

- Schema version check against `POLICY_SUPPORTED_SCHEMA_VERSIONS`
- Feature gating: posture requires >= 1.2.0, origins >= 1.4.0, broker >= 1.5.0
- Glob pattern compilation via `glob::Pattern::new()` and `GlobBuilder`
- Regex compilation for secret patterns, shell command patterns, patch patterns
- Placeholder syntax validation (`${VAR}` references)
- Cross-field consistency: origin profiles referencing undefined posture states,
  prompt injection `warn_at_or_above` <= `block_at_or_above`, etc.
- Custom guard config structure checks (JSON object type, duplicate IDs)
- Posture state machine validation (initial state exists, transitions reference
  defined states, timeout transitions require `after` field)

Validation is fail-closed: any error rejects the entire policy.

### 1.3 Compilation pipeline

```
YAML string
  -> from_yaml_unvalidated()    [serde_yaml::from_str]
  -> validate()                 [field-level checks, glob/regex compilation]
  -> resolve_base() / extends   [inheritance resolution]
  -> merge()                    [strategy-aware merging]
  -> create_guards()            [GuardConfigs -> PolicyGuards struct]
```

The `create_guards()` method maps each `Option<Config>` to its
corresponding guard instance:

```rust
pub(crate) fn create_guards(&self) -> PolicyGuards {
    PolicyGuards {
        forbidden_path: self.guards.forbidden_path.clone()
            .map(ForbiddenPathGuard::with_config)
            .unwrap_or_default(),
        egress_allowlist: self.guards.egress_allowlist.clone()
            .map(EgressAllowlistGuard::with_config)
            .unwrap_or_default(),
        // ... 12 guard types total
    }
}
```

The upstream suite also supports async guard compilation via
`build_async_guards()` and custom guard compilation via
`CustomGuardRegistry`.

### 1.4 Inheritance model

The `extends` field references a base policy by name or path. Resolution
supports:

- **Built-in rulesets** (e.g., `extends: default`, `extends: strict`)
- **Local filesystem paths** (relative to the referencing file)
- **Git repository references** (`PolicyLocation::Git`)
- **Package references** (`PolicyLocation::Package`)
- **Cycle detection** via canonical key tracking

The `PolicyResolver` trait abstracts resolution:

```rust
pub trait PolicyResolver {
    fn resolve(&self, reference: &str, from: &PolicyLocation)
        -> Result<ResolvedPolicySource>;
}
```

`LocalPolicyResolver` is the default, resolving built-in rulesets and
filesystem paths.

### 1.5 Merge strategies

Three strategies controlled by `merge_strategy`:

| Strategy | Behavior |
|----------|----------|
| `Replace` | Child replaces base entirely |
| `Merge` | Shallow: child values override base at top level |
| `DeepMerge` | Deep: recursive merge of nested structures (default) |

Deep merge has specialized logic per guard type. For example:
- `forbidden_path` supports `additional_patterns` and `remove_patterns`
  for additive/subtractive inheritance
- `egress_allowlist` supports `additional_allow`, `remove_allow`,
  `additional_block`, `remove_block`
- `prompt_injection` and `jailbreak` track `present_fields` so partial
  overlays only overwrite explicitly-set keys
- `origins.profiles` merges by profile `id` (child replaces matching IDs,
  appends new ones)
- `settings.verification` merges monotonically (child can only strengthen)

### 1.6 HushSpec compiler

The upstream suite includes a bidirectional HushSpec compiler
(`hushspec_compiler.rs`):

- `compile()` / `compile_hushspec()`: HushSpec -> upstream Policy
- `decompile()`: the upstream suite Policy -> HushSpec

The compiler maps HushSpec rule types to upstream guard configs, handles
HushSpec extensions (posture, origins, detection), and converts
HushSpec-prefixed extends references (`hushspec:X` -> `X`).

`is_hushspec()` detects the format by checking for a `hushspec:` top-level
key. `from_yaml_auto()` uses this for transparent format detection.

### 1.7 Built-in rulesets

The upstream suite ships 11 built-in rulesets via `include_str!()`:

| Ruleset | Purpose |
|---------|---------|
| `default` | Balanced security for AI agent execution |
| `strict` | Maximum security, minimal permissions, fail-fast |
| `permissive` | Relaxed rules for development environments |
| `ai-agent` | Optimized for AI coding assistants |
| `ai-agent-posture` | AI agent with posture state machine |
| `cicd` | CI/CD pipeline security |
| `remote-desktop` | Baseline remote desktop controls |
| `remote-desktop-strict` | Strict remote desktop lockdown |
| `remote-desktop-permissive` | Relaxed remote desktop |
| `spider-sense` | Threat intelligence patterns (full feature only) |
| `origin-enclaves-example` | Example origin-aware policy |

Each ruleset is a validated YAML file in `rulesets/`. The `RuleSet` struct
provides `by_name()`, `yaml_by_name()`, and `list()` for enumeration.

### 1.8 Signed policy bundles

`PolicyBundle` wraps a compiled `Policy` with:
- `bundle_id` (UUID)
- `compiled_at` (ISO-8601)
- `policy_hash` (SHA-256 of canonicalized policy JSON)
- `sources` (provenance: which files contributed)

`SignedPolicyBundle` adds Ed25519 signing and verification. This enables
tamper-evident policy distribution.

---

## 2. What Chio's chio-policy Already Has

### 2.1 Complete HushSpec schema

`chio-policy/src/models.rs` defines the full HushSpec schema as native Rust
types. It covers all 10 rule types (forbidden_paths, path_allowlist, egress,
secret_patterns, patch_integrity, shell_commands, tool_access, computer_use,
remote_desktop_channels, input_injection) and all extension modules (posture,
origins, detection, reputation, runtime_assurance).

Chio's schema is a superset of the upstream HushSpec support -- it includes
`reputation` and `runtime_assurance` extensions, plus `WorkloadIdentityMatch`
on tool_access rules, plus `GovernanceMetadata`.

### 2.2 Validation

`chio-policy/src/validate.rs` validates the full HushSpec schema:
- Version checks against `HUSHSPEC_SUPPORTED_VERSIONS`
- Regex compilation for secret patterns, shell commands, patch integrity
- Posture state machine consistency
- Detection threshold ordering
- Reputation tier ranges and scoring weights
- Runtime assurance tier uniqueness and verifier binding validation

### 2.3 Merge/inheritance

`chio-policy/src/merge.rs` implements deep merge for HushSpec documents:
- Rule-level merge (child rules override base per slot)
- Extension deep merge (posture states merge by name, origins profiles merge
  by ID, detection fields merge per-field with Option fallback, reputation
  tiers and scoring weights merge individually)
- `Replace`, `Merge`, `DeepMerge` strategies

`chio-policy/src/resolve.rs` resolves `extends` chains:
- Filesystem-based resolution with relative path support
- Cycle detection via stack tracking
- `create_composite_loader()` for extensible loading

### 2.4 Conditions

`chio-policy/src/conditions.rs` provides conditional rule activation:
- `Condition` type with `time_window`, `context`, `all_of`, `any_of`, `not`
- `RuntimeContext` with user, environment, deployment, agent, session, request,
  custom fields
- Fail-closed evaluation, depth-limited nesting (max 8)

### 2.5 Detection

`chio-policy/src/detection.rs` provides regex-based content detectors for
prompt injection, jailbreak, and secret patterns.

### 2.6 Evaluation

`chio-policy/src/evaluate.rs` evaluates a HushSpec policy against an action,
producing `Allow`, `Warn`, or `Deny` decisions. It handles posture-aware
evaluation, origin profile selection, and produces `EvaluationResult` with
matched rules and reasons.

### 2.7 Receipts

`chio-policy/src/receipt.rs` wraps evaluation in auditable receipts with
timing, hashing, and decision metadata.

### 2.8 Compiler bridge

`chio-policy/src/compiler.rs` compiles HushSpec policies into Chio guard
pipelines:

```rust
pub fn compile_policy(policy: &HushSpec) -> Result<CompiledPolicy, CompileError> {
    let guards = compile_guards(policy)?;
    let default_scope = compile_scope(policy);
    Ok(CompiledPolicy { guards, default_scope })
}
```

This maps 7 rule types to Chio guard instances:
- `forbidden_paths` -> `ForbiddenPathGuard`
- `shell_commands` -> `ShellCommandGuard`
- `egress` -> `EgressAllowlistGuard`
- `tool_access` -> `McpToolGuard`
- `secret_patterns` -> `SecretLeakGuard`
- `patch_integrity` -> `PatchIntegrityGuard`
- `path_allowlist` -> `PathAllowlistGuard`

It also derives an `ChioScope` from tool_access rules.

---

## 3. Gap Analysis

| Capability | Upstream | Chio (chio-policy) | Gap |
|-----------|-------------|------------------|-----|
| Schema format | Native YAML with versioned schema | HushSpec YAML (0.1.0) | Chio lacks a native policy format with schema versioning |
| Schema versioning | 1.1.0 - 1.5.0 with feature gating | 0.1.0 only | Chio needs versioned schema evolution |
| Guard compilation | 12 guard types + async + custom | 7 guard types, sync only | Missing: prompt_injection, jailbreak, computer_use, remote_desktop, input_injection |
| Custom guards | `PolicyCustomGuardSpec` + `CustomGuardRegistry` | None | No policy-driven custom guard instantiation |
| Built-in rulesets | 11 rulesets via `include_str!()` | None | No built-in rulesets |
| Signed bundles | `SignedPolicyBundle` with Ed25519 | None | No tamper-evident policy distribution |
| Policy resolver | `PolicyResolver` trait with filesystem + builtin | Filesystem + cycle detection | Missing: builtin rulesets, git/package locations |
| Merge strategy | Deep merge with `additional_*`/`remove_*` modifiers | Deep merge, no additive/subtractive modifiers | Merge is simpler; lacks overlay operators |
| Async guards | `AsyncGuardRuntime` + policy-driven config | None | Async guard support deferred for Chio |
| HushSpec interop | Bidirectional compiler (compile + decompile) | One-way (compile only) | Decompile not needed for Chio |
| Validation depth | Glob, regex, placeholder, cross-field, version gating | Regex, posture, detection, reputation | Missing: glob validation, placeholder support |
| Settings | fail_fast, verbose_logging, session_timeout, verification | None | No policy-level kernel settings |
| Posture program | `PostureProgram` compiled from config | Posture in schema and eval, not compiled | No compiled state machine for the kernel |
| Origin runtime | `OriginRuntimeState`, budget counters, bridge checks | Origin matching in evaluation | No runtime state tracking |
| Broker policy | `BrokerConfig` for provider-mediated egress | None | Not needed for Chio v1 |

### Critical gaps for universal kernel

1. **Guard compilation coverage**: Chio compiles 7 of 12 guard types. The
   missing 5 (prompt_injection, jailbreak, computer_use, remote_desktop,
   input_injection) are defined in the schema but not compiled to guards.

2. **Built-in rulesets**: operators should be able to write
   `extends: chio:strict` without shipping YAML files.

3. **Schema versioning**: Chio needs its own versioned schema so policies
   can be forward-compatible and feature-gated.

4. **WASM guard declaration in policy**: the policy format has no way to
   declare WASM guards. An operator must configure them separately in
   `chio.yaml`.

5. **Signed policy bundles**: for production deployments, policies must be
   integrity-verifiable.

---

## 4. Unification Plan

### 4.1 Strategy: absorb, don't wrap

The HushSpec policy engine was built for the upstream async guard trait.
Chio has its own synchronous `Guard` trait and its own guard implementations.
Wrapping the upstream suite as a dependency would drag in async runtime,
upstream-specific guard types, and an incompatible guard interface.

Instead: **absorb the design patterns into chio-policy** while keeping Chio's
type system.

### 4.2 What moves into chio-policy

| Feature | Source | Target | Adaptation |
|---------|--------|--------|------------|
| Guard compilation (full) | `policy.create_guards()` | `compiler::compile_policy()` | Add 5 missing guard types to existing compiler |
| Built-in rulesets | `RuleSet`, `rulesets/` | `chio-policy/rulesets/` + `Ruleset` enum | Port YAML files; adapt to HushSpec format |
| Schema versioning | `POLICY_SCHEMA_VERSION` | `version.rs` | Chio uses its own version track |
| Policy resolver (builtins) | `PolicyResolver` trait | `resolve.rs` | Extend existing resolver with builtin support |
| Merge modifiers | `additional_*`/`remove_*` | `merge.rs` | Add additive/subtractive operators to HushSpec merge |
| PolicySettings | `PolicySettings` | New `settings` module | Map settings to kernel config |
| Signed bundles | `PolicyBundle`, `SignedPolicyBundle` | New `bundle` module | Use Chio's existing signing primitives |
| Custom guard specs | `PolicyCustomGuardSpec` | New `custom_guards` field on `HushSpec` | Bridge to WASM guard loading |
| Load-time verification | `install_policy_load_verifier()` | Hook on kernel load | Policy integrity check at startup |

### 4.3 What stays in the upstream guard suite

- the upstream native YAML schema (non-HushSpec)
- the upstream async guard trait and runtime
- `HushEngine` (the upstream enforcement engine)
- upstream-specific guards (Spider Sense threat intel, output sanitizer)
- Bidirectional HushSpec compiler (only needed inside the upstream suite)
- Broker policy (not applicable to Chio's model)

### 4.4 Phased implementation

**Phase 1: Complete guard compilation**

Extend `chio-policy/src/compiler.rs` to compile all guard types that
`chio-guards` implements. This requires adding guards that Chio already has
Rust implementations for but does not compile from policy:

```rust
// In compile_guards(), add:
// computer_use -> ComputerUseGuard (if chio-guards has it)
// remote_desktop_channels -> RemoteDesktopSideChannelGuard
// input_injection -> InputInjectionCapabilityGuard
// detection.prompt_injection -> PromptInjectionGuard
// detection.jailbreak -> JailbreakGuard
```

For guards that Chio does not yet have native implementations of, the
compiler should emit a warning and skip (fail-open for missing guard
implementations, fail-closed for misconfigured existing guards).

**Phase 2: Built-in rulesets**

Port the upstream suite rulesets to HushSpec format and embed them:

```rust
// chio-policy/src/rulesets.rs
pub enum BuiltinRuleset {
    Default,
    Strict,
    Permissive,
    AiAgent,
    AiAgentPosture,
    Cicd,
}

impl BuiltinRuleset {
    pub fn yaml(&self) -> &'static str {
        match self {
            Self::Default => include_str!("../rulesets/default.yaml"),
            // ...
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        let id = name.strip_prefix("chio:").unwrap_or(name);
        match id {
            "default" => Some(Self::Default),
            // ...
        }
    }
}
```

Update `resolve.rs` to check builtins before filesystem:

```rust
pub fn create_composite_loader() -> impl Fn(&str, Option<&str>)
    -> Result<LoadedSpec, ResolveError>
{
    move |reference, from| {
        // Try built-in rulesets first
        if let Some(ruleset) = BuiltinRuleset::from_name(reference) {
            let spec = HushSpec::parse(ruleset.yaml())
                .map_err(|e| ResolveError::Parse { ... })?;
            return Ok(LoadedSpec {
                source: format!("builtin:{reference}"),
                spec,
            });
        }
        // Fall through to filesystem
        load_from_filesystem(reference, from)
    }
}
```

**Phase 3: Schema versioning**

Chio's HushSpec schema starts at `0.1.0`. As features are absorbed, the
version increments:

| Version | Added |
|---------|-------|
| 0.1.0 | Current: 10 rule types, posture, origins, detection |
| 0.2.0 | Custom guards, policy settings |
| 0.3.0 | Reputation, runtime assurance (already in schema, needs compiler) |
| 1.0.0 | Stable schema, signed bundles, full guard compilation |

Version checks in `validate.rs` gate features:

```rust
pub const HUSHSPEC_SUPPORTED_VERSIONS: &[&str] = &["0.1.0", "0.2.0"];

pub fn version_supports_custom_guards(version: &str) -> bool {
    semver_at_least(version, (0, 2, 0))
}
```

**Phase 4: WASM guard declaration (Section 5)**

**Phase 5: Signed bundles**

Port `PolicyBundle` and `SignedPolicyBundle`, using Chio's existing
`chio-core` signing primitives instead of `hush-core`:

```rust
pub struct PolicyBundle {
    pub version: String,
    pub bundle_id: String,
    pub compiled_at: String,
    pub policy: HushSpec,
    pub policy_hash: chio_core::Hash,
    pub sources: Vec<String>,
}

pub struct SignedPolicyBundle {
    pub bundle: PolicyBundle,
    pub signature: chio_core::Signature,
    pub public_key: Option<chio_core::PublicKey>,
}
```

---

## 5. WASM Guards in the Policy Format

Today WASM guards are configured in `chio.yaml` via `WasmGuardEntry` and are
completely separate from the HushSpec policy. For the universal kernel, the
policy format must be the single configuration surface.

### 5.1 Schema addition

Add a `custom_guards` section to HushSpec (gated behind version 0.2.0):

```yaml
hushspec: "0.2.0"
name: acme-production

extends: chio:ai-agent

rules:
  # ... standard rules ...

custom_guards:
  - id: pii-scanner
    type: wasm
    path: ./guards/pii-scanner.wasm
    fuel_limit: 5000000
    priority: 50
    advisory: false
    config:
      region: us-east-1
      redact_patterns: ["ssn", "credit_card"]

  - id: compliance-checker
    type: wasm
    path: ./guards/compliance.wasm
    fuel_limit: 10000000
    priority: 100
    config:
      framework: hipaa

  - id: velocity-limiter
    type: builtin
    config:
      max_calls_per_minute: 60
      max_calls_per_hour: 500
```

### 5.2 Rust types

```rust
/// A custom guard declared in policy.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomGuardSpec {
    /// Unique identifier for this guard instance.
    pub id: String,
    /// Guard type: "wasm" or "builtin".
    #[serde(default = "default_wasm")]
    pub guard_type: CustomGuardType,
    /// Path to .wasm binary (for wasm type).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Fuel limit for WASM execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fuel_limit: Option<u64>,
    /// Evaluation priority (lower = earlier).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
    /// If true, this guard produces advisory signals, not hard denials.
    #[serde(default)]
    pub advisory: bool,
    /// Enable/disable flag.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Guard-specific configuration.
    #[serde(default)]
    pub config: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustomGuardType {
    Wasm,
    Builtin,
}
```

### 5.3 Compilation

The compiler emits `CustomGuardSpec` entries alongside the `GuardPipeline`.
The kernel startup code is responsible for loading the WASM binaries and
registering them. The compiler does not instantiate WASM guards -- it
validates the spec and passes it through:

```rust
pub struct CompiledPolicy {
    pub guards: GuardPipeline,
    pub default_scope: ChioScope,
    pub custom_guards: Vec<CustomGuardSpec>,  // new
    pub settings: Option<PolicySettings>,     // new
}
```

### 5.4 Pipeline ordering

The compiled output defines ordering via priority:

1. HushSpec-compiled native guards (always first, in canonical order)
2. Custom guards sorted by `priority` (ascending)
3. Advisory guards last (custom guards with `advisory: true`)

This matches the ordering specified in `04-HUSHSPEC-POLICY-INTEGRATION.md`
Section 1.

---

## 6. Built-in Ruleset Strategy

### 6.1 Which rulesets to port

| Upstream ruleset | Port to Chio? | Rationale |
|---------------------|-------------|-----------|
| `default` | Yes | Universal baseline; every deployment needs a starting point |
| `strict` | Yes | High-security baseline for production |
| `permissive` | Yes | Development and testing |
| `ai-agent` | Yes | Primary use case for Chio |
| `ai-agent-posture` | Yes | Demonstrates posture state machine |
| `cicd` | Yes | Common deployment context |
| `remote-desktop` | No | upstream-specific use case, not relevant to Chio's agent model |
| `remote-desktop-strict` | No | Same |
| `remote-desktop-permissive` | No | Same |
| `spider-sense` | No | Depends on the upstream threat-intel infrastructure |
| `origin-enclaves-example` | Yes | Demonstrates origin-aware policy |

### 6.2 Adaptation required

Upstream rulesets use the upstream native YAML format. Chio rulesets must
use HushSpec format. The translation is mechanical:

Upstream native:
```yaml
version: "1.1.0"
guards:
  forbidden_path:
    patterns: [...]
  egress_allowlist:
    allow: [...]
```

Chio HushSpec:
```yaml
hushspec: "0.1.0"
rules:
  forbidden_paths:
    patterns: [...]
  egress:
    allow: [...]
```

Key differences:
- Top-level `version` -> `hushspec`
- `guards.*` -> `rules.*` (with name changes: `egress_allowlist` -> `egress`,
  `mcp_tool` -> `tool_access`, `forbidden_path` -> `forbidden_paths`)
- the upstream `settings` section has no HushSpec equivalent (will be added
  in version 0.2.0)
- Detection guards (prompt_injection, jailbreak) move under
  `extensions.detection`

### 6.3 Namespace

Built-in rulesets are referenced with an `chio:` prefix:

```yaml
extends: chio:ai-agent
```

The prefix is optional (bare names check builtins first). The `chio:` prefix
is for clarity when mixing with filesystem paths.

---

## 7. Universal Kernel: One YAML, All Surfaces

### 7.1 The vision

A single HushSpec policy configures guards across all Chio integration
surfaces:

```
HushSpec YAML
  |
  v
chio-policy compiler
  |
  +--> GuardPipeline (native guards)
  |      |
  |      +--> chio-kernel (direct tool calls)
  |      +--> chio-mcp-edge (MCP protocol)
  |      +--> chio-a2a-edge (A2A protocol)
  |      +--> future OpenAI adapter (deferred, not shipped)
  |      +--> chio-api-protect (HTTP proxy)
  |
  +--> CustomGuardSpec[] (WASM guards)
  |      |
  |      +--> chio-wasm-guards runtime
  |
  +--> ChioScope (default capability scope)
  |
  +--> PolicySettings (kernel configuration)
```

Today each edge crate constructs its own kernel with independently
configured guards. With policy absorption, each edge instead:

1. Loads the HushSpec policy (from file, bundle, or inline)
2. Resolves `extends` chains (including built-in rulesets)
3. Calls `compile_policy()` to get `CompiledPolicy`
4. Registers `guards` on the kernel
5. Loads WASM binaries from `custom_guards`
6. Applies `settings` to kernel configuration

### 7.2 Integration surface adaptation

Different surfaces may need different policy views. The policy format
supports this via `when` conditions:

```yaml
hushspec: "0.2.0"
rules:
  egress:
    when:
      context:
        surface: mcp
    allow: ["*.internal.example.com"]
    default: block

  tool_access:
    when:
      context:
        surface: a2a
    allow: ["search", "summarize"]
    default: block
```

The edge crate populates `RuntimeContext.request.surface` with its protocol
identifier. Conditional rule activation (already implemented in
`conditions.rs`) handles the rest.

### 7.3 Cross-protocol guard sharing

A guard registered on the kernel evaluates identically regardless of which
edge delivered the request. This is by design: the kernel does not know or
care about the transport protocol. Guards see a `GuardContext` with tool
name, arguments, agent identity, and scopes. The edge crate is responsible
for translating protocol-specific requests into `GuardContext`.

---

## 8. Schema Evolution

### 8.1 Upstream schema lineage

The upstream native schema versions:

| Version | Features added |
|---------|---------------|
| 1.1.0 | Baseline: forbidden_path, egress, secret_leak, patch_integrity, shell_command, mcp_tool, prompt_injection, jailbreak |
| 1.2.0 | path_allowlist, posture extension |
| 1.3.0 | spider_sense (threat intel) |
| 1.4.0 | origins extension |
| 1.5.0 | broker extension, custom guards with async config |

### 8.2 Chio's HushSpec schema lineage

Chio uses HushSpec format, which has its own version track. The current
version is `0.1.0` (pre-stable). Chio's schema already contains features
that the upstream suite added incrementally (posture, origins, detection,
reputation, runtime assurance).

Chio's schema evolution is independent of the upstream suite. The HushSpec
compiler in the upstream guard suite handles the translation. Chio does not need to track
The upstream version numbers.

### 8.3 Forward compatibility contract

```rust
// chio-policy/src/version.rs

pub const HUSHSPEC_VERSION: &str = "0.1.0";
pub const HUSHSPEC_SUPPORTED_VERSIONS: &[&str] = &["0.1.0"];

// After absorption phases:
pub const HUSHSPEC_VERSION: &str = "0.2.0";
pub const HUSHSPEC_SUPPORTED_VERSIONS: &[&str] = &["0.1.0", "0.2.0"];
```

The rules:
1. New fields are always `Option<T>` with `#[serde(default)]`
2. Old versions parse cleanly against new schemas (unknown fields rejected
   by `deny_unknown_fields`)
3. New features require minimum version checks in validation
4. The compiler produces guards only for features present in the document;
   absent features mean "no guard" (not "default guard")

### 8.4 Version bump cadence

Chio increments the HushSpec minor version when adding:
- New rule types to the `rules` block
- New extension modules
- New top-level sections (e.g., `custom_guards`, `settings`)

Patch versions for non-breaking additions within existing sections
(new optional fields on existing types).

Major version (`1.0.0`) when the schema is considered stable and
backward-incompatible changes require migration support.

---

## 9. Architecture and Type Signatures

### 9.1 Compiled policy output

```rust
/// The result of compiling a HushSpec policy into Chio primitives.
pub struct CompiledPolicy {
    /// Native guard pipeline configured from policy rules.
    pub guards: GuardPipeline,
    /// Default capability scope derived from tool_access rules.
    pub default_scope: ChioScope,
    /// WASM and builtin custom guard specifications.
    pub custom_guards: Vec<CustomGuardSpec>,
    /// Policy-level settings for kernel configuration.
    pub settings: Option<PolicySettings>,
    /// Source policy hash for receipt attribution.
    pub policy_hash: Option<[u8; 32]>,
}
```

### 9.2 Policy settings

```rust
/// Kernel-level settings derived from policy.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySettings {
    /// Stop guard evaluation on first denial.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_fast: Option<bool>,
    /// Session timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_timeout_secs: Option<u64>,
    /// Enable verbose guard logging.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verbose_logging: Option<bool>,
}
```

### 9.3 Builtin ruleset type

```rust
/// Built-in rulesets shipped with Chio.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltinRuleset {
    Default,
    Strict,
    Permissive,
    AiAgent,
    AiAgentPosture,
    Cicd,
    OriginEnclavesExample,
}

impl BuiltinRuleset {
    pub fn yaml(&self) -> &'static str { ... }
    pub fn from_name(name: &str) -> Option<Self> { ... }
    pub fn id(&self) -> &'static str { ... }
    pub fn list() -> &'static [&'static str] { ... }
}
```

### 9.4 Extended resolver

```rust
/// Resolve `extends` references against builtins, filesystem, or custom loaders.
pub fn create_composite_loader() -> impl Fn(&str, Option<&str>)
    -> Result<LoadedSpec, ResolveError>
{
    move |reference, from| {
        // 1. Check built-in rulesets
        if let Some(ruleset) = BuiltinRuleset::from_name(reference) {
            let spec = HushSpec::parse(ruleset.yaml())
                .map_err(|e| ResolveError::Parse {
                    path: format!("builtin:{}", ruleset.id()),
                    message: e.to_string(),
                })?;
            return Ok(LoadedSpec {
                source: format!("builtin:{}", ruleset.id()),
                spec,
            });
        }

        // 2. Reject remote references
        if reference.starts_with("https://") || reference.starts_with("http://") {
            return Err(ResolveError::Http {
                message: "HTTP-based policy loading is not supported".into(),
            });
        }

        // 3. Filesystem resolution
        load_from_filesystem(reference, from)
    }
}
```

### 9.5 Kernel integration sketch

```rust
// In chio-kernel startup or edge crate setup:

use chio_policy::{compile_policy, resolve_from_path, validate};

// Load and resolve
let spec = resolve_from_path("./policy.yaml")?;
let validation = validate(&spec);
if !validation.is_valid() {
    return Err(/* fail closed */);
}

// Compile
let compiled = compile_policy(&spec)?;

// Build kernel
let mut kernel = ChioKernel::new(identity);

// Register native guards
for guard in compiled.guards.into_guards() {
    kernel.add_guard(guard);
}

// Load and register WASM guards
let mut wasm_entries: Vec<_> = compiled.custom_guards.iter()
    .filter(|g| g.guard_type == CustomGuardType::Wasm && g.enabled)
    .collect();
wasm_entries.sort_by_key(|e| e.priority.unwrap_or(u32::MAX));
for entry in wasm_entries {
    let path = entry.path.as_deref()
        .ok_or_else(|| /* missing path error */)?;
    wasm_runtime.load_guard(path, entry.fuel_limit, &entry.config)?;
}
for guard in wasm_runtime.into_guards() {
    kernel.add_guard(guard);
}

// Apply settings
if let Some(settings) = compiled.settings {
    kernel.configure_from_policy(&settings);
}
```

---

## 10. Open Questions

1. **Should chio-policy depend on chio-guards?** Currently it does (compiler.rs
   imports guard types). This is acceptable for the compiler module but
   creates a coupling. Alternative: compiler returns configuration structs
   and the kernel performs instantiation. Decision: keep the current coupling
   for simplicity; the guard types are stable.

2. **Merge modifier syntax.** the upstream `additional_*`/`remove_*` fields
   are ergonomic for additive inheritance. Should HushSpec adopt the same
   pattern, or use a different syntax (e.g., `+patterns` / `-patterns`)?
   Decision: adopt the upstream field-name convention for consistency with
   the existing ecosystem.

3. **Policy reload.** The kernel currently loads guards at startup. Hot reload
   of policy (re-compile and swap guards) is a future concern. The
   `CompiledPolicy` return type supports this pattern but the kernel does not
   implement it yet.

4. **Remote policy resolution.** The upstream suite supports `PolicyLocation::Git`
   and `PolicyLocation::Url`. Chio should add these when needed, behind a
   feature flag. Not required for initial absorption.

5. **Detection guard compilation.** Chio has `detection.rs` with regex-based
   detectors but does not have native `PromptInjectionGuard` or
   `JailbreakGuard` implementations in `chio-guards`. These would need to be
   implemented or the detection extension would only work through
   `chio-policy`'s own evaluation path (not the kernel guard pipeline).
   Decision: implement minimal detection guards in `chio-guards` that delegate
   to `chio-policy::detection`.
