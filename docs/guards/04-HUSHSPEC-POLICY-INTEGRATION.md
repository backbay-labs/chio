# WASM Guards: HushSpec and Policy-Engine Integration

This document addresses how WASM guards fit alongside the existing HushSpec
rule format and the upstream policy engine. The prior documents (01-03) designed
the WASM guard runtime in isolation. This addendum ensures the design accounts
for the full policy stack.

---

## The Policy Stack Today

```
  HushSpec YAML          (portable, declarative rules)
       |
       v
  Policy engine          (reference engine: compiles rules to guards)
       |
       v
  chio-guards            (Chio-native Guard trait impls, adapted from the upstream suite)
       |
       v
  ChioKernel.guards       (Vec<Box<dyn Guard>>, evaluated in registration order)
```

A HushSpec document defines declarative rules (forbidden_paths, egress, secret
patterns, tool access, etc.). The policy engine compiles these into its async Guard
trait implementations. The `chio-guards` crate adapts 11+ upstream guards
to Chio's synchronous `Guard` trait. These get registered on the kernel.

WASM guards must slot into this stack without duplicating it.

---

## 1. Where WASM Guards Sit in the Stack

WASM guards are **not a replacement for HushSpec**. They serve different
purposes:

| Concern | HushSpec + the upstream engine | WASM Guards |
|---------|----------------------|-------------|
| Rule format | Declarative YAML | Programmatic (code) |
| Rule authoring | Security teams, operators | Developers, integrators |
| Evaluation model | Stateless pattern matching | Arbitrary computation |
| Distribution | YAML files, `extends` chains | `.wasm` binaries + manifests |
| Use cases | Standard policy (paths, egress, secrets) | Custom logic (org-specific, context-dependent) |
| Language | YAML | Rust, Python, TypeScript, Go (compiled to WASM) |

**HushSpec handles the 80% case** -- the common, well-understood security rules
that every deployment needs. WASM guards handle the **20% tail** -- org-specific
logic, domain-specific checks, rules that require computation (ML models,
external lookups via host functions, stateful pattern matching).

### Pipeline position

WASM guards run in the same `Vec<Box<dyn Guard>>` as everything else. The
recommended registration order:

1. HushSpec-compiled guards (via `chio_policy::compiler::compile_policy()`)
2. WASM guards -- custom programmatic guards
3. `AdvisoryPipeline` -- non-blocking observations (last, since they never deny)

This ordering matters because:
- HushSpec-compiled guards are fast (native Rust, no WASM overhead) and catch
  common violations cheaply
- WASM guards run only on requests that pass the standard checks
- Advisory guards always Allow, so they should run last

> **Correction:** `GuardPipeline::default_pipeline()` creates guards with
> hard-coded default configs, ignoring any HushSpec policy. The real HushSpec
> bridge is `chio_policy::compiler::compile_policy()`, which reads a HushSpec
> document and produces a `GuardPipeline` configured from the policy's rule
> blocks (patterns, allowlists, thresholds, enabled flags, etc.).
>
> **Correction:** `WasmGuardRuntime` does **not** sort by priority despite
> its doc-comment claim. `add_guard` preserves insertion order. Startup code
> must sort `WasmGuardEntry` list by priority before loading.

The startup code should enforce this ordering:

```rust
use chio_policy::compiler::compile_policy;

// 1. HushSpec-compiled guards (respects policy config)
let compiled = compile_policy(&hushspec)?;
kernel.add_guard(Box::new(compiled.guards));

// 2. WASM guards (sorted by priority EXTERNALLY -- runtime does not sort)
let mut entries = config.wasm_guards.clone();
entries.sort_by_key(|e| e.priority);
for entry in &entries {
    wasm_runtime.load_guard(/* ... */)?;
}
for guard in wasm_runtime.into_guards() {
    kernel.add_guard(guard);
}

// 3. Advisory pipeline
kernel.add_guard(Box::new(advisory_pipeline));
```

---

## 2. HushSpec Rule Types vs. WASM Guard Capabilities

HushSpec defines 10 core rule types and 3 extension modules. Here is where
WASM guards complement vs. overlap:

### No overlap needed (HushSpec handles these well)

| HushSpec Rule | Upstream Guard | Chio Guard | WASM needed? |
|---------------|------------------|-----------|-------------|
| `forbidden_paths` | ForbiddenPathGuard | ForbiddenPathGuard | No |
| `path_allowlist` | PathAllowlistGuard | PathAllowlistGuard | No |
| `egress` | EgressAllowlistGuard | EgressAllowlistGuard | No |
| `secret_patterns` | SecretLeakGuard | SecretLeakGuard | No |
| `patch_integrity` | PatchIntegrityGuard | PatchIntegrityGuard | No |
| `shell_commands` | ShellCommandGuard | ShellCommandGuard | No |
| `tool_access` | McpToolGuard | McpToolGuard | No |

These are pattern-matching rules. HushSpec's declarative format is the right
tool. Writing a WASM guard to block `/etc/shadow` would be reinventing
`forbidden_paths`.

### WASM adds value (beyond what HushSpec can express)

**Near-term (v1 -- stateless, sync, pure pre-dispatch):**

| Use case | Why HushSpec can't do it | WASM guard example |
|----------|------------------------|--------------------|
| Semantic argument inspection | HushSpec matches patterns, not meaning | Guard that parses SQL in arguments and blocks DROP/TRUNCATE |
| Org-specific compliance | HushSpec rules are generic | Guard enforcing HIPAA-specific data handling for a healthcare org |
| Complex pattern matching | HushSpec uses glob/regex | Guard with domain-specific parsers (URL normalization, AST checks) |
| Custom secret detection | HushSpec patterns are static regex | Guard with entropy analysis or format-aware secret detection |

**Deferred (requires runtime model changes):**

> The following use cases require capabilities beyond the current v1 model.
> The kernel `Guard` trait is synchronous (`fn evaluate`), each WASM call
> gets a fresh `Store` (no persistent state), and `session_metadata` is
> always `None` in `WasmGuard::build_request`. These are real goals but
> not near-term deliverables.

| Use case | Blocker | What would need to change |
|----------|---------|--------------------------|
| Cross-request correlation | Fresh Store per call, no persistent state | Per-guard context store or host-backed session query |
| External policy lookup (OPA, etc.) | No network host functions, sync trait | Async guard trait or blocking host function with timeout |
| ML-based detection | WASM module size/perf constraints | Benchmark feasibility; may need host-side ML with WASM as glue |
| Dynamic configuration | Config is load-time only | Host function for runtime config reload or config watch |
| Cost/budget policies | No pricing context in GuardRequest | Enrich GuardRequest with budget metadata from kernel |

### Overlap zones (could go either way)

| Concern | HushSpec approach | WASM approach | Recommendation |
|---------|------------------|---------------|----------------|
| Rate limiting | Posture extension (budget transitions) | VelocityGuard / custom WASM | Use built-in VelocityGuard; WASM only for exotic rate-limit logic |
| Prompt injection | Detection extension (regex thresholds) | ML model in WASM | HushSpec for baseline regex; WASM for advanced ML detection |
| Computer use | `computer_use` rules | Programmatic CUA checks | HushSpec for action-type allowlisting; WASM for semantic screen analysis |

---

## 3. HushSpec Detector Trait vs. WASM Guards

HushSpec already has an extensibility point for custom detection:

```rust
pub trait Detector: Send + Sync {
    fn name(&self) -> &str;
    fn category(&self) -> DetectorCategory;
    fn detect(&self, input: &str) -> DetectionResult;
}
```

This is registered via `DetectorRegistry` and used by the Detection extension.
It runs during HushSpec evaluation, not in the Chio kernel guard pipeline.

**Should WASM guards also be usable as HushSpec detectors?**

No. Keep the boundaries clean:
- HushSpec detectors run during HushSpec evaluation (in the upstream guard suite)
- WASM guards run during Chio kernel guard evaluation
- They serve different layers of the stack

However, the **Detection extension thresholds** in HushSpec (prompt injection,
jailbreak, threat intelligence) should be queryable by WASM guards via a host
function. This lets a WASM guard author say "use whatever prompt injection
detection is configured" without reimplementing it:

```
chio.evaluate_hushspec_detection(input_ptr, input_len, category: i32) -> i32
    -- Returns the detection score (0-100) for the given input using the
       HushSpec detection configuration. Category: 0=prompt_injection,
       1=jailbreak, 2=threat_intel.
    -- Returns -1 if detection is not configured.
```

This is a future host function, not a launch requirement.

---

## 4. Upstream Guard Trait vs. Chio Guard Trait

The upstream suite and Chio have slightly different guard interfaces:

| | Upstream | Chio |
|-|-------------|-----|
| Trait | `Guard` (async) | `Guard` (sync) |
| Method | `check(&self, action, context)` | `evaluate(&self, ctx)` |
| Input | `GuardAction` + `GuardContext` | `GuardContext` (contains request) |
| Output | `GuardResult` (verdict + severity + message) | `Result<Verdict, KernelError>` |
| Verdict | Allowed / Denied (with message) | Allow / Deny |
| Async | Yes (`#[async_trait]`) | No |

WASM guards implement Chio's `Guard` trait, not the upstream suite. This is correct
because WASM guards run inside the Chio kernel, not inside the upstream suite.

But the `GuardRequest` type sent to WASM guests (defined in
`chio-wasm-guards/src/abi.rs`) should include enough context for the guest to
make decisions that the upstream richer `GuardAction` enables. Currently
`GuardRequest` has:

```rust
pub struct GuardRequest {
    pub tool_name: String,
    pub server_id: String,
    pub agent_id: String,
    pub arguments: serde_json::Value,
    pub scopes: Vec<String>,
}
```

### Missing fields that Upstream guards use

> **The authoritative v1 `GuardRequest` shape is defined in
> `05-V1-DECISION.md` Section 3.** The table below is the full wish-list
> from the upstream guard suite analysis. Fields marked [v1] ship in v1; the rest
> are candidates for later versions.

| Field | The upstream suite uses it for | v1? |
|-------|------------------------|-----|
| Action type (FileAccess, NetworkEgress, ShellCommand, etc.) | Routing to the right guard | [v1] `action_type: Option<String>` |
| File path (normalized) | Path-based guards | [v1] `extracted_path: Option<String>` |
| Network target (domain) | Egress guards | [v1] `extracted_target: Option<String>` |
| Session filesystem roots | Path allowlisting | [v1] `filesystem_roots: Vec<String>` |
| Matched grant index | Budget/velocity guards | [v1] `matched_grant_index: Option<usize>` |
| Patch/write content | Patch integrity | Deferred -- large payloads would inflate JSON serialization cost |
| Capability metadata (issuer, delegation depth) | Delegation-aware guards | Deferred -- assess demand after v1 |

The host pre-extracts `ToolAction` via `extract_action()` and populates the
v1 fields before serializing `GuardRequest` to JSON for the WASM guest.
This way:
- WASM guests don't need to reimplement `extract_action()` logic
- Guests written in Python/TypeScript don't need to parse tool arguments
- The host controls normalization (symlink resolution, etc.)

---

## 5. HushSpec Policy as WASM Guard Configuration

A WASM guard might need to know about the active HushSpec policy -- not to
re-evaluate its rules, but to be aware of the security posture. For example:

- A custom compliance guard might behave differently under "strict" vs.
  "permissive" posture
- A cost-control guard might check if the current HushSpec policy allows a
  tool before doing its own expensive check

Two options:

### Option A: Manifest-only config (v1)

In v1, guard-specific configuration lives in `guard-manifest.yaml` shipped
alongside the `.wasm` binary. The `chio.yaml` schema (`WasmGuardEntry`)
currently only allows `name`, `path`, `fuel_limit`, `priority`, and
`advisory` with `deny_unknown_fields` -- it has no `config` field. The
guard reads manifest config at load time via `chio.get_config(key)`.

### Option B: `chio.yaml` config field (v1.1 -- not yet implemented)

A future schema change would add an inline `config` map to `WasmGuardEntry`,
letting operators override manifest defaults per deployment:

```rust
// Proposed for v1.1 -- requires schema change in chio-config/src/schema.rs
pub struct WasmGuardEntry {
    pub name: String,
    pub path: String,
    #[serde(default = "default_wasm_fuel_limit")]
    pub fuel_limit: u64,
    #[serde(default = "default_wasm_priority")]
    pub priority: u32,
    #[serde(default)]
    pub advisory: bool,
    /// Arbitrary key-value config passed to the guard at load time.
    /// Overrides manifest defaults.
    #[serde(default)]
    pub config: std::collections::HashMap<String, serde_json::Value>,
}
```

This is deferred to v1.1 per `05-V1-DECISION.md` Section 4.

### Option C: Host function for policy query (future)

```
chio.query_hushspec(rule_type: i32, target_ptr: i32, target_len: i32) -> i32
    -- Returns 0=allow, 1=deny for the given rule type and target
       according to the loaded HushSpec policy.
```

This is more powerful but couples WASM guards to HushSpec internals. Defer
to a future version.

---

## 6. HushSpec Conditional Rules and WASM Guards

HushSpec supports conditional rules via a `when` field:

```yaml
rules:
  egress:
    when:
      any_of:
        - context.environment: production
        - time_window: { start: "09:00", end: "17:00" }
    allow: ["api.example.com"]
```

WASM guards could provide the **condition evaluation** that HushSpec's
declarative format cannot:

- HushSpec's conditions are limited to time windows, context matching, and
  logical operators
- A WASM "condition evaluator" could check external state (is the user on
  VPN? what's the current threat level? is this agent in a supervised session?)

This is a future integration point. The design would be:
1. HushSpec adds a `when.wasm_condition` type
2. The condition delegates to a named WASM guard that returns a boolean
3. The WASM guard is loaded from the same `wasm_guards` pool

Not needed for v1, but the architecture should not preclude it.

---

## 7. Receipt and Audit Integration

Both the upstream suite and Chio sign receipts. WASM guard decisions need to flow into
the same audit trail:

| System | Receipt type | What it records |
|--------|-------------|-----------------|
| Upstream | Ed25519-signed `GuardResult` | Verdict, severity, guard name, message |
| Chio | Signed `Decision` in receipt log | Allow/Deny, guard name, denial reason |
| HushSpec | `DecisionReceipt` (via `evaluate_audited`) | Decision, matched rule, reason, rule trace |

WASM guard denials already flow through `KernelError::GuardDenied` and get
recorded in Chio's receipt log. But the receipt should include:

- Guard name (already captured)
- Denial reason (available via `chio_deny_reason` or offset-64K protocol)
- Fuel consumed (proposed in 03-IMPLEMENTATION-PLAN.md Section 8.3)
- **Guard manifest hash** -- which exact `.wasm` binary made the decision

The manifest hash connects the receipt to a specific, integrity-verified guard
binary. This is important for audit: "the request was denied by
`pii-guard@1.2.0` (SHA-256: a1b2c3d4...)" is a reproducible, verifiable
statement.

---

## 8. Distribution: HushSpec Rulesets vs. WASM Guard Packages

HushSpec distributes rules as YAML files with `extends` chains (builtins,
local files, remote URLs, git refs). The upstream suite ships built-in rulesets
(default, strict, permissive, ai-agent, cicd, remote-desktop, etc.).

WASM guards need a parallel distribution model. The two should not be
conflated:

| | HushSpec rules | WASM guards |
|-|---------------|-------------|
| Format | YAML | `.wasm` + `guard-manifest.yaml` |
| Size | ~1-10 KB | ~50 KB - 15 MB |
| Verification | Schema validation | SHA-256 hash + optional signing |
| Composition | `extends` + `merge_strategy` | Independent modules, no inheritance |
| Registry | Builtins + filesystem + URL | Filesystem + URL + OCI (future) |

But they should be **co-distributable**. A security policy package might
include both:

```
acme-security-policy/
  hushspec.yaml           # Declarative rules
  guards/
    compliance.wasm       # Custom WASM guard
    guard-manifest.yaml
```

The `chio.yaml` configuration should support referencing both in a single
policy bundle:

```yaml
# chio.yaml (current schema -- no config field yet)
wasm_guards:
  - name: compliance
    path: ./acme-security-policy/guards/compliance.wasm
    fuel_limit: 5000000
    priority: 50
```

Guard-specific configuration (e.g., `region: us-east-1`) lives in the guard
manifest file alongside the `.wasm` binary until the `config` field is added
to `WasmGuardEntry` (see Section 5, Option A above).

---

## 9. Gap Analysis: What the Prior Documents Missed

> **Updated** after external review. Items marked [FIXED] have been corrected
> in the relevant documents.

| Gap | Impact | Status |
|-----|--------|--------|
| No mention of HushSpec anywhere in 01-03 | WASM guard ABI designed without considering existing declarative rule format | [FIXED] This document (04) addresses it |
| `GuardRequest` missing extracted action type | WASM guests must re-parse tool arguments | Open -- see 05-V1-DECISION.md |
| No guidance on when to use HushSpec vs. WASM | Users might write WASM guards for things HushSpec handles | [FIXED] This document Section 2 |
| Guard pipeline ordering not specified | WASM guards could run before cheap guards | [FIXED] Section 1 now specifies ordering via `compile_policy()` |
| Doc 01 wrongly claimed priority sorting existed | Plans built on non-existent feature | [FIXED] Doc 01 now notes sorting is not implemented |
| Doc 04 used `default_pipeline()` instead of `compile_policy()` | Would bypass HushSpec-specific config | [FIXED] Section 1 now uses `chio_policy::compiler` |
| Config `config` field not in schema | Example YAML would fail to parse | [FIXED] Section 5 now documents the schema gap |
| Docs 02 and 03 disagreed on ABI platform | Risk of building two ecosystems | [FIXED] Doc 02 Section 3.5 now says raw ABI v1, WIT v2 |
| Use cases ahead of runtime model | Promised capabilities the sync/stateless design can't deliver | [FIXED] Section 2 now separates near-term vs. deferred |
| Severity on denials underspecified | Implied it connected to advisory promotion (it doesn't) | [FIXED] Recommendation 3 now scoped to receipts only |
| Receipt doesn't include manifest hash | Audit trail can't trace to verified binary | Open -- v1 scope item |
| No co-distribution model for HushSpec + WASM | Two separate management surfaces | Documented in Section 8, implementation deferred |

---

## 10. Recommendations

1. **Enrich `GuardRequest`** with pre-extracted action fields so WASM guests
   don't reimplement `extract_action()`. The host does the parsing; the guest
   does the policy logic.

2. **Document the "use HushSpec first" principle.** If a rule can be expressed
   declaratively in HushSpec, it should be. WASM guards are for logic that
   HushSpec cannot express. This prevents ecosystem fragmentation.

3. **Consider severity on `GuardVerdict::Deny` for receipts only.**
   the upstream `GuardResult` includes severity. Adding it to WASM verdicts
   would enrich receipt metadata. However, advisory promotion today operates
   on `AdvisorySignal` (from `AdvisoryGuard` trait), not on `Guard` verdicts.
   Severity on deterministic denials would not plug into advisory promotion
   without additional plumbing. The v1 value is strictly for receipt
   enrichment and log filtering:
   ```rust
   pub enum GuardVerdict {
       Allow,
       Deny { reason: String, severity: Option<String> },
   }
   ```
   This is a nice-to-have, not a v1 blocker.

4. **Include manifest SHA-256 in receipts.** When a WASM guard produces a
   verdict, the receipt should include the guard's verified hash from its
   manifest.

5. **Reserve the `chio.evaluate_hushspec_detection` host function** in the ABI
   design. Don't implement it now, but don't use that namespace for something
   else.

6. **Co-locate HushSpec + WASM in policy bundles.** The config format should
   support a single directory containing both `hushspec.yaml` and WASM guards
   with their manifests.

7. **Enforce pipeline ordering in startup code.** Built-in (HushSpec-derived)
   guards first, WASM guards second, advisory last. This is a performance
   and correctness concern.
