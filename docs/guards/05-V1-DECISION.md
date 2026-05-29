# WASM Guard v1: Decision Record

This document defines the scoped v1 of WASM guards for Chio. It resolves the
ambiguities identified in review and draws a hard line between what ships in
v1 and what is deferred.

---

## Decisions

### 1. ABI: Raw core-WASM, not WIT/Component Model

**Choice:** Raw `evaluate(ptr, len) -> i32` over JSON in linear memory,
targeting `wasm32-unknown-unknown`.

**Why:** The code already implements this (`chio-wasm-guards/src/abi.rs`,
`runtime.rs`). WIT would require rewriting the host, the ABI types, and
introducing new compilation toolchains before the basic execution envelope
is validated. We are not going to build two ecosystems.

**WIT is the v2 target.** Once v1 validates latency, fuel, and memory on real
workloads, define a WIT interface and migrate. Support both raw modules
(legacy) and components (new) during transition.

### 2. State model: Pure stateless pre-dispatch guard

**Choice:** Each WASM guard invocation gets a fresh `Store`. No persistent
per-guard state across calls. No async. No network.

**Why:** The kernel `Guard` trait is synchronous. The `WasmtimeBackend`
creates a fresh `Store<()>` per call (line 324 of `runtime.rs`). This gives
isolation, deterministic fuel accounting, and no state-leakage bugs.

**What this rules out for v1:**
- Cross-request correlation (needs persistent context store)
- External policy lookups (needs network host functions + async)
- Dynamic config reload (needs host-side config watch)

These are real goals but they require a state model redesign, not incremental
runtime work. Defer to v2.

### 3. Guard request: Host-extracted action context

**Choice:** The host pre-extracts `ToolAction` fields and adds them to
`GuardRequest` so WASM guests don't reimplement `extract_action()`.

**Current `GuardRequest`** (`abi.rs`):

```rust
pub struct GuardRequest {
    pub tool_name: String,
    pub server_id: String,
    pub agent_id: String,
    pub arguments: serde_json::Value,
    pub scopes: Vec<String>,
    pub session_metadata: Option<serde_json::Value>,
}
```

**v1 `GuardRequest`** (add these fields):

```rust
pub struct GuardRequest {
    // existing
    pub tool_name: String,
    pub server_id: String,
    pub agent_id: String,
    pub arguments: serde_json::Value,
    pub scopes: Vec<String>,

    // v1 additions -- host-extracted action context
    /// Action type derived by the host via extract_action().
    /// One of: "file_access", "file_write", "network_egress",
    /// "shell_command", "mcp_tool", "patch", "unknown".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_type: Option<String>,

    /// Normalized file path (for file_access, file_write, patch actions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extracted_path: Option<String>,

    /// Network target domain (for network_egress actions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extracted_target: Option<String>,

    /// Session filesystem roots from GuardContext (when available).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filesystem_roots: Vec<String>,

    /// Matched grant index from the capability scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_grant_index: Option<usize>,
}
```

All new fields are optional and additive -- existing WASM guards that
ignore them continue to work. The host populates them by calling
`chio_guards::extract_action()` before serializing.

**Why the host extracts, not the guest:**
- `extract_action()` contains heuristic tool-name matching, path
  normalization, and symlink resolution that should not be reimplemented
  in every language.
- The host controls normalization (defeating symlink bypasses, etc.).
- Guests in Python/TypeScript should not need to parse raw JSON arguments.

### 4. Config: Manifest-only for v1, schema change for v1.1

**Choice:** Guard-specific configuration lives in `guard-manifest.yaml`
shipped alongside the `.wasm` binary. The `chio.yaml` `WasmGuardEntry` is
not changed in v1.

**Why:** `WasmGuardEntry` uses `deny_unknown_fields`. Adding a `config`
map requires a schema change, tests, and documentation. The manifest
already has a natural place for config. Do the schema change as a fast
follow (v1.1) once the manifest format is validated.

**v1 flow:**
1. `chio.yaml` references the guard: `path: /etc/chio/guards/pii/pii.wasm`
2. The loader looks for `guard-manifest.yaml` adjacent to the `.wasm` file
3. Manifest contains `config:` block
4. Config is loaded into `WasmHostState` and exposed via `chio.get_config`

**v1.1 flow** (after schema change):
1. `chio.yaml` gains a `config: {}` field on `WasmGuardEntry`
2. Values from `chio.yaml` override manifest defaults
3. Lets operators customize guard behavior per deployment without editing
   the manifest

### 5. Pipeline ordering: Explicit startup contract

**Choice:** Startup code enforces this order:

1. **HushSpec-compiled guards** via `chio_policy::compiler::compile_policy()`
2. **WASM guards** sorted by `WasmGuardEntry.priority` before loading
3. **Advisory pipeline** (always last)

**Why:**
- HushSpec guards are native Rust, fast, and catch the common 80% of
  violations. Running them first avoids burning WASM fuel on requests that
  would be denied by a glob pattern.
- `WasmGuardRuntime` does NOT sort by priority (despite its doc-comment).
  The startup code must sort the `WasmGuardEntry` vector by priority before
  loading guards into the runtime.
- Advisory guards always return Allow, so they must run last to avoid
  short-circuiting nothing.

**Not** `GuardPipeline::default_pipeline()` -- that creates guards with
hard-coded defaults, ignoring the HushSpec policy. The real bridge is
`chio_policy::compiler::compile_policy()`.

### 6. Scope: What ships in v1

**In scope:**

- [ ] Shared `Chio<Engine>` across all WASM guards (currently one per guard)
- [ ] `WasmHostState` instead of `()` in Store (carries config + log buffer)
- [ ] Host functions: `chio.log`, `chio.get_config`, `chio.get_time_unix_secs`
- [ ] `chio_alloc` support (check for export, use it, fall back to offset 0)
- [ ] `chio_deny_reason` export support (fall back to offset-64K convention)
- [ ] Guard manifest format (`guard-manifest.yaml`) with SHA-256 verification
- [ ] Enriched `GuardRequest` with host-extracted action context
- [ ] Memory limit enforcement (`ResourceLimiter`)
- [ ] Module import validation (reject non-`chio` imports)
- [ ] Wiring: `chio-config` `wasm_guards` entries to kernel startup via
      `chio_policy::compiler` + `WasmGuardRuntime`
- [ ] Fix: sort WASM guards by priority in startup code
- [ ] Fuel consumption in receipt metadata
- [ ] Guard manifest SHA-256 in receipt metadata
- [ ] Benchmarks: module load time, instantiate time, p50/p99 evaluate
      latency, fuel overhead on representative Chio workloads

**Out of scope (deferred):**

- WIT / Component Model ABI (v2)
- Guest-side Rust SDK / proc macro (v2 -- after ABI is stable)
- Non-Rust guest SDKs (TypeScript, Python, Go) (v2)
- CLI tooling (`chio guard new/build/test/pack`) (v2)
- Guard registry / marketplace / OCI distribution (v2+)
- Persistent per-guard state across invocations (v2)
- Async host functions / network access (v2)
- `WasmGuardEntry.config` field in `chio.yaml` schema (v1.1)
- Epoch interruption as secondary timeout (v1.1)
- HushSpec detection delegation host function (v2)
- Severity field on `GuardVerdict::Deny` (v1.1 -- receipts only)
- Advisory promotion from WASM guard verdicts (v2)
- Co-distribution packaging (HushSpec + WASM bundles) (v2)

### 7. Validation: What we need to measure before committing

Before building out the full v1, run a benchmark spike:

1. **Module load time** -- `Module::new()` on a representative `.wasm` guard
   (50 KiB Rust, 5 MiB Python-via-componentize-py)
2. **Instantiation time** -- `Linker::instantiate()` per call
3. **Evaluate latency** -- p50/p99 for a trivial guard (immediate Allow) and
   a realistic guard (JSON parse + pattern match + Deny)
4. **Fuel overhead** -- percentage slowdown with fuel metering enabled vs.
   disabled
5. **Memory ceiling** -- verify `ResourceLimiter` actually caps growth

If module load exceeds 50ms or evaluate p99 exceeds 5ms on a trivial guard,
revisit the per-call fresh-Store model (consider instance pooling).

---

## File changes required

| File | Change |
|------|--------|
| `crates/chio-wasm-guards/src/abi.rs` | Add `action_type`, `extracted_path`, `extracted_target`, `filesystem_roots`, `matched_grant_index` to `GuardRequest`. Remove `session_metadata`. |
| `crates/chio-wasm-guards/src/runtime.rs` | Update `build_request` to call `extract_action()` and populate new fields. Fix doc-comment on `WasmGuardRuntime` (does not sort). |
| `crates/chio-wasm-guards/src/runtime.rs` | `WasmtimeBackend`: accept `Chio<Engine>`, add `WasmHostState`, register `chio.*` host functions, add `chio_alloc`/`chio_deny_reason` support, add `ResourceLimiter`. |
| `crates/chio-wasm-guards/Cargo.toml` | Add dep on `chio-guards` (for `extract_action`). |
| `crates/chio-config/src/schema.rs` | No change in v1. Add `config: HashMap` in v1.1. |
| Startup code (proxy/CLI) | Wire `compile_policy()` + sorted WASM entries + advisory pipeline in correct order. |
| New file: `crates/chio-wasm-guards/src/manifest.rs` | Guard manifest parsing + SHA-256 verification. |
| New file: `crates/chio-wasm-guards/src/host.rs` | `WasmHostState` struct, `chio.log`/`chio.get_config`/`chio.get_time_unix_secs` implementations. |
| New file: `crates/chio-wasm-guards/benches/` | Benchmark suite for the validation measurements. |

---

## Relationship to HushSpec and the policy engine

**HushSpec first, WASM for what YAML can't say.**

- HushSpec (via `chio-policy`) handles the standard declarative rules: path
  blocking, egress allowlists, secret detection, shell command blocking, tool
  access control, patch integrity.
- The HushSpec policy engine is the reference engine. `chio-guards` adapts the
  upstream guard implementations to Chio's `Guard` trait. `chio-policy::compiler`
  bridges HushSpec rules to configured `chio-guards` instances.
- WASM guards handle the custom tail: semantic argument inspection,
  org-specific compliance, complex pattern matching, custom secret detection.

A WASM guard should never be the answer when a HushSpec rule would suffice.
The docs, examples, and eventual CLI tooling should make this boundary clear.
