# 10 - Cedar First Guard: Porting `McpToolGuard` and Sizing the Migration

> **Historical research note (PR 652):** Use [00-overview-v2.md](00-overview-v2.md) and [18-decision-packet.md](18-decision-packet.md) for planning. This file remains research input, not an implementation ticket.
>
> **Erratum (PR 652 review + v1-only collapse):** References below to
> `policy_digest: [u8; 32]` are digest-source sketches, not final receipt wire
> shape. The current signed receipt field is `policy_hash`, encoded as a hex or
> operator-pinned `String`; `policy_digest` remains only an internal
> per-engine sketch term in this historical research.

## TL;DR

The cleanest candidate for the `PolicyEngineProvider` proof-of-concept from
doc 04 is `McpToolGuard` (`crates/chio-guards/src/mcp_tool.rs`, 429 LOC):
small, high-density (block list, allow list, default action, arg-size cap,
enable flag), self-contained, stable, and entity-typed
(`Agent / invoke / Tool`). Port shrinks ~80 lines of decision code into
~18 lines of Cedar plus a 60-line schema; Cedar's `Validator` enforces the
CLAUDE.md "invalid policies reject at load time" rule for free.

Scope recommendation: **Option A', greenfield Cedar plus opt-in flagship
ports of `McpToolGuard` and `EgressAllowlistGuard`.** Full migration is
not justified: most guards are ML/heuristic (jailbreak, prompt injection,
spider sense) or stateful over the session journal (velocity, data flow,
behavioral sequence); Cedar is the wrong tool for those. About 4-6 guards
are pure list-and-branch; migration candidates only if audit asks.

---

## 1. Guard survey

LOC includes tests and docs. "Density" rates the proportion of decision
logic that is list-driven allow/deny vs. parsing, normalization, ML, or
journal state.

### `chio-guards/src/` (high-density first)

| Guard | LOC | Density | Description |
|-------|-----|---------|-------------|
| `egress_allowlist.rs` | 196 | **High** | Glob allow/block on egress hostname |
| `forbidden_path.rs` | 221 | **High** | Glob deny on FS paths with exceptions |
| `mcp_tool.rs` | 429 | **High** | Allow/block lists + default action + arg-size cap |
| `path_allowlist.rs` | 503 | **High** | Per-op (read/write/patch) glob allowlists |
| `shell_command.rs` | 815 | Medium | Glob plus AST patterns on shell commands |
| `internal_network.rs` | 452 | Medium | CIDR membership for private/reserved space |
| `patch_integrity.rs` | 481 | Medium | Header/marker checks on patches |
| `code_execution.rs` | 401 | Medium | Module/import denylist parsing |
| `browser_automation.rs` | 559 | Medium | Verb allowlist + URL checks |
| `computer_use.rs` | 525 | Medium | Action-type allowlist + frequency caps |
| `input_injection.rs` | 257 | Medium | Input-channel typing + capability check |
| `remote_desktop.rs` | 264 | Medium | Side-channel detection rules |
| `memory_governance.rs` | 378 | Medium | R/W quotas over memory namespace |
| `content_review.rs` | 535 | Medium | Per-category content rules |
| `agent_velocity.rs`, `velocity.rs`, `data_flow.rs`, `behavioral_sequence.rs`, `behavioral_profile.rs` | 324-647 each | Low | Stateful over session journal |
| `jailbreak.rs`, `jailbreak_detector.rs`, `prompt_injection.rs`, `spider_sense.rs`, `secret_leak.rs`, `response_sanitization.rs` | 366-1608 each | Low | ML / heuristic / entropy scoring |
| `post_invocation.rs`, `advisory.rs` | 359, 862 | Low | Pipeline plumbing |

### `chio-data-guards/src/`

| Guard | LOC | Density | Description |
|-------|-----|---------|-------------|
| `sql_guard.rs` | 488 | Medium | SQL parser + statement-class allow/deny |
| `result_guard.rs` | 837 | Medium | Row/column projection rules |
| `vector_guard.rs` | 987 | Medium | Vector-store namespace + similarity rules |
| `warehouse_cost_guard.rs` | 833 | Low | Cost projection vs. budget |

### `chio-external-guards/src/external/`

Cloud guardrails (Bedrock, Azure, Vertex, Safe Browsing, Snyk, VirusTotal).
Decision logic is "what the upstream told us"; no in-process policy density
worth porting. Right home for `CedarPolicyGuard` as a sibling adapter.

---

## 2. Pick: `McpToolGuard`

- **Size.** 429 LOC; ~80 are decision logic. The rest is tests, config
  plumbing, and a hand-rolled JSON byte-counter. One-PR port.
- **Density.** Five orthogonal conditions in `is_allowed` plus arg-size
  (`crates/chio-guards/src/mcp_tool.rs:118-178`): enabled, block precedence,
  allowlist-mode toggle, default action, arg-size cap. Each is a boolean
  predicate, exactly what Cedar `when`/`unless` encodes best.
- **Self-contained.** Touches only `request.tool_name`, `request.arguments`,
  and config. No journal, no FS normalization, no upstream call.
- **Stable.** Untouched since the initial guard import; not on any TODO.
- **Entity-typed.** `Chio::Agent::"<agent_id>"` / `Action::"invoke"` /
  `Chio::Tool::"<server_id>/<tool_name>"`.

`EgressAllowlistGuard` and `ForbiddenPathGuard` are runners-up: each needs
glob hostnames or FS canonicalization. Cedar's `like` covers single-segment
wildcards but multi-segment glob (`*.foo.com`) needs custom pre-processing.
`McpToolGuard` only needs exact string membership, which Cedar nails.

---

## 3. The port

### 3.1 Original logic (sketch)

From `crates/chio-guards/src/mcp_tool.rs:154-178`:

```rust
fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
    if !self.enabled { return Ok(Verdict::Allow); }
    let action = extract_action(&ctx.request.tool_name, &ctx.request.arguments);
    let (tool_name, args) = match &action {
        ToolAction::McpTool(name, args) => (name.as_str(), args),
        _ => return Ok(Verdict::Allow),
    };
    let args_size = json_size_bytes(args)?;
    if args_size > self.max_args_size { return Ok(Verdict::Deny); }
    match self.is_allowed(tool_name) {
        ToolDecision::Allow => Ok(Verdict::Allow),
        ToolDecision::Block => Ok(Verdict::Deny),
    }
}

pub fn is_allowed(&self, tool_name: &str) -> ToolDecision {
    if self.block_set.contains(tool_name) { return ToolDecision::Block; }
    if !self.allow_set.is_empty() {
        return if self.allow_set.contains(tool_name) {
            ToolDecision::Allow
        } else {
            ToolDecision::Block
        };
    }
    if self.default_action == McpDefaultAction::Block { ToolDecision::Block }
    else { ToolDecision::Allow }
}
```

### 3.2 Cedar policy file (`mcp_tool.cedar`)

```cedar
// Default: allow any MCP tool invocation. Overridden by forbids below.
permit (
    principal,
    action == Action::"invoke",
    resource
)
when {
    resource is Chio::Tool &&
    context.guard_enabled == true &&
    context.args_size_bytes <= context.max_args_size_bytes &&
    !(context.block_set.contains(resource.tool_name)) &&
    (context.allow_set_empty || context.allow_set.contains(resource.tool_name))
};

// Hard forbid for the default block-list tools. Forbids beat permits in
// Cedar so this gives the same precedence the Rust guard expresses.
forbid (
    principal,
    action == Action::"invoke",
    resource
)
when {
    resource is Chio::Tool &&
    context.block_set.contains(resource.tool_name)
};

// When the guard is disabled, allow unconditionally. Encoded as a separate
// permit so the audit log can distinguish "allowed by policy" from "allowed
// because the guard was off".
permit (
    principal,
    action == Action::"invoke",
    resource
)
when {
    context.guard_enabled == false
};
```

`McpDefaultAction::Block` becomes a config-time choice: operators flip a
flag that selects one of two policy sets. Keeps each `.cedar` file readable
and avoids embedding mode flags as policies-about-policies.

### 3.3 Cedar schema (`mcp_tool.cedarschema.json`)

```json
{
  "Chio": {
    "commonTypes": {
      "ToolName": { "type": "String" }
    },
    "entityTypes": {
      "Agent": {
        "shape": {
          "type": "Record",
          "attributes": {
            "tenant_id":   { "type": "String", "required": true },
            "capability_scope": { "type": "Set", "element": { "type": "String" } }
          }
        }
      },
      "Tool": {
        "shape": {
          "type": "Record",
          "attributes": {
            "server_id": { "type": "String", "required": true },
            "tool_name": { "type": "String", "required": true }
          }
        }
      }
    },
    "actions": {
      "invoke": {
        "appliesTo": {
          "principalTypes": ["Agent"],
          "resourceTypes":  ["Tool"],
          "context": {
            "type": "Record",
            "attributes": {
              "guard_enabled":         { "type": "Boolean" },
              "args_size_bytes":       { "type": "Long" },
              "max_args_size_bytes":   { "type": "Long" },
              "allow_set_empty":       { "type": "Boolean" },
              "allow_set":             { "type": "Set", "element": { "type": "String" } },
              "block_set":             { "type": "Set", "element": { "type": "String" } }
            }
          }
        }
      }
    }
  }
}
```

The schema also gives Cedar enough information to reject malformed policies
at `validate()` time, which is the load-time check we need.

### 3.4 Wiring code

`CedarPolicyGuard` lives at `crates/chio-external-guards/src/external/cedar.rs`,
implements `PolicyEngineProvider`, and is wrapped into `ExternalGuard` by
the doc-04 blanket adapter. Sketch:

```rust
pub struct CedarPolicyGuard {
    name: String,
    authorizer: cedar_policy::Authorizer,
    policy_set: cedar_policy::PolicySet,
    schema: cedar_policy::Schema,
    entities: cedar_policy::Entities,
    policy_digest_bytes: [u8; 32],
}

impl CedarPolicyGuard {
    pub fn load(name: &str, cedar_src: &str, schema_src: &str)
        -> Result<Self, CedarLoadError>
    {
        let schema = cedar_policy::Schema::from_str(schema_src)
            .map_err(CedarLoadError::Schema)?;
        let policy_set = cedar_policy::PolicySet::from_str(cedar_src)
            .map_err(CedarLoadError::Parse)?;
        // Fail-closed at load: reject any policy that does not type-check.
        let validator = cedar_policy::Validator::new(schema.clone());
        let result = validator.validate(&policy_set, cedar_policy::ValidationMode::Strict);
        if !result.validation_passed() { return Err(CedarLoadError::Invalid(result)); }
        let mut hasher = sha2::Sha256::new();
        hasher.update(cedar_src.as_bytes()); hasher.update(b"\x00"); hasher.update(schema_src.as_bytes());
        Ok(Self {
            name: name.to_string(),
            authorizer: cedar_policy::Authorizer::new(),
            policy_set, schema,
            entities: cedar_policy::Entities::empty(),
            policy_digest: hasher.finalize().into(),
        })
    }
}

#[async_trait]
impl PolicyEngineProvider for CedarPolicyGuard {
    fn engine(&self) -> &'static str { "cedar" }
    fn policy_digest(&self) -> [u8; 32] { self.policy_digest }
    async fn evaluate(&self, ctx: &GuardCallContext)
        -> Result<EngineDecision, ExternalGuardError>
    {
        let request = build_cedar_request(ctx, &self.schema)
            .map_err(|e| ExternalGuardError::Permanent(e.to_string()))?;
        let response = self.authorizer.is_authorized(&request, &self.policy_set, &self.entities);
        let verdict = match response.decision() {
            cedar_policy::Decision::Allow => Verdict::Allow,
            cedar_policy::Decision::Deny  => Verdict::Deny,
        };
        Ok(EngineDecision {
            verdict,
            decision_id: uuid::Uuid::new_v4().to_string(),
            obligations: serde_json::json!({}),
            diagnostics: format_diagnostics(response.diagnostics()),
        })
    }
}
```

`build_cedar_request` constructs `principal = Chio::Agent::"<agent_id>"`,
`action = Action::"invoke"`, `resource = Chio::Tool::"<server>/<tool>"`,
plus the context record. The blanket adapter from doc 04 then wraps this
into `ExternalGuard` so the existing `AsyncGuardAdapter` /
`ScopedAsyncGuard` (`crates/chio-external-guards/src/lib.rs:35-139`)
applies cache, circuit breaker, and rate limit unchanged. Registration:

```rust
let g = CedarPolicyGuard::load("mcp-tool-cedar",
    include_str!("../policies/mcp_tool.cedar"),
    include_str!("../policies/mcp_tool.cedarschema.json"))?;
kernel.add_guard(Box::new(ScopedAsyncGuard::new(
    AsyncGuardAdapter::builder(Arc::new(g)).cache_ttl(Duration::from_secs(60)).build(),
    vec![],
)));
```

### 3.5 Test fixture parity

Drive both implementations with the same `GuardCallContext` across the
matrix from `crates/chio-guards/src/mcp_tool.rs:181-428`:

| # | block | allow | default | tool | arg_size | Verdict |
|---|-------|-------|---------|------|----------|---------|
| 1 | `[shell_exec]` | `[]` | Allow | `shell_exec` | 10 | Deny |
| 2 | `[]` | `[]` | Allow | `read_file` | 10 | Allow |
| 3 | `[]` | `[safe_tool]` | Block | `other` | 10 | Deny |
| 4 | `[a]` | `[a]` | Allow | `a` | 10 | Deny |
| 5 | `[]` | `[]` | Block | `x` | 10 | Deny |
| 6 | `[shell_exec]` | `[]` | Block | `read_file` | disabled | Allow |
| 7 | `[]` | `[]` | Allow | `x` | 200 (cap=100) | Deny |

Becomes a property test: enumerate cross product over small sets, evaluate
both, assert equality. Original guard is the oracle.

---

## 4. Measurements (estimated)

I cannot run `cargo` from this research worktree without diverging from the
swarm's "no code changes" mode, so the numbers below are estimates from
the [`cedar-policy` 4.x release notes](https://crates.io/crates/cedar-policy)
and public Cedar benchmarks.

| Metric | Rust today | Cedar port | Notes |
|--------|-----------|------------|-------|
| Decision LOC | ~80 (`is_allowed` + `evaluate` + arg-size) | ~18 (3 policies) | Net -62 LOC of decision code |
| Schema LOC | 0 (implicit in struct) | ~60 (JSON) | Pays back as audit/lint surface |
| Test LOC | ~250 in-file | ~250 unchanged + parity table | Reuse oracle |
| Load-time validation | none (impossible patterns swallowed by `Pattern::new(p).ok()` filter elsewhere; mcp_tool itself has no patterns) | `Schema::from_str` + `Validator::validate(..Strict)` | Refuses malformed policies; rule-shape mismatches flagged |
| Eval overhead | ~50-500 ns (HashSet lookups + JSON byte count) | ~10-50 us (Cedar typical) | Cedar is 100-1000x slower per call, mitigated by `AsyncGuardAdapter`'s TTL cache |
| Memory footprint | ~1 KB per guard (two HashSets) | ~50-200 KB per guard (parsed PolicySet + Schema + Authorizer) | Per-process, not per-call |

Eval-overhead jump is likely acceptable for `McpToolGuard` because (a) the
kernel already does a sync-to-async hop via `ScopedAsyncGuard::block_on`
(`crates/chio-external-guards/src/lib.rs:66-94`) for HTTP cloud guardrails,
(b) `AsyncGuardAdapter::TtlCache` keyed on `(tool, agent, args_hash)` can
collapse repeated decisions when workloads actually repeat, and (c) Cedar is
in-process with policy/schema loaded once at startup. The cache hit rate must
be measured with the real bench bodies from the PR 652 decision packet before
this becomes a latency claim. For raw single-digit-us guards
(`ForbiddenPathGuard` on hot path), the overhead would dominate; do not
migrate those.

---

## 5. Decision: greenfield with two flagship ports (Option A')

**Recommended: A', a hybrid.** Ship Cedar greenfield (operators add new
policy in `.cedar`), AND port two flagship guards as living documentation:
`McpToolGuard` and `EgressAllowlistGuard`. The flagships prove the
abstraction, give audit a reference, and exercise the schema-validation
startup path. Everything else stays Rust.

Why not B: only ~6 of ~30 guards are pure list-and-branch. The rest are
journal-stateful (Cedar's entity store cannot represent a journal without
becoming a copy of it) or ML/heuristic (statistical scoring, not policy).
Porting those either fails or synthesizes a phantom entity graph that goes
stale and lies to the audit log.

Why not C: worst transitional state. Half the guards in each system,
operators learning both, migration overhead without "one pane" benefit.

Triggers that push A' to B: (1) regulator wants a single auditable policy
artifact (Cedar files + schema digest qualifies; Rust source does not),
(2) audit builds replay infrastructure that prefers structured decisions
over re-running Rust, (3) OpenFGA lands and operators already accept
multi-engine config.

---

## 6. Receipt embedding

Per doc 04: every engine decision contributes `engine_id: "cedar"`,
`policy_digest: String` (hex-encoded from the internal digest bytes), and
`decision_id: String`. Matched policy IDs come from
`response.diagnostics().reason()` as `Vec<PolicyId>`.

Coordinate with current v1 receipt-kind semantics: `extensions` is a typed
namespace map. Reserve `policy.cedar`:

```json
{
  "engine_id":   "cedar",
  "policy_digest": "0x9f2b...",
  "decision_id": "uuid-...",
  "matched_policies": ["mcp_tool.permit_default", "mcp_tool.forbid_block"],
  "errored_policies": []
}
```

Sits inside `extensions["policy.cedar"]` per Cedar-backed call. The
existing `ChioReceiptBody.policy_hash`
(`crates/chio-core-types/src/receipt.rs:166`) still aggregates digests
across the pipeline; the extension is per-engine detail.

Replay: fetch artifact by `policy_digest`, reconstruct request from
`content_hash`, run Cedar, assert verdict and matched-policy set match.
`decision_id` differs (UUIDv4); verdict and matched set must be identical.

---

## 7. Failure semantics

CLAUDE.md: "invalid policies reject at load time." Wire as follows.

**Where.** `CedarPolicyGuard::load` (sketch in 3.4) validates the policy
set against the schema before construction. Failure returns
`CedarLoadError::Invalid(ValidationResult)` and propagates to the kernel
boot.

**Bootstrap path.** Control plane builds guards at
`crates/chio-control-plane/src/lib.rs:368` via `add_guard`. The
config-loading code preceding that call must surface a fatal
`KernelError::ConfigError` on `CedarLoadError`; the load function returns
`Result`, so boot does not start until every guard is constructed.

**Error type.** New variant in `chio-external-guards`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum CedarLoadError {
    #[error("cedar schema parse failed: {0}")]
    Schema(cedar_policy::SchemaError),
    #[error("cedar policy parse failed: {0}")]
    Parse(cedar_policy::ParseErrors),
    #[error("cedar policy did not validate against schema:\n{0}")]
    Invalid(cedar_policy::ValidationResult),
}
```

`Invalid` carries the full `ValidationResult`, which is `Display` and
renders structured per-finding errors, so the operator sees every policy
ID, attribute, and type mismatch on stderr.

**Operator diagnosis.** A failed boot prints, per invalid policy:

```
ERROR cedar policy did not validate against schema:
  mcp_tool.permit_default: UnrecognizedEntityType: Chio::Agentt at line 3
  mcp_tool.forbid_block:   UnexpectedType: context.block_set: expected Set<String>, got Long at line 8
```

Kernel exits non-zero. No partial-load, no degraded mode.

**Runtime failures.** Cedar eval errors (e.g. missing entity attributes)
return `ExternalGuardError::Permanent`, mapped by the adapter to
`Verdict::Deny` without tripping the breaker
(`crates/chio-guards/src/external/mod.rs:381-398`). Fail-closed at request
level mirrors fail-closed at load level.

---

## 8. Open questions

Items needing `cargo` against `cedar-policy` 4.x to settle:

1. **`Validator` strictness.** Sketch uses `Strict`. Need to confirm Cedar
   idioms like `principal is Chio::Agent` type narrowing are not rejected.
2. **`Entities::empty()` vs. precomputed.** Sketch is empty since
   `McpToolGuard` needs no agent attributes. Egress port will need real
   entities; whether the store mutates per-request or rebuilds per
   capability event is undesigned.
3. **Set-attribute cost.** `block_set`/`allow_set` as `Set<String>` is
   rebuilt per request. Whether cost is linear in size or Cedar interns is
   unclear from docs; benchmark.
4. **Receipt namespace.** Assumed `policy.cedar` under `extensions`.
   Coordinate with X1; body shape is portable across namespace choice.
5. **Hot reload.** `PolicySet` is immutable. Wiring for atomic swap
   (`ArcSwap`?) is undesigned.
6. **`unwrap_used = "deny"` interaction.** Cedar's error types are many;
   real implementation needs careful `?`-only propagation.
7. **Entity-digest receipts.** Cedar decision is a function of
   `(policies, entities, request)`; receipt embeds `policy_digest` but not
   `entities_digest`. Defer to phase 2 (OpenFGA).

---

## Summary

1. Chosen guard: **`McpToolGuard`** (`crates/chio-guards/src/mcp_tool.rs`,
   429 LOC; high-density list-and-branch policy that maps cleanly to
   Cedar `Agent / invoke / Tool`).
2. Recommendation: **Option A' (Cedar greenfield + two flagship ports:
   `McpToolGuard` and `EgressAllowlistGuard`).** Full migration is not
   justified by the policy-density distribution.
3. File: this file.
