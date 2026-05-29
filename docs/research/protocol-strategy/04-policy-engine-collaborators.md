# 04 - Policy Engine Collaborators: OPA, Cedar, OpenFGA, Tetragon

> **Erratum:** [`ChioReceiptBody.policy_hash`](../../../crates/chio-core-types/src/receipt.rs#L159) is the current signed receipt field and is a hex or operator-pinned `String`, not `[u8; 32]`. The `policy_digest` wording below is an internal per-engine digest sketch, not a current core receipt field. See [reviews/03-policy-guards-review.md](reviews/03-policy-guards-review.md).

## TL;DR

Chio already has a clean asynchronous extension seam (`ExternalGuard` plus
`AsyncGuardAdapter`) that today wraps cloud guardrails like Bedrock and Azure
Content Safety. The same seam fits OPA, Cedar, and OpenFGA with almost no new
abstraction. Recommendation: ship **Cedar first** (Rust-native, deterministic,
formally analyzable, no sidecar, lowest friction), then **OpenFGA second** (it
closes a genuine ReBAC gap Chio does not currently fill), then **OPA third**
(industry coverage, but sidecar latency and Rego footgun argue for "supported,
not native"). Treat **Tetragon as observability/evidence**, not as a guard
collaborator: ingest its signals into Chio receipts and use them to inform
later guard decisions, rather than calling Tetragon synchronously per tool
call. The new public abstraction is a single `PolicyEngineProvider` trait that
lives in `chio-external-guards`, layers cleanly over `ExternalGuard`, and
emits a structured `EngineDecision` whose hash and identifier are embedded in
the receipt's `evidence` and `policy_hash` fields so audits can replay.

---

## Phase 1: Chio guard architecture today

Chio's kernel mediates every tool call via the bridge contract
`ToolServerConnection`
(`crates/chio-kernel/src/runtime.rs:255`). Before forwarding, the kernel runs
a list of `Guard` implementations
(`crates/chio-kernel/src/kernel/mod.rs:964`), each producing a `Verdict`
(`crates/chio-kernel/src/runtime.rs:29`). The verdict is one of
`Allow | Deny | PendingApproval`. A signed `ChioReceipt`
(`crates/chio-core-types/src/receipt.rs:105`) records the outcome, including a
`policy_hash`, a `content_hash`, and a `Vec<GuardEvidence>` array
(`crates/chio-core-types/src/receipt.rs:1176`) that names each guard and its
verdict.

The native extension surfaces today:

1. **In-process sync guards.** `Guard::evaluate(&GuardContext) -> Result<Verdict, KernelError>`. The trait is synchronous. Examples: `ForbiddenPathGuard`,
   `EgressAllowlistGuard`, `McpToolGuard`, all listed in
   `crates/chio-guards/src/lib.rs:11-27`.

2. **Async external guards.** `chio-guards::external::ExternalGuard` defines
   the async contract
   (`crates/chio-guards/src/external/mod.rs:119-129`):
   ```rust
   #[async_trait]
   pub trait ExternalGuard: Send + Sync {
       fn name(&self) -> &str;
       fn cache_key(&self, ctx: &GuardCallContext) -> Option<String>;
       async fn eval(&self, ctx: &GuardCallContext)
           -> Result<Verdict, ExternalGuardError>;
   }
   ```
   `AsyncGuardAdapter` composes a circuit breaker, token bucket, TTL cache,
   and retry-with-jitter around any `ExternalGuard`
   (`crates/chio-guards/src/external/mod.rs:308-400`). Default failure mode is
   **fail-closed**: `CircuitOpenVerdict::Deny` and
   `RateLimitedVerdict::Deny` are the defaults
   (`crates/chio-guards/src/external/mod.rs:133-170`). This matches the
   `CLAUDE.md` house rule.

3. **Sync-to-async kernel bridge.** `chio-external-guards::ScopedAsyncGuard`
   wraps an `AsyncGuardAdapter` as a sync `Guard` so it can be installed on
   the kernel pipeline
   (`crates/chio-external-guards/src/lib.rs:35-139`). Concrete adapters
   already living in the tree:
   `BedrockGuardrailGuard`, `AzureContentSafetyGuard`, `VertexSafetyGuard`,
   `SafeBrowsingGuard`, `SnykGuard`, `VirusTotalGuard`
   (`crates/chio-external-guards/src/lib.rs:14-39`).

4. **WASM guards** authored against `chio-guard-sdk` and packaged as
   `.arcguard` OCI artifacts via `chio-guard-registry`. SDK ABI is JSON over
   linear memory (`crates/chio-guard-sdk/src/types.rs:29-56`). Macros in
   `chio-guard-sdk-macros` will (per the comment at
   `crates/chio-guard-sdk/src/lib.rs:22`) generate the `evaluate` export.

5. **Envoy ext_authz bridge.** `chio-envoy-ext-authz` exposes
   `envoy.service.auth.v3.Authorization/Check`
   (`crates/chio-envoy-ext-authz/src/service.rs:51-82`). This is the "Chio is
   the policy decision point that Envoy calls" direction: Envoy speaks
   ext_authz to a Chio service which delegates to an `EnvoyKernel` trait
   (`crates/chio-envoy-ext-authz/src/service.rs:26-31`). Chio is the PDP, not
   the PEP, in this pattern.

The relevant insight: Chio already has both directions of the collaborator
pattern. `ExternalGuard` lets the kernel **call out** to a sidecar. The
`ChioExtAuthzService` lets a sidecar **call into** the kernel. New policy
engine integrations should reuse `ExternalGuard` for the call-out direction
and leave the ext_authz direction unchanged.

`AGENTS.md:5` declares "no external policy engine is required." That stays
true. The integrations below are opt-in adapters, not preconditions.

There are no in-tree TODOs naming OPA, Cedar, OpenFGA, or Tetragon - so this
design is greenfield against the existing seams.

---

## OPA (Open Policy Agent)

**What it gives us that a hand-rolled guard does not.** Rego is a mature
declarative policy language with a large operator community, a stable REST
decision API, and a deep tooling ecosystem (bundles, decision logs,
discovery). For organizations that already encode authz, admission control,
or data-filtering rules in Rego, having Chio reuse those rules avoids
duplication. See [the OPA docs](https://www.openpolicyagent.org/docs/latest/).

**Wire integration.** Two routes:

- **REST sidecar.** `POST /v1/data/<package>/<rule>` with JSON
  `{"input": ...}`, response `{"result": ...}`. Standard pattern; OPA's
  documented decision API. Latency is typically 1-5 ms intra-host (sidecar)
  and 5-20 ms over a service mesh.
- **In-process via [`regorus`](https://github.com/microsoft/regorus).**
  Microsoft's Rust-native Rego interpreter. Pure-Rust, no FFI, no sidecar.
  Slower than Go OPA on huge policy sets but eliminates the deployment burden
  and keeps Chio fail-closed without a separate health check.

Recommendation: **support both, default to regorus.** A `RegoOpaGuard` enum
with `Embedded(regorus::Engine)` and `Sidecar(reqwest::Client + url)` variants
maps onto a single `ExternalGuard` impl. Operators who already run an OPA
fleet point at the sidecar; everyone else gets a self-contained binary.

**Input shape.** Package `ToolCallRequest` as the OPA `input` document:
```json
{
  "tool_name": "github.create_pr",
  "server_id": "github-prod",
  "agent_id": "agent_a1b2",
  "arguments": { ... },
  "scopes": ["repo:write"],
  "session_filesystem_roots": ["/tmp/work"],
  "matched_grant_index": 2
}
```
This is a near-direct serialization of `GuardCallContext`
(`crates/chio-guards/src/external/mod.rs:77-87`) plus a few extras from
`GuardContext`. Stable schema; bump a version string when fields are added so
Rego policies can guard on it.

**Output shape.** Map OPA's typical
`{"allow": true, "deny": ["reason"], "obligations": [...]}` to a Chio
`Verdict`. `allow: true` and empty `deny` produces `Verdict::Allow`. Any
non-empty `deny` produces `Verdict::Deny`. Obligations (header mutations,
masking instructions, approval requirements) are stored in `GuardEvidence.details` as JSON. Chio's PEP plane (the tool server adapter)
inspects them.

**Caching.** `cache_key(ctx)` should hash `(policy_bundle_digest, input_json)`.
Bundle digest changes invalidate the cache atomically. With `regorus`, also
cache the parsed `Engine` per bundle digest.

**Receipt embedding.** Set `evidence[i] = GuardEvidence { guard_name:
"opa:<package>", verdict, details: Some(serde_json::json!({ "bundle_digest":
..., "decision_id": ..., "obligations": ... }).to_string()) }`. Aggregate the
bundle digests of all OPA-backed guards into `policy_hash` so a verifier can
replay.

**Failure semantics.** Sidecar unreachable -> `ExternalGuardError::Transient`
-> circuit breaker opens after the configured failure threshold -> `CircuitOpenVerdict::Deny` (fail-closed default at
`crates/chio-guards/src/external/mod.rs:136`). Embedded `regorus` panics are
caught by the adapter and become Deny.

---

## Cedar (AWS)

**What it gives us.** Cedar is Rust-native and a first-class crate
([`cedar-policy`](https://crates.io/crates/cedar-policy)). Unlike Rego it has
a typed schema, formal analysis tools (the SMT-based policy validator), and
guaranteed decidable evaluation. For Chio's "fail-closed, no surprises" stance
this is a much better fit than Rego. See
[Cedar docs](https://docs.cedarpolicy.com/).

**Wire integration.** **In-process only.** Cedar is a library; there is no
canonical sidecar. Link `cedar-policy` directly and call
`Authorizer::is_authorized(&Request, &PolicySet, &Entities)`.

**Input shape.** Cedar's request is `(principal, action, resource, context)`.
Chio mapping:
- `principal = User::"<agent_id>"`
- `action = Action::"tool::<tool_name>"`
- `resource = Tool::"<server_id>/<tool_name>"`
- `context = arguments + scopes + extracted_action`

Entities are precomputed: for each agent, build a Cedar entity with parents
matching its capability scopes. Refresh the entity store on capability
issuance/revocation rather than per call.

**Output shape.** Cedar returns `Decision::Allow | Decision::Deny` plus
`Diagnostics` (which policies matched, which errored). Map directly to
`Verdict`. Stash policy IDs and the policy set's SHA-256 in
`GuardEvidence.details`.

**Strengths over OPA.**

- Schema validation rejects bad policies at load time. Aligns with the
  CLAUDE.md "invalid policies reject at load time" rule.
- Formal analyzer can prove "no policy allows tool X for principal class Y" -
  property tests for policy intent.
- No sidecar. No deserialization-over-the-wire. Sub-microsecond evaluation
  for typical policy sets.
- Pure Rust: integrates with `unwrap_used = "deny"` and
  `expect_used = "deny"` workspace lints (`CLAUDE.md`).

**Recommendation.** **Ship first.** This is the lowest-friction integration
and the policy engine whose design philosophy lines up most cleanly with
Chio's. A `CedarPolicyGuard` would live at
`crates/chio-external-guards/src/external/cedar.rs` and implement
`ExternalGuard`. No new async transport, no new health-check surface.

---

## OpenFGA / Zanzibar-style ReBAC

**What it gives us.** OpenFGA is a relationship-based authorization engine
modeled on Google's Zanzibar paper. The data shape is fundamentally different
from OPA/Cedar: rules are about **tuples** (`user:alice` -
`viewer` -
`document:secret.pdf`) and inheritance is over a graph of relationships, not
attributes. See [OpenFGA docs](https://openfga.dev/docs).

Chio does not currently have a ReBAC story. Today, a guard cannot ask "is
this agent's caller allowed to read this customer's record?" without
re-implementing a tuple store. This is a real gap.

**Wire integration.** gRPC `Check`, `ListObjects`, and `BatchCheck` against an
OpenFGA server (cloud or self-hosted). Library:
[`openfga-rs`](https://crates.io/crates/openfga-rs) (community) or hand-rolled
tonic client.

**Input shape.** A guard authoring policy in terms of OpenFGA describes a
template:
```rust
OpenFgaCheckRequest {
    store_id,
    authorization_model_id,
    tuple_key: TupleKey {
        user: format!("agent:{}", ctx.agent_id),
        relation: "can_invoke",
        object: format!("tool:{}/{}", ctx.server_id, ctx.tool_name),
    },
    context: Some(arguments_json),
}
```
Templates are guard configuration, not policy. Operators register a guard
saying "for `customer-record:read`, check
`viewer(agent:<caller>, customer:<arguments.customer_id>)`."

**Output shape.** `CheckResponse.allowed: bool` -> `Verdict::Allow|Deny`. The
trace (`CheckResponse.resolution`) goes into `GuardEvidence.details`.

**Latency budget.** OpenFGA Check is typically 5-15 ms cold, 1-5 ms warm
(documented in the OpenFGA performance guide). This is well within Chio's
per-guard budget for cloud-mediated calls, but it does mean ReBAC checks
cannot live in a sub-millisecond hot path. The existing TTL cache on
`AsyncGuardAdapter` mitigates this; cache keys should hash
`(store_id, model_id, tuple_key)` and TTL should be short (1-30 s) so
relationship changes propagate. Set `cache_ttl: Duration::from_secs(5)` as a
sane default.

**Recommendation.** **Ship second.** This is the integration that closes a
capability gap rather than offering an alternative encoding. Land it after
Cedar so operators have a clear story:
- Cedar: "what is allowed in principle"
- OpenFGA: "what is allowed given the live relationship graph"

---

## Tetragon (eBPF runtime enforcement)

**Why it does not fit the same shape.** Tetragon enforces and observes at the
syscall level inside the kernel via eBPF
([Tetragon docs](https://tetragon.io/docs/)). It has no concept of "AI agent
making a tool call" - that is application context Tetragon cannot see. Chio
cannot synchronously call Tetragon to ask "should this tool call proceed";
the abstraction is wrong.

What Tetragon **can** do for Chio:

1. **Observability collaboration.** Tetragon emits `process_exec`,
   `process_kprobe`, and `tracepoint` events into a stream. Chio can ingest
   these and correlate by PID/cgroup with active tool calls. If the kernel
   recently allowed a `bash` execution and Tetragon emits a `process_exec`
   for `/bin/curl` from the same cgroup invoking an unexpected destination,
   that signal becomes evidence on subsequent receipts.

2. **Out-of-band enforcement.** Tetragon's `TracingPolicy` can deny syscalls.
   Chio can **emit enforcement intents** (e.g., "for the next 60 s, deny
   network egress from cgroup X to anything outside the allowlist") that a
   Tetragon controller translates into a `TracingPolicy`. This is asymmetric:
   Chio expresses intent, Tetragon enforces, but the enforcement is not
   coupled to a single tool call.

3. **Deny-event ingestion.** When Tetragon kills a process for a policy
   violation, Chio's session journal records the event as a
   `GuardEvidence` entry on the next receipt and may transition the session
   to a quarantined state.

**Recommendation.** **Defer past Cedar and OpenFGA.** Build a separate
`chio-tetragon-bridge` crate when needed, modeled on
`chio-envoy-ext-authz` (sidecar collaboration), exposing two flows: an event
ingestor (Tetragon -> session journal) and an intent emitter (Chio -> Tetragon
TracingPolicy). Do not try to fit Tetragon under `ExternalGuard`.

---

## Cross-cutting: trait, receipts, failure model

### The `PolicyEngineProvider` trait

A single new trait in `crates/chio-external-guards/src/lib.rs` layered on top
of `ExternalGuard`. It exists so engine-aware code (config loaders, receipt
emitters, policy-hash aggregation) can treat all engines uniformly:

```rust
#[async_trait]
pub trait PolicyEngineProvider: Send + Sync {
    /// Stable engine identifier. "opa", "cedar", "openfga".
    fn engine(&self) -> &'static str;

    /// SHA-256 of the policy artifact backing this provider. Folded into
    /// the receipt's policy_hash. Must change whenever the policy set changes.
    fn policy_digest(&self) -> [u8; 32];

    /// Evaluate. Same shape as ExternalGuard::eval but returns rich detail.
    async fn evaluate(&self, ctx: &GuardCallContext)
        -> Result<EngineDecision, ExternalGuardError>;
}

pub struct EngineDecision {
    pub verdict: Verdict,
    pub decision_id: String,         // opaque, engine-supplied (OPA decision-id,
                                     // Cedar request-id, OpenFGA trace-id)
    pub obligations: serde_json::Value,
    pub diagnostics: Option<String>,
}
```

A blanket adapter wraps any `PolicyEngineProvider` as an `ExternalGuard`,
populating `GuardEvidence.details` from `EngineDecision`. This keeps the
existing `AsyncGuardAdapter` (circuit breaker, token bucket, cache, retry)
unchanged. Authors who need raw control still implement `ExternalGuard`
directly; the new trait is opt-in.

### Receipt semantics

For an allow verdict backed by engine `E` with policy digest `D` and decision
ID `id`:

- `ChioReceiptBody.policy_hash`
  (`crates/chio-core-types/src/receipt.rs:166`) is computed by hashing the
  concatenation of every contributing policy digest in pipeline order. This
  already accommodates multi-guard pipelines; engine providers just contribute
  another digest.
- `ChioReceiptBody.evidence`
  (`crates/chio-core-types/src/receipt.rs:169`) gets one `GuardEvidence` per
  provider: `guard_name = format!("{}:{}", engine, instance_name)`, `verdict`
  = allow/deny, `details` = JSON-encoded `{decision_id, obligations,
  diagnostics}`.
- Audits replay by: fetch policy artifact by digest, re-construct input from
  `content_hash`, re-evaluate, expect `decision_id` to differ but verdict to
  match. Decision IDs are non-deterministic (UUIDs); verdict and obligations
  must be deterministic given (policy_digest, input).

### Failure model

Default fail-closed already applies because `ExternalGuard` is the substrate:

- Engine unreachable / timeout -> `ExternalGuardError::Transient` -> retry
  -> circuit opens after threshold -> `CircuitOpenVerdict::Deny` (default at
  `crates/chio-guards/src/external/mod.rs:136`).
- Engine returns malformed response ->
  `ExternalGuardError::Permanent` -> `Verdict::Deny`, breaker untouched
  (`crates/chio-guards/src/external/mod.rs:381-398`).
- Engine rate-limited by Chio's own `TokenBucket` -> `RateLimitedVerdict::Deny`
  (default at `crates/chio-guards/src/external/mod.rs:155`).

The one new policy: **policy digest unavailable at startup -> refuse to
register the guard.** This matches the CLAUDE.md rule that invalid policies
reject at load time.

---

## Phased rollout

| Phase | Engine | Surface added | Risk |
|-------|--------|---------------|------|
| 1 | Cedar (in-process) | `CedarPolicyGuard` in `chio-external-guards`, `PolicyEngineProvider` trait, receipt evidence schema for engine decisions | Low. Pure Rust, no new transport. |
| 2 | OpenFGA (gRPC) | `OpenFgaCheckGuard`, tuple-template configuration model, short-TTL cache | Medium. New gRPC dependency, latency budget tuning. |
| 3 | OPA (regorus + REST sidecar) | `RegoPolicyGuard` enum (Embedded / Sidecar), bundle digest tracking | Medium. Rego semantics are easy to get wrong; ship with a curated rule library. |
| 4 | Tetragon (separate crate) | `chio-tetragon-bridge`: event ingestor + intent emitter | High. Privileged cluster surface, eBPF policy compilation, async coupling. |

Phase 1 is small enough to scope as a single PR. Phases 2 and 3 are each one
crate plus configuration plumbing. Phase 4 is a multi-week deliverable and
should not block 1-3.

A non-goal for all four phases: do not re-implement what the engine does.
Chio's job remains: mediate the tool call, run guards, sign a receipt. The
guards now have richer collaborators.
