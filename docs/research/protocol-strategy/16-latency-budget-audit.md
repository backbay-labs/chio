# 16 - Chio Hot-Path Latency Budget Audit

> Task X2. Coordinates with E3 (voice agents, sub-200ms budget) and R4 (Cedar
> first-guard, engine overhead). Code paths are cited repo-relative. Numbers
> labeled (measured) come from existing benches; the rest are engineering
> estimates from primitive costs and code structure.

> **Erratum (resolved in-tree):**
> - **Bench-stub coverage was broader than reported below.** A subsequent verification pass ([reviews/04-receipts-kernel-latency-review.md](reviews/04-receipts-kernel-latency-review.md)) confirmed **11+ stubs**, not 4: `single_guard`, `cap_verify_ed25519`, `receipt_sign`, `guard_pipeline_5`, `scope_match`, `time_bound`, `revocation_lookup`, `budget_decrement`, `receipt_append`, `session_lookup`, `dispatch_deny` were all `b.iter(|| black_box(0_u64))`. The bench bodies now drive real dispatch through `dispatch_request_fixture` rather than constants. The hybrid family (`hybrid_receipt_sign`, `canonical_bytes_hybrid`, `pq_key_load_after_self_quote`, `compliance_certificate_hybrid`) is still wired as tests, not live Criterion benches; do not cite those names as benchmark evidence until they are added to the bench target set. The remaining open work in this area is gating benches with `required-features` per bench file.
> - **`build_and_sign_receipt` path was wrong.** Below this doc cites `crates/chio-http-core/src/responses.rs:1506-1507`; the actual location is [`crates/chio-kernel/src/kernel/responses.rs:1459-1517`](../../../crates/chio-kernel/src/kernel/responses.rs#L1459). Several other `responses.rs` references in this doc omit the `chio-kernel/src/kernel/` crate qualifier.

## TL;DR

The HTTP verdict path on a warm in-process configuration is dominated by
**three Ed25519 signatures + one verify** (capability verify, kernel
self-issued inner capability, kernel receipt sign, outer HttpReceipt sign),
two canonical-JSON passes, and a projection guard. Best estimate for
Ed25519-only path: **median ~2-4 ms, p99 ~10-20 ms** with no external guards.
The shipped pilot SLO is p50 < 75 ms / p95 < 250 ms / p99 < 1 s
(`docs/operator-runbook/slo.md:32-36`) and the sustained nightly probe warns at
p99 = 50 ms (`crates/chio-kernel/benches/sustained_p99_30min.rs:14`).
Voice integration at sub-200ms is **conditional**: feasible with Ed25519-only,
in-process guards (Cedar), and async receipt write; infeasible with hybrid
Ed25519+ML-DSA-65 plus OpenFGA Check plus synchronous SQLite persistence in
the same call. The single biggest historical finding -- **almost every per-stage bench was a
`black_box(0_u64)` placeholder** (`single_guard.rs:8`, `cap_verify_ed25519.rs:7`,
`receipt_sign.rs:8`, `guard_pipeline_5.rs:8`) while only `dispatch_allow` did live
work (`dispatch_allow.rs:12-14`) -- is resolved in-tree: the bench bodies now
drive real dispatch through `dispatch_request_fixture`. The remaining work is
gating benches with `required-features` per bench file so a per-stage latency
budget in CI is built on the new bodies.

## Hot-path trace

For an HTTP bridge request through `HttpAuthority::evaluate`
(`crates/chio-http-core/src/authority.rs:305-339`):

1. HTTP frame parse, routing (outside Chio).
2. `CallerIdentity` extraction (`crates/chio-http-core/src/identity.rs:43-65`).
3. `identity_hash()`: canonical JSON + SHA-256
   (`identity.rs:82-85`).
4. `validate_presented_capability` when a token is supplied
   (`authority.rs:654-714`): JSON parse, `trusted_issuers.contains`,
   `verify_signature()`, `validate_time`, optional scope match
   (`authority.rs:797`).
5. `ChioHttpRequest::content_hash()` (`authority.rs:378`).
6. Kernel self-issue and dispatch: `HttpAuthority::authorize_via_kernel`
   (`authority.rs:532-598`). This issues a **fresh** Chio capability via
   `self.kernel.issue_capability(...)` (line 545), plans a cross-protocol
   route, then calls `evaluate_tool_call_blocking_with_metadata` (line 595).
7. Kernel pre-admission in
   `ChioKernel::evaluate_tool_call_async_with_session_context`
   (`crates/chio-kernel/src/kernel/mod.rs:3299-3460`): tenant resolution,
   emergency-stop, receipt-version admission, capability verify, time bounds,
   revocation, delegation, subject binding.
8. Guard chain. `HttpAuthority` registers one in-process guard,
   `HttpProjectionGuard` (`authority.rs:283`). External guards loaded via
   `AsyncGuardAdapter` add their own pipeline
   (`crates/chio-guards/src/external/mod.rs:308`).
9. Tool-server invocation of the inner authorization probe
   (`authority.rs:179-192`).
10. Kernel receipt sign via `build_and_sign_receipt`
    (`crates/chio-kernel/src/kernel/responses.rs:1459-1517`). Ed25519-only
    unless `with_hybrid_signing_backend` is configured (`mod.rs:1213`).
11. Outer `HttpReceipt::sign` (`crates/chio-http-core/src/receipt.rs:108-130`),
    a second canonical JSON + Ed25519 sign.
12. Response return (outside Chio).

So the steady-state allow path does **three Ed25519 signs** (inner-capability
issue, kernel receipt, outer receipt) plus one verify on the presented
capability. None of the placeholder benches measure this.

### Bridge variants

- `chio-envoy-ext-authz` synthesizes a `http.<method>.<path>` tool identity
  and runs the same `ToolServerConnection.invoke` shape
  (doc 06 line 13). Same path as 1-12, no outer signature.
- `chio-mcp-edge`, Bedrock/Anthropic tool adapters call
  `ChioKernel::evaluate_tool_call` directly; skip the
  `validate_presented_capability` re-verify and the outer `HttpReceipt::sign`.
- Voice bridges (doc 14: LiveKit, Pipecat, Vapi, Retell) sit between the LLM
  tool-call frame and `evaluate_tool_call`; closest to the direct MCP path.

## Existing benchmarks

- Real: `dispatch_allow` (`benches/dispatch_allow.rs:1-19`). End-to-end
  `evaluate_tool_call` on a current-thread tokio runtime, one in-process tool
  server, no registered guards (`dispatch_request_fixture.rs:21-50`). This is
  the artifact CI compares for regressions
  (`.github/workflows/bench-regression.yml:108`).
- Real: `chio-core/benches/core_primitives.rs` covers Ed25519
  `signature_verification`, `canonical_json_bytes`, Merkle tree
  build/prove/verify (1024 leaves), full `capability_validation_path`
  (`core_primitives.rs:177-265`).
- Real: `chio-store-sqlite/benches/store_receipt_write_throughput.rs` runs
  8 appender threads at 64 receipts/batch (lines 10-11).
- Stubs (still `black_box(0_u64)`): `single_guard`, `cap_verify_ed25519`,
  `guard_pipeline_5`, `receipt_sign`, `dispatch_deny`, `budget_decrement`,
  `revocation_lookup`, `scope_match`, `session_lookup`, `time_bound`,
  `receipt_append`. The README labels these as placeholders for the
  async-kernel pivot (`benches/single_guard.rs:2`).
- Synthetic p99 probe: `sustained_p99_30min` runs an in-process
  queue+exporter loop with `P99_WARN_MICROS = 50_000` (50 ms)
  (`sustained_p99_30min.rs:14, 48-50`). It does not drive `evaluate_tool_call`.
- `bench/healthcare-pilot-capacity/` is a CapacityReport scaffold, not a
  runtime measurement. `bench/ttfrh/` is reserved scaffolding for a future
  provider latency study.

In-process histogram buckets in `chio-http-core/src/metrics.rs:67-76` are
25 / 50 / 75 / 100 / 250 / 500 / 1000 / 2500 ms, consistent with the pilot
SLO (`docs/operator-runbook/slo.md:32-36`).

## Per-stage estimates

Warm-cache, in-process, single-core (desktop x86_64 or Apple Silicon class).
Anything not labeled (measured) should be re-measured before being put in an
SLA.

| Stage | Estimate | Notes |
|---|---|---|
| HTTP framing + routing | 50-200 us | Framework, not Chio. |
| `identity_hash` | 5-15 us | Small canonical JSON + SHA-256. |
| `validate_presented_capability` (V1 Ed25519) | 100-300 us | One Ed25519 verify (50-100 us with `ed25519-dalek`) plus JSON parse and time/issuer checks (`authority.rs:769-812`). |
| Hybrid capability verify (Ed25519 + ML-DSA-65) | 250-500 us | ML-DSA-65 verify ~100-150 us; both halves serialize through `Signature::from_hybrid_parts` (`crates/chio-core-types/src/pq.rs:166-170`); **sequential** today. |
| `content_hash` | 20-100 us | Canonical JSON + SHA-256 over request metadata; body-size dependent. |
| `kernel.issue_capability` (inner) | 100-200 us | Ed25519 sign + canonical JSON. |
| `plan_authoritative_route` | 20-80 us | In-mem route-table lookup + metadata serialize. |
| Kernel pre-admission | 100-300 us | Emergency-stop, admission, time/revocation/subject/delegation checks (`mod.rs:3320-3460`). |
| `HttpProjectionGuard::evaluate` | 5-15 us | JSON deserialize + match (`authority.rs:201-225`). |
| Inner tool-server invoke | 5-20 us | JSON construction. |
| `build_and_sign_receipt` (Ed25519) | 100-200 us | Canonical JSON + Ed25519 sign (`responses.rs:1506-1507`). |
| Hybrid kernel receipt | 350-600 us | Ed25519 (~50-100 us) + ML-DSA-65 sign (~250-400 us), sequential. |
| `HttpReceipt::sign` (outer) | 100-200 us | Second canonical JSON + Ed25519 sign. |
| Receipt persistence, sync SQLite | 1-10 ms | WAL fsync dominates; pilot p95 target 100 ms (`slo.md:36`). |
| Receipt persistence, in-mem ring | 5-30 us | Ring buffer push only. |

Summed for the Ed25519-only HTTP allow path with no external guards:
**~600 us to ~1.5 ms of CPU** plus persistence. Hybrid on both signatures:
**~1.5-2.5 ms of CPU** plus persistence. Doc 14 cites Ed25519 sign ~25 us and
hybrid ~150-225 us (E3 sourced from published ML-DSA-65 numbers), consistent
with the lower end of the range here.

External guards change the picture:

| Guard class | Per-call overhead | Source |
|---|---|---|
| In-process Cedar | 30-150 us | Cedar published benches at https://github.com/cedar-policy/cedar; doc 04 claims sub-microsecond which is optimistic. |
| In-process Rego (regorus) | 200 us-2 ms | Per doc 04. |
| Sidecar OPA REST | 1-5 ms | Loopback HTTP + JSON. |
| OpenFGA `Check` gRPC | 5-50 ms | Network + tuple-store lookup. |
| External LLM-judge guard | 100 ms-5 s | Out of voice tier scope. |
| `AsyncGuardAdapter` cache hit | 10-30 us | LRU + clock check (`mod.rs:175-207`); default 1024 entries, 60 s TTL. |

## Voice budget feasibility (E3 reconciliation)

E3 needs sub-200 ms end-to-end including network. A plausible split:

- Audio/LLM round trip: 50-120 ms (out of Chio's control).
- Network in+out for the Chio sidecar (loopback or in-VPC): 1-5 ms per leg.
- Chio verdict CPU + persistence: must be <= 50 ms p99 to leave headroom.

That works for Ed25519-only signing, in-process guards (Cedar, jailbreak,
manifest), async receipt persistence, and cache hits within the 60 s adapter
TTL. It does **not** work as a default for OpenFGA Check on every call, for
external LLM-judge guards, or for hybrid signing on both signatures with
synchronous persistence (already pushes p99 to 5-10 ms of CPU before SQLite
WAL fsync, and pilot p95 receipt-write target is 100 ms).

Recommended SLO classes:

- **Voice tier** (sub-200 ms end-to-end). Hard caps: Ed25519-only, in-process
  guards only, async receipt write to an in-mem ring with bounded-loss SLO.
  No OpenFGA, no remote OPA, no LLM judges. Cedar OK. Bridges should call
  `evaluate_tool_call` directly; the double-sign `HttpAuthority` path is too
  heavy for voice.
- **Standard tier** (matches `slo.md:32-36`, p50 < 75 / p95 < 250 / p99 < 1000).
  Sidecar OPA permitted, OpenFGA permitted, hybrid permitted, synchronous
  persistence permitted.
- **Audit tier** (compliance, no latency budget). Hybrid required,
  synchronous persistence, all guards on.

Per-bridge documentation should record which tier each ships under by
default; `HttpAuthority` today is standard, not voice, because of the double
sign and the per-request `issue_capability`.

## Cedar overhead estimate (R4 reconciliation)

Cedar in-process is the doc 04 pick
(`04-policy-engine-collaborators.md:200-201`). For small policysets
(single-digit policies, one principal/action/resource) `is_authorized` is in
the 20-80 us range on a modern x86_64 core; schema validation runs at policy
load. For Chio wired through an `ExternalGuard` blanket impl, realistic
per-evaluation overhead:

- Entity assembly from `GuardContext`: 10-30 us if pre-cached, 100+ us if
  rebuilt per call. **Cache `Entities` per agent/capability and invalidate on
  issuance or revocation** (doc 04 line 185-187).
- Cedar `is_authorized`: 30-80 us, growing roughly linearly with policy count.
- `AsyncGuardAdapter` LRU + TTL: 10-30 us.

A `CedarPolicyGuard` hot evaluation should sit at **< 150 us** after warmup,
invisible inside the voice budget.

## Double-gating overhead (doc 05 reconciliation)

Doc 05 calls for two gates: `ToolServerConnection`
(`crates/chio-kernel/src/runtime.rs:255`) and the narrower `HttpEgressContract`
(`crates/chio-egress-contract/src/lib.rs:15`). The egress gate is **not** a
second sign+verify cycle; `HttpEgressContract::enforce_url` is a pure-Rust
allowlist + URL parse (scheme, authority set, redirect chain, response byte
cap, DNS-resolution policy) per doc 05 line 39-43. Estimated 20-80 us per
call, dominated by URL parse. **Double-gating is functionally free on the
latency budget.** The real risk is forgetting to wire one of the two gates
(doc 05 line 257-258).

## Optimization candidates (ranked by ROI)

1. **Async receipt write to a bounded ring buffer**. Sync sign + canonical
   JSON stay on the hot path; SQLite write moves to a tokio task with bounded
   queue. Mitigation for crash-loss: window-fsync (every 200 ms or N
   receipts), expose `chio_receipts_inflight` gauge, alert on depth. Expected
   gain: 1-10 ms off p95.
2. **Skip outer `HttpReceipt::sign` when in-VPC** and let the kernel receipt
   stand as the canonical artifact. Removes the second sign + canonical JSON
   (~150-250 us per request, more on hybrid). Opt-in `voice_tier` toggle on
   `HttpAuthority`. Needs a version flag for Envoy/auditors that consume the
   outer receipt header.
3. **Pipelined hybrid signing**. Today `HybridBackend::sign_bytes` runs
   Ed25519 then ML-DSA-65 sequentially (`crates/chio-core-types/src/pq.rs:166-170`).
   Run them concurrently on a rayon pool. Saves ~50-100 us per hybrid sign.
   Watch thread-pool contention under load.
4. **TTL cache for capability verification**, keyed by token hash + issuer
   set. Default `AsyncGuardAdapter` shape (1024 / 60 s) is a fine template.
   Strict invalidation on revocation.
5. **Pre-warm guard state at boot**: load Cedar PolicySet + Entities, warm
   the SQL parser, prime the revocation view. Kills cold-start spikes that
   today land in the 50-75 ms bucket.
6. **Skip ML-DSA on voice tier**. PQ is a tail-risk hedge for archival;
   voice calls last < 5 min and an ephemeral non-PQ receipt has negligible
   exfiltration value. Operator-configurable, off by default, documented as a
   trade-off.
7. **Per-bridge fast paths**. A voice bridge could call `evaluate_tool_call`
   directly with a leaner request, saving the inner `issue_capability` +
   `plan_authoritative_route` (~150-300 us). Audit risk: fast paths fragment
   the shared evaluator. Mitigation: extract a shared `evaluate_inner` so the
   voice and HTTP paths share the same kernel call.
8. **Streaming canonical JSON** that hashes inline; saves an allocation per
   sign. Expected gain < 30 us. Lower priority.

## CI / benchmark recommendations

The placeholder benches need bodies. Minimal Criterion suite to land before
R4 (Cedar) and E3 (voice) ship:

| Bench | Measures | Why |
|---|---|---|
| `cap_verify_ed25519` | Ed25519 `verify_capability_full` | Previously a stub (resolved in-tree); required for base verify cost. |
| `cap_verify_hybrid` (new) | Ed25519+ML-DSA-65 verify | Quantifies PQ tax. |
| `single_guard` | One in-process guard end-to-end | Required by R4. |
| `guard_pipeline_5` | 5-guard chain | Tail under realistic stacking. |
| `cedar_authorize_small_policyset` (new) | Cedar `is_authorized` with 5 policies | R4 owns, cite in their doc. |
| `receipt_sign_ed25519` | Ed25519 sign + canonical JSON | Historically a stub (resolved in-tree). |
| `receipt_sign_hybrid` | Hybrid sign | Voice vs standard delta. |
| `canonical_json_receipt_body` | RFC 8785 over a realistic body | Catches body-bloat regressions. |
| `http_authority_allow_full` (new) | End-to-end `HttpAuthority::evaluate`, warm | The single number operators care about. |
| `http_authority_deny_full` (new) | Capability-invalid deny path | Deny skips kernel dispatch; cost should be lower. |

The existing `bench-regression` workflow already runs
`cargo bench -p chio-kernel --bench "$bench" -- --noplot --sample-size 100`
(`.github/workflows/bench-regression.yml:108`); the stub bodies have been
replaced with real dispatch bodies in-tree, so the remaining CI work is
gating benches with `required-features` per bench file.

Also recommended: wire **per-stage tracing spans** that feed child histograms
into the existing `chio_kernel_decision_latency_seconds`
(`crates/chio-http-core/src/metrics.rs:158-165`):
`chio_cap_verify_seconds`,
`chio_guard_chain_seconds{guard="..."}`,
`chio_receipt_sign_seconds{algorithm="..."}`,
`chio_receipt_persist_seconds`. Makes per-stage attribution observable in
production, not just in bench.

## Open questions

1. **Real p50/p99 for `dispatch_allow`** on the CI reference runner. The bench
   exists and runs in `bench-regression`; the absolute number is not in any
   doc this audit found. Pull the most recent CI artifact and publish in the
   runbook.
2. **ML-DSA-65 sign/verify wall time** on the deployment fleet. Apple Silicon
   and Graviton differ from x86_64; the 250-400 us estimate is x86_64.
3. **SQLite WAL fsync p99** under the 5x replay load modeled by
   `bench/healthcare-pilot-capacity/`. Required to validate "async write".
4. **Cedar entity-cache invalidation cost** when capability issuance is
   frequent. Cache hit rate determines whether the < 150 us hot path holds.
5. **Cross-bridge cost variance**. Envoy ext_authz, MCP edge, hosted MCP, and
   `HttpAuthority` go through different paths. No bench measures the
   non-`HttpAuthority` bridges today.
6. **Cold start**. Kernel boot loads trusted issuer keys, runs persistence
   negotiation, optionally derives PQ keys (`mod.rs:1213-1226`). First-request
   latency is likely 10x+ steady state; per-call voice sessions need a
   warm-pool strategy.
7. **`AsyncGuardAdapter` cache hit rate** in production. Default 1024 / 60 s
   may need tenant-aware tuning.

---

**3-line summary**

1. Estimated median verdict latency: **~2-4 ms Ed25519-only, ~6-10 ms hybrid**
   on the HTTP-authority path, dominated by three signatures plus capability
   verify; no real per-stage bench exists in CI today.
2. Voice (sub-200 ms): **conditional** (yes with Ed25519, in-process guards
   like Cedar, async receipt write, and per-bridge fast paths; no with hybrid
   plus remote guards plus synchronous SQLite).
3. Path: `docs/research/protocol-strategy/16-latency-budget-audit.md`.
