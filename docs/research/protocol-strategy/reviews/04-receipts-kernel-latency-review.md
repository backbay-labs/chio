# Review 04 - Receipts, Kernel, Latency Cluster (docs 09, 15, 16)

> Reviewer scope: consistency review and codebase grounding for docs 09
> (event-action schema), 15 (current v1 receipt-kind semantics), 16 (latency budget audit),
> with cross-references into 00-overview-v2, 12, 13, 14. All citations
> verified against a local checkout.

## TL;DR

The bench-stub finding was **confirmed and broader than the doc reported (resolved in-tree).**
Every per-stage Criterion bench in `crates/chio-kernel/benches/` except
`dispatch_allow` (and `dispatch_allow_dhat`) used to be literally
`b.iter(|| black_box(0_u64))` (`single_guard.rs:8`, `cap_verify_ed25519.rs:7`,
`receipt_sign.rs:7`, `guard_pipeline_5.rs:7`); the bench-regression workflow
at `.github/workflows/bench-regression.yml:101-108` ingests **all of them**
from `Cargo.toml` and runs each through `cargo bench -p chio-kernel`. The
bench bodies now drive real dispatch through `dispatch_request_fixture`
in-tree, so CI compares real bodies for the previously-stubbed primitives;
the remaining open work is `required-features` gating per bench and
re-baselining latency claims against the new bodies. The receipt-shape and
event-action proposals in 15 and 09 ground cleanly, with three name
inconsistencies and one mislabelled file path (doc 16 cites `chio-http-core/src/responses.rs:1506-1507` for `build_and_sign_receipt`; the
function actually lives at
`crates/chio-kernel/src/kernel/responses.rs:1459-1517`).

## Verified citation table

| Claim (source) | Cited path | Verified? |
|---|---|---|
| `policy_hash` on receipt body, line 159 (doc 15 line 27, doc 00) | `crates/chio-core-types/src/receipt.rs:168` | Partial. `ChioReceiptBody` starts at line 159 but `policy_hash` is at line 168. Doc 15 also notes "168" later. |
| `GuardEvidence` at line 1176 (doc 04, doc 15 line 51) | `crates/chio-core-types/src/receipt.rs:1174-1184` | Verified. |
| Sequential hybrid signing (doc 16 line 118, 223) | `crates/chio-core-types/src/pq.rs:166-170` | Verified. `sign_bytes` calls `classical.sign_bytes` then `pq.sign_bytes` in sequence; no parallelization. |
| `single_guard.rs:8` stub | `crates/chio-kernel/benches/single_guard.rs:8` | Verified literal `black_box(0_u64)`. |
| `cap_verify_ed25519.rs:7` stub | `crates/chio-kernel/benches/cap_verify_ed25519.rs:7` (doc cites line 7, body is line 8) | Verified, off-by-one (`bench_function` is line 7, `iter` is line 8). |
| `receipt_sign.rs:8` stub | `crates/chio-kernel/benches/receipt_sign.rs:7-8` | Verified. |
| `guard_pipeline_5.rs:8` stub | `crates/chio-kernel/benches/guard_pipeline_5.rs:7-8` | Verified. |
| `dispatch_allow.rs:12-14` live | `crates/chio-kernel/benches/dispatch_allow.rs:9-14` | Verified - uses `DispatchAllowFixture::dispatch_allow_once()`. |
| CI runs benches at workflow line 108 | `.github/workflows/bench-regression.yml:108` | Verified - `cargo bench -p chio-kernel --bench "$bench"` inside a loop fed by an awk pass over `Cargo.toml`. |
| `ToolAction` variants line 16-46 (doc 09 line 14) | `crates/chio-guards/src/action.rs:16-46` | Verified. 12 variants exactly. |
| `HttpAuthority::evaluate` at line 305 (doc 16) | `crates/chio-http-core/src/authority.rs:305-339` | Verified. |
| `issue_capability` invoked at line 545 (doc 16) | `crates/chio-http-core/src/authority.rs:545` | Verified. |
| `build_and_sign_receipt` cited at `responses.rs:1506-1507` (doc 16) | **`crates/chio-kernel/src/kernel/responses.rs:1459-1517`** | **Wrong crate.** File `chio-http-core/src/responses.rs` does not exist. The kernel-side function is at the cited line range, but doc 16 names the wrong crate path. |
| `HttpReceipt::sign` at line 108-130 (doc 16) | `crates/chio-http-core/src/receipt.rs:108-130` | Verified. |
| `chio-kernel/src/dpop.rs` (doc 16, doc 03) | `crates/chio-kernel/src/dpop.rs:1-358` | Verified; chio-native invocation DPoP, schema `chio.dpop_proof.v1`. |
| `slo.md:32-36` | `docs/operator-runbook/slo.md:31-36` | Verified (p50 < 75 ms, p95 < 250 ms, p99 < 1 s). |
| `sustained_p99_30min.rs:14` `P99_WARN_MICROS = 50_000` | `crates/chio-kernel/benches/sustained_p99_30min.rs:14` | Verified. |
| `PROTOCOL.md:7-8` additive v3 | `spec/PROTOCOL.md:7-10` | Verified. |
| `PROTOCOL.md:172-180` hybrid signing | `spec/PROTOCOL.md:171-180` | Verified (Ed25519 default, `hybrid:<classical>:<pq>:<alg_set>` prefix). |
| `PROTOCOL.md:305-329` ceiling negotiation | `spec/PROTOCOL.md:305-329` | Verified. |
| `TOOL_MANIFEST_SCHEMA = "chio.manifest.v1"` line 20 | `crates/chio-manifest/src/lib.rs:20` | Verified. |
| `RequiredPermissions` at line 165 (doc 09) | `crates/chio-manifest/src/lib.rs:163-177` | Verified - struct has only `read_paths`, `write_paths`, `network_hosts`, `environment_variables`. No `event_*` fields. |
| `ToolServerConnection` trait at line 255 (task brief) | `crates/chio-kernel/src/runtime.rs:255` | Verified. |
| `ToolCallChunk` at line 109-125 (task brief) | `crates/chio-kernel/src/runtime.rs:109-125` | Verified. |
| `ToolServerStreamResult` (task brief) | `crates/chio-kernel/src/runtime.rs:134-142` | Verified. |
| RFC 8785 canonical JSON | `crates/chio-core-types/src/canonical.rs:1-12`; `spec/PROTOCOL.md:169-171` references "canonical JSON" but the literal string "8785" does not appear in `PROTOCOL.md`. | Partial - implementation file labels it RFC 8785, spec does not name the RFC. |

## Bench-stub verification (resolved in-tree)

Verified read of each cited bench file shows the stubs are literal:

```rust
// single_guard.rs
pub fn bench(c: &mut Criterion) {
    c.bench_function("single_guard", |b| {
        b.iter(|| black_box(0_u64));
    });
}
```

Identical body in `cap_verify_ed25519.rs`, `receipt_sign.rs`,
`guard_pipeline_5.rs`. Each carries a header comment "Body fills in once the
async-kernel pivot lands."

Cargo manifest enumerates the benches at
`crates/chio-kernel/Cargo.toml` lines 90-187:

- Stubs (confirmed by reading the files): `cap_verify_ed25519`, `scope_match`,
  `time_bound`, `revocation_lookup`, `budget_decrement`, `single_guard`,
  `guard_pipeline_5`, `receipt_sign`, `receipt_append`, `session_lookup`,
  `dispatch_deny`.
- Live: `dispatch_allow`, `dispatch_allow_dhat`, `hybrid_receipt_sign`,
  `compliance_certificate_hybrid`, `pq_key_load_after_self_quote`,
  `canonical_bytes_hybrid`, plus `replay_proptest`,
  `dual_track_receipt_identity`, `tokio_console_smoke` (some gated by
  `required-features`).

Doc 16 says "only `dispatch_allow` does live work" - **partly wrong.** Live
hybrid/PQ benches also exist (`hybrid_receipt_sign`,
`canonical_bytes_hybrid`, `pq_key_load_after_self_quote`,
`compliance_certificate_hybrid`). The fixable statement is "only
`dispatch_allow` measures the end-to-end allow path; primitive-stage benches
are stubs." Hybrid signing primitives are measured separately from the
Ed25519-only stage benches. Doc 16's recommendation table should explicitly
acknowledge `hybrid_receipt_sign` and avoid implying it needs to be created.

The CI workflow at `.github/workflows/bench-regression.yml:101-108` enumerates
benches with awk over `Cargo.toml`, **excluding only those with
`required-features =`**. The stub benches have no `required-features` line,
so they run on every PR. CI therefore compares "stub-vs-stub": always a
no-op, but it appears in the workflow's success record as "benches ran."

This is more material than a missing baseline. **Recommendation:** mark every
stub bench with `required-features = ["bench-stub"]` (or delete them) so CI's
listing pass skips them; or replace the bodies before next merge.

## Receipt-shape audit (current vs proposed v3)

Current `ChioReceiptBody` (`receipt.rs:158-181`), 13 fields:

| Field | Type | Notes |
|---|---|---|
| `id` | `String` | Doc 15 keeps. |
| `timestamp` | `u64` | Doc 15 keeps. |
| `capability_id` | `String` | Doc 15 keeps. |
| `tool_server` | `String` | Doc 15 keeps. |
| `tool_name` | `String` | Doc 15 keeps. |
| `action` | `ToolCallAction` | Doc 15 keeps; doc 09 wants additional `event_decision` block. |
| `decision` | `Decision` | Doc 15 keeps. |
| `content_hash` | `String` | Doc 15 keeps. |
| `policy_hash` | `String` | Doc 15 keeps **and** adds `policy_digest: [u8; 32]` alongside. See conflict note below. |
| `evidence` | `Vec<GuardEvidence>` | Doc 15 keeps. |
| `metadata` | `Option<Value>` | Doc 15 **removes** (replaced by typed extensions). Doc 09 wants to lodge `event_decision` here on v2 path. Conflict, see below. |
| `trust_level` | `TrustLevel` | Doc 15 keeps. Doc 15 open question 4 flags overlap with `tool_origin`. |
| `tenant_id` | `Option<String>` | Doc 15 keeps. |
| `kernel_key` | `PublicKey` | Doc 15 keeps. |

Doc 15's proposed v3 additions are a clean additive extension on top of v2.
No proposed field name collides with an existing v2 field. The conflict
points are semantic:

1. **`policy_hash` vs `policy_digest`.** v2 has `policy_hash: String` (hex
   SHA-256). Doc 15's v3 keeps `policy_hash` and adds
   `policy_digest: [u8; 32]`. Doc 04 (`04-policy-engine-collaborators.md:154`)
   treats `policy_hash` as the aggregation of multiple engine digests, with
   per-engine `policy_digest` carried in evidence/extension. **Doc 15 should
   be explicit that `policy_hash` is "Chio kernel policy hash" (aggregator)
   and `policy_digest` is the optional first-engine raw digest** - otherwise
   the two fields collide on meaning.
2. **`metadata` removal vs doc 09's v2 piggyback.** Doc 09 line 154-179
   proposes putting an `event_decision` block inside
   `ChioReceiptBody.metadata` on v2 and promoting to a typed sibling on v3.
   Doc 15 removes `metadata` entirely from the v3 body. Reconcile: either
   keep `metadata` as a v3 deprecation-window field or have doc 09's
   `event_decision` arrive only via the v3 extensions map
   (`extensions["events"] = EventDecisionExtension`).
3. **`GuardEvidence::details` is `Option<String>`** (`receipt.rs:1183`), not
   structured. Docs 04 and 10 want JSON-encoded
   `{decision_id, obligations, diagnostics}` inside `details`. v3 should
   either widen `details` to `Option<Value>` or rely entirely on the Cedar
   extension. **Pick one; doc 04, 10, and 15 currently all overlap here.**
4. **`extensions_hash` placement.** Doc 15 line 308 keeps it in the body for
   signing. The trade-off is real: hashing the extension blob doubles canonical-JSON
   work (one over extensions, one over body). Doc 15 open-question 7
   correctly flags this for X2 (doc 16) reconciliation - which doc 16 does
   **not** address. The two docs should not ship without a coordinated
   decision.

## Cross-doc field-name consistency

| Concept | Doc 12 (OpenAI) | Doc 13 (Bedrock) | Doc 14 (Voice) | Doc 15 (v3) | Doc 00 v2 |
|---|---|---|---|---|---|
| `tool_origin` enum variants | `HostExecutedProviderReported {...}`, `HostExecutedUnmediated`, `CallerExecuted` (doc 12 line 152-155); also `"host-executed-unmediated"` string form (doc 12 line 145) | not used by name; "Lambda action group" stand-in | not used | `HostExecutedUnmediated | HostExecutedProviderReported | CallerExecuted` (line 121, 429-431) | core v3 field; "caller-executed", "host-executed-provider-reported", "host-executed-unmediated", **`host-executed-redacted`** (overview v2 line 35) |
| `engine_id` | n/a | n/a | n/a | core v3 field, `String` | core v3 field |
| `policy_digest` | n/a | n/a | n/a | `[u8; 32]`, core v3 + on `CedarExtension` | per doc 04 / doc 10 - `[u8; 32]` on a per-engine `EngineDecision` |
| `actor_chain` | n/a | n/a | n/a | core v3 (`Vec<ActorRef>`) | core v3 |
| `extensions_hash` | n/a | n/a | n/a | core v3 (`[u8; 32]`) | core v3 |
| `decision_id` | n/a | n/a | n/a | optional core v3 + on Cedar ext | per doc 04 - engine-supplied (UUIDv4 for Cedar, OPA's `decision_id`) |
| Deferred durability | n/a | n/a | "deferred durability status flag in v3" (doc 14 line 135) | not mentioned anywhere | not in overview |

**Issues to fix:**

1. **`tool_origin` variant set is inconsistent across docs.** Doc 12 and doc
   15 define **three** variants; overview v2 line 35 adds a fourth
   (`host-executed-redacted`). Pick three or four; pick a single casing
   (`HostExecutedUnmediated` or `host-executed-unmediated`); reflect in
   `00-overview-v2.md`, `12-openai-responses-adapter.md`, `13-bedrock-agents-bridge.md`,
   and `15-receipt-kind-v1.md` in lockstep.
2. **`tool_origin` placement.** Overview v2 says "core v3 field, not an
   extension." Doc 15 puts it on `OpenaiResponsesExtension` only (line
   429-431) and explicitly recommends extension over core (line 502-508).
   These two docs disagree on the highest-impact field. **Resolve in
   overview v2.**
3. **Deferred durability flag.** Doc 14 (line 135) says X1 owes a "deferred
   durability status flag in v3." Doc 15 does not mention it. Add either to
   the core body (as a `durability: Durability::Deferred | Persisted | Mirrored`
   field) or to a `voice` / `durability` extension. Spec the shape; today
   it is a phrase, not a type.

## Other findings

5. **`pq.rs:166-170` parallelization.** Verified strictly sequential. Doc
   16's claim is correct. There's a real win from `rayon::join` or
   `tokio::join!` on the two halves - **but** ML-DSA-65 dominates by
   roughly 5x over Ed25519, so the parallelization upper bound is
   `max(50us, 250us) = 250us` rather than the sum, saving ~50-100us as
   doc 16 estimates. Worth pursuing only if the steady-state hybrid budget
   is tight.

6. **`ToolAction` extension for events fits cleanly.** Adding `EventPublish`
   and `EventConsume` variants to `ToolAction` (currently 12 variants,
   `action.rs:16-46`) is purely additive. `extract_action()` is a
   non-exhaustive match returning `ToolAction::Unknown` or
   `ToolAction::McpTool(...)` as fallback (line 350-357), so callers depend
   on `match` arms only by name. No existing `BrokerKind` type appears in
   the workspace - safe to introduce in `chio-core-types`. Confirm by
   grep: no top-level `BrokerKind` definition exists today.

7. **Manifest schema version is `chio.manifest.v1`** at line 20, exactly as
   doc 09 claims. `validate_manifest` enforces equality at line 237-239.
   `deny_unknown_fields` is on `ToolManifest` at line 24. PR 652 later folded
   event-action planning into current v1 manifest work because Chio is
   unreleased, so there is no pre-release manifest compatibility negotiation
   to add before implementation.

8. **HTTP path 3-signs + 1-verify count is correct.** Each cited location
   performs a sign or verify:

   - `validate_presented_capability` at `authority.rs:780-782` calls
     `token.verify_signature()`. **One verify.**
   - `kernel.issue_capability(...)` at `authority.rs:545` reaches
     `chio-store-sqlite/src/authority.rs:613` `CapabilityToken::sign(body,
     &keypair)`. **One sign.** (Inner capability for kernel self-issue.)
   - `kernel.evaluate_tool_call_blocking_with_metadata` at
     `authority.rs:596` reaches kernel `build_and_sign_receipt` at
     `chio-kernel/src/kernel/responses.rs:1507` calling
     `chio_kernel_core::sign_receipt(body, &backend)`. **One sign.**
   - `HttpAuthority::sign_decision_receipt -> HttpReceipt::sign` at
     `chio-http-core/src/receipt.rs:111` calls
     `keypair.sign_canonical(&body)`. **One sign.**

   Total: **3 sign + 1 verify**, exactly as doc 16 line 12-13 claims. The
   only path nit is doc 16 line 58 attributes
   `build_and_sign_receipt` to `chio-kernel/src/kernel/responses.rs:1459-1517`
   (which is correct), but earlier on line 125 the doc cites
   `responses.rs:1506-1507` without the `chio-kernel/` qualifier. **Edit
   doc 16 line 125 to fully qualify the path.**

9. **DPoP duplication is real and intentional.** Two distinct surfaces:

   - Chio-native invocation DPoP at `crates/chio-kernel/src/dpop.rs:1-358`,
     schema `chio.dpop_proof.v1` (line 45). Binds capability_id +
     tool_server + tool_name + action_hash + nonce + issued_at.
   - RFC 9449 JWT DPoP at the HTTP edge - **not yet implemented.** Doc
     03 line 28-30, 130 confirms the gap; the DPoP boundary contract in
     `spec/PROTOCOL.md` is the action plan. Doc 16's mention is correct
     but should explicitly say "the chio-native one ships; RFC 9449 is
     the HTTP-edge end state." Without that, the reader can't square doc
     03's "needs adding" with doc 16's "already exists."

10. **Extensions map well-typedness for verify-without-understand.** Doc 15
    line 351 has `ExtensionPayload::Unknown(serde_json::Value)` as the
    forward-compat slot. That suffices for "preserve bytes and re-sign"
    but **does not let a verifier check `extensions_hash`** without
    canonicalizing the unknown payload - which requires the verifier to
    re-canonicalize a `serde_json::Value` whose key order it didn't
    control. RFC 8785 sort fixes that as long as the verifier uses Chio's
    `canonical_json_bytes`. Doc 15 should state explicitly: **unknown
    extensions still canonicalize via RFC 8785, so `extensions_hash` is
    verifiable without knowing the kind.** Doc 15 line 248-253 alludes to
    this; make it normative.

11. **Cedar 150 us claim.** Doc 16 line 196 ("< 150 us with entity cache")
    is a sum-of-parts estimate (10-30 us entity assembly + 30-80 us
    `is_authorized` + 10-30 us LRU). It is **not** a published Cedar
    bench number. Doc 16 line 141 links to the cedar-policy repo but
    doesn't pull a specific bench. **Pull a real `cedar-policy` bench
    artifact for the small-policyset case** (doc 16 calls for
    `cedar_authorize_small_policyset`; that's the right deliverable but it
    doesn't exist yet). The 150 us number is plausible but should be
    labelled "estimate" not "expected."

12. **Federation negotiation pattern fits.** `chio.capabilities.v1`
    (`PROTOCOL.md:286-303`) already advertises `accepts_receipt_v2`. Adding
    `accepts_receipt_v3` and `accepts_ext.<namespace>` is mechanically
    identical. The ceiling-negotiation theorem at
    `formal/lean4/Chio/Chio/Proofs/HandshakeNegotiation.lean` (cited by doc
    15) needs the v3 analog as flagged. No risk to existing semantics.

## Recommended edits per doc

**Doc 09 (event-action schema):**
- Line 208: explicitly add a `chio.capabilities.v1` feature
  `accepts_manifest_v2` and a `max_manifest_schema` ceiling alongside
  `max_capability_schema`. Without this, the ceiling-negotiation glue is
  one-way.
- Resolve the receipt-embedding direction. Doc 15's recommendation is to
  put `event_decision` in `extensions["events"]` on v3 and **not** to use
  `metadata` on v2 (doc 15 removes `metadata`). Pick one path and update
  doc 09 lines 151-179 to match.

**Doc 15 (current v1 receipt-kind semantics):**
- Promote `tool_origin` to a current v1 core body field per overview v2 line
  14, OR edit overview v2 to demote it back into the extensions map. The two
  docs currently disagree on the highest-impact field.
- Add the deferred-durability flag (doc 14 line 135) - spec the shape
  (`durability: Persisted | DeferredQueued | Mirrored`) and choose body
  vs extension placement.
- Clarify `policy_hash` (kernel aggregate) vs `policy_digest` (per-engine
  raw) per doc 04 vs doc 15.
- Widen or remove `GuardEvidence::details: Option<String>` if doc 04 / 10
  evidence shapes are normative.
- Make "extensions_hash is verifiable without understanding `kind`"
  normative (doc 15 line 248 alludes; promote to spec language).

**Doc 16 (latency audit):**
- Correct `chio-http-core/src/responses.rs:1506-1507` (line 125) to
  `chio-kernel/src/kernel/responses.rs:1506-1517`. The file as written
  does not exist; the function does, in the kernel crate.
- Acknowledge live hybrid benches (`hybrid_receipt_sign`,
  `canonical_bytes_hybrid`, `pq_key_load_after_self_quote`,
  `compliance_certificate_hybrid`) - doc 16's table at lines 251-260
  treats some of these as "needs creation."
- Document the **CI-runs-stubs** issue explicitly. Today CI compares
  stub-vs-stub for 10+ benches and reports success. Recommend either
  `required-features = ["bench-stub"]` gating or deletion of the stub
  files.
- Reconcile the `extensions_hash` indirection cost with doc 15 open
  question 7.
- Tag the 150 us Cedar estimate as engineering-estimate, not benchmark.

---

## Three-line summary

1. Bench-stub claim **verified, and worse**: CI ingests every bench from
   `crates/chio-kernel/Cargo.toml` (workflow line 101-108) and runs the
   stubs along with the live ones, so the regression check is comparing
   `black_box(0_u64)` to itself for 10+ supposed primitives.
2. Most consequential ungrounded citation: doc 16 line 125 attributes
   `build_and_sign_receipt` to `chio-http-core/src/responses.rs:1506-1507`
   - that file does not exist; the function lives at
   `crates/chio-kernel/src/kernel/responses.rs:1459-1517`.
3. Path:
   this file.
