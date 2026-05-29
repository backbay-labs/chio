# Review swarm synthesis

> **Status: errata applied.** All 11 numbered errata below have landed as documentation edits:
>
> - **#1 n8n Chain D / Chain C** corrected in [05](../05-workflow-orchestrator-mediation.md), [00-overview](../00-overview.md), [00-overview-v2](../00-overview-v2.md).
> - **#2 bench-stub count + responses.rs path** corrected in [16](../16-latency-budget-audit.md), [00-overview-v2](../00-overview-v2.md).
> - **#3 `human_principal` typed twice** canonicalized: typed enum on `CallerIdentity` in [14](../14-voice-agent-bridges.md); receipt extension in [15](../15-receipt-kind-v1.md) references by canonical encoding.
> - **#4 `ActorRef` undefined** addressed: definition stub added to [15](../15-receipt-kind-v1.md) erratum block.
> - **#5 `policy_hash` String vs `[u8; 32]`** canonicalized to hex `String` in [04](../04-policy-engine-collaborators.md), [15](../15-receipt-kind-v1.md), [00-overview](../00-overview.md), [00-overview-v2](../00-overview-v2.md).
> - **#6 `tool_origin` enum drift** was initially canonicalized to include `HostExecutedRedacted`, then PR 652 review split execution origin from redaction policy. Current planning default: `CallerExecuted | HostExecutedProviderReported | HostExecutedUnmediated` plus separate signed redaction mode; see [18](../18-decision-packet.md).
> - **#7 `chio-bridge-*` prefix** struck in favor of `-adapter` convention across overviews and superseded `chio-bridge-agntcy` per erratum #10.
> - **#8 three-ACPs warning** restored in [00-overview-v2](../00-overview-v2.md); doc 02 `chio-bridge-acp` references covered by erratum at top of doc 02.
> - **#9 em dashes** removed from both overview docs (verified zero across all 26 docs in this directory).
> - **#10 AGNTCY ACP archival** captured in [17](../17-agntcy-revisited.md); doc 08 marked SUPERSEDED; doc 02 has erratum; build queue updated in both overviews.
> - **#11 PR 652 follow-up grounding** captured in [18](../18-decision-packet.md): `policy_version` / `manifest_id` are not current receipt fields, `args_schema` is design shorthand rather than current `SkillStep` shape, and manifest event-action planning is folded into current v1 manifest work before release.

## Context

Six review agents audited the 17 research docs in `docs/research/protocol-strategy/` for cross-doc consistency and codebase grounding. Each cluster verified file:line citations against the real code, cross-checked field names and trait shapes, and flagged contradictions. Reviews live in this directory:

- [01-identity-credentials-review.md](01-identity-credentials-review.md)
- [02-bridges-consistency-review.md](02-bridges-consistency-review.md)
- [03-policy-guards-review.md](03-policy-guards-review.md)
- [04-receipts-kernel-latency-review.md](04-receipts-kernel-latency-review.md)
- [05-egress-orchestrator-review.md](05-egress-orchestrator-review.md)
- [06-vision-non-goals-review.md](06-vision-non-goals-review.md)

## TL;DR

Verdict: **historical mixed-clean, now superseded for planning**. The review
swarm found a well-grounded corpus plus several inconsistencies that have
since been corrected or moved into explicit ADR gates. The active reviewer
entry point is now [18-decision-packet.md](../18-decision-packet.md), with
[00-overview-v2.md](../00-overview-v2.md) as the plan of record.

## Verified claims (high confidence)

These claims hold up under code grounding. They can be cited downstream without re-verification.

- **chio-streaming Python SDK** exists at `sdks/python/chio-streaming/`, 5013 LOC across 12 modules. All seven brokers from doc 01 confirmed: Kafka top-level `middleware.py` plus per-broker `nats.py`, `pulsar.py`, `eventbridge.py`, `pubsub.py`, `redis_streams.py`, `flink.py`. ([C5](05-egress-orchestrator-review.md))
- **chio-temporal** (1291 LOC, `ChioActivityInterceptor`) and **chio-airflow** (1384 LOC, `ChioOperator` + decorator + DAG listener) exist as Python SDKs. Doc 05's framing matches. ([C5](05-egress-orchestrator-review.md))
- **Bench stubs (historical, resolved in-tree)**: verification at the time confirmed **11+ stubs**, not 4: `single_guard`, `cap_verify_ed25519`, `receipt_sign`, `guard_pipeline_5`, `scope_match`, `time_bound`, `revocation_lookup`, `budget_decrement`, `receipt_append`, `session_lookup`, `dispatch_deny` were all `b.iter(|| black_box(0_u64))`. The bench bodies now drive real dispatch through `dispatch_request_fixture`; the hybrid family is still wired as tests rather than live Criterion benches and CI runs benches from Cargo.toml without `required-features` gating, so re-baselining and gating are the remaining open work. ([C4](04-receipts-kernel-latency-review.md))
- **`ToolServerConnection` trait** at `crates/chio-kernel/src/runtime.rs:255` is real and unchanged. All five new bridge proposals map onto it without inventing methods. ([C2](02-bridges-consistency-review.md))
- **Guard inventory** in doc 10 is exact. 16 guards spot-checked, all LOC counts match. `ExternalGuard`, `AsyncGuardAdapter`, `ScopedAsyncGuard`, `ChioExtAuthzService`, `McpToolGuard`, `GuardEvidence` citations all resolve. ([C3](03-policy-guards-review.md))
- **OAuth AS** at `chio-mcp-remote/src/remote_mcp/oauth.rs`: live but opt-in scaffolding (doc 07). Hybrid signing claims and OAuth profile in `spec/PROTOCOL.md:1351-1453` hold. ([C1](01-identity-credentials-review.md))
- **Strategic discipline respected end-to-end.** No doc violates the v2 non-goals in `spec/PROTOCOL.md:96-115`. No proposed bridge drifts into permissionless peer discovery, pub-sub, or wire-protocol replacement. ([C6](06-vision-non-goals-review.md))

## Historical errata findings

The findings below are preserved as review history. For current planning, use
[00-overview-v2.md](../00-overview-v2.md) and the PR 652 decision packet in
[18-decision-packet.md](../18-decision-packet.md).

### 1. n8n priority anchor cites the wrong threat chain (addressed)

The earlier versions of [`00-overview.md`](../00-overview.md) and [`05-workflow-orchestrator-mediation.md`](../05-workflow-orchestrator-mediation.md) anchored n8n priority-1 on the Talos 686% abuse spike. Doc 11 established that spike is **Chain D (unauthenticated webhook ingress, NOT blocked by Chio)**. The actually-blocked chain is **Chain C (prompt-injection agent-to-webhook)**. Current overview and orchestrator docs now carry that correction.

**Fix applied:** Doc 05 and 00-overview now rewrite the priority-1 justification around Chain C and explicitly note that Chain D (the 686% spike) is below Chio's layer and out-of-scope. ([C5](05-egress-orchestrator-review.md))

### 2. Bench-stub coverage is broader than reported (addressed, follow-up plan required)

Doc 16 named 4 stubs. The real count is 11+. Doc 16 also has a wrong file path: it attributes `build_and_sign_receipt` to `crates/chio-http-core/src/responses.rs:1506-1507`. That file does not exist. The function lives at `crates/chio-kernel/src/kernel/responses.rs:1459-1517`.

**Fix applied:** Doc 16 and overview-v2 now carry the 11-stub finding and the
correct `responses.rs` path. The remaining work is the bench-stub engineering
plan and later code PR. ([C4](04-receipts-kernel-latency-review.md))

### 3. `human_principal` typed twice with two different shapes (addressed)

[Doc 14:207-214](../14-voice-agent-bridges.md) defines it as a typed `HumanPrincipal` enum on `CallerIdentity`. [Doc 15:450](../15-receipt-kind-v1.md) defines it as `Option<String>` inside a `VoiceExtension`. Same name, two homes, two types.

**Fix applied:** Canonical form is the typed enum on `CallerIdentity`; receipt
extensions reference it by canonical encoding. ([C1](01-identity-credentials-review.md))

### 4. `ActorRef` undefined anywhere (addressed as ADR input)

Doc 15 promotes `actor_chain: Vec<ActorRef>` to the current v1 receipt body.
**The `ActorRef` type was defined in no doc, no spec, no code.** The IETF
agent-OBO draft is the implicit source but its exact wire shape was never
lifted into a Chio-side type.

**Fix applied:** Doc 15 now carries a definition stub. ADR-0010 must settle the
final wire shape before implementation. ([C1](01-identity-credentials-review.md))

### 5. `policy_hash` is `String`, not `[u8; 32]` (addressed with PR 652 follow-up)

[`crates/chio-core-types/src/receipt.rs`](../../../../crates/chio-core-types/src/receipt.rs) defines `policy_hash` as a hex `String`. Earlier docs used byte-array sketches for `policy_digest`; after the v1-only collapse, `policy_hash` is the current signed receipt field and `policy_digest` remains only a historical per-engine sketch term.

**Fix applied:** Receipt-facing current v1 docs name `policy_hash`; historical
`policy_digest` sketches are labeled as non-current. ([C3](03-policy-guards-review.md))

### 6. `tool_origin` enum drift across three docs (addressed with PR 652 follow-up)

Doc 12 introduces: `CallerExecuted | HostExecutedProviderReported | HostExecutedUnmediated`. Doc 13 implicitly adds `HostExecutedRedacted`. Doc 15 and overview-v2 reference the field but with slightly different variant names. C2 found 3 different versions across docs 00-v2, 12, 15.

**Fix applied:** PR 652 review split execution origin from redaction policy. Current planning default is `CallerExecuted | HostExecutedProviderReported | HostExecutedUnmediated` plus separate signed redaction mode. ([C2](02-bridges-consistency-review.md))

### 7. Crate naming: `chio-bridge-*` is not a workspace convention (superseded)

No existing crate uses the `chio-bridge-*` prefix. Doc 08 introduced
`chio-bridge-agntcy`, but the later AGNTCY review superseded the bridge
entirely because ACP is archived. Current guidance: no AGNTCY ACP adapter;
keep only static/operator-pinned `chio-directory`.

**Fix applied:** The active overviews and decision packet now hard-defer AGNTCY
ACP and keep `chio-directory` as the only AGNTCY-aligned path. ([C2](02-bridges-consistency-review.md))

### 8. Three-ACPs warning dropped from v2 overview

[`00-overview.md`](../00-overview.md) has the warning about Zed ACP vs IBM ACP vs AGNTCY ACP. [`00-overview-v2.md`](../00-overview-v2.md) does not. Worse: doc 02 (the decentralized-networks doc) still uses the superseded `chio-bridge-acp` name at lines 132 and 243, which the naming warning explicitly forbade and doc 08 retracts. The `chio-acp-*` namespace already belongs to Zed ACP in `crates/chio-acp-edge`.

**Fix applied:** The three-ACPs warning is restored in overview-v2; AGNTCY ACP
adapter naming is superseded by the `chio-directory` decision. ([C6](06-vision-non-goals-review.md))

### 9. Em dashes in both overview docs (addressed)

[`00-overview.md`](../00-overview.md) has 11 em dashes (U+2014). [`00-overview-v2.md`](../00-overview-v2.md) has 20. CLAUDE.md forbids em dashes in code, comments, and documentation.

**Fix applied:** Overview docs have been cleaned, and PR 652 verification scans
the research directory for em/en dashes. ([C6](06-vision-non-goals-review.md))

## Cross-cutting threads

1. **`policy_hash` / historical per-engine digest sketches / `decision_id` is the highest-traffic identity-of-decision field group.** It surfaces in docs 04, 10, 15, plus the v2 overview, and the C3 verification revealed a real type incompatibility. Current v1 uses signed `policy_hash`; historical `policy_digest` sketches are not core receipt fields.

2. **The "extensions" map in doc 15 is load-bearing for the bridge round.** Voice (`human_principal`, `deferred_durability`), Bedrock (`trace_redaction_mode`, `action_group_kind`), OpenAI (`tool_origin` if extension instead of core), directory traces, and event-actions (R3) all depend on it. The C1 finding that two docs put `human_principal` in different homes shows the design needs a clear "core vs extension" criterion before bridge work starts.

3. **The bench-stub finding affected every latency claim across the swarm (resolved in-tree).** The 11+ stubs now carry real bodies driven through `dispatch_request_fixture`, so the Cedar `<150 µs` estimate, the voice `200 ms` budget, and the hybrid signing `150-225 µs` figure can be re-baselined against the new bodies rather than extrapolated from external benchmarks.

## Historical next steps and current disposition

1. **Bench-stub fix PR** remains the next measurement workstream, but starts with a docs-only engineering plan.
2. **Errata pass** is captured by PR 652 and [18-decision-packet.md](../18-decision-packet.md).
3. **Canonical specs** are now ADR inputs for current v1 receipt-kind semantics, origin/redaction, current v1 event-action planning, and async receipt durability.
4. **Verification CI** for dash scanning remains a future hygiene improvement.
5. **Citation linting** remains a future hygiene improvement.

## Closing note

The corpus is in better shape than I expected from a swarm of this size. The errata are all mechanical except for items 3-5 (the typed-field disagreements), and even those are clear-cut decisions with one obviously-right answer. Once cleaned up, the 17 docs form a coherent strategy that respects Chio's discipline. The build queue in [00-overview-v2.md](../00-overview-v2.md) holds with the n8n caveat from item 1 applied.
