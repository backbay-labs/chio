# Review swarm synthesis (wave 3)

> **Status: errata applied (commit on this branch following wave 4).** All 10 numbered errata below have landed as documentation edits:
>
> - **#1 n8n Chain D / Chain C** corrected in [05](../05-workflow-orchestrator-mediation.md), [00-overview](../00-overview.md), [00-overview-v2](../00-overview-v2.md).
> - **#2 bench-stub count + responses.rs path** corrected in [16](../16-latency-budget-audit.md), [00-overview-v2](../00-overview-v2.md).
> - **#3 `human_principal` typed twice** canonicalized: typed enum on `CallerIdentity` in [14](../14-voice-agent-bridges.md); receipt extension in [15](../15-receipt-schema-v3.md) references by canonical encoding.
> - **#4 `ActorRef` undefined** addressed: definition stub added to [15](../15-receipt-schema-v3.md) erratum block.
> - **#5 `policy_hash` String vs `[u8; 32]`** canonicalized to hex `String` in [04](../04-policy-engine-collaborators.md), [15](../15-receipt-schema-v3.md), [00-overview](../00-overview.md), [00-overview-v2](../00-overview-v2.md).
> - **#6 `tool_origin` enum drift** canonicalized to 4 variants (`CallerExecuted | HostExecutedAttested | HostExecutedUnmediated | HostExecutedRedacted`) in [12](../12-openai-responses-adapter.md), [13](../13-bedrock-agents-bridge.md), [15](../15-receipt-schema-v3.md), [00-overview-v2](../00-overview-v2.md).
> - **#7 `chio-bridge-*` prefix** struck in favor of `-adapter` convention across overviews and superseded `chio-bridge-agntcy` per erratum #10.
> - **#8 three-ACPs warning** restored in [00-overview-v2](../00-overview-v2.md); doc 02 `chio-bridge-acp` references covered by erratum at top of doc 02.
> - **#9 em dashes** removed from both overview docs (verified zero across all 26 docs in this directory).
> - **#10 AGNTCY ACP archival** captured in [17](../17-agntcy-revisited.md); doc 08 marked SUPERSEDED; doc 02 has erratum; build queue updated in both overviews.

## Context

Six review agents audited the 17 research docs in `docs/research/protocol-strategy/` for cross-doc consistency and codebase grounding. Each cluster verified file:line citations against the real code, cross-checked field names and trait shapes, and flagged contradictions. Reviews live in this directory:

- [01-identity-credentials-review.md](01-identity-credentials-review.md)
- [02-bridges-consistency-review.md](02-bridges-consistency-review.md)
- [03-policy-guards-review.md](03-policy-guards-review.md)
- [04-receipts-kernel-latency-review.md](04-receipts-kernel-latency-review.md)
- [05-egress-orchestrator-review.md](05-egress-orchestrator-review.md)
- [06-vision-non-goals-review.md](06-vision-non-goals-review.md)

## TL;DR

Verdict: **mixed-clean**. The docs are unusually well-grounded for swarm output (policy/guards cluster nearly perfect; SDKs all verified with exact LOC counts; bench-stub bombshell confirmed). But there are nine concrete inconsistencies that need errata before the build queue can be executed without confusion. Two are urgent (n8n priority anchor cites the wrong threat chain; bench-stub coverage is broader than reported), four are typed-field shape disagreements across docs, and three are document hygiene issues including a house-rule violation in my own synthesis docs.

## Verified claims (high confidence)

These claims hold up under code grounding. They can be cited downstream without re-verification.

- **chio-streaming Python SDK** exists at `sdks/python/chio-streaming/`, 5013 LOC across 12 modules. All seven brokers from doc 01 confirmed: Kafka top-level `middleware.py` plus per-broker `nats.py`, `pulsar.py`, `eventbridge.py`, `pubsub.py`, `redis_streams.py`, `flink.py`. ([C5](05-egress-orchestrator-review.md))
- **chio-temporal** (1291 LOC, `ChioActivityInterceptor`) and **chio-airflow** (1384 LOC, `ChioOperator` + decorator + DAG listener) exist as Python SDKs. Doc 05's framing matches. ([C5](05-egress-orchestrator-review.md))
- **Bench stubs**: verified and **worse than doc 16 reported**. Not 4 stubs, **11+**: `single_guard`, `cap_verify_ed25519`, `receipt_sign`, `guard_pipeline_5`, `scope_match`, `time_bound`, `revocation_lookup`, `budget_decrement`, `receipt_append`, `session_lookup`, `dispatch_deny` are all `b.iter(|| black_box(0_u64))`. Only `dispatch_allow` (Ed25519 path) and the hybrid family do real work. CI at `.github/workflows/bench-regression.yml:101-108` runs every bench from Cargo.toml without `required-features` gating, so PR regression checks compare stub-vs-stub for 10+ primitives. ([C4](04-receipts-kernel-latency-review.md))
- **`ToolServerConnection` trait** at `crates/chio-kernel/src/runtime.rs:255` is real and unchanged. All five new bridge proposals map onto it without inventing methods. ([C2](02-bridges-consistency-review.md))
- **Guard inventory** in doc 10 is exact. 16 guards spot-checked, all LOC counts match. `ExternalGuard`, `AsyncGuardAdapter`, `ScopedAsyncGuard`, `ChioExtAuthzService`, `McpToolGuard`, `GuardEvidence` citations all resolve. ([C3](03-policy-guards-review.md))
- **OAuth AS** at `chio-mcp-remote/src/remote_mcp/oauth.rs`: live but opt-in scaffolding (doc 07). Hybrid signing claims and OAuth profile in `spec/PROTOCOL.md:1351-1453` hold. ([C1](01-identity-credentials-review.md))
- **Strategic discipline respected end-to-end.** No doc violates the v2 non-goals in `spec/PROTOCOL.md:96-115`. No proposed bridge drifts into permissionless peer discovery, pub-sub, or wire-protocol replacement. ([C6](06-vision-non-goals-review.md))

## Errata required (ordered by consequence)

### 1. n8n priority anchor cites the wrong threat chain (URGENT)

[`00-overview.md:35`](../00-overview.md) and [`05-workflow-orchestrator-mediation.md:56-72`](../05-workflow-orchestrator-mediation.md) anchor n8n priority-1 on the Talos 686% abuse spike. Doc 11 established that spike is **Chain D (unauthenticated webhook ingress, NOT blocked by Chio)**. The actually-blocked chain is **Chain C (prompt-injection agent-to-webhook)**. [`00-overview-v2.md:26,61`](../00-overview-v2.md) acknowledges this but the wave-1 docs have not been backported.

**Fix:** Edit doc 05 and 00-overview to rewrite the priority-1 justification around Chain C; explicitly note that Chain D (the 686% spike) is below Chio's layer and out-of-scope. ([C5](05-egress-orchestrator-review.md))

### 2. Bench-stub coverage is broader than reported (URGENT)

Doc 16 named 4 stubs. The real count is 11+. Doc 16 also has a wrong file path: it attributes `build_and_sign_receipt` to `crates/chio-http-core/src/responses.rs:1506-1507`. That file does not exist. The function lives at `crates/chio-kernel/src/kernel/responses.rs:1459-1517`.

**Fix:** Edit doc 16 to expand the stub list and correct the `responses.rs` path. Update the bench-stub Wave A action in 00-overview-v2 to enumerate all 11 stubs explicitly. ([C4](04-receipts-kernel-latency-review.md))

### 3. `human_principal` typed twice with two different shapes

[Doc 14:207-214](../14-voice-agent-bridges.md) defines it as a typed `HumanPrincipal` enum on `CallerIdentity`. [Doc 15:450](../15-receipt-schema-v3.md) defines it as `Option<String>` inside a `VoiceExtension`. Same name, two homes, two types.

**Fix:** Pick one. Recommend: typed enum on `CallerIdentity` (matches the existing `CallerIdentity` extensibility pattern); receipt extension references it by canonical encoding. Update both docs to agree. ([C1](01-identity-credentials-review.md))

### 4. `ActorRef` undefined anywhere

Doc 15 promotes `actor_chain: Vec<ActorRef>` to v3 core body at lines 105, 209, 301, 418. **The `ActorRef` type is defined in no doc, no spec, no code.** The IETF agent-OBO draft is the implicit source but its exact wire shape was never lifted into a Chio-side type.

**Fix:** Add an `ActorRef` definition to doc 15 (or to a separate spec extension) before any v3 work begins. Should include subject, issuer, scopes, expiry. ([C1](01-identity-credentials-review.md))

### 5. `policy_hash` is `String`, not `[u8; 32]`

[`crates/chio-core-types/src/receipt.rs`](../../../crates/chio-core-types/src/receipt.rs) defines `policy_hash` as a hex `String`. Doc 04 said "fold `policy_digest: [u8; 32]` into `policy_hash`," which is type-incompatible. Doc 15 separately promotes `policy_digest: [u8; 32]` to v3 core.

**Fix:** Pick one canonical form (recommend: keep `String` hex on receipts because RFC 8785 canonical JSON works better with hex strings than raw bytes; document the encoding rule). Update docs 04 and 15 to agree. ([C3](03-policy-guards-review.md))

### 6. `tool_origin` enum drift across three docs

Doc 12 introduces: `CallerExecuted | HostExecutedAttested | HostExecutedUnmediated`. Doc 13 implicitly adds `HostExecutedRedacted`. Doc 15 and overview-v2 reference the field but with slightly different variant names. C2 found 3 different versions across docs 00-v2, 12, 15.

**Fix:** Canonicalize the enum in doc 15 (since 15 is the schema doc) with all four variants, then update docs 12, 13, and overview-v2 to reference it. ([C2](02-bridges-consistency-review.md))

### 7. Crate naming: `chio-bridge-*` is not a workspace convention

No existing crate uses the `chio-bridge-*` prefix. Doc 08 introduced `chio-bridge-agntcy`. C2 recommends renaming to **`chio-agntcy-acp-adapter`** to match `chio-bedrock-agents-adapter`, `chio-openai-responses-adapter`. The `-edge` / `-adapter` / `-proxy` triad is the established convention.

**Fix:** Rename in docs 02, 08, 00-overview-v2. Keep `chio-directory` as the leaf trait crate. ([C2](02-bridges-consistency-review.md))

### 8. Three-ACPs warning dropped from v2 overview

[`00-overview.md`](../00-overview.md) has the warning about Zed ACP vs IBM ACP vs AGNTCY ACP. [`00-overview-v2.md`](../00-overview-v2.md) does not. Worse: doc 02 (the wave-1 decentralized-networks doc) still uses the superseded `chio-bridge-acp` name at lines 132 and 243, which v1's warning explicitly forbade and doc 08 retracts. The `chio-acp-*` namespace already belongs to Zed ACP in `crates/chio-acp-edge`.

**Fix:** Add the three-ACPs warning back into 00-overview-v2 as a callout block. Edit doc 02 to use `chio-agntcy-acp-adapter` consistently. ([C6](06-vision-non-goals-review.md))

### 9. Em dashes in both overview docs (house-rule violation; my own work)

[`00-overview.md`](../00-overview.md) has 11 em dashes (U+2014). [`00-overview-v2.md`](../00-overview-v2.md) has 20. CLAUDE.md forbids em dashes in code, comments, and documentation.

**Fix:** Replace all em dashes with hyphens, parens, or semicolons in both overview docs. One-line sed possible; manual review preferred to choose the right replacement per context. ([C6](06-vision-non-goals-review.md))

## Cross-cutting threads

1. **`policy_hash` / `policy_digest` / `decision_id` is the highest-traffic identity-of-decision field group.** It surfaces in docs 04, 10, 15, plus the v2 overview, and the C3 verification revealed a real type incompatibility. This needs a one-paragraph canonical spec before any wave-A code lands.

2. **The "extensions" map in doc 15 is load-bearing for half of wave 2.** Voice (`human_principal`, `deferred_durability`), Bedrock (`trace_redaction_mode`, `action_group_kind`), OpenAI (`tool_origin` if extension instead of core), AGNTCY (`acp_peer_id`), event-actions (R3) all depend on it. The C1 finding that two docs put `human_principal` in different homes shows the design needs a clear "core vs extension" criterion before bridge work starts.

3. **The bench-stub finding affects every latency claim across the swarm.** Until the 11+ stubs have real bodies, no doc can cite a verified per-stage latency number. The Cedar `<150 µs` estimate, the voice `200 ms` budget, the hybrid signing `150-225 µs` figure are all extrapolations from external benchmarks.

## Recommended next steps (in order)

1. **Bench-stub fix PR** (lands real `b.iter` bodies for the 11 enumerated stubs; gates CI to `required-features` per bench). Highest leverage; unblocks every other latency claim. (Wave 2 Wave A item, already prioritized.)
2. **Errata pass** through the 9 numbered items above. Estimate: one PR, mostly mechanical edits to existing docs, no new content. Should land before any new wave-A design begins to avoid downstream churn.
3. **Canonical specs** for the three undefined types: `ActorRef`, the unified `tool_origin` enum, the canonical `policy_digest` encoding form. One spec doc or three short ones, lives at `spec/` or in the existing PROTOCOL.md as a v3 appendix.
4. **Verification CI**: add a check that grep's the docs/research tree for em dashes (U+2014) and fails on hits. House rule compliance becomes automatic.
5. **Citation linting**: a lightweight script that walks every `path:line` reference in the docs and warns on broken paths. Would have caught the `responses.rs:1506` error.

## Closing note

The corpus is in better shape than I expected from a swarm of this size. The errata are all mechanical except for items 3-5 (the typed-field disagreements), and even those are clear-cut decisions with one obviously-right answer. Once cleaned up, the 17 docs form a coherent strategy that respects Chio's discipline. The build queue in [00-overview-v2.md](../00-overview-v2.md) holds with the n8n caveat from item 1 applied.
