# Chio protocol strategy research, wave 2 (May 2026)

## Context

Ten parallel research agents extended the May 2026 swarm: five **refine** passes that deepened doc-03/04/05 gating questions plus added concrete designs for AGNTCY ACP and the event-action vocabulary, three **expand** passes that filled the Tier-1 surfaces missing from wave 1 (OpenAI Responses, Bedrock Agents, voice), and two **cross-cutting** passes that stress-tested the receipt schema and audited hot-path latency.

Output: docs `07-` through `16-` on `research/protocol-strategy-2026`. Wave 1 docs (`00-` through `06-`) are preserved as historical research with errata.

> **Plan-of-record status (PR 652 review):** This file is the synthesis of record for the research branch. The earlier [00-overview.md](00-overview.md) remains useful historical context, but follow-on planning should start here and then use [18-decision-packet.md](18-decision-packet.md) for architecture decisions before implementation tickets.

> **Erratum (wave 3 + wave 4)**:
> - AGNTCY ACP is dead. `agntcy/acp-spec` was archived 2026-04-11 (the date doc 08 cited was the *archival* date, not a stabilization freeze). The bridge plan in Wave C is struck; only the consume-only `chio-directory` integration survives. See [17-agntcy-revisited.md](17-agntcy-revisited.md).
> - The n8n priority-1 framing here originally referenced the Talos 686% abuse spike, which is **Chain D** (NOT blocked by Chio). The actually-blocked attack is **Chain C** (prompt-injection agent-to-webhook). See [11-n8n-threat-mapping.md](11-n8n-threat-mapping.md).
> - Bench-stub coverage is broader than originally reported: not 4 stubs, but **11+** ([reviews/04-receipts-kernel-latency-review.md](reviews/04-receipts-kernel-latency-review.md)). Doc 16's `responses.rs:1506` citation is also a wrong file path; the function lives at `crates/chio-kernel/src/kernel/responses.rs:1459-1517`.
> - Canonical type forms: `policy_hash` / `policy_digest` is hex `String` (matches existing code, RFC 8785 friendly); ADR-0010 keeps `tool_origin` (`CallerExecuted | HostExecutedProviderReported | HostExecutedUnmediated`) and `redaction_mode` as separate signed v3 fields; `human_principal` is the typed enum on `CallerIdentity` (doc 14) referenced by the receipt extension (doc 15), not duplicated.
> - `ActorRef` (the actor-chain element type promoted to v3 core in doc 15) needs a concrete definition stub before any v3 work begins. Captured in doc 15.
> - Follow-up grounding corrections from PR 652 review: doc 05's `policy_version` / `manifest_id` receipt fields and `args_schema` examples are design intent, not current code; doc 09's manifest-v2 negotiation needs new manifest-ceiling plumbing and is not handled by today's capability ceiling alone.

## TL;DR

Two findings change the immediate priorities:

1. **Every per-stage kernel bench is a `black_box(0_u64)` stub.** ([X2](16-latency-budget-audit.md), with wave-3 verification at [reviews/04](reviews/04-receipts-kernel-latency-review.md) expanding the list to 11+: `single_guard`, `cap_verify_ed25519`, `receipt_sign`, `guard_pipeline_5`, `scope_match`, `time_bound`, `revocation_lookup`, `budget_decrement`, `receipt_append`, `session_lookup`, `dispatch_deny`.) CI runs them at [`.github/workflows/bench-regression.yml:101-108`](../../../.github/workflows/bench-regression.yml#L101) without `required-features` gating, so PR regression checks are comparing stub-vs-stub for 10+ primitives. All wave-1 and wave-2 latency claims are currently unverifiable. **Fixing this is the highest-leverage first task in the build queue.**
2. **`tool_origin` is a core v3 receipt field, separate from redaction.** It surfaced independently in E1 (OpenAI built-in tools) and E2 (Bedrock Lambda action groups). PR 652 review tightened the rule: execution origin and redaction stay orthogonal. The planning default is `CallerExecuted | HostExecutedProviderReported | HostExecutedUnmediated` plus a separate redaction mode.

Everything else is incremental but coherent: Cedar, OpenAI Responses, Bedrock Agents, voice (LiveKit-first) all fit. AGNTCY ACP is dead but AGNTCY Directory + Identity consumption survives. n8n priority restricted to Chain C. OAuth AS stays live but blocked for product work until a dedicated ADR or equivalent decision note is accepted.

## Per-doc headlines

| # | Agent | Headline | Recommendation |
|---|---|---|---|
| [07](07-oauth-as-usage-audit.md) | R1 OAuth AS audit | **Live but opt-in.** Real product code, 5 integration tests, conformance runner support, normative profile in [`spec/PROTOCOL.md:1351-1453`](../../../spec/PROTOCOL.md#L1351). Dead-by-default at runtime (handlers 404 without `--auth-server-seed-file`). No telemetry. | Block product tickets until an OAuth AS ADR or equivalent decision note settles feature gating, naming, scope clamp, telemetry, and posture. |
| [08](08-agntcy-acp-bridge-spec.md) | R2 AGNTCY ACP | **SUPERSEDED.** ACP archived 2026-04-11; doc 08's "frozen v0.2.3" framing was wrong. See [17-agntcy-revisited.md](17-agntcy-revisited.md). | Drop `chio-bridge-agntcy`. Keep `chio-directory` (DirectoryProvider trait + StaticAgntcyDirectoryProvider) for consume-only Directory + Identity integration. |
| [09](09-event-action-schema.md) | R3 Event actions | Unified `EventDestination` / `EventSource` with `BrokerKind` enum, not per-broker variants. | `chio.manifest.v1` to `v2` additive bump. Requires the explicit `maxManifestSchema` ceiling chosen in ADR-0012; today's capability ceiling does not provide that by itself. |
| [10](10-cedar-first-guard.md) | R4 Cedar first-guard | `McpToolGuard` ([`chio-guards/src/mcp_tool.rs`](../../../crates/chio-guards/src/mcp_tool.rs), 429 LOC) is the right port. Only ~6 of ~30 guards are pure list-and-branch; the rest are journal-stateful or ML/heuristic. | **Option A': greenfield + two flagship ports** (`McpToolGuard` and `EgressAllowlistGuard`). Not full migration. |
| [11](11-n8n-threat-mapping.md) | R5 n8n threat map | Priority-1 is **partially justified**. Chio blocks Chain C (prompt-injection webhook exfil) cleanly; does NOT block Chain D (the 686% ingress-abuse spike, which is below Chio's layer). | Keep n8n in the priority list; restrict the value-prop framing to Chain C. |
| [12](12-openai-responses-adapter.md) | E1 OpenAI Responses | New crate `chio-openai-responses-adapter`. **MVP: caller-executed `function` tools only over streaming SSE on non-reasoning models.** Refuses built-in-tool or reasoning requests. | Needs `tool_origin` execution-locus semantics plus an API refresh against official Responses docs before codegen. |
| [13](13-bedrock-agents-bridge.md) | E2 Bedrock Agents | New crate `chio-bedrock-agents-adapter`. **MVP: RETURN_CONTROL action groups full mediation**, Lambda actions receipt-logged only (AWS trust boundary). | Trace redaction default: `summary` (salted SHA-256 hashes preserving structural metadata). Opt-in `redacted` and `full` (full gated by separate IAM scope). |
| [14](14-voice-agent-bridges.md) | E3 Voice agents | **MVP: `chio-livekit-py` Python middleware** (`@chio_function_tool` decorator wrapping LiveKit's `@function_tool`). Pipecat FrameProcessor second; paired Vapi+Retell HTTP shim third. Signing fits the budget; **durability writes (5-50ms) are the limiter**. | Sign synchronously, write asynchronously, fail-closed bounded queue, sequence-numbered receipts. Needs v3 "deferred durability" flag (coordinate with X1). |
| [15](15-receipt-schema-v3.md) | X1 Receipt schema v3 | **Option D (hybrid candidate).** Promote a small core field set and route bridge / engine / surface-specific payloads through typed extensions. | Implement through ADR-0010: explicit `maxReceiptSchema`, separate `tool_origin` and redaction, signed extension handling, `must_understand`, and hex `String` encoding for `policy_digest`. |
| [16](16-latency-budget-audit.md) | X2 Latency audit | Estimated median verdict latency: **~2-4ms Ed25519-only, ~6-10ms hybrid**. Voice sub-200ms is **conditional**: yes with Ed25519 + in-process guards + async receipt write + per-bridge fast paths; no with hybrid + remote guards + sync SQLite. | Land bench stub bodies (urgent: 11+ stubs, not 4). Parallelize hybrid signing (~50-100us savings). HTTP path does 3 signatures + 1 verify per request: voice fast-path should skip outer sign. |

## Cross-cutting threads that emerged

1. **`tool_origin` belongs on the core v3 receipt body, but redaction is orthogonal.** E1 and E2 both need execution-locus provenance. The planning default is `CallerExecuted | HostExecutedProviderReported | HostExecutedUnmediated`; Bedrock trace redaction is represented by a separate signed `redaction_mode` / `trace_redaction_mode`, not a fourth origin variant.

2. **Async receipt write + sequence numbering is now load-bearing for voice.** E3 needs it; X1's extensions map can hold a `deferred_durability` flag with a bounded-loss SLO. This needs a coordinated design across X1, X2, and E3 before E3 starts.

3. **Cedar looks plausible for selected guards, but latency is not proven.** R4 + X2 reconciliation estimated ~150us with entity cache, which would fit normal tiers if real workloads confirm it. The current bench stubs mean this is not yet a claim. Voice-tier planning still needs a **policy tier classification on guards**: voice-tier guards must declare in-process + async-durability.

4. **Double-gating is functionally free.** [`HttpEgressContract::enforce_url`](../../../crates/chio-egress-contract/src/lib.rs) is pure-Rust URL parse + allowlist (20-80us). Doc 05's double-gating recommendation stands without latency caveat.

5. **Four new crates proposed** + one blocked existing-surface follow-up: `chio-directory` (consume-only), `chio-bedrock-agents-adapter`, `chio-openai-responses-adapter`, `chio-livekit-py`, plus a future OAuth AS posture ticket only after its ADR or equivalent decision note is accepted. The previously-counted `chio-bridge-agntcy` has been struck (see erratum block). Coherent footprint, no overlap. The `chio-bridge-*` prefix is not a workspace convention; existing pattern is `-edge` (expose) / `-adapter` (consume) / `-proxy` (variant).

## Naming-collision warning

Three protocols are named "ACP":

1. **Zed's Agent Client Protocol / Anthropic Compute Protocol**: covered today by [`chio-acp-edge`](../../../crates/chio-acp-edge/).
2. **IBM Agent Communication Protocol**: converging with A2A; no Chio bridge today.
3. **AGNTCY Agent Connect Protocol**: archived 2026-04-11; absorbed into A2A. No Chio bridge planned.

The `chio-acp-*` namespace is owned by Zed's ACP. Do not propose other crates with that prefix. The wave-2 doc 02 used the name `chio-bridge-acp` for AGNTCY, which is doubly wrong (now-dead protocol + non-convention prefix) and is corrected in the erratum at the top of [doc 02](02-decentralized-agent-networks.md).

## Updated phased build queue

Before implementation tickets, use [18-decision-packet.md](18-decision-packet.md)
and the accepted ADRs it points to as the decision record for receipt-v3
semantics, the boundary matrix, manifest-v2 negotiation, and async receipt
durability. OAuth AS product work stays blocked until a dedicated OAuth AS ADR
or equivalent decision note is accepted.

### Wave A: foundation (close gaps, unblock everything else)

- **Land real bench bodies in CI.** Drop `black_box(0_u64)` for the 11 stubs enumerated in TL;DR finding 1. Without this, the rest of Wave A and B is unmeasurable. Also gate benches with `required-features` per bench file. **Highest priority.** ([16](16-latency-budget-audit.md), [reviews/04](reviews/04-receipts-kernel-latency-review.md))
- **Receipt v3 semantic gate**: implement the accepted ADR-0010 decisions for
  `receipt_kind`, `maxReceiptSchema`, older-verifier behavior, `tool_origin`,
  redaction, `ActorRef`, hex `policy_digest`, extension signing, and
  `must_understand`. ([15](15-receipt-schema-v3.md), [18](18-decision-packet.md))
- **`EventPublish` / `EventConsume` ToolAction variants** + `chio.manifest.v2`
  bump, following the accepted ADR-0012 `maxManifestSchema` ceiling and broker
  identity decisions. ([09](09-event-action-schema.md))
- **OAuth AS posture ADR or equivalent decision note** before any feature-flag,
  rename, or scope-clamp product ticket. ([07](07-oauth-as-usage-audit.md),
  [03](03-oauth-oidc-issuer.md))
- **Boundary classification gate**: every bridge plan must carry the accepted
  ADR-0011 `boundary_class` (`prevent`, `detect_only`, `advisory_only`,
  `cannot_see`) and `planning_status` (`ready_after_adr`, `blocked_by_adr`,
  `deferred`, `hard_skip`). ([18](18-decision-packet.md))
- **Manifest v2 enforcement gate**: implement `maxManifestSchema`, broker
  identity, strict unknown-field rejection, and the event enforcement layer
  before event-action rollout. ([09](09-event-action-schema.md),
  [18](18-decision-packet.md))
- **`tool_origin` core v3 field** (execution locus only; redaction separate by
  default). ([12](12-openai-responses-adapter.md),
  [13](13-bedrock-agents-bridge.md), [15](15-receipt-schema-v3.md),
  [18](18-decision-packet.md))
- **Parallelize hybrid signing** (`crates/chio-core-types/src/pq.rs:166-170` per doc 16: verify the citation as part of this work). ~50-100us savings on every receipt. ([16](16-latency-budget-audit.md))

### Wave B: high-ROI new bridges

- **`chio-openai-responses-adapter`**: function-tools-only MVP, refuses built-in / reasoning at boundary. ([12](12-openai-responses-adapter.md))
- **`chio-bedrock-agents-adapter`**: RETURN_CONTROL mediation, summary redaction default. ([13](13-bedrock-agents-bridge.md))
- **Cedar `PolicyEngineProvider`** + port `McpToolGuard` + `EgressAllowlistGuard` as flagship references. ([10](10-cedar-first-guard.md))
- **n8n orchestrator-egress, Chain C only**: prompt-injection agent-to-webhook exfiltration is the value-prop; do NOT cite the Talos 686% spike (Chain D is below Chio's layer). ([11](11-n8n-threat-mapping.md))

### Wave C: strategic expansions

- **`chio-directory`** (consume-only): `DirectoryProvider` trait + `StaticAgntcyDirectoryProvider`. Read-only AGNTCY Directory + Identity consumption, mirroring Webex's production pattern. NO `chio-bridge-agntcy` (ACP is archived). ([17](17-agntcy-revisited.md))
- **`chio-livekit-py`**: voice mediation, paired with async receipt write + sequence numbering + bounded-loss SLO. ([14](14-voice-agent-bridges.md))
- **Per-bridge fast paths + voice-tier policy classification**: voice fast-path skips outer signature; voice-tier guards declare in-process. ([14](14-voice-agent-bridges.md), [16](16-latency-budget-audit.md))

### Wave D: defer

- AMQP / SNS+SQS / WebSub additions to `chio-streaming` ([01](01-pubsub-coverage-audit.md))
- Pipecat FrameProcessor, Vapi+Retell shims, and voice implementation before async durability is settled ([14](14-voice-agent-bridges.md))
- OPA / OpenFGA `PolicyEngineProvider` implementations (engines 2 and 3) ([04](04-policy-engine-collaborators.md))
- CDP / WebDriver BiDi computer-use bridge design (its own swarm)
- `PresignedUrlGuard` in `chio-data-guards` ([06](06-below-l7-mediation.md))
- AGNTCY ACP bridge, AGNTCY SLIM wire bridge, Agora, live directory import, and broad Cedar migration. Static/operator-pinned `chio-directory` remains the only AGNTCY-aligned path. ([17](17-agntcy-revisited.md), [18](18-decision-packet.md))

## Open questions

1. **Voice-tier policy classification**: should guards declare a tier (`voice` | `standard` | `batch`) and the kernel refuse to compose incompatible chains? Decide before E3 lands.
2. **`must_understand` extension registry**: who owns it? Probably `spec/PROTOCOL.md` plus a registry doc; needs a v3 governance answer.
3. **AGNTCY Directory + Identity consumption details**: what's the production wire format Webex uses? Replaces the prior "zero-securitySchemes" question, which was specific to the now-dead ACP. See [17](17-agntcy-revisited.md).
4. **Async receipt write bounded-loss SLO**: what's acceptable? 1 receipt per 10^6? Per-bridge or per-tier?
5. **Bench baseline citation policy**: after the bench-stub PR lands, latency
   claims must cite the exact bench commit, feature set, and command that
   produced the numbers.

## Files

All in `docs/research/protocol-strategy/`. Wave 1: 00-overview, 01 through 06. Wave 2: 07 through 16. Wave 3 reviews: [reviews/](reviews/). Wave 4 AGNTCY follow-up: [17-agntcy-revisited.md](17-agntcy-revisited.md). PR 652 decision packet: [18-decision-packet.md](18-decision-packet.md). This file: `00-overview-v2.md`.
