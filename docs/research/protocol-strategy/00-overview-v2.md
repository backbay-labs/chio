# Chio protocol strategy research, wave 2 (May 2026)

## Context

Ten parallel research agents extended the May 2026 swarm: five **refine** passes that deepened doc-03/04/05 gating questions plus added concrete designs for AGNTCY ACP and the event-action vocabulary, three **expand** passes that filled the Tier-1 surfaces missing from wave 1 (OpenAI Responses, Bedrock Agents, voice), and two **cross-cutting** passes that stress-tested the receipt schema and audited hot-path latency.

Output: docs `07-` through `16-` on `research/protocol-strategy-2026`. Wave 1 docs (`00-` through `06-`) are unchanged.

## TL;DR

Two findings change the immediate priorities:

1. **Every per-stage kernel bench is a `black_box(0_u64)` stub.** ([X2](16-latency-budget-audit.md), `crates/chio-kernel/benches/single_guard.rs:8`, `cap_verify_ed25519.rs:7`, `receipt_sign.rs:8`, `guard_pipeline_5.rs:8`.) CI runs them ([.github/workflows/bench-regression.yml:108](.github/workflows/bench-regression.yml:108)). All wave-1 and wave-2 latency claims are currently unverifiable. **Fixing this is the highest-leverage first task in the build queue.**
2. **`tool_origin` is a core v3 receipt field, not an extension.** It surfaced independently in E1 (OpenAI built-in tools) and E2 (Bedrock Lambda action groups), and shows up implicitly in R2 (AGNTCY ACP hop). X1's hybrid v3 schema (Option D) should promote it onto the core body alongside `actor_chain`, `engine_id`, `policy_digest`, `decision_id`, `extensions_hash`.

Everything else is incremental but coherent: AGNTCY ACP, Cedar, OpenAI Responses, Bedrock Agents, voice (LiveKit-first) all fit. n8n priority needs a footnote. OAuth AS gets a feature flag, not deletion.

## Per-doc headlines

| # | Agent | Headline | Recommendation |
|---|---|---|---|
| [07](07-oauth-as-usage-audit.md) | R1 OAuth AS audit | **Live but opt-in.** Real product code, 5 integration tests, conformance runner support, normative profile in [`spec/PROTOCOL.md:1351-1453`](spec/PROTOCOL.md:1351). Dead-by-default at runtime (handlers 404 without `--auth-server-seed-file`). No telemetry. | **(c) Cargo feature flag + rename + scope-clamp.** Path to deletion preserved. |
| [08](08-agntcy-acp-bridge-spec.md) | R2 AGNTCY ACP | **ACP v0.2.3** ([github.com/agntcy/acp-spec](https://github.com/agntcy/acp-spec/blob/main/openapi.json), frozen 2026-04-11). **Zero `securitySchemes`** in the spec — identity inherited from HTTP substrate. | New crates `chio-bridge-agntcy` + `chio-directory` (DirectoryProvider trait + StaticAgntcyDirectoryProvider). MVP uses `POST /runs/wait` and `POST /runs/stream`. |
| [09](09-event-action-schema.md) | R3 Event actions | Unified `EventDestination`/`EventSource` with `BrokerKind` enum, not per-broker variants. | `chio.manifest.v1`→`v2` additive bump, fail-closed via ceiling negotiation, no flag-day. |
| [10](10-cedar-first-guard.md) | R4 Cedar first-guard | `McpToolGuard` ([`chio-guards/src/mcp_tool.rs`](crates/chio-guards/src/mcp_tool.rs), 429 LOC) is the right port. Only ~6 of ~30 guards are pure list-and-branch; the rest are journal-stateful or ML/heuristic. | **Option A' — greenfield + two flagship ports** (`McpToolGuard` + `EgressAllowlistGuard`). Not full migration. |
| [11](11-n8n-threat-mapping.md) | R5 n8n threat map | Priority-1 is **partially justified**. Chio blocks Chain C (prompt-injection webhook exfil) cleanly; does NOT block Chain D (the 686% ingress-abuse spike, which is below Chio's layer). | Keep n8n in the priority list; tighten doc 05's framing to specify Chain C as the value prop. |
| [12](12-openai-responses-adapter.md) | E1 OpenAI Responses | New crate `chio-openai-responses-adapter`. **MVP: caller-executed `function` tools only over streaming SSE on non-reasoning models.** Refuses built-in-tool or reasoning requests. | Introduce `tool_origin: CallerExecuted | HostExecutedAttested | HostExecutedUnmediated` (core v3 field). |
| [13](13-bedrock-agents-bridge.md) | E2 Bedrock Agents | New crate `chio-bedrock-agents-adapter`. **MVP: RETURN_CONTROL action groups full mediation**, Lambda actions receipt-logged only (AWS trust boundary). | Trace redaction default: `summary` (salted SHA-256 hashes preserving structural metadata). Opt-in `redacted` and `full` (full gated by separate IAM scope). |
| [14](14-voice-agent-bridges.md) | E3 Voice agents | **MVP: `chio-livekit-py` Python middleware** (`@chio_function_tool` decorator wrapping LiveKit's `@function_tool`). Pipecat FrameProcessor second; paired Vapi+Retell HTTP shim third. Signing fits the budget; **durability writes (5-50ms) are the limiter**. | Sign synchronously, write asynchronously, fail-closed bounded queue, sequence-numbered receipts. Needs v3 "deferred durability" flag (coordinate with X1). |
| [15](15-receipt-schema-v3.md) | X1 Receipt schema v3 | **Option D (hybrid).** Promote `schema`, `actor_chain`, `engine_id`, `policy_digest`, `decision_id`, `extensions_hash` to v3 core body; route bridge/engine/surface-specific payloads through typed `extensions: BTreeMap<ExtensionNamespace, ExtensionEnvelope>` with `must_understand` flag per extension. | v3 bump is additive per [`spec/PROTOCOL.md:7-8`](spec/PROTOCOL.md:7); v2 stays universal floor; federation negotiates via new `accepts_receipt_v3` + `accepts_ext.<namespace>` bitset features. Lean theorem v3-analog required. |
| [16](16-latency-budget-audit.md) | X2 Latency audit | Estimated median verdict latency: **~2-4ms Ed25519-only, ~6-10ms hybrid**. Voice sub-200ms is **conditional**: yes with Ed25519 + in-process guards + async receipt write + per-bridge fast paths; no with hybrid + remote guards + sync SQLite. | Land bench stub bodies (urgent). Parallelize hybrid signing (~50-100µs savings). HTTP path does 3 signatures + 1 verify per request — voice fast-path should skip outer sign. |

## Cross-cutting threads that emerged

1. **`tool_origin` belongs on the core v3 receipt body.** Not an extension. E1, E2, and implicitly R2 all need it. The four categories are sufficient: `caller-executed`, `host-executed-attested` (with a separate attestation hash), `host-executed-unmediated`, `host-executed-redacted`.

2. **Async receipt write + sequence numbering is now load-bearing for voice.** E3 needs it; X1's extensions map can hold a `deferred_durability` flag with a bounded-loss SLO. This needs a coordinated design across X1, X2, and E3 before E3 starts.

3. **Cedar fits everywhere on latency.** R4 + X2 reconciliation: ~150µs with entity cache is well inside any tier's budget. The blockers for voice are *not* Cedar (good) but OpenFGA's Check (5-50ms) and synchronous SQLite (1-10ms). This justifies a **policy tier classification on guards** — voice-tier guards must declare in-process + async-durability.

4. **Double-gating is functionally free.** [`HttpEgressContract::enforce_url`](crates/chio-egress-contract/src/lib.rs) is pure-Rust URL parse + allowlist (20-80µs). Doc 05's double-gating recommendation stands without latency caveat.

5. **Five new crates proposed** + 1 existing feature-flagged: `chio-bridge-agntcy`, `chio-directory`, `chio-bedrock-agents-adapter`, `chio-openai-responses-adapter`, `chio-livekit-py`, plus a feature flag wrap around `chio-mcp-remote`'s AS. Coherent footprint — no overlap.

## Updated phased build queue

### Wave A — Foundation (close gaps, unblock everything else)

- **Land real bench bodies in CI.** Drop `black_box(0_u64)` for `single_guard.rs`, `cap_verify_ed25519.rs`, `receipt_sign.rs`, `guard_pipeline_5.rs`. Without this, the rest of Wave A and B is unmeasurable. **Highest priority.** ([16](16-latency-budget-audit.md))
- **Receipt v3 schema** (Option D): core body promotions + extensions map + `must_understand` semantics + federation negotiation features. ([15](15-receipt-schema-v3.md))
- **`EventPublish`/`EventConsume` ToolAction variants** + `chio.manifest.v2` bump. ([09](09-event-action-schema.md))
- **OAuth AS feature flag** + rename to "Chio Governed Authorization Bridge" + scope-clamp. ([07](07-oauth-as-usage-audit.md))
- **`tool_origin` core v3 field** (cross-cuts E1, E2, R2). ([12](12-openai-responses-adapter.md), [13](13-bedrock-agents-bridge.md))
- **Parallelize hybrid signing** ([`chio-core-types/src/pq.rs:166-170`](crates/chio-core-types/src/pq.rs:166)). ~50-100µs savings on every receipt. ([16](16-latency-budget-audit.md))

### Wave B — High-ROI new bridges

- **`chio-openai-responses-adapter`** — function-tools-only MVP, refuses built-in/reasoning at boundary. ([12](12-openai-responses-adapter.md))
- **`chio-bedrock-agents-adapter`** — RETURN_CONTROL mediation, summary redaction default. ([13](13-bedrock-agents-bridge.md))
- **Cedar `PolicyEngineProvider`** + port `McpToolGuard` + `EgressAllowlistGuard` as flagship references. ([10](10-cedar-first-guard.md))
- **n8n orchestrator-egress (Chain C only)** — tighten doc 05's framing to specify the Chain C value prop. ([11](11-n8n-threat-mapping.md))

### Wave C — Strategic expansions

- **`chio-bridge-agntcy` + `chio-directory`** — DirectoryProvider trait + StaticAgntcyDirectoryProvider + AGNTCY ACP bridge. ([08](08-agntcy-acp-bridge-spec.md))
- **`chio-livekit-py`** — voice mediation, paired with async receipt write + sequence numbering + bounded-loss SLO. ([14](14-voice-agent-bridges.md))
- **Per-bridge fast paths + voice-tier policy classification** — voice fast-path skips outer signature; voice-tier guards declare in-process. ([14](14-voice-agent-bridges.md), [16](16-latency-budget-audit.md))

### Wave D — Defer

- AMQP/SNS+SQS/WebSub additions to `chio-streaming` ([01](01-pubsub-coverage-audit.md))
- Pipecat FrameProcessor, Vapi+Retell shims ([14](14-voice-agent-bridges.md))
- OPA / OpenFGA `PolicyEngineProvider` implementations (engines 2 and 3) ([04](04-policy-engine-collaborators.md))
- CDP/WebDriver BiDi computer-use bridge design (its own swarm)
- PresignedUrlGuard in `chio-data-guards` ([06](06-below-l7-mediation.md))

## Open questions

1. **Voice-tier policy classification** — should guards declare a tier (`voice` | `standard` | `batch`) and the kernel refuse to compose incompatible chains? Decide before E3 lands.
2. **`must_understand` extension registry** — who owns it? Probably `spec/PROTOCOL.md` plus a registry doc; needs a v3 governance answer.
3. **AGNTCY zero-securitySchemes** ([08](08-agntcy-acp-bridge-spec.md)) — should Chio require an out-of-band mTLS or token gate before the bridge talks to a directory entry? Probably yes; spec the floor.
4. **Async receipt write bounded-loss SLO** — what's acceptable? 1 receipt per 10⁶? Per-bridge or per-tier?
5. **Bench stub fix as a blocking PR** — should this be the very first commit before any wave-A design? Yes, recommend it is.

## Files

All in `docs/research/protocol-strategy/`. Wave 1: 00-overview, 01 through 06. Wave 2: 07 through 16. This file: `00-overview-v2.md`.
