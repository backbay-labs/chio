# 06 - Vision and Non-Goals Review

> Round-2 swarm seat 6: vision-level consistency. Branch
> `research/protocol-strategy-2026`. Reads 17 docs in
> `docs/research/protocol-strategy/` against `spec/PROTOCOL.md:96-115`
> (v2 non-goals), `spec/PROTOCOL.md:305-329` (ceiling negotiation), and
> `CLAUDE.md` house rules. Citations are file:line.

## TL;DR

Overall coherence is **mixed**. The 17 docs respect Chio's stated discipline
(lift tool calls off wires, sign verdicts, return) almost everywhere; no doc
proposes a long-lived peer daemon, a permissionless directory node, or a
generic MCP / A2A wire replacement. The strong vision drift is concentrated
in three places: (1) the relationship between `00-overview.md` and
`00-overview-v2.md` is undeclared, with Phase A items contradictory across
the two files; (2) the three-ACPs naming warning carried in v1 is not
propagated forward into v2, and doc 02 still names the AGNTCY bridge
`chio-bridge-acp` (which would collide with the existing Zed
`crates/chio-acp-edge`); and (3) the `tool_origin` field is described
three incompatible ways across docs 12, 13, 15, and the v2 overview. Em
dashes slipped into both overviews despite the CLAUDE.md ban.

## Strategic discipline verdict

Every bridge proposed in 02, 08, 12, 13, and 14 stays on the discipline:
each one lifts a request/response tool call, runs a verdict, signs, and
returns. Specifically:

- Doc 02 line 53: NANDA is consumed read-only, "out-of-band, an operator
  pins the subset they care about, and the kernel keeps its closed-world
  view." Doc 02 line 273 hard-non-goals NANDA index participation, SLIM
  group/pub-sub termination, Agora PD negotiation in-kernel.
- Doc 08 line 7-19: AGNTCY bridge is an HTTP `ToolServerConnection` against
  `/runs/wait` and `/runs/stream` only; threads, run search, cancel, resume
  are out of scope (line 134-140). `DirectoryProvider.advisory_capabilities`
  is structurally separate from `CapabilityToken::scope`
  (`08-agntcy-acp-bridge-spec.md:326-335`).
- Doc 12 line 188-211: each `function_call_arguments.done` triggers one
  `ToolServerConnection::invoke` evaluation; host-executed calls emit
  trace receipts because Chio cannot retroactively block them. The
  adapter buffers, gates, and lowers.
- Doc 13 line 22-28: `RETURN_CONTROL` is mediated; `LAMBDA` is receipt-only,
  with `mediation_scope = "trace_only"` stamped on the receipt
  so audit cannot be deceived. Honest disclosure of where the discipline
  cannot reach.
- Doc 14 line 82-99: voice bridge sits between LLM tool-call event and
  execution; audio frames, VAD, barge-in are explicitly out of scope.

No doc proposes Chio as a broker, a peer daemon, a CA operator, a SLIM
endpoint, a NANDA index node, or a wire replacement for MCP / A2A. Good.

## Non-goals violation audit

`spec/PROTOCOL.md:96-115` is the canonical non-goals list. Auditing each
against the most-likely violators:

| Non-goal (PROTOCOL.md line) | Suspect doc | Verdict |
|---|---|---|
| multi-region consensus / Byzantine replication (98) | none | clean |
| public certification marketplace (99) | none | clean |
| automatic SCIM provisioning (100) | 03 | **clean**, explicitly disclaimed (`03-oauth-oidc-issuer.md:42, 118, 140`) |
| synthetic cross-issuer passport scoring (101) | 03 | clean, called out at `03-oauth-oidc-issuer.md:152` ("PROTOCOL non-goal ... argues for hash-only") |
| generic OID4VP / SIOP / DIDComm (107) | 03 | clean: doc 03 stays at PDP + step-up, does not propose SIOP / DIDComm |
| permissionless anchor discovery (110) | none | clean |
| permissionless public identity / wallet discovery that widens trust (106) | 02, 08 | clean: `02-decentralized-agent-networks.md:49-55` and `08-agntcy-acp-bridge-spec.md:324-335` both forbid advisory-capability widening into scope |
| replacement of MCP or A2A at wire-protocol ecosystem level (115) | 02, 08, 12, 13 | clean: each bridge runs alongside MCP / A2A, none replaces them |
| arbitrary plugins that redefine signed truth (104) | 04, 10 | **clean**: doc 04 routes engines through `ExternalGuard` and folds digests into `policy_hash` (`04-policy-engine-collaborators.md:346-364`); doc 10's `CedarLoadError::Invalid` rejects malformed policies at load time (`10-cedar-first-guard.md:425-438`). Engines are collaborators, not truth redefiners. |
| permissionless wallet-network beyond Chio profile (107-109) | 02 | clean |
| arbitrary chain anchoring (110-111) | none | clean |

Specific scrutiny of the suspects called out by the swarm prompt:

- **Doc 02 (NANDA / AGNTCY / Agora)**: the `DirectoryProvider` shape is
  strictly read-only with a hard clippy-enforced rule against advisory ->
  scope conversion (`08-agntcy-acp-bridge-spec.md:326-335`). The Agora
  bridge is research-track and gated by operator-allowlisted PD hashes
  (`02-decentralized-agent-networks.md:177-186`).
- **Doc 03 (OAuth)**: holds the PDP-plus-step-up line. The "issuer of last
  resort" framing is bounded explicitly to `chio-governed-rar-v1` and
  refuses DCR / refresh / SCIM / MFA (`03-oauth-oidc-issuer.md:140`).
- **Doc 04 (policy engines)**: Cedar / OPA / OpenFGA wired through
  `ExternalGuard`; Tetragon punted to observability, not made a guard
  (`04-policy-engine-collaborators.md:269-303`). No engine "redefines
  signed Chio truth"; each contributes a digest into `policy_hash`.
- **Doc 14 (voice, managed)**: the Vapi / Retell shim is operator-pointed
  HTTPS, HMAC-verified; no permissionless discovery, no telephony peering
  (`14-voice-agent-bridges.md:164-179`).
- **Doc 08 (AGNTCY ACP)**: the directory consumer enforces operator
  allowlist + closed-world resolution
  (`08-agntcy-acp-bridge-spec.md:241-260`). Empty `securitySchemes` is
  flagged and a refuse-non-HTTPS rule proposed (line 550-557).

No non-goals violations.

## Three-ACPs warning propagation

This is the **largest vision-level inconsistency** in the corpus.

- v1 overview (`00-overview.md:67-75`) carries an explicit "Naming-collision
  warning" naming Zed ACP, IBM ACP, AGNTCY ACP and forbidding `chio-acp-*`
  names for the new AGNTCY bridge.
- v2 overview (`00-overview-v2.md`) has **no equivalent section**. The
  warning is not propagated; the build-queue table at line 23 just says
  "AGNTCY ACP" without disambiguation.
- Doc 02 still says **`chio-bridge-acp`** (`02-decentralized-agent-networks.md:132, 243`)
  - the exact name the v1 overview forbade.
- Doc 08 obeys the warning and renames to `chio-bridge-agntcy`
  (`08-agntcy-acp-bridge-spec.md:11-13, 433-444`).
- Doc 12 (`12-openai-responses-adapter.md`), doc 13 (Bedrock Agents),
  doc 14 (LiveKit) do not use the bare token "ACP" without context, so
  they are fine.

Action items: (a) add the three-ACPs warning section to
`00-overview-v2.md`; (b) edit `02-decentralized-agent-networks.md:132, 243`
to rename `chio-bridge-acp` to `chio-bridge-agntcy`, matching doc 08; (c)
update line 8 of `00-overview-v2.md`'s "first-round docs unchanged" claim -
the naming fix in doc 02 is a second-round edit and should be acknowledged.

## Overview v1 vs v2 reconciliation

The relationship is undeclared. `00-overview-v2.md:7` says "round-1 docs
(`00-` through `06-`) are unchanged" but never says whether v2 supersedes
v1, builds on it, or is a delta document. The two phased queues disagree:

| Phase | v1 (`00-overview.md`) Phase A | v2 (`00-overview-v2.md`) Phase A |
|---|---|---|
| Top item | `EventPublish`/`EventConsume` variants | **Land real bench bodies** (new, urgent) |
| Item 2 | OAuth consumer/verifier posture | Current v1 receipt-kind schema (Option D) |
| Item 3 | Rename AS to "Chio Governed Authorization Bridge" | EventPublish/EventConsume variants (demoted) |
| OAuth AS | "rename + scope-clamp" | "feature flag + rename + scope-clamp" |

The deltas are real:

- v2's bench-stub finding (`00-overview-v2.md:13`,
  `16-latency-budget-audit.md:22-26`) is genuinely new and reorders the
  queue. v1 has no entry for it.
- v2 demotes the OAuth-consumer-posture work (RFC 9449 JWT DPoP, RFC 9470
  step-up, actor-chain validation) that v1 had as a top-three Phase A item.
  Doc 03 still proposes it but the v2 overview does not list it under any
  phase. **This is a regression in the overview, not in the underlying
  research.**
- v1 Phase C lists "AGNTCY ACP bridge" and "DirectoryProvider seam";
  v2 Phase C lists `chio-bridge-agntcy + chio-directory` (same items,
  agreed) plus `chio-livekit-py` (new from doc 14, agreed) plus per-bridge
  fast paths (new from doc 16, agreed).
- v1 "Defer or hard skip" lists database wire protocols, Agora, AGNTCY
  SLIM, Temporal/Airflow dedicated bridges; v2's Phase D defer list is
  much shorter and omits all four. The defers are not contradicted - they
  are just silently dropped.

**Recommendation**: v2 should be marked as **superseding** v1 and merge
the un-superseded parts back in (OAuth consumer-side step-up + DPoP +
actor-chain validation; the explicit defer list for DB / SOCKS / DNS /
TLS interception). Add a header to v2: "Supersedes 00-overview.md. v1
items not repeated below are explicitly carried forward; v1 items
contradicted below are explicitly retired." Keep v1 as a historical
record but link from v2 to it.

## "We already have" surprise propagation

Round 1 surfaced five surprises (`00-overview.md:13-23`):

1. Python `chio-streaming` SDK -> doc 09 (`09-event-action-schema.md:8-9, 210-237`)
   explicitly aligns the SDK with the kernel vocabulary. No doc proposes
   to "build a new pub/sub bridge" in ignorance.
2. Real OAuth AS in `chio-mcp-remote` -> doc 07 confirms it is live but
   opt-in (`07-oauth-as-usage-audit.md:5-7`). Doc 03 already knew about it.
   Reconciled.
3. `chio-temporal` and `chio-airflow` SDKs -> doc 05 keeps them as the
   primary recommendation, defers dedicated bridges
   (`05-workflow-orchestrator-mediation.md:27-32, 277-282`). No doc
   proposes a dedicated Temporal/Airflow bridge as priority.
4. `chio-envoy-ext-authz` covers QUIC/gRPC transparently -> doc 06 line 61
   confirms.
5. `ExternalGuard` + `AsyncGuardAdapter` -> doc 04 reuses it and doc 10
   threads through `ScopedAsyncGuard`
   (`10-cedar-first-guard.md:296-303`).

Propagation is clean. No doc still proposes to build something already
shipping.

## Crate count verification

`00-overview-v2.md:43` claims "Five new crates proposed + 1 existing
feature-flagged":

1. `chio-bridge-agntcy` (doc 08) - confirmed
2. `chio-directory` (doc 08) - confirmed at `08-agntcy-acp-bridge-spec.md:226-232`
3. `chio-bedrock-agents-adapter` (doc 13) - confirmed
4. `chio-openai-responses-adapter` (doc 12) - confirmed at `12-openai-responses-adapter.md:273-289`
5. `chio-livekit-py` (doc 14) - confirmed at `14-voice-agent-bridges.md:141-148`
6. Feature flag on `chio-mcp-remote` (doc 07) - confirmed

But other docs **propose more crates** that the v2 overview does not
enumerate:

- `chio-broker-contract` (`09-event-action-schema.md:29, 227`) -
  parallel to `chio-egress-contract`. New crate.
- `chio-orchestrator-egress` (`05-workflow-orchestrator-mediation.md:264-267`).
  New crate.
- `chio-directory-nanda` (`02-decentralized-agent-networks.md:61, 253`).
  New crate.
- `chio-transport-slim` (`02-decentralized-agent-networks.md:136-138, 263`).
  New crate (Phase 3, optional).
- `chio-bridge-agora` (`02-decentralized-agent-networks.md:187-188`).
  Research-track, but still a new crate.
- `chio-pipecat`, `chio-managed-voice-shim`
  (`14-voice-agent-bridges.md:159-178`). Two more new packages.
- `chio-tetragon-bridge` (`04-policy-engine-collaborators.md:299-303`).
  Deferred but proposed.
- `chio-bedrock-iam` extraction (`13-bedrock-agents-bridge.md:139-145`).
  New crate.
- `chio-wire-mediation` sibling (`06-below-l7-mediation.md:5, 82`).
  Reserved for future.

Actual count of *proposed-anywhere-in-the-corpus* new crates is closer
to **fourteen**. v2's "5 + 1 flag" is the right number only if you also
say "Phase A through C critical path." The v2 overview should clarify
that the five it lists are the *committed-to* set, and explicitly note
the future-reserved names (`chio-broker-contract`, `chio-orchestrator-egress`,
`chio-pipecat`, `chio-managed-voice-shim`, `chio-wire-mediation`) so the
naming surface is not silently colonized by later docs.

## Big-findings status

- **Bench-stub urgency (resolved in-tree)**: was clear in 00-overview-v2.md:13, 49 and in
  `16-latency-budget-audit.md:22-26, 244-265`. Docs 04, 10, and 14 cite
  per-stage latency numbers (e.g. `04-policy-engine-collaborators.md:108-112`,
  `10-cedar-first-guard.md:332-348`, `14-voice-agent-bridges.md:109-117`)
  that depended on benches which used to measure `black_box(0_u64)`. The
  bench bodies now drive real dispatch through `dispatch_request_fixture`,
  so the open work is re-baselining those per-stage numbers against the
  new bodies rather than backfilling missing measurement infrastructure.
- **`tool_origin` core vs extension**: **NOT consistent**. v2 overview
  line 14, 35, 53 says core v3 field with FOUR variants
  (`caller-executed`, `host-executed-provider-reported`, `host-executed-unmediated`,
  `host-executed-redacted`). Doc 12 line 150-157 enumerates THREE
  variants (no `redacted` form). Doc 15 line 425-432, 502-509 puts
  `tool_origin` inside `OpenaiResponsesExtension` and explicitly
  recommends keeping it on the extension, not promoting to core. Doc 13
  uses `mediation_scope` (binary `trace_only` /
  `full_runtime`) instead of `tool_origin`
  (`13-bedrock-agents-bridge.md:25, 97`). Doc 14 mentions neither. Pick
  one (the v2 overview is the right place to land the call) and have
  X1, E1, E2 amend.
- **n8n priority erratum**: doc 05 at line 56-73 still asserts priority
  1 without the Chain-C caveat. Doc 11 line 4-15 cleanly explains the
  caveat. v2 overview line 26 captures it. Recommended edit: a one-line
  "errata" note at the top of doc 05 pointing at doc 11.
- **OAuth AS verdict**: doc 03's "rename + scope-clamp" + doc 07's
  "Cargo feature flag" are *compatible*, not contradictory. Doc 07
  recommends outcome (c) which is keep-behind-flag + apply doc 03's
  rename and scope-clamp (`07-oauth-as-usage-audit.md:97-103`). v2
  overview line 22 captures this correctly. Add a one-line cross-link
  at the top of doc 03 noting doc 07's feature-flag addendum.

## Open questions reconciled

Round 1 open questions (`00-overview.md:77-83`):

1. "Is the existing OAuth AS actively used or stale?" -> **answered**
   by doc 07: live but opt-in, dead-by-default at runtime, no
   telemetry, no evidence of external partner use.
2. "Are `chio-temporal` and `chio-airflow` production-deployed?" ->
   **unanswered**; carried into v2 implicitly. Worth listing.
3. "Should `DirectoryProvider` be a new crate or live in
   `chio-federation`?" -> **answered** by doc 08: new `chio-directory`
   crate (`08-agntcy-acp-bridge-spec.md:225-232`).
4. "Cedar adoption greenfield vs migrate?" -> **answered** by doc 10:
   Option A' = greenfield + two flagship ports
   (`10-cedar-first-guard.md:352-373`).
5. "Vocabulary changes require manifest bump?" -> **answered** by doc 09:
   yes, `chio.manifest.v1` -> `v2`, additive, fail-closed via ceiling
   negotiation (`09-event-action-schema.md:181-208`).

v2 open questions (`00-overview-v2.md:77-83`) are new and load-bearing:
voice-tier policy classification, `must_understand` extension registry
ownership, AGNTCY zero-securitySchemes, async receipt write SLO,
bench-stub PR ordering. None repeat round-1 items.

## Top inconsistencies to fix

1. **Doc 02 names `chio-bridge-acp`** despite the v1 naming warning and
   doc 08's `chio-bridge-agntcy`. (`02-decentralized-agent-networks.md:132, 243`)
2. **v2 overview drops the three-ACPs warning** entirely.
3. **`tool_origin` shape disagreement** across 00-v2, 12, 13, 15. Three
   variants vs four; core vs extension; absent in 13 (uses
   `mediation_scope`).
4. **v1 vs v2 overview relationship undeclared**. Phase A items differ.
   OAuth consumer-side step-up (Phase A in v1) is dropped from v2's
   queue, though doc 03 still proposes it.
5. **Em dashes in both overviews**: 11 in `00-overview.md`, 20 in
   `00-overview-v2.md`. CLAUDE.md forbids U+2014 anywhere; the round-1
   and round-2 docs themselves are clean. Examples at
   `00-overview-v2.md:23, 25, 31, 39, 43, 47, 56, 58, 59, 61` and
   `00-overview.md:27, 31, 33, 37, 39, 42, 44, 71, 72, 73`.
6. **Crate count understated**: v2 lists 5 new crates; the corpus
   actually proposes ~14 if you include future-reserved names.

## Recommended edits per doc

- `00-overview-v2.md`: add explicit "supersedes 00-overview.md" header
  with carry-forward and retire lists; restore the three-ACPs warning;
  carry forward OAuth consumer-side step-up + DPoP + actor-chain as a
  Phase A item; enumerate future-reserved crate names; replace 20 em
  dashes with hyphens.
- `00-overview.md`: mark as superseded by v2; replace 11 em dashes
  with hyphens (or migrate the content into v2 and retire v1).
- `02-decentralized-agent-networks.md`: rename `chio-bridge-acp` to
  `chio-bridge-agntcy` at lines 132 and 243; cross-link to doc 08 as
  the canonical AGNTCY bridge spec.
- `03-oauth-oidc-issuer.md`: add a one-line cross-link to doc 07 noting
  the Cargo feature-flag addendum.
- `04-policy-engine-collaborators.md`, `10-cedar-first-guard.md`,
  `14-voice-agent-bridges.md`: add a one-line "Bench dependency" note
  at the top citing doc 16 bench stubs.
- `05-workflow-orchestrator-mediation.md`: add an errata note pointing
  at doc 11's Chain-C narrowing.
- `12-openai-responses-adapter.md`: align `ToolOrigin` enum variants
  with the v2 overview's four-variant set (add
  `host-executed-redacted` or have the v2 overview drop it).
- `13-bedrock-agents-bridge.md`: reconcile `mediation_scope` with
  `tool_origin`; either map Lambda to
  `tool_origin = host-executed-unmediated` and drop `mediation_scope`,
  or have v2 overview acknowledge two parallel fields.
- `14-voice-agent-bridges.md`: add `tool_origin = caller-executed` to
  the receipt-field table so the cross-cut is visible.
- `15-receipt-kind-v1.md`: promote `tool_origin` from
  `OpenaiResponsesExtension` to the core v3 body per v2 overview's
  call; reconcile open question 4 (`15-receipt-kind-v1.md:502-509`)
  with the v2 overview's verdict.

---

## Three-line summary

1. Vision coherence: **mixed**. Discipline ("lift, sign, return") is
   respected end-to-end; no non-goals violations; but overview-level
   inconsistencies (three-ACPs warning dropped, `tool_origin` shape
   disagreement, v1/v2 relationship undeclared) need fixing.
2. Biggest single violation: **doc 02 still names the AGNTCY bridge
   `chio-bridge-acp`** (`02-decentralized-agent-networks.md:132, 243`),
   which v1's naming warning forbade and doc 08 explicitly retracts -
   the `chio-acp-*` namespace already belongs to Zed ACP in
   `crates/chio-acp-edge`.
3. Path:
   this file.
