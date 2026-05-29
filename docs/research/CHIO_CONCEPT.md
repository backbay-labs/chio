# Chio: Cross-Trust-Boundary Coordination for Agent Swarms

Status: Concept / Future Vision (next iteration of chio's federation surface)
Date: 2026-05-04 (v1.1)
Supersedes: CHIODOME_CONCEPT.md (2026-04-14)

Revision history:
- v1.0 (2026-05-04): initial chio framing; SOC consortium hero; pheromone substrate flagged as missing
- v1.1 (2026-05-04): hero pivoted to cross-vendor agent action attestation; SOC consortium demoted to second-wave; trust-anchor honesty added (section 2.5); pheromone substrate promoted from "missing" to gating spec (section 4); per-action-class consistency model added to governance ladder; partition-divergent co-sign added to hard problems; adjacent-work survey added (Sigstore, MLS, BBS+, MISP)

---

## 1. What Chio Is

Chio is the protocol of treaty-based, evidence-referential, dynamically-trusted coordination across organisational kernels. It is not a host the swarm lives inside. It is the discipline of how kernels behave when they coordinate across trust boundaries.

A chio is implicit in the federation graph: it is the transitive closure of peers willing to co-sign within some scope. Membership is not a roster you join; it is a property of the bilateral handshakes you have completed and the receipts you have jointly authored. There is no chio master kernel. Each kernel remains sovereign. The swarm emerges from the federation graph.

This reframe matters. The earlier framing (CHIODOME_CONCEPT, 2026-04-14) cast the system as a self-contained "agent nation-state" with an internal legislature, treasury, and citizenry. That framing assumed a deployable cluster, an internal voting body, and a fiscal mandate. The progress on chio since then makes that framing wrong-shaped: federation is bilateral, governance is evidence-referential rather than vote-counted, and trust is bounded by handshakes that explicitly expire. Chio is what you get when you take chio's primitives seriously.

---

## 2. Why This Exists: Cross-Vendor Agent Action Attestation

The hero use case is **cross-vendor agent action attestation**: when Vendor A's agent invokes Vendor B's tool on a buyer's behalf, both kernels produce a jointly-verifiable receipt that the buyer can audit without trusting either vendor unilaterally.

This matters because the third-party agent ecosystem is fragmenting fast. Buyers want to compose agents across vendors (LLM provider, tool provider, data provider, orchestrator) but they inherit liability for actions they did not directly approve. Today the answer is contractual (vendor SLAs, DPA addendums, audit rights nobody exercises). Chio is the cryptographic answer: every cross-vendor action produces a bilateral co-signed receipt that survives in both vendors' audit stores and the buyer's, with the workflow receipt capturing the multi-step plan as a single artefact.

The buyer pitch is concrete: "your auditor can verify every action your composed agents took across every vendor, without trusting any of them." The budget line exists (third-party agent governance, vendor risk management, AI/ML compliance) and is growing. The closest competing approach is Sigstore + in-toto extending to runtime invocation receipts, in active working-group discussion but not yet shipping; chio's bilateral co-signing semantics are structurally different (joint commit at action time vs. post-hoc transparency-log anchoring) and remain defensible even if Sigstore-for-runtime ships. Chio receipts written to Rekor as an additional property is a friendly integration, not a competitor-defeating move.

### Federated detection swarms as a second-wave application

The same primitives also support **federated detection swarms across organisational trust boundaries**. Each SOC runs an autonomous detection swarm internally; Chio lets two or more such swarms compose:

- pheromone deposits from peer SOCs flow into the local concentration calculation, weighted by peer reputation
- response actions that cross organisational boundaries are co-signed by both kernels
- compromised participants are expelled by revocation gossip propagating bilaterally through the graph
- adversary co-evolution arenas test the joint immune response and feed reputation
- workflow receipts capture multi-step joint incident response as single auditable artefacts

This is a real capability gap (no current system supports "Pouncer at SOC A taking destructive action partially authorised by Tom at SOC B with a single auditable workflow receipt"), but the binding constraints on SOC adoption are operational, not protocol: analyst capacity to triage shared IOCs, legal and PR liability of acting on a peer's signal, and attribution risk if a peer is wrong. MISP, FS-ISAC, H-ISAC, CISA AIS, and commercial threat-intel platforms (Recorded Future, ThreatConnect, Anomali) already address the *information* problem at scale. Chio's cryptographic accountability is useful in post-incident litigation and mostly invisible at incident time. SOCs will adopt it as a free byproduct of cross-vendor agent action attestation, not as a primary capability.

The repositioning here is a v1.1 correction: v1.0 led with the SOC consortium pitch because the swarm-team-six runtime was the most legible reference. The cross-vendor wedge is the better lead because it maps to a budget line, has a weaker incumbent, and the same primitives serve both.

The institutional and fiscal possibilities of the v1 (CHIODOME) framing are not dropped. They are demoted to long-term scenarios in section 6.

---

## 2.5 Trust Anchor Honesty

Chio unbundles centralisation from the wire. It does not eliminate it from operations.

The protocol layer is genuinely sovereign per kernel: trust establishment is bilateral, key pinning is per-peer, revocation propagates via gossip, and there is no master key, no validator election, no quorum threshold for routine action. But every kernel still has to answer the operational question: "which kernel public keys do I accept handshakes from in the first place?" The answer is necessarily out-of-band. In practice it will be one of:

- An industry consortium roster (an ISAC-equivalent for the relevant sector), published and signed.
- An out-of-band PKI (a CA, regardless of what it is called), with chio kernels acting as relying parties.
- Operator-mediated key exchange (does not scale past dozens of peers, fine for early adoption).
- A sector regulator publishing the canonical roster (likely outcome for finance and healthcare).

This is a feature, not a bug. Different application domains will choose different bootstrap models, and no protocol decision should constrain that choice. Chio deliberately does not specify the bootstrap layer.

But the doc must be honest in writing: chio is a sovereignty-preserving overlay on top of an operational trust anchor that the participants choose. The trust-anchor problem still exists. It has been moved out of the wire and into operations, where it is amenable to renegotiation, rotation, and sectoral choice. That is a real improvement over a single hardcoded anchor, but it is not the same as "no central authority."

The protocol is well-shaped to make the trust-anchor swap visible: a chio participant declares its accepted bootstrap roots in its passport, and any peer can verify whether the roots match its own expectations before the handshake completes. Trust-anchor migrations (a sector moving from operator-mediated exchange to a published roster) are a renewable contract, not a fork.

---

## 3. Architecture

Chio has three layers. Each cites the chio primitive that already implements it.

### 3.1 Three Layers

```text
+------------------------------------------------------------------+
|                        CHIO PARTICIPATION                     |
+------------------------------------------------------------------+
|                                                                  |
|  COORDINATION DISCIPLINE (cross-kernel, governance, market)      |
|  - Bilateral co-signed receipts                                  |
|    (chio-federation::bilateral)                                  |
|  - Trust establishment + key pinning + rotation                  |
|    (chio-federation::trust_establishment)                        |
|  - Revocation gossip with sparse-Merkle epoch roots              |
|    (chio-revocation-oracle + federation::revocation_gossip)      |
|  - Evidence-referential governance cases                         |
|    (chio-governance: dispute / freeze / sanction / appeal)       |
|  - Open-market task allocation                                   |
|    (chio-open-market: BidRequest -> AskResponse -> AcceptedBid)  |
|  - Workflow receipts as the unit of joint cognition              |
|    (chio-workflow)                                               |
|  - Deterministic local reputation as a pure function over        |
|    receipts and lineage (chio-reputation)                        |
|  - Adversary co-evolution arenas with replayable fitness         |
|    (chio-arena: coevolve, leaderboard)                           |
|                                                                  |
+------------------------------------------------------------------+
|                                                                  |
|  PARTICIPANT KERNEL (one swarm per organisation)                 |
|  Reference shape: Swarm Team Six runtime                         |
|  - Telemetry ingest -> Whisker detection -> pheromone substrate  |
|  - Tom governance ladder (observation / guarded / receipt-backed |
|    / partition-contingency / maintenance)                        |
|  - Pouncer dispatches response under capability lease            |
|  - Bounded async lanes (Stalker, Weaver, Sphinx, Calico, Kitten) |
|  - Tick-based dispatcher with shared mode and health             |
|                                                                  |
+------------------------------------------------------------------+
|                                                                  |
|  PROTOCOL LAYER (chio)                                           |
|  - Capability tokens, attenuated delegation                      |
|  - Guard pipeline (chio-guards, chio-data-guards,                |
|    chio-external-guards, chio-wasm-guards)                       |
|  - Receipt log (Merkle-committed, anchorable)                    |
|  - Agent passports (chio-credentials)                            |
|  - Provenance DAG (chio-lineage)                                 |
|  - Tower middleware turns any HTTP service into a participant    |
|    (chio-tower)                                                  |
|                                                                  |
+------------------------------------------------------------------+
```

Two things to notice:

- **The middle layer is not part of chio.** It is a separate runtime (STS in the cybersec domain; could be other runtimes for other domains). Chio participation is what happens when that runtime adopts the disciplines in the top layer.
- **The top layer is not a deployment.** It is a set of disciplines a participant kernel agrees to honour. Joining the swarm is implicit in honouring them, not in installing anything.

### 3.2 Roles, Cross-Domain

The v1 doc defined institutional roles (Legislature, Executor, Policy Lab, Citizen). The STS roles already cover the same archetypes with better domain-specific names. The chio role taxonomy generalises them across domains:

| Archetype | STS name | v1 chiodome name | Function | Authority |
|---|---|---|---|---|
| Sensor | Whisker | Oracle | Ingests signals, deposits pheromones | Read + deposit, no execution |
| Investigator | Stalker | Auditor | Follows leads, reconstructs lineage | Read + query, can flag |
| Correlator | Weaver | Analyst | Joins signals into incidents | Read + publish, advisory |
| Responder | Pouncer | Executor | Executes approved actions | Write under capability lease |
| Governance | Tom | Legislature | Issues receipts, manages quorum | Governance, no direct execution |
| Evolver | Kitten | Policy Lab | Drift-driven mutation + canary | Proposal authority |
| Memory | Sphinx | Archivist | Durable knowledge graph | Append-only knowledge |
| Adversarial | Calico (deception); arena coevolve | Stress Tester | Adversary deployment + fitness | Sandboxed only |

A finance-domain participant might call its Sensor an "Oracle" and its Adversarial role an "Adversary"; a cybersec participant uses Whisker and Calico. The capability scopes and governance authority are domain-independent.

### 3.3 How Decisions Get Made (Cross-Trust-Boundary)

**Routine cross-org coordination** (most cross-org actions; Observation mode):

1. Local Whisker deposits a signed pheromone in the local substrate.
2. Federation gossip pushes selected deposits to peers under treaty scope.
3. Peer concentration calculation weights the deposit by peer reputation (a deterministic local function over observed receipts).
4. No co-signing required; observation is non-destructive and audited.

**Joint destructive action** (Receipt-backed mode):

1. Local Pouncer asks local Tom for a destructive-response receipt.
2. If the action affects a peer's domain (for example, revoking a credential the peer issued), the request is escalated to bilateral co-signing.
3. Both kernels independently evaluate the request; both sign the same canonical body via [chio-federation::bilateral](../../crates/chio-federation/src/bilateral.rs).
4. Either party can verify the action retrospectively from its own receipt store; neither party can rewrite the joint history.
5. A workflow receipt captures the full joint multi-step plan, signed by both kernels at the boundary tick.

**Cross-org task allocation** (Market mode, not committee):

1. A participant publishes a [BidRequest](../../crates/chio-open-market/src/bidding.rs) for a hunt, investigation, or response action.
2. Peers respond with AskResponses; pricing reflects local cost and confidence.
3. The requester signs an AcceptedBid; the AcceptedBid mints a scoped capability for the awarded peer.
4. The peer executes under the capability lease; the workflow receipt produces a complete trace.
5. Reputation updates from execution outcome plus arena-fitness signals.

**Compromised peer expulsion** (Sanction case + revocation gossip):

1. Evidence of misbehaviour accumulates in the local receipt store.
2. A [chio-governance](../../crates/chio-governance/src/lib.rs) Sanction case is filed with named evidence (signed listings, prior trust activations, operator reports).
3. Any third party can replay the case from the evidence and reach the same finding (no vote required).
4. On enforcement, the [passport revocation bridge](../../crates/chio-revocation-oracle/src/passport_bridge.rs) flips the peer's passport state.
5. The next [revocation oracle epoch](../../crates/chio-revocation-oracle/src/epoch.rs) root carries the change; bilateral [revocation gossip](../../crates/chio-federation/src/revocation_gossip.rs) propagates pairwise.
6. Kernels fail-closed against the revoked peer at next verdict, freshness-gated to prevent permanent contagion from transient gossip outages.

**Partition contingency** (rare; copy STS's pattern verbatim):

1. Federation peers detect a partition in the trust graph.
2. Each side issues a contingency lease with explicit blast-radius cap and TTL.
3. Destructive actions during the partition produce enhanced receipts with lease reference.
4. On reconnection, mandatory reconciliation via a governance case.

### 3.4 Adopting STS's Governance Ladder

Chio adopts the four-mode governance ladder shipping in STS today (sibling repo, `docs/CONSENSUS.md`):

| Mode | Coverage | Required artefact |
|---|---|---|
| **Observation** | Detection, investigation, correlation, memory, status publication | Standard signed deposits and audit only |
| **Guarded response** | Non-destructive escalation, decoy deployment, listing publication | Policy validation and ordinary audit |
| **Receipt-backed response** | Destructive actions (block, isolate, revoke) | Signed governance receipt; bilateral co-signing if cross-org |
| **Partition contingency** | Destructive response under partition | Staged contingency lease + later reconciliation |
| **Maintenance** | Operator review, export, replay | Authenticated operator access only |

The ladder generalises beyond cybersec: any chio participant slots its action surface into one of the five modes. The crucial property is that **most cross-org coordination is Observation** (cheap, no joint signature) and only the destructive minority requires Receipt-backed bilateral co-signing.

---

## 4. What Chio Still Needs to Specify

Two specifications gate further chio work. **Both must land before more code ships in chio-federation, chio-market, chio-governance, or chio-workflow,** because all of these touch wire formats the specifications will define. This is the load-bearing path; deferring either turns chio into retrofitting later.

### 4.1 Pheromone Substrate (chio-pheromone) - the gating spec

Adapt STS's `swarm-pheromone` (sibling repo, `crates/swarm-pheromone/src/lib.rs`) into a chio-native substrate. Recommended crate boundary: new top-level `chio-pheromone` beside `chio-reputation` and `chio-federation`, depending only on `chio-core-types` and `chio-credentials`; reputation is *not* a dependency (avoids a cycle since pheromone outcomes feed reputation via outcome receipts). Federation gossip lives in a thin sibling module under `chio-federation` (mirroring how `chio-revocation-oracle` and `chio-federation::revocation_gossip` factor today).

Required surface:

- Signed deposits with exponential decay; canonical-JSON-signed bodies on top of the existing chio crypto stack.
- Subject hierarchy keyed on a domain-supplied class (threat class for cybersec, signal class for finance, compliance class for governance domains, and so on); soft-pluggable so cross-domain chio works.
- Source-diversity enforcement: deposits signed by per-agent passport keys (not kernel keys), counted as `(kernel_id, agent_passport_key_hash)` pairs. Per-pair token-bucket budget per epoch. Per-kernel cap of `O(sqrt(active_peers))` distinct passport keys per subject-class per window (Cheng-Friedman scarcity result; see hard problem 8).
- Evaporation garbage collection.
- Newcomer-discount: a passport's effective weight is `min(1, age_in_anchored_epochs / N)` to mitigate whitewashing. Combine with org-level binding in revocation evidence so a fresh passport from a sanctioned org inherits the sanction.
- Verifiable observation-cost commitment field on deposits (e.g., a hash-chain reference to telemetry receipts), so peers that only co-sign without originating can be detected and weight-capped by the scorer.
- Federation gossip: reuse the bilateral push-queue pattern from `chio-federation::revocation_gossip` verbatim, scoped per-treaty at subscribe boundary; FIFO with per-origin rate limit (no supersession; pheromones do not replace each other).
- Receiver-side reputation weighting at concentration-query time, via a closure injected by the chio runtime (substrate stays unaware of reputation), pinned to a `chio-anchor` epoch so concentrations are reproducible.
- Optional ZK selective disclosure for sensitive deposits (proof of concentration without revealing raw indicators); see [CHIO_ZK_RECEIPT_PROOFS_MEMO.md](CHIO_ZK_RECEIPT_PROOFS_MEMO.md) and the BBS+/zkVM choice still open at the time of v1.1.
- Storage-agnostic substrate trait, like `chio-reputation` does. Reference impls: in-memory and local-journal; JetStream and other durable backends live in adapter crates so chio's "no host required" property survives.

**Why this is gating, not optional:** the substrate is the missing stigmergic layer. Without it, chio is committee-shaped, not swarm-shaped, and every other primitive (federation gossip surface, reputation weighting function, ZK disclosure shape, action-class consistency model) has to retrofit around whatever wire eventually ships. The wire freeze must come first.

### 4.2 Action-Class to Governance-Mode Mapping (with consistency model)

Specify which action classes map to which governance modes, declared as a per-participant **governance ladder manifest** signed and pinned at federation handshake time. [chio-governance](../../crates/chio-governance/src/lib.rs) has dispute / freeze / sanction / appeal cases but does not yet stratify governance intensity by action class.

The manifest declares, per action class: `mode` (Observation / Guarded / Receipt-backed / Partition-contingency / Maintenance), `destructive` (boolean; destructive must be at or above the declared `destructive_floor`), `cross_org_visibility`, `evidence_required`, `co_sign` (`none` / `bilateral_if_cross_org` / `bilateral_required` / `n_of_m`), optional `partition_fallback` with `lease_kind`, `blast_radius_cap`, and TTL.

The manifest must also declare a **consistency model per action class.** This closes the gap that bilateral co-signing alone leaves open. Bilateral trees prove N parties signed but not that they signed *consistently*: A↔B can co-sign credential X's revocation at t=10 while B↔C co-sign continued use of X at t=11, with both receipts independently valid (the partition-divergent co-sign problem; see hard problem 2). The fix is to declare consistency at the action-class level:

- `crdt-commutative`: deposits and observations whose merge operation is commutative and absorbs divergence (IOC pheromones, listings, status updates). Bilateral trees are sufficient; partition-divergent co-signs converge automatically on reconnect.
- `totally-ordered`: actions that require a hash-chained ordering anchor (workflow steps, sequential capability grants). Bilateral trees plus an anchor reference catches divergence.
- `quorum-required`: destructive actions that mutate shared state (revocations, settlements, sanctions). FROST-aggregated quorum signature over a canonical body, with the quorum scope declared at handshake time. This is the opt-in N-of-M path from the joint-commit research; it lives here as a per-action-class declaration, not a wire-level alternative.

A ladder manifest that declares a destructive class as `crdt-commutative` is rejected at handshake (validation rule `ladder.consistency_underspecified`).

Cross-domain conflict resolution (when Org A's cybersec ladder and Org B's financial ladder federate and an action class is in one but not the other): handshake produces a co-signed `ladder_intersection` artefact listing the higher-intensity mode of the two ladders per class; treaty scope only authorises classes in the intersection; unknown classes fall back to the local kernel's `default_unmapped_mode` (recommended: `receipt_backed`, never lower); refuse handshake when destructive_floor is missing or differs by more than one rung. Aliases handle shared semantics with different names across domains.

The full schema is a separate spec artefact (`spec/CHIO_LADDER.md`, to be written); v1.1 names it as gating work, not a complete design.

---

## 5. What Makes Chio Different

### vs. CHIODOME (the v1 framing)

- v1 was a single-host nation-state with a Legislature; chio is a federation discipline with no host.
- v1 reached for Tendermint BFT for joint decisions; chio prefers bilateral co-signing trees that compose, with BFT as an opt-in special case.
- v1 derived legitimacy from internal voting; chio derives it from evidence-referential cases that any third party can replay.
- v1 needed plutocracy mitigation; chio has no roster to capture.

### vs. STS (and any single-org swarm runtime)

STS is the in-production reference for what one chio participant looks like internally. It is single-org by design: Tom is the legislature, the registry is the trust root, and there is no cross-kernel handshake. Chio is what STS becomes when two or more SOCs share pheromones.

The relationship is layered: STS-style runtime (or any equivalent) at the participant level, chio disciplines at the cross-trust layer. Joining chio does not require replacing the participant runtime.

### vs. ISACs and STIX / TAXII

ISACs are humans-in-the-loop intel sharing. STIX / TAXII is a slow, polling, document-shaped feed. Chio is real-time stigmergic deposit propagation with cryptographic accountability and bounded trust expiry. The closest existing analogue is something like CISA's automated indicator sharing, but with sovereign per-org kernels and bilateral co-signed receipts instead of a central hub.

### vs. DAOs

DAOs are voting systems bolted onto treasuries. Chio has no token, no electorate, and no quorum threshold for routine action. Cross-org coordination is mostly observation-mode, with bilateral co-signing only at destructive boundaries. Plutocratic capture has no surface to attack.

### vs. Multi-Agent Frameworks (CrewAI, AutoGen, LangGraph)

These coordinate task execution within a single trust boundary. Chio is the trust-boundary protocol; it composes orthogonally with any of them. A participant kernel could use LangGraph internally and still join a chio via [chio-tower](../../crates/chio-tower/src/lib.rs) middleware.

### vs. Agent-to-Agent Payment Protocols (x402, ACP)

Payment protocols move money between agents. Chio manages the institutional context around why something is allowed: who signed, under what treaty, with what reputation, producing what auditable workflow receipt. Chio uses these protocols as plumbing, not as substitutes.

### vs. Sigstore / in-toto / SLSA for runtime attestation

Sigstore + in-toto + SLSA today are artifact-centric: build provenance signed by builder identity, anchored in Rekor's transparency log. Chio uses Sigstore today for release-artifact verification ([chio-attest-verify](../../crates/chio-attest-verify/src/lib.rs)).

The in-toto attestation working group has active discussion (OpenSSF AI/ML Security WG, CoSAI Workstream 4) about extending to runtime invocation receipts. The predicate-shaped slice ("agent A invoked tool B with args C at time T, signed by builder identity") is likely 6-12 months out via someone like Microsoft's Agent Governance Toolkit or a CoSAI WS4 spinout. **The structural slice is durable**, not temporal: bilateral co-signed *intent* (both parties independently evaluated and signed the same canonical body), per-action attenuated capability scoping, workflow receipts as joint multi-party plans, and evidence-referential governance over a lineage DAG are different questions than transparency-log-anchored single-party signatures. Co-signing on top of Rekor is possible (DSSE multi-sig + custom predicate), but the predicate, the verifier, the capability binding, and the dispute model are not what Sigstore ships.

The right posture: **reposition the chio cross-vendor pitch around the structural slice that does not collapse**, and treat Rekor anchoring as a free integration win (write chio receipt DSSE envelopes to Rekor v2 for public tamper-evidence; the inverse path of [chio-attest-verify::sigstore](../../crates/chio-attest-verify/src/sigstore.rs) is small). Engage Aditya Sirish A Yelgundhalli (in-toto), Tom Hennen (SLSA), and the CoSAI WS4 / OpenSSF AI/ML WG early on a "bilateral co-signed invocation" predicate proposal: either chio's semantics get into the in-toto vocabulary, or the structural gap gets confirmed in writing.

---

## 6. Possibilities

### Near-term (the hero scenario)

**Cross-vendor agent action attestation.** Vendor A's agent invokes Vendor B's tool on a buyer's behalf; both kernels co-sign the receipt; the buyer's auditor verifies every cross-vendor action without trusting either vendor unilaterally. Maps to a real budget line (third-party agent governance, vendor risk management, AI/ML compliance). The closest competing approach is in-toto extending to runtime invocation receipts; the predicate-level overlap is real but the bilateral-consent + capability-scoping + workflow-receipt slice is structurally distinct. This is the lead pitch.

**Federated SOC consortium.** Two-to-five SOCs sharing pheromone gradients across organisational boundaries. Detection deposits flow under bilateral treaty scope. Destructive cross-org actions (for example, blocking a credential one org issued and another sees abused) are bilaterally co-signed. Compromised participants are expelled by revocation gossip. Adversary co-evolution arenas feed reputation. The same primitives, applied to the cybersec domain. Adoption follows the cross-vendor wedge into market because the binding constraints on SOC adoption are operational (analyst capacity, legal liability, attribution risk), not protocol; SOCs will take chio as a free property of cross-vendor agent governance, not as a primary capability they buy.

### Medium-term

**Industry detection consortiums.** Whole sectors (finance, healthcare, energy) with shared chio infrastructure. Sector-specific subject-class taxonomies and governance ladders. Attestation-bearing pheromones counted toward sector regulatory reporting.

**Cross-org incident response workflows.** Multi-step joint incident response (detect at A, investigate at B, contain at C) signed as one workflow receipt. The chain of custody is cryptographically intact across orgs.

### Long-term

**Cross-organisation agent consortiums for non-cybersec domains.** Supply chain coordination, joint ventures, industry consortiums where multiple companies' agents collaborate under shared chio discipline.

**Public-infrastructure chioes for shared resources.** Compute markets, data commons, research funding pools managed as cross-org agent collectives. The v1.0 doc led with this; v1.1 demotes it because the cross-vendor hero is closer to shipping.

**Fiscal-policy laboratories.** The original CHIODOME framing. Still possible if the model proves out, but no longer the thesis.

---

## 7. Hard Problems (Unsolved)

Re-ordered in v1.1 by load-bearing impact on near-term work.

1. **Pheromone substrate freeze, see section 4.1.** The wire format must land before more code ships in chio-federation, chio-market, chio-governance, or chio-workflow. Deferring this is the most expensive mistake in the architecture.

2. **Partition-divergent co-sign (the bilateral-tree double-spend analogue).** A↔B can co-sign credential X's revocation at t=10 while B↔C co-sign continued use of X at t=11; both `DualSignedReceipt`s are independently valid with no global ordering to catch the conflict. Section 4.2's per-action-class consistency model (`crdt-commutative` / `totally-ordered` / `quorum-required`) is the proposed answer and lives inside the governance ladder manifest. Residual: classes whose semantics genuinely have no clean consistency model are forced into `quorum-required` and inherit FROST-quorum operational overhead.

3. **Action-class governance mapping, see section 4.2.** Until specified, peers cannot declare or interpret each other's governance intensity. Coupled to #2 because the consistency_model lives in the same manifest.

4. **Privacy and selective disclosure.** Receipts are signed canonical JSON, hence cleartext. Cross-trust participation needs selective-disclosure proofs over receipts so two parties can prove "we authorised X" to a third without revealing the body. v1.1 leans toward a hybrid: BBS+ (`bbs-2023` cryptosuite plus AnonCreds v2 `RangeStatement` predicates) as the default surface for the three driving use cases (cybersec confidence-threshold, finance amount-cap, compliance tier-floor), with a zkVM (Risc0/SP1 + Groth16 wrap) escape hatch for chained-receipt proofs, predicates over the Ed25519 signature itself, or non-arithmetic boolean logic. Receipt format gains a parallel `bbs_messages()` projection; Ed25519 over JCS stays authoritative; BBS+ becomes a secondary commitment. EUDI Wallet does not approve BLS12-381, so non-EUDI interop is the BBS+ target and EUDI bridging needs SD-JWT VC mapping. See [CHIO_ZK_RECEIPT_PROOFS_MEMO.md](CHIO_ZK_RECEIPT_PROOFS_MEMO.md).

5. **Reputation-poisoning attack surface.** Receiver-side reputation-weighted concentration is the same surface 15+ years of collaborative-IDS literature targets (Fung & Boutaba BTrM, Hoffman-Zage-Nita-Rotaru CSUR 2009 taxonomy, Fang et al. USENIX 2020 on Krum/median brittleness, more recent FL-poisoning surveys). Concrete defenses by layer: chio-pheromone owns Cheng-Friedman sqrt(N) passport-key cap per kernel, per-pair token bucket, observation-cost commitment field, newcomer age-discount; chio-reputation owns asymmetric EWMA (penalty rate >> reward rate per Buchegger-Boudec), confidence-variance weighting, collusion-cluster Jaccard penalty; chio-arena owns replayable-precision adversary scoring exported as a multiplicative reputation factor.

6. **Multi-party (more than two) joint signature semantics.** Bilateral trees with path-cover predicate are the recommended default; FROST-aggregated Ed25519 over a canonical body is the opt-in for action classes declared `quorum-required` in the governance ladder manifest. Smallest validating experiment: a 3-party fixture in `crates/chio-federation/tests/` reusing the existing `InProcessCoSigner` to drive A-B over R1 and B-C over a parent R2 referencing R1's hash, with a `verify_joint_commit(set, root)` helper that walks the DAG.

7. **Trust anchor bootstrap, see section 2.5.** Bilateral handshakes still need an out-of-band root. The protocol layer cannot solve this; operational design per sector is required.

8. **Discovery gossip without leakage.** Listings are local-by-default. The federation needs a gossip layer for cross-org discovery that does not leak each org's full tool surface to every peer. Reusing the bilateral revocation-gossip pattern, scoped per-treaty, is the leading direction.

9. **Reputation epoch-pinning.** Two peers with divergent receipt corpora compute divergent reputation scores. Anchor reputation to a named epoch ([chio-anchor](../../crates/chio-anchor/src/lib.rs)) so cross-peer comparison is always epoch-qualified.

10. **Jurisdiction.** Bilateral co-signing helps (each side has a court-admissible artefact in its own jurisdiction), but the legal structure for cross-org chio still needs careful design per domain.

### Honest residuals (defended-imperfectly)

- **Sustained majority collusion.** Cheng-Friedman (PODC 2005) and Fang et al. (USENIX 2020) both prove no symmetric weighting survives if more than ~50% of effective passport mass (not peer count) is adversarial under coordinated strategy. Mitigation must be exogenous: bilateral handshake admission must keep effective adversarial mass below ~30%.
- **Mimicry-style slow-drift below sensor noise.** Diffusion/GAN-generated deposits can be made indistinguishable from honest deposits at any single window. Arena replay catches them only if arena coverage overlaps the mimicked subject-class; residual loss in uncovered classes must be accepted and budgeted.
- **Cross-org operator collusion via friendly re-issuance.** If two distinct operator-orgs cooperate to re-issue passports for sanctioned operators, no in-band reputation function detects this. Out-of-band governance (chio-governance Sanction case against the *issuing org*, not the passport) is the only recourse.

---

## 8. Relationship to Chio and STS

Chio is not a fork. It is a layer that sits above chio and orthogonal to runtime projects like STS:

- **Chio** provides the trust primitives (capabilities, receipts, federation, governance, revocation, market, workflow, reputation, lineage, arena).
- **STS** (and any equivalent runtime) provides the participant-kernel shape: how one organisation runs an internal swarm.
- **Chio** is the discipline by which two or more such kernels coordinate across trust boundaries.

The two missing specifications (chio-pheromone substrate and the governance ladder manifest with consistency_model) live in chio. Adopting them does not change STS; it lets STS-style runtimes compose into a chio.

Chio ships when chio's federation, governance, revocation, market, and workflow primitives are stable in production and the two gating specifications land. It is no longer "post-chio launch"; it is "next iteration of chio's federation surface."

---

## 9. v1.1 Open Decisions and Next Moves

Tracked here so the next revision has a clear inheritance.

**Decisions made in v1.1:**

- Hero use case is cross-vendor agent action attestation; SOC consortium is second-wave, served by the same primitives.
- chio-pheromone is gating, not deferred.
- Per-action-class consistency model (`crdt-commutative` / `totally-ordered` / `quorum-required`) lives in the governance ladder manifest.
- Multi-party joint commit defaults to bilateral trees with a path-cover predicate; FROST quorum is the opt-in for action classes declared `quorum-required`.
- Selective disclosure leans BBS+ (`bbs-2023` + AnonCreds v2 predicates) as default, zkVM as escape hatch.
- Chio receipt DSSE envelopes anchored to Rekor v2 is a free integration win, not a competitor-defeating move; the cross-vendor pitch leans on the structural slice.
- Trust-anchor bootstrap is operational, not protocol; the doc says so in writing (section 2.5).

**Open decisions still owed:**

- `spec/CHIO_LADDER.md`: the full ladder-manifest schema (worked tables for cybersec, financial, compliance domains exist as research output and need to be normalised into a spec).
- `spec/CHIO_PHEROMONE.md`: the wire format for chio-pheromone deposits, gossip envelopes, and concentration queries.
- BBS+ receipt-format migration: schema-versioned `bbs_messages()` projection over `ChioReceiptBody`, ordered field list, secondary BBS keypair per kernel. Coupled to selective-disclosure spec.
- Engagement plan with in-toto / SLSA / CoSAI WS4 to either land "bilateral co-signed invocation" predicate semantics in their vocabulary or confirm the structural gap in writing.

**Next research lanes worth spawning:**

- Worked example of a 3-vendor cross-vendor scenario end-to-end (BidRequest, AcceptedBid, bilateral co-signed invocation receipt, workflow receipt, ladder-intersection check, BBS+ disclosure to a buyer auditor), as a reference fixture.
- Cost model for the operational trust-anchor problem per sector (which sectors have a natural roster issuer; which need a chio-specific consortium; which can use existing PKI).
- Adversarial economics: at what passport-issuance cost does the Cheng-Friedman scarcity argument bite for a given operator-org budget?
