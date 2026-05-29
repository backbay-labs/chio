# Chio: Reading-Order Index

**Status**: Living index over the chio artifact set
**Date**: 2026-05-04

This index orients a new participant to chio. It does not duplicate
content from the artifacts; it tells you what each one is, in what
order to read them, and what dependencies the spec set has on each
other.

If you are short on time, read just sections 1 and 2 below, then
[CHIO_CONCEPT.md](CHIO_CONCEPT.md) sections 1-3.

---

## 1. What chio is, in one paragraph

Chio is the protocol of treaty-based, evidence-referential,
dynamically-trusted coordination across organisational kernels. It is
not a host the swarm lives inside; it is the discipline kernels follow
when they coordinate across trust boundaries. It sits above
[chio](../../README.md) (the trust-primitive layer) and orthogonal to
runtime projects like Swarm Team Six
(an in-production reference shape for one chio participant). The
hero use case is **cross-vendor agent action attestation**: when
Vendor A's agent invokes Vendor B's tool on a buyer's behalf, both
kernels produce a jointly-verifiable receipt the buyer's auditor can
verify without trusting either vendor unilaterally. Federated
detection swarms across organisational trust boundaries are a
second-wave application of the same primitives.

---

## 2. The artifact set

Eight documents. Three are concept / research, five are spec drafts
(four chio-side, one upstream proposal).

### Concept and research (`docs/research/`)

| File | Purpose | Lines |
|---|---|---|
| [CHIO_CONCEPT.md](CHIO_CONCEPT.md) v1.1 | Concept doc. Hero use case, architecture, hard problems, open decisions. | 381 |
| [CHIO_3VENDOR_FIXTURE.md](CHIO_3VENDOR_FIXTURE.md) | End-to-end worked scenario across three vendors and one buyer. Surfaces 11 numbered gaps in the spec set. | 798 |
| [CHIO_TRUST_ANCHOR_COSTS.md](CHIO_TRUST_ANCHOR_COSTS.md) | Operational analysis of bootstrap cost per sector. Tier 1 / Tier 2 / Tier 3 sequencing. | 284 |
| [CHIO_SCARCITY_ECONOMICS.md](CHIO_SCARCITY_ECONOMICS.md) | Quantitative analysis of when the pheromone source-diversity defenses actually constrain adversaries. Drives v0.2 of the pheromone spec. | 676 |
| [INTOTO_WG_ISSUE_DRAFT.md](INTOTO_WG_ISSUE_DRAFT.md) | Ready-to-paste GitHub issue body for upstream engagement with the in-toto attestation WG. | ~150 |

### Spec drafts (`spec/`)

| File | Status | Purpose | Lines |
|---|---|---|---|
| [CHIO_PHEROMONE.md](../../spec/CHIO_PHEROMONE.md) | Draft v0.2 | Wire-freeze for the chio-pheromone substrate. Gating spec from CONCEPT v1.1 section 4.1. | 589 |
| [CHIO_LADDER.md](../../spec/CHIO_LADDER.md) | Draft v0.1 | Governance ladder manifest schema. Per-action-class mode and consistency_model declaration. Gating spec from CONCEPT v1.1 section 4.2. | 1160 |
| [CHIO_SELECTIVE_DISCLOSURE.md](../../spec/CHIO_SELECTIVE_DISCLOSURE.md) | Draft v0.1 | BBS+ projection over ChioReceipt and WorkflowReceipt; predicate language; verification algorithm. Closes CONCEPT v1.1 hard problem 4. | 653 |
| [CHIO_BILATERAL_COSIGN_INVOCATION.md](../../spec/CHIO_BILATERAL_COSIGN_INVOCATION.md) | Draft v0.1 | in-toto attestation predicate proposal for upstream. Engagement artifact; not Chio-internal. | 586 |

---

## 3. Reading order by reader role

Pick one path. Each is self-contained.

### Newcomer reading cold

Goal: understand the shape and the pitch in under an hour.

1. [CHIO_CONCEPT.md](CHIO_CONCEPT.md) sections 1-3 (what it is, why it exists, architecture).
2. [CHIO_3VENDOR_FIXTURE.md](CHIO_3VENDOR_FIXTURE.md) the walkthrough (sections 1-9). Skip the gaps section unless you are reviewing.
3. Back to [CHIO_CONCEPT.md](CHIO_CONCEPT.md) section 5 (vs. other approaches) and section 6 (possibilities).

You can stop here and have a working mental model.

### Implementer planning to build

Goal: know exactly what wire formats and validation rules to honour.

1. [CHIO_CONCEPT.md](CHIO_CONCEPT.md) sections 1-3 (orientation), then section 9 (open decisions).
2. [CHIO_LADDER.md](../../spec/CHIO_LADDER.md) - the manifest declares everything else; read it first.
3. [CHIO_PHEROMONE.md](../../spec/CHIO_PHEROMONE.md) - the substrate the ladder targets.
4. [CHIO_SELECTIVE_DISCLOSURE.md](../../spec/CHIO_SELECTIVE_DISCLOSURE.md) - selective-disclosure proofs over receipts.
5. [CHIO_BILATERAL_COSIGN_INVOCATION.md](../../spec/CHIO_BILATERAL_COSIGN_INVOCATION.md) - the in-toto-shaped attestation surface (read whether or not you target in-toto; Chio's bilateral-cosign primitive is shaped the same way).
6. [CHIO_3VENDOR_FIXTURE.md](CHIO_3VENDOR_FIXTURE.md) end-to-end - exercise all four specs together; read the gap analysis last.

The 3-vendor fixture's gap section is the single highest-signal item for an implementer; it tells you what is missing in the chio crates today.

### Skeptic / reviewer

Goal: stress-test the framing.

1. [CHIO_CONCEPT.md](CHIO_CONCEPT.md) section 7 (hard problems, in priority order) and section 5 (vs. other approaches).
2. [CHIO_SCARCITY_ECONOMICS.md](CHIO_SCARCITY_ECONOMICS.md) - the load-bearing finding (sqrt(N) cap is a cost-shifter, not a cost-reducer) is here.
3. [CHIO_TRUST_ANCHOR_COSTS.md](CHIO_TRUST_ANCHOR_COSTS.md) - go-to-market is the constraint, not protocol design.
4. [CHIO_3VENDOR_FIXTURE.md](CHIO_3VENDOR_FIXTURE.md) gap analysis (last third of the doc).
5. [CHIO_CONCEPT.md](CHIO_CONCEPT.md) section 2.5 (trust-anchor honesty) - the honest framing of where centralisation still lives.

If you want to stress the cryptography, also read
[CHIO_SELECTIVE_DISCLOSURE.md](../../spec/CHIO_SELECTIVE_DISCLOSURE.md)
section 13 (v0.2 deferred lane) and section 14 (open questions).

### Strategic / business

Goal: understand the market wedge and adoption sequencing.

1. [CHIO_CONCEPT.md](CHIO_CONCEPT.md) sections 1, 2, 2.5, 6 (concept, hero, trust-anchor honesty, possibilities).
2. [CHIO_TRUST_ANCHOR_COSTS.md](CHIO_TRUST_ANCHOR_COSTS.md) - the Tier 1 / 2 / 3 sequencing maps to which sectors to lead with.
3. [CHIO_3VENDOR_FIXTURE.md](CHIO_3VENDOR_FIXTURE.md) sections 1-9 - the worked scenario is the demo.
4. [INTOTO_WG_ISSUE_DRAFT.md](INTOTO_WG_ISSUE_DRAFT.md) - upstream engagement artefact.

---

## 4. Spec dependency graph

```text
CHIO_CONCEPT (v1.1)
        |
        +--> CHIO_LADDER (v0.1)
        |       declares per-action-class mode + consistency_model;
        |       referenced by every other spec for action-class semantics
        |
        +--> CHIO_PHEROMONE (v0.2)
        |       wire-freeze for the substrate;
        |       depends on LADDER for cost_committed_only,
        |       newcomer_discount_horizon, destructive flag
        |
        +--> CHIO_SELECTIVE_DISCLOSURE (v0.1)
        |       BBS+ projection over receipts and workflow receipts;
        |       depends on LADDER for consistency_model field index;
        |       PHEROMONE section 11 defers to this spec
        |
        +--> CHIO_BILATERAL_COSIGN_INVOCATION (v0.1)
                in-toto predicate proposal;
                depends on LADDER for consistency_model values;
                depends on SELECTIVE_DISCLOSURE for the BBS+ commitment
                that may attach to the predicate body
```

Research artifacts feed back into the spec set:

```text
CHIO_3VENDOR_FIXTURE        --> surfaces gaps in PHEROMONE + LADDER +
                                   SELECTIVE_DISCLOSURE used together
                                   (G3/G9 are the load-bearing two)

CHIO_SCARCITY_ECONOMICS     --> drives PHEROMONE v0.2 calibration
                                   (sqrt(N) reframe, N=8 default,
                                   destructive observation-cost default)

CHIO_TRUST_ANCHOR_COSTS     --> informs CONCEPT section 2.5 framing
                                   and CONCEPT section 6 sector ordering

INTOTO_WG_ISSUE_DRAFT          --> packages BILATERAL_COSIGN_INVOCATION
                                   for upstream filing
```

---

## 5. Status snapshot

What is decided (in spec):

- Hero use case (cross-vendor agent action attestation), with
  federated SOC consortium as second-wave.
- Bilateral co-signing as the default joint-commit primitive;
  FROST-aggregated quorum as opt-in for action classes declared
  `quorum-required`.
- Per-action-class consistency model
  (`crdt-commutative` / `totally-ordered` / `quorum-required`).
- Pheromone substrate wire format (v0.2).
- Local pheromone deposit and hub-transit evidence, including signed
  workflow context and relay-owned transit chain validation.
- Governance ladder manifest schema (v0.1).
- Selective disclosure via BBS+ default with zkVM escape hatch (v0.1).
- in-toto bilateral-cosign-invocation predicate proposal (v0.1).
- Pheromone defaults: `N = 8` newcomer-discount, observation-cost
  commitments required for destructive subject classes.
- Trust-anchor bootstrap is operational, not protocol.

What is open (next decisions):

- `chio-workflow::StepRecord` extension for cross-vendor invocation
  (the load-bearing code change; G3/G9 from the 3-vendor fixture).
- BBS+ projection ordering: alphabetical-by-serde-field (per
  SELECTIVE_DISCLOSURE) vs schema-declared (open question 1 in that
  spec).
- in-toto WG response: do they want the predicate type, or do they
  prefer a sibling DSSE envelope variant?
- Sector roster issuer engagements per
  [CHIO_TRUST_ANCHOR_COSTS.md](CHIO_TRUST_ANCHOR_COSTS.md)
  Tier 1 (banking via SWIFT PKI; federal government via FPKI).

What is deferred (post-v0.1):

- zkVM escape-hatch wire format
  ([CHIO_SELECTIVE_DISCLOSURE.md](../../spec/CHIO_SELECTIVE_DISCLOSURE.md) v0.2).
- N-party FROST quorum normative spec (current research recommends
  bilateral trees as default; FROST opt-in is a sketch).
- SD-JWT VC bridging for EUDI Wallet compatibility (BLS12-381 is not
  approved on EUDI's curve list).
- `spec/CHIO_WORKFLOW_COMPOSITION.md` for chained workflow
  receipts (mentioned in BILATERAL_COSIGN_INVOCATION as a separate
  spec).
- Live pheromone relay runtime: persistence adapters, catch-up,
  scheduling, daemon transport, and workflow-context consumption.

---

## 6. Where to file feedback

- **Spec issues**: open against the spec file in this repo with the
  spec name in the title (e.g., `[CHIO_PHEROMONE] sqrt(N) framing`).
- **Concept-level pushback**: open against
  [CHIO_CONCEPT.md](CHIO_CONCEPT.md); reviewers are encouraged
  to read the v1.1 revision history first to avoid re-litigating
  v1.0 decisions.
- **in-toto WG outreach**: file the issue from
  [INTOTO_WG_ISSUE_DRAFT.md](INTOTO_WG_ISSUE_DRAFT.md) under your own
  GitHub identity once the spec is published to a public URL.
