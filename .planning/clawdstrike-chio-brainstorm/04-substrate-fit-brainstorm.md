# Substrate-Fit Brainstorm

Goal: find the smallest experiments that decisively prove or refute the
"clawdstrike endpoint = Chio polity" thesis. Constraints per experiment:
days-to-weeks, single laptop, no production deploy, demonstrable in 60
seconds.

The load-bearing claims in the peer thesis are, in priority order:

1. **Receipt-shape compatibility.** Clawdstrike's `EndpointDecisionReceipt`
   can be lifted into a Chio bilateral DSSE envelope (`predicateType =
   chio.endpoint-decision.v1`) and pass `chio-federation`'s strict
   verifier without changing the verifier.
2. **Constitutional refinement.** Real EDR policy promotions
   ("audit -> block") survive Chio's `amendment_admissible_iff_backward_refinement`
   check, and adversary-narrowing promotions get rejected.
3. **Multi-lane anchoring is real, not a slide.** A daily Merkle root of
   endpoint receipts can be written to Rekor + OTS via `chio-anchor` and
   verified later.
4. **Selective disclosure works at endpoint granularity.** A BBS
   projection of one endpoint's findings verifies for a cloud correlator
   that never sees the underlying receipts.
5. **OS-grounded admission.** The NE extension's `EgressPolicy.decision`
   verdict can drive a Chio admission hook decision end-to-end.

Each experiment below targets exactly one of these. Anything that tests
"can we architect this" rather than "does the load-bearing claim hold"
is excluded.

---

## Top experiment (highest signal-to-effort ratio)

**E1 — The receipt translation demo.**

- *Load-bearing claim:* (1) receipt-shape compatibility. If this fails,
  every other experiment is a paint job over a broken pipe.
- *Tools already in place:* `EndpointDecisionReceipt` struct
  (`clawdstrike/crates/libs/clawdstrike-policy-event/src/edr.rs:4820`),
  `DsseEnvelope` + `DsseStatement` + `BilateralPredicate` + the strict
  verifier (`arc/crates/chio-federation/src/bilateral_dsse.rs:332,295,166`
  and `arc/crates/chio-federation/src/bilateral_verifier.rs`),
  `sign_dsse_envelope_full` at line 630.
- *Glue surface:* one ~200-line test crate that (a) constructs a real
  `EndpointDecisionReceipt::for_detection(...)` from clawdstrike fixtures,
  (b) canonical-JSON-encodes it into a `DsseStatement.predicate` JSON blob
  with `predicateType = "https://chio.dev/endpoint-decision/v1"`, (c)
  signs with two Ed25519 keys (endpoint = "tool_server_a", a stand-in
  kernel = "tool_server_b"), (d) calls the existing strict verifier.
- *Pass criterion:* the strict verifier returns `Ok(_)` on a faithfully
  translated receipt and `Err` on a tampered payload byte.
- *If it passes:* the central typology mapping is real; we know the
  predicate vocabulary expansion is the actual work, not a research
  question.
- *If it fails:* the verifier rejects (probably on `subject.digest`
  recomputation, on `payloadType` mismatch, or on a `deny_unknown_fields`
  collision between `EndpointDecisionReceipt` and `BilateralPredicate`
  extension semantics). That tells us the bilateral predicate schema is
  too narrow to host EDR receipts unchanged and the whole "near-1:1"
  framing has to be downgraded to "bridge-only with a wrapper predicate".
- *False positive risk:* low. The verifier already enforces canonical
  bytes and `passport_key_fingerprint` matching; you can't accidentally
  produce a green light.
- *False negative risk:* medium. Verifier may reject for a
  field-name-mapping reason (e.g. snake_case vs camelCase) that is
  trivially fixable but feels load-bearing. Mitigation: when it fails,
  capture the exact `BilateralCoSigningError` variant so the failure
  mode is unambiguous.

This is the Monday experiment. Two days of work.

---

## Other experiments worth running

**E2 — The backward-refinement demo (3-5 days).**

- *Load-bearing claim:* (2) refinement actually distinguishes legitimate
  rule promotions from adversarial narrowing.
- *Tools already in place:* the Predicate ADT and `refinesOn` in
  `arc/formal/lean4/Chio/Chio/Treaty/PredicateLang.lean` (lines 47-95);
  the `amendment_admissible_iff_backward_refinement` theorem in
  `Intersection.lean:133`. The Lean side is decidable and
  computable, so we don't need a new proof, just terms.
- *Glue surface:* hand-translate one real policy delta from clawdstrike's
  bundle into two `Predicate` terms (`K_old`, `K_new`) over an enumerated
  `AtomTag` set covering ~20 receipt-id classes. Compute `refinesOn K_new
  K_old sample` from a sampled list of historical receipt ids. Then do
  the same for a deliberately adversarial promotion (e.g. "narrow the
  set of actors that match the rule to exclude the attacker only").
- *Pass criterion:* legitimate promotion yields `refinesOn = true`,
  adversarial yields `false`, on the same sample.
- *If it passes:* the formal refinement check actually has discriminative
  power on real EDR semantics. This is the Lean theorem demo the peer
  proposed, but anchored to real policy bytes.
- *If it fails:* either every promotion looks like refinement (the
  predicate language is too coarse) or none does (atoms are too fine).
  Either way the "audit -> block needs a Lean proof" pillar is dead until
  the atom vocabulary is rebuilt.
- *FP risk:* medium - you can cherry-pick a sample that makes the toy
  predicate succeed. Mitigation: pick the sample BEFORE writing the
  predicates.
- *FN risk:* low.

**E3 — The agent-tool-call cosignature demo (~1 week).**

- *Load-bearing claim:* bilateral DSSE actually buys something the EDR
  doesn't already have - cross-vendor cosignature at the tool boundary.
- *Tools already in place:* `sign_dsse_envelope_with_cosigner`
  (`bilateral_dsse.rs:769`), `tool_server_a`/`tool_server_b` fields in
  `BilateralPredicate` (line 175,177), `scope_digest` (228).
- *Glue surface:* a 50-line MCP middleware running locally that captures
  one Claude -> GitHub MCP `tools/call` request, packages
  `(actor_did, tool_id, scope_hash)` as a Chio bilateral predicate,
  cosigns with two local keys, and refuses to forward the tool call
  unless the strict verifier accepts under the expected scope. Then swap
  the scope predicate for a different one and demonstrate denial.
- *Pass criterion:* identical request bytes admit under scope predicate
  P_correct and deny under P_swap, with no clawdstrike code in the loop.
- *If it passes:* the cosignature primitive is the gain, and EDR is
  optional context. (Important: this might mean clawdstrike doesn't need
  Chio - or vice versa.)
- *If it fails:* the scope-predicate digest doesn't bind tightly enough
  to tool-call bytes, and we owe a new envelope variant.
- *FP/FN:* both low; it's a local interception, no flaky network.

**E4 — The anchor write demo (~1 week wall-clock, mostly OTS wait).**

- *Load-bearing claim:* (3) `chio-anchor` actually produces verifiable
  Rekor + OTS inclusion proofs without a customer in the loop.
- *Tools already in place:* `chio-anchor`'s `build_anchor_inclusion_proof`
  (`crates/chio-anchor/src/lib.rs:188`), `Web3CheckpointStatement`,
  Rekor and OTS lanes per `chio-anchor/src/{bitcoin,evm,solana}.rs`.
- *Glue surface:* one tiny binary that reads N JSONL receipts, builds
  a Merkle tree, calls `chio-anchor`'s submit path against the real Rekor
  public log + real OTS calendar. Wait a week for OTS confirmation.
  Run inclusion verification.
- *Pass criterion:* same root verifies via both lanes after the OTS
  Bitcoin confirmation lands.
- *If it passes:* the "anchored receipts" pillar is real and not a slide.
- *If it fails:* the work to ship the anchoring story is bigger than
  the peer's plan suggests, and `chio-anchor` is closer to a research
  artifact than a tool.
- *FP risk:* medium - OTS confirmation latency may mask issues that only
  appear in adversarial conditions.

---

## Skip these (low signal or wrong shape for this stage)

- **The OS-sensor demo (peer's #7).** The Chio admission-hook surface is
  shifting (chio-chiodos-runtime is still partially on a feature branch);
  plumbing NE verdicts in now tests glue, not the thesis. Defer until E1
  + E2 land.
- **The BBS projection demo (peer's #5).** `chio-selective-disclosure`
  is solid library code, but a one-endpoint BBS demo proves "BBS works"
  not "BBS-on-EDR-data works" - there is no fleet correlator on the
  other side yet to consume the projection, so success is hollow. Run
  this AFTER you have at least three real translated receipts (i.e.
  after E1).
- **A Lean theorem statement for SuspendProcessTree (peer's #2 in the
  prompt).** Writing a theorem statement without proof is cheap but
  proves nothing - it's a press release. Either write it as part of E2
  (where it pays its way) or skip.
- **Anything that requires the missing TerminateProcessTree executor or
  the TTL auto-expiry scheduler.** Those are clawdstrike-side gaps; you
  cannot test substrate fit against missing code.

---

## Novel experiment the peer didn't name

**E0 — The negative-control predicate-collision experiment (1 day).**

Before E1, run the test in reverse: take a `BilateralPredicate` that the
chio-federation suite already accepts, then mutate one byte of the
embedded predicate body in the in-toto Statement. Does the verifier
catch it? Does it catch a `predicateType` flip from
`chio.tool-call.v1` to `chio.endpoint-decision.v1` while keeping
identical payload bytes? This is one day's work and answers a question
that none of the peer's experiments answer: **is the verifier's
predicateType binding tight enough that we can introduce a new
predicate vocabulary without forking the verifier?**

If predicateType is bound only by the statement bytes and the verifier
has no allowlist, then we can ship endpoint-decision predicates as a
pure consumer of `chio-federation`. If predicateType is enforced
against a hardcoded allowlist, then every clawdstrike adoption ships
with a chio-federation fork - which kills the "category-of-one"
positioning in the peer's product story.

This is cheaper than E1, sharper than E1, and tells us whether E1 even
makes sense to run.

Pass criterion: byte-mutated payloads are rejected AND
predicateType-flipped envelopes are rejected when the consumer requests
a specific predicate type; non-allowlisted predicate types fail open or
fail closed in a known, documented way.

---

## What "the integration thesis is dead" would look like

The thesis dies if any one of the following lands:

- **E0 fails closed on unknown predicateType with no extension point.**
  Adopting Chio requires forking chio-federation per new predicate
  family. The "substrate" framing is a fiction; chio-federation is a
  bespoke verifier for the existing chio.tool-call predicate, not a
  substrate.
- **E1 fails with a structural rejection** (i.e. `BilateralPredicate`'s
  `deny_unknown_fields` collides irreparably with the receipt taxonomy,
  or canonical-JSON encoding diverges between the two codebases). Then
  "near-1:1" is wrong; every endpoint receipt needs a hand-mapped
  wrapper. The integration shrinks to "another publishing format" -
  worth doing but not category-defining.
- **E2 fails by accepting an adversarial promotion as refinement.** Then
  the headline claim ("audit -> block becomes an auditor-provable
  guarantee under Chio") is false, and the peer's product story collapses
  to "anchored receipts with a fancier signature scheme".
- **E2 fails by rejecting all real promotions.** Then refinement is too
  strict to be useful operationally; the EDR loop and the substrate
  cannot share a policy lifecycle.
- **E4 fails on the OTS lane** (proofs unverifiable after confirmation,
  or no confirmation in a reasonable window). The "multi-lane anchor"
  story is a single-lane story with a Bitcoin slide.

If E0, E1, and E2 all pass, the thesis survives its hardest tests at a
total cost of ~5 engineer-days. Run E0 Monday morning.
