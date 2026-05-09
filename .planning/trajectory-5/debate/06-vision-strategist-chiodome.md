# Position Paper 06: The Chiodome Slice

**Author role:** Vision Strategist (Chiodome / Economic Substrate)
**Date:** 2026-05-07
**Trajectory:** release work scoping debate
**Disposition:** Pick the moat. Demo it. Ship one bilateral cosigned invocation, end-to-end, with bounded labels.

---

## 1. Thesis

Chio is not "another tool-call gateway." Every adapter shop on earth is
building one of those. The hardening lanes (HTTP egress, SSRF, hybrid PQ,
mobile attestation) are necessary but **fungible**: they are commodity floor
that every protocol-substrate project converges to within 18 months.

The Chiodome bet, recorded in user memory at
`local project vision note`,
is that "agent swarm congregates as digital fiscal nation states... combines
the chio (ARC) protocol layer for secure attested agent capabilities... with
the swarm architecture from standalone/swarm-team-six... applied to finance
and governance domains instead of just cybersecurity." That is the moat.
That is the asymmetric bet no other agent-protocol project is equipped to
make, because no other project ships:

- a credit substrate (`crates/chio-credit/src/lib.rs` with
  `chio.credit.exposure-ledger.v1`, `chio.credit.scorecard.v1`,
  `chio.credit.facility.v1`, `chio.credit.bond.v1`,
  `chio.credit.capital-book.v1`, `chio.credit.bonded-execution-simulation-report.v1`)
- a market substrate with insurance flow (`crates/chio-market/src/lib.rs`
  -- `chio.market.quote-request.v1`, `chio.market.bound-coverage.v1`)
- a settlement substrate with EVM, Solana, and CCIP rails
  (`crates/chio-settle/src/{evm.rs,solana.rs,ccip.rs}`)
- an anchor substrate with Bitcoin, EVM, Solana lanes plus checkpoint
  aggregation and OTS linkage (`crates/chio-anchor/src/lib.rs`)
- bilateral cross-kernel cosigning **already implemented** in
  `crates/chio-federation/src/bilateral.rs` (`CoSigningBody`,
  `DualSignedReceipt`, schemas `chio.federation-bilateral-cosigning.v1`
  and `chio.federation-dual-signed-receipt.v1`)
- a chiodos spec corpus (CHIODOS_BILATERAL_COSIGN_INVOCATION,
  CHIODOS_LADDER, CHIODOS_PHEROMONE, CHIODOS_SELECTIVE_DISCLOSURE) and
  a worked three-vendor fixture in
  `docs/research/CHIODOS_3VENDOR_FIXTURE.md`

The primitives exist. The vision exists. What does not exist is a
**single demoable slice** that takes those primitives, connects them
end-to-end, and lets a third party watch it run. release work should ship that
slice.

---

## 2. The ONE Demo Slice for release work

**Name:** Chiodome v0.1 Cross-Kernel Refund -- two kernels, one cosigned
invocation, one bonded settlement, one selective-disclosure auditor view.

**Concretely:**

1. Two `chio-federation` peers (Org A and Org B) complete the existing
   `trust_establishment.rs` handshake.
2. They exchange and pin a minimum-viable
   `chio.chiodos-ladder.v1` manifest each
   (`spec/CHIODOS_LADDER.md` section 2). Intersection produces a
   co-signed `chio.chiodos-ladder-intersection.v1` artefact. Domain:
   `financial`. One action class only: `refund.execute`. Mode:
   `receipt_backed`. Consistency: `totally-ordered`. Anchor:
   `chio-anchor` (we already have it).
3. Org A's agent invokes Org B's `refund.execute(amount, customer)`
   tool. The kernels emit one
   `chio.bilateral-cosign-invocation.v1` DSSE envelope per
   `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` section 6, riding on
   top of the existing `CoSigningBody` (the spec already names this
   primitive at section 2 lines 56-67).
4. The invocation references a `chio-credit` budget bond
   (`chio.credit.bond.v1`) as `capability_lease_ref`. Sibling-sum
   budgeting from trj4 wave 1.5 already enforces this.
5. Settlement runs through `chio-settle/evm.rs` against a Base Sepolia
   mock (or local devnet -- `LocalDevnetDeployment` in
   `crates/chio-settle/src/config.rs` already exists). A
   `Web3CheckpointStatement` lands and `chio-anchor` pins it.
6. A third-party "auditor" presents the BBS+ selective-disclosure
   proof from `spec/CHIODOS_SELECTIVE_DISCLOSURE.md` section 6: "the
   refund step transferred no more than $250 to a customer at KYC tier
   2 or higher" -- without learning the customer or exact amount. This
   is exactly Gap G6 from `CHIODOS_3VENDOR_FIXTURE.md` section 11, and
   the predicate language (eq, cmp, member, AND-only, eight-clause
   ceiling) is frozen at v0.1 in the spec.

**Bounded-claim label:** "Chiodome v0.1 demonstrates one bilateral
cosigned cross-kernel invocation with budget-bonded settlement and
auditor-side selective disclosure, on Base Sepolia testnet plus local
Solana devnet, against a frozen v0.1 ladder intersection. Not a
production multi-tenant deployment. Not a permissionless federation.
Not consensus-grade HA."

**What lights up at the end:** a single CLI walk-through (extending
`chio-cli`) that emits, for the same refund: the dual-signed receipt,
the bilateral-cosign-invocation Statement, the workflow receipt, the
EVM/Solana settlement evidence, the anchor inclusion proof, and the
BBS+ disclosure proof. One command, six artifacts, one cohesive story.
That is **the Chiodome demo**, not "yet another v3.x bounded
hardening pass."

---

## 3. Why This Matters (Strategic Positioning)

Every other lane on the release work menu is fungible. Five years from now:
- HTTP egress hardening will be table stakes (every protocol does it).
- WASM guard plugins will be table stakes (Envoy already has them).
- Decomposed kernels will be table stakes (every middleware does it).
- Receipt v2, hybrid PQ, mobile attestation -- table stakes.

What will **not** be table stakes is "two organisations independently
evaluated their separate policies on the same canonical action under
named capability leases, jointly committed via a multi-signature DSSE
envelope keyed to passport fingerprints, with a third-party auditor
verifying a predicate over the receipt without learning the body, all
anchored to a settlement chain." That is the structural slice
`spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` section 10's comparison
table calls out: in-toto runtime-trace doesn't do it, SLSA provenance
doesn't do it, single-party DSSE on Rekor doesn't do it. **No one is
shipping this primitive end-to-end.** Chio has a code-resident lead.
Squander it on six more bounded hardening passes and the lead
evaporates.

The user's roadmap-framing memory
(`feedback_roadmap_framing.md`) explicitly says: anchor proposals to
RELEASE_AUDIT / QUALIFICATION / BOUNDED_OPERATIONAL_PROFILE / PROTOCOL,
do not silently widen claims. The Chiodome demo respects that: it
ships under bounded claim labels, against the frozen
`bounded-operational-profile` (no consensus HA, no distributed
linearizable spend), and it slots cleanly into PROTOCOL.md as a
new predicate type.

---

## 4. Counter-Arguments

**(a) "trj4 isn't even closed (TRAJECTORY-4-CLOSEOUT-ERRATUM.md);
adding new spec drafts is reckless."**

Fair, and acknowledged. The demo does **not** require new spec drafts.
Every wire format it consumes is already either implemented
(`chio-federation::bilateral::CoSigningBody` /
`DualSignedReceipt` schemas, `chio-credit::CREDIT_BOND_ARTIFACT_SCHEMA`,
`chio-settle::CHIO_CCIP_SETTLEMENT_MESSAGE_SCHEMA`) or frozen in a
v0.1 spec the codebase already references
(`CHIODOS_BILATERAL_COSIGN_INVOCATION` v0.1,
`CHIODOS_SELECTIVE_DISCLOSURE` v0.1,
`CHIODOS_LADDER` v0.1, `CHIODOS_PHEROMONE` v0.2). The new code is
exactly **one adapter** in
`crates/chio-federation/src/bilateral.rs` to emit the DSSE envelope
shape from spec section 6 under the chio-namespaced fallback URI -- a
straightforward wrapping over existing co-signing logic, called out
explicitly in spec section 12 as "the chio-side fixture exists; the
adapter is straightforward." trj4 wave-1.5 already wired chain-binding
and sibling-sum budget; this demo consumes those waves' work and
demonstrates payoff.

**(b) "No users care about Chiodome -- it's a future vision."**

The user memory itself frames Chiodome as "post-launch idea (months
after chio ships, if adoption)." That is true for the **full**
Chiodome -- agent swarms as digital fiscal nation states, the
swarm-team-six fusion, the DAO replacement. We are not shipping that
in release work. We are shipping the **smallest demo that proves the
primitives compose**. Strategic positioning math: a recorded
cross-vendor walk-through that no competitor can replicate is the
single best artefact for buyer conversations, partnership outreach,
and standards-body engagement (the in-toto WG conversation called out
in spec section 12). Hardening lane #97 produces zero such artefacts.

**(c) "We'll lose the floor."**

Pair the Chiodome lane with **one** harden-the-floor lane. Concretely:
take the highest-priority trj4 wave that did not close
(per `TRAJECTORY-4-FINAL.md` reopened rows -- wave 0/4 threat coverage
and wave 1 chain-binding/sibling-sum/attenuation-witness soundness are
the hot ones) and run it as the parallel commodity-hardening track.
Two lanes, not seven. The Chiodome demo lane does **not** require
distributed linearizable spend or consensus HA, so it cannot regress
on those dimensions. The pairing rebuts the false dichotomy.

---

## 5. Concessions

**Drop now (too speculative for release work):**

- `CHIODOS_PHEROMONE` v0.2 cross-trust gossip surfaces. The wire
  format is frozen, but the substrate behaviour (sqrt-N cap as
  cost-shifter, observation-cost commitments for destructive classes)
  needs adversarial economic modelling that
  `docs/research/CHIODOS_SCARCITY_ECONOMICS.md` flags as still being
  reframed. Pheromone deposits are **out of scope** for the release work demo;
  they appear as an optional second-wave step in the three-vendor
  fixture (section 9) and remain there. Ship without them.
- The full three-vendor `CHIODOS_3VENDOR_FIXTURE.md` walk-through.
  Three vendors, three workflows, full BBS+ disclosure -- this is
  research-illustrative (the fixture itself says "Status: Research /
  illustrative"). The release work demo runs **two** kernels, **one**
  invocation, **one** disclosure predicate. Concede the federation-of-
  three for trj6.
- `CHIODOS_LADDER` amendment lifecycle (section 8). The handshake-
  pinned manifest is enough for v0.1; in-flight amendment is not
  needed to demo a single refund.

**Ship with bounded-claim labels:**

- The bilateral-cosign-invocation predicate emits the
  `chio.bilateral-cosign-invocation.v1` namespaced URI, **not** the
  proposed in-toto URI. Spec section 3 already mandates this until WG
  acceptance: "implementations MUST emit the chio-namespaced fallback
  so verifiers do not collide with an unaccepted reservation." That is
  the bounded label.
- Settlement ships against Base Sepolia testnet plus local Solana
  devnet (`LocalDevnetDeployment` in `chio-settle/src/config.rs`).
  v2.71 Web3 Live Activation in `.planning/PROJECT.md` (line 153)
  remains deferred pending external Base Sepolia credentials, reviewed
  live-chain artifacts, and OTS tooling. The Chiodome demo does not
  promote v2.71 to live; it consumes v2.71's testnet artefacts and
  labels accordingly.
- BBS+ ships behind the default-off `bbs-stub` Cargo feature in a new
  `chio-federation` workspace member, exactly as
  `CHIODOS_SELECTIVE_DISCLOSURE` section 2.1 prescribes. Verifiers
  uninterested in selective disclosure ignore the secondary commitment
  -- Ed25519 over RFC 8785 JCS remains authoritative.

---

## 6. Recommendation

**Trj5 = Chiodome Demo Lane (primary) + one trj4 reopened wave
(parallel).**

Drop the seven-lane menu. Pick the slice with the highest
strategic-positioning-per-engineering-week ratio. The primitives are
already written. The spec is already drafted. The fixture document
already names every gap. release work closes those gaps in **one** integrated
demo, with bounded-claim labels respecting the user's roadmap-framing
memory, and produces an artefact no other agent-protocol project on
earth can replicate.

Hardening a substrate nobody uses for a vision nobody can demo is
wasted heat. Ship the demo.
