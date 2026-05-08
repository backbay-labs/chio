# `v0.1.0-bounded-chiodome` Release Bar

This document is the release-notes draft for the
`v0.1.0-bounded-chiodome` tag. It is written in the v3.18 bounded-claim
discipline (matching the tone of the existing
`README.md` mutation banner, which says "31%" not "65% target").

The text below is intentionally cut-and-paste-ready: the C6 release
ticket (release work-C6.1) takes this content into `RELEASE_NOTES.md` with
formatting only; no claims should change between this file and the
shipped notes.

---

## v0.1.0-bounded-chiodome

This release introduces a single end-to-end demo composing existing
Chio primitives across two kernels. The demo lives at
`examples/chiodome-bilateral/` and ships under a strict bounded-claim
discipline: every artefact the demo produces is real (kernel-emitted,
not mocked); every property the demo claims is narrowly scoped; every
deferred property is named.

This release is NOT a 1.0. It is the smallest release that lets a
third party watch the bilateral cosigned cross-kernel invocation
machinery actually run.

## What v0.1.0-bounded-chiodome contains

The release tag includes:

1. The example crate `examples/chiodome-bilateral/` with a runnable
   smoke (`smoke.sh`).
2. The fixture set
   `examples/chiodome-bilateral/fixtures/<scenario>/`:
   - `handshake/` - federation handshake bodies for both kernels.
   - `ladder-intersection.json` - the pinned
     `chio.chiodos-ladder-intersection.v1` artefact.
   - `credit-bond.json` - the `CreditBondArtifact` carrying the
     capability lease.
   - `receipts/<id>.json` - one v2 ChioReceipt per tool call.
   - `bilateral-cosign-invocation.json` - the DSSE
     `chio.bilateral-cosign-invocation.v1` envelope.
   - `anchor-inclusion.json` - the `AnchorInclusionProof` against
     `LocalDevnetDeployment`.
   - `policy-deny.json` - the deny scenario's bilateral envelope
     showing `policy.verdict_disagreement`.
   - `auditor-view/proof.json` - selective-disclosure proof
     (only when built with `--features bbs-stub`; deferable to v0.2 per
     RISK-REGISTER R6 if BBS+ deps cannot resolve).
3. A new `chio-federation::bilateral_dsse` module wrapping the
   spec section 6 envelope shape.
4. A new `chio-federation` workspace member behind a
   default-off `bbs-stub` feature.
5. Updated `chio receipt explain` rendering for bilateral chains.
6. A new doc page `docs/guides/EXPLAIN_A_DENIAL.md`.
7. A required CI check `chio-demo-smoke` that runs
   `examples/chiodome-bilateral/smoke.sh` on every PR to main.
8. A signed tarball of the fixture set:
   `chiodome-bilateral-fixtures-v0.1.0.tar.gz`.

## What this release CLAIMS

These claims are narrow on purpose. Every one is verifiable from the
example artifacts shipped with the tag.

1. Two `chio-kernel` instances complete a federation handshake using
   `crates/chio-federation/src/trust_establishment.rs` and pin a
   ladder intersection per `spec/CHIODOS_LADDER.md` section 6.1.
2. A cross-kernel `refund.execute` invocation produces a DSSE
   envelope conforming to
   `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` section 6 (under
   the chio-namespaced predicateType
   `chio.bilateral-cosign-invocation.v1`, per spec section 3 lines
   97-103 mandate). Lane B sub-lane B4
   (`lane-b-wiring/dsse-bilateral-signing.md`, tickets
   `bilateral DSSE signing item-B4.6` plus `bilateral DSSE signing item` Evidence Gate close)
   replaced the
   `crates/chio-federation/src/bilateral.rs` signing surface so the
   production hot path emits spec §6 PAE Ed25519 signatures.
   `DualSignedReceipt::verify` is rewired to validate against PAE
   bytes; legacy `CoSigningBody` preimage signing is retained only
   as a fixture-only signer used by B4's negative conformance test.
3. The DSSE envelope verifies under the spec section 7 section 7
   verification algorithm. Each spec section 7.1 error code has a
   negative conformance fixture in
   `crates/chio-federation/tests/bilateral_dsse_negative.rs`.
4. The receipt is anchored through
   `crates/chio-anchor::Web3CheckpointStatement`
   (`crates/chio-anchor/src/lib.rs:138`) and an
   `AnchorInclusionProof` is produced via
   `build_anchor_inclusion_proof`.
5. The capability lease references a
   `CreditBondArtifact`
   (`crates/chio-credit/src/lib.rs:766`); the bond's `bond_id`
   becomes the predicate's `capability_lease_ref.lease_id`.
6. `chio mcp serve --policy
   examples/chiodome-bilateral/policies/refund-policy.yaml`
   (`crates/chio-cli/src/cli/types.rs:993`) wraps the local KB MCP
   gateway at `:8111/mcp/` (per `ops/knowledge-base/`); each call
   produces a v2 receipt.
7. `chio receipt explain` (`crates/chio-cli/src/cli/types.rs:2660`,
   `crates/chio-cli/src/cli/trust_commands.rs:2629`) walks the
   bilateral chain end-to-end and surfaces the cosign summary,
   anchor checkpoint summary, and policy verdict details.
8. When built with `--features bbs-stub`, the demo emits a
   `chio.selective-disclosure-proof.v1` envelope verifying the
   single predicate
   `cmp(refund_amount_minor, <=, 25000, scale=2)` against a hidden
   amount, per `spec/CHIODOS_SELECTIVE_DISCLOSURE.md` section 6.4
   worked example.

## What this release DOES NOT CLAIM

The Vision Strategist's bounded-claim label
(`debate/06-vision-strategist-chiodome.md` section 2) is normative
here:

> Chiodome v0.1 demonstrates one bilateral cosigned cross-kernel
> invocation with budget-bonded settlement and auditor-side selective
> disclosure, on **local devnet only**, against a frozen v0.1 ladder
> intersection. **Not a production multi-tenant deployment. Not a
> permissionless federation. Not consensus-grade HA.**

In the language this release uses:

1. **Not a production multi-tenant deployment.** Two kernels run
   in-process by default. A two-process variant is supported via
   `chio-federation`'s mTLS transport stub but is not the smoke's
   default path.
2. **Not a permissionless federation.** Both kernels' passport
   public keys are pre-pinned via `FederationPeer`. The demo does
   not exercise dynamic peer discovery.
3. **Not consensus-grade HA.** No quorum, no distributed
   linearisable spend, no global ordering across more than two
   participants. The synthesis explicitly rules out consensus HA
   for Lane C.
4. **No live web3 activation.** The settlement leg runs against
   `LocalDevnetDeployment`
   (`crates/chio-settle/src/config.rs:393`); v2.71 Web3 Live
   Activation is deferred per
   `.planning/PROJECT.md` line 153 and is NOT promoted by this
   release. The bounded label states this; the fixtures' `rpc_url`
   field shows the local devnet URL.
5. **Not a transparency log.** The DSSE envelope is not uploaded
   to Rekor (spec section 9 sketches Rekor composition; the demo
   does NOT do it).
6. **The auditor view (selective disclosure) is a local proof.**
   See `.planning/trajectory-5/lane-c-demo/selective-disclosure.md`
   bounded-claim section: NOT a transparency-log artefact, NOT
   consensus-grade, AND-only composition, no native predicates
   over wholesale-only fields, BBS+ cryptosuite at W3C CR stage
   (not Recommendation), no zkVM lane, no SD-JWT VC bridging.
7. **Predicate type is the chio-namespaced fallback.** The
   envelope's `predicateType` is
   `chio.bilateral-cosign-invocation.v1`, not the proposed
   `https://in-toto.io/attestation/bilateral-cosign-invocation/v1`.
   Spec section 3 mandates the chio fallback until WG acceptance;
   the demo MUST emit it. Verifiers MUST accept either per spec
   section 7 step 4, but production receivers should treat the
   chio URI as authoritative for now.
8. **No new spec ratification.** Per
   `00-SYNTHESIS.md` line 142, no new normative drafts. The DSSE
   adapter is exactly the section-12 reference implementation the
   spec already calls for.
9. **No three-vendor fixture.** The
   `docs/research/CHIODOS_3VENDOR_FIXTURE.md` walk-through is
   research-illustrative and out of scope.
10. **No pheromone deposits.** Out of scope per Vision Strategist
    section 5.
11. **No ladder amendment in flight.**
    `spec/CHIODOS_LADDER.md` section 8 amendment lifecycle is out
    of scope.
12. **The substrate floor numbers in the README banner have not
    changed.** This release does not move the mutation-kill or
    threat-coverage banners; Lane A is responsible for those. If
    they read 31% the day this tag goes out, the tag goes out
    with that number visible. Bounded-claim discipline forbids
    quietly upgrading the banner ahead of the floor.
13. **Auditor view (selective disclosure) is single-party local
    verification, not a transparency log.** The auditor inspects a
    proof envelope they were handed; verification produces a
    yes/no for the predicate and the disclosed step fields. There
    is no public log, no append-only journal, and no third-party
    witness commitment. A malicious issuer who holds both kernels'
    keys can backdate or omit; the cosign envelope is what binds
    two organisations to the same body, the auditor view is what
    lets one party check a predicate over that body without seeing
    it. The bounded-claim section in `selective-disclosure.md`
    enumerates the auditor non-claims in detail.
14. **Selective disclosure auditor view may be DEFERRED to v0.2.**
    Per RISK-REGISTER.md R6 and `selective-disclosure.md` "Fallback
    if BBS+ deps cannot resolve", if the BBS+ dependency tree
    (`bbs-2023` cryptosuite, BLS12-381, AnonCreds v2 RangeStatement)
    cannot be assembled within the release work window or forces a chio
    MSRV bump, this release ships as a five-artifact bundle (no
    auditor view) and the auditor predicate is deferred to a
    `v0.2.0-bounded-chiodome` release. If you read this in the
    final notes, that decision has already been made.

## Forcing-function dependency on Lane B

This release tag does NOT ship unless Lane B's four negative
conformance fixtures are committed and green:

1. `crates/chio-conformance/tests/capability_v2_negative.rs` -
   the single-entry `verify_capability_full` enforcement on the
   kernel hot path. (Lane B `release work-B1.x`.)
2. `crates/chio-conformance/tests/receipt_v2_negative.rs` -
   the receipt v2 fail-closed enforcement at
   `chio-kernel/src/kernel/mod.rs:1574-1591`
   (`kernel_receipt_version_for_remote`). (Lane B `release work-B2.x`.)
3. `crates/chio-conformance/tests/anchor_witness_negative.rs` -
   the anchor-batch async-only enforcement at
   `crates/chio-anchor/src/batch.rs:208-258`. (Lane B `release work-B3.x`.)
4. `crates/chio-conformance/tests/b4_bilateral_dsse_pae_only_is_conformant.rs`
   - the DSSE-conformant signing-surface enforcement, where a
   legacy `CoSigningBody`-shaped signature is rejected by the
   production verifier. (Lane B `bilateral DSSE signing item`.)

Each negative test references the demo's fixtures by exact path so
that removing any of the four Lane B enforcements turns
`chio-demo-smoke` red as a second-order effect. This is the forcing
function the Lane C contract requires; the synthesis is explicit
that "if Lane C breaks, Lanes A and B aren't real either."

If any of the four is missing on the day we want to tag, the tag
slips. The tag is unblocked when all four exist and pass.

## What downstream gets out of this release

- **Auditors / regulators.** A reproducible artefact set showing
  what a Chio cross-org bilateral cosigned invocation looks like in
  practice: handshake, ladder intersection, capability lease, dual
  signature, DSSE envelope, anchor inclusion, optional auditor
  view.
- **Standards bodies.** A working DSSE adapter for
  `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` they can run
  against their own test vectors. The chio-namespaced URI is
  emitted today; switching to the in-toto canonical URI is a
  one-line change after WG acceptance.
- **Integrators.** A worked example using `chio mcp serve --policy`
  against a real MCP gateway (the local KB MCP at `:8111/mcp/`).
  The example's policy YAML, smoke script, and fixture format are
  the templates a buyer integration would clone.
- **Internal contributors.** A canary that catches Lane B
  regressions: if the receipt-v2 hot path silently downgrades or
  the anchor-batch sync path is reachable under public-witness
  required, the demo smoke fails on the next CI run.

## Anti-patterns avoided in this release

- **No new normative draft.** Per synthesis line 142.
- **No live web3 activation.** Per synthesis line 142, "no new
  Web3 live deployment".
- **No mock receipts.** Every receipt in `fixtures/` was produced
  by the production kernel via its real call sites; the smoke run
  is the producer, not a hand-written template generator.
- **No silent banner upgrade.** The README mutation banner is
  Lane A's; this release does not touch it.
- **No quietly-decoupled demo.** Lane B's negative conformance
  fixtures reference Lane C's fixture paths; if Lane B regresses
  enforcement, Lane C goes red.

## Where to go next

- Read `examples/chiodome-bilateral/README.md` for the runnable
  walk-through.
- Read
  `.planning/trajectory-5/lane-c-demo/architecture.md` for the
  flow diagram.
- Read
  `.planning/trajectory-5/lane-c-demo/bilateral-cosign-flow.md`
  for the DSSE adapter design.
- Read
  `.planning/trajectory-5/lane-c-demo/selective-disclosure.md`
  for the bounded-claim text governing the `bbs-stub` feature.
- Run `make kb-up && make ci-demo` to reproduce the full smoke
  locally.

## Acknowledgements

The Lane C scoping debate and the bounded-claim discipline are the
direct work of the release work position-paper authors; the synthesis is at
`.planning/trajectory-5/debate/00-SYNTHESIS.md`. The Vision
Strategist's chiodome slice
(`.planning/trajectory-5/debate/06-vision-strategist-chiodome.md`
section 2) is the demo's spine. The Productization Champion's KB
MCP dogfood
(`.planning/trajectory-5/debate/05-productization-sdk-champion.md`
section 1.5) is the user-facing surface.
