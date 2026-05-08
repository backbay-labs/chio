# Selective Disclosure - The `bbs-stub` Cargo Feature

This document specifies the design of the `bbs-stub` Cargo feature for Lane
C, the new workspace member `crates/chio-federation/`, and the
bounded-claim text the demo uses when emitting (or refusing to emit)
the auditor view.

The spec source of truth is
`spec/CHIODOS_SELECTIVE_DISCLOSURE.md`. The mandate is spec section
6 (BBS+ workflow projection) for the workflow + step projections,
plus spec section 8 for the disclosure envelope schema.

**Wave 3 honesty pass (review finding 6):** the BBS+ Cargo dependency
tree (`bbs-2023` cryptosuite, `bls12_381`, AnonCreds v2
`RangeStatement`) is not assembled in the chio workspace today and
no Wave 1 deliverable verified that the proposed dep set even
compiles together against the current chio MSRV. review finding 6 and
RISK-REGISTER R6 require an explicit fallback: if Wave 1 cannot
land a `crates/chio-federation/Cargo.toml` skeleton that resolves
against the current MSRV by W2 of Lane C, the auditor view is
DROPPED from `v0.1.0-bounded-chiodome` and shipped in
`v0.2.0-bounded-chiodome`. The release tag's bounded-claim text
already enumerates this possibility (`release-bar.md` item 14).

## Feature shape

```toml
# crates/chio-federation/Cargo.toml
[features]
default = []
bbs-stub = ["dep:bbs", "dep:bls12_381", "dep:anoncreds-rs"]   # default OFF
```

Spec section 2.1 explicitly mandates "default-off `bbs-stub` Cargo feature"
in a "new workspace member `chio-federation`" sibling to
`chio-attest-verify`. The demo and the example crate both opt-in
explicitly when the auditor scenario runs.

## What's revealed to whom

Demo scenario (matches spec section 6.4 worked example):

| Audience | Disclosed | Withheld | Predicate result |
|---|---|---|---|
| Org A (issuer) | full receipt body | nothing | knows everything |
| Org B (issuer) | full receipt body | nothing | knows everything |
| Auditor (third party with the disclosure proof envelope only) | step `step_index`, step `tool_name`, step `outcome`, workflow `schema`, workflow `skill_id`, workflow `skill_version` | customer_id, exact `amount_minor`, refund reason, agent identity, full receipt body | "the refund step transferred no more than $250" (true / false only) |

Disclosed and withheld field indices come straight from spec section
6.1 (workflow-level table) and 6.2 (StepRecord table).

## The auditor predicate

Per spec section 6.4 worked example and the bounded-claim
discipline: ONE clause, AND-only composition.

```
clauses: [
  cmp(refund_amount_minor, <=, 25000, scale=2)
]
```

The `25000` cap matches the `amount_minor` cap in
`refund-policy.yaml` and the `partition_fallback.blast_radius_cap` in
`spec/CHIODOS_LADDER.md` section 5.2's narrow_destructive lease.

The `kyc_tier >= 2` clause from the worked example is OPTIONAL in
the demo; the demo issues a synthetic KYC child receipt for the
customer and the auditor proof MAY include the second clause as a
v0.2-ready demonstration. The bounded-claim language treats this as
illustrative.

Spec section 7.3 caps composition at eight clauses and forbids OR /
negation / nested quantifiers. The demo's two-clause maximum is well
within the cap.

## Field-by-field projection (subset relevant to demo)

Per `spec/CHIODOS_SELECTIVE_DISCLOSURE.md` section 6.2 step
projection, the refund step's projection messages:

| Idx | Field | Encoding | Demo's disclosure decision |
|---|---|---|---|
| 0 | `step_index` | U64 | disclose |
| 1 | `server_id` | S | withhold |
| 2 | `tool_name` | S | disclose |
| 3 | `allowed` | B (u8 padded) | withhold (auditor learns it from outcome) |
| 4 | `tool_receipt_id` | Opt<S> | withhold |
| 5 | `outcome` | S (`success`/`denied`/`failed`/`skipped`) | disclose |
| 6 | `duration_ms` | U64 | withhold |
| 7 | `cost` | H (wholesale-only) | withhold; predicate clause runs against parallel commitment of `refund_amount_minor` |
| 8 | `output_hash` | Opt<S> | withhold |

The `cost` field is wholesale-only at the BBS+ projection level
(spec section 6.2). The amount predicate runs against a parallel
BBS+ commitment to a separately-projected `refund_amount_minor`
scalar, exactly as spec section 6.4 prescribes.

## Cryptosuite pinning

Per spec section 3:

- BBS+ cryptosuite: `bbs-2023` (W3C Data Integrity BBS Cryptosuites
  v1.0 CR Draft).
- BBS+ signature: `draft-irtf-cfrg-bbs-signatures-10` over
  BLS12-381, default `bls12-381-sha-256`.
- `cmp` range proofs: AnonCreds v2 `RangeStatement` (Bulletproofs).
- `member` Merkle: SHA-256, RFC 9162 leaf encoding (not used in the
  demo but supported for completeness).

The crate pins exact versions and refuses to upgrade across CR
revisions without a schema-version bump.

## BBS+ as secondary commitment

Per spec section 3 lines 97-103, Ed25519 over RFC 8785 JCS remains
the **authoritative** signature on every chio receipt. BBS+ is a
**secondary commitment** scoped to the auditor projection. The
demo's receipts are signed Ed25519 exactly as today; if the `bbs-stub`
feature is off, verifiers ignore the absent BBS+ commitment and
the rest of the demo verifies normally.

(Note: an earlier W1 design tried to apply the same
"two-signatures-per-side, one authoritative + one supplementary"
pattern to the bilateral cosign DSSE envelope. That design was
rejected by review finding 1 and replaced with Lane B sub-lane B4
(`lane-b-wiring/dsse-bilateral-signing.md`) which makes DSSE PAE
the single canonical signing surface. The "secondary commitment"
language is correct for BBS+ but does NOT apply to the bilateral
cosign envelope as of W3.)

## Auditor view fixtures

When the demo runs with `--features bbs-stub`:

```
examples/chiodome-bilateral/fixtures/auditor-view/
  proof.json             # chio.selective-disclosure-proof.v1
  predicate-failed.json  # adversarial: amount_minor = 100000, predicate must reject
  receipt-projection.json # the projected messages for verifier replay
```

Each file is canonical JSON. `proof.json` validates against the
spec section 8 envelope schema and verifies under spec section 9's
verification algorithm.

When the demo runs WITHOUT `--features bbs-stub`, the orchestrator prints:

```
[selective-disclosure: built without --features bbs-stub]
[                      this demo's v0.1 bounded-claim acknowledges]
[                      the auditor view is gated on the feature.   ]
[                      see selective-disclosure.md.                ]
```

and exits 0. The smoke does not require the auditor view fixtures
unless the workflow opts into the bbs-stub feature.

## Bounded-claim text (verbatim for release notes)

The release notes for `v0.1.0-bounded-chiodome` MUST carry this
language verbatim in the selective-disclosure section. It is
deliberately conservative.

> ### Auditor view (selective disclosure) - what we DO claim
>
> **Headline caveat: the BBS+ cryptosuite is at W3C Candidate
> Recommendation Draft stage, not Recommendation stage.** The
> `bbs-2023` cryptosuite that this demo uses may evolve before W3C
> Recommendation; future recommendations may invalidate proofs
> produced by this release. Verifiers MUST treat the fixture as
> illustrative until a Recommendation-grade implementation lands.
>
> When built with `--features bbs-stub`, the demo emits a
> `chio.selective-disclosure-proof.v1` envelope per
> `spec/CHIODOS_SELECTIVE_DISCLOSURE.md` section 8. The envelope
> verifies under spec section 9 against a single AND-composed
> predicate: `cmp(refund_amount_minor, <=, 25000, scale=2)`. The
> auditor learns the predicate outcome plus the disclosed step
> fields (step_index, tool_name, outcome) and learns nothing else
> about the receipt body. Verification is single-party local
> (the auditor holds the envelope and the issuer's BBS+ public key);
> there is no transparency log, no public witness, and no
> consensus commitment of the proof.
>
> ### Auditor view - what we DO NOT claim
>
> 1. This is a **local proof**. It is not a transparency-log
>    artefact. The proof is verifiable by anyone holding the
>    envelope and the issuer's public BBS+ key; it is not anchored
>    to any public ledger.
> 2. This is **not consensus-grade**. There is no quorum, no
>    distributed witness, no ledger commitment of the BBS+
>    signature. A malicious issuer who controls both kernels could
>    backdate the projection. The bilateral cosign envelope (DSSE)
>    is what binds two organisations to the same body; the
>    selective disclosure envelope is what lets a third party
>    verify a predicate over that body without seeing it.
> 3. **No `OR`, no negation, no nested quantifiers.** Spec section
>    7.3 freezes v0.1 at AND-only composition with an eight-clause
>    ceiling. The demo uses one clause.
> 4. **No native predicates over wholesale-only fields.** Spec
>    section 7.4 forbids predicates over fields hashed into a
>    single BBS+ message; the demo's amount predicate runs against
>    a separately-projected scalar (`refund_amount_minor`), not
>    against the wholesale `cost` field.
> 5. **No SD-JWT VC bridging, no zkVM lane.** Spec section 2.2
>    defers both to v0.2.
> 6. **(Promoted to headline above.) The cryptosuite is W3C
>    CR-stage, not Recommendation-stage.** Repeated here for the
>    list audit. `bbs-2023` is at Candidate Recommendation Draft;
>    implementations MUST track CR exit and bind to the eventual
>    Recommendation hash. This release does not.
> 7. **The auditor predicate IS the demo's only selective-disclosure emission.** No
>    other proof paths are claimed (no proof-carrying chained
>    receipts, no proof over Ed25519 itself, etc.).
> 8. **The auditor view fixture's BBS+ implementation may not be
>    cryptographically conformant with the eventual `bbs-2023`
>    W3C Recommendation.** A research-grade Rust BBS+ crate is
>    likely; verifiers MUST treat the fixture as illustrative.
> 9. **The auditor view may be DEFERRED to v0.2.** Per
>    RISK-REGISTER R6, if the BBS+ Cargo dep tree cannot be
>    assembled within the release work window, this release ships as a
>    five-artifact bundle (no auditor view) and the auditor
>    predicate moves to `v0.2.0-bounded-chiodome`.

## What this contributes to Lane C's forcing function

The bbs-stub feature is the only sub-lane in Lane C where Lane B does NOT
provide forcing-function enforcement. That is by design:

- The auditor predicate is constructed from a receipt that came out
  of the production kernel (so Lane B's hot-path enforcement still
  bears on the inputs).
- The BBS+ proof itself is a pure cryptographic transformation
  applied AFTER the receipt; no kernel hot-path is involved in proof
  emission.
- Therefore, if Lane B regresses, the auditor view fixtures still
  emit and verify (the failure mode shows up upstream, in the
  receipt body, not here).

The bounded-claim language says so explicitly. The demo's smoke does
not gate on the bbs-stub feature; the release tag does not depend on the
selective-disclosure fixture's existence; the release notes label the stub path as
optional.

## Fallback if BBS+ deps cannot resolve (R6 escalation)

If by W2 of Lane C the `crates/chio-federation/Cargo.toml`
skeleton does not resolve `--features bbs-stub` against the current chio
MSRV, **C5 is dropped from `v0.1.0-bounded-chiodome`** and the
release ships as a five-artifact bundle:

1. Kernel A v2 receipt
2. Kernel B v2 receipt
3. `DualSignedReceipt` shape (rewired by B4)
4. `chio.bilateral-cosign-invocation.v1` DSSE envelope
5. `Web3CheckpointStatement` + `AnchorInclusionProof`

The auditor view fixture (#6) and the `chio-federation` workspace
member become a `v0.2.0-bounded-chiodome` deliverable. Release
notes cite the deferral as known and intentional, not a regression.

This fallback is acceptable because BBS+ is the only sub-lane in
Lane C where Lane B does NOT provide forcing-function enforcement
(see "What this contributes to Lane C's forcing function" below);
dropping it does not change the demo's "Lane B canary" behavior.

The decision-owner is the Lane C lead. Sign-off by the release work owner.
Trigger conditions are itemized in `architecture/RISK-REGISTER.md` R6.

## What we don't ship under the bbs-stub feature

- BBS#, threshold-BBS, hardware-token-bound BBS+ - spec section 3
  pins narrowly.
- Proofs over the chained receipt parent graph - v0.2 zkVM.
- Predicate translations to SD-JWT VC for EUDI Wallet interop - v0.2.
- Selective disclosure of the bilateral DSSE envelope itself. Spec
  section 4 line 121-126 says the disclosure proof MAY bind to a
  bilateral envelope by referencing its `subject.digest.sha256`; the
  demo emits one such cross-binding fixture and labels it
  illustrative.

## Files touched

- `crates/chio-federation/Cargo.toml` - new
- `crates/chio-federation/src/lib.rs` - new
- `crates/chio-federation/src/projection.rs` - new (workflow + step
  projections)
- `crates/chio-federation/src/envelope.rs` - new (envelope
  construction + verify)
- `crates/chio-federation/src/predicates.rs` - new (eq, cmp, member,
  AND composition, eight-clause ceiling)
- `crates/chio-federation/tests/spec_64_worked_example.rs` - new
  (round-trip the spec section 6.4 example bit-for-bit)
- `examples/chiodome-bilateral/src/auditor.rs` - new (demo wiring)
- `examples/chiodome-bilateral/fixtures/auditor-view/proof.json` -
  generated artefact
- `examples/chiodome-bilateral/fixtures/auditor-view/predicate-failed.json`
  - generated artefact
