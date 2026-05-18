# V7 — Threshold cosigning (FROST/ROAST) for two-key DSSE binding (design)

Action-plan item: "V7: threshold cosigning (FROST/ROAST) for two-key DSSE binding".

Status: design only. Library integration + key-share lifecycle deferred
to a focused engineering session because (a) the choice between
`frost-ed25519` and `roast`-wrapped FROST is a workspace-wide
cryptographic commitment, (b) key-share generation needs an out-of-band
DKG ceremony, and (c) the per-share custody flow touches the operator
runbook. The autonomous-execution cron should not commit a crypto
library choice.

## Context

The current bilateral DSSE envelope (`crates/chio-federation/src/bilateral_dsse.rs`)
carries exactly two single-key Ed25519 signatures:

```text
envelope = {
    "payloadType": "application/vnd.in-toto+json",
    "payload":     base64(canonical_json(in_toto_statement)),
    "signatures":  [
        { "keyid": sha256_hex(passport_pubkey_a), "sig": base64(sig_a) },
        { "keyid": sha256_hex(passport_pubkey_b), "sig": base64(sig_b) },
    ],
}
```

Each signature is one Ed25519 sig from one secret key. The two-key
binding gives separation-of-duties between issuer and cosigner, but
each side is a single key — compromise of either issuer key OR
cosigner key forges a slot.

V7 replaces each side with a t-of-n threshold Schnorr signature
(FROST-Ed25519). The on-wire signature length and verification cost
stay constant (one 64-byte Ed25519 sig); the signing flow becomes a
multi-round protocol among the t participants.

## Library choice

Three serious candidates:

| Library            | Maintainer            | Status         | Notes |
|--------------------|-----------------------|----------------|-------|
| `frost-ed25519`    | ZF/ZcashFoundation    | RFC-9591       | Ed25519 ciphersuite of `frost-core`; production. |
| `frost-secp256k1`  | ZF/ZcashFoundation    | RFC-9591       | secp256k1 variant; out of scope for an Ed25519 DSSE envelope. |
| `roast`            | (research; not on crates.io)| paper-only | Asynchronous-robust wrapper around FROST; useful when a participant can be slow or unresponsive but the protocol must still terminate. |

Recommendation: **`frost-ed25519`** (ZF `frost-core` v2.x) for v2.

Reasons:

1. RFC 9591 standardized FROST in Sept 2024. `frost-core` tracks the RFC,
   so the wire format and KDF derivation are stable.
2. Ed25519 ciphersuite produces a 64-byte Schnorr signature that
   verifies under standard Ed25519 verification — drop-in replacement
   for the existing per-slot signature byte field. No verifier-side code
   changes other than key aggregation.
3. ROAST adds robustness but at the cost of a longer protocol and
   additional async messaging. Without an operational driver (high
   signer unavailability rate), ROAST is over-engineering for v2.

V8 (BBS issuer rotation) is a separate consideration; this design
covers only the Ed25519 DSSE slot.

## Integration surface

Two changes to the existing flow:

### 1. Signing path

`bilateral_dsse.rs::Ed25519Backend` currently produces a single
signature from a single keypair. The threshold variant produces the
same 64-byte signature but via a t-of-n protocol:

```text
1.  Round 1: each participant samples a nonce pair and broadcasts
    public nonces.
2.  Round 2: the coordinator computes a binding factor and a group
    commitment, sends them to participants.
3.  Each participant computes their signature share, broadcasts it.
4.  Coordinator aggregates the shares into the final signature.
```

Encapsulate this behind a new `SigningBackend` impl
`ThresholdEd25519Backend` that takes a `ThresholdKeyShare` and a
`SignerCoordinator` handle. The coordinator runs the FROST protocol
out-of-process (via gRPC or whatever the inter-signer transport is)
and returns the 64-byte aggregated signature. The caller of
`sign_envelope` should not need to know whether the backend is single-
key or threshold — the bytes look the same.

### 2. Key lifecycle

Add four new pieces:

- `ThresholdKeyShare`: serializable per-signer key share, holding the
  `Identifier` (FROST participant id), `SigningShare` (secret share),
  and `VerifyingKey` (group public key).
- `ThresholdKeyDkg`: a trusted-setup helper that runs `frost-core::keys::generate_with_dealer`
  or the distributed `frost-core::keys::dkg::part1/2/3` flow.
- `SignerCoordinator` trait: abstracts the round-trip messaging; one
  impl per transport (in-process for tests, gRPC for production).
- `ThresholdPassport`: extends the passport struct with the group
  `VerifyingKey` (so a verifier only needs the group key, not the
  individual shares).

The verifier side is unchanged: the same Ed25519 signature-verification
path works because FROST produces standard Schnorr-over-Ed25519.

## Lean formalization (V7-companion)

Optional but high-value: extend `PredicateLang.lean` with a small
abstract model of threshold signing as a quorum:

```lean
structure ThresholdPolicy where
  totalSigners : Nat
  threshold : Nat
  deriving Repr, BEq, DecidableEq, Inhabited

structure ThresholdWitness where
  contributingShares : List Nat   -- participant identifiers
  deriving Repr, BEq, DecidableEq, Inhabited

def thresholdSatisfied
    (policy : ThresholdPolicy) (witness : ThresholdWitness) : Bool :=
  decide (policy.threshold ≤
          (witness.contributingShares.dedup.filter
            (fun id => id < policy.totalSigners)).length)

theorem threshold_signature_iff_t_of_n_shares :
    forall policy witness,
      ...
```

This mirrors V3's `anchor_admission_iff_lane_quorum_satisfied` but at
the signing layer rather than the anchor layer. The same `Inhabited`-
derived `chain[i]!` indexing pattern from V5/V4 carries over.

Defer to a follow-up cron fire because the abstract model design
benefits from the actual library API being chosen first.

## Test strategy

1. Property test: t-of-n threshold-signed envelopes verify under the
   group public key on any t-element participant subset.
2. Property test: (t-1)-of-n shares do NOT produce a valid signature.
3. Fixture in `tests/replay/`: `allow_threshold_cosign/01_3_of_5_ok`
   and `deny_threshold_cosign/02_2_of_5_below_threshold` (paired with
   V6's manifest authoring step). These fixtures are gated by
   `--bless` per the V6 design doc.

## Why this is not the autonomous cron's job

1. Committing a workspace-wide `frost-ed25519` dependency is a
   cryptographic choice that should be reviewed by the security
   maintainer.
2. Key-share generation (DKG) needs an out-of-band ceremony or a
   well-documented trusted-setup helper; the cron is not the place to
   author the operator runbook.
3. The coordinator transport (gRPC? Already-Chio-internal protocol?)
   is a systems decision that touches multiple crates.

So the cron writes this design and stops here.

## Connection to the paper

§5 "Implementation" should be amended in v2 to mention threshold-Schnorr
as the binding step for the bilateral DSSE slot. §9 "Limitations"
v1 bullet on "single-key compromise forges a slot" gets retired once
V7 ships. The §7 "willing co-signing counterparty" paragraph (M6)
naturally extends to a threshold-counterparty quorum without rewriting
the framing.

## Connection to V8

V7 (threshold Ed25519 DSSE) and V8 (BBS issuer rotation epoch binding)
are orthogonal: V7 is about *who* can sign the envelope, V8 is about
*when* a signature was valid. A v2 deployment that ships both gets:

- The DSSE slot signed by a quorum of cosigners (V7).
- Each BBS-derived attribute carries an epoch tag binding it to the
  issuer's current rotation (V8).

Both are needed for a defensible "no single key forges a v2 receipt"
claim.
