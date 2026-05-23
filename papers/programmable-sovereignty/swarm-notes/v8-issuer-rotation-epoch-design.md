# V8 — Issuer-rotation epoch binding for BBS derivation (design)

Action-plan item: "V8: issuer-rotation epoch binding for BBS derivation".

Status: design only. Schema field + registry-side rotation log +
verifier rejection rule deferred to a focused engineering session
because (a) adding an epoch field to the BBS-derived envelope is a
schema-version bump touching `spec/schemas/`, (b) the rotation log
itself needs a Merkle-rooted format, and (c) the operator runbook for
rotation events needs human review.

## Context

Current BBS issuer state (per `crates/chio-selective-disclosure/src/lib.rs`):

- Each issuer is identified by `issuer_fingerprint = sha256_hex(public_key)`.
- A registry maps fingerprints to current public keys.
- The PAE-style derivation transcript includes the issuer fingerprint
  as a length-prefixed field (`append_len_prefixed`).

What's missing: nothing binds a derivation to a *point in time* in
the issuer's rotation history. An attacker who obtains a leaked
private key share from rotation epoch N can produce derivations that
verify under the registry's current public key, even if the verifier
*should* refuse signatures issued before epoch N+1 because rotation
N→N+1 was specifically a response to a known compromise event.

V8 adds an epoch counter to the derivation and a rotation-log gate
to the verifier so an issuer can repudiate everything signed under a
prior epoch after rotation.

## Threat model addressed

1. **Key-share compromise leak**. An adversary obtains a private key
   share for issuer epoch N. The issuer detects this and rotates to
   epoch N+1, but the leaked share continues to produce signatures
   that verify under epoch N's public key. Without epoch binding,
   the verifier cannot distinguish forgeries from legitimate epoch-N
   signatures.

2. **Quietly-rotated issuer**. An adversary forces an issuer to
   rotate keys (e.g., social engineering, regulatory pressure) but
   then continues using the old key off-channel. Verifiers that
   accept all-fingerprints-ever cannot distinguish "still-valid"
   from "issuer rotated away from this key for a reason".

V8 closes both by making the rotation epoch a load-bearing field in
the verification predicate.

## Schema change

Add `issuer_epoch: u32` to the BBS-derived envelope and to the PAE
preimage:

```text
pae = "BBSv2" SP
      LEN(issuer_fingerprint) SP issuer_fingerprint SP
      LEN(epoch_bytes) SP epoch_bytes SP        // new in v2
      LEN(disclosed_attrs) SP disclosed_attrs SP
      LEN(proof_bytes) SP proof_bytes
```

`epoch_bytes` is the big-endian u32 of the issuer's rotation index at
signing time. Order is "issuer field, then epoch" so a parser can
short-circuit the epoch check before fetching the rest of the
disclosure.

This is a wire-format change. New envelope schema goes under
`spec/schemas/chio-wire/v2/bbs-derived.json`; v1 keeps its existing
shape. Verifiers can be polyglot: accept v1 *only if* the issuer's
registry entry declares `accepts_legacy_v1: true`, and reject v1
otherwise (fail-closed default).

## Rotation log format

The issuer maintains an append-only rotation log:

```json
{
  "issuer_fingerprint_v0": "<sha256-of-original-key>",
  "rotations": [
    {
      "epoch": 0,
      "public_key_hex": "<original>",
      "valid_from_unix": 1730000000,
      "valid_until_unix": null,
      "rotation_reason": null
    },
    {
      "epoch": 1,
      "public_key_hex": "<rotated>",
      "valid_from_unix": 1735000000,
      "valid_until_unix": null,
      "rotation_reason": "scheduled-90-day",
      "supersedes_epoch": 0
    }
  ],
  "log_root": "<merkle-root-over-rotations[]>",
  "log_root_signature": "<issuer-sig-over-root>"
}
```

Notes:

- The log is Merkle-rooted so a verifier can fetch a compact proof
  of "epoch N is currently the latest" without trusting the registry
  to be honest about the suffix.
- Each rotation entry carries an optional `rotation_reason` so the
  verifier surface can warn on `compromise-suspected` (vs. routine
  `scheduled-90-day`).
- The `log_root` is itself signed by the issuer's *operator* key,
  which is distinct from the BBS issuance key and rotated on a much
  slower cadence (annually, with hardware custody).

## Verifier change

Verification predicate becomes:

```text
verify(envelope) iff
    bbs_signature_valid(envelope, issuer_public_key_at_epoch(envelope.issuer_epoch))
  ∧ envelope.issuer_epoch == current_epoch_for(envelope.issuer_fingerprint_v0)
  ∧ issuer_not_repudiated_epoch(envelope.issuer_fingerprint_v0, envelope.issuer_epoch)
```

The third conjunct is new: a separate "repudiated epochs" set the
issuer can extend if it detects post-hoc that some prior epoch was
compromised. By default this set is empty.

## Lean formalization (V8-companion)

Optional, but a natural sibling theorem in `PredicateLang.lean`:

```lean
structure IssuerEpoch where
  fingerprint : String
  epoch : Nat
  deriving Repr, BEq, DecidableEq, Inhabited

structure RotationLog where
  currentEpoch : Nat
  repudiatedEpochs : List Nat
  deriving Repr, BEq, DecidableEq, Inhabited

def epochCurrent
    (log : RotationLog) (claim : IssuerEpoch) : Bool :=
  decide (claim.epoch = log.currentEpoch) &&
  ! (log.repudiatedEpochs.elem claim.epoch)

theorem epoch_verification_rejects_repudiated
    (log : RotationLog) (claim : IssuerEpoch)
    (hRepudiated : claim.epoch ∈ log.repudiatedEpochs) :
    epochCurrent log claim = false := by
  ...
```

Defer to a follow-up cron fire because the abstract model design
benefits from the actual schema-v2 field layout being committed
first.

## Migration strategy

1. **Phase 1 (release N)**: schema-v2 envelope authoring lands behind
   a feature flag. v1 producers continue to write v1; v2 producers
   write v2. Verifier accepts both.

2. **Phase 2 (release N+1)**: schema-v2 becomes the default for new
   producers. Registry adds `accepts_legacy_v1: bool` per issuer;
   defaults to `true` for backward compat.

3. **Phase 3 (release N+2)**: `accepts_legacy_v1` defaults to `false`.
   Issuers that haven't migrated must explicitly opt in. Verifier
   rejects v1 by default.

4. **Phase 4 (release N+3)**: v1 path is removed. Pre-rotation
   signatures can still be re-issued under v2 by the issuer if
   needed for historical receipts.

## Test strategy

1. Property test: an envelope signed at epoch N where the registry
   has rolled to epoch N+1 fails verification with `EpochStale`.
2. Property test: a repudiated-epoch envelope fails with `EpochRepudiated`
   even if the signature would otherwise verify.
3. Replay-corpus fixture (paired with V6 manifest authoring):
   `deny_bbs_stale_epoch/01_basic_stale.json` and
   `deny_bbs_repudiated_epoch/01_basic_repudiated.json`.

## Why this is not the autonomous cron's job

1. A wire-format schema bump (`v1 → v2`) is a workspace-wide commitment
   that touches `spec/schemas/`, every BBS producer / verifier, and
   the conformance test corpus. It should land with a deliberate
   release-note + migration plan, not a cron fire.

2. The rotation log format needs operator-side documentation: who
   rotates, on what cadence, where the log is stored, how the
   operator-key signature is generated. The cron is not the place to
   author the operator runbook.

3. Migration phases 1-4 each need a release cycle; the cron cannot
   sequence releases.

So the cron writes this design and stops here.

## Connection to the paper

§8 "Verifier and selective disclosure" should be amended in v2 to
mention the epoch field and the rotation-log gate. §9 "Limitations"
v1 bullet "an issuer cannot retroactively repudiate signatures from
a compromised epoch" gets retired once V8 ships. The PQC paragraph
(M4) is orthogonal — epoch binding is a *signature-time* property,
PQC migration is a *crypto-algorithm* property; they compose.

## Connection to V7

V7 (threshold cosigning) hardens the *act* of signing (no single key
forges a slot). V8 (epoch binding) hardens the *time* of signing
(forgeries from a compromised epoch can be repudiated). The two
together close the "trust the issuer's signing key forever" gap
that v1 implicitly accepted.
