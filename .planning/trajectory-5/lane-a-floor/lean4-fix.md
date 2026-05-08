# Trajectory 5 - Lane A: Lean4 negotiation_safety Fix

This document covers sub-lane A5 (Lean4 `negotiation_safety` re-proof
against the executable model). It diagnoses the `rfl` tautology, names
the target re-statement, identifies the executable-model term, and
lists file paths.

## Diagnosis: the rfl tautology

The current proof at
`formal/lean4/Chio/Chio/Proofs/HandshakeNegotiation.lean:77-84`:

```
theorem negotiation_safety
    (tokenSchema peerMax : Schema) :
    schemaCeilingCheck tokenSchema peerMax =
      (if Schema.le tokenSchema peerMax then
         CeilingVerdict.admit
       else
         CeilingVerdict.rejectExceedsCeiling) := by
  rfl
```

Per the Quality Skeptic
(`.planning/trajectory-5/debate/04-quality-verification-skeptic.md`
line 52): "is proven by `rfl` -- the function definition is literally
that expression. Tautology proven by definitional unfolding, not
refinement against the Rust verifier."

To verify: `schemaCeilingCheck` is defined at lines 43-47 of the same
file as

```
def schemaCeilingCheck (tokenSchema peerMax : Schema) : CeilingVerdict :=
  if Schema.le tokenSchema peerMax then
    CeilingVerdict.admit
  else
    CeilingVerdict.rejectExceedsCeiling
```

So the theorem statement says: `schemaCeilingCheck = (if le then admit
else reject)`, and the function definition is `if le then admit else
reject`. `rfl` succeeds because both sides are the same expression.

The proof says nothing about the Rust verifier behavior. It only says
that `schemaCeilingCheck` evaluates the way it is defined to evaluate.

## What the theorem must say to be load-bearing

The theorem `negotiation_safety` is named in `formal/theorem-inventory.json`
and `formal/proof-manifest.toml`. Its load-bearing claim, per the file
docstring (lines 4-8): "an inbound capability token whose declared
schema exceeds the peer-negotiated maximum schema is rejected by the
verifier before any signature, time, or floor check runs."

For the proof to be load-bearing:

- The verifier must be modeled in Lean as an executable-model term that
  reflects the production decision shape, not a function whose only
  definition is the property to be proven.
- The theorem must be a refinement statement: the verifier admits iff
  the schema-ceiling property holds; rejects iff it does not.
- The proof must use the executable-model term's definitional structure
  to extract the schema-ceiling step, which is genuine refinement work,
  not unfolding.

## Target re-statement (rewritten per R2 BLOCKER 5.1)

The Rust verifier entry that the model term must mirror is
`verify_capability_with_negotiated_floor` at
`crates/chio-kernel-core/src/capability_verify.rs:226-255` (verified by
`grep -n 'fn verify_capability_with_negotiated_floor'
crates/chio-kernel-core/src/capability_verify.rs` returning line 226;
function body inspected lines 226-255).

The actual Rust signature is (verbatim from the source, lines 226-232):

```rust
pub fn verify_capability_with_negotiated_floor(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    clock: &dyn Clock,
    crypto_floor: CapabilityCryptoFloor,
    peer: &CapabilityNegotiation,
) -> Result<VerifiedCapability, CapabilityError>
```

Key differences from the prior draft (which mis-stated `CryptoFloor`
and a flat `Schema` parameter):

- The fourth argument type is `CapabilityCryptoFloor`, not `CryptoFloor`.
- The fifth argument is `&CapabilityNegotiation` (a struct), not a flat
  `Schema`. The peer's schema ceiling is reached via
  `peer.max_capability_schema` per the Rust function body at line 240.
- The return type is `Result<VerifiedCapability, CapabilityError>`,
  not `Result<(), _>`.

The Lean model term consumes `(tokenSchema, peerMax, signatureOk,
timeOk, floorOk)`. The mapping to the Rust signature is:

- `tokenSchema` <- `token.schema` (a `String` parsed via
  `CapabilitySchemaVersion::parse` in the Rust function at line 239).
  In the Lean model, `tokenSchema : Schema` is the abstracted lattice
  rung.
- `peerMax` <- `peer.max_capability_schema` (also a `String` parsed via
  `CapabilitySchemaVersion::parse`). In Lean, `peerMax : Schema`.
- `signatureOk : Bool` <- the result of the embedded
  `verify_capability_with_floor` call (the trusted-issuer signature
  check, line 254).
- `timeOk : Bool` <- the embedded clock check inside
  `verify_capability_with_floor`.
- `floorOk : Bool` <- the result of the `crypto_floor` check inside
  `verify_capability_with_floor` (the `CapabilityCryptoFloor`
  parameter is reduced to a Boolean witness at the refinement
  abstraction level).

This is a refinement-level abstraction: the Lean model term collapses
the three downstream sub-decisions into Booleans because the property
proven is the schema-ceiling step ordering, not the internal
correctness of those sub-decisions. Each of those is the subject of a
separate theorem (signature soundness, clock fail-closed, crypto-floor
admission), out of scope for this ticket.

### Target Lean signature

```
def verify_capability_with_negotiated_floor_model
    (tokenSchema   : Schema)
    (peerMax       : Schema)
    (signatureOk   : Bool)
    (timeOk        : Bool)
    (floorOk       : Bool)
    : CeilingVerdict :=
  -- (1) Schema-ceiling check first; reject before any other check.
  match schemaCeilingCheck tokenSchema peerMax with
  | CeilingVerdict.rejectExceedsCeiling => CeilingVerdict.rejectExceedsCeiling
  -- (2) On admit, all subsequent checks must pass.
  | CeilingVerdict.admit =>
      if signatureOk && timeOk && floorOk then
        CeilingVerdict.admit
      else
        CeilingVerdict.rejectExceedsCeiling
        -- Note: this captures only the schema-ceiling vs not distinction,
        -- which is sufficient for negotiation_safety. A finer-grained
        -- result type can be introduced if other theorems need it.
```

### Target re-stated theorems (R2 MAJOR 5.2: at least three)

The original draft stated only one direction (admit -> Schema.le),
which is not enough to discharge the docstring's full claim. release work-A5.3
proves three theorems, the third being the ordering theorem the
docstring genuinely requires:

#### Theorem 1: `negotiation_safety_admit_implies_le`

```
theorem negotiation_safety_admit_implies_le
    (tokenSchema peerMax : Schema)
    (signatureOk timeOk floorOk : Bool) :
    (verify_capability_with_negotiated_floor_model
       tokenSchema peerMax signatureOk timeOk floorOk
     = CeilingVerdict.admit)
    -> Schema.le tokenSchema peerMax = true := by
  intro h
  cases hSchema : schemaCeilingCheck tokenSchema peerMax with
  | rejectExceedsCeiling =>
      simp [verify_capability_with_negotiated_floor_model, hSchema] at h
  | admit =>
      unfold schemaCeilingCheck at hSchema
      split_ifs at hSchema with hLe
      · exact hLe
      · simp at hSchema
```

#### Theorem 2: `negotiation_safety_reject_implies_not_le_or_other_failure`

```
theorem negotiation_safety_reject_implies_not_le_or_other_failure
    (tokenSchema peerMax : Schema)
    (signatureOk timeOk floorOk : Bool) :
    (verify_capability_with_negotiated_floor_model
       tokenSchema peerMax signatureOk timeOk floorOk
     = CeilingVerdict.rejectExceedsCeiling)
    -> (Schema.le tokenSchema peerMax = false)
       \/ (signatureOk = false)
       \/ (timeOk = false)
       \/ (floorOk = false) := by
  intro h
  -- Case-split on the executable-model term's `match`. The reject
  -- branch is reachable from either the schema-ceiling reject or
  -- the conjunction-failure of the three downstream Booleans.
  cases hSchema : schemaCeilingCheck tokenSchema peerMax with
  | rejectExceedsCeiling =>
      -- Schema-ceiling rejected; pull the Schema.le=false witness out.
      unfold schemaCeilingCheck at hSchema
      split_ifs at hSchema with hLe
      · simp at hSchema
      · left; exact hLe
  | admit =>
      -- Schema-ceiling admitted; the reject must come from the
      -- signatureOk && timeOk && floorOk conjunction failing.
      simp [verify_capability_with_negotiated_floor_model, hSchema] at h
      -- `h` is now `if (signatureOk && timeOk && floorOk) then admit
      --  else reject = reject`, which forces the conjunction to be
      --  false.
      cases signatureOk <;> cases timeOk <;> cases floorOk <;>
        simp_all <;> tauto
```

This theorem captures the fail-closed-default clause from the
synthesis (`Section "Fail-closed default"` in the docstring): a reject
verdict ALWAYS has a witness, never a silent admit on partial
information.

#### Theorem 3: `negotiation_safety_schema_first` (the ordering theorem)

```
theorem negotiation_safety_schema_first
    (tokenSchema peerMax : Schema)
    (signatureOk timeOk floorOk : Bool) :
    Schema.le tokenSchema peerMax = false ->
    verify_capability_with_negotiated_floor_model
      tokenSchema peerMax signatureOk timeOk floorOk
    = CeilingVerdict.rejectExceedsCeiling := by
  intro hNotLe
  -- The schema-ceiling step rejects regardless of the three downstream
  -- Booleans. This is the "before any signature, time, or floor check
  -- runs" claim from the file docstring.
  unfold verify_capability_with_negotiated_floor_model schemaCeilingCheck
  rw [hNotLe]
  -- Both `match` arms reduce to rejectExceedsCeiling because
  -- schemaCeilingCheck rejected.
  rfl
```

This is the load-bearing claim of the docstring. Without theorem 3,
the proof set discharges only the verdict mapping, not the ordering.

### Headline `negotiation_safety` theorem

The `formal/theorem-inventory.json` row for
`handshake.negotiation_safety` is now backed by the conjunction of the
three theorems above. The simplest framing is to keep theorem 1 as the
named `negotiation_safety` (it is the primary admit-direction
implication) and reference theorems 2 and 3 as siblings. The theorem
inventory carries all three rows.

This proof set:

- Does **not** evaluate by `rfl` against `schemaCeilingCheck`'s own
  definition (R2 MINOR 7.2: theorem 2 uses `cases ... <;> tauto`,
  theorem 3 uses `unfold` + `rw` + `rfl` at the leaves only after
  case work, theorem 1 uses `cases` and `split_ifs`).
- Does refinement work: it extracts the schema-ceiling guard from the
  executable-model term's `match` arm.
- Pins the property the docstring claims: schema-ceiling rejection
  precedes signature, time, and floor checks (theorem 3).
- Proves the no-silent-admit clause (theorem 2).

## File paths

- `formal/lean4/Chio/Chio/Proofs/HandshakeNegotiation.lean`: site of
  re-stated theorems and new model term.
- `formal/theorem-inventory.json`: rows for
  `handshake.negotiation_safety`,
  `handshake.negotiation_safety_reject_implies_not_le_or_other_failure`,
  and `handshake.negotiation_safety_schema_first` updated from
  `assumed` to `proven` (one row per theorem).
- `formal/MAPPING.md`: cross-reference added between
  `verify_capability_with_negotiated_floor_model` (Lean) and
  `verify_capability_with_negotiated_floor` (Rust at
  `crates/chio-kernel-core/src/capability_verify.rs:226-255`). The
  mapping notes that `crypto_floor: CapabilityCryptoFloor` and
  `peer: &CapabilityNegotiation` are abstracted to Boolean witnesses
  (`floorOk`, `peerMax`) at the refinement level.
- `crates/chio-kernel-core/src/capability_verify.rs`: source-of-truth
  for the Rust function signature; no edits expected, only
  cross-reference.
- `.github/workflows/lean.yml` (new) or whichever existing lane
  release work-A5.1 chooses: enables Lean toolchain in CI so the proof is
  type-checked.

## What the executable model must refine

The executable-model term must refine the Rust verifier in three
respects:

1. **Order of checks.** Schema-ceiling MUST happen before signature,
   time, and floor checks. The Rust source at
   `crates/chio-kernel-core/src/capability_verify.rs:233-251` already
   has this order (the `exceeds_ceiling` early-return precedes the
   `verify_capability_with_floor` call at line 254); the model
   captures it. Theorem 3 above proves this.
2. **Fail-closed default.** Any unmodeled error path defaults to
   `rejectExceedsCeiling` (or a finer-grained reject variant if
   introduced). No silent admit on partial information. Theorem 2
   above proves this.
3. **Result type alignment.** The `CeilingVerdict` type uses two
   constructors: `admit` and `rejectExceedsCeiling`. If finer-grained
   reject reasons are needed for other theorems, the model can be
   extended; this theorem set only needs the binary distinction. The
   Rust `Result<VerifiedCapability, CapabilityError>` carries the
   richer error variants; refinement maps `Ok(_) -> admit` and
   `Err(_) -> rejectExceedsCeiling` for the schema-ceiling property.

## Sibling theorems and tautology audit

The other `rfl` theorems in the same file (lines 52-71) are also
tautological by the same diagnosis:

- `negotiation_safety_v2_rejected_under_v1_ceiling` (lines 52-54)
- `negotiation_safety_v1_admitted_under_v2_ceiling` (lines 59-61)
- `negotiation_safety_v1_admitted_under_v1_ceiling` (lines 64-66)
- `negotiation_safety_v2_admitted_under_v2_ceiling` (lines 69-71)

These are concrete-value sanity checks (e.g. `schemaCeilingCheck v2 v1
= rejectExceedsCeiling`). For concrete inputs, `rfl` is genuinely
correct: the function evaluates concretely and the answer is the
constant. These four are NOT in the same failure class as the universal
`negotiation_safety` and do not need rewriting. They serve as smoke
tests that `schemaCeilingCheck` evaluates the way the docstring claims
on the four corner inputs.

The audit-doc cross-reference for these four is preserved (no edits to
`theorem-inventory.json` rows).

## Anti-pattern guard

Per Lane A's close bar:

- A proof body that is `rfl` against the same function definition that
  defines the function under test fails the close bar (this is the
  pattern the Quality Skeptic identified, line 52).
- A proof that uses `decide` to discharge the universal statement
  without case analysis is acceptable only if `decide` invokes the
  executable-model term (not `schemaCeilingCheck`'s own body).
- The proof body MUST include at least one of `cases`, `induction`,
  `split_ifs`, or `intro`-followed-by-non-rfl. A one-line `by ...`
  proof that elaborates without case analysis fails the close bar
  (R2 MINOR 7.2). The three theorems above each satisfy this.
- The `assumed` row in `theorem-inventory.json` cannot remain after
  release work-A5.4 lands.

## Lean toolchain in CI (re-scoped per R2 MINOR 5.3)

release work-A5.1 wires the Lean toolchain into CI. The current state
(`HandshakeNegotiation.lean` lines 10-12): "The Lean toolchain is
currently unavailable in CI, so the manifest status for this theorem is
`assumed`. The Rust shell is exercised by
`crates/chio-conformance/tests/verify_rejects_v2_token_when_peer_negotiated_v1_only.rs`."

The Rust shell test continues to exercise the property at runtime; A5
adds Lean type-checking on top. Both layers are kept.

**Re-scope from M to L** (R2 MINOR 5.3): Lean 4 toolchain bringup in CI
is non-trivial. release work-A5.1 owns:

- Pin a specific Lean 4 toolchain version in
  `formal/lean4/lean-toolchain` (or equivalent). Without a pin every
  PR rebuilds the proof set against whatever Lean version is current,
  which produces non-deterministic CI.
- Document the elaboration time + CI cache strategy. The current proof
  set elaborates in seconds; if the cache is warm. From a cold cache,
  `lake build` for the full proof set takes minutes; the cache key is
  the toolchain pin file plus the source-tree hash.
- Add `.github/workflows/lean.yml` (or extend an existing workflow)
  with `lake build` and a one-liner manifest check.

## release work-A5.3 acceptance (additions per R2 MAJOR 5.2 and R2 MINOR 7.2)

After merge, the close bar requires:

- Three theorems land (not one).
- The proof bodies use `cases`, `split_ifs`, or `intro`-with-case-work,
  not a one-line `rfl` or `decide` against the executable-model term's
  own definition.
- After merge, replace the executable-model term body with the
  schemaCeilingCheck-only one-liner (`fun ts pm _ _ _ =>
  schemaCeilingCheck ts pm`) and confirm Lean elaboration FAILS for at
  least theorem 2 and theorem 3 (theorem 1 is also expected to fail
  but theorem 1 alone is too weak to be load-bearing). Capture the
  failing elaboration to
  `audits/evidence/release work-A5.3/elaboration-fails-on-revert.txt`.
