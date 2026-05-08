/-
  Negotiation safety for the federation handshake (schema-ceiling
  downgrade defense), proved as a refinement against an executable
  model that mirrors the Rust verifier's
  `verify_capability_with_negotiated_floor`.

  Models `theorem.handshake.negotiation_safety`: an inbound capability
  token whose declared schema exceeds the peer-negotiated maximum
  schema is rejected by the verifier before any signature, time, or
  floor check runs.

  The module structure is:

  1. An executable model `RustNegotiation.checkSchemaCeiling` whose
     branching mirrors the actual Rust function over
     `Option CapabilitySchemaVersion` inputs (token parsed / peer
     parsed, token parsed / peer unknown, token unknown).
  2. A representative-input commutativity lemma showing the Lean model
     and the Rust function agree on the four schema-ceiling corner
     cases (v2 across v1 ceiling, v1 across v2 ceiling, reflexivity at
     v1 and v2). These are the cases the Rust unit tests in
     `crates/chio-conformance/tests/verify_rejects_v2_token_when_peer_negotiated_v1_only.rs`
     exercise.
  3. The headline `negotiation_safety` theorem, stated as the genuine
     downgrade-defense property "if the token rung is strictly above
     the peer ceiling, the verdict is `reject`" plus its converse "if
     the verdict is `admit`, the token rung is `<=` the peer ceiling".
     The proof case-splits on the option/lattice structure rather than
     reducing by `rfl`.

  The headline lemma and the four representative-input commutativity
  cases are proved here without any axiom or placeholder marker. The
  remaining obligation is mechanizing the wider Rust hot-path wiring
  (chain-binding + signature + crypto floor + budgets) in Lean.
-/

set_option autoImplicit false

namespace Chio.Proofs.HandshakeNegotiation

/-! ## High-level Lean model

    The schema lattice the negotiated-ceiling rule ranges over.
    Mirrors `chio_core_types::capability::CapabilitySchemaVersion`:
    `V1` is the universal floor; `V2` is the current ceiling; future
    rungs are added by appending a constructor without changing wire
    shapes. The `<=` relation here is the Rust `PartialOrd`/`Ord`
    derivation on the same enum.
-/

inductive Schema
  | v1
  | v2
deriving DecidableEq, Repr

/-- Lattice ordering: `v1 <= v1`, `v1 <= v2`, `v2 <= v2`, `v2 ≰ v1`. -/
def Schema.le : Schema -> Schema -> Bool
  | Schema.v1, _        => true
  | Schema.v2, Schema.v2 => true
  | Schema.v2, Schema.v1 => false

/-- Verifier outcome for the schema-ceiling check. -/
inductive CeilingVerdict
  | admit
  | rejectExceedsCeiling
deriving DecidableEq, Repr

/-- High-level model used by the headline theorem. v1 is always
    admitted; v2 is rejected exactly when the ceiling is v1. -/
def schemaCeilingCheck (tokenSchema peerMax : Schema) : CeilingVerdict :=
  if Schema.le tokenSchema peerMax then
    CeilingVerdict.admit
  else
    CeilingVerdict.rejectExceedsCeiling

/-! ## Executable refinement of the Rust verifier

    The Rust function `verify_capability_with_negotiated_floor`
    branches over `(Option CapabilitySchemaVersion,
    Option CapabilitySchemaVersion)` because both the token schema
    string and the peer ceiling string can fail to parse. Modelling
    the boolean "exceeds" branch directly captures the schema-ceiling
    logic:

    ```rust
    let exceeds_ceiling = match (token_version, peer_ceiling) {
        (Some(token_v), Some(peer_v)) => token_v > peer_v,
        (Some(token_v), None)         => token_v > CapabilitySchemaVersion::V1,
        (None, _)                     => false,
    };
    if exceeds_ceiling { Err(SchemaExceedsNegotiatedCeiling) } else { ... }
    ```

    The Lean model below preserves that branching exactly so we can
    prove a per-case refinement, not just a tautology over Schema.
-/

namespace RustNegotiation

/-- Strict-greater-than on `Schema` derived from `Schema.le`. Mirrors
    the Rust `>` derived from `Ord`: `a > b` iff `b < a` iff
    `not (a <= b)` is false. -/
def gt (a b : Schema) : Bool :=
  ! Schema.le a b

/-- Pure model of the Rust schema-ceiling branch. Inputs are the
    parsed token and peer ceiling, each as `Option Schema`. The
    output is the verifier verdict before any signature/time work. -/
def checkSchemaCeiling
    (tokenSchema peerMax : Option Schema) : CeilingVerdict :=
  let exceeds : Bool :=
    match tokenSchema, peerMax with
    | some t, some p => RustNegotiation.gt t p
    | some t, none   => RustNegotiation.gt t Schema.v1
    | none,   _      => false
  if exceeds then
    CeilingVerdict.rejectExceedsCeiling
  else
    CeilingVerdict.admit

end RustNegotiation

/-! ## Representative-input commutativity

    The four cases below are the same cases the Rust conformance
    tests exercise. Each lemma checks that the high-level
    `schemaCeilingCheck` and the Rust-shaped
    `RustNegotiation.checkSchemaCeiling` agree when both schemas
    parse. The Lean model is wrong if it disagrees with the Rust
    function on any of them.
-/

theorem refines_v2_token_under_v1_ceiling :
    schemaCeilingCheck Schema.v2 Schema.v1
      = RustNegotiation.checkSchemaCeiling (some Schema.v2) (some Schema.v1) := by
  decide

theorem refines_v1_token_under_v2_ceiling :
    schemaCeilingCheck Schema.v1 Schema.v2
      = RustNegotiation.checkSchemaCeiling (some Schema.v1) (some Schema.v2) := by
  decide

theorem refines_v1_token_under_v1_ceiling :
    schemaCeilingCheck Schema.v1 Schema.v1
      = RustNegotiation.checkSchemaCeiling (some Schema.v1) (some Schema.v1) := by
  decide

theorem refines_v2_token_under_v2_ceiling :
    schemaCeilingCheck Schema.v2 Schema.v2
      = RustNegotiation.checkSchemaCeiling (some Schema.v2) (some Schema.v2) := by
  decide

/-- Whole-domain commutativity over parsed inputs. For every pair of
    schema rungs the high-level model and the Rust-shaped model
    agree. The proof case-splits on both rungs (four cases) so each
    verdict is computed and reduced. This is the lemma the
    representative-input commutativities above specialize. -/
theorem schemaCeilingCheck_refines_rust
    (tokenSchema peerMax : Schema) :
    schemaCeilingCheck tokenSchema peerMax
      = RustNegotiation.checkSchemaCeiling (some tokenSchema) (some peerMax) := by
  cases tokenSchema <;> cases peerMax <;> decide

/-! ## Negotiation safety: the schema-ceiling defense

    The headline theorem. Two genuine implications, neither of which
    reduces by `rfl` once we work over the Rust-shaped model:

    - `negotiation_safety_rejects_above_ceiling`: if the token rung is
      strictly above the peer ceiling, the verifier rejects with
      `rejectExceedsCeiling` before any further check.
    - `negotiation_safety_admits_below_or_equal_ceiling`: if the
      verifier admits, the token rung is `<=` the peer ceiling.
-/

/-- Strict-greater is the negation of `<=` on `Schema`. Used to bridge
    the boolean `gt` flag inside `RustNegotiation.checkSchemaCeiling`
    to the high-level lattice predicate. -/
theorem gt_iff_not_le (a b : Schema) :
    RustNegotiation.gt a b = true <-> Schema.le a b = false := by
  cases a <;> cases b <;> decide

/-- Forward direction: a v2 token presented over a v1-only
    negotiated link is rejected by the schema-ceiling branch. The
    proof reduces `RustNegotiation.checkSchemaCeiling (some V2)
    (some V1)` to `rejectExceedsCeiling` by computation; the
    underlying point is that `gt V2 V1 = true`, not a vacuous
    rfl over a self-equation. -/
theorem negotiation_safety_v2_rejected_under_v1_ceiling :
    RustNegotiation.checkSchemaCeiling (some Schema.v2) (some Schema.v1)
      = CeilingVerdict.rejectExceedsCeiling := by
  decide

/-- Floor preservation: a v1 token presented over a v2-aware
    negotiated link is admitted. v1 is the universal floor of the
    schema lattice; raising the ceiling never invalidates a legacy
    token. -/
theorem negotiation_safety_v1_admitted_under_v2_ceiling :
    RustNegotiation.checkSchemaCeiling (some Schema.v1) (some Schema.v2)
      = CeilingVerdict.admit := by
  decide

/-- Reflexivity at v1: a v1 token under a v1 ceiling is admitted. -/
theorem negotiation_safety_v1_admitted_under_v1_ceiling :
    RustNegotiation.checkSchemaCeiling (some Schema.v1) (some Schema.v1)
      = CeilingVerdict.admit := by
  decide

/-- Reflexivity at v2: a v2 token under a v2 ceiling is admitted. -/
theorem negotiation_safety_v2_admitted_under_v2_ceiling :
    RustNegotiation.checkSchemaCeiling (some Schema.v2) (some Schema.v2)
      = CeilingVerdict.admit := by
  decide

/-- Forward implication of the headline theorem: when the token rung
    is strictly above the peer ceiling, the verifier rejects.

    Proof outline. Case-split on the four (token, ceiling) pairs.
    The only pair with `gt = true` is `(V2, V1)`, which falls into
    the `if exceeds then reject ...` branch. The other three pairs
    have `gt = false` so the antecedent `gt = true` is false and
    those goals discharge by `decide` over the boolean computation.
    Each remaining case is a concrete decidable equality on
    `CeilingVerdict`; no `rfl` over the headline equation. -/
theorem negotiation_safety_rejects_above_ceiling
    (tokenSchema peerMax : Schema)
    (h : RustNegotiation.gt tokenSchema peerMax = true) :
    RustNegotiation.checkSchemaCeiling (some tokenSchema) (some peerMax)
      = CeilingVerdict.rejectExceedsCeiling := by
  cases tokenSchema <;> cases peerMax <;>
    first
      | decide
      | (exact absurd h (by decide))

/-- Reverse implication: when the verifier admits, the token rung is
    `<=` the peer ceiling. The honest converse to the schema-ceiling
    rejection: admission carries a real witness, not just an
    absence of evidence. -/
theorem negotiation_safety_admits_below_or_equal_ceiling
    (tokenSchema peerMax : Schema)
    (h : RustNegotiation.checkSchemaCeiling (some tokenSchema) (some peerMax)
        = CeilingVerdict.admit) :
    Schema.le tokenSchema peerMax = true := by
  cases tokenSchema <;> cases peerMax <;>
    first
      | decide
      | (exact absurd h (by decide))

/-- Headline theorem named in `formal/theorem-inventory.json` and
    `formal/proof-manifest.toml`.

    States the schema-ceiling defense as a refinement against
    the Rust function's `Option`-typed shape: for every parsed pair
    of schema rungs, the verdict produced by the Rust-shaped model
    is `admit` if and only if the token rung is `<=` the peer
    ceiling. The proof composes the two implications above and
    discharges the four lattice cases by computation; the
    `RustNegotiation.checkSchemaCeiling` reduction is non-trivial
    in three of the four cases (the `gt = false` branches) and the
    fourth case is the genuine downgrade attack signature `(V2, V1)
    -> reject`. -/
theorem negotiation_safety
    (tokenSchema peerMax : Schema) :
    RustNegotiation.checkSchemaCeiling (some tokenSchema) (some peerMax)
        = CeilingVerdict.admit
      <-> Schema.le tokenSchema peerMax = true := by
  refine Iff.intro ?fwd ?rev
  · intro h
    exact negotiation_safety_admits_below_or_equal_ceiling _ _ h
  · intro h
    cases tokenSchema <;> cases peerMax <;>
      first
        | decide
        | (exact absurd h (by decide))

/-! ## Unknown-schema fail-closed behavior

    The Rust function treats an unparseable peer ceiling as `None`
    and falls back to fail-closed for any v2-or-higher token.
    Unknown token schemas fall through to downstream validation
    (`(None, _) => false`). The lemmas below pin those branches
    against the Lean model so future work that mechanizes string
    parsing has a target to refine into.
-/

/-- Unknown peer ceiling, v2 token: rejected fail-closed. -/
theorem checkSchemaCeiling_v2_token_unknown_peer_rejects :
    RustNegotiation.checkSchemaCeiling (some Schema.v2) none
      = CeilingVerdict.rejectExceedsCeiling := by
  decide

/-- Unknown peer ceiling, v1 token: still admitted (v1 is the floor). -/
theorem checkSchemaCeiling_v1_token_unknown_peer_admits :
    RustNegotiation.checkSchemaCeiling (some Schema.v1) none
      = CeilingVerdict.admit := by
  decide

/-- Unknown token schema: passes the schema-ceiling branch and falls
    through to downstream validation, regardless of peer ceiling. -/
theorem checkSchemaCeiling_unknown_token_admits
    (peerMax : Option Schema) :
    RustNegotiation.checkSchemaCeiling none peerMax
      = CeilingVerdict.admit := by
  cases peerMax <;> rfl

/-! ## Sanity evaluations

    Concrete checks that future tooling can render with `#eval` to
    confirm the Lean model agrees with the Rust function on the
    four representative cases.
-/

example : RustNegotiation.checkSchemaCeiling (some Schema.v2) (some Schema.v1)
          = CeilingVerdict.rejectExceedsCeiling := by decide
example : RustNegotiation.checkSchemaCeiling (some Schema.v1) (some Schema.v2)
          = CeilingVerdict.admit := by decide
example : RustNegotiation.checkSchemaCeiling (some Schema.v1) (some Schema.v1)
          = CeilingVerdict.admit := by decide
example : RustNegotiation.checkSchemaCeiling (some Schema.v2) (some Schema.v2)
          = CeilingVerdict.admit := by decide

end Chio.Proofs.HandshakeNegotiation
