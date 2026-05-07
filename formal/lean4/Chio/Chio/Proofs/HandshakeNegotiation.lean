/-
  Negotiation safety for the federation handshake.

  Models `theorem.handshake.negotiation_safety`: an inbound capability
  token whose declared schema exceeds the peer-negotiated maximum schema
  is rejected by the verifier before any signature, time, or floor check
  runs. This blocks a v1-only Mallory from forcing a v2-aware Alice to
  parse v2-only fields (W1.3 downgrade-attack defense).

  The Lean toolchain is currently unavailable in CI, so the manifest
  status for this theorem is `assumed`. The Rust shell is exercised by
  `crates/chio-conformance/tests/verify_rejects_v2_token_when_peer_negotiated_v1_only.rs`.
-/

set_option autoImplicit false

namespace Chio.Proofs.HandshakeNegotiation

/-- Capability-token schema lattice. v1 sits below v2; the verifier
    refuses to parse a token whose declared rung is above the peer
    ceiling. -/
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

/-- Pure model of the schema-ceiling check inside
    `verify_capability_with_negotiated_floor`. The implementation
    rejects when the token rung is strictly above the peer's negotiated
    maximum. -/
def schemaCeilingCheck (tokenSchema peerMax : Schema) : CeilingVerdict :=
  if Schema.le tokenSchema peerMax then
    CeilingVerdict.admit
  else
    CeilingVerdict.rejectExceedsCeiling

/-- Negotiation-safety theorem: a v2 token presented to a peer whose
    negotiated ceiling is v1 is rejected by the schema-ceiling check.
    This is the W1.3 downgrade-attack defense in its purest form. -/
theorem negotiation_safety_v2_rejected_under_v1_ceiling :
    schemaCeilingCheck Schema.v2 Schema.v1 = CeilingVerdict.rejectExceedsCeiling := by
  rfl

/-- Symmetric direction: a v1 token presented to a v2-aware peer is
    admitted. v1 is the universal floor; raising the ceiling never
    invalidates legacy tokens. -/
theorem negotiation_safety_v1_admitted_under_v2_ceiling :
    schemaCeilingCheck Schema.v1 Schema.v2 = CeilingVerdict.admit := by
  rfl

/-- Reflexivity at v1: a v1 token is admitted under a v1 ceiling. -/
theorem negotiation_safety_v1_admitted_under_v1_ceiling :
    schemaCeilingCheck Schema.v1 Schema.v1 = CeilingVerdict.admit := by
  rfl

/-- Reflexivity at v2: a v2 token is admitted under a v2 ceiling. -/
theorem negotiation_safety_v2_admitted_under_v2_ceiling :
    schemaCeilingCheck Schema.v2 Schema.v2 = CeilingVerdict.admit := by
  rfl

/-- Headline theorem named in `formal/theorem-inventory.json` and
    `formal/proof-manifest.toml`. The verdict is exactly `admit` iff the
    token rung is below or equal to the peer ceiling; otherwise it is
    `rejectExceedsCeiling`. -/
theorem negotiation_safety
    (tokenSchema peerMax : Schema) :
    schemaCeilingCheck tokenSchema peerMax =
      (if Schema.le tokenSchema peerMax then
         CeilingVerdict.admit
       else
         CeilingVerdict.rejectExceedsCeiling) := by
  rfl

end Chio.Proofs.HandshakeNegotiation
