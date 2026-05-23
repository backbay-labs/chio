/-
  Current-schema admission model for the federation handshake.

  Chio is pre-release and exposes one Chio-owned capability schema:
  `chio.capability.v1`. The handshake still exchanges feature bits, but it does
  not negotiate alternate Chio-owned capability schema rungs. Unknown schema
  identifiers are rejected fail-closed before signature, time, floor, or budget
  checks run.
-/

set_option autoImplicit false

namespace Chio.Proofs.HandshakeNegotiation

inductive CurrentSchema
  | current
  | unknown
deriving DecidableEq, Repr

inductive Admission
  | admit
  | rejectUnknownSchema
deriving DecidableEq, Repr

def checkCurrentSchema : CurrentSchema -> Admission
  | CurrentSchema.current => Admission.admit
  | CurrentSchema.unknown => Admission.rejectUnknownSchema

/-- The current Chio-owned schema admits, and every unknown schema rejects. -/
theorem negotiation_safety :
    checkCurrentSchema CurrentSchema.current = Admission.admit ∧
      checkCurrentSchema CurrentSchema.unknown = Admission.rejectUnknownSchema := by
  constructor
  · rfl
  · rfl

end Chio.Proofs.HandshakeNegotiation
