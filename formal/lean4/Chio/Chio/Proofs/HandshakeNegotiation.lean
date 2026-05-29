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

/-- Fail-closed admission soundness: the handshake admits a schema ONLY if
    that schema is the current Chio-owned one. Equivalently, any schema other
    than `current` is rejected. This is the load-bearing safety direction
    (it quantifies over the whole `CurrentSchema` domain and rules out
    admitting anything unrecognized), rather than merely restating the two
    definitional match arms of `checkCurrentSchema`. -/
theorem negotiation_admit_only_current (schema : CurrentSchema)
    (h_admit : checkCurrentSchema schema = Admission.admit) :
    schema = CurrentSchema.current := by
  cases schema with
  | current => rfl
  | unknown => simp [checkCurrentSchema] at h_admit

end Chio.Proofs.HandshakeNegotiation
