import Chio.Json.Canonical

/-!
# Symbolic receipt hash

The hash function is abstract. Its sole property is symbolic collision
resistance over the image of the canonical renderer. Real SHA-256 is a
compressing function, so concrete security remains a computational assumption
outside Lean rather than literal mathematical injectivity.
-/

set_option autoImplicit false

namespace Chio.Json

abbrev CanonicalBytes :=
  { bytes : ByteSeq // ∃ value : JValue, canonical value = bytes }

def canonicalBytes (value : JValue) : CanonicalBytes :=
  ⟨canonical value, ⟨value, rfl⟩⟩

structure SymbolicHash where
  Output : Type
  digest : CanonicalBytes → Output
  injective : ∀ left right, digest left = digest right → left = right

axiom hash_collision_resistant : SymbolicHash

abbrev HashVal := hash_collision_resistant.Output

noncomputable def digest (value : JValue) : HashVal :=
  hash_collision_resistant.digest (canonicalBytes value)

theorem digest_injective {left right : JValue}
    (equal : digest left = digest right) :
    canonical left = canonical right := by
  have inputsEqual : canonicalBytes left = canonicalBytes right :=
    hash_collision_resistant.injective _ _ equal
  exact congrArg Subtype.val inputsEqual

#print axioms hash_collision_resistant

end Chio.Json
