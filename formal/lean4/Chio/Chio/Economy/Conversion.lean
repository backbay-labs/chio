import Aeneas

set_option autoImplicit false

namespace Chio.Economy.Conversion

def u64Max : Nat := 18446744073709551615

def roundUp (product denominator : Nat) : Nat :=
  if product % denominator = 0 then
    product / denominator
  else
    product / denominator + 1

def convertCeil (units numerator denominator : Nat) : Option Nat :=
  if numerator = 0 then
    none
  else if denominator = 0 then
    none
  else
    if roundUp (units * numerator) denominator > u64Max then
      none
    else
      some (roundUp (units * numerator) denominator)

def convertFloor (units numerator denominator : Nat) : Option Nat :=
  if numerator = 0 then
    none
  else if denominator = 0 then
    none
  else
    if units * numerator / denominator > u64Max then
      none
    else
      some (units * numerator / denominator)

theorem convert_floor_envelope
    {units numerator denominator value : Nat}
    (converted : convertFloor units numerator denominator = some value) :
    numerator ≠ 0 ∧ denominator ≠ 0 ∧
      value * denominator ≤ units * numerator ∧
      units * numerator < (value + 1) * denominator := by
  unfold convertFloor at converted
  split at converted
  · contradiction
  next numeratorNonzero =>
    split at converted
    · contradiction
    next denominatorNonzero =>
      split at converted
      · contradiction
      next valueFits =>
        injection converted with valueEq
        subst value
        refine ⟨numeratorNonzero, denominatorNonzero, ?_, ?_⟩
        · exact Nat.div_mul_le_self _ _
        · simpa [Nat.mul_comm] using
            Nat.lt_mul_div_succ (units * numerator)
              (Nat.pos_of_ne_zero denominatorNonzero)

theorem convert_ceil_envelope
    {units numerator denominator value : Nat}
    (converted : convertCeil units numerator denominator = some value) :
    numerator ≠ 0 ∧ denominator ≠ 0 ∧
      units * numerator ≤ value * denominator ∧
      (value = 0 ∨ (value - 1) * denominator < units * numerator) := by
  unfold convertCeil at converted
  split at converted
  · contradiction
  next numeratorNonzero =>
    split at converted
    · contradiction
    next denominatorNonzero =>
      simp only [roundUp] at converted
      split at converted
      next remainderZero =>
        split at converted
        · contradiction
        next valueFits =>
          injection converted with valueEq
          subst value
          refine ⟨numeratorNonzero, denominatorNonzero, ?_, ?_⟩
          · have decomposition := Nat.div_add_mod (units * numerator) denominator
            have productEq :
                units * numerator / denominator * denominator = units * numerator := by
              rw [Nat.mul_comm]
              omega
            exact productEq.ge
          · by_cases quotientZero : units * numerator / denominator = 0
            · exact Or.inl quotientZero
            · exact Or.inr (by
                have quotientPositive : 0 < units * numerator / denominator :=
                  Nat.pos_of_ne_zero quotientZero
                have predecessorLess : units * numerator / denominator - 1 <
                    units * numerator / denominator := Nat.sub_lt quotientPositive (by omega)
                have denominatorPositive : 0 < denominator :=
                  Nat.pos_of_ne_zero denominatorNonzero
                have multiplied := Nat.mul_lt_mul_of_pos_right predecessorLess denominatorPositive
                have decomposition := Nat.div_add_mod (units * numerator) denominator
                have productEq :
                    units * numerator / denominator * denominator = units * numerator := by
                  rw [Nat.mul_comm]
                  omega
                exact multiplied.trans_eq productEq)
      next remainderNonzero =>
        split at converted
        · contradiction
        next valueFits =>
          injection converted with valueEq
          subst value
          have denominatorPositive : 0 < denominator :=
            Nat.pos_of_ne_zero denominatorNonzero
          have remainderBound := Nat.mod_lt (units * numerator) denominatorPositive
          have decomposition := Nat.div_add_mod (units * numerator) denominator
          refine ⟨numeratorNonzero, denominatorNonzero, ?_, Or.inr ?_⟩
          · calc
              units * numerator = denominator * (units * numerator / denominator) +
                  units * numerator % denominator := decomposition.symm
              _ ≤ denominator * (units * numerator / denominator) + denominator := by omega
              _ = (units * numerator / denominator + 1) * denominator := by
                simp [Nat.mul_add, Nat.mul_comm]
          · simp only [Nat.add_sub_cancel]
            have remainderPositive : 0 < units * numerator % denominator :=
              Nat.pos_of_ne_zero remainderNonzero
            calc
              units * numerator / denominator * denominator <
                  denominator * (units * numerator / denominator) +
                    units * numerator % denominator := by
                      rw [Nat.mul_comm]
                      omega
              _ = units * numerator := decomposition

#print axioms convert_floor_envelope
#print axioms convert_ceil_envelope

end Chio.Economy.Conversion
