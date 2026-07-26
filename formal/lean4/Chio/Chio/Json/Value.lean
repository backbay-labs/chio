import Lean.Elab.Tactic.Omega

/-!
# Bounded canonical JSON values

Strings are sequences of Unicode scalar values. Integers use canonical decimal
digits and cover the signed i64 and unsigned u64 ranges. Object ordering is
expressed by the separate `SortedObject` predicate.
-/

set_option autoImplicit false

namespace Chio.Json

abbrev CodePoint := Nat
abbrev CodeSeq := List CodePoint
abbrev Byte := Fin 256
abbrev ByteSeq := List Byte
abbrev HexDigit := Fin 16
abbrev DecimalDigit := Fin 10

def controlValue (high low : HexDigit) : Nat :=
  high.val * 16 + low.val

def IsEscapedControl (high low : HexDigit) : Prop :=
  let value := controlValue high low
  value ≤ 31 ∧
    value ≠ 8 ∧ value ≠ 9 ∧ value ≠ 10 ∧ value ≠ 12 ∧ value ≠ 13

instance (high low : HexDigit) : Decidable (IsEscapedControl high low) :=
  by unfold IsEscapedControl; infer_instance

def IsUnicodeScalar (value : Nat) : Prop :=
  value ≤ 0x10ffff ∧
    ¬(0xd800 ≤ value ∧ value ≤ 0xdfff)

instance (value : Nat) : Decidable (IsUnicodeScalar value) :=
  by unfold IsUnicodeScalar; infer_instance

def IsLiteralScalar (value : Nat) : Prop :=
  IsUnicodeScalar value ∧
    value ≠ 34 ∧ value ≠ 92 ∧
    ¬(value ≤ 31)

instance (value : Nat) : Decidable (IsLiteralScalar value) :=
  by unfold IsLiteralScalar; infer_instance

inductive JScalar where
  | literal (value : Nat) (valid : IsLiteralScalar value)
  | quote
  | reverseSolidus
  | backspace
  | tab
  | lineFeed
  | formFeed
  | carriageReturn
  | control (high low : HexDigit) (valid : IsEscapedControl high low)
  deriving DecidableEq, Repr

abbrev ScalarSeq := List JScalar

def JScalar.value : JScalar → Nat
  | .literal value _ => value
  | .quote => 34
  | .reverseSolidus => 92
  | .backspace => 8
  | .tab => 9
  | .lineFeed => 10
  | .formFeed => 12
  | .carriageReturn => 13
  | .control high low _ => controlValue high low

theorem JScalar.valid (scalar : JScalar) : IsUnicodeScalar scalar.value := by
  cases scalar with
  | literal value valid => exact valid.1
  | quote | reverseSolidus | backspace | tab | lineFeed | formFeed |
      carriageReturn => decide
  | control high low valid =>
      simp only [JScalar.value, IsUnicodeScalar, controlValue]
      constructor <;> omega

def decimalValue (digits : List DecimalDigit) : Nat :=
  digits.foldl (fun value digit => value * 10 + digit.val) 0

def CanonicalInteger (negative : Bool) (digits : List DecimalDigit) : Prop :=
  digits ≠ [] ∧
    digits.length ≤ 20 ∧
    (digits.length = 1 ∨ digits.head?.map Fin.val ≠ some 0) ∧
    (negative = true → decimalValue digits ≠ 0) ∧
    (if negative then decimalValue digits ≤ 9223372036854775808
     else decimalValue digits ≤ 18446744073709551615)

instance (negative : Bool) (digits : List DecimalDigit) :
    Decidable (CanonicalInteger negative digits) :=
  by unfold CanonicalInteger; infer_instance

structure BoundedInt where
  negative : Bool
  digits : List DecimalDigit
  valid : CanonicalInteger negative digits
  deriving DecidableEq, Repr

structure BoundedUInt where
  digits : List DecimalDigit
  valid : CanonicalInteger false digits
  deriving DecidableEq, Repr

def BoundedUInt.toBoundedInt (value : BoundedUInt) : BoundedInt :=
  { negative := false, digits := value.digits, valid := value.valid }

def BoundedInt.toBoundedUInt? : BoundedInt → Option BoundedUInt
  | ⟨false, digits, valid⟩ => some ⟨digits, valid⟩
  | ⟨true, _, _⟩ => none

@[simp] theorem BoundedUInt.toBoundedInt_toBoundedUInt?
    (value : BoundedUInt) :
    value.toBoundedInt.toBoundedUInt? = some value := by
  rcases value with ⟨digits, valid⟩
  rfl

def scalarUtf16Units (scalar : JScalar) : List Nat :=
  let value := scalar.value
  if value < 0x10000 then
    [value]
  else
    let shifted := value - 0x10000
    [0xd800 + shifted / 0x400, 0xdc00 + shifted % 0x400]

def utf16Units (scalars : ScalarSeq) : List Nat :=
  scalars.flatMap scalarUtf16Units

def codeSeqLess : List Nat → List Nat → Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | left :: leftTail, right :: rightTail =>
      if left < right then true
      else if right < left then false
      else codeSeqLess leftTail rightTail

def utf16Less (left right : ScalarSeq) : Bool :=
  codeSeqLess (utf16Units left) (utf16Units right)

mutual
  inductive JValue where
    | null
    | bool (value : Bool)
    | int (value : BoundedInt)
    | str (value : ScalarSeq)
    | arr (values : JArray)
    | obj (entries : JObject)
    deriving DecidableEq, Repr

  inductive JArray where
    | nil
    | cons (head : JValue) (tail : JArray)
    deriving DecidableEq, Repr

  inductive JObject where
    | nil
    | cons (key : ScalarSeq) (value : JValue) (tail : JObject)
    deriving DecidableEq, Repr
end

inductive KeyBeforeAll (key : ScalarSeq) : JObject → Prop where
  | nil : KeyBeforeAll key .nil
  | cons {nextKey : ScalarSeq} {value : JValue} {tail : JObject}
      (ordered : utf16Less key nextKey = true)
      (remaining : KeyBeforeAll key tail) :
      KeyBeforeAll key (.cons nextKey value tail)

inductive SortedObject : JObject → Prop where
  | nil : SortedObject .nil
  | cons {key : ScalarSeq} {value : JValue} {tail : JObject}
      (before : KeyBeforeAll key tail)
      (sorted : SortedObject tail) :
      SortedObject (.cons key value tail)

def JArray.toList : JArray → List JValue
  | .nil => []
  | .cons head tail => head :: tail.toList

def JArray.ofList : List JValue → JArray
  | [] => .nil
  | head :: tail => .cons head (ofList tail)

theorem JArray.toList_ofList (values : List JValue) :
    (JArray.ofList values).toList = values := by
  induction values with
  | nil => rfl
  | cons head tail ih => simp [JArray.ofList, JArray.toList, ih]

def JObject.toList : JObject → List (ScalarSeq × JValue)
  | .nil => []
  | .cons key value tail => (key, value) :: tail.toList

end Chio.Json
