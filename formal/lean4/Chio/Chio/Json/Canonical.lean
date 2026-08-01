import Chio.Json.Value

/-!
# Canonical JSON rendering

The public renderer emits UTF-8 bytes. A code-point layer makes the lexical
proofs tractable, and `utf8Encode` is proved injective on Unicode scalar
sequences. RFC 8785 escapes only C0 controls, with the standard short forms
preferred where JSON defines them. DEL and C1 controls are emitted directly.
-/

set_option autoImplicit false

namespace Chio.Json

private def encodeUtf8One (value : CodePoint) (upper : value < 0x80) : ByteSeq :=
  [⟨value, Nat.lt_trans upper (by decide)⟩]

private def utf8Continuation (value : Nat) (upper : value < 0x40) : Byte :=
  ⟨0x80 + value,
    Nat.lt_trans (Nat.add_lt_add_left upper 0x80) (by decide)⟩

@[simp] private theorem utf8Continuation_val (value : Nat)
    (upper : value < 0x40) :
    (utf8Continuation value upper).val = 0x80 + value := rfl

private def encodeUtf8Two (value : CodePoint) (upper : value < 0x800) : ByteSeq :=
  [⟨0xc0 + value / 0x40, by
      have quotient : value / 0x40 < 0x20 :=
        Nat.div_lt_of_lt_mul (by simpa using upper)
      exact Nat.lt_trans (Nat.add_lt_add_left quotient 0xc0) (by decide)⟩,
    utf8Continuation (value % 0x40)
      (Nat.mod_lt value (by decide : 0 < 0x40))]

private def encodeUtf8Three (value : CodePoint)
    (upper : value < 0x10000) : ByteSeq :=
  [⟨0xe0 + value / 0x40 / 0x40, by
      have quotient : value / 0x40 / 0x40 < 0x10 := by
        rw [Nat.div_div_eq_div_mul]
        exact Nat.div_lt_of_lt_mul (by simpa using upper)
      exact Nat.lt_trans (Nat.add_lt_add_left quotient 0xe0) (by decide)⟩,
    utf8Continuation ((value / 0x40) % 0x40)
      (Nat.mod_lt (value / 0x40) (by decide : 0 < 0x40)),
    utf8Continuation (value % 0x40)
      (Nat.mod_lt value (by decide : 0 < 0x40))]

private def encodeUtf8Four (value : CodePoint)
    (upper : value ≤ 0x10ffff) : ByteSeq :=
  [⟨0xf0 + value / 0x40 / 0x40 / 0x40, by
      have quotient : value / 0x40 / 0x40 / 0x40 < 5 := by
        simp only [Nat.div_div_eq_div_mul]
        exact Nat.div_lt_of_lt_mul
          (Nat.lt_of_le_of_lt upper (by decide))
      exact Nat.lt_trans (Nat.add_lt_add_left quotient 0xf0) (by decide)⟩,
    utf8Continuation ((value / 0x40 / 0x40) % 0x40)
      (Nat.mod_lt (value / 0x40 / 0x40) (by decide : 0 < 0x40)),
    utf8Continuation ((value / 0x40) % 0x40)
      (Nat.mod_lt (value / 0x40) (by decide : 0 < 0x40)),
    utf8Continuation (value % 0x40)
      (Nat.mod_lt value (by decide : 0 < 0x40))]

/-- Encode one Unicode code point as UTF-8. The function is total, while the
    injectivity theorem restricts its argument to Unicode scalar values. -/
def encodeUtf8Scalar (value : CodePoint) : ByteSeq :=
  if ascii : value < 0x80 then
    encodeUtf8One value ascii
  else if twoByte : value < 0x800 then
    encodeUtf8Two value twoByte
  else if threeByte : value < 0x10000 then
    encodeUtf8Three value threeByte
  else if fourByte : value ≤ 0x10ffff then
    encodeUtf8Four value fourByte
  else
    []

def utf8Encode (values : CodeSeq) : ByteSeq :=
  values.flatMap encodeUtf8Scalar

def CodeSeqValid (values : CodeSeq) : Prop :=
  ∀ value ∈ values, IsUnicodeScalar value

instance (values : CodeSeq) : Decidable (CodeSeqValid values) := by
  unfold CodeSeqValid
  infer_instance

private def continuation (value : Byte) : Bool :=
  0x80 ≤ value.val && value.val < 0xc0

private theorem continuation_utf8Continuation (value : Nat)
    (upper : value < 0x40) :
    continuation (utf8Continuation value upper) = true := by
  simp [continuation, utf8Continuation]
  omega

private def decodeUtf8Prefix : ByteSeq → Option (CodePoint × ByteSeq)
  | [] => none
  | first :: rest =>
      if first.val < 0x80 then
        some (first.val, rest)
      else if 0xc2 ≤ first.val ∧ first.val < 0xe0 then
        match rest with
        | second :: tail =>
            if continuation second then
              some ((first.val - 0xc0) * 0x40 + (second.val - 0x80), tail)
            else
              none
        | _ => none
      else if 0xe0 ≤ first.val ∧ first.val < 0xf0 then
        match rest with
        | second :: third :: tail =>
            if continuation second ∧ continuation third then
              some (((first.val - 0xe0) * 0x40 +
                (second.val - 0x80)) * 0x40 + (third.val - 0x80), tail)
            else
              none
        | _ => none
      else if 0xf0 ≤ first.val ∧ first.val < 0xf5 then
        match rest with
        | second :: third :: fourth :: tail =>
            if continuation second ∧ continuation third ∧
                continuation fourth then
              some ((((first.val - 0xf0) * 0x40 +
                (second.val - 0x80)) * 0x40 +
                (third.val - 0x80)) * 0x40 + (fourth.val - 0x80), tail)
            else
              none
        | _ => none
      else
        none

set_option maxRecDepth 10000 in
private theorem decodeUtf8Prefix_encode (value : CodePoint)
    (valid : IsUnicodeScalar value) (rest : ByteSeq) :
    decodeUtf8Prefix (encodeUtf8Scalar value ++ rest) = some (value, rest) := by
  rcases valid with ⟨maximum, notSurrogate⟩
  have lowDecomposition := Nat.div_add_mod value 0x40
  have middleDecomposition :
      0x40 * (value / 0x40 / 0x40) + (value / 0x40) % 0x40 =
        value / 0x40 := by
    exact Nat.div_add_mod (value / 0x40) 0x40
  have highDecomposition :
      0x40 * (value / 0x40 / 0x40 / 0x40) +
          (value / 0x40 / 0x40) % 0x40 =
        value / 0x40 / 0x40 := by
    exact Nat.div_add_mod (value / 0x40 / 0x40) 0x40
  have decompositionTwo :
      (value / 0x40) * 0x40 + value % 0x40 = value := by
    simpa [Nat.mul_comm] using lowDecomposition
  have decompositionThree :
      ((value / 0x40 / 0x40) * 0x40 + (value / 0x40) % 0x40) *
          0x40 + value % 0x40 = value := by
    calc
      _ = (value / 0x40) * 0x40 + value % 0x40 := by
        rw [Nat.mul_comm (value / 0x40 / 0x40) 0x40,
          middleDecomposition]
      _ = value := decompositionTwo
  have decompositionFour :
      (((value / 0x40 / 0x40 / 0x40) * 0x40 +
          (value / 0x40 / 0x40) % 0x40) * 0x40 +
          (value / 0x40) % 0x40) * 0x40 + value % 0x40 = value := by
    calc
      _ = ((value / 0x40 / 0x40) * 0x40 +
          (value / 0x40) % 0x40) * 0x40 + value % 0x40 := by
        rw [Nat.mul_comm (value / 0x40 / 0x40 / 0x40) 0x40,
          highDecomposition]
      _ = (value / 0x40) * 0x40 + value % 0x40 := by
        rw [Nat.mul_comm (value / 0x40 / 0x40) 0x40,
          middleDecomposition]
      _ = value := decompositionTwo
  by_cases ascii : value < 0x80
  · simp [encodeUtf8Scalar, encodeUtf8One, ascii, decodeUtf8Prefix]
  · by_cases twoByte : value < 0x800
    · have quotientUpper : value / 0x40 < 0x20 :=
        Nat.div_lt_of_lt_mul (by simpa using twoByte)
      have valueLower : 0x80 ≤ value := Nat.le_of_not_gt ascii
      have quotientLower : 2 ≤ value / 0x40 :=
        (Nat.le_div_iff_mul_le (by decide)).2 (by simpa using valueLower)
      have leadRange :
          0xc2 ≤ 0xc0 + value / 0x40 ∧
            0xc0 + value / 0x40 < 0xe0 :=
        ⟨Nat.add_le_add_left quotientLower 0xc0,
          Nat.add_lt_add_left quotientUpper 0xc0⟩
      have leadNotAscii : ¬(0xc0 + value / 0x40 < 0x80) :=
        Nat.not_lt_of_ge (Nat.le_trans (by decide) (Nat.le_add_right 0xc0 _))
      have continued := continuation_utf8Continuation (value % 0x40)
        (Nat.mod_lt value (by decide : 0 < 0x40))
      simp [encodeUtf8Scalar, ascii, twoByte, decodeUtf8Prefix,
        encodeUtf8Two, leadRange, leadNotAscii, continued]
      exact decompositionTwo
    · by_cases threeByte : value < 0x10000
      · have quotientUpper : value / 0x40 / 0x40 < 0x10 := by
          rw [Nat.div_div_eq_div_mul]
          exact Nat.div_lt_of_lt_mul (by simpa using threeByte)
        have leadRange :
            0xe0 ≤ 0xe0 + value / 0x40 / 0x40 ∧
              0xe0 + value / 0x40 / 0x40 < 0xf0 :=
          ⟨Nat.le_add_right 0xe0 _, Nat.add_lt_add_left quotientUpper 0xe0⟩
        have leadNotAscii : ¬(0xe0 + value / 0x40 / 0x40 < 0x80) :=
          Nat.not_lt_of_ge (Nat.le_trans (by decide) (Nat.le_add_right 0xe0 _))
        have leadNotTwo : ¬(0xc2 ≤ 0xe0 + value / 0x40 / 0x40 ∧
            0xe0 + value / 0x40 / 0x40 < 0xe0) :=
          fun range => (Nat.not_lt_of_ge (Nat.le_add_right 0xe0 _)) range.2
        have middleContinued := continuation_utf8Continuation
          ((value / 0x40) % 0x40)
          (Nat.mod_lt (value / 0x40) (by decide : 0 < 0x40))
        have lowContinued := continuation_utf8Continuation (value % 0x40)
          (Nat.mod_lt value (by decide : 0 < 0x40))
        simp [encodeUtf8Scalar, ascii, twoByte, threeByte,
          encodeUtf8Three, decodeUtf8Prefix, leadRange,
          leadNotAscii, leadNotTwo, middleContinued, lowContinued]
        exact decompositionThree
      · have quotientUpper : value / 0x40 / 0x40 / 0x40 < 5 := by
          simp only [Nat.div_div_eq_div_mul]
          exact Nat.div_lt_of_lt_mul
            (Nat.lt_of_le_of_lt maximum (by decide))
        have leadRange :
            0xf0 ≤ 0xf0 + value / 0x40 / 0x40 / 0x40 ∧
              0xf0 + value / 0x40 / 0x40 / 0x40 < 0xf5 :=
          ⟨Nat.le_add_right 0xf0 _, Nat.add_lt_add_left quotientUpper 0xf0⟩
        have leadNotAscii :
            ¬(0xf0 + value / 0x40 / 0x40 / 0x40 < 0x80) :=
          Nat.not_lt_of_ge (Nat.le_trans (by decide) (Nat.le_add_right 0xf0 _))
        have leadNotTwo : ¬(0xc2 ≤ 0xf0 + value / 0x40 / 0x40 / 0x40 ∧
            0xf0 + value / 0x40 / 0x40 / 0x40 < 0xe0) :=
          fun range => (Nat.not_lt_of_ge
            (Nat.le_trans (by decide) (Nat.le_add_right 0xf0 _))) range.2
        have leadNotThree : ¬(0xe0 ≤ 0xf0 + value / 0x40 / 0x40 / 0x40 ∧
            0xf0 + value / 0x40 / 0x40 / 0x40 < 0xf0) :=
          fun range => (Nat.not_lt_of_ge (Nat.le_add_right 0xf0 _)) range.2
        have highContinued := continuation_utf8Continuation
          ((value / 0x40 / 0x40) % 0x40)
          (Nat.mod_lt (value / 0x40 / 0x40) (by decide : 0 < 0x40))
        have middleContinued := continuation_utf8Continuation
          ((value / 0x40) % 0x40)
          (Nat.mod_lt (value / 0x40) (by decide : 0 < 0x40))
        have lowContinued := continuation_utf8Continuation (value % 0x40)
          (Nat.mod_lt value (by decide : 0 < 0x40))
        simp [encodeUtf8Scalar, ascii, twoByte, threeByte,
          encodeUtf8Four, decodeUtf8Prefix, maximum, leadRange,
          leadNotAscii, leadNotTwo, leadNotThree, highContinued,
          middleContinued, lowContinued]
        exact decompositionFour

/-- UTF-8 scalar encoding is injective on Unicode scalar values. -/
theorem utf8_scalar_inj {left right : CodePoint}
    (leftValid : IsUnicodeScalar left) (rightValid : IsUnicodeScalar right)
    (equal : encodeUtf8Scalar left = encodeUtf8Scalar right) :
    left = right := by
  have decoded := congrArg decodeUtf8Prefix equal
  have decodedEqual :
      some (left, ([] : ByteSeq)) = some (right, ([] : ByteSeq)) := by
    calc
      some (left, []) = decodeUtf8Prefix (encodeUtf8Scalar left) := by
        simpa using (decodeUtf8Prefix_encode left leftValid []).symm
      _ = decodeUtf8Prefix (encodeUtf8Scalar right) := decoded
      _ = some (right, []) := by
        simpa using decodeUtf8Prefix_encode right rightValid []
  exact congrArg Prod.fst (Option.some.inj decodedEqual)

/-- Concatenated UTF-8 encoding is injective for Unicode scalar sequences. -/
theorem utf8_encode_inj {left right : CodeSeq}
    (leftValid : CodeSeqValid left)
    (rightValid : CodeSeqValid right)
    (equal : utf8Encode left = utf8Encode right) :
    left = right := by
  induction left generalizing right with
  | nil =>
      cases right with
      | nil => rfl
      | cons rightHead rightTail =>
          have rightHeadValid := rightValid rightHead (by simp)
          have decoded := congrArg decodeUtf8Prefix equal
          simp only [utf8Encode, List.flatMap_nil, List.flatMap_cons] at equal
          simp only [utf8Encode, List.flatMap_nil, List.flatMap_cons] at decoded
          rw [decodeUtf8Prefix_encode rightHead rightHeadValid] at decoded
          simp [decodeUtf8Prefix] at decoded
  | cons leftHead leftTail ih =>
      cases right with
      | nil =>
          have leftHeadValid := leftValid leftHead (by simp)
          have decoded := congrArg decodeUtf8Prefix equal
          simp only [utf8Encode, List.flatMap_nil, List.flatMap_cons] at equal
          simp only [utf8Encode, List.flatMap_nil, List.flatMap_cons] at decoded
          rw [decodeUtf8Prefix_encode leftHead leftHeadValid] at decoded
          simp [decodeUtf8Prefix] at decoded
      | cons rightHead rightTail =>
          have leftHeadValid := leftValid leftHead (by simp)
          have rightHeadValid := rightValid rightHead (by simp)
          simp only [utf8Encode, List.flatMap_cons] at equal
          have decoded := congrArg decodeUtf8Prefix equal
          rw [decodeUtf8Prefix_encode leftHead leftHeadValid,
            decodeUtf8Prefix_encode rightHead rightHeadValid] at decoded
          have headsEqual : leftHead = rightHead := by
            exact congrArg Prod.fst (Option.some.inj decoded)
          cases headsEqual
          have tailsEqual : utf8Encode leftTail = utf8Encode rightTail := by
            exact List.append_cancel_left equal
          have leftTailValid : CodeSeqValid leftTail := by
            intro value member
            exact leftValid value (by simp [member])
          have rightTailValid : CodeSeqValid rightTail := by
            intro value member
            exact rightValid value (by simp [member])
          have tailValuesEqual := ih leftTailValid rightTailValid tailsEqual
          cases tailValuesEqual
          rfl

def renderHexDigit (digit : HexDigit) : CodePoint :=
  if digit.val < 10 then 48 + digit.val else 87 + digit.val

def renderDecimalDigit (digit : DecimalDigit) : CodePoint :=
  48 + digit.val

def renderInt (value : BoundedInt) : CodeSeq :=
  (if value.negative then [45] else []) ++ value.digits.map renderDecimalDigit

def escapeScalar : JScalar → CodeSeq
  | .literal value _ => [value]
  | .quote => [92, 34]
  | .reverseSolidus => [92, 92]
  | .backspace => [92, 98]
  | .tab => [92, 116]
  | .lineFeed => [92, 110]
  | .formFeed => [92, 102]
  | .carriageReturn => [92, 114]
  | .control high low _ =>
      [92, 117, 48, 48, renderHexDigit high, renderHexDigit low]

def escapeString (value : ScalarSeq) : CodeSeq :=
  value.flatMap escapeScalar

def escapeStringBytes (value : ScalarSeq) : ByteSeq :=
  utf8Encode (escapeString value)

private theorem ascii_valid {value : Nat} (upper : value < 0x80) :
    IsUnicodeScalar value := by
  simp only [IsUnicodeScalar]
  omega

private theorem renderHexDigit_valid (digit : HexDigit) :
    IsUnicodeScalar (renderHexDigit digit) := by
  unfold renderHexDigit
  split <;> apply ascii_valid <;> omega

theorem escapeScalar_valid (scalar : JScalar) :
    CodeSeqValid (escapeScalar scalar) := by
  intro code member
  cases scalar with
  | literal value valid =>
      simp only [escapeScalar, List.mem_cons, List.not_mem_nil, or_false] at member
      subst code
      exact valid.1
  | quote | reverseSolidus | backspace | tab | lineFeed | formFeed |
      carriageReturn =>
      simp only [escapeScalar, List.mem_cons, List.not_mem_nil, or_false] at member
      rcases member with rfl | rfl <;> decide
  | control high low valid =>
      simp only [escapeScalar, List.mem_cons, List.not_mem_nil, or_false] at member
      rcases member with rfl | rfl | rfl | rfl | codeHigh | codeLow
      · decide
      · decide
      · decide
      · decide
      · simpa [codeHigh] using renderHexDigit_valid high
      · simpa [codeLow] using renderHexDigit_valid low

theorem escapeString_valid (value : ScalarSeq) :
    CodeSeqValid (escapeString value) := by
  intro code member
  simp only [escapeString, List.mem_flatMap] at member
  rcases member with ⟨scalar, scalarMember, codeMember⟩
  exact escapeScalar_valid scalar code codeMember

inductive Token where
  | nullValue
  | trueValue
  | falseValue
  | integer (value : BoundedInt)
  | string (value : ScalarSeq)
  | leftBracket
  | rightBracket
  | leftBrace
  | rightBrace
  | comma
  | colon
  deriving DecidableEq

mutual
  def valueTokens : JValue → List Token
    | .null => [.nullValue]
    | .bool true => [.trueValue]
    | .bool false => [.falseValue]
    | .int value => [.integer value]
    | .str value => [.string value]
    | .arr values => .leftBracket :: arrayTokens values
    | .obj entries => .leftBrace :: objectTokens entries

  def arrayTokens : JArray → List Token
    | .nil => [.rightBracket]
    | .cons head .nil => valueTokens head ++ [.rightBracket]
    | .cons head tail@(.cons _ _) => valueTokens head ++ .comma :: arrayTokens tail

  def objectTokens : JObject → List Token
    | .nil => [.rightBrace]
    | .cons key value .nil =>
        .string key :: .colon :: valueTokens value ++ [.rightBrace]
    | .cons key value tail@(.cons _ _ _) =>
        .string key :: .colon :: valueTokens value ++ .comma :: objectTokens tail
end

def renderToken : Token → CodeSeq
  | .nullValue => [110, 117, 108, 108]
  | .trueValue => [116, 114, 117, 101]
  | .falseValue => [102, 97, 108, 115, 101]
  | .integer value => renderInt value
  | .string value => 34 :: escapeString value ++ [34]
  | .leftBracket => [91]
  | .rightBracket => [93]
  | .leftBrace => [123]
  | .rightBrace => [125]
  | .comma => [44]
  | .colon => [58]

def renderTokens (tokens : List Token) : CodeSeq :=
  tokens.flatMap renderToken

theorem renderInt_valid (value : BoundedInt) :
    CodeSeqValid (renderInt value) := by
  intro code member
  rcases value with ⟨negative, digits, valid⟩
  cases negative with
  | false =>
      have mapped : code ∈ digits.map renderDecimalDigit := by
        simpa [renderInt] using member
      rcases List.mem_map.mp mapped with ⟨digit, digitMember, rfl⟩
      apply ascii_valid
      simp [renderDecimalDigit]
      omega
  | true =>
      have mapped : code = 45 ∨ code ∈ digits.map renderDecimalDigit := by
        simpa [renderInt] using member
      rcases mapped with rfl | mapped
      · decide
      · rcases List.mem_map.mp mapped with ⟨digit, digitMember, rfl⟩
        apply ascii_valid
        simp [renderDecimalDigit]
        omega

theorem renderToken_valid (token : Token) :
    CodeSeqValid (renderToken token) := by
  cases token with
  | integer value => exact renderInt_valid value
  | string value =>
      intro code member
      simp only [renderToken, List.mem_cons, List.mem_append,
        List.not_mem_nil, or_false] at member
      rcases member with (rfl | escaped) | rfl
      · decide
      · exact escapeString_valid value code escaped
      · decide
  | nullValue => decide
  | trueValue => decide
  | falseValue => decide
  | leftBracket => decide
  | rightBracket => decide
  | leftBrace => decide
  | rightBrace => decide
  | comma => decide
  | colon => decide

theorem renderTokens_valid (tokens : List Token) :
    CodeSeqValid (renderTokens tokens) := by
  intro code member
  simp only [renderTokens, List.mem_flatMap] at member
  rcases member with ⟨token, tokenMember, codeMember⟩
  exact renderToken_valid token code codeMember

def canonicalCodePoints (value : JValue) : CodeSeq :=
  renderTokens (valueTokens value)

theorem canonicalCodePoints_valid (value : JValue) :
    CodeSeqValid (canonicalCodePoints value) :=
  renderTokens_valid (valueTokens value)

/-- Canonical RFC 8785 output bytes for the modeled value domain. -/
def canonical (value : JValue) : ByteSeq :=
  utf8Encode (canonicalCodePoints value)

end Chio.Json
