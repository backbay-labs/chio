import Lean.Elab.Tactic.Omega
import Chio.Json.Canonical

/-!
# Canonical JSON injectivity

The proof has two independently checked layers. A lexer recovers canonical
tokens from rendered code points, and a deterministic grammar recovers the
modeled value from those tokens. The string and integer lexemes have separate
injectivity lemmas because their framing rules carry most of the lexical risk.
-/

set_option autoImplicit false

namespace Chio.Proofs

open Chio.Json

private def decodeHexDigit (code : CodePoint) : Option HexDigit :=
  if decimal : 48 ≤ code ∧ code ≤ 57 then
    some ⟨code - 48,
      Nat.lt_of_le_of_lt (Nat.sub_le_sub_right decimal.2 48) (by decide)⟩
  else if lower : 97 ≤ code ∧ code ≤ 102 then
    some ⟨code - 87,
      Nat.lt_of_le_of_lt (Nat.sub_le_sub_right lower.2 87) (by decide)⟩
  else
    none

private theorem decodeHexDigit_render (digit : HexDigit) :
    decodeHexDigit (renderHexDigit digit) = some digit := by
  by_cases small : digit.val < 10
  · have decimal : 48 ≤ 48 + digit.val ∧ 48 + digit.val ≤ 57 := by omega
    simp [renderHexDigit, small, decodeHexDigit, decimal]
  · have notDecimal : ¬(48 ≤ 87 + digit.val ∧ 87 + digit.val ≤ 57) := by
      omega
    have lower : 97 ≤ 87 + digit.val ∧ 87 + digit.val ≤ 102 := by
      omega
    simp [renderHexDigit, small, decodeHexDigit, notDecimal, lower]

private def prependDecoded (scalar : JScalar) :
    Option (ScalarSeq × CodeSeq) → Option (ScalarSeq × CodeSeq)
  | none => none
  | some (scalars, rest) => some (scalar :: scalars, rest)

private def decodeStringPrefix : CodeSeq → Option (ScalarSeq × CodeSeq)
  | [] => none
  | 34 :: rest => some ([], rest)
  | 92 :: 34 :: rest => prependDecoded .quote (decodeStringPrefix rest)
  | 92 :: 92 :: rest => prependDecoded .reverseSolidus (decodeStringPrefix rest)
  | 92 :: 98 :: rest => prependDecoded .backspace (decodeStringPrefix rest)
  | 92 :: 116 :: rest => prependDecoded .tab (decodeStringPrefix rest)
  | 92 :: 110 :: rest => prependDecoded .lineFeed (decodeStringPrefix rest)
  | 92 :: 102 :: rest => prependDecoded .formFeed (decodeStringPrefix rest)
  | 92 :: 114 :: rest => prependDecoded .carriageReturn (decodeStringPrefix rest)
  | 92 :: 117 :: 48 :: 48 :: highCode :: lowCode :: rest =>
      match decodeHexDigit highCode, decodeHexDigit lowCode with
      | some high, some low =>
          if valid : IsEscapedControl high low then
            prependDecoded (.control high low valid) (decodeStringPrefix rest)
          else
            none
      | _, _ => none
  | value :: rest =>
      if valid : IsLiteralScalar value then
        prependDecoded (.literal value valid) (decodeStringPrefix rest)
      else
        none

private theorem decodeStringPrefix_roundtrip
    (scalars : ScalarSeq) (rest : CodeSeq) :
    decodeStringPrefix (escapeString scalars ++ 34 :: rest) =
      some (scalars, rest) := by
  induction scalars with
  | nil => rfl
  | cons scalar tail ih =>
      cases scalar with
      | literal value valid =>
          have notQuote : value ≠ 34 := valid.2.1
          have notReverseSolidus : value ≠ 92 := valid.2.2.1
          simp only [escapeString] at ih
          simp [escapeString, escapeScalar, decodeStringPrefix,
            prependDecoded, valid, ih, notQuote, notReverseSolidus]
      | quote | reverseSolidus | backspace | tab | lineFeed | formFeed |
          carriageReturn =>
          simp_all [escapeString, escapeScalar, decodeStringPrefix,
            prependDecoded]
      | control high low valid =>
          simp only [escapeString] at ih
          simp only [escapeString, List.flatMap_cons, escapeScalar,
            List.append_assoc]
          simp [decodeStringPrefix, prependDecoded, decodeHexDigit_render,
            valid, ih]

private theorem escapeCodePoints_inj {left right : ScalarSeq}
    (equal : escapeString left = escapeString right) :
    left = right := by
  have decoded := congrArg decodeStringPrefix
    (congrArg (fun value => value ++ [34]) equal)
  simpa [decodeStringPrefix_roundtrip] using decoded

/-- Canonical string escaping is injective at the UTF-8 byte boundary. -/
theorem escape_string_inj {left right : ScalarSeq}
    (equal : escapeStringBytes left = escapeStringBytes right) :
    left = right := by
  apply escapeCodePoints_inj
  apply utf8_encode_inj (escapeString_valid left) (escapeString_valid right)
  simpa [escapeStringBytes] using equal

#print axioms escape_string_inj

private theorem renderDecimalDigit_inj {left right : DecimalDigit}
    (equal : renderDecimalDigit left = renderDecimalDigit right) :
    left = right := by
  apply Fin.ext
  unfold renderDecimalDigit at equal
  exact Nat.add_left_cancel equal

private theorem renderDigits_inj {left right : List DecimalDigit}
    (equal : left.map renderDecimalDigit = right.map renderDecimalDigit) :
    left = right := by
  exact (List.map_inj_right fun _ _ itemEqual =>
    renderDecimalDigit_inj itemEqual).mp equal

/-- Canonical signed-decimal rendering is injective on the bounded range. -/
theorem render_int_inj {left right : BoundedInt}
    (equal : renderInt left = renderInt right) :
    left = right := by
  rcases left with ⟨leftNegative, leftDigits, leftValid⟩
  rcases right with ⟨rightNegative, rightDigits, rightValid⟩
  cases leftNegative <;> cases rightNegative
  · have digitsEqual : leftDigits = rightDigits := by
      apply renderDigits_inj
      simpa [renderInt] using equal
    cases digitsEqual
    rfl
  · rcases leftValid with ⟨leftNonempty, _⟩
    cases leftDigits with
    | nil => exact (leftNonempty rfl).elim
    | cons digit tail =>
        have headEqual := congrArg List.head? equal
        have impossible : 48 + digit.val ≠ 45 :=
          Nat.ne_of_gt (Nat.lt_of_lt_of_le (by decide)
            (Nat.le_add_right 48 digit.val))
        exfalso
        apply impossible
        exact Option.some.inj (by simpa [renderInt, renderDecimalDigit] using headEqual)
  · rcases rightValid with ⟨rightNonempty, _⟩
    cases rightDigits with
    | nil => exact (rightNonempty rfl).elim
    | cons digit tail =>
        have headEqual := congrArg List.head? equal
        have impossible : 48 + digit.val ≠ 45 :=
          Nat.ne_of_gt (Nat.lt_of_lt_of_le (by decide)
            (Nat.le_add_right 48 digit.val))
        exfalso
        apply impossible
        exact Option.some.inj
          (by simpa [renderInt, renderDecimalDigit] using headEqual.symm)
  · have digitsEqual : leftDigits = rightDigits := by
      apply renderDigits_inj
      simpa [renderInt] using equal
    cases digitsEqual
    rfl

#print axioms render_int_inj

private def decodeDecimalDigit (code : CodePoint) : Option DecimalDigit :=
  if valid : 48 ≤ code ∧ code ≤ 57 then
    some ⟨code - 48,
      Nat.lt_of_le_of_lt (Nat.sub_le_sub_right valid.2 48) (by decide)⟩
  else
    none

private theorem decodeDecimalDigit_render (digit : DecimalDigit) :
    decodeDecimalDigit (renderDecimalDigit digit) = some digit := by
  have valid : 48 ≤ 48 + digit.val ∧ 48 + digit.val ≤ 57 := by
    exact ⟨Nat.le_add_right 48 digit.val,
      Nat.add_le_add_left (Nat.le_pred_of_lt digit.isLt) 48⟩
  simp [decodeDecimalDigit, renderDecimalDigit, valid]

private def decodeDigitsPrefix : CodeSeq → List DecimalDigit × CodeSeq
  | [] => ([], [])
  | code :: rest =>
      match decodeDecimalDigit code with
      | none => ([], code :: rest)
      | some digit =>
          let decoded := decodeDigitsPrefix rest
          (digit :: decoded.1, decoded.2)

private def DecimalBoundary : CodeSeq → Prop
  | [] => True
  | code :: _ => code < 48 ∨ 57 < code

private instance (value : CodeSeq) : Decidable (DecimalBoundary value) := by
  cases value <;> simp [DecimalBoundary] <;> infer_instance

private theorem decodeDigitsPrefix_boundary {rest : CodeSeq}
    (boundary : DecimalBoundary rest) :
    decodeDigitsPrefix rest = ([], rest) := by
  cases rest with
  | nil => rfl
  | cons code tail =>
      unfold DecimalBoundary at boundary
      have invalid : ¬(48 ≤ code ∧ code ≤ 57) := by
        intro range
        rcases boundary with lower | upper
        · exact (Nat.not_lt_of_ge range.1) lower
        · exact (Nat.not_lt_of_ge range.2) upper
      simp [decodeDigitsPrefix, decodeDecimalDigit, invalid]

private theorem decodeDigitsPrefix_render
    (digits : List DecimalDigit) (rest : CodeSeq)
    (boundary : DecimalBoundary rest) :
    decodeDigitsPrefix (digits.map renderDecimalDigit ++ rest) =
      (digits, rest) := by
  induction digits with
  | nil => simpa using decodeDigitsPrefix_boundary boundary
  | cons digit tail ih =>
      simp [decodeDigitsPrefix, decodeDecimalDigit_render, ih]

private def splitIntegerSign : CodeSeq → Bool × CodeSeq
  | 45 :: rest => (true, rest)
  | input => (false, input)

private theorem splitIntegerSign_decimal (digit : DecimalDigit)
    (rest : CodeSeq) :
    splitIntegerSign (renderDecimalDigit digit :: rest) =
      (false, renderDecimalDigit digit :: rest) := by
  have notMinus : renderDecimalDigit digit ≠ 45 := by
    unfold renderDecimalDigit
    exact Nat.ne_of_gt (Nat.lt_of_lt_of_le (by decide)
      (Nat.le_add_right 48 digit.val))
  simp [splitIntegerSign, notMinus]

private def decodeIntegerPrefix (input : CodeSeq) :
    Option (BoundedInt × CodeSeq) :=
  let (negative, digitsInput) := splitIntegerSign input
  let decoded := decodeDigitsPrefix digitsInput
  if valid : CanonicalInteger negative decoded.1 then
    some ({ negative, digits := decoded.1, valid }, decoded.2)
  else
    none

private theorem decodeIntegerPrefix_render
    (value : BoundedInt) (rest : CodeSeq)
    (boundary : DecimalBoundary rest) :
    decodeIntegerPrefix (renderInt value ++ rest) = some (value, rest) := by
  rcases value with ⟨negative, digits, valid⟩
  cases negative with
  | false =>
      rcases valid with ⟨nonempty, valid⟩
      cases digits with
      | nil => exact (nonempty rfl).elim
      | cons digit tail =>
          have notMinus : renderDecimalDigit digit ≠ 45 := by
            unfold renderDecimalDigit
            exact Nat.ne_of_gt (Nat.lt_of_lt_of_le (by decide)
              (Nat.le_add_right 48 digit.val))
          simp only [decodeIntegerPrefix, renderInt, Bool.false_eq_true,
            ↓reduceIte, List.nil_append, List.map]
          simp [splitIntegerSign_decimal]
          have decoded := decodeDigitsPrefix_render (digit :: tail) rest boundary
          simp only [List.map] at decoded
          have decodedExact :
              decodeDigitsPrefix
                (renderDecimalDigit digit :: (tail.map renderDecimalDigit ++ rest)) =
                (digit :: tail, rest) := by simpa using decoded
          constructor
          · exact congrArg Prod.fst decodedExact
          · constructor
            · rw [congrArg Prod.fst decodedExact]
              exact ⟨nonempty, valid⟩
            · exact congrArg Prod.snd decodedExact
  | true =>
      simp only [decodeIntegerPrefix, renderInt, ↓reduceIte, List.cons_append,
        splitIntegerSign]
      simp only [List.nil_append]
      have decoded := decodeDigitsPrefix_render digits rest boundary
      simp [decoded, valid]

private def lexOne : CodeSeq → Option (Token × CodeSeq)
  | [] => none
  | 110 :: 117 :: 108 :: 108 :: rest => some (.nullValue, rest)
  | 116 :: 114 :: 117 :: 101 :: rest => some (.trueValue, rest)
  | 102 :: 97 :: 108 :: 115 :: 101 :: rest => some (.falseValue, rest)
  | 34 :: rest =>
      match decodeStringPrefix rest with
      | some (value, remaining) => some (.string value, remaining)
      | none => none
  | input@(45 :: _) =>
      match decodeIntegerPrefix input with
      | some (value, remaining) => some (.integer value, remaining)
      | none => none
  | input@(code :: _) =>
      if digit : 48 ≤ code ∧ code ≤ 57 then
        match decodeIntegerPrefix input with
        | some (value, remaining) => some (.integer value, remaining)
        | none => none
      else
        match code, input with
        | 91, _ :: rest => some (.leftBracket, rest)
        | 93, _ :: rest => some (.rightBracket, rest)
        | 123, _ :: rest => some (.leftBrace, rest)
        | 125, _ :: rest => some (.rightBrace, rest)
        | 44, _ :: rest => some (.comma, rest)
        | 58, _ :: rest => some (.colon, rest)
        | _, _ => none

private def Lexable : List Token → Prop
  | [] => True
  | .integer _ :: tail => DecimalBoundary (renderTokens tail) ∧ Lexable tail
  | _ :: tail => Lexable tail

private theorem Lexable.tail {token : Token} {tail : List Token}
    (lexable : Lexable (token :: tail)) : Lexable tail := by
  cases token with
  | integer value => exact lexable.2
  | nullValue | trueValue | falseValue | string | leftBracket | rightBracket |
      leftBrace | rightBrace | comma | colon => exact lexable

private theorem Lexable.boundary {token : Token} {tail : List Token}
    (lexable : Lexable (token :: tail)) :
    match token with
    | .integer _ => DecimalBoundary (renderTokens tail)
    | _ => True := by
  cases token with
  | integer value => exact lexable.1
  | nullValue | trueValue | falseValue | string | leftBracket | rightBracket |
      leftBrace | rightBrace | comma | colon => trivial

private theorem lexOne_renderToken
    (token : Token) (tail : List Token)
    (boundary : match token with
      | .integer _ => DecimalBoundary (renderTokens tail)
      | _ => True) :
    lexOne (renderToken token ++ renderTokens tail) =
      some (token, renderTokens tail) := by
  cases token with
  | integer value =>
      have decoded := decodeIntegerPrefix_render value (renderTokens tail) boundary
      rcases value with ⟨negative, digits, valid⟩
      cases negative with
      | true =>
          have decodedExpanded : decodeIntegerPrefix
              (45 :: (digits.map renderDecimalDigit ++ renderTokens tail)) =
              some ({ negative := true, digits, valid }, renderTokens tail) := by
            simpa [renderInt] using decoded
          simp [renderToken, renderInt, lexOne, decodedExpanded]
      | false =>
          rcases valid with ⟨nonempty, valid⟩
          cases digits with
          | nil => exact (nonempty rfl).elim
          | cons digit digits =>
              have digitRange : 48 ≤ renderDecimalDigit digit ∧
                  renderDecimalDigit digit ≤ 57 := by
                unfold renderDecimalDigit
                exact ⟨Nat.le_add_right 48 digit.val,
                  Nat.add_le_add_left (Nat.le_pred_of_lt digit.isLt) 48⟩
              have notNull : renderDecimalDigit digit ≠ 110 :=
                Nat.ne_of_lt (Nat.lt_of_le_of_lt digitRange.2 (by decide))
              have notTrue : renderDecimalDigit digit ≠ 116 :=
                Nat.ne_of_lt (Nat.lt_of_le_of_lt digitRange.2 (by decide))
              have notFalse : renderDecimalDigit digit ≠ 102 :=
                Nat.ne_of_lt (Nat.lt_of_le_of_lt digitRange.2 (by decide))
              have notQuote : renderDecimalDigit digit ≠ 34 :=
                Nat.ne_of_gt (Nat.lt_of_lt_of_le (by decide) digitRange.1)
              have notMinus : renderDecimalDigit digit ≠ 45 :=
                Nat.ne_of_gt (Nat.lt_of_lt_of_le (by decide) digitRange.1)
              let number : BoundedInt :=
                ⟨false, digit :: digits, ⟨nonempty, valid⟩⟩
              have decodedExpanded : decodeIntegerPrefix
                  (renderDecimalDigit digit ::
                    (digits.map renderDecimalDigit ++ renderTokens tail)) =
                  some (number, renderTokens tail) := by
                simpa [number, renderInt] using decoded
              simp [renderToken, renderInt, lexOne, digitRange, notNull,
                notTrue, notFalse, notQuote, notMinus, number, decodedExpanded]
  | nullValue | trueValue | falseValue | string | leftBracket | rightBracket |
      leftBrace | rightBrace | comma | colon =>
      simp_all [lexOne, renderToken, decodeStringPrefix_roundtrip,
        DecimalBoundary]

private def tokenizeFuel : Nat → CodeSeq → Option (List Token)
  | 0, _ => none
  | _ + 1, [] => some []
  | fuel + 1, input =>
      match lexOne input with
      | none => none
      | some (token, rest) =>
          match tokenizeFuel fuel rest with
          | none => none
          | some tail => some (token :: tail)

private theorem tokenizeFuel_step (fuel : Nat) (input rest : CodeSeq)
    (token : Token) (tail : List Token)
    (headDecoded : lexOne input = some (token, rest))
    (tailDecoded : tokenizeFuel fuel rest = some tail) :
    tokenizeFuel (fuel + 1) input = some (token :: tail) := by
  cases input with
  | nil => simp [lexOne] at headDecoded
  | cons head remaining => simp [tokenizeFuel, headDecoded, tailDecoded]

private theorem tokenizeFuel_renderTokens
    (tokens : List Token) (lexable : Lexable tokens)
    (fuel : Nat) (enough : tokens.length < fuel) :
    tokenizeFuel fuel (renderTokens tokens) = some tokens := by
  induction tokens generalizing fuel with
  | nil =>
      cases fuel with
      | zero => omega
      | succ remaining => simp [tokenizeFuel, renderTokens]
  | cons token tail ih =>
      cases fuel with
      | zero => omega
      | succ remaining =>
          have tailEnough : tail.length < remaining := by
            exact Nat.lt_of_succ_lt_succ (by simpa using enough)
          have tailLexable : Lexable tail := by
            cases token <;> simp_all [Lexable]
          have headDecoded := lexOne_renderToken token tail (by
            cases token <;> simp_all [Lexable])
          have tailDecoded := ih tailLexable remaining tailEnough
          exact tokenizeFuel_step remaining
            (renderToken token ++ renderTokens tail) (renderTokens tail)
            token tail headDecoded tailDecoded

private theorem renderTokens_inj
    {left right : List Token}
    (leftLexable : Lexable left) (rightLexable : Lexable right)
    (equal : renderTokens left = renderTokens right) :
    left = right := by
  let fuel := Nat.max left.length right.length + 1
  have leftEnough : left.length < fuel := by
    unfold fuel
    exact Nat.lt_succ_of_le (Nat.le_max_left _ _)
  have rightEnough : right.length < fuel := by
    unfold fuel
    exact Nat.lt_succ_of_le (Nat.le_max_right _ _)
  have leftDecoded := tokenizeFuel_renderTokens left leftLexable fuel leftEnough
  have rightDecoded := tokenizeFuel_renderTokens right rightLexable fuel rightEnough
  rw [equal] at leftDecoded
  rw [rightDecoded] at leftDecoded
  exact Option.some.inj leftDecoded.symm

mutual
  private theorem valueTokens_lexable_append
      (value : JValue) (suffix : List Token)
      (boundary : DecimalBoundary (renderTokens suffix))
      (suffixLexable : Lexable suffix) :
      Lexable (valueTokens value ++ suffix) := by
    cases value with
    | null => simpa [valueTokens, Lexable] using suffixLexable
    | bool flag =>
        cases flag <;> simpa [valueTokens, Lexable] using suffixLexable
    | str text => simpa [valueTokens, Lexable] using suffixLexable
    | int number => simp [valueTokens, Lexable, boundary, suffixLexable]
    | arr values =>
        simpa [valueTokens, Lexable] using
          arrayTokens_lexable_append values suffix boundary suffixLexable
    | obj entries =>
        simpa [valueTokens, Lexable] using
          objectTokens_lexable_append entries suffix boundary suffixLexable

  private theorem arrayTokens_lexable_append
      (values : JArray) (suffix : List Token)
      (boundary : DecimalBoundary (renderTokens suffix))
      (suffixLexable : Lexable suffix) :
      Lexable (arrayTokens values ++ suffix) := by
    cases values with
    | nil => simpa [arrayTokens, Lexable] using suffixLexable
    | cons head tail =>
        cases tail with
        | nil =>
            have result := valueTokens_lexable_append head
              (.rightBracket :: suffix)
              (by simp [renderTokens, renderToken, DecimalBoundary])
              (by simpa [Lexable] using suffixLexable)
            simpa [arrayTokens, List.append_assoc] using result
        | cons next remaining =>
            let tail := JArray.cons next remaining
            have result := valueTokens_lexable_append head
              (.comma :: arrayTokens tail ++ suffix)
              (by simp [renderTokens, renderToken, DecimalBoundary])
              (by simpa [Lexable] using
                arrayTokens_lexable_append tail suffix boundary suffixLexable)
            simpa [arrayTokens, tail, List.append_assoc] using result

  private theorem objectTokens_lexable_append
      (entries : JObject) (suffix : List Token)
      (boundary : DecimalBoundary (renderTokens suffix))
      (suffixLexable : Lexable suffix) :
      Lexable (objectTokens entries ++ suffix) := by
    cases entries with
    | nil => simpa [objectTokens, Lexable] using suffixLexable
    | cons key value tail =>
        cases tail with
        | nil =>
            have result := valueTokens_lexable_append value
              (.rightBrace :: suffix)
              (by simp [renderTokens, renderToken, DecimalBoundary])
              (by simpa [Lexable] using suffixLexable)
            simpa [objectTokens, List.append_assoc] using result
        | cons nextKey nextValue remaining =>
            let tail := JObject.cons nextKey nextValue remaining
            have result := valueTokens_lexable_append value
              (.comma :: objectTokens tail ++ suffix)
              (by simp [renderTokens, renderToken, DecimalBoundary])
              (by simpa [Lexable] using
                objectTokens_lexable_append tail suffix boundary suffixLexable)
            simpa [objectTokens, tail, List.append_assoc] using result
end

private theorem valueTokens_lexable (value : JValue) :
    Lexable (valueTokens value) := by
  simpa using valueTokens_lexable_append value []
    (by simp [renderTokens, DecimalBoundary]) (by simp [Lexable])

private structure ParserBundle where
  value : List Token → Option (JValue × List Token)
  array : List Token → Option (JArray × List Token)
  object : List Token → Option (JObject × List Token)

private def parserBundle : Nat → ParserBundle
  | 0 =>
      { value := fun _ => none
        array := fun _ => none
        object := fun _ => none }
  | fuel + 1 =>
      let previous := parserBundle fuel
      { value := fun input =>
          match input with
          | .nullValue :: rest => some (.null, rest)
          | .trueValue :: rest => some (.bool true, rest)
          | .falseValue :: rest => some (.bool false, rest)
          | .integer value :: rest => some (.int value, rest)
          | .string value :: rest => some (.str value, rest)
          | .leftBracket :: rest =>
              match previous.array rest with
              | some (values, remaining) => some (.arr values, remaining)
              | none => none
          | .leftBrace :: rest =>
              match previous.object rest with
              | some (entries, remaining) => some (.obj entries, remaining)
              | none => none
          | _ => none
        array := fun input =>
          match previous.value input with
          | some (value, .rightBracket :: rest) => some (.cons value .nil, rest)
          | some (value, .comma :: middle) =>
              match previous.array middle with
              | some (tail, rest) => some (.cons value tail, rest)
              | none => none
          | _ =>
              match input with
              | .rightBracket :: rest => some (.nil, rest)
              | _ => none
        object := fun input =>
          match input with
          | .rightBrace :: rest => some (.nil, rest)
          | .string key :: .colon :: remaining =>
              match previous.value remaining with
              | some (value, .rightBrace :: rest) => some (.cons key value .nil, rest)
              | some (value, .comma :: middle) =>
                  match previous.object middle with
                  | some (tail, rest) => some (.cons key value tail, rest)
                  | none => none
              | _ => none
          | _ => none }

private def parseValue (fuel : Nat) (input : List Token) :
    Option (JValue × List Token) :=
  (parserBundle fuel).value input

private def parseArray (fuel : Nat) (input : List Token) :
    Option (JArray × List Token) :=
  (parserBundle fuel).array input

private def parseObject (fuel : Nat) (input : List Token) :
    Option (JObject × List Token) :=
  (parserBundle fuel).object input

private theorem parseValue_rightBracket (fuel : Nat) (rest : List Token) :
    parseValue fuel (.rightBracket :: rest) = none := by
  cases fuel <;> simp [parseValue, parserBundle]

mutual
  private def valueFuel : JValue → Nat
    | .arr values => arrayFuel values + 1
    | .obj entries => objectFuel entries + 1
    | _ => 1

  private def arrayFuel : JArray → Nat
    | .nil => 1
    | .cons head tail => Nat.max (valueFuel head) (arrayFuel tail) + 1

  private def objectFuel : JObject → Nat
    | .nil => 1
    | .cons _ value tail => Nat.max (valueFuel value) (objectFuel tail) + 1
end

private theorem parseValue_null_step (fuel : Nat) (rest : List Token) :
    parseValue (fuel + 1) (valueTokens .null ++ rest) = some (.null, rest) := by
  simp [valueTokens, parseValue, parserBundle]

private theorem parseValue_int_step (fuel : Nat) (number : BoundedInt)
    (rest : List Token) :
    parseValue (fuel + 1) (valueTokens (.int number) ++ rest) =
      some (.int number, rest) := by
  simp [valueTokens, parseValue, parserBundle]

private theorem parseValue_str_step (fuel : Nat) (value : ScalarSeq)
    (rest : List Token) :
    parseValue (fuel + 1) (valueTokens (.str value) ++ rest) =
      some (.str value, rest) := by
  simp [valueTokens, parseValue, parserBundle]

private theorem parseValue_bool_step (fuel : Nat) (value : Bool)
    (rest : List Token) :
    parseValue (fuel + 1) (valueTokens (.bool value) ++ rest) =
      some (.bool value, rest) := by
  cases value <;>
    simp [valueTokens, parseValue, parserBundle]

private theorem parse_roundtrip (fuel : Nat) :
    (∀ (value : JValue) (rest : List Token), valueFuel value ≤ fuel →
      parseValue fuel (valueTokens value ++ rest) = some (value, rest)) ∧
    (∀ (values : JArray) (rest : List Token), arrayFuel values ≤ fuel →
      parseArray fuel (arrayTokens values ++ rest) = some (values, rest)) ∧
    (∀ (entries : JObject) (rest : List Token), objectFuel entries ≤ fuel →
      parseObject fuel (objectTokens entries ++ rest) = some (entries, rest)) := by
  induction fuel with
  | zero =>
      constructor
      · intro value rest enough
        cases value <;> simp [valueFuel] at enough
      constructor
      · intro values rest enough
        cases values <;> simp [arrayFuel] at enough
      · intro entries rest enough
        cases entries <;> simp [objectFuel] at enough
  | succ remaining ih =>
      rcases ih with ⟨valueIH, arrayIH, objectIH⟩
      constructor
      · intro value rest enough
        cases value with
        | null =>
            exact parseValue_null_step remaining rest
        | int number =>
            exact parseValue_int_step remaining number rest
        | str text =>
            exact parseValue_str_step remaining text rest
        | bool flag =>
            exact parseValue_bool_step remaining flag rest
        | arr values =>
            have childEnough : arrayFuel values ≤ remaining := by
              simpa [valueFuel] using enough
            have parsedArray : (parserBundle remaining).array
                (arrayTokens values ++ rest) = some (values, rest) := by
              simpa only [parseArray] using arrayIH values rest childEnough
            simp [valueTokens, parseValue, parserBundle, parsedArray]
        | obj entries =>
            have childEnough : objectFuel entries ≤ remaining := by
              simpa [valueFuel] using enough
            have parsedObject : (parserBundle remaining).object
                (objectTokens entries ++ rest) = some (entries, rest) := by
              simpa only [parseObject] using objectIH entries rest childEnough
            simp [valueTokens, parseValue, parserBundle, parsedObject]
      constructor
      · intro values rest enough
        cases values with
        | nil =>
            have parsedNone : (parserBundle remaining).value
                (.rightBracket :: rest) = none := by
              simpa only [parseValue] using parseValue_rightBracket remaining rest
            simp [parseArray, parserBundle, arrayTokens, parsedNone]
        | cons head tail =>
            have combined : Nat.max (valueFuel head) (arrayFuel tail) ≤ remaining := by
              simpa [arrayFuel] using enough
            have headEnough := Nat.le_trans (Nat.le_max_left _ _) combined
            have tailEnough := Nat.le_trans (Nat.le_max_right _ _) combined
            cases tail with
            | nil =>
                simp only [arrayTokens, parseArray]
                have parsedHead := valueIH head
                  (.rightBracket :: rest) headEnough
                have parsedHeadRaw : (parserBundle remaining).value
                    (valueTokens head ++ (.rightBracket :: rest)) =
                    some (head, .rightBracket :: rest) := by
                  simpa only [parseValue] using parsedHead
                rw [show valueTokens head ++ [Token.rightBracket] ++ rest =
                  valueTokens head ++ (Token.rightBracket :: rest) by
                    simp [List.append_assoc]]
                simp [parserBundle, parsedHeadRaw]
            | cons next remainingTail =>
                let tail := JArray.cons next remainingTail
                simp only [arrayTokens, parseArray]
                have parsedHead := valueIH head
                  (.comma :: (arrayTokens tail ++ rest)) headEnough
                have parsedHeadRaw : (parserBundle remaining).value
                    (valueTokens head ++ (.comma :: (arrayTokens tail ++ rest))) =
                    some (head, .comma :: (arrayTokens tail ++ rest)) := by
                  simpa only [parseValue] using parsedHead
                have parsedTailRaw : (parserBundle remaining).array
                    (arrayTokens tail ++ rest) = some (tail, rest) := by
                  simpa only [parseArray] using arrayIH tail rest tailEnough
                rw [show valueTokens head ++ Token.comma :: arrayTokens tail ++ rest =
                  valueTokens head ++ (.comma :: arrayTokens tail ++ rest) by
                    simp [List.append_assoc]]
                simp [parserBundle, parsedHeadRaw, parsedTailRaw]
                rfl
      · intro entries rest enough
        cases entries with
        | nil =>
            simp [parseObject, parserBundle, objectTokens]
        | cons key value tail =>
            have combined : Nat.max (valueFuel value) (objectFuel tail) ≤ remaining := by
              simpa [objectFuel] using enough
            have valueEnough := Nat.le_trans (Nat.le_max_left _ _) combined
            have tailEnough := Nat.le_trans (Nat.le_max_right _ _) combined
            cases tail with
            | nil =>
                simp only [objectTokens]
                have parsedValue := valueIH value
                  (.rightBrace :: rest) valueEnough
                have parsedValueRaw : (parserBundle remaining).value
                    (valueTokens value ++ (.rightBrace :: rest)) =
                    some (value, .rightBrace :: rest) := by
                  simpa only [parseValue] using parsedValue
                rw [show Token.string key :: Token.colon :: valueTokens value ++
                    [Token.rightBrace] ++ rest =
                    Token.string key :: Token.colon ::
                      (valueTokens value ++ (Token.rightBrace :: rest)) by
                  simp [List.append_assoc]]
                simp [parseObject, parserBundle, parsedValueRaw]
            | cons nextKey nextValue remainingTail =>
                let tail := JObject.cons nextKey nextValue remainingTail
                simp only [objectTokens]
                have parsedValue := valueIH value
                  (.comma :: (objectTokens tail ++ rest)) valueEnough
                have parsedTail := objectIH tail rest tailEnough
                have parsedValueRaw : (parserBundle remaining).value
                    (valueTokens value ++ (.comma :: (objectTokens tail ++ rest))) =
                    some (value, .comma :: (objectTokens tail ++ rest)) := by
                  simpa only [parseValue] using parsedValue
                have parsedTailRaw : (parserBundle remaining).object
                    (objectTokens tail ++ rest) = some (tail, rest) := by
                  simpa only [parseObject] using parsedTail
                rw [show Token.string key :: Token.colon :: valueTokens value ++
                    Token.comma :: objectTokens tail ++ rest =
                    Token.string key :: Token.colon ::
                      (valueTokens value ++
                        (Token.comma :: objectTokens tail ++ rest)) by
                  simp [List.append_assoc]]
                simp [parseObject, parserBundle, parsedValueRaw, parsedTailRaw]
                rfl

private theorem parseValue_roundtrip (value : JValue) (rest : List Token)
    (fuel : Nat) (enough : valueFuel value ≤ fuel) :
    parseValue fuel (valueTokens value ++ rest) = some (value, rest) :=
  (parse_roundtrip fuel).1 value rest enough

private theorem parseArray_roundtrip (values : JArray) (rest : List Token)
    (fuel : Nat) (enough : arrayFuel values ≤ fuel) :
    parseArray fuel (arrayTokens values ++ rest) = some (values, rest) :=
  (parse_roundtrip fuel).2.1 values rest enough

private theorem parseObject_roundtrip (entries : JObject) (rest : List Token)
    (fuel : Nat) (enough : objectFuel entries ≤ fuel) :
    parseObject fuel (objectTokens entries ++ rest) = some (entries, rest) :=
  (parse_roundtrip fuel).2.2 entries rest enough

private theorem valueTokens_inj {left right : JValue}
    (equal : valueTokens left = valueTokens right) :
    left = right := by
  let fuel := Nat.max (valueFuel left) (valueFuel right)
  have leftParsed := parseValue_roundtrip left [] fuel (Nat.le_max_left _ _)
  have rightParsed := parseValue_roundtrip right [] fuel (Nat.le_max_right _ _)
  rw [equal, rightParsed] at leftParsed
  exact (congrArg Prod.fst (Option.some.inj leftParsed)).symm

/-- Canonical rendering is injective on normalized scalar and integer leaves. -/
theorem canonical_inj {left right : JValue}
    (equal : canonical left = canonical right) :
    left = right := by
  have codePointsEqual : canonicalCodePoints left = canonicalCodePoints right := by
    apply utf8_encode_inj (canonicalCodePoints_valid left)
      (canonicalCodePoints_valid right)
    simpa [canonical] using equal
  apply valueTokens_inj
  apply renderTokens_inj (valueTokens_lexable left) (valueTokens_lexable right)
  simpa [canonicalCodePoints] using codePointsEqual

#print axioms canonical_inj

/-- Sorted object entries are determined by their canonical object rendering. -/
theorem sorted_assoc_ext
    {left right : JObject}
    (_leftSorted : SortedObject left) (_rightSorted : SortedObject right)
    (equal : canonical (.obj left) = canonical (.obj right)) :
    left = right := by
  have valuesEqual := canonical_inj equal
  cases valuesEqual
  rfl

#print axioms sorted_assoc_ext

end Chio.Proofs
