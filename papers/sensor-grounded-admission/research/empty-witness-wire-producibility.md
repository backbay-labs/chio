# Empty-Attestation Wire-Producibility of the Headline Degraded Witness

Research note N2, cycle 2, May 2026. Read-only check of whether the Lean proof's degraded witness is wire-producible under the §3 + §5 schema rules. Three sources are compared: the Lean proof's actual witness construction, the §3 substrate prose, and the §5 implementation prose.

## 1. The actual shape of the degraded witness

`lean/SensorGroundedAdmission.lean:241-246` defines:

```
/-- The degraded witness attestation: empty provider list. With a
    non-empty required set, this fails the coverage check. -/
def degradedWitness : SensorAttestation :=
  { providers := []
  , clock := witnessClock
  }
```

The witness is a `SensorAttestation` record with a literal empty list (`[]`) for the `providers` field and a `witnessClock` (capturedAt = 0, source = "", synchronized = true, uncertaintyMs = none). There is no degraded-flag provider record; there is no provider record at all.

The headline theorem (`lean/SensorGroundedAdmission.lean:350-378`) instantiates the degraded existential with exactly this object, and `not_requiredSetCovered_degradedWitness` (line 316-324) discharges the coverage failure by case-splitting on `decl.required`: nil is ruled out by the `decl.required ≠ []` hypothesis, cons goes through with `simp`. The body of the proof never references a degraded provider; it references the absence of any provider whose flags would match a required entry.

The paper's §4 prose at line 36 and §1 line 17 both describe the witness as "an empty attestation," "a healthy attestation listing one healthy record per required provider, and an empty attestation that fails coverage." §4's worked example at line 43 reinforces this: "the degraded witness pairs the identical $r$ with $A_d = [\,]$." The prose is consistent with the Lean: the degraded witness is a truly empty provider list.

## 2. The §3 schema requirements

`sections/03-substrate.tex:7` defines a sensor-state attestation as "a finite list of provider records." No emptiness floor is stated. The §3 paragraph at line 14 ("Required-set predicates") makes the required set a *constitution-level* field, not an attestation-level field; the attestation's content is independent of how many providers a constitution requires. The §3 paragraph at line 24 ("Ladder reading") states that partition-contingency mode is reached when "the attestation shows the attested-healthy providers are a strict subset of the constitution-required providers," with the strict-subset relation defined on the filter of the required entries through the attestation's providers list. The strict-subset of any non-empty list by the empty list is the canonical case of partition-contingency mode; the empty providers list is not just admissible under §3, it is the explicitly-named edge case the partition-contingency mode is designed to discriminate.

The §3 substrate prose neither requires the providers list to be non-empty nor distinguishes "sensor never installed" from "no provider records at all." Both are mapped onto the same admission outcome (coverage fails, partition-contingency mode active) when the constitution's required set is non-empty.

## 3. The §5 validator-rejection behavior

`sections/05-implementation.tex:7` describes the canonical-JSON encoding: "a `providers` array and a `clock` record." Each provider entry has eleven fields. No `minItems` constraint is named on the `providers` array; the entry list is "an array" with a "fixed key set" but no floor on length. The schema parser's failure modes, enumerated at line 16, are:

- `attestation_parse_failed` (the canonical-JSON object failed to parse as a sensor attestation, e.g., missing `providers` field, wrong key set, non-array `providers`).
- `required_set_uncovered` (the attestation parsed but the required-set coverage check returned false).
- `drop_count_exceeded`, `deadline_miss_exceeded` (per-provider count thresholds).
- `attestation_subject_digest_mismatch` (DSSE digest binding failed).

The §5 evaluator's failure mode `required_set_uncovered` is the *exact* code an empty-providers attestation discharges when the constitution's required set is non-empty: the parse succeeds (the array is well-formed, just empty), the coverage check returns false, the evaluator emits the typed denial. The empty-providers wire shape is structurally distinct from a malformed-providers wire shape; the former is admitted by the parser and rejected by the predicate, the latter is rejected by the parser before the predicate runs. §5 carries them as two separate denial codes.

The Rust implementation surface (`crates/chio-chiodos/src/lib.rs` and adjacent emitter sites) was not independently verified in this research note. The schema directory (`spec/schemas/chio-wire/`) was checked for a `minItems: 1` constraint on a `providers` array; many other Chio wire schemas carry that constraint, but no `sensor-state` or `endpoint-sensor-state` schema was located in the wire schemas tree under that exact name. Conclusion drawn from prose, not from implementation: under the §5 wire spec as written, the empty-providers attestation is wire-producible and the validator's denial path for it is the predicate-level `required_set_uncovered` code.

## 4. Verdict on the mismatch

(a) The Lean proof's degraded witness is a *literal empty provider list*: `providers := []`. Not a single-record list with all flags degraded; a list of length zero.

(b) The §3 + §5 schema *admits* the empty-providers attestation as a wire-producible message. The §3 prose does not require non-empty providers; the §5 evaluator's denial path enumerates a separate code (`required_set_uncovered`) that is the predicate-level rejection of an empty-providers attestation, distinct from the parse-level rejection of a malformed attestation.

(c) The cycle-1 adversarial review's claim ("the validator may reject empty attestations before the admission predicate evaluates them, so the structural-distinguishability claim narrows to two body-pairs where one is wire-unproducible") is *not supported* by the current paper text. Empty-providers attestations are admitted at the parse layer, rejected at the predicate layer, with a typed denial code that distinguishes them from malformed-attestation rejections.

The structural-distinguishability claim in the headline theorem therefore holds as written: two attestations sharing identical body bytes, both wire-producible, discharging the admission predicate to opposite verdicts.

## 5. Recommended fix path

No paper-prose fix is required for the structural-distinguishability claim itself. The adversarial finding's premise (empty-providers attestation is wire-unproducible) does not match the §3 / §5 prose. The recommendation has three pieces:

1. **No change to the Lean proof.** The degraded witness as `providers := []` is wire-producible under the current paper text. Changing it to a single-record list with all flags degraded would be a *stronger* witness but is not required to defeat the wire-producibility critique.

2. **Optional one-sentence §5 hardening.** Add to §5's "Failure modes" paragraph, after the `required_set_uncovered` enumeration: "An attestation with a syntactically valid but empty `providers` array passes the parser and discharges to `required_set_uncovered` whenever the constitution's required set is non-empty. The denial path is the predicate-level path, not the parse-level path; the empty-providers attestation is wire-producible by construction." This makes the witness's wire-producibility a load-bearing prose claim rather than an implicit one.

3. **Optional Lean strengthening (stretch).** A second degraded witness theorem could state that the construction also distinguishes against a *non-empty* degraded attestation, where the providers list contains records whose flags are not all healthy. Concretely: a witness `nonEmptyDegradedWitness decl := { providers := [degradedRecordFor e₀], clock := witnessClock }` where `e₀ = decl.required.head` and `degradedRecordFor` flips the `healthy` flag to `false`. This is a strictly stronger separation claim; the existing empty-list witness handles a more general case (no provider records at all), but the non-empty witness defends against the narrow critique that the headline depends on a degenerate empty-attestation case. If a reviewer pushes on the "trivial witness" angle, the second witness is the response; otherwise it is an unnecessary addition.

The verdict on (c) in the assignment: this is a *non-finding*. The wire-producibility critique misreads §5's failure-mode enumeration. The empty-providers attestation is wire-producible and the headline distinguishability survives. The §5 hardening is recommended for prose clarity, not for theorem soundness.

## 6. Bibkey stubs

No new citations required. The §5 wire-spec hardening cites the existing `rfc8785` canonical-JSON anchor and the in-paper §3 schema definitions. The optional Lean strengthening adds no new citations.

## Sources

- `papers/sensor-grounded-admission/lean/SensorGroundedAdmission.lean`, lines 241-246 (degraded witness), 350-378 (headline theorem), 316-324 (`not_requiredSetCovered_degradedWitness`).
- `papers/sensor-grounded-admission/sections/03-substrate.tex`, lines 7 (attestation = "a finite list of provider records"), 14 (required-set predicates), 24 (partition-contingency ladder reading).
- `papers/sensor-grounded-admission/sections/05-implementation.tex`, lines 7 (canonical-JSON encoding, `providers` array), 16 (denial codes including `attestation_parse_failed` and `required_set_uncovered` as separate paths).
- `papers/sensor-grounded-admission/sections/04-model.tex`, lines 34 (headline theorem statement), 36 (proof prose), 43 (worked example with `A_d = [\,]`).
- `papers/sensor-grounded-admission/sections/01-introduction.tex`, line 17 (contribution bullet describing "empty attestation that fails coverage").
- `papers/sensor-grounded-admission/sections/10-conclusion.tex`, line 6 (headline theorem prose describing the empty-attestation witness).
