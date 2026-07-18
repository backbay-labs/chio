# FV-C3: Mechanize canonical-JSON injectivity and shrink the single axiom

- Status: Implemented (2026-07-12)
- Theme: C - Turn verification into product surface
- Effort: M-L
- Depends on: none
- Feeds: shrinks the sole Lean axiom to a pure crypto assumption; narrows ASSUME-CANONICAL-JSON; strengthens the receipt-id story consumed by [FV-C2](FV-C2-verified-inclusion-verifier.md) and [FV-C1](FV-C1-receipt-trace-validation.md)
- Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G2), [FV-A4](FV-A4-mirror-drift-hashes.md), [FV-E1](FV-E1-spec-mutation-testing.md)

## Summary

The verified core previously carried one Lean axiom, `receipt_id_collision_resistant`, asserting that equal receipt ids imply equal content and policy hashes. That axiom conflated two different things: a software property (canonical serialization is injective on its modeled domain) and a cryptographic property (SHA-256 collision resistance). FV-C3 mechanizes the software half with normalized JSON values whose integer and scalar leaves are bounded, arbitrary finite arrays and objects, an actual UTF-8 byte renderer, and a checked inverse proof `canonical_inj : canonical a = canonical b -> a = b`. Receipt identifiers are remodeled as `hash (canonical projection)`, the sole axiom is now the symbolic hash idealization registered as ASSUME-SHA256, and both full 20-field binding and the downstream content/policy implication are theorems.

## Decisions (2026-07-12)

- The mechanized domain uses normalized signed-decimal digits covering negative
  i64 through positive u64. Raw numeric representations that canonicalize to
  the same value are unconstructible in the model.
- The production audit found 20 fields in `ChioReceiptIdInput`. The formal
  projection emits the same named object fields in UTF-16 key order. It also
  mirrors serde's omission of absent options and empty `actor_chain` and
  `evidence` vectors. Field presence distinguishes absence from every present
  value, including JSON null. A checked inverse recovers all 20 typed slots.
- Float exclusion is not vacuous: `action` and `metadata` can contain arbitrary
  `serde_json::Value` leaves. The full-field theorem therefore applies only
  when every projected compound value inhabits the modeled `JValue` domain. Rust serde
  correspondence and float-bearing cases remain under ASSUME-CANONICAL-JSON.
- The proof establishes injectivity of the normalized semantic projection, not
  raw JSON syntax or all `serde_json::Value` representations. A stronger raw
  input claim would be false without additional production validation.
- Prefix recovery uses a deterministic lexer and structural token grammar.
  Fixture propositions use kernel `decide`; `native_decide` is not used.
- The symbolic output type, digest function, and injectivity property are
  packaged in the single `hash_collision_resistant` axiom. Separate opaque
  declarations would create unregistered assumptions and are not used.
- The public renderer emits actual `Fin 256` UTF-8 bytes. The internal
  code-point layer is proved scalar-valid, and UTF-8 encoding is proved
  injective before `canonical_inj` crosses that boundary.
- The fixture generator transcribes 16 bounded integer and scalar corpus cases
  within elaboration bounds of 64 nodes and depth 8. It orders object entries
  by UTF-16 solely to construct the model's normalized object representation;
  expected bytes always come unchanged from the frozen corpus. Required
  U+007F escape and supplementary-plane ordering vectors are identity-pinned so they
  cannot disappear behind the corpus floor. Oversized and floating vectors
  remain in the Rust differential lane.
- A general parse-after-render theorem is deferred. The dedicated lexer and
  grammar prove the inverse needed for injectivity.
- The existing receipt mirror now hashes `ChioReceiptIdInput` and
  `chio_receipt_id` in addition to the receipt body and verifier symbols, so
  field-set or omission-rule drift forces formal review.
- The non-ratcheted Lean pilot now allowlists `IsLiteralScalar` and
  `CanonicalInteger`. Mutant
  `37e32776c83bdbabbba2` (`IsLiteralScalar`, `≠` to `=`) was killed by the
  `escape_string_inj` proof surface, and mutant `ca598a103d091d655e66`
  (`CanonicalInteger`, nonempty `≠` to `=`) was killed by the
  `render_int_inj` proof surface. These are local calibration results, not a
  promoted mutation-score ratchet.

## Motivation and evidence

- The former receipt axiom's in-file justification identified three missing pieces: a Lean model of the JCS serializer, a model of the hash, and a collision-resistance assumption tied to ASSUME-SHA256. This implementation supplies all three.
- `formal/proof-manifest.toml` now allowlists only the hash-level axiom and ties it one-to-one to ASSUME-SHA256.
- Signed payloads in Chio are canonical JSON (RFC 8785) per the repository conventions. ASSUME-CANONICAL-JSON is now narrowed to production agreement with the mechanized renderer plus behavior outside the modeled domain; serializer injectivity inside the model is proved.
- The differential harness shows the property is subtle enough to deserve a proof: formal/diff-tests/tests/canonical_json_diff.rs checks 12 named invariants against an independent in-file canonical JSON oracle. The U+007F case pins Chio's compatibility escape and the supplementary-plane case pins UTF-16 surrogate key ordering. Both boundaries are injectivity-adjacent.
- `FORM-NO-SOFTWARE-AXIOMS` is now approved with explicit scope: every root-imported Lean axiom is a registered cryptographic idealization, while production refinement and out-of-domain serializer behavior remain audited assumptions.

## Pre-implementation evidence

- The former axiom was:

  ```
  axiom receipt_id_collision_resistant
      (idInput1 idInput2 : ReceiptBody) :
      idInput1.id = idInput2.id ->
        idInput1.contentHash = idInput2.contentHash /\
          idInput1.policyHash = idInput2.policyHash
  ```

  `ReceiptBody` previously treated the identifier as opaque and the implication above as an axiom. The current receipt model instead derives the implication from the 20-field projection, canonical injectivity, and the symbolic hash assumption.
- Production canonicalizer: `chio_core::canonical::{canonicalize, canonical_json_bytes, canonical_json_string}` in crates/core/chio-core-types/src/canonical.rs (named as the production implementation by the diff harness header, canonical_json_diff.rs:5-6, imports L33).
- Differential evidence: `canonical_json_diff.rs` checks 12 named invariants (idempotence, UTF-16 key sorting, insignificant whitespace, integer form, string escaping, parse round trip, oracle byte agreement, UTF-8 validity, determinism, literals, empty collections, and non-finite rejection). Its proptest strategy is restricted to integer numbers, with floats covered by the frozen vector corpus. The committed proptest regression file remains part of that lane.
- Production escape behavior, pinned by the diff test: strings escape U+0000..U+001F, U+007F..U+009F, quotes, and reverse solidus. Escaping DEL and C1 controls preserves the canonical bytes emitted by earlier Chio versions.
- ASSUME-SHA256 (audited_crypto, backs P4/P7) and ASSUME-CANONICAL-JSON (audited_serialization, backs P4/P7/P10) are registered at formal/assumptions.toml:20-21.

## Design

### New Lean modules

1. `formal/lean4/Chio/Chio/Json/Value.lean` - the normalized JSON domain:
   - Mutually inductive `JValue`, `JArray`, and `JObject` types with `null`, `bool`, canonical signed-decimal integers, scalar strings, arrays, and ordered object-entry lists. `SortedObject` is a separate UTF-16 ordering predicate used at the canonical production boundary.
   - Strings are a modeled scalar sequence (a list of Unicode scalar values), not Lean `String`, so escaping and UTF-16 code-unit comparisons are definable functions rather than trusted library behavior.
   - Object rendering preserves its ordered entry list. Production fixtures are transcribed after UTF-16 key sorting, and `sorted_assoc_ext` accepts explicit `SortedObject` witnesses.
   - Floats are deliberately absent from the domain. This mirrors the diff-test integer restriction [v] and keeps ryu shortest-form out of scope.
2. `formal/lean4/Chio/Chio/Json/Canonical.lean` - the RFC 8785 serializer for that domain:
   - `canonical : JValue -> ByteSeq`, where `ByteSeq` is `List (Fin 256)`, composed from `renderInt`, `escapeString`, `renderArr`, and `renderObj`.
   - Key ordering by UTF-16 code unit is expressed by `utf16Units`, `utf16Less`, and `SortedObject`. Receipt projections and generated fixtures construct objects in that order; the historical supplementary-plane regression is why scalar-value order is insufficient.
   - Escaping mirrors production byte-for-byte: U+0000..U+001F, U+007F..U+009F, quote, and reverse solidus are escaped, while other Unicode scalar values remain literal.
3. `formal/lean4/Chio/Chio/Proofs/CanonicalInjective.lean` - the theorem:
   - `theorem canonical_inj : canonical a = canonical b -> a = b`, using an injective UTF-8 boundary, deterministic token recovery, and a fuel-bounded parser whose render round trip is proved by induction.
   - Hardest sub-lemmas, named explicitly so progress is trackable:
     - `escape_string_inj : escapeString s1 = escapeString s2 -> s1 = s2` (needs: escape map is prefix-free per scalar; no escape output collides with a literal character's output).
     - `render_int_inj : renderInt m = renderInt n -> m = n` (needs: no leading zeros, unique minus placement, nonempty digit string; this is where `integer_no_decimal_point` becomes a proved property instead of a tested one).
     - `sorted_assoc_ext`: two sorted, duplicate-free key lists rendering equal byte sequences are equal lists (uses `escape_string_inj` plus the delimiter grammar).

Implemented statement shapes:

```lean
-- Chio/Json/Value.lean
inductive JValue where
  | null
  | bool (b : Bool)
  | int  (n : BoundedInt)
  | str  (s : ScalarSeq)          -- modeled scalar-value sequence
  | arr  (xs : List JValue)
  | obj  (entries : JObject)      -- ordered entry list

-- Chio/Json/Canonical.lean
def canonical : JValue -> ByteSeq

-- Chio/Proofs/CanonicalInjective.lean
theorem escape_string_inj : escapeString s1 = escapeString s2 -> s1 = s2
theorem render_int_inj    : renderInt m = renderInt n -> m = n
theorem sorted_assoc_ext  : renderObj kvs1 = renderObj kvs2 -> kvs1 = kvs2
theorem canonical_inj     : canonical a = canonical b -> a = b

-- Chio/Json/Hash.lean
abbrev CanonicalBytes := { bytes : ByteSeq // exists v, canonical v = bytes }
structure SymbolicHash where
  Output : Type
  digest : CanonicalBytes -> Output
  injective : Function.Injective digest
axiom hash_collision_resistant : SymbolicHash

-- Chio/Proofs/Receipt.lean: the axiom becomes this theorem
theorem receipt_id_collision_resistant ... :=
  ... hash_collision_resistant ... canonical_inj ...
```

Before and after, in one line each:

- Before: one axiom conflating serializer injectivity (software) with hash collision resistance (crypto).
- After: `canonical_inj` (proved) plus `hash_collision_resistant` (audited crypto axiom, ASSUME-SHA256) derive `receipt_id_collision_resistant` (now a theorem).

### Restructuring the axiom

- Extend the receipt model with a typed 20-field `ReceiptIdProjection`, an injective serde-shaped object projection `toJValue : ReceiptIdProjection -> JValue`, and an abstract hash over canonical UTF-8 bytes.
- Model the id as `receiptId input = H (canonical (toJValue input))`.
- New, smaller axiom: `hash_collision_resistant` packages an abstract digest and injectivity only over the subtype of byte lists in the image of `canonical`. It is stated in `Chio/Json/Hash.lean` and tied one-to-one to ASSUME-SHA256. Injectivity-as-collision-resistance is the standard symbolic-model reading; real SHA-256 is compressing and concrete security remains the audited computational assumption.
- `receipt_id_collision_resistant` is then proved: equal ids -> equal hashes -> (hash axiom) equal canonical bytes -> (`canonical_inj`) equal `JValue` -> (projection injectivity on the modeled fields) equal `contentHash` and `policyHash`. The old axiom declaration is deleted; the theorem keeps the same name so downstream proofs (P4 lane) are untouched.

### Scope honesty

- Floats are excluded from the modeled domain. Production receipt metadata is an arbitrary `serde_json::Value`, so this exclusion is not vacuous. Float-valued and arbitrary numeric metadata leaves stay under the frozen vector corpus, differential lane, and ASSUME-CANONICAL-JSON.
- The proof binds the model serializer, not crates/core/chio-core-types/src/canonical.rs. The bridge to reality is fixtures, not refinement (below). ASSUME-CANONICAL-JSON survives, narrowed: what remains assumed is "the production canonicalizer agrees with the mechanized serializer on the modeled domain" (checked by fixtures and the diff harness) plus the float boundary, instead of "RFC 8785 serialization is deterministic and byte-stable" as an unanalyzed whole.

### Bridge to reality: fixture re-export

- Re-export the frozen diff-test vector corpus (tests/bindings/vectors/canonical/v1.json, bounded integer-domain subset) as generated Lean fixtures: `formal/lean4/Chio/Chio/Json/Fixtures.lean` with kernel `#guard` checks asserting `canonical fixture = expectedUtf8Bytes` for each vector small enough to elaborate cheaply.
- Generation is mechanical (a small generator emitting Lean from the JSON corpus) and checked into the tree; regeneration is drift-gated like other generated artifacts (the `--check` pattern in xtask/src/cli.rs:84-96).
- This links the model serializer to the production byte oracle: the same bytes the production canonicalizer is diff-tested against are the bytes the Lean serializer provably emits on those inputs.

## Implementation delivered

1. Phase 1 - domain and serializer.
   - Added `Json/Value.lean` and `Json/Canonical.lean` and root-imported both modules.
   - Added checked U+007F compatibility-escape and supplementary-plane key-ordering fixtures.
2. Phase 2 - injectivity proof.
   - Added `Proofs/CanonicalInjective.lean` with `escape_string_inj`, `render_int_inj`, `sorted_assoc_ext`, and `canonical_inj`.
3. Phase 3 - axiom restructuring.
   - Added `Json/Hash.lean`, replaced the receipt axiom with the identically named theorem, and modeled the serde-shaped `ReceiptIdProjection` in `Core/Receipt.lean`.
4. Phase 4 - fixture bridge and registries.
   - Added `scripts/generate-lean-json-fixtures.py` and generated `Json/Fixtures.lean`; updated the proof manifest, theorem inventory, mapping, assumptions, claim registry, coverage page, and receipt mirror hashes.

## CI and gating changes

- `scripts/check-formal-proofs.sh` builds the root-imported modules, checks fixture drift, scans for forbidden declarations and placeholders, and cross-checks the proof registries.
- The manifest axiom gate swaps the receipt axiom for the hash axiom, so any unregistered software axiom, opaque declaration, or constant fails the formal check.
- The formal PR path classifier routes fixture-generator and canonical-vector changes to the Lean job, where `--check` rejects fixture drift.
- No change to diff-test lanes; canonical_json_diff.rs remains the production-side gate.

## Acceptance criteria

- [x] `canonical_inj` is sorry-free and root-imported; its inverse proof is by parser-fuel induction after deterministic lexical recovery.
- [x] `escape_string_inj` and `render_int_inj` exist as named lemmas (not inlined), so FV-E1 spec-mutation can target them individually.
- [x] The model escape category byte-matches production behavior, demonstrated by kernel-checked U+007F compatibility-escape and surrogate-ordering byte fixtures.
- [x] `receipt_id_collision_resistant` is a theorem; the only explicit root-imported Lean axiom is `hash_collision_resistant`.
- [x] proof-manifest `allowed_axioms` lists exactly the hash-level axiom, cross-referenced to ASSUME-SHA256.
- [x] Frozen-corpus Lean fixtures elaborate and pass in the formal lane.
- [x] `excluded_surfaces` documents the float and Rust-refinement boundaries.
- [x] Downstream P4-lane proofs build with the same content/policy implication theorem.
- [x] The modeled receipt-id projection uses the production named-object shape,
  canonical key order, and serde omission rules; its decoder is a proved left
  inverse and the corresponding Rust symbols are mirror-gated.

## Residual risks and mitigations

- Regressions in escape, integer, or structural framing logic would invalidate injectivity. Mitigation: the named lemmas are root-built, fixture-gated, and exposed to the Lean mutation pilot.
- The model/production bridge is not a refinement proof. Rust `String` values contain Unicode scalar values rather than lone surrogates, but byte agreement still relies on the frozen fixtures, differential tests, mirror hashes, and ASSUME-CANONICAL-JSON.
- The hash axiom overstates computational collision resistance as mathematical injectivity. Mitigation: restrict its type to the image of the canonical renderer, document it as the standard symbolic idealization, and keep the CLAIM_REGISTRY wording at the `symbolic_crypto` and `audited_assumption` level.
- Fixture generation could become a second serializer to trust. Mitigation: expected bytes are transcribed unchanged from the corpus. The only normalization step orders parsed object entries by UTF-16 before constructing the formal value, and required regression identities are pinned.
- Scope creep toward floats. Mitigation: hard out-of-scope statement here and in `excluded_surfaces`; the diff-test integer restriction is the precedent (canonical_json_diff.rs:62-69).

## Manifest and registry updates

- formal/proof-manifest.toml:
  - `allowed_axioms`: remove `Chio.Proofs.receipt_id_collision_resistant`; add `Chio.Json.hash_collision_resistant` with a comment tying it to ASSUME-SHA256 (same style as the current entry, L128-135).
  - `root_modules`: add the four Json modules and Proofs/CanonicalInjective.lean.
  - `excluded_surfaces`: add the float-boundary sentence.
  - `property_matrix`: P4 row gains `proof.canonical_inj` and `proof.receipt_id_collision_resistant` (now a theorem id, not an assume id).
- formal/theorem-inventory.json: add entries for `canonical_inj`, `escape_string_inj`, `render_int_inj`, `sorted_assoc_ext`, the reproved `receipt_id_collision_resistant` (kind theorem, rootImported true, mapsTo P4/P7); replace the receipt-id assumption entry with `assume.hash.collision_resistant` for the new hash axiom.
- formal/assumptions.toml: ASSUME-SHA256 unchanged; ASSUME-CANONICAL-JSON prose narrowed to the fixture-bridged residue ("production canonicalizer agrees with the mechanized RFC 8785 model on the modeled domain; float leaves and encoder determinism outside that domain remain assumed"), keeping the same ID so MAPPING rows stay resolvable.
- formal/MAPPING.md: no Kani/TLA names change; add an informational Lean cross-reference row set for the new theorems.
- formal/proof-manifest.toml receipt mirror: add `ChioReceiptIdInput` and
  `chio_receipt_id` to the reviewed symbol hash set.
- docs/reference/CLAIM_REGISTRY.md: approve `FORM-NO-SOFTWARE-AXIOMS` only for explicit root-imported Lean axioms. The wording preserves production canonicalizer agreement, UTF-8, floats, and arbitrary numeric metadata as audited external assumptions. LEAN-4-VERIFIED and P4-END-TO-END remain disallowed; this claim does not imply either.
