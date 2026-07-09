# FV-C3: Mechanize canonical-JSON injectivity and shrink the single axiom

- Status: Proposed (2026-07-09)
- Theme: C - Turn verification into product surface
- Effort: M-L
- Depends on: none
- Feeds: shrinks the sole Lean axiom to a pure crypto assumption; narrows ASSUME-CANONICAL-JSON; strengthens the receipt-id story consumed by [FV-C2](FV-C2-verified-inclusion-verifier.md) and [FV-C1](FV-C1-receipt-trace-validation.md)
- Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G2), [FV-A4](FV-A4-mirror-drift-hashes.md), [FV-E1](FV-E1-spec-mutation-testing.md)

## Summary

The verified core carries exactly one Lean axiom: `receipt_id_collision_resistant` (formal/lean4/Chio/Chio/Proofs/Receipt.lean:140), which asserts that equal receipt ids imply equal content and policy hashes. Its own comment says why it is an axiom: the bounded model has no canonicalizer and no hash to prove injectivity against (L122-139). That axiom conflates two very different things - a software property (the RFC 8785 serializer is injective on its domain) and a cryptographic property (SHA-256 is collision resistant). This plan mechanizes the software half: a bounded JSON value domain in Lean, an RFC 8785 serializer over it, and a structural-induction proof `canonical_inj : canonical a = canonical b -> a = b`. The receipt id is then remodeled as `hash (canonical body)`, the axiom shrinks to hash collision resistance (exactly ASSUME-SHA256, already an audited assumption [v]), and `receipt_id_collision_resistant` becomes a theorem.

## Motivation and evidence

- The axiom's in-file justification is a to-do list, verified this session (Proofs/Receipt.lean:122-139): mechanizing requires (1) a Lean model of the JCS serializer, (2) a model of the hash, (3) a collision-resistance assumption on the hash discharged as a crypto assumption citing ASSUME-SHA256. This plan is that list, executed.
- The axiom is whitelisted in formal/proof-manifest.toml `allowed_axioms` (L128-135) and tied to ASSUME-SHA256 [v]. After this plan, the whitelist entry names only a hash-level assumption - an assumption class security reviewers accept without reading Lean.
- Signed payloads in Chio are canonical JSON (RFC 8785) per the repository conventions, and ASSUME-CANONICAL-JSON (formal/assumptions.toml:21) currently assumes the entire serializer is "deterministic and byte-stable" as a monolith. A mechanized serializer with a fixture bridge narrows what must be assumed about the production implementation.
- The differential harness shows the property is subtle enough to deserve a proof: formal/diff-tests/tests/canonical_json_diff.rs checks 12 named invariants against an independent in-file RFC 8785 oracle, and its committed proptest regressions include a U+007F control-escaping catch and a UTF-16 surrogate key-ordering catch [v]. Both historical bugs are exactly injectivity-adjacent (escaping and ordering).
- Marketing truthfully: after this lands, the claim "the verified core has zero software axioms - every axiom is a named cryptographic assumption" becomes available (see registry section). Today that sentence is false by one axiom.

## Current state

- The axiom, verified this session:

  ```
  axiom receipt_id_collision_resistant
      (idInput1 idInput2 : ReceiptBody) :
      idInput1.id = idInput2.id ->
        idInput1.contentHash = idInput2.contentHash /\
          idInput1.policyHash = idInput2.policyHash
  ```

  (formal/lean4/Chio/Chio/Proofs/Receipt.lean:140-144; `ReceiptBody` treats `id` as an opaque String, Core/Receipt.lean:12-16.)
- Production canonicalizer: `chio_core::canonical::{canonicalize, canonical_json_bytes, canonical_json_string}` in crates/core/chio-core-types/src/canonical.rs (named as the production implementation by the diff harness header, canonical_json_diff.rs:5-6, imports L33).
- Differential evidence, verified this session: the 12 named invariants are listed at canonical_json_diff.rs:16-27 (idempotence, key_sort_utf16, no_insignificant_whitespace, integer_no_decimal_point, string_minimal_escaping, parse_round_trip_equal, byte_stable_oracle_match, valid_utf8_output, determinism, null_bool_literals, empty_collections, nan_infinity_rejected). The proptest strategy is restricted to integer numbers - no f64 re-implementation - with floats covered by the frozen vector corpus tests/bindings/vectors/canonical/v1.json (L62-69) [v]. The committed regression file formal/diff-tests/tests/canonical_json_diff.proptest-regressions exists.
- Production escape behavior, pinned by the diff test: strings escape the category U+0000..U+001F plus U+007F..U+009F and nothing else outside the JSON-mandated characters (canonical_json_diff.rs:478-486). This is slightly broader than the RFC's minimal floor; the model must mirror production, not the RFC's floor, because the fixture bridge compares bytes.
- ASSUME-SHA256 (audited_crypto, backs P4/P7) and ASSUME-CANONICAL-JSON (audited_serialization, backs P4/P7/P10) are registered at formal/assumptions.toml:20-21.

## Design

### New Lean modules

1. `formal/lean4/Chio/Chio/Json/Value.lean` - the bounded JSON domain:
   - `inductive JValue` with `null`, `bool`, `int (n : Int)` bounded to the modeled integer range, `str (s : JString)`, `arr (xs : List JValue)`, `obj (kvs : SortedAssocList JString JValue)`.
   - Strings are a modeled scalar sequence (a list of Unicode scalar values), not Lean `String`, so escaping and UTF-16 code-unit comparisons are definable functions rather than trusted library behavior.
   - Objects are sorted association lists: the sortedness and key-uniqueness invariants are carried in the type (a subtype or a well-formedness predicate bundled with the constructor), so "canonical input domain" is a type, not a side condition scattered through proofs.
   - Floats are deliberately absent from the domain. This mirrors the diff-test integer restriction [v] and keeps ryu shortest-form out of scope.
2. `formal/lean4/Chio/Chio/Json/Canonical.lean` - the RFC 8785 serializer for that domain:
   - `canonical : JValue -> List Byte` (or `String` over the modeled alphabet), composed from `renderInt`, `escapeString`, `renderArr`, `renderObj`.
   - Key ordering by UTF-16 code unit: define `utf16Units : ScalarSeq -> List UInt16` and the induced lexicographic order; the `obj` constructor's sortedness predicate uses exactly this order (the historical surrogate-ordering regression is the reason this cannot be scalar-value order).
   - Escaping mirrors production's pinned category (U+0000..U+001F plus U+007F..U+009F, plus quote and backslash and the RFC short forms), matching canonical_json_diff.rs:478-486 byte-for-byte.
3. `formal/lean4/Chio/Chio/Proofs/CanonicalInjective.lean` - the theorem:
   - `theorem canonical_inj : canonical a = canonical b -> a = b`, by structural induction on `JValue` with a prefix-freedom framing (the serializer's output grammar is self-delimiting: first byte discriminates the constructor class; strings are quote-delimited with escaped interiors; collections bracket-delimited with comma separators).
   - Hardest sub-lemmas, named explicitly so progress is trackable:
     - `escape_string_inj : escapeString s1 = escapeString s2 -> s1 = s2` (needs: escape map is prefix-free per scalar; no escape output collides with a literal character's output).
     - `render_int_inj : renderInt m = renderInt n -> m = n` (needs: no leading zeros, unique minus placement, nonempty digit string; this is where `integer_no_decimal_point` becomes a proved property instead of a tested one).
     - `sorted_assoc_ext`: two sorted, duplicate-free key lists rendering equal byte sequences are equal lists (uses `escape_string_inj` plus the delimiter grammar).

Statement sketches (names final, statements indicative):

```lean
-- Chio/Json/Value.lean
inductive JValue where
  | null
  | bool (b : Bool)
  | int  (n : BoundedInt)
  | str  (s : ScalarSeq)          -- modeled scalar-value sequence
  | arr  (xs : List JValue)
  | obj  (kvs : SortedKeyList)    -- sortedness by UTF-16 units in the type

-- Chio/Json/Canonical.lean
def canonical : JValue -> ByteSeq

-- Chio/Proofs/CanonicalInjective.lean
theorem escape_string_inj : escapeString s1 = escapeString s2 -> s1 = s2
theorem render_int_inj    : renderInt m = renderInt n -> m = n
theorem sorted_assoc_ext  : renderObj kvs1 = renderObj kvs2 -> kvs1 = kvs2
theorem canonical_inj     : canonical a = canonical b -> a = b

-- Chio/Json/Hash.lean
axiom hash_collision_resistant : H x = H y -> x = y   -- exactly ASSUME-SHA256

-- Chio/Proofs/Receipt.lean: the axiom becomes this theorem
theorem receipt_id_collision_resistant ... :=
  ... hash_collision_resistant ... canonical_inj ...
```

Before and after, in one line each:

- Before: one axiom conflating serializer injectivity (software) with hash collision resistance (crypto).
- After: `canonical_inj` (proved) plus `hash_collision_resistant` (audited crypto axiom, ASSUME-SHA256) derive `receipt_id_collision_resistant` (now a theorem).

### Restructuring the axiom

- Extend the receipt model: introduce `ReceiptIdInput` (the field set the kernel hashes), a projection `toJValue : ReceiptIdInput -> JValue`, and an abstract hash `H : List Byte -> HashVal`.
- Model the id as `receiptId input = H (canonical (toJValue input))`.
- New, smaller axiom: `axiom hash_collision_resistant : H x = H y -> x = y` over the bounded byte domain - stated in `Chio/Json/Hash.lean` and tied one-to-one to ASSUME-SHA256. (Injectivity-as-collision-resistance is the standard symbolic-model reading; the doc states plainly that real SHA-256 is compressing and this is the audited symbolic idealization, same class as the existing symbolic_crypto lanes.)
- `receipt_id_collision_resistant` is then proved: equal ids -> equal hashes -> (hash axiom) equal canonical bytes -> (`canonical_inj`) equal `JValue` -> (projection injectivity on the modeled fields) equal `contentHash` and `policyHash`. The old axiom declaration is deleted; the theorem keeps the same name so downstream proofs (P4 lane) are untouched.

### Scope honesty

- Floats are excluded from the modeled domain. Receipt-id inputs are hashes, ids, and structural fields - not floats - so the exclusion is believed vacuous for the receipt path, but it must be stated: proof-manifest `excluded_surfaces` gains "float-valued JSON leaves are outside the mechanized canonical-JSON domain; float canonicalization remains covered by the frozen vector corpus and ASSUME-CANONICAL-JSON".
- The proof binds the model serializer, not crates/core/chio-core-types/src/canonical.rs. The bridge to reality is fixtures, not refinement (below). ASSUME-CANONICAL-JSON survives, narrowed: what remains assumed is "the production canonicalizer agrees with the mechanized serializer on the modeled domain" (checked by fixtures and the diff harness) plus the float boundary, instead of "RFC 8785 serialization is deterministic and byte-stable" as an unanalyzed whole.

### Bridge to reality: fixture re-export

- Re-export the frozen diff-test vector corpus (tests/bindings/vectors/canonical/v1.json, integer-domain subset) as generated Lean fixtures: `formal/lean4/Chio/Chio/Json/Fixtures.lean` with `#eval`/`decide` checks asserting `canonical (parseFixture i) = expectedBytes i` for each vector small enough to elaborate cheaply.
- Generation is mechanical (a small generator emitting Lean from the JSON corpus) and checked into the tree; regeneration is drift-gated like other generated artifacts (the `--check` pattern in xtask/src/cli.rs:84-96).
- This links the model serializer to the production byte oracle: the same bytes the production canonicalizer is diff-tested against are the bytes the Lean serializer provably emits on those inputs.

## Implementation plan

1. Phase 1 - domain and serializer.
   - Add `formal/lean4/Chio/Chio/Json/Value.lean`, `formal/lean4/Chio/Chio/Json/Canonical.lean`; modify `formal/lean4/Chio/Chio.lean` root imports.
   - Add executable sanity `#eval`s for the known regression shapes: a U+007F-bearing string, a surrogate-pair key ordering case.
2. Phase 2 - injectivity proof.
   - Add `formal/lean4/Chio/Chio/Proofs/CanonicalInjective.lean` with `escape_string_inj`, `render_int_inj`, `sorted_assoc_ext`, `canonical_inj`.
3. Phase 3 - axiom restructuring.
   - Add `formal/lean4/Chio/Chio/Json/Hash.lean` (abstract `H`, `hash_collision_resistant`); modify `formal/lean4/Chio/Chio/Proofs/Receipt.lean` to delete the axiom and prove the identically-named theorem; modify `formal/lean4/Chio/Chio/Core/Receipt.lean` only if the `ReceiptIdInput` projection needs a home there.
4. Phase 4 - fixture bridge and registries.
   - Add the fixture generator (proposed `formal/lean4/tools/gen-json-fixtures/`, or an xtask `gen` leaf) and `formal/lean4/Chio/Chio/Json/Fixtures.lean`; modify formal/proof-manifest.toml, formal/theorem-inventory.json, formal/MAPPING.md, docs/reference/CLAIM_REGISTRY.md per the registry section.

## CI and gating changes

- `scripts/check-formal-proofs.sh` covers the new modules once root-imported (lake build plus sorry hygiene); no new lane needed.
- The manifest axiom gate is the real enforcement point: `allowed_axioms` swaps the receipt axiom for the hash axiom, so any reappearance of a software axiom fails the manifest check.
- Fixture regeneration gets a drift check alongside the existing generated-artifact checks (`--check` exits nonzero on drift), wired into the PR job that already runs `cargo test -p chio-formal-diff-tests`.
- No change to diff-test lanes; canonical_json_diff.rs remains the production-side gate.

## Acceptance criteria

- [ ] `canonical_inj` proved by structural induction, sorry-free, root-imported.
- [ ] `escape_string_inj` and `render_int_inj` exist as named lemmas (not inlined), so FV-E1 spec-mutation can target them individually.
- [ ] The model escape category byte-matches production's pinned category (U+0000..U+001F plus U+007F..U+009F), demonstrated by fixture `#eval`s including a U+007F case and a surrogate key-ordering case.
- [ ] `receipt_id_collision_resistant` is a theorem; `axiom` grep over the Lean tree finds only `hash_collision_resistant` (plus any pre-existing allowlisted signature oracle).
- [ ] proof-manifest `allowed_axioms` lists exactly the hash-level axiom, cross-referenced to ASSUME-SHA256.
- [ ] Frozen-corpus Lean fixtures elaborate and pass in the formal lane.
- [ ] `excluded_surfaces` documents the float boundary.
- [ ] Downstream P4-lane proofs build unchanged (same theorem name and statement).

## Risks and mitigations

- Proof difficulty concentrates in `escape_string_inj` (escape sequences must be prefix-free against each other and against literal bytes). Mitigation: the escape map is a finite table; prove prefix-freedom by `decide` over the finite alphabet of escape heads, leaving only the literal-vs-escape case as a real argument (backslash never appears unescaped).
- Model/production divergence on an unpinned corner (for example lone surrogates, which JSON strings can carry as WTF-16 artifacts). Mitigation: the modeled string domain is Unicode scalar values only; whether production `canonicalize` can ever receive lone surrogates through `serde_json::Value` is checked during phase 1 and, if reachable, the domain note moves to `excluded_surfaces` explicitly rather than being silently wrong.
- The hash axiom overstates (injectivity vs collision resistance). Mitigation: state it over the bounded modeled byte domain, document it as the standard symbolic idealization, and keep the CLAIM_REGISTRY wording at the `symbolic_crypto`/`audited_assumption` level - this is the same posture the existing P4 lane already takes [v].
- Fixture generator becomes a second serializer to trust. Mitigation: the generator only transcribes corpus bytes into Lean literals; it serializes nothing.
- Scope creep toward floats. Mitigation: hard out-of-scope statement here and in `excluded_surfaces`; the diff-test integer restriction is the precedent (canonical_json_diff.rs:62-69).

## Open questions

- Should `render_int_inj` cover the full i64/u64 range of the production strategy or the bounded model integer range? (Proposal: model range matches the strategy domain, i64 plus u32-lifted u64 values, so the fixture bridge covers what proptest covers.)
- Is `decide`-based prefix-freedom for the escape table fast enough for the PR lane, or does it need `native_decide` (which would add a trust note)?
- Does `ChioReceiptIdInput` on the Rust side (the actual hashed field set) contain any non-integer numeric field that would falsify the "float exclusion is vacuous for receipts" belief? Phase 1 includes a one-time audit of that struct.
- Do we also want `canonical_parse_roundtrip` in Lean (parse after serialize), or is injectivity alone the load-bearing half? (Roundtrip is strictly extra; propose deferring.)

## Manifest and registry updates

- formal/proof-manifest.toml:
  - `allowed_axioms`: remove `Chio.Proofs.receipt_id_collision_resistant`; add `Chio.Json.hash_collision_resistant` with a comment tying it to ASSUME-SHA256 (same style as the current entry, L128-135).
  - `root_modules`: add the three Json modules and Proofs/CanonicalInjective.lean.
  - `excluded_surfaces`: add the float-boundary sentence.
  - `property_matrix`: P4 row gains `proof.canonical_inj` and `proof.receipt_id_collision_resistant` (now a theorem id, not an assume id).
- formal/theorem-inventory.json: add entries for `canonical_inj`, `escape_string_inj`, `render_int_inj`, `sorted_assoc_ext`, the reproved `receipt_id_collision_resistant` (kind theorem, rootImported true, claimClass bounded_model, mapsTo P4/P7); move the old `assume.receipt.id_collision_resistant` entry to reference the new hash axiom; the inventory's separate `assumptions` block gains the hash axiom and drops the receipt-id one.
- formal/assumptions.toml: ASSUME-SHA256 unchanged; ASSUME-CANONICAL-JSON prose narrowed to the fixture-bridged residue ("production canonicalizer agrees with the mechanized RFC 8785 model on the modeled domain; float leaves and encoder determinism outside that domain remain assumed"), keeping the same ID so MAPPING rows stay resolvable.
- formal/MAPPING.md: no Kani/TLA names change; add an informational Lean cross-reference row set for the new theorems.
- docs/reference/CLAIM_REGISTRY.md: propose new claim `FORM-NO-SOFTWARE-AXIOMS` (approved_with_scope), exact wording: "Every axiom in Chio's root-imported Lean development is a named cryptographic idealization registered in formal/assumptions.toml; no serializer, protocol, or kernel behavior is axiomatized." Evidence classes: `lean_root_imported`, `audited_axiom`, `audited_assumption`. LEAN-4-VERIFIED (registry L74) and P4-END-TO-END (L77) remain disallowed; this claim does not imply either.
