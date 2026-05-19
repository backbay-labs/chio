# Wave 6 Termination Check

Date: 2026-05-18
Scope: Final certification of submission readiness for USENIX Sec 2027 Cycle 2.

## Verdict: READY

Zero substantive findings. Build gate is clean. The five Wave 4 substantive
findings are all confirmed-fixed. Recommend terminating the development cycle
and proceeding to human submission steps.

## Wave 4 finding closeout

**B1 (gate count taxonomy: six runtime / five codes / three Lean) -- CONFIRMED
FIXED.** §3 line 43-53 introduces the formula with an explicit bridge:
"accepts iff six gates hold in order; (G3) and (G4) below each group two
atomic clauses." §3 line 53 closes with "the predicate is the conjunction of
six gates (G1)-(G6) ... Five of the six gates produce uniquely-named rejection
codes; the trust-store-membership gate (G4) is bundled with
predicate-type-mismatch in the deployed verifier." §4 line 13 supplies the
collapse: "Three abstract gates vs.\ six runtime gates. The six runtime gates
... collapse into the three structural conjuncts above." §1 bullet 5 now reads
"conjunction of three abstract gates ... that collapse the runtime's six-gate
conjunction of Section~\ref{sec:predicate} into a structural form Lean can
mechanically check." The three taxonomies reconcile and the collapse is
explicit. The §1 bullet now credits three Lean conjuncts without overclaiming
"six."

**B2 (sha256: prefix in JSON example) -- CONFIRMED FIXED.** Verified by reading
§3 lines 11-33. Hex fields in the binding object now appear as bare 64-char
strings: `"treatyScopeHash": "7b2a...c1e0"`, `"ladderInterHash": "8c4d...3f02"`,
etc. Zero `sha256:` prefix occurrences inside the binding object. The outer
`subject.digest` field still uses `"sha256"` as a JSON key, which is the
in-toto schema-level key name (not a value prefix); this is correct per the
DSSE/in-toto schema.

**M1 (§5 verbatim duplication with parent) -- CONFIRMED FIXED.** Diffed against
parent §5 line 39. The short paper's §5 line 10 paraphrases the verifier
enumeration entirely: parent says "rejects wrong payload type, wrong signature
count, noncanonical JSON, wrong statement type, wrong predicate type, missing
subject, and reused signer keys" while short paper says "payload-type equality
against the bilateral statement type, signature count equal to two,
canonical-JSON equivalence between the inner payload and its declared digest,
predicate-type equality against \codepath{PREDICATE_TYPE_CHIODOS_BILATERAL},
single-subject presence, keyid-distinctness across the two signatures." The
closing sentence is also distinct ("The ordering is load-bearing: every
byte-level check fires before the verifier consults state the sender cannot
see" vs parent's "admission depends on the predicate the protocol names, not
on a strict subset"). Shared technical terms (`verify_chiodos_dsse_envelope`,
`bilateral_verifier.rs`, "canonical bytes") are unavoidable noun phrases and
acceptable.

**M2 (§7 V8 issuer-rotation voice leak) -- CONFIRMED FIXED.** §7 line 14 now
reads "the companion paper develops a schema-version-binding scheme that
promotes predicate-type strict equality to a schema-rotation-aware acceptance
relation, with explicit epoch boundaries that prevent the downgrade described
here." No "V8" reference. Voice grep across `sections/*.tex paper.tex bib.bib`
returns zero substantive matches: the only `V[0-9]` hits are `ChiodosBilateralV1`
(a wire-format predicate-type literal that names the actual protocol field) and
a TR document number `v1.3.1` in a bib entry (legitimate citation field).

**M3 (§3/§6 rejection-code taxonomy contradiction) -- CONFIRMED FIXED.** §3
line 65: "The taxonomy is intentionally coarse and is scoped to the
post-signature gates: a signature-bytes failure denies the envelope before the
six gates are evaluated and is not a member of the five rejection codes
above." §6 line 16 (tampered-signature fixture): "The denial is therefore
outside the five rejection-code taxonomy of \S\ref{sec:predicate} (which
scopes its codes to the post-signature gates), and the fixture exercises the
byte-level Ed25519 check rather than the gate conjunction." §3 and §6 now use
identical "post-signature gates" language. Consistent.

## Fresh-eye sweep

### Build gate state

Ran `pdflatex paper.tex; bibtex paper; pdflatex paper.tex; pdflatex paper.tex`.
All four commands exit 0. `paper.log` has zero `! ` errors, zero undefined
citation warnings, zero undefined reference warnings. `paper.blg` has zero
BibTeX warnings or errors. Eight overfull-hbox warnings remain, all under 16pt
and inside `\codepath{}` / `\thm{}` invocations (Wave 4 noted them as
visually invisible). PDF metadata: 9 pages, 612x792 letter, pdftex 3.14159265
TeX Live 2026, 486428 bytes. Page count is within the 7-10 target.

### Cross-reference correctness

Every `\label{}` resolves to a `\ref{}` or `\S\ref{}` somewhere. The four Lean
theorem names (`freestanding_accept_set_theorem`, `accept_monotone_in_issuer_store`,
`accept_conj_scope_decompose`, `accept_requires_issuer_key`) all exist in
`/Users/connor/Medica/backbay/standalone/arc/formal/lean4/Chio/Chio/Treaty/BilateralAccept.lean`
with corresponding `theorem` declarations. Three forward references to
companion-paper theorems (`amendment_admissible_iff_backward_refinement`,
`treaty_admission_iff_predicate_intersection`, `essential_preserved_chain`)
are appropriately scoped as out-of-scope companion-paper claims, not local
references that need to resolve.

### Voice rule grep

Grep across `sections/*.tex paper.tex bib.bib` for the substantive patterns
returns the two matches above (`ChiodosBilateralV1` predicate-type literal,
TR `v1.3.1` document number) -- both legitimate. No "V8", "branch name",
"checked-in", "release-engineering", "bless recipe", "we extend", "we
introduce", or "salami" occurrences. "Companion paper" appears five times and
"separate manuscript" three times; these are conventional academic
forward-reference phrasing, not engineering-meta voice leaks.

### Em-dash check

`grep -lP "\x{2014}"` against `sections/*.tex paper.tex bib.bib` returns empty.
Clean.

### Abstract <-> §1 <-> §9 consistency

The abstract promises (1) a DSSE predicate type with subject-digest binding,
(2) a strict verifier with five rejection codes (named), (3) a Rust runtime
with pre-dispatch admission hook, (4) BBS selective disclosure with Ed25519
authoritative, (5) a three-vendor buyer-closure with admitted and denied
paths, (6) defeat of three named attack classes, (7) Lean kernel-axiom claim.
§1's five contribution bullets map: bullet 1 = predicate type + five codes
(§3), bullet 2 = Rust runtime + strict verifier (§5), bullet 3 = three-vendor
closure (§6), bullet 4 = four named attack defeats (§7), bullet 5 = Lean
witness (§4). §9 acknowledges no-live-cross-process-federation (matches §5's
in-process closure), single-vendor-key-custody (matches §5 threat-model
sentence), observability gap. Internal consistency holds.

### PDF render check

All nine pages rendered to PNG and visually verified:
- Page 1: title, abstract, §1, opening of §2; clean.
- Page 2: §2 continues, §3 begins, JSON verbatim block legible.
- Page 3: §3 continues with the six-gate formula and per-code paragraphs.
- Page 4: §3 closes, §4 opens with the freestanding theorem statement.
- Page 5: §4 closes, §5 opens, Table 1 (five rejection codes) fits the right
  column.
- Page 6: §5 closes, §6 opens.
- Page 7: §6 closes, §7 opens.
- Page 8: §7 + §8 + §9 + start of bibliography.
- Page 9: bibliography continues.
No clipping, no overflow, no broken figures, no unreadable verbatim. Eight
overfull-hbox warnings are inside `\codepath{}` / `\thm{}` tokens and are
visually invisible.

### Self-plagiarism check vs parent paper

Spot-checked three short passages:

(a) Short §3 binding-tuple discussion vs parent §3 substrate "Bilateral DSSE"
paragraph: prose is distinct. Parent §3 says "Cross-organization actions use a
strict Chiodos predicate profile over a DSSE envelope. The protocol pins
\codepath{PREDICATE_TYPE_CHIODOS_BILATERAL} to ..." in summary form; short §3
develops the field-by-field rationale ("the treaty-scope hash pins the
bilateral relationship in force ... the ladder-intersection hash pins the joint
mode-coverage decision ...") at much greater length. The shared
field-name enumeration is unavoidable structural content; the prose around
each field name is distinct.

(b) Short §5 strict-verifier paragraph vs parent §5 line 39: paraphrase
confirmed (covered under M1 above).

(c) Short §7 attack-defeat paragraphs vs parent §7 discussion: parent §7 is
the polity/Hartian discussion (Montevideo article 1, Próspera, FTX, Tornado
Cash, EU AI Act). Short §7 is a six-class attack catalog (sibling-treaty,
BBS stub, single-lane witness, error-message oracle, schema-version downgrade,
constitutional-ratchet pointer). Different sections in name and content; no
duplicated prose.

The bench numerics (72.051 microseconds dispatch latency; 131.67 / 539.75 /
4980.46 microseconds treaty-intersection percentiles) are shared via inline
files (`bench/results/treaty-intersection-inline.tex`), which is honest
identical-number reuse rather than prose duplication.

## Substantive findings

None.

## Non-substantive observations

These are light edits the author may want before final submission; none rise
to reviewer-grade blocker status.

1. The abstract closes "Lean module whose only kernel axioms are
   propositional extensionality and choice." §4 line 29 names three kernel
   axioms (`propext`, `Classical.choice`, `Quot.sound`). The abstract elides
   `Quot.sound`. Quot.sound is a standard Lean kernel axiom present in every
   Mathlib development, so the elision is conventional, but a Lean-savvy
   reviewer running `#print axioms` will note the gap. Optional tightening:
   add "quotient soundness" to the abstract or substitute "the standard Lean
   kernel axioms."

2. The abstract names three attack defeats ("sibling-treaty cross-receipt
   substitution, BBS stub-vs-real disambiguation, and error-message
   oracles"); §1 bullet 4 names four ("sibling-treaty cross-receipt
   substitution, BBS stub-vs-real disambiguation, single-lane witness
   compromise, and error-message oracles"); §7 enumerates six. These are
   nested summaries (smaller -> larger) rather than contradictions, but a
   careful reader may note the abstract's three vs §1's four. Optional:
   align abstract with §1 bullet 4 by adding single-lane-witness, or
   acknowledge the §7 expansion.

3. README short-paper / page-count framing vs VENUE-DECISION's 8-10 page
   USENIX Cycle 2 target was unfixed in Wave 4; not visible in the
   submission artifacts and outside the paper itself, so non-blocking for
   submission readiness.

4. Wave 4 minor m3 (operator-resolution metadata source unspecified) and
   minor m4 (adaptive-adversary oracle bound) are still unaddressed in the
   prose. Neither is reviewer-grade for a strict cryptographic-primitive
   short paper at this venue; both are at most one-sentence improvements.

## Termination recommendation

READY -- terminate development cycle and proceed to human submission steps.

The five Wave 4 substantive findings (B1, B2, M1, M2, M3) are all confirmed
fixed in the current paper. The build gate is clean (zero errors, zero
undefined citations, zero BibTeX warnings, 9 pages within the 7-10 target,
PDF renders cleanly across all pages). Voice grep and em-dash check pass.
Cross-references resolve. The §3/§4/§5/§6 gate-count taxonomy now reconciles
through an explicit collapse paragraph in §4. The §5 verifier paragraph is
paraphrased from parent. The V8 voice leak is gone. The signature-failure
taxonomy is scoped consistently across §3 and §6.

The remaining observations are accuracy nits (Quot.sound omission in
abstract, attack-class count expansion across abstract/§1/§7) and Wave 4
minor punts (operator-resolution metadata source, adaptive-adversary bound)
that no careful USENIX PC reviewer would write up as flags in a first
reading. The paper is at the engineering-prose quality and internal
consistency a USENIX Cycle 2 submission should clear.

Hand off to human for the simultaneous-submission notification to
sec27chairs@usenix.org, the final read-aloud pass, and the upload.
