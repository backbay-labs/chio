# Wave 4 Final Adversarial Review

Date: 2026-05-18
Scope: Submission-readiness certification for USENIX Sec 2027 Cycle 2 (Jan 2027 deadline).

## Verdict: NOT READY

Two blockers and three majors remain. The headline issue is a gate-count inconsistency that propagates through abstract, §1 bullet 5, the §3 formula, the §3 prose, the §4 Lean theorem, §5, §6, and §8. A Lean-knowledgeable reviewer will catch it. One narrow FIX cycle.

## Wave 2 finding closeout

1. §4 simp-trivial honesty rewrite -- **fixed**. §4 now opens "not a deep theorem and is not load-bearing"; the "What the Lean module does not prove" paragraph names four gaps.
2. §3 canonical-encoding paragraph -- **fixed**. JCS over ten named fields, sixty-four lowercase ASCII hex, no `sha256:` prefix inside the binding object. But the worked envelope visually contradicts it (B2 below).
3. §6 bench-scope clarification -- **fixed**. §6 line 12 admits 72.051 microseconds measures "the full admission-hook entry-point" and is "not a cryptographic-primitive measurement."
4. §7 schema-version-downgrade -- **partially fixed**. §7 line 14 acknowledges strict match but punts to "the companion paper's V8 issuer-rotation work" -- forward reference plus voice leak.
5. §3 worked-envelope placeholders -- **partially fixed**. Encoding now specified, but the example still uses the `sha256:` prefix the new paragraph excludes.
6. §7 BBS stub-vs-real motivation -- **fixed**.
7. §5 real cosigners honesty -- **partially fixed**. §9 names single-vendor-key-custody but §5 talks of "two kernels" without naming the in-process closure reality.
8. §6 vs parent paper overlap -- **partially fixed**. §5 still duplicates parent §5 verbatim (R1).
9. §8 thinness -- **fixed**. Five per-lineage paragraphs, ~580 words.
10. README short-paper framing -- **unfixed**. Still says "6-8 pages, USENIX Security short paper" while VENUE-DECISION pins USENIX Cycle 2 at 8-10 pages.
11. §5 macOS ES stub caveat -- **partially fixed** via hedge that the primitive operates regardless of telemetry. Acceptable.
12. Voice leak + em-dash check -- **partially fixed**. No em-dashes. But §7 line 14 carries the "V8 issuer-rotation work" engineering-meta leak.
13. PDF render check -- **fixed**. Eight pages clean; JSON verbatim on page 2 legible; Table 1 on page 5 fits; §8 wraps correctly. Eight overfull-hbox warnings sub-16-pt and inside `\codepath{}`/`\thm{}` tokens, visually invisible.

Also unfixed from Wave 2's adversarial detail:

- S2 (adaptive-adversary oracle bound): §3 line 68 still asserts a flat `log_2 5 ≈ 2.32` leak; adaptive O(5) localization unacknowledged.
- T2 (signature-verification as a sixth code): §3 has five codes; §6 line 16 fixture "denies on signature verification, distinct from the predicate-type and signer-reuse gates." Self-contradiction.
- T3 (operator-resolution metadata): §3 still says "verifier-owned attribution metadata" without specifying its source.
- N1 / N2 (continuation-hash forking, revocation-epoch probing): not in Wave 3 priority queue, unaddressed, not named in §7 residual risk.
- V3 ("by construction" overuse): fixed. Three instances paper-wide, none in §7.

## Wave 2 constructive drafts landing check

- Draft A (abstract close cleanup): **landed**. Abstract closes on attack defeats plus Lean axioms.
- Draft B (§1 fifth bullet, Lean witness): **landed in form, broken in content**. The fifth bullet exists but claims the Lean theorem characterizes "exactly the six gate predicates §3 names" -- which is the load-bearing inconsistency. Draft B's actual wording was "trust-store membership and scope-predicate denotation," which would have matched §4's three-conjunct accept relation; Wave 3 substituted "six gate predicates," creating the mismatch.
- Draft F (§5 function-to-code mapping): **landed** as Table 1 with five rows and source pointers.
- Draft H (§8 related-work expansion): **landed** as five per-lineage paragraphs.
- Draft I (§9 inherited limits): **NOT LANDED**. §9 is still 154 words and three paragraphs; schema-evolution and key-custody-rotation limits absent.

Four of the five priority drafts landed. The missed one is §9 expansion.

## Fresh-eye sweep

### Cross-reference correctness

Every `\label{}` in `sections/*.tex` resolves to a `\ref{}` or `\S\ref{}` elsewhere. The four Lean theorem names (`freestanding_accept_set_theorem`, `accept_monotone_in_issuer_store`, `accept_conj_scope_decompose`, `accept_requires_issuer_key`) exist in `formal/lean4/Chio/Chio/Treaty/BilateralAccept.lean` and are referenced consistently across §1, §4, §8.

### Numerical / unit consistency

**The blocker.** The paper carries at least four different gate counts that do not reconcile:

- Abstract: "the conjunction of **six gate predicates** over canonical bytes."
- §1 bullet 5: "characterizing the verifier's accept relation as the conjunction of exactly the **six gate predicates** Section~\ref{sec:predicate} names."
- §3 line 56 prose: "the conjunction of **six gates** ... returns one of **five rejection codes**."
- §3 formula (lines 44-55): **eight** explicit conjuncts.
- §4 Lean accept relation (lines 4-10): **three** conjuncts (`issuerSig.kid in issuerKeys`, `kernelSig.kid in kernelKeys`, `denote(scope)(receiptId)`).
- §5 (twice) and §6 (once): "**five-gate** verifier."
- §8 line 7: "the **six-gate conjunction**."

A reviewer counts the §3 formula and gets eight; reads §3 prose and gets six; reads §5 and gets five; reads §4 Lean and gets three. The §1 bullet 5 promise that the Lean theorem characterizes "exactly the six gate predicates §3 names" is wrong on its face: the Lean theorem characterizes three conjuncts under deliberate signature-byte abstraction. Other numbers (page count 8, 50 fixtures across 10 families, bench 72.051 microseconds CI 71.745-72.367, treaty-intersection 131.67 / 539.75 / 4980.46 at N=1/10/100) cross-check correctly.

### Voice rule grep

The full grep returns one substantive hit: §7 line 14 "the companion paper's **V8 issuer-rotation work** is the **v2 strengthening**." V8 is an internal milestone label, prohibited by the "Paper Voice -- No Engineering-Meta" rule. "Companion paper" and "separate manuscript" appear five times each; these are conventional academic prose, acceptable.

### Em-dash check

`grep -lP "\x{2014}"` against `*.tex` and `bib.bib` returns no hits. Clean.

### Abstract vs §1 contribution consistency

Five-bullet contribution list in §1 corresponds to abstract claims one-to-one. The Lean bullet survives as a fifth contribution; the gate-count inconsistency is inherited from the abstract phrasing.

### Long paper redundancy check

**Major finding R1: §5 "Strict bilateral verifier" paragraph duplicates parent §5 verbatim.** The closing sentence ("Together, the envelope check and the operational check ensure admission depends on the predicate the protocol names, not on a strict subset a sender could satisfy with degenerate data.") is identical word-for-word between the short paper's §5 and the parent paper's §5. The enumerations of what `verify_chiodos_dsse_envelope` rejects and what `bilateral_verifier.rs` layers are near-verbatim. USENIX permits parent-and-short with anonymized citation, but verbatim duplication will read as salami-slicing.

The §6 bench numerics (131.67 / 539.75 / 4980.46 microseconds) come from `\input{bench/results/treaty-intersection-inline.tex}` so the same numbers appear in both papers; honest. §1, §2, §3 formula, §4, §7, §8, §9 do not visibly duplicate parent prose.

### PDF render check

Eight pages render cleanly at 130 DPI. JSON verbatim block on page 2 legible. Table 1 on page 5 fits the right column. §8 paragraphs on page 7 wrap correctly. Page 8 closes mid-bibliography. `paper.blg` zero BibTeX warnings. `paper.log` eight overfull-hbox warnings, all under 16 pt and inside `\codepath{}` or `\thm{}` invocations; visually invisible.

## Substantive findings

**Blocker B1: Gate-count inconsistency (six / eight / three / five).** Detail above. The §3 formula has eight conjuncts, §3 prose says six, §5 / §6 say five, §4 Lean theorem characterizes three, abstract and §1 bullet 5 say six. A Lean-knowledgeable reviewer reading §1 bullet 5's "exactly the six gate predicates" then reading §4's three-conjunct accept relation will write the paper up as misrepresenting its mechanical artifact. Fix: one paragraph in §3 reconciling formula with prose (e.g., "of which `IssuerKeys` and `KernelKeys` membership are abstracted into trust-store conjuncts"), plus rewrite §1 bullet 5 and the abstract clause to either match the §4 three-conjunct Lean abstraction (Draft B's original wording: "trust-store membership and scope-predicate denotation") or to consistently say "six gates" everywhere with the §3 formula rewritten to match.

**Blocker B2: §3 worked envelope contradicts the canonical-encoding paragraph two paragraphs below it.** Wave 3 added a paragraph specifying "sixty-four lowercase ASCII characters with no `sha256:` prefix inside the binding object," but the worked envelope shows nine fields like `"treatyScopeHash": "sha256:7b2a..."` with the prefix. An implementer cannot tell which is canonical. Fix: rewrite the JSON example so the inner binding-object hex fields are bare lowercase without the prefix.

**Major M1: Verbatim §5 self-duplication with the parent paper.** Detail under R1. Fix: paraphrase the §5 "Strict bilateral verifier" paragraph so the same engineering facts surface through different sentences.

**Major M2: V8 engineering-meta voice leak in §7 line 14.** Fix: replace "the companion paper's V8 issuer-rotation work is the v2 strengthening" with venue-neutral prose, e.g. "the companion paper specifies a versioned migration profile that issues envelopes under the new predicate type with explicit lineage."

**Major M3: Signature-verification taxonomy contradiction between §3 and §6.** §3 enumerates five rejection codes; §6 line 16 says a `tampered-signature` fixture "denies on signature verification, distinct from the predicate-type and signer-reuse gates." Either fold signature failure into the §3 taxonomy as a sixth code (helpfully aligning the §3 prose "six gates" with the formula's signature-membership conjuncts), or scope the §3 taxonomy explicitly to "post-signature gates."

**Minor m1: §9 is still 154 words.** Constructive Draft I (schema evolution, key custody and rotation) did not land. Fix: paste Draft I between "Observability gap" and the polity paragraph. Net plus 85 words, lifts §9 to ~240 words.

**Minor m2: README contradicts VENUE-DECISION** on page count and short-paper framing.

**Minor m3: T3 operator-resolution metadata still unspecified.** §3 references "verifier-owned attribution metadata" without definition. One sentence either specifying the source or weakening §3 to keyid-equality with operator-resolution flagged as future hardening.

**Minor m4: S2 adaptive-adversary bound on the rejection-code oracle is missing.** §3 line 68 asserts a flat `log_2 5 ≈ 2.32 bits per attempt`. One-sentence scope to the non-adaptive case and acknowledge adaptive O(5) localization.

## Non-substantive observations

§7's six attack classes are ordered by impact rather than verifier-depth (Draft G's rationale sentence did not land). "Companion paper" appears five times; "separate manuscript" three; could be normalized. Eight overfull-hbox warnings cosmetic only.

## What the paper is now

An eight-page, single-table short paper defending a single cryptographic construction (bilateral DSSE with treaty-bound subject digest, five rejection codes, pre-dispatch admission hook, three-vendor buyer-closure) standalone of the polity / Hart / sovereignty framing of the parent. Wave 3 honestly downgraded §4 to "audit artifact," expanded §8 with per-lineage citations, and added the rejection-code-to-source table. PDF renders cleanly, bibliography is warning-free, voice is mostly clean. Two blockers remain: a load-bearing gate-count inconsistency propagating through every section, and a worked envelope that visually contradicts its own encoding spec. Three majors: §5 verbatim self-duplication with the parent, a V8 voice leak in §7, and a signature-failure taxonomy contradiction between §3 and §6.

## Termination recommendation

One more FIX cycle on the five substantive findings: B1 (gate count reconciliation), B2 (worked envelope JSON), M1 (§5 self-duplication paraphrase), M2 (V8 voice leak), M3 (signature-failure taxonomy). Optionally land Draft I (§9 expansion), the README fix, and the S2 / T3 one-sentence acknowledgements in the same cycle. The five core edits are at most ninety minutes of careful prose. After they land, the paper is submission-ready for USENIX Cycle 2 (Jan 2027).
