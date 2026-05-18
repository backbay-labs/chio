# Post-execution review 3

Date: 2026-05-17
Scope: Third fresh-eye review with special focus on engineering-meta voice.

## New issues found

### Issue 1: §7 discussion opens with engineering-status-report voice ("The construction defended here supplies...")
**Severity**: major
**Where**: `sections/07-discussion.tex:4` (first paragraph after the §7 header)
**Problem**: The §7 opening reads "The construction defended here supplies a treaty scope type, a ladder-intersection artifact, ..." followed by "The claim defended is that Chio can instantiate ...". This is engineering-meta voice — a project-status cadence ("the construction defended here", "the claim defended is") narrating what the paper has done rather than asserting what is true about the system. The same paragraph used to open with the "v1.1 Chiodos concept note" sentence the user excised; the replacement still leaks the same voice. The Discussion opener should make a substantive claim, not audit the paper's contribution bullets.
**Suggested fix**: Recast as a direct property statement: "Chio instantiates receipt-bounded polities whose laws are executable predicates and whose external relations are admission contracts; a treaty scope type, ladder-intersection artifact, cross-kernel continuation, bilateral-invocation binding, admission hook, BBS selective-disclosure mechanism, multi-lane anchor, and bounded Lean model realise that claim." Drops "defended here / claim defended".

### Issue 2: §3 "The live implementation sets..." is engineering-meta voice
**Severity**: major
**Where**: `sections/03-substrate.tex:16` (Bilateral DSSE paragraph)
**Problem**: "Cross-organization actions use a strict Chiodos predicate profile over a DSSE envelope. The live implementation sets `PREDICATE_TYPE_CHIODOS_BILATERAL` to `chio.bilateral-cosign-invocation.v1` and ..." The phrase "the live implementation sets X to Y" reads as a changelog / project-status note (compare "the live Chiodos branch" the user already flagged). The substance is fine; the framing presents protocol content as "what the live tree currently does" rather than "what the substrate requires."
**Suggested fix**: "The protocol pins `PREDICATE_TYPE_CHIODOS_BILATERAL` to `chio.bilateral-cosign-invocation.v1` and defines a treaty binding reference over ..." The predicate type is a protocol fact, not a current-state observation.

### Issue 3: §6 "paper build loop tractable" and "the codebase contains" leak engineering-process voice
**Severity**: major
**Where**: `sections/06-evaluation.tex:38` ("The codebase contains receipt-shaped benchmark scaffolds...") and `:53` ("a small sample count chosen to keep the paper build loop tractable")
**Problem**: Both sentences narrate the author's engineering process: "the codebase contains scaffolds whose bodies do not yet measure" sounds like a TODO in a project README, and "chosen to keep the paper build loop tractable" tells the reader about the author's continuous-integration constraints rather than about experimental design. A peer-reviewed systems paper does not say "the codebase contains X" or "the paper build loop".
**Suggested fix**: §6:38 → "Receipt-shaped benchmark scaffolds exist whose bodies black-box a constant; reporting their numbers would manufacture a measurement." §6:53 → "The dispatch number uses a Criterion sample count chosen for reproducibility on the baseline machine." Substance survives both rephrases.

### Issue 4: §6 replay paragraph uses repo-internal jargon ("checked-in fixtures", "checked-in golden", "bless recipe", "release-engineering matrix")
**Severity**: major
**Where**: `sections/06-evaluation.tex:41` (replay paragraph)
**Problem**: Four phrases in one paragraph leak engineering-meta voice: "50 checked-in fixtures", "canonicalised against a checked-in golden", "reproducibility of the bless recipe", and "release-engineering matrix exercises additional surfaces". "Checked-in" is git-internal language (on the user's banned list). "Bless recipe" is an internal CI verb the reader does not know. "Release-engineering matrix" reads like an SRE document, not a method section.
**Suggested fix**: "checked-in fixtures" → "fixtures distributed with the runtime"; "checked-in golden" → "stored golden manifest"; "reproducibility of the bless recipe" → "reproducibility of canonical verdicts"; "the release-engineering matrix exercises additional surfaces" → "additional fixture families are exercised separately."

### Issue 5: "v1 treats" / "v2 kernel-independence" / "remains v2 work" leak project-versioning meta voice
**Severity**: minor
**Where**: `sections/04-model.tex:62`; `sections/09-limitations.tex:20,21`; `sections/03-substrate.tex:37`
**Problem**: Several places frame design decisions as "v1 treats X / v2 will do Y" (e.g., "which v1 treats as an operational-discipline assumption", "v2 kernel-independence attestation", "remains v2 work; v1 binds the predicate as a non-amendable axiom", "deferred to v2"). This reads as project-release planning rather than substrate-property statement. The substantive content is fine; the labelling reads as project history.
**Suggested fix**: Replace "v1 treats" → "the present construction treats". Replace "v2 kernel-independence attestation" → "kernel-independence attestation as a future substrate primitive". Replace "remains v2 work; v1 binds the predicate as a non-amendable axiom" → "is future work; the present construction binds the predicate as a non-amendable axiom". Same swap for "deferred to v2" → "left as future work". Content preserved; the project-versioning frame removed.

### Issue 6: §1 "the workspace proof root" is repo-internal language
**Severity**: minor
**Where**: `sections/01-introduction.tex:3`
**Problem**: §1 line 3 ends "attested by a named Lean theorem under the workspace proof root, and signed into a canonical receipt admitted only when the constitution and the scope accept." "The workspace proof root" is git-monorepo language (cf. `lake build` workspace structure). A reader outside the project doesn't know what a "workspace proof root" is; the substantive claim is just "attested by a named Lean theorem".
**Suggested fix**: Drop "under the workspace proof root" — "attested by a named Lean theorem, and signed into a canonical receipt..." with no loss of content.

### Issue 7: Six @misc bib entries still carry year={2026} for clearly older artifacts
**Severity**: minor
**Where**: `bib.bib` entries `fuchsiaCapabilities` (line 99), `projectEverest` (141), `sigstoreSecurity` (175), `rekorGithub` (182), `slsa` (207), `compoundGov` (244), `polkadotOpenGov` (251)
**Problem**: P2-I3 flagged these as mismatched; the action-plan deferred them as "stylistic". But each artefact predates 2026 by 1-9 years: Compound Governor Bravo (2020), Polkadot Gov2 (2023), SLSA 1.0 spec (2022), Sigstore (2021), Rekor (2021), Fuchsia CFv2 capabilities (2020), Project Everest (2017). `year=2026` on each misrepresents these as 2026 references; with the rest of the bib clean, this is the visible remainder.
**Suggested fix**: Set `year` to first-publish year and add `note = {Accessed 2026}` (or use `@online`+`urldate`).

### Issue 8: §5 Table 2 cites `treaty.rs:455` for `treaty_admission_iff_predicate_intersection`, but §4 prose pins the same theorem's production counterpart at `treaty.rs:264`
**Severity**: minor
**Where**: `sections/05-implementation.tex:63` (Table 2 row 1) vs `sections/04-model.tex:45`
**Problem**: §4:45 says "The production counterpart at `treaty.rs:264` validates treaty scope, freshness, manifest coverage, declared participant hashes, ...". Table 2 in §5 maps the same theorem to `treaty.rs:455`. A reviewer who cross-checks the proof-to-code map against the §4 prose finds two different anchor lines for the same theorem within the same paper.
**Suggested fix**: Pick one canonical anchor and use it in both places. If both lines are correct entry points for different aspects (e.g., :264 is the scope validator while :455 is the admission entrypoint), distinguish them in the table column rather than letting the reader infer.

## Summary

Eight new issues. Four are engineering-meta voice (Issues 1-4) — the dominant remaining defect class: the paper still narrates project state ("the construction defended here", "the live implementation", "the codebase contains", "the paper build loop", "checked-in fixtures", "bless recipe", "release-engineering matrix"). Issue 5 is a minor variant (v1/v2 framing). Issue 6 is "the workspace proof root" in §1. Issue 7 leaves six @misc entries with cite-year 2026 for artefacts that predate 2026 by 1-9 years. Issue 8 is a line-anchor drift between §4 and §5 for the headline theorem. None alone is borderline-accept-to-reject, but Issues 1-4 are the same defect class the user has flagged repeatedly; closing them is the difference between "still sounds like a project changelog in places" and "reads cleanly as systems-paper prose throughout."

Verdict: 8 issues remain.
