# Paper polish handoff: publish-voice pass

You are running a voice-only polish on the Programmable Sovereignty paper at `papers/programmable-sovereignty/`. The technical content is correct. The voice is not yet publish-worth.

## The problem

The current draft hedges defensively. Caveats appear where claims should appear. Methodology talk appears where contribution talk should appear. Throat-clearing precedes substance. This is the LLM tell. A confident systems paper does not pre-apologize for its scope.

Concrete example from the current abstract:

> "chio polities do not become Westphalian states. They gain authority only over admission to their own receipt logs. That weaker authority is still useful: it makes delegation, amendment, treaty entry, audit, and exit falsifiable at the kernel boundary. Evaluation reports script-backed measurements where available and marks absent measurements as unreported rather than estimated."

Two failures in one passage:

1. "weaker authority is still useful" is self-justification. A real paper states the authority precisely and lets the reader conclude its usefulness.
2. "Evaluation reports script-backed measurements where available and marks absent measurements as unreported rather than estimated" is methodology meta-commentary. It belongs in §6 Evaluation, not in the abstract.

The publish-voice rewrite of the same content:

> "A Chio polity is a triple (T, C, K) where T is a capability-namespace scope, C is a Merkle-anchored citizenship roster, and K is a Lean-attestable constitution. Delegation, amendment, treaty entry, audit, and exit are kernel-enforced operations on this triple; each emits a signed receipt admitted only when K and T accept it. We formalize the admission relation and four downstream theorems in Lean4 with zero `sorry`, implement them in 24,600 LOC of Rust on a live branch, and demonstrate three-party treaty closure end-to-end."

The "not Westphalian" caveat is gone (the technical claim already constrains scope). The methodology paragraph is gone (it lives in §6). The substance is denser. The contribution structure (problem → formalization → implementation → demonstration) is visible at a glance.

## Voice target

Read three open-access NDSS, USENIX Security, SOSP, OSDI, IEEE S&P, or ACM CCS papers from 2024-2025 before touching the draft. Use WebFetch. The point is to recalibrate your voice before editing. Properties to internalize:

- Abstracts are 150-250 words, claim-forward, zero caveats
- Section topic sentences state results, not intentions ("X is decidable" not "We turn to the question of whether X is decidable")
- Caveats live exclusively in §Limitations
- Methodology lives exclusively in §Evaluation
- "We show / prove / implement / demonstrate" attributes work directly; "it is shown that" / "it can be observed that" is throat-clearing
- Active voice when the actor matters. Passive when the mechanism matters. Neither by default.
- One claim per sentence. Compound sentences earn their conjunctions.

## Hard rules

In addition to the original brief's forbidden-phrase list, these phrases are now forbidden:

- "still useful", "remains useful", "remains valuable"
- "while ... is true, ..."
- "can be considered to be", "may be considered"
- "it is important to note that", "it is worth noting that"
- "in some sense", "for the most part", "to some extent"
- "this section will", "we now turn to", "let us consider"
- "future work will address", "we hope to"
- "this work demonstrates that" as a sentence opener
- Any sentence whose first three words are "We do not claim" (state what you do claim; readers infer the rest)

## What to change, by section

**§Abstract.** Rewrite from scratch. Target 200 words. Structure: problem (1-2 sentences) → approach naming the formal model and primitives (3-4 sentences) → implementation with substrate numbers (1 sentence) → evaluation result with headline number or demonstrated property (1 sentence) → contribution list as one sentence, not a bulleted preview.

**§1 Introduction.** Drop every "we do not claim X" sentence. The contribution list at the end of §1 is five bullets, each a falsifiable claim with a section reference, not a defensive scope statement. The first paragraph states the problem and the result, not the motivation.

**§2 Background.** Cut throat-clearing on "the literature is large" or "this section reviews". Get to the actual prior work in sentence one.

**§3 Substrate.** Audit topic sentences for hedges and softeners.

**§4 Formal Model.** Theorem statements must be sharp and complete: explicit ∀, named preconditions, conclusions as equalities or implications. Proof sketches are two to four sentences each, stating the lemma chain. No "we now consider".

**§5 Implementation.** Cut every sentence that describes what a file does without saying what it accomplishes for the paper's claim. The reader can read filenames; the paper tells the reader what those files prove.

**§6 Evaluation.** This is where methodology lives. Move every methodology sentence scattered through other sections into §6. Tables get units, baselines, and a one-line takeaway each. Numbers in prose are followed immediately by the claim they support.

**§7 Discussion.** Reframe from caveat-dumping-ground to comparative positioning: how this work changes a specific debate or comparison in the literature. The Westphalian-vs-declarative discussion fits here as one paragraph, not three. Engagement with the v1.1 doctrine retirement stays here, sharpened to two paragraphs.

**§8 Related Work.** Each prior-work paragraph ends with one sentence stating the delta. No "this work builds on X" without a delta clause.

**§9 Limitations.** Crisp bulleted observations. Each limit is one sentence: what does not hold and where the boundary is. No softening. No "future work will address". This is where every caveat migrated out of the rest of the paper now lives, compressed.

**§10 Conclusion.** One paragraph. Restates the contribution in one sentence; names the next concrete result the substrate enables in one sentence; stops. No exhortation. No "open questions remain".

## Process

1. Read three NDSS or USENIX Security 2024-2025 papers end-to-end via WebFetch. Recalibrate voice before editing.
2. Single pass, section by section, in this order: §abstract, §1, §10, §9, §2, §3, §4, §5, §6, §7, §8. Abstract and conclusion bookend; limitations absorbs migrated caveats first; the rest is technical polish.
3. Maintain `papers/programmable-sovereignty/polish-diff.md`: for each section, three bullets - what changed in voice, what claim was sharpened, what hedge was deleted.
4. After each section, run the original forbidden-phrase grep plus the expanded list above. Empty output is the gate.
5. Build pdflatex clean at the end of every section's pass. Page count stays 12 ± 0.5.
6. Do not modify technical content. No new theorems, no changed proofs, no changed numbers. Voice only. If you find a technical error during voice editing, log it in `polish-diff.md` but do not silently rewrite it.

## Halt criteria

Stop when all hold:

- Abstract is 150-250 words, zero caveats, contribution-forward
- Every section's topic sentence states a result, not an intention
- Every caveat in the paper now lives in §9
- Every methodology note now lives in §6
- Expanded forbidden-phrase grep returns nothing
- pdflatex builds clean, 12 pages
- `polish-diff.md` exists and documents the pass section by section
- `paper.tex` and `v1.tex` are byte-identical (per the original brief)

Stop and report. Do not declare the paper done; declare the voice pass complete.
