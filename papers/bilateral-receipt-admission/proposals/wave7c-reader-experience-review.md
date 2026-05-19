# Wave 7C: Reader-Experience Review (Cold Read)

Date: 2026-05-18
Persona: USENIX Security PC member with crypto + provenance background, no Chio context.

## First-30-seconds skim score

**Overall: 5/10** (rescuable with surgical edits; not currently inviting).

1. *Abstract concrete in 200 words?* **4/10.** Names the problem and primitive, but roughly half its 220 words lean on terms a cold reader has no referent for: "treaty-bound predicate," "ladder-intersection hash," "receipt-graph state," "continuation," "polity," "BBS stub-vs-real disambiguation."
2. *Each contribution bullet names a checkable artifact?* **7/10.** Three of five bullets point at something openable: schema, Rust runtime, Lean file path. "Three-vendor buyer-closure" is named but the reader cannot tell if it is a bench, a corpus, or a live deployment. "Negative-result characterization" is a claim, not an artifact.
3. *Single quotable acceptance sentence?* **6/10.** Best candidate: "the smallest construction that answers [whether two organizations jointly admitted a cross-vendor action]" (§2). Abstract has no equivalent one-liner.
4. *Self-describing title?* **7/10.** Topic and mechanism land. "Bilateral Receipt Admission" and "treaty-bound" are project-internal phrasings; reader wonders whether "treaty" is a metaphor or a defined term.

## Undefined / inadequately-defined terms

- **"Chiodos predicate / profile."** §1 line 5, §3, §5, §6. **Never defined.** Reader infers it is the project name; paper should say so on first use.
- **"Treaty / treaty-bound / treaty scope hash."** Used 30+ times from abstract. Closest gloss is §3's "(participant identities, named action classes, lifetime)" - belongs in abstract or §1, not three pages in.
- **"Ladder / ladder-intersection hash."** Abstract, §1, §3. §3 says "joint mode-coverage decision (which action class was evaluated at which mode under the intersected ladder)." Reader still has no idea what a "ladder" is structurally. One sentence ("A ladder is a totally-ordered set of evaluation modes per action class") closes the gap.
- **"Continuation hash."** §3's gloss "pins linkage to receipt-graph state" is circular since "receipt graph" itself is undefined.
- **"Receipt graph."** Used throughout; not defined. Reader will guess "append-only DAG of signed receipts" and be right, but paper should say so.
- **"Polity."** §3, §4, §6. Never defined here. Reader cannot tell whether it means "organization," a stricter notion, or a jurisdiction model from the companion.
- **"Kernel."** Means "the runtime decision engine inside each organization." A USENIX OS reader will hear "OS kernel" first. §2 should pin: "each organization's *kernel* (the runtime admission engine, not an OS kernel)."
- **"Admission report hash."** §3 binding-tuple defines it adequately.
- **"Cosigner network."** Not used.

## Implicit-knowledge gaps

- **Strict DSSE vs generic DSSE.** §3 contrasts with "generic DSSE provenance" but never says: the contribution is a *strict* verifier that refuses any DSSE bundle not matching this predicate type. One framing sentence at the start of §3 would fix this.
- **Verifier-owned trust store.** Phrase does heavy work and is never defined. Reader needs: "state local to the verifier, configured out-of-band, that names the keys, lease epochs, and treaty manifests the verifier trusts; nothing inside an envelope can mutate it."
- **Companion paper.** Mentioned in abstract and §1, §4, §6, §7, §8, §9 (seven times). The paper never says whether the companion exists as a preprint, anonymized submission, or is hypothetical. **The bib does not cite it.** Either cite it or mark each reference "(under separate submission)."
- **What treaty-binding buys you that two signatures does not.** Conceptual crux the paper never states baldly. Add: "Two signatures over different canonical bytes prove only that two parties signed *something*; treaty-binding via the shared subject digest proves they signed *the same admission decision*."
- **Ed25519 + BBS coexistence.** §2 and §5 say BBS is "presentation-only." Reader who knows BBS as multi-message needs: "We do not use BBS for admission signatures; BBS only signs a projection of the canonical body so a holder can disclose a subset of fields to a third party."

## Section-flow issues

- **§1 to §2.** §1 ends on contributions. §2 reopens with motivation ("Signed-evidence systems decide one of two questions"). Reader was ready for construction; §2 redoes motivation. Open §2 with the four-concern decomposition directly.
- **§3 to §4.** §3 closes on rejection-code leakage ("$\log_2 5 \approx 2.32$ bits"). §4 opens "The verifier of §3 admits a machine-checkable transcription in Lean 4." Non-formal-methods reviewer asks "why Lean now?" Add one sentence: "To pin the informal predicate to a mechanical object that cannot silently drift as the schema evolves..."
- **§6 to §7.** §6 ends "every disagreement is named by exactly one rejection code." §7 opens with six attack classes. Reader saw five codes, now sees six attacks; relationship is unstated. Add: "Each attack maps to one or more of the five rejection codes, plus two classes whose defense is structural."
- **§5 internal.** "Stub disclosure" paragraph at end of §5 lands strangely: a paper about a cryptographic primitive closes implementation with a macOS Endpoint Security stub. Move to §9.

## Visual / format observations

- **§3 worked envelope (p2).** Readable, fits column width, hex truncations work.
- **Accept-set align block (p3).** Tight but readable; (G3)/(G4) grouping parseable.
- **§4 Lean theorem (p4).** `freestanding_accept_set_theorem` awkwardly hyphenated by `\seqsplit` but legible.
- **Table 1 (p5).** Path `bilateral_dsse.rs:996` repeats five times; cite once and drop repetition.
- **Citations.** No `[?]` artifacts. Bib has 71 entries.
- **Footnotes.** None observed; no orphans.
- **§6 Evaluation (p6).** Dense unbroken prose with no figure relief. Consider a small latency table.

## Cold-read paraphrase

A reasonable USENIX reviewer would say: *This paper proposes a new DSSE predicate type for two-organization cross-vendor agent invocations. The subject digest binds a ten-field tuple; a strict verifier accepts iff six gates hold and emits one of five rejection codes otherwise. The construction is implemented in Rust with a pre-dispatch admission hook, and a Lean file transcribes a stripped three-gate version of the accept relation whose only kernel axioms are propext + choice. A three-vendor buyer-closure exercises admit/deny paths with $\sim$72$\mu$s median admission latency (dominated by the local policy path, not the bilateral DSSE primitive). The paper claims by-construction defense of six attack classes including sibling-treaty cross-receipt substitution and signer reuse, with frequent forward-references to a companion paper addressing higher-layer constitutional questions.*

## Gap between cold-read paraphrase and stated claims

Small but real. Two of the six §7 attack classes (schema-version downgrade migration, constitutional ratchet) are partially or wholly deferred to the companion paper, so the abstract's "structural composition of the rejection codes" only covers the in-scope subset. Also: the abstract names the Lean module as witnessing the conjunction-of-six, but §4 walks back from six gates to three abstract gates with four runtime gates "treated as preconditions of the trust-store conjuncts." The abstract should say "transcribes the accept relation at a three-gate structural level in Lean."

## Recommended additions / clarifications (priority order)

1. **(High)** Add a one-paragraph glossary at the end of §1 or start of §2 defining: treaty, ladder, kernel (the agent runtime, not OS), receipt graph, polity, Chiodos. Six sentences total. Single change that rescues most readability complaints.
2. **(High)** Resolve the companion-paper reference. Either cite it (preprint, anonymized submission) or mark each occurrence "(under separate submission, anonymized for review)." Currently the reader has no protocol for "trust me, the next-layer claims exist."
3. **(High)** Add one sentence to the abstract or §1 stating the intuitive crux: "Two signatures over different canonical bytes prove only that two parties signed *something*; treaty-binding via the shared subject digest proves they signed the *same admission decision* over the same context."
4. **(Medium)** Adjust the abstract Lean sentence to "transcribes the accept relation at a three-gate structural level" rather than implying Lean witnesses all six runtime gates.
5. **(Medium)** Add the "why Lean" framing sentence at the §3-to-§4 transition.
6. **(Medium)** Move §5's macOS Endpoint Security stub paragraph into §9 so the implementation section closes on the cryptographic primitive, not a platform stub.
7. **(Low)** Bridge the five-codes-vs-six-attacks count at the §6-to-§7 transition. One sentence.

## Overall reader-experience verdict

**needs-light-edits.** The paper is technically complete and the contribution is real; a USENIX reviewer can recover the argument cold. But the first 30 seconds will not sell it: the abstract leans on undefined Chio-internal vocabulary, and seven references to a companion paper that is not cited will read as either anonymization noise or hand-waving. None of the issues require a rewrite; the seven recommendations above are surgical insertions of one to three sentences each. With those, the same reviewer who scores this at 5/10 on the 30-second skim would likely score it at 8/10.

---

### Summary for caller

1. **First-30-seconds skim score:** 5/10 (4/7/6/7 across four sub-questions).
2. **Most damaging implicit-knowledge gap:** Seven uncited references to a "companion paper" - the cold reader has no anchor for what exists, what is claimed, or whether it is anonymized. Largest single source of reviewer skepticism.
3. **One-sentence verdict:** The paper's content is acceptance-grade but its presentation assumes Chio-internal vocabulary in the abstract and §1; surgical edits (define six terms, resolve the companion reference, add one crux sentence) would convert a hesitant reviewer to a confident one.
