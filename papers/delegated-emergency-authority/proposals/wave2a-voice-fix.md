# Wave 2A: Page-1 voice fixes (abstract + §6)

Targeted prose surgery on two REJECT-RISK items Wave 1D flagged. Scope limited to
`paper.tex` (abstract block only) and `sections/06-implementation.tex`.

## Abstract changes

Word count: 420 before, 448 after (per `wc -w` on the extracted abstract block).
The +28 reflects the added normative-payoff sentence Wave 1D §5 recommends.
Five CS-tells from Wave 1D §5 were replaced:

1. "proof-carrying programmable governance" -> "machine-checkable governance receipts"
   (Wave 1D §5 line 72).
2. "in the well-typed sense" -> "as a matter of construction" (Wave 1D §5 line 70).
3. "fails to type-check" (abstract instance) -> "the construction itself fails"
   (Wave 1D §5 line 71). Body uses are retained as the audit allows.
4. "develops the grammar against five case studies" -> "applies the grammar to
   five case studies" (Wave 1D §5 line 73).
5. Added closing normative sentence verbatim from Wave 1D §5: "The Article's claim
   therefore is not abolition or expansion of any particular emergency authority
   but reformulation: any future grant should be enacted with the four-component
   grammar this Article specifies."

"Structural defect" was not present in the abstract block; nothing to trim.
Three-paragraph structure preserved. No em dashes introduced.

## Section 6 changes

Word count: 858 before, 99 in body plus 83 in a single footnote after. Total
compression to roughly 21 percent of the original, with technical specifics
relocated to the footnote a legal reader can ignore.

The compressed body paragraph follows Wave 1D §4's recommended language nearly
verbatim, with the em dash replaced by a parenthetical per the standing rule.
Items removed from the body and not re-introduced anywhere:

- "security platform" framing and EDR parenthetical (Wave 1D §4 line 49).
- SIGCONT / egress allowlist / network policy reversion specifics (Wave 1D §4
  line 52). These now appear, briefly, in the footnote without UNIX signal
  vocabulary.
- "device-level signature and operator-level signature within a specified time
  window" (Wave 1D §4 line 53). The footnote refers only to "concurrent
  device-level and operator-level signatures within a bounded window."
- The second observation block on "operationally observable artifact"
  (Wave 1D §4 lines 56-57). The substantive point is preserved in one footnote
  clause: "Each admitted action emits a signed receipt that is auditable in
  canonical form."

The four-tuple math notation $(\text{act}, \TTL, w, q)$ was removed from §6 prose;
the notation remains in §4 (where the grammar is formally introduced) and §5.

## Build verification

`pdflatex -interaction=nonstopmode paper.tex` exits non-zero with twelve `^!`
lines, all pre-existing `\text{...}` invocations in §4 and §5 that lack an
`amsmath` import. None of the twelve errors come from the files in this wave's
scope; §6 no longer contains any `\text` calls. The PDF still rebuilds and
`pdfinfo paper.pdf` reports 19 pages (down from 20). The pre-existing `\text`
failures are flagged for a separate pass.
