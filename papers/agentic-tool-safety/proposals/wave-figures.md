# Wave Figures: TikZ Diagrams for agentic-tool-safety

## Summary

Two TikZ figures were added to the workshop paper. Both render without errors, all references and citations resolve, and the build remains at 13 pages (within tolerance; figures absorbed prior whitespace rather than expanding the page count).

## Figure 1: Tool-call lifecycle (§4)

Placement: `sections/04-formal-grammar.tex`, immediately before the "four operations" paragraph, where the gates are first defined. The figure appears on page 5 of the rendered PDF and is referenced from both `§4` (anchor paragraph) and `§5` (worked example, indirectly through the gate codes it walks through).

Visual structure: a left-to-right horizontal flow showing the envelope entering four diamond gates (capability, class, TTL, rollback slot), each with a "pass" arrow forward and a dashed red "fail" arrow down to a rejection-receipt box (`cap-denied`, `class-mismatch`, `ttl-invalid`, `rollback-missing`). The four rejection boxes are fitted inside a dashed red container captioned "rejection receipt with named code". The pass path terminates at a green "Executed + receipt" box. Gate numbering matches the §4 prose exactly.

Label: `\label{fig:tool-call-lifecycle}`. Cross-reference added to the §4 prose.

## Figure 2: Orthogonal composition (§7)

Placement: `sections/07-discussion.tex`, immediately before the "Three composition pairs, named precisely" paragraph. This is the strongest anchor: the prose enumerates the exact pairings the figure illustrates. Cross-reference also added from `§1` introduction at the first mention of composition. The figure appears on page 10.

Visual structure: an envelope box on the left feeds two coloured layers (blue training-layer, orange admission-layer) in series. The training-layer box lists Constitutional AI, RLHF, alignment-faking research, scalable oversight, debate. The admission-layer box lists positive TTL, typed rollback witness, bilateral cosignature (irreversible), substrate-issued receipts. A green "Executed action" box receives the pass path; a red "Rejection receipt" box receives the fail arrows from both layers, captioned "either layer refuses".

Label: `\label{fig:orthogonal-composition}`.

## Preamble

Added to `paper.tex`:

```
\usepackage{tikz}
\usetikzlibrary{arrows.meta, positioning, shapes.geometric, calc, fit, decorations.pathreplacing}
```

## Build verification

```
errors: 0
undef cites: 0
undef refs: 0
overfull: 0
Pages: 13
```

The figure ordering in the PDF follows order-of-appearance: §4 lifecycle is Figure 1 (page 5), §7 composition is Figure 2 (page 10). All four cross-references resolve to the correct numbers. House rules respected: no em dashes, no engineering-meta voice, anonymous, workshop register.

## Redesign pass

Both figures were redesigned to fix specific layout and semantic problems.

Figure 1 was too compressed: external gate labels were cut off, the gate diamonds were too small to carry the gate name internally, and the four bottom rejection-code labels were cramped. The redesign widens the layout (node distance 10mm between gates, with `\resizebox{\textwidth}{!}` so the wider tikzpicture still fits the column), enlarges each diamond (minimum width 26mm, height 14mm) so the gate name fits inside ("Gate 1 capability", "Gate 2 class", "Gate 3 TTL > 0", "Gate 4 rollback slot"), and gives each rejection-code box its own dedicated minimum width with 16mm vertical separation from the gate above. The pass arrows carry "pass" labels above; the dashed red fail arrows carry an italicised "fail" label to the right of each downward arrow. The four rejection-code boxes remain grouped inside a dashed red `fit` container captioned "rejection receipt with named code".

Figure 2 was the bigger semantic fix: the previous figure was a LINEAR FLOW (envelope to training-layer box to admission-layer box to executed-action, with rejection arrows pointing down), which showed the two layers in series and did not convey orthogonality at all. The caption claimed orthogonality; the visual contradicted it. The redesign builds a genuine 2D plane: Training-layer safety on the horizontal axis with bullet ticks distributed along it (Constitutional AI, RLHF, alignment-faking research, scalable oversight, debate); Admission-layer safety on the vertical axis with bullet ticks distributed along it (positive TTL, typed rollback witness, bilateral cosignature, substrate-issued receipts). Dashed grey gridlines partition the plane into four quadrants. The upper-right quadrant is the green "Executed action / both axes cleared" cell; the other three quadrants are red dashed rejection cells ("Training-layer refusal", "Admission-layer refusal", "Refusal on both axes"). The geometry now carries the claim: orthogonal axes, conjunction at upper-right, three failure modes in the other three quadrants.

Post-fix build: 0 errors, 13 pages. Figure 1 is on page 5, Figure 2 is on page 10. Rendered PNGs verified at 200 DPI for both pages.
