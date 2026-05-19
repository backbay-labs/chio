# Wave: Figures (variant matrix + TTL-window state diagram)

Two figures landed in `paper.tex` per the figure brief. Build is clean: 0 errors, 0 undefined references, 16 pages.

## Preamble

`\usepackage{tikz}` plus `\usetikzlibrary{arrows.meta, positioning, shapes.geometric, calc, fit, decorations.pathreplacing}` was inserted in the existing usepackage block (after `underscore`, before `hyperref`). No other preamble change.

## Figure 1: action-variant matrix (sec 3 substrate)

Placed in `sections/03-substrate.tex`, immediately after the "partition is structural rather than operational" paragraph that gives the canonical reversibility examples (file rename, SIGSTOP/SIGCONT). The variant-by-witness table belongs in section 3 because that section enumerates the action taxonomy; section 5 only re-describes the deployment dispatch.

Implemented as a `booktabs` + `tabularx` table rather than a TikZ matrix. The content is dense text (witness descriptions like "content-hash-gated restore", "SIGCONT (substrate-issued capability)") that reads cleaner in tabular form than in a TikZ grid. Four columns: variant, class, rollback witness, TTL behavior. Five rows: the four reversible variants plus process-tree terminate as the destructive case.

Cross-reference added: "Figure~\ref{fig:variants} summarizes the five operational variants and the shape of the rollback witness each admits." Appended to the existing paragraph, no new paragraph break.

Caption uses the brief's text verbatim. Label is `fig:variants`.

## Figure 2: TTL-window state diagram (sec 4 model)

Placed in `sections/04-model.tex`, immediately after the `activeAt` definition's "case split is a substrate-level abstraction" paragraph, which introduces the TTL-window semantics in prose. Figure follows the math display.

Implemented as a TikZ horizontal timeline. Components: a left-to-right time axis with two tick marks at $t_0$ and $t_0 + T$; two shaded regions (blue in-window, gray expired) labeled with their `activeAt` value and the rollback-witness state; two top arrows pinning the admission event and the auto-revert event; a `decorations.pathreplacing` brace under the in-window span annotating the per-step `BackwardRefines` claim and the composition theorem reference.

Cross-reference added: "Figure~\ref{fig:ttl-window} illustrates the evolution of an admitted amendment across the window boundary." Appended to the existing paragraph.

Caption uses the brief's text. Label is `fig:ttl-window`.

## House-rule compliance

No em dashes used. No engineering-meta voice in captions. No author identifiers (Anonymous title preserved). The single overfull hbox warning in the build log is pre-existing (long math display at section 4 rollback admissibility, untouched by this wave).
