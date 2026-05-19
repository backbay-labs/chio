# Wave 2A: Figures landed

Two load-bearing figures added to the sensor-grounded-admission paper. TikZ enabled in both shells (paper.tex and paper-usenix.tex) via `\usepackage{tikz}` and `\usetikzlibrary{arrows.meta, positioning, shapes.geometric, calc, fit, decorations.pathreplacing}`.

## Figure 1: Sensor-state attestation field layout

Lands in §3 (`sections/03-substrate.tex`), immediately after the "Sensor-state attestation" paragraph and before "Clock state." A new sentence at the end of that paragraph cross-references the figure ("Figure~\ref{fig:attestation-layout} shows how the per-provider records sit beside the body inside the signed envelope.").

The diagram is a column-width `\begin{figure}` showing:
- Outer signed envelope rectangle (DSSE, Ed25519).
- Receipt body block with canonical-JSON field list.
- Sensor-state attestation block with a four-row sensor table (endpointSec, networkExt, sigDrift, supplyGuard) carrying installed/active/healthy/degraded flags and drop/miss counts. Below the table: the clock record and the substrate key id.
- Signature block over the canonical-JSON subject digest.
- A left-side brace (amplitude=7pt, raise=1pt, mirror) covers body and attestation jointly, with the legend "body and attestation both covered by subject digest".

Column-width fit was the main constraint. The Wave 1A sketch put the brace on the right at amplitude=4pt; that would have been invisible at USENIX column width. The published version moves the brace to the left margin space at amplitude=7pt so it renders crisply at 200 DPI and stays inside the column. Flag column headings were shortened to single letters (i/a/h/d) to fit at USENIX 10pt; the caption decodes them.

## Figure 2: Admission decision tree

Lands in §4 (`sections/04-model.tex`), at the end of the "Ladder structuring" paragraph. A new sentence integrates the cross-reference ("Figure~\ref{fig:admission-decision-tree} renders the resulting three-way verdict as a single traversal over the attestation.").

This is the load-bearing figure per Wave 1A's priority ranking. Structure as a `\begin{figure*}` (full text width) because the three-decision spine plus three side-verdicts does not fit one USENIX column:
- Root box: receipt arrives.
- Diamond 1: parses and verifies? -> No: red refuse box (attestation_parse_failed). Yes: down.
- Diamond 2: required set covered? -> Yes: green admit (receipt-backed mode). No: down.
- Diamond 3: strict-sublist relation? -> Yes: yellow admit (partition-contingency, reconciliation obligation). No: red refuse (required_set_uncovered).
- Edges labeled yes/no with white-fill labels.

Color semantics: green (accept) for receipt-backed, yellow (caution) for partition-contingency, red (refuse) for both refusal paths. The verdict boxes name the typed denial codes directly so a reader can map the figure onto §5's evaluator outputs without rereading the model.

## Build state

- Article (`paper.tex`): 0 errors, 0 overfull boxes, 20 pages (was 18). 4 undefined-citation warnings (pre-existing, not introduced by this wave).
- USENIX (`paper-usenix.tex`): 0 errors, 0 overfull boxes, 14 pages (was 12). 4 undefined-citation warnings (pre-existing).
- Figure 1 lands on USENIX p.4 / article p.5; Figure 2 lands on USENIX p.7 / article p.9. Both rendered at 150-200 DPI and visually confirmed: braces visible, diamonds aligned, color fills intact, no clipping.

No em dashes introduced. No engineering-meta voice in captions; both captions describe what the figure is, not how the project produced it.
