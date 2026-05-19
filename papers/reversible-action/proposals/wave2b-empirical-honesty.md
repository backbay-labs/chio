# Wave 2B: empirical-honesty fixes

Six fixes against the Wave 1B/1A/1C findings on the reversible-action
draft. File scope: `paper.tex` abstract block, `sections/05-implementation.tex`,
`sections/06-evaluation.tex`, `sections/09-limitations.tex`. Build:
0 LaTeX errors, 15 pages (no page count change). No em dashes
introduced. Inline thebibliography retained; no bibtex run.

## 1. Abstract: content-hash-gated qualifier and composition-theorem
   hedge

The abstract previously asserted that all four reversible variants
carry "content-hash-gated rollback constructors." Per the code (and
the matching §5 hedge), only the file-class pairs (quarantine,
persistence-disable) are literally content-hash-gated; process-tree
suspend uses SIGSTOP/SIGCONT, and egress restriction uses a policy
snapshot. The abstract now reads "with the file-class variants gated
on content-hash parity against the recorded forward artifact and the
process- and network-class variants gated on substrate-recorded
inverse witnesses." The composition-theorem sentence is prefaced
with "Subject to mechanized confirmation," matching the README's
"plausibly non-rfl" framing rather than asserting a discharged proof.

## 2. §9: third missing-rollback executor corrected

Per Wave 1B's code cross-check, the three forward executors with no
inverse are process-tree-terminate, revoke-grant, and collect-evidence;
the §9 bullet previously named "network isolate" as the third, which
is incorrect (network isolate / egress-restriction is one of the four
reversible variants). The bullet now reads "Process-tree terminate,
grant revoke, and evidence collection are destructive."

## 3. §6: append-after-effect race named in the chapter

The Wave 1B finding noted the race was acknowledged in §9 but absent
from §6; a reviewer who stops at §6 would see "rollback closes the
chain" without the crash-window caveat. A 75-word paragraph follows
the "Forward and rollback latency" paragraph stating that the OS
primitive runs before the ledger append, naming the crash window,
referencing §9, and pointing to the write-ahead redesign that closes
the gap.

## 4. §6: measurement-honesty caveats

A 130-word paragraph after the lead sentence states explicitly that
the figures are point measurements on a single workstation (Apple
Silicon, macOS 14.x, Darwin 23.x kernel) rather than statistically
confident measurements; names the substrate-side reproducibility
property; and lists the deployment requirement for USENIX-grade
evaluation (N$\geq$30 per cell, documented hardware matrix, stated
warm-up policy, confidence intervals). The chapter no longer reads as
a measurement plan that quietly poses as a measurement chapter.

## 5. §5 voice slip and §9 voice fixes

Three changes from Wave 1C. §5: "the response engine does not yet
wire" became "the response engine is not wired against." §9 rfl-gate
bullet: "Confirmation requires a focused Lean session" became
"Mechanized confirmation is required"; "the paper has no headline"
became "no headline result remains"; "is plausibly non-rfl in this
construction's reading" became "is plausibly non-rfl" with the
substantive reason kept inline.

## 6. Out of scope and residual risks

Wave 1A's deeper finding (Candidate 3 is non-rfl but pointwise rather
than inductive, and Candidate 4 does not mechanically compose with it)
is a Lean-side concern outside this wave's file scope. The remediation
options (weaken `h_chain_base` to a `BackwardRefines` hypothesis, or
add explicit induction over the chain; supply the syntactic-to-closure
bridge) belong in a separate wave that touches `theorems.lean` and §4.
The anonymity-via-theorem-names concern from Wave 1C is also unmodified
here; both are flagged for follow-up.
