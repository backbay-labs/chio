# Proof-Carrying Bilateral Admission

LaTeX source and reproducibility materials for "Proof-Carrying Bilateral
Admission for Cross-Organization Agent Tool Calls," targeting USENIX Security
2027, Cycle 1.

The USENIX submission build is:

```sh
make submit-check
```

The gate performs the complete LaTeX and BibTeX build, checks references and
citations, and enforces the 13-body-page limit. `paper-usenix.tex` is the
submission source; `paper.tex` is the ACM-style fallback.

The paper's formal and empirical evidence is pinned in
`supplementary/artifact-manifest.json`. From the repository root, validate the
manifest and independently rebuild its Lean archive with:

```sh
bash scripts/check-programmable-sovereignty-artifact.sh
```

For proofs, focused tests, experiments, and the PDF in one pass:

```sh
bash scripts/check-programmable-sovereignty-artifact.sh --full
```

The manuscript's strongest allowed wording is maintained in
`CLAIM_LEDGER.md`. In particular, Lean proves properties of an explicit bounded
model, the Rust relation is differential alignment, two keys do not establish
two organizations, and programmable sovereignty denotes authority only over a
receiver's local receipt-admission boundary.
