# Receiver-Owned Bilateral Admission

LaTeX source and reproducibility materials for "Receiver-Owned Bilateral
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

`CLAIM_LEDGER.md` maps each result to its evidence and limits. Lean proves the
finite-domain checker theorem. The Rust evidence is differential testing, and
two configured keys do not establish two independent organizations.
