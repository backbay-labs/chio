# Wave 3A: Open Science Appendix

Date: 2026-05-19
Scope: USENIX Security 2027 Cycle 1 mandatory Open Science statement
Files touched:
- NEW: `sections/11-appendix-open-science.tex`
- MOD: `paper.tex` (added `\appendix` block + input)
- MOD: `paper-usenix.tex` (same)

## Appendix structure

The appendix carries four subsections that map one to one with the
USENIX Security 2027 Open Science policy:

1. **Artifact availability** (`sec:open-science:availability`). Names the
   three artifact classes: the 583-line Lean 4 mechanization packaged
   as a self-contained Lake project (central artifact), the
   primary-source bibliography, and the paper text under the same
   permissive license that governs the substrate's public artifacts.
   States that the public repository location is named in the
   camera-ready version under double-blind review discipline.

2. **Reproducing the Lean mechanization** (`sec:open-science:lean`).
   Names the toolchain pinning via `lean-toolchain` and `lakefile.lean`,
   the two-command rebuild path (`tar xzf` then `lake build`), the
   3-5 minute cold-cache build, the no-warnings and no-`sorry` state,
   and the `#print axioms` audit showing only the standard kernel
   axioms `propext`, `Classical.choice`, `Quot.sound`. Points to
   `proof-manifest.toml` for the fully qualified theorem-axiom
   correspondence.

3. **Reproducing the empirical claims** (`sec:open-science:empirical`).
   Cross-references Section 5 (Implementation) and Section 6
   (Evaluation). Describes the reproduction path: exercise the kernel
   against the receipt corpus, extract each receipt's signed
   attestation block, verify both the attestation signature and the
   DSSE subject digest binding attestation bytes to body bytes. States
   the canonical-JSON parser and provider-record schema are in the
   released runtime package. Anonymizes the runtime deployment for
   review.

4. **Bibliography accessibility** (`sec:open-science:bib`). Confirms
   every load-bearing citation resolves to a publicly retrievable
   primary source: vendor specifications (Intel TDX, AMD SEV-SNP,
   Apple PCC, Arm CCA, AWS Nitro), Internet standards (RFC 8785,
   RFC 9334), and peer-reviewed publications from USENIX, IEEE, and
   ACM venues.

## Anonymization compliance

No author names, institution names, GitHub URLs, or organization
identifiers appear in the appendix. The two cross-references that
might leak identity (the deployed runtime and the public repository)
are phrased as "anonymized for review" / "named in the camera-ready"
in line with the brief's anonymization discipline. The substrate
identifier (Chio) does not appear in the appendix; it is already
present in §1, §8, and the parent-paper bibkey, and the
SUBMISSION-CHECKLIST flagged that for human confirmation rather than
agent removal.

## Voice compliance

No em dashes (U+2014); grep verified clean. No engineering-meta
voice: the appendix describes what IS available and what a reviewer
DOES to reproduce, not what shipped or what the project versioned.

## Build state

Both shells build clean with the appendix wired in:

```
article: errors 0 | pages 24    (was 18 before both appendices)
usenix:  errors 0 | pages 16    (was 12 before both appendices)
```

The Ethics appendix is also present (added by the parallel agent);
Open Science is placed BEFORE Ethics in both shells per the brief's
ordering rule. The USENIX two-column build adds ~1 page for Open
Science (the brief's target).

## Concurrency note

The parallel agent's Ethics appendix landed in `paper.tex` and
`paper-usenix.tex` between the initial reads and the verification
pass. Both inputs are present in the correct order. No conflict.
