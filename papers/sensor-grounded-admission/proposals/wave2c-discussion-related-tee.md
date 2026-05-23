# Wave 2C: §7 reframing, §8 TEE coverage extension, voice cleanup

## Scope

Two structural fixes plus a voice pass across `sections/07-discussion.tex` and `sections/08-related-work.tex`, with four supporting bib entries appended to `bib.bib`. Touched files: `sections/07-discussion.tex`, `sections/08-related-work.tex`, `bib.bib`. No other files modified.

## Fix 1: §7 reframed toward a structural argument

The prior §7 carried three structural paragraphs followed by two defensive paragraphs ("what about kernels that lie?" and "what this paper does not claim"). The defensive material restated §9 limitations and inserted authorial-meta voice ("the paper does not claim ...") in a section whose job is to carry the positive structural argument.

The reframe removes the two defensive paragraphs and replaces them with three subsections that name what the construction makes structurally visible:

- **What sensor-grounded admission reveals that the trust-store-honest model hides.** A receipt whose body parses cleanly but whose attestation shows a degraded sensor set is now admissible only at partition-contingency with an explicit reconciliation obligation, where the prior model admitted it silently at receipt-backed. The cross-substrate effect names the bilateral-treaty case: a degraded sensor required by only one polity's required set is now a treaty-rejection.
- **Composition with the parent paper's ladder.** The five-mode ladder is now driven by a structural attestation field rather than by operator discretion. Receipt-backed and partition-contingency, previously adjacent rungs distinguished only by an operator's reading of recent kernel health, are now distinguished by a decidable predicate on the receipt itself. The composition argument is positive (the headline theorem composes with the parent's bilateral-treaty admission; the ladder-floor stability theorem composes with the constitution-required-set discipline; the amendment-refinement theorem gains a paired re-attestation obligation).
- **Boundary against TEE-compromise.** Where the TEE root holds, the construction strictly improves observability. Where the TEE root fails, the construction collapses to single-key signing as the parent paper assumed. The collapse is named by attack family (microarchitectural side channels, voltage-glitching) and decomposed in §9.

A final subsection names the downstream artifacts the placement choice unlocks (a sensor-coverage auditor whose disagreement is a signed artifact; a treaty whose required-set predicate is decidable across an organizational trust boundary). These are out of scope for the construction and in-scope for the structural placement.

The section retains the original `The structural argument` and `Why this is not heuristic substitution` paragraphs, which were already carrying their weight.

## Fix 2: §8 TEE coverage extended to 2025-2026 dominant systems

The prior §8 TEE paragraph covered Intel TDX, AMD SEV-SNP, AWS Nitro Enclaves, Apple PCC, and Arm CCA. Wave 1B identified four 2025-2026 dominant systems missing from that coverage:

- **NVIDIA Hopper Confidential Compute (H100, H200)** — GPU-side SPDM-tunnelled attestation reports binding on-chip firmware version, secure-boot state, and a workload-supplied nonce. Relevant because agentic-AI workloads increasingly span GPU.
- **Google Cloud Confidential Computing** — Confidential VMs (SEV-SNP, TDX) layered under Confidential Space attestation tokens signed by Google's Attestation Verifier, carrying TEE measurements and a workload identity claim.
- **CNCF Confidential Containers (CoCo)** — Kubernetes-native trusted-execution path composing Kata-rooted TEE workloads with a Remote Attestation Service whose Reference Value Provider supplies policy-side acceptance rules.
- **Microsoft Pluton** — PC-tier security processor anchoring a hardware root certified up to Microsoft Azure Attestation.

Each is named with its attestation primitive (what is being attested) and located relative to the construction. The paragraph closes with the substrate-agnostic positioning: the construction consumes any of these wire formats as the carrier for its hardware-rooted attestation-signing key and overlays a sensor-coverage claim that the underlying format does not itself express.

## Fix 3: Voice cleanup

Wave 1B flagged 14 "this paper" / "the paper" hits across the document. The §7/§8 scope contained three (one paragraph heading and two body sentences in §7), all in the defensive paragraphs removed by Fix 1. After the rewrite, `grep -nE "this paper|the paper|\bwe (propose|extend|introduce|present|claim|show|argue)\b"` returns zero hits across §7 and §8. Em-dash grep also returns zero hits.

## Bib additions

Four new `@misc` entries appended at the end of `bib.bib` under section 16, after the Wave 2B section-15 TEE-compromise additions (no collision):

- `nvidiaHopperCC2024` (NVIDIA Hopper Confidential Compute whitepaper).
- `googleConfidentialComputing2024` (Google Cloud Confidential Computing documentation).
- `cncfConfidentialContainers2024` (CNCF CoCo project documentation).
- `microsoftPluton2023` (Microsoft Pluton documentation).

Each uses institutional authorship in double braces and a `howpublished` field naming the documentation source.

## Build verification

Both LaTeX targets compile clean with bibtex resolution:

- `paper.tex`: 0 errors, 0 bib misses, 0 undefined citations, 21 pages.
- `paper-usenix.tex`: 0 errors, 0 bib misses, 0 undefined citations, 15 pages.

The four new bib entries resolve through the bibtex pipeline (`grep -c` against `paper.bbl` and `paper-usenix.bbl` returns 4 for each).

## Concurrency note

`bib.bib` was already touched by Wave 2B (section 15, TEE-compromise primary sources: Plundervolt, Foreshadow, Downfall, Half-Double). The four Wave 2C entries land in a new section 16 appended after section 15, so the two waves' bib changes coexist without collision.
