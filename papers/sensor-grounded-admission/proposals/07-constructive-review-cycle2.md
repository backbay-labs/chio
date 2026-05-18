# Constructive Review (Cycle 2)

Sources: paper sections 01-10 (~6720 words), bib.bib (32 entries, no orphans), `lean/SensorGroundedAdmission.lean`, four cycle-2 research notes, and `proposals/05-constructive-review-cycle1.md`. Cycle-2 FIX/WRITE has landed §3 within-window discretization, §9 flapping row, §1 five-bullet contribution map, §10 bookend mirror, §8 TEE reframing, §4 honest Σ-construction prose, and bib orphan cleanup. The remaining surface: research findings S1/N1/N2 not absorbed, Theorem 1's name does not match its prose, and one §3 paragraph could close the cryptographic-strengthening axis cheaply.

## Top 3 highest-leverage additions / changes (drafts included)

### 1. §9 single-key collapse limitation row (S1 absorption)

Highest-leverage gap left. Research note `single-key-collapse.md` confirms the construction signs body and attestation under one kernel key (§3:18, §4:59); every surveyed TEE/HRoT separates them; parent paper §9:20 already acknowledges the collapse. The present substrate inherits the parent's row plus a second collapse axis (body/attestation); the strengthening is structural-not-cryptographic until a TEE-rooted attestation key is wired in.

Draft for placement after the "Clock attestation is not separately validated" paragraph:

> \paragraph{Attestation-key isolation.}
> The construction signs the receipt body and the sensor-state attestation under a single kernel key. A workload-level compromise of the kernel yields a forger who can mint coherent attestations under any sensing posture; the strengthening of this paper is structural (the wire-level statement is falsifiable) rather than cryptographic (no signature-level evidence isolates a healthy-attestation kernel from a degraded-attestation forger). A separate attestation key rooted in a hardware-managed identity (Intel TDX Quoting Enclave key signed by the Provisioning Certification Key, AMD SEV-SNP VCEK or VLEK, Apple Secure Enclave User Identity Key, Microsoft Pluton AK certified by EK, TPM 2.0 AK certified by EK) would close this axis cryptographically. RFC 9334's Attester / Target distinction~\cite{rfc9334RATS} is the standards-anchor; deployment platforms are surveyed in Section~\ref{sec:related}. The single-key default is a substrate choice, not a hardware limitation, and the dual-key extension is named in Section~\ref{sec:substrate} as a deployment axis the substrate admits.

Uses `rfc9334RATS` (already in bib.bib). No new bibkeys.

### 2. §3 TEE-rooted attestation extension paragraph (S1 strengthening)

Cycle-1 proposed this; not landed. Research note `single-key-collapse.md:46-51` sharpens the platform list (PCE/QE, VCEK/VLEK, SEP UIK, Pluton AK, TPM 2.0 AK/EK) and confirms each is deployed today. Draft for placement after "Falsifiable but not externally audited", before "Within-window discretization":

> \paragraph{TEE-rooted attestation-key separation.}
> The structural strengthening above is a placement choice over a single signing key. A natural extension closes it cryptographically by signing the attestation under a hardware-managed key the workload cannot extract: Intel TDX provisions a Quoting Enclave attestation key signed under a Provisioning Certification Key derived from fused secrets~\cite{intelTDXSpec2023}; AMD SEV-SNP signs the \texttt{ATTESTATION\_REPORT} under a Versioned Chip Endorsement Key the guest cannot control~\cite{amdSEVSNPSpec2025}; Apple's Secure Enclave derives a User Identity Key inside its PKA hardware block, not readable by sepOS~\cite{applePlatformSecurity2024}; TPM 2.0 binds an Attestation Key under an Endorsement Key whose private half is sealed in TPM hardware~\cite{rfc9334RATS}. The pattern is universal: hardware-rooted attestation key signs attestations, application-controlled key signs workloads, verifier accepts only attestations whose AK is certified back to a platform endorsement key. The substrate admits this extension as a deployment choice; the resulting attestation would carry signature-level evidence of the attesting environment, and a workload-level compromise would no longer suffice to forge coherent attestations.

Reuses `intelTDXSpec2023`, `amdSEVSNPSpec2025`, `applePlatformSecurity2024`, `rfc9334RATS` (all in bib.bib). ~140 words.

### 3. Theorem 1 rename across all sites

Post-honesty-pass prose in §1, §4, §10 describes Theorem 1 as a Σ-construction over two fixed witnesses; the name still reads `admission_under_degraded_state_distinguishable_from_healthy`, inviting the misreading that it proves general structural separation. Rename to `admission_predicate_separates_healthy_and_degraded_witnesses` (verb `separates` honest about what the witnesses do; noun `witnesses` flags the Σ shape).

Site list:

- `lean/SensorGroundedAdmission.lean:12` (header comment) and `:350` (theorem declaration).
- `sections/01-introduction.tex:17` (`\thm{...}` in headline bullet).
- `sections/10-conclusion.tex:6` (`\thm{...}` in conclusion recap).
- `swarm-state.md` (working memory).
- `research/headline-theorem-candidates.md`, `research/empty-witness-wire-producibility.md`, `research/single-key-collapse.md`, `proposals/04-adversarial-review-cycle1.md`, `proposals/05-constructive-review-cycle1.md` (working memory).
- `lean/STATUS.md` (out of paper scope, but in same FIX cycle).

§4 prose does not reference the theorem name directly; its "headline theorem" prose already aligns. No §4 edit beyond verification.

## Other strengthening opportunities (ranked by impact)

### 4. N1 ambiguity resolution: Path A (delete) recommended

Research note `amendment-cycle-paradox.md` shows §5:21-22 plus §9:21-22 opens a Case A / Case B reading the paper does not resolve. Case A violates `BackwardRefines`; Case B does not. Path A: delete both paragraphs, declaring the construction is over a fresh substrate with no schema-version migration in scope. Path B: keep the paragraph plus one resolving sentence.

Reasoning: Path B admits a genuinely unaddressed amendment-cycle question. Path A retires it. Schema-version discussion adds zero load-bearing content to the headline contribution; §9:21-22 currently says "the parent paper's amendment-refinement discipline applies" which is the unaddressed question itself.

Deletions:
- `sections/05-implementation.tex:21-22` (Wire compatibility paragraph).
- `sections/09-limitations.tex:21-22` (Schema versioning paragraph).

Net delta: ~-130 words.

Path B fallback sentence (if wire-compatibility prose is preferred for perceived deployment value):

> The sensor-attestation construction is a fresh constitution rather than an amendment of the parent body-only constitution; the parent's `amendment_admissible_iff_backward_refinement` obligation applies to amendments within the new constitution, not to the construction's introduction.

Recommendation: Path A.

### 5. Lean theorem candidate `sensor_attestation_marginal_trust_requires_separate_key`

Research note `single-key-collapse.md:48-49` proposes a stub theorem: under a single-key model the attestation's signed claim is cryptographically a no-op (any key that signs the body can sign any attestation).

Type-signature candidate (no proof):

```
/-- Marginal-trust collapse: under single-key signing, attestation signature
    is a cryptographic no-op. The kernel that signs the body can sign any
    attestation; marginal cryptographic content is zero. -/
theorem sensor_attestation_marginal_trust_requires_separate_key
    (k : KernelKey) (body : ReceiptBody) (a : SensorAttestation)
    (h_sig : signsAttestation k a) :
    signsBody k body → (∀ a' : SensorAttestation, signsAttestation k a')
```

Recommendation: state it without proof in §A appendix or as a §3 inline LaTeX statement, not in Lean. The Lean substrate currently abstracts over signing keys (`SensorAwareConstitution.bodyPredicates : List (ReceiptId → Bool)`, no key model); adding a key model just to state the collapse is one day of Lean work for a one-line claim. Prose statement is cheaper. Mechanization defers to v2.

### 6. N2 optional one-sentence §5 addition (wire-producibility)

Research note `empty-witness-wire-producibility.md` confirms the empty-providers attestation is wire-producible. Cycle-1 N2 was a misreading. Cheap textual fix:

Append to §5's failure-modes paragraph:

> An attestation with a syntactically valid but empty \codepath{providers} array passes the parser and discharges to \codepath{required\_set\_uncovered} whenever the constitution's required set is non-empty; the denial path is the predicate-level path, and the empty-providers attestation is therefore wire-producible by construction.

~45 words. Closes N2 textually.

### 7. §4 worked example: keep as-is

§4's worked example at lines 38-43 is not redundant with §1. §1 names the contribution shape; §4 gives concrete bytes. A reviewer can verify the headline theorem from §4 prose without opening the Lean. Cycle-2 WRITE preserved it through a -194-word tightening of §4. No edit.

### 8. §A appendix decision: include, draft shell ready

Cycle-1 deferred. Cycle-2 makes it cheaper: Lean is mature (four theorems, no `sorry`, kernel axioms only). Appendix is ~1 page; serves as reviewer's receipt.

Draft shell:

```
\section{Appendix: Lean Theorem Signatures and Build Reproduction}
\label{sec:appendix-lean}

The four theorems mechanized in lean/SensorGroundedAdmission.lean appear
here with Lean signatures verbatim. Build: Lean 4.28.0-rc1, mathlib4
pin in lean-toolchain. `lake build` exits 0; `#print axioms` reports
only propext, Classical.choice, Quot.sound. No `sorry`.

Theorem 1 (headline existence):
  admission_predicate_separates_healthy_and_degraded_witnesses
  [lines 350-363, post-rename]

Theorem 2 (partition-contingency biconditional):
  partition_contingency_mode_iff_degraded_subset
  [lines 419-423]

Theorem 3 (admission-witnesses-coverage projection):
  healthy_attestation_required_for_destructive_admission
  [lines 465-472; destructive-family hypothesis presently inert]

Theorem 4 (amendment-improvement):
  degraded_sensor_admission_requires_re_attestation
  [lines 544-558]

Optional: prose statement of item 5 marginal-trust collapse.
```

Page impact: +1 page; with item 4 deletions, net +0.6 page (current 17 → ~17.6). Cut if conference target is 12; include otherwise. Strongest reviewer-facing artifact at lowest cost.

### 9. §7 contribution-drift audit

Cycle-1 cut alignment-evaluation paragraph. Current §7 paragraphs: structural argument, heuristic-substitution refutation, parent-paper composition, kernels-that-lie, scope-fencing. All within scope, no contribution drift. Cycle-1 cut held. No edit.

### 10. §2 background dangling-citation audit

§2 citations against current bib.bib: `rfc8785`, `dsse`, `cokerPrinciplesRemoteAttestation2011`, `linuxAuditSubsystem`, `sailerTCGIMA2004`, `applePlatformSecurity2024`, `microsoftETW`, `haldarSemanticRemoteAttestation2004`, `chengTDXDemystified2024`, `amdSEVSNP2020`, `hammoudConfidentialCloud2023`, `msaa2025`. All present. No dangling citations. No edit.

## Drafts ready for the next FIX cycle

- §9 attestation-key isolation row (item 1, ~125 words; uses `rfc9334RATS`).
- §3 TEE-rooted attestation-key separation paragraph (item 2, ~140 words; uses `intelTDXSpec2023`, `amdSEVSNPSpec2025`, `applePlatformSecurity2024`, `rfc9334RATS`).
- §5 empty-attestation wire-producibility sentence (item 6, ~45 words).
- Path A deletions (item 4): drop §5:21-22 + §9:21-22 (~-130 words).
- Theorem 1 rename (item 3): six file sites.
- §A appendix shell (item 8, ~250 words plus four Lean signatures).

No new bibkeys required. Cycle-2 bib.bib (32 entries) covers all referenced citations.

## What the paper does well already (cycle-2 progress)

- §1 five-bullet contribution map: 1:1 onto four Lean theorems plus impl instance. Theorem 3's previously-invisible projection has its own bullet.
- §4 honest Σ-construction prose at §4:36; list-induction work in supporting lemmas. Closed cycle-1 F1.
- §4 worked example: `endpointSecurity` + `networkExtension` healthy vs empty attestation against same body bytes. Reviewer can verify headline from prose.
- §8 TEE reframing: "what surveyed wire formats structurally cannot express" with seven TEE primary-source bibkeys.
- §8 eBPF lineage: `linuxAuditSubsystem`, `sekarEAudit2024`, `falcoProject2025`, `tetragonProject2025`.
- §3 within-window discretization (§3:20) + §9 matching flapping row (§9:15-16). Both bibkeys in bib.bib.
- §9 Lean honesty paragraph (§9:28) on Theorem 3's inert hypothesis. STATUS.md and paper agree.
- Lean substrate: four theorems, no `sorry`, kernel axioms only. Strongest reviewable artifact.
- bib.bib post-cycle-2: 32 entries, 0 warnings, 0 undefined citations.

## Priority queue for next FIX cycle (top 5)

1. §9 attestation-key isolation row (item 1). Highest leverage of any remaining single edit; closes cycle-1 S1; ~125 words; no new bibkeys.
2. §3 TEE-rooted attestation paragraph (item 2). Pairs with item 1: §9 names the gap, §3 names the deployment-axis closure. ~140 words; reuses bibkeys.
3. Theorem 1 rename (item 3). Six sites; mechanical; smallest change that makes paper name and post-honesty-pass prose agree.
4. N1 Path A deletions (item 4). Net -130 words; closes amendment-cycle paradox.
5. §5 empty-attestation wire-producibility sentence (item 6). ~45 words; closes cycle-1 N2.

Stretch (cycle 3 or v2):
- §A appendix (item 8). Cut if conference target is 12; include otherwise.
- `sensor_attestation_marginal_trust_requires_separate_key` informal statement (item 5). Defer Lean mechanization to v2.

---

**Report back:** (1) Highest-leverage single addition: §9 attestation-key isolation row (item 1). Closes cycle-1 S1; ~125 words; no new bibkeys; makes the structural-vs-cryptographic distinction explicit. (2) Top-3 FIX priorities: §9 attestation-key isolation row, §3 TEE-rooted attestation-key separation paragraph, Theorem 1 rename across six sites. (3) Fraction of potential realized: roughly 80 percent, up from cycle-1's 70 percent. §1/§10 bookend revision, §3 discretization, §8 TEE reframing, §9 limitation rows, and bib.bib cleanup all landed in cycle-2. Residual 20 percent is S1 absorption (items 1-2), N1 resolution (item 4), Theorem 1 rename (item 3), and the optional appendix (item 8). Lean substrate, §6 empirical cut, §8 lineage at final quality; residual is honest-ledger work plus the rename.
