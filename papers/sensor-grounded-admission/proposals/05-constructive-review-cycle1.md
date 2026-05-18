# Constructive Review (Cycle 1)

Source materials: paper sections 01-10 (6729 words), `bib.bib` (37 entries), `lean/STATUS.md`, the three research notes, and the prior adversarial / evaluation / related-work proposals. The FIX cycle landed §2 bridge paragraphs, the §6 cut, the §8 property-attestation rewrite, and the Theorem 2/4 substantive reformulations. Three load-bearing gaps remain: research findings have not been absorbed, §1 / §10 do not credit the four-theorem inventory cleanly, and the model-discretization assumption is implicit.

## Top 3 highest-leverage additions

### 1. §3 binary-state-discretization paragraph

The single load-bearing implicit assumption in the model. Without naming it, the categorical `(installed, active, healthy, degraded)` schema reads as a modeling choice the paper expects the reader not to notice; with it, the paper inherits the phi-accrual lineage and explicitly defers continuous-suspicion to future work. Draft (135 words) for placement after the "Falsifiable but not externally audited" paragraph in §3:

> The four flags discretize a state space that is, in reality, continuous over the decision window. A provider that delivers 99.7 percent of events with bursts of brief deadline misses is mapped to a single categorical record at attestation time; a provider that flaps at 10 Hz within a 100 ms decision is collapsed to whichever value the kernel's observability path samples last. The model treats the categorical state as the dominant condition across the decision window and treats within-window oscillation as captured by the drop and miss counts rather than by the flags. The continuous-suspicion alternative is the phi-accrual failure-detector family, which derives a real-valued suspicion signal from heartbeat inter-arrival times~\cite{hayashibaraPhiAccrual2004}; the discretization threshold is a constitutional parameter and the model admits a continuous extension as future work~\cite{cardenasICS2008}.

New bibkeys: `hayashibaraPhiAccrual2004` (SRDS 2004), `cardenasICS2008` (HotSec 2008).

### 2. §8 reframe from "code vs sensors" to "what surveyed wire formats structurally cannot express"

The tee-attestation-delta research note settled this: the structural distinction is representational (no TEE wire format types per-sensor coverage), not philosophical. The current §8 TEE paragraph says "adjacent but distinct" but does not name the representational gap. Draft (110 words) replacing the third-from-last sentence in the §8 TEE paragraph:

> No surveyed TEE wire format expresses per-sensor coverage as a primitive: Intel TDX RTMR0-3, Arm CCA REM, and AWS Nitro PCR8 are SHA-384 extension chains that record the order of post-launch events but cannot, by construction, distinguish a degraded sensor from an uninstalled one~\cite{intelTDX2023,armCCA2026,awsNitroNSM2024}. The 64-byte REPORT_DATA slot in SEV-SNP and the `x-ms-runtime` JSON bag in MAA admit free-form claims that the platform does not interpret as sensor evidence~\cite{amdSEVSNP2025,microsoftMAATDX2026}. The sensor-attested admission predicate types each provider record and evaluates the required-set as a structural induction over typed records, not as digest equality.

### 3. §1 contribution bullets revised to map 1:1 onto the four Lean theorems

The current four bullets in §1 muddle three of the four theorems into a single supporting-theorems bullet. A skim reader does not learn what is mechanized; Theorem 3 (admission-witnesses-coverage projection) is invisible. Replacement bullets mapping to file theorem names:

> \begin{itemize}
>   \item A formal admission predicate over body and substrate-state attestation, with healthy and degraded admission as separate cases (\thm{admissibleUnderSensorState}).
>   \item Headline existence: under any constitution with a non-empty required set, body-identical receipts with healthy and degraded attestations discharge admission to opposite verdicts (\thm{admission_under_degraded_state_distinguishable_from_healthy}).
>   \item A biconditional placing the parent paper's partition-contingency ladder mode at the proper-sublist relation between attested-healthy and required providers (\thm{partition_contingency_mode_iff_degraded_subset}).
>   \item An admission-witnesses-coverage projection over the predicate's three-conjunct shape (\thm{healthy_attestation_required_for_destructive_admission}) and an amendment-improvement theorem that a re-admitted partition-contingency receipt is no longer in partition contingency under the amended substrate (\thm{degraded_sensor_admission_requires_re_attestation}).
>   \item A canonical-JSON encoding deployed against six host-snapshot emitter sites in a working admission kernel, retiring the parent paper's substrate-honest-by-assumption row.
> \end{itemize}

This is five bullets, one per theorem plus the implementation instance. §10 then mirrors these five.

## Other strengthening opportunities (ranked by impact)

**4. §9 within-window flapping limitation row** (paired with #1). Draft for placement after the "Drop-and-miss thresholds are not action-specific" paragraph:

> The discretization of provider state into four flags collapses within-window oscillation onto whichever sample the kernel's observability path captures at attestation time. A provider flapping at a rate comparable to the decision window's duration produces an attestation whose categorical state may not represent the dominant condition. The model treats drop and miss counts as the within-window oscillation evidence, but a constitution that needs to reject high-frequency flapping has no schema field for "transition rate" and must subdivide the receipt family. The continuous-suspicion extension is named in Section~\ref{sec:substrate} as future work~\cite{hayashibaraPhiAccrual2004,mitchellChenCPSSurvey2014}.

**5. Aerospace-TMR novelty claim in §8.** Sensor-flapping research found genuine novelty relative to Yeh 1996 Boeing 777 PFC mid-value-select and ARINC 653 health monitoring: aerospace solved sensor disagreement with hardware redundancy and voting, never with cryptographic attestation. Draft for §8, end of "Property attestation and the trusted-sensors lineage":

> The aerospace lineage handles sensor flapping with hardware redundancy and mid-value-select voting (Boeing 777 PFC~\cite{yeh1996Boeing777}) and reaction-policy partitioning (ARINC 653 health monitoring~\cite{arinc653}). The construction here does not vote sensors; it signs the federation's coverage state as a first-class field, which is the move the aerospace lineage does not make. The two compose: a TMR-voted sensor produces a single signed reading whose voting record could be part of a future-version sensor attestation.

**6. §7 paragraph on the constitutional layer above attestation.** The tee-attestation-delta note converged on this framing: the irreducible delta is the predicate-on-attestation evaluated at a polity admission boundary. The current §7 implies this but does not state it.

> The constitutional layer is the irreducible delta over the property-attestation lineage. Sailer 2004, Haldar 2004, Coker 2011, and the TEE wire formats above all attest properties of a host's code or launch state and emit those properties as claims a verifier evaluates against a published reference. The sensor-attested admission predicate adds two compositional commitments the lineage does not make: the attested property is consumed by a polity constitution that the receiver controls~\cite{chioProgrammableSovereignty2027}, and the predicate composes through a bilateral treaty under which both polities' required sets must be covered. The lineage stops at "the verifier accepts iff the attested system has the property the verifier requires"; the constitutional layer adds "the polity admits iff the attested system has the property the constitution declares, composed with the treaty partner's constitution under the union of required sets."

**7. §10 conclusion rewrite mirroring revised §1 bullets.** The current §10 cites only the headline theorem and gestures vaguely at the supporting ones. Tightened replacement for §10 paragraph 2 (215 words):

> The contribution is a placement choice and the formal consequences of that choice. Four theorems mechanize the consequences. The headline existence theorem (\thm{admission_under_degraded_state_distinguishable_from_healthy}) constructs body-identical receipts with opposite admission verdicts under one constitution; the proof is constructive, not definitional. The partition-contingency biconditional (\thm{partition_contingency_mode_iff_degraded_subset}) places the parent paper's ladder mode at a proper-sublist relation, with `Sublist.length_le` and `Sublist.eq_of_length` carrying both directions. The admission-witnesses-coverage projection (\thm{healthy_attestation_required_for_destructive_admission}) extracts required-set coverage from the admission predicate's three-conjunct shape. The amendment improvement theorem (\thm{degraded_sensor_admission_requires_re_attestation}) establishes that a re-admitted partition-contingency receipt is no longer in partition contingency under the amended substrate, on the same attestation bytes. The implementation instance covers six host-snapshot emitter sites in a working admission kernel; the parent paper's substrate-honest-by-assumption row is retired as a structural matter rather than as operational discipline.

**8. Honest §4 paragraph on Lean STATUS.md residue.** STATUS.md documents two honest gaps: Theorem 3's `_h_destructive` is inert, and Theorem 4's `_h_prev_decl` is structural-constraint-only. Current §4 prose ("destructive-admission floor is therefore type-conditioned") overclaims Theorem 3. Replacement sentence:

> Theorem~3 carries an admission-witnesses-coverage projection: any admitted receipt has a declared required set for its family and the attestation covers that set. The theorem is stated with the receipt family discriminator present, but the projection holds for any admitted receipt; the family discriminator is a structural-constraint-only binder retained for prose alignment with the destructive-admission floor's intended invariant.

**9. §A appendix shell for Lean theorem statements.** Camera-ready: a reviewer's-receipt of the formal substrate. Structure (no body):

> \section{Appendix: Lean Theorem Statements}\label{sec:appendix-lean}
> Theorem 1 verbatim signature (Lean lines 350-363); Theorem 2 (419-423); Theorem 3 (465-472); Theorem 4 (544-558). Build reproduction: lean 4.28.0-rc1, `lake build` exits 0; axiom dependencies `propext`, `Classical.choice`, `Quot.sound`.

**10. Threat model: post-hoc forgery and colluding cosigners.** §4's threat model treats kernel-key compromise as out of scope but does not name post-hoc forgery: an operator who recovers the receipt-signing key after the fact can mint healthy attestations covering a historical body. The colluding-cosigners case is also unhandled. Two-sentence addition:

> An operator who recovers the signing key after the fact can mint attestations covering historical bodies; the substrate's defense is the transparency anchor and external auditor named as the structural complement of this work, not the in-substrate predicate. A quorum-required admission with colluding cosigners that produces matching forged attestations is structurally equivalent to single-key compromise; the substrate's role is to make the forgery a signed-falsifiable statement rather than a silent operational fact.

**11. §9 signing-key isolation limitation row.** The adversarial agent flagged that single-key signing makes the strengthening "structural-not-cryptographic." This belongs in §9 honestly:

> Attestation and body are signed by the same kernel key in the construction here. A separate attestation key, rooted in a TEE platform's quote-signing identity (TDX quote key, SEV-SNP VCEK, Apple PRA platform key, AWS Nitro NSM), would make the strengthening cryptographic in addition to structural. The substrate admits this extension as a constitutional declaration of the key-isolation discipline; the v1 default takes single-key signing and names dual-key signing as the natural extension.

## Drafts ready for the next FIX cycle

New bibkeys (sketch; concrete bibtex stubs are in `research/os-observability-analogs.md` and `research/tee-attestation-delta.md`):

- Failure-detector / CPS lineage: `hayashibaraPhiAccrual2004`, `cardenasICS2008`, `mitchellChenCPSSurvey2014`.
- eBPF observability: `sekarEAudit2024`.
- Property-based attestation: `sadeghiPBA2004`.
- Aerospace TMR: `yeh1996Boeing777`, `arinc653`.
- TEE primary sources (replace academic survey aliases): `intelTDX2023` (348549-002US Jan 2023), `amdSEVSNP2025` (56860 r1.58 May 2025), `applePCCBundle2024` (security-pcc proto Oct 2024), `armCCA2026` (draft-ffm-rats-cca-token-03), `awsNitroNSM2024`, `microsoftMAATDX2026`, `ratsArch2023` (RFC 9334).

The research notes already carry verified DOIs / URLs / dates for each. The FIX-cycle bibtex pass is a copy-paste from the two research files plus a check that the existing alias entries (`chengTDXDemystified2024`, `applePRA2024`, `microsoftMAA2025`) survive as secondary anchors rather than primary.

## What the paper does well already

- **§3 falsifiable-but-not-externally-audited paragraph.** Structural-vs-cryptographic distinction is clean; the strengthening is honestly named as strict but not absolute. Voice the rest of the paper should match.
- **§4 worked example.** Healthy-vs-empty-attestation example is concrete enough that a reviewer can verify the headline theorem from prose alone.
- **§6 honest empirical cut.** The 6-of-13 host-snapshot-vs-placeholder breakdown disarms the reviewer who would otherwise call the chapter overclaimed.
- **§8 property-attestation lineage.** Sailer / Haldar / Coker / Saroiu / Liu / Asokan citation graph is the right shape; contribution boundary argued explicitly.
- **Lean substrate.** Four theorems compile cleanly with no `sorry`, only standard kernel axioms, STATUS.md honest about which hypotheses are inert. The strongest reviewable artifact in the paper's evidence basis.

## Priority queue for next FIX cycle

1. **§3 binary-state-discretization paragraph** (item 1, 135 words, two new bibkeys). Highest leverage: closes the model-fidelity gap.
2. **§1 contribution bullets revised to 1:1 onto the four theorems** (item 3, ~150 words). Pair with §10 conclusion mirror (item 7) in the same edit.
3. **§8 TEE wire-format gap reframing** (item 2, 110 words, seven new TEE primary-source bibkeys).
4. **§9 within-window flapping limitation row** (item 4, paired with item 1).
5. **§4 honest paragraph on Theorem 3's inert hypothesis** (item 8). Closes STATUS.md-vs-prose gap.
6. **§7 constitutional-layer paragraph** (item 6).
7. **§8 aerospace-TMR novelty claim** (item 5, paired with `yeh1996Boeing777`, `arinc653`).
8. **§A appendix shell** (item 9). Defer if page budget tight.
9. **Threat-model post-hoc forgery and colluding-cosigners additions** (item 10).
10. **§9 signing-key isolation limitation row** (item 11).

Items 1-3 are the load-bearing trio for the next FIX cycle. Items 4-7 cover residual research-note absorption. Items 8-10 are polish.

---

**Report back:** (1) Highest-leverage single addition: §3 binary-state-discretization paragraph (item 1). The discretization choice is the implicit assumption a phi-accrual-literate reviewer hits first; naming it costs 135 words and inherits the entire failure-detector lineage as honest context. (2) Top-3 FIX priorities: §3 discretization paragraph, §1 contribution bullets to map 1:1 onto the four Lean theorems, §8 TEE wire-format reframing. (3) Fraction of potential realized: roughly 70 percent. The Lean substrate, §6 honest cut, and §8 property-attestation framing are at near-final quality; the §1 / §10 bookends, the §3 discretization assumption, and the research-note absorption are the residual 30 percent the next FIX cycle can close.
