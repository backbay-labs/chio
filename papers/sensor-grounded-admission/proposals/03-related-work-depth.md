# Related Work Depth + Background Assessment

The v0 §8 exists but its substantive references are TODO-keyed placeholders (`TODO_tdx`, `TODO_sev_snp`, `TODO_aws_nitro`, `TODO_arm_cca`, `TODO_nvidia_h100`, `TODO_msaa_2025`, `TODO_project_everest`, `TODO_code_signature_drift`, `TODO_behavioral_attestation`, `TODO_bbs`, `TODO_camenisch_credentials`, `TODO_rekor`, `TODO_ots`, `TODO_tessera`, `TODO_fls_partial_info`, `TODO_dsse`, `TODO_chio_2027`). The shape of §8 is correct, but the citation graph has a load-bearing hole on three axes: the trusted-computing / remote-attestation lineage, the endpoint-detection-and-response (EDR) literature, and the trusted-sensor / IoT-attestation literature.

## Citations that MUST be added (reviewer will flag if missing)

1. **Sailer, Zhang, Jaeger, van Doorn, "Design and Implementation of a TCG-based Integrity Measurement Architecture", USENIX Security 2004.** The IMA paper, canonical Linux-side load-time attestation. The sensor-grounded paper claims a placement at "a different layer" than launch attestation; the honest way to make that claim is to name IMA as the layer the new construction sits above. Lands in §2 "Sensor state on real kernels" and the §8 attestation paragraph.

2. **Coker, Guttman, Loscocco, Herzog, Millen, O'Hanlon, Ramsdell, Segall, Sheehy, Sniffen, "Principles of Remote Attestation", International Journal of Information Security 2011.** Canonical formal-models-of-attestation paper. Five principles: fresh information, comprehensive information, constrained disclosure, semantic explicitness, trustworthy mechanism. The `admissibleUnderSensorState` predicate is in dialogue with this paper; a PC reviewer who works on attestation will ask "which of the Coker principles does this satisfy." Lands in §2 "The honest-substrate assumption" and §8 as the formal-model anchor.

3. **Haldar, Chandra, Franz, "Semantic Remote Attestation", USENIX VMRTS 2004.** Earliest property-attestation paper. The sensor-grounded paper's claim ("attest sensing posture rather than launch measurements") is structurally a property-attestation move; the lineage predates this paper by twenty-two years. Absence of this cite is the single hole most likely to draw a "this is property attestation rebadged" reviewer comment.

4. **DSSE + in-toto: confirm reuse of the parent's `dsse` and `torres2019intoto` keys.** §2 "Receipts as signed canonical statements" cites `TODO_dsse` where it should resolve to the parent's existing bib entries.

5. **Saroiu, Wolman, "I Am a Sensor, and I Approve This Message", HotMobile 2010.** The trusted-sensor founding paper. A hardware sensor signs its own readings so downstream consumers can trust the value. This is the closest prior art at the conceptual level; the sensor-grounded paper is the kernel-level lift of the Saroiu-Wolman idea. Reviewer working in systems security will flag absence. Lands in §8 in a new paragraph "Trusted sensors and IoT attestation."

6. **Liu, Saroiu, Wolman, Raj, "Software Abstractions for Trusted Sensors", MobiSys 2012.** The follow-up; sensor-signing primitive composes through OS abstractions. Closest construction to "the kernel attests its own sensors" in the cited literature.

7. **Intel TDX: Cheng, Ozga, Valdez, et al., "Intel TDX Demystified", ACM Computing Surveys 2024.** Citable academic anchor for `TODO_tdx`.

8. **AMD SEV-SNP: AMD white paper 2020.** Plus Li et al., "A Tale of Two Worlds: Assessing the Vulnerability of Enclave Shielding Runtimes", CCS 2022 for an honest security-properties account.

9. **AWS Nitro: Hammoud et al., "Confidential Computing on the Cloud: A Survey", IEEE Cloud 2023.** Replaces `TODO_aws_nitro`.

10. **Apple Platform Security guide and Endpoint Security framework documentation.** The empirical chapter mentions code-signature drift detectors, kernel callouts, and behavioral telemetry, which are the Apple Endpoint Security categories. A macOS-security reviewer will ask.

11. **Linux IMA (Zohar, Sailer) and Linux audit subsystem (Grubb).** The substrate references "kernel callouts, behavioral telemetry, supply-chain runtime guards"; the Linux-side anchors are the audit subsystem and IMA. §2 names sensor categories without naming the OS-level analogs.

12. **NIST SP 800-155 (BIOS Integrity Measurement Guidelines, 2011)** as the standards anchor for "what an integrity measurement architecture is supposed to look like."

## Citations that SHOULD be added (would strengthen the paper)

1. **Asokan, Brasser, Ibrahim, Sadeghi, Schunter, Tsudik, Wachsmann, "SEDA", CCS 2015.** Collective attestation: a different problem with the same predicate-on-attested-state shape.
2. **Halawa 2020 or Bahrami 2022 EDR survey.** §7's preemptive defense against "this is an EDR runbook" bites harder with a survey cite.
3. **Newman, Meyers, Torres-Arias, "Sigstore", CCS 2022.** Replaces `TODO_rekor` with a real venue.
4. **Kotzias, Caballero, Bilge, "How Did That Get In My Phone?", IEEE S&P 2021.** Closest "what goes wrong in code-signature drift at scale" cite.
5. **TPM 2.0 architecture (TCG).** Implicit in IMA; worth citing if §2 wants to state the construction is not TPM-rooted.
6. **Birgisson et al., "Macaroons", NDSS 2014.** Contrast: macaroons attenuate authority at the request layer; sensor-grounded admission attenuates at the substrate layer.
7. **Erlingsson, Pihur, Korolova, "RAPPOR", CCS 2014.** Head off a "does the attestation leak tenant identity" reviewer question.

## What the v0 §2 background gets right

- Polity admission triple `(T, C, K)` stated cleanly with the parent theorem named.
- Honest-substrate paragraph correctly framed: the gap is stipulative, not cryptographic.
- "Sensor state on real kernels" names provider categories at a useful resolution.
- "Attested execution" already names TDX, SEV-SNP, Nitro, ARM CCA, NVIDIA Hopper, MAA: the right shortlist for the TEE side.

## What the v0 §2 background is missing

1. **No bridge for the EDR reader.** A reviewer who works on endpoint security will not see a single EDR-vocabulary anchor. Insert one paragraph between "Sensor state on real kernels" and "Attested execution" naming the EDR analog: the provider categories map to Linux auditd / IMA, macOS Endpoint Security framework, and Windows ETW, and the construction is at the admission layer above these sources rather than at the EDR product layer.

2. **No load-bearing pre-citation of the attestation lineage.** §2 says the construction is "not new in kind, only in placement"; this claim is uncited in §2, and the body never names Sailer 2004, Coker 2011, or Haldar 2004. The "Attested execution" paragraph should pre-cite Sailer (load-time), Coker (formal principles), Haldar (property attestation); §8 then does the depth pass.

3. **No bridge for the polity reader who does not know OS sensors.** §2 names provider tags but does not say what an OS provider actually is. A polity-substrate reader who has not implemented an EDR will read "kernel callout" without a referent. One sentence per category, with citation, closes the bridge.

4. **The honest-substrate paragraph could cite Coker's "trustworthy mechanism" principle directly.** This is the single citation that makes §2 read as known-lineage rather than stand-alone invention.

5. **Cut suggestion: "Receipts as signed canonical statements" is partially redundant with §3.** Shrink to one sentence pointing at the parent paper's receipt format, freeing space for the EDR-bridge paragraph above.

## How the paper differentiates from the closest prior art

1. **Saroiu-Wolman 2010 (trusted sensors).** Saroiu-Wolman attest the input (a sensor signs its reading); sensor-grounded admission attests the kernel's posture toward a federation of software sensors at decision time, and the attestation lives inside a polity constitution's admission predicate.

2. **Sailer 2004 (IMA) and the load-time-attestation lineage.** IMA is a snapshot at boot; sensor-grounded admission is per-receipt rolling state. The placement (per-receipt, inside the admission predicate of a bilateral treaty) is the load-bearing distinction, not the temporal granularity.

3. **Haldar 2004 and the property-attestation lineage.** Property attestation lifts attestation from "what code is running" to "what property the code has." Sensor-grounded admission lifts further: from "the kernel has the property of running approved code" to "the kernel reports its own sensing-posture property in a falsifiable signed claim that the admission predicate evaluates", tied to the parent paper's amendment cycle through the re-attestation theorem.

## Risk of "this is just TEE attestation rebadged"

Honest verdict: the closest prior art is **Saroiu-Wolman 2010** plus the **property-attestation lineage (Haldar 2004, Coker 2011)**. The irreducible delta over Saroiu-Wolman is that Saroiu-Wolman provides no constitutional layer above the sensor; sensor-grounded admission conditions a polity admission predicate on the attestation, ties it to a bilateral-treaty admission relation, and discharges a re-attestation obligation under amendment. The TEE attestation framing (TDX / SEV-SNP / Nitro) is not the closest prior art; TEE attestation is a different layer (launch measurements), and v0 §8 correctly states this. The reviewer pushback to anticipate is "this is property attestation with a treaty layer", and the defense is the bilateral-treaty composition theorem plus the amendment re-attestation theorem. The risk becomes severe only if Sailer / Coker / Haldar / Saroiu are missing; with those cites and a property-attestation framing paragraph in §2, the contribution is clearly delta-positive.

## Recommended bib additions

```bibtex
@inproceedings{sailerIMA2004,
  author = {Sailer, Reiner and Zhang, Xiaolan and Jaeger, Trent and van Doorn, Leendert},
  title = {Design and Implementation of a {TCG}-based Integrity Measurement Architecture},
  booktitle = {13th USENIX Security Symposium}, pages = {223--238}, year = {2004}}
@article{cokerRemoteAttestation2011,
  author = {Coker, George and Guttman, Joshua and Loscocco, Peter and Herzog, Amy and Millen, Jonathan and O'Hanlon, Brian and Ramsdell, John and Segall, Ariel and Sheehy, Justin and Sniffen, Brian},
  title = {Principles of Remote Attestation},
  journal = {Int. J. Inf. Sec.}, volume = {10}, number = {2}, pages = {63--81}, year = {2011}, doi = {10.1007/s10207-011-0124-7}}
@inproceedings{haldarSemanticAttestation2004,
  author = {Haldar, Vivek and Chandra, Deepak and Franz, Michael},
  title = {Semantic Remote Attestation: A Virtual Machine Directed Approach to Trusted Computing},
  booktitle = {USENIX VMRTS}, year = {2004}}
@inproceedings{saroiuTrustedSensors2010,
  author = {Saroiu, Stefan and Wolman, Alec},
  title = {{I Am a Sensor, and I Approve This Message}},
  booktitle = {HotMobile}, year = {2010}, doi = {10.1145/1734583.1734597}}
@inproceedings{liuTrustedSensors2012,
  author = {Liu, He and Saroiu, Stefan and Wolman, Alec and Raj, Himanshu},
  title = {Software Abstractions for Trusted Sensors},
  booktitle = {MobiSys}, pages = {365--378}, year = {2012}, doi = {10.1145/2307636.2307670}}
@inproceedings{asokanSEDA2015,
  author = {Asokan, N. and Brasser, Ferdinand and Ibrahim, Ahmad and Sadeghi, Ahmad-Reza and Schunter, Matthias and Tsudik, Gene and Wachsmann, Christian},
  title = {{SEDA}: Scalable Embedded Device Attestation},
  booktitle = {CCS}, pages = {964--975}, year = {2015}, doi = {10.1145/2810103.2813670}}
@article{chengTDXDemystified2024,
  author = {Cheng, Pau-Chen and others},
  title = {Intel {TDX} Demystified: A Top-Down Approach},
  journal = {ACM Computing Surveys}, volume = {56}, number = {9}, year = {2024}, doi = {10.1145/3652597}}
@misc{amdSEVSNP2020,
  author = {{AMD}}, title = {{SEV-SNP}: Strengthening VM Isolation with Integrity Protection and More},
  year = {2020}, howpublished = {AMD White Paper}}
@inproceedings{newmanSigstore2022,
  author = {Newman, Zachary and Meyers, John Speed and Torres-Arias, Santiago},
  title = {Sigstore: Software Signing for Everybody},
  booktitle = {CCS}, pages = {2353--2367}, year = {2022}, doi = {10.1145/3548606.3560596}}
@misc{applePlatformSecurity2024,
  author = {{Apple Inc.}}, title = {Apple Platform Security},
  year = {2024}, howpublished = {Technical Documentation}}
@misc{nistSP800155,
  author = {{NIST}}, title = {{BIOS} Integrity Measurement Guidelines},
  howpublished = {NIST SP 800-155 (Draft)}, year = {2011}}
@inproceedings{kotziasUnwantedApps2021,
  author = {Kotzias, Platon and Caballero, Juan and Bilge, Leyla},
  title = {How Did That Get In My Phone? Unwanted App Distribution on Android Devices},
  booktitle = {IEEE S\&P}, pages = {53--69}, year = {2021}, doi = {10.1109/SP40001.2021.00041}}
@misc{linuxAuditSubsystem,
  author = {Grubb, Steve}, title = {The {Linux} Audit Subsystem},
  year = {2017}, howpublished = {Linux kernel documentation}}
```

## Report back

**Single most load-bearing missing citation:** Sailer, Zhang, Jaeger, van Doorn 2004 (IMA, USENIX Security). Canonical Linux integrity-measurement-architecture paper and the closest pre-existing "structural placement of an attestation" reference. A USENIX Security PC reviewer who sees neither this cite nor Coker 2011 in §2 will read the paper as not-aware-of-lineage. The v0 cites neither: this is the single highest-impact gap.

**Honest verdict on contribution delta:** Delta-positive but structural and modest. Sensor-grounded admission is property attestation (Haldar 2004) plus trusted-sensor abstractions (Saroiu 2010, Liu 2012) lifted into a polity constitution's admission predicate, composed bilaterally, and discharged through an amendment re-attestation obligation. The genuine novelty is the constitutional layer above the attestation, not the attestation itself; the paper's voice already says this honestly ("not new in kind, only in placement"). A reviewer who treats the parent-paper substrate as the load-bearing contribution will accept the delta. A reviewer in isolation will be more skeptical; the defense is the property-attestation framing in §2 plus the constitutional-composition theorems. Risk of "this is X with a new name" is manageable with the §8 depth pass and a one-paragraph property-attestation framing in §2; the v0 has neither, and that §2 framing paragraph is the cheapest, highest-leverage edit.
