# Single-Key Collapse of Bilateral Cosignature in Sensor-Grounded Admission

Research note, May 2026. No paper-file edits attempted; this is a read-only survey of TEE-rooted attestation-key separation, threshold-signing patterns, and hardware-root-of-trust models, anchored against the paper's own acknowledgement that the construction signs body and attestation under the same key.

## 1. Top finding

Structurally enforced attestation-key independence from application-signing-key DOES exist in commodity hardware. Every surveyed TEE platform (Intel TDX, AMD SEV-SNP, Apple Secure Enclave, Microsoft Pluton TPM, OP-TEE on Arm, OpenTitan, TCG TPM 2.0) provisions a platform-rooted attestation-signing key (TPM Endorsement Key derived Attestation Key, TDX Quoting Enclave key signed by Provisioning Certification Key, AMD VCEK / VLEK, Apple User Identity Key) whose private material is sealed inside the hardware boundary and is, by construction, not the same key the workload uses to sign its own outputs. The sensor-grounded admission paper, however, explicitly signs the attestation with the same kernel key that signs the receipt body (`sections/03-substrate.tex:18`: "The attestation is signed by the same key that signs the receipt body"; `sections/04-model.tex:59`: "Attestation and body are signed by the same kernel key in the construction here"). The mechanism is therefore not unrealistic; it is just not yet wired in. The marginal cryptographic guarantee of separate keys is real, available in deployed hardware, and the paper's own §4 names it as "an extension axis."

The parent paper anticipated this exact failure mode at `programmable-sovereignty/sections/09-limitations.tex:20`: "two-key DSSE under a single actor collapses to one-of-one (kernel-independence attestation is left as a future substrate primitive)." The sensor-grounded paper inherits the row without contradiction but also without closing it.

## 2. TEE-rooted attestation-key separation

The Intel TDX attestation architecture, documented in the Intel TDX DCAP Quote Generation and Verification Library API, Rev 0.9 (May 2025) and the Intel TDX Module Base Architecture Specification 348549-002US (January 2023), provisions two architectural enclaves inside the CPU package: the Provisioning Certification Enclave (PCE) holds the Provisioning Certification Key (PCK) derived from fused secrets, and the Quoting Enclave (QE) generates an ECDSA attestation key signed under the PCK. The TDREPORT_STRUCT produced by the TD is countersigned into a TDX Quote by the QE's attestation key, never by any application-level key the TD's workload controls. AMD SEV-SNP applies the same structural choice through a different key class: the AMD SEV Secure Nested Paging Firmware ABI Specification 56860 r1.58 (May 2025) Table 21 defines the `ATTESTATION_REPORT` as signed by the Versioned Chip Endorsement Key (VCEK), unique to each AMD chip at a specific TCB version, or the alternative Versioned Loaded Endorsement Key (VLEK) introduced in r1.54 for cloud-provider-rooted attestation. Both are firmware-managed; the guest VM cannot sign an `ATTESTATION_REPORT` under any key it chose.

Apple's User Identity Key (UIK), documented in the Apple Platform Security Guide and the Apple Secure Enclave Processor security certifications, is a P-256 keypair derived from the UID inside the SEP, accessible only to the Public Key Accelerator hardware block, and not even readable by sepOS. Apple's Managed Device Attestation and WebAuthn attestation flows sign attestation tickets under UIK; an application's data-signing key, even a SEP-resident one, is a separate object the UIK certifies.

Microsoft Pluton, documented at `learn.microsoft.com/en-us/windows/security/hardware-security/pluton/microsoft-pluton-security-processor`, implements a TPM 2.0 functional surface integrated into the CPU die. Pluton's Attestation Key follows the TCG TPM 2.0 Library Specification Part 1 (revision 1.83), which mandates that the Endorsement Key (EK) private half "is expected to never be exposed outside of the TPM hardware" and that Attestation Keys (AKs) are restricted signing keys certified by the EK Credential.

The structural pattern is consistent across vendors: a hardware-rooted attestation key signs *attestations*, an application-controlled key signs *workloads*, and the verifier accepts an attestation only if the AK is certified back to a platform endorsement key.

## 3. Threshold-signing patterns

FROST (Komlo and Goldberg, SAC 2020, ePrint 2020/852; RFC 9591) and MuSig2 (Nick, Ruffing, and Seurin, CRYPTO 2021, ePrint 2020/1261) give two-round threshold and multi-signature constructions over Schnorr / Ed25519 with security under concurrent signing sessions. Threshold BBS+ (Doerner, Kondi, Lee, Shelat, Tyner, IEEE S&P 2023, ePrint 2023/602) extends the pattern to anonymous-credential issuance. The structural use against single-key collapse is direct: if the paper's substrate required the attestation to be signed by a `t`-of-`n` quorum where `t-1` of the shares live in a distinct trust domain from the body-signing material, single-actor collapse becomes a `t`-key compromise rather than a one-key compromise. The cost is real: FROST requires a coordinator and one round of pre-processing; MuSig2 requires nonce aggregation discipline. Both produce signatures syntactically identical to single-key Schnorr / Ed25519, so the receipt schema needs no change.

The threshold pattern is structurally distinct from TEE-rooted separation. TEE-rooted separation enforces that a single party operate two non-interchangeable keys on the same host. Threshold signing enforces that two or more parties cooperate to produce one signature. The former hardens against a workload-level compromise of one principal; the latter hardens against compromise of one of `n` principals. Both close the single-key-collapse hole, but on different threat models.

## 4. Hardware-root-of-trust models

Apple's Secure Enclave produces the UIK already covered above. Microsoft Pluton's TPM 2.0 surface produces AKs whose private halves the OS and kernel cannot read; the AKs sign `TPM2_Quote` outputs binding PCR values into a verifier-checkable structure, certified by the EK. Google's OpenTitan, documented at `opentitan.org/book/doc/security/`, exposes attestation as a discrete-manufactured-RoT capability with provisioning-time identity and per-owner attestation PKIs. OP-TEE on Arm TrustZone, with the Trusted and Encrypted Keys subsystem documented at `docs.kernel.org/security/keys/trusted-encrypted.html`, roots keys in a Hardware Unique Key burned into on-chip fuses; the HUK is accessible only inside the secure world, and trusted keys sealed under it are not exfiltratable to the normal-world kernel.

The deployment posture across these models is the same: every model produces a signed attestation, of some quantity (boot measurement, PCR set, sealed-config ledger, or a workload-supplied report-data nonce), under a key whose private material the running OS and kernel cannot extract. None of them, however, produces a *sensor-state* attestation in the sense the sensor-grounded admission paper defines: every quantity attested is launch-time code identity or post-launch hash-chain extension, not per-sensor coverage flags. The `research/tee-attestation-delta.md` note already established this gap. The point here is narrower: a TEE-rooted kernel could sign a `(installed, active, healthy, degraded, drop, miss)` provider record under an attestation key whose private material is sealed inside the TEE, and a separate body-signing key would still sign the receipt body. The two keys would be structurally separated by hardware, not by operational discipline.

## 5. Prior-art critique

No surveyed paper makes the *exact* single-key collapse argument against TEE attestation applicable to this paper, because deployed TEE attestation already has key separation: there is no collapse to argue against. The closest critiques in the literature target adjacent failures. The Privacy Preserving and Post-Compromise Secure Attestation work at HAL hal-05245012 (March 2025) treats the case where a compromised TEE leaks both its attestation key and its workload key and asks how recovery is possible; the assumption that the two keys are structurally distinct is foundational to the threat model. Coker, Guttman, Loscocco, Herzog, Millen, O'Hanlon, Ramsdell, Segall, Sheehy, and Sniffen's *Principles of Remote Attestation* (Int. J. Inf. Sec. 2011) names domain separation as one of five principles, motivated explicitly by the failure mode where the attesting agent and the workload it attests share a trust boundary. The IETF RATS architecture (RFC 9334, Section 4.2) names the Attesting Environment and the Target Environment as distinct, with the Attesting Environment certifying claims about the Target rather than producing claims under the Target's own key.

The sensor-grounded admission paper falls below this baseline. The receipt body is the Target; the sensor attestation is a claim about the kernel's coverage of the Target's substrate; the kernel signs both under one key. The RATS architecture's name for this collapse is "the Attester is also the Target," which RFC 9334 admits as a degenerate case and warns the verifier to treat with caution.

## 6. Verdicts and recommended paper response

(a) Deployed TEE platforms structurally enforce sensor-attestation-key independence from application-signing-key. The paper's fix-in-principle (separate signing keys for attestation and body) is realistic in any deployment with a TPM 2.0, an SEV-SNP / TDX TEE, Apple SEP, Microsoft Pluton, OP-TEE, or OpenTitan present.

(b) The paper's current construction (one kernel key signs both) is a structural choice, not a hardware limitation. The §4 acknowledgement ("a separate attestation key, rooted in a TEE platform's quote-signing identity, would make the strengthening cryptographic in addition to structural and is named as an extension axis") is honest but understated; the structural improvement is available, not speculative.

(c) Recommended response, smallest to largest:

1. Add a §9 limitation row in the existing table format: *Assumption*: Body-signing and attestation-signing keys are the same kernel key. *Used for*: Single-actor receipt + attestation issuance. *Residual risk*: A compromised kernel signs coherent false attestations; the strengthening is structural, not cryptographic. The cryptographic strengthening is available through TEE-rooted attestation-key separation (Intel TDX QE / PCE, AMD SEV-SNP VCEK, TPM 2.0 AK / EK, Apple SEP UIK) and is named in `sections/04-model.tex:59` as an extension axis.

2. Add a stub theorem in `lean/SensorGroundedAdmission.lean`: `sensor_attestation_marginal_trust_requires_separate_key`, stating that under a model where the same key signs body and attestation, the marginal cryptographic content of the attestation collapses to the body's authentication. The proof would be a one-line existence: a kernel that can sign the body can also sign any attestation, so the attestation's signed claim is a no-op cryptographically. This is a *structural* theorem, not a cryptographic one; it makes the paper's own §4 prose load-bearing in Lean.

3. Add a §3 paragraph (after "Falsifiable but not externally audited") naming the key-separation extension axis explicitly: "A TEE-rooted attestation-signing key whose private material is sealed inside the platform's hardware boundary (Intel TDX Quoting Enclave, AMD SEV-SNP VCEK / VLEK, Apple SEP UIK, Microsoft Pluton AK, TPM 2.0 AK certified by EK) would produce a cryptographic strengthening: a compromised workload-key alone could not sign a coherent attestation. The construction here does not assume that environment; the extension axis is a deployment choice, not a substrate change."

The §9 row is the minimum honest fix and closes the single-key-collapse finding. The Lean theorem is the structural strengthening. The §3 paragraph closes the prose-honesty gap that the §4 line currently carries alone.

## 7. Bibkey stubs for new citations

- `\bibitem{komloFROST2020}` Komlo, C. and Goldberg, I. *FROST: Flexible Round-Optimized Schnorr Threshold Signatures*. Selected Areas in Cryptography 2020. ePrint 2020/852. RFC 9591 (December 2024).
- `\bibitem{nickMuSig2_2021}` Nick, J., Ruffing, T., and Seurin, Y. *MuSig2: Simple Two-Round Schnorr Multi-Signatures*. CRYPTO 2021, ePrint 2020/1261.
- `\bibitem{doernerThresholdBBS2023}` Doerner, J., Kondi, Y., Lee, E., Shelat, A., and Tyner, L. *Threshold BBS+ Signatures for Distributed Anonymous Credential Issuance*. IEEE S&P 2023, ePrint 2023/602.
- `\bibitem{intelTDXDCAP2025}` Intel Corporation. *Intel TDX DCAP Quote Generation Library and Quote Verification Library API*. Rev 0.9, May 2025. Already in `tee-attestation-delta.md`; cite Section 2 and Appendix A.3 for QE-key-from-PCE-certification.
- `\bibitem{amdSEVSNP2025}` Advanced Micro Devices. *SEV Secure Nested Paging Firmware ABI Specification*. Publication 56860 r1.58, May 2025. Already covered; cite Table 21 for VCEK / VLEK signing.
- `\bibitem{tcgTPM2Library}` Trusted Computing Group. *TPM 2.0 Library Specification Part 1: Architecture*. Revision 1.83 (TODO_VERIFY: latest revision number).
- `\bibitem{applePlatformSecurity2024}` Apple Inc. *Apple Platform Security Guide*. Already cited as `applePlatformSecurity2024`; cite the "Secure Enclave" and "Attestation process security" subsections for UIK separation.
- `\bibitem{rfc9334RATS}` Already cited; the Section 4.2 Attester / Target distinction is the standards-anchor for the structural separation argument.

## Sources

- [Intel TDX DCAP Quote Library API Rev 0.9, May 2025](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf)
- [AMD SEV-SNP Firmware ABI Specification 56860, r1.58](https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf)
- [Apple Platform Security: The Secure Enclave](https://support.apple.com/guide/security/the-secure-enclave-sec59b0b31ff/web)
- [Apple Platform Security: Attestation process security](https://support.apple.com/guide/security/attestation-process-security-sec97eb9e2f2/web)
- [Microsoft Pluton security processor documentation](https://learn.microsoft.com/en-us/windows/security/hardware-security/pluton/microsoft-pluton-security-processor)
- [TCG TPM 2.0 Library Specification Part 1: Architecture](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf)
- [TCG TPM 2.0 Keys for Device Identity and Attestation](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf)
- [OpenTitan Security Documentation](https://opentitan.org/book/doc/security/)
- [Linux Trusted and Encrypted Keys (OP-TEE)](https://docs.kernel.org/security/keys/trusted-encrypted.html)
- [Komlo and Goldberg, FROST, SAC 2020, ePrint 2020/852](https://eprint.iacr.org/2020/852)
- [Nick, Ruffing, Seurin, MuSig2, CRYPTO 2021, ePrint 2020/1261](https://eprint.iacr.org/2020/1261)
- [Doerner, Kondi, Lee, Shelat, Tyner, Threshold BBS+, IEEE S&P 2023, ePrint 2023/602](https://eprint.iacr.org/2023/602)
- [RFC 9591, The FROST Protocol for Two-Round Schnorr Signatures](https://datatracker.ietf.org/doc/html/rfc9591)
- [Privacy Preserving and Post-Compromise Secure Attestation, HAL hal-05245012](https://hal.science/hal-05245012v1/document)
- [RFC 9334, Remote Attestation Procedures Architecture](https://www.rfc-editor.org/rfc/rfc9334.html)
