# Wave 7A: Recent Prior Art Survey

Date: 2026-05-18

## Headline finding

§8 is NOT defensible as it stands. The dominant gap is the absence of any reference to IETF SCITT (Supply Chain Integrity, Transparency, and Trust): draft-ietf-scitt-architecture-22 reached AUTH48 in October 2025 as a Proposed Standard and explicitly specifies cross-organizational signed statements with countersignature receipts. Bilateral DSSE is vocabulary-adjacent to what SCITT calls "a signed statement countersigned by a transparency service." A reviewer who has tracked the IETF will flag the omission. Two further must-adds follow from the same family: RFC 9942 (COSE Receipts, also AUTH48) and in-toto attestation framework v1.2.0 (March 2024). After those three, §8 reads as defensible. Cycle 1 USENIX adds two should-cite candidates (Cremers on protocol composition, Distributed Vector Commitments).

## USENIX Security 2026 Cycle 1 candidates

**Secure Protocol Composition under Dynamic Corruption** -- Cas Cremers, Erik Pallas, Aleksi Peltonen (CISPA). Applied pi-Calculus composition with disjointness, demonstrated on TLS 1.3 + ECH. RELEVANCE: HIGH-MEDIUM. Bilateral DSSE is a runtime-level composition of two DSSE verifications, not symbolic protocol composition, but Cremers is the closest cryptographic-protocol-literature anchor for "composition under attacker corruption." ePrint 2026/900.

**Distributed Vector Commitments and Their Applications** -- Gao, Wang (Nanjing PT), Wan (Hangzhou Normal), Hu (SJTU). DVC where vector splits across machines. RELEVANCE: MEDIUM. §3's binding tuple commits to ten field hashes in one digest, structurally a vector commitment. One-sentence cite alongside IRONDICT.

**Efficient Threshold ML-DSA** -- Celi (Brave), del Pino, Espitau, Niot, Prest (PQShield, IRISA). PQ threshold ML-DSA up to 6 parties. RELEVANCE: MEDIUM. Strengthens any PQ-migration footnote in §7. ePrint 2026/013.

**MASLEAK** (Wang et al., HKUST/Renmin/Lingnan). MAS IP-leakage attack. RELEVANCE: LOW. Threat-model-adjacent to agent-and-tool paragraph but bilateral primitive does not address IP leakage; citing is a stretch.

**Tracegram, Verity, Shred-to-Shine, Garuda and Pari** -- All examined. None direct fits: Tracegram is MIL for traffic analysis; Verity is verifiable LDP; the latter two are SNARK-internal MLPCS work. DROP all four.

## NDSS 2026

NDSS 2026 (265 accepted: 113 summer, 152 fall):

**ACTS: Attestations of Contents in TLS Sessions** -- Della Monica, Visconti, Vitaletti, Zecchini (Sapienza). Cryptographic attestation that a TLS session contained specific contents. RELEVANCE: MEDIUM. Both bilateral DSSE and ACTS are "attestation of action" rather than "attestation of state" (the IMA-2004 family). Cite alongside SAGA in the agent-and-tool paragraph.

**Les Dissonances** (Li, Cui, Liao, Xing, UIUC). Cross-tool attack class. RELEVANCE: LOW-MEDIUM. Reinforces the "topologically distinct boundary" claim; not load-bearing.

**EXIA** (Huang et al., SJTU/Auburn). Within-enclave attestation. RELEVANCE: LOW.

NDSS 2026 contains no direct bilateral-cosigning paper. SAGA NDSS 2025 remains the closest anchor; no follow-up exists.

## ACM CCS 2025 / 2026

CCS 2025 (Taipei, October 13-17, 2025; 316 accepted, 14.5%). The accepted-papers page does not enumerate titles in a WebFetch-accessible form (403/empty). Targeted searches for transparency-log, in-toto, DSSE, cosigning, and threshold-signing in CCS 2025 surfaced no direct-fit candidate. The 2022 PolyLog SCORED paper is relevant but predates the bib window. CCS 2026 CFP closes August 2026; accepted papers will not appear before USENIX Cycle 2 deadline. TODO_VERIFY: a manual sweep of https://dblp.org/db/conf/ccs/2025.html. Absent that, treat CCS 2025 as no must-cite contribution.

## IETF drafts and standards

**draft-ietf-scitt-architecture-22 (SCITT)** -- Birkholz, Delignat-Lavaud, Fournet, Pavlovic, Steele. AUTH48 (entered 2025-10-10), Proposed Standard. Specifies cross-organizational signed statements registered with a transparency service that returns a COSE-signed countersignature receipt. Multi-issuer explicit: "Multiple Issuers can make different, even conflicting Statements, about the same Artifact." URL: https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/. THE CRITICAL MISSING CITATION. §8 needs one paragraph distinguishing: bilateral DSSE constrains BOTH parties to be admission-time cosigners with bytes-equal canonicalization and a predicate-conjunction accept-set; SCITT permits a single issuer and a separate witness service.

**RFC 9942 (COSE Receipts, draft-ietf-cose-merkle-tree-proofs-18)** -- Steele (Tradeverifyd), Birkholz (Fraunhofer SIT), Delignat-Lavaud and Fournet (Microsoft). AUTH48 with RFC 9942 assigned. Specifies COSE encoding of Merkle inclusion/consistency proofs for transparency-log receipts. The wire-format companion of SCITT. Cite to ground the COSE-vs-DSSE choice.

**in-toto Attestation Framework v1.2.0** (March 18, 2024) -- Adds Simple Verification Result (SVR) predicate and Rust bindings; ITE-5 compliance. The bib cites the 2019 origin paper (torres2019intoto); the spec has versioned forward six times.

**DSSE v1.0.2** (May 10, 2024) -- The bib's `dsse` entry points to GitHub master without pinning a version. Tighten to v1.0.2.

## Recommended must-add citations (priority order)

1. **scittArchitecture2025** -- Birkholz, Delignat-Lavaud, Fournet, Pavlovic, Steele, "An Architecture for Trustworthy and Transparent Digital Supply Chains," draft-ietf-scitt-architecture-22 (AUTH48, October 2025) / RFC TBD. LANDS in the supply-chain-provenance paragraph, between the in-toto/SLSA/Sigstore/Rekor chain and IRONDICT. CLAIM SUPPORTED: places bilateral-DSSE inside the IETF transparency-service vocabulary, distinguishing bilateral-admission cosigning from single-issuer transparency-service countersignature. ONE-SENTENCE INSERT: "SCITT's transparency-service receipt countersigns a single-issuer statement; bilateral DSSE constrains both parties to cosign the same admission-time binding tuple, attesting a joint accept rather than a single-side issuance plus a separate notarisation."

2. **rfc9942** -- Steele, Birkholz, Delignat-Lavaud, Fournet, "COSE Receipts," RFC 9942 (AUTH48, expected publication mid-2026). LANDS in the same paragraph or in §5's wire-format discussion. CLAIM SUPPORTED: justifies the DSSE-over-COSE choice. ONE-SENTENCE INSERT: "RFC 9942's COSE Receipts standardize Merkle-inclusion proofs as countersignatures for transparency-service deployments; bilateral DSSE uses JCS-canonicalised JSON and Ed25519 because the relying party is the receiving kernel, not an asynchronous log auditor."

3. **intotoAttestation12** -- in-toto Attestation Framework v1.2.0 (March 2024). LANDS in the supply-chain-provenance paragraph as a follow-on to torres2019intoto. CLAIM SUPPORTED: the bib cites the 2019 origin paper for a spec that has evolved through six versions; pin the modern revision.

4. **cremersCompositionUS26** -- Cremers, Pallas, Peltonen, "Secure Protocol Composition under Dynamic Corruption," USENIX Security 2026 Cycle 1 (ePrint 2026/900). LANDS in a new sentence at the end of the property-attestation paragraph or in §4's framing. CLAIM SUPPORTED: the modern symbolic-composition vocabulary for §4's modest accept-set witness. ONE-SENTENCE INSERT: "Cremers et al.'s compositional symbolic analysis applies to single-protocol composition under dynamic corruption; the bilateral primitive composes two verifications at runtime, a structurally simpler regime where the byte-level digest commitment substitutes for an applied-pi disjointness proof."

5. **distributedVCUS26** -- Gao, Wang, Wan, Hu, "Distributed Vector Commitments and Their Applications," USENIX Security 2026 Cycle 1. LANDS alongside IRONDICT in the supply-chain-provenance paragraph. CLAIM SUPPORTED: the binding-tuple-as-commitment framing; one-sentence cite.

## Recommended should-add citations

- **threshholdMLDSA2026** (Celi et al., USENIX 2026 Cycle 1) -- only if a PQ-migration footnote is added to §7.
- **actsNDSS2026** (Della Monica et al.) -- if the agent-and-tool paragraph expands its "post-2024 attestation literature" framing.
- **dsseV102** (Secure Systems Lab, v1.0.2, May 2024) -- tighten the existing `dsse` cite.

## Closed gaps

- The IRONDICT (hafeziIRONDICT2026) and UncoreBleed (uncoreBleed2026) citations are correct and current.
- The SAGA NDSS 2025 cite is the right NDSS anchor; no NDSS 2026 successor exists.
- The Cedar OOPSLA 2024 / FSE 2024 pair is sufficient for the policy-language paragraph; no 2025 follow-up needed.
- IsolateGPT NDSS 2025 is the right agent-isolation anchor.

## Open questions for the orchestrator

- TODO_VERIFY: CCS 2025 accepted-papers list could not be enumerated via WebFetch (403 on dl.acm.org, empty on sigsac.org/CCS2025/accepted-papers). A reviewer could surface a CCS 2025 paper I missed. Recommended action: a human pass over the DBLP CCS 2025 listing https://dblp.org/db/conf/ccs/2025.html before submission.
- The SCITT architecture RFC number is not yet assigned at the time of this survey; once published, replace the draft-22 cite with the RFC number.
- RFC 9942 publication is imminent (AUTH48 entered Q4 2025); the citation should use the RFC number rather than the draft-18 ID.

## Bottom line

Three must-add citations close the gap (SCITT, RFC 9942, in-toto v1.2.0). Two should-add citations from Cycle 1 strengthen the framing (Cremers, Distributed VC). With these five, §8 becomes defensible against a SCITT-aware or in-toto-aware reviewer. Without the SCITT cite specifically, a USENIX PC reviewer who has read draft-ietf-scitt-architecture will reject §8 as out-of-date on the central comparator.
