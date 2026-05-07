# Chiodos Trust-Anchor Bootstrap Costs Per Sector

Status: Research / operational. Not normative. Informs go-to-market sequencing for chiodos adoption.
Date: 2026-05-04 (v1.0)
Companion to: [CHIODOS_CONCEPT.md](CHIODOS_CONCEPT.md), section 2.5 ("Trust Anchor Honesty").

---

## 1. Intent

[CHIODOS_CONCEPT.md section 2.5](CHIODOS_CONCEPT.md) acknowledges that chiodos unbundles centralisation from the wire but does not eliminate it from operations. Each kernel still has to answer the operational question: "which kernel public keys do I accept handshakes from in the first place?" The protocol layer is sovereignty-preserving; the bootstrap layer is not, and chiodos deliberately does not specify it.

This document analyses what that operational posture costs per industry sector. It is not a protocol proposal. It is the input to a sequencing decision: where can chiodos ride existing infrastructure inside a year, where does the federation need a chiodos-specific consortium, and where is the trust-anchor problem genuinely unsolved.

The analysis does not claim every sector will adopt chiodos. It claims that adoption sequencing is gated by the bootstrap-layer cost, and that cost is uneven enough across sectors to make the sequencing decision strategic.

---

## 2. Framework: Four Bootstrap Models

Per [CHIODOS_CONCEPT.md section 2.5](CHIODOS_CONCEPT.md), four bootstrap models are available. Each is plausible somewhere; none is plausible everywhere.

### 2.1 Industry Consortium Roster

A sector-specific membership organisation publishes and signs the canonical roster of accepted kernel public keys. Members onboard once via the consortium, and any participating kernel pins the consortium's roster as a trust source.

Examples in flight today: FS-ISAC, H-ISAC, E-ISAC, Auto-ISAC, RH-ISAC, REN-ISAC, Aviation ISAC, MTS-ISAC. Most run as 501(c)(6) trade alliances; some are non-profits with government cooperative agreements ([National Council of ISACs](https://www.nationalisacs.org/)).

### 2.2 Out-of-Band PKI

A certificate authority (or federation of CAs), independent of the chiodos protocol, issues kernel-key certificates that chiodos relying parties verify. Trust path is `kernel_key -> sector_CA -> root` and the chiodos handshake checks the chain rather than a roster lookup.

Examples: SWIFT PKI for interbank messaging, DirectTrust PKI for healthcare Direct messaging, the Federal PKI / FBCA for government, DoD PKI cross-certified with FBCA at FBCA Medium Hardware assurance ([cyber.mil PKI/PKE interoperability](https://www.cyber.mil/pki-pke/interoperability/)).

### 2.3 Operator-Mediated Key Exchange

Two kernels' operators exchange pinned public keys directly (email, signed document, in-person at a working group). No roster, no CA. Scales to dozens of peers; does not scale to thousands.

Universally available because it requires no infrastructure. The default early-adoption posture for any sector without a natural anchor.

### 2.4 Sector Regulator Publishing the Canonical Roster

A government regulator with sectoral authority publishes the accepted kernel-key roster as a regulatory artefact. Onboarding is a regulatory filing rather than a private contract.

Plausible only where the regulator already controls a comparable list (e.g., bank charters, NRC reactor licences, FAA part 121 carriers). Carries the regulatory-capture risk noted in section 7.

### 2.5 Cost Dimensions

Each per-sector entry in section 3 is rated against six dimensions:

- **Operational setup cost**: one-time spend to stand up the bootstrap (CA hardware, governance committees, legal review). Low / Medium / High.
- **Ongoing maintenance**: recurring spend to operate the bootstrap (key rotation, audits, dispute handling).
- **Governance friction**: how hard is it to add, remove, or reclassify a participant? Includes voting overhead, regulatory review, sectoral politics.
- **Scalability ceiling**: how many participants can plausibly be supported before the bootstrap mechanism breaks?
- **Cross-sector portability**: can a participant's bootstrap credential be reused in an adjacent sector, or does each sector require fresh onboarding?
- **Time-to-first-handshake**: from a participant's first contact to the first valid bilateral chiodos handshake.

These dimensions are not orthogonal (low setup cost often implies a low scalability ceiling, for instance) but they do split the sectors usefully.

---

## 3. Per-Sector Analysis

Each subsection covers: natural roster issuer, suitability as a chiodos roster issuer, operational cost band, named friction points, and a 1-5 readiness rating (5 = chiodos can bootstrap on existing infrastructure within 6 months; 1 = no path without inventing the anchor).

### 3.1 Financial Services (banking, insurance, payments)

The natural anchor is bifurcated. Interbank messaging already runs over [SWIFT PKI](https://www.swift.com/myswift/join-swift), with BIC-bound key material and the [Customer Security Programme (CSP)](https://worldinformatixcs.com/2025/10/16/swift-csp-2026-changes-you-need-to-know/) operationalising key rotation and attestation; the v2026 CSCF promotes Control 2.4 from advisory to mandatory. For a bank-to-bank chiodos, SWIFT's PKI is a usable bootstrap with minor schema work to bind a kernel key to a BIC. Outside interbank, [FS-ISAC](https://www.fsisac.com/) connects roughly 7,000 institutions across 70+ jurisdictions and is the obvious roster issuer for non-bank financial-services participants (insurers, fintech, payment processors). Insurance does not currently have an FS-ISAC equivalent specific to it; payments has overlapping coverage from FS-ISAC plus the PCI Security Standards Council (which is a controls publisher, not a PKI). The friction is governance, not infrastructure: FS-ISAC membership has admission gates and member-tier-driven access controls that will need to extend to "kernel-key publication" as a first-class data type, and SWIFT's CSP attestation regime will not accept a chiodos passport as evidence without explicit expansion.

Readiness: 4 (banks via SWIFT PKI in 6-12 months; broader FS-ISAC roster needs 12-18 months for the data type to land).

### 3.2 Healthcare (providers, payors, pharma, clearinghouses)

Two viable anchors. [Health-ISAC](https://health-isac.org/) connects "thousands of health security professionals" across 140 countries and has the membership reach to act as a roster issuer for the provider, payor, pharma, and device segments. Separately, [DirectTrust](https://directtrust.org/what-we-do/trust-framework) operates a PKI that already underwrites Direct Secure Messaging across 2.7M identity-proofed endpoints at 260,000 organisations, with a [2026 accreditation criteria refresh](https://www.financialcontent.com/article/accwirecq-2026-1-5-directtrustr-announces-2026-accreditation-criteria-versions-for-all-accreditation-programs) including a new AI accreditation program mapped to NIST AI RMF. DirectTrust is the rare healthcare PKI that already exists at scale and has a governance regime that can absorb a kernel-key endpoint type. The friction points are HIPAA/HITECH downstream-liability framing (payors are very cautious about any new attestation surface that could be discovered in a breach action) and the providers' fragmentation (a regional clinic and a 50-hospital integrated delivery network have very different operational maturities).

Readiness: 4 (DirectTrust path is short for messaging-flavoured scenarios; clinical-data scenarios are slower because of HIPAA).

### 3.3 Energy and Utilities

[E-ISAC](https://www.nerc.com/programs/e-isac), operated by NERC, is the natural roster issuer for the electric subsector and has a $45.2M 2026 budget including CRISP. NERC CIP standards are themselves operationally binding on registered entities (CIP-003-9 effective 2026-04-01, CIP virtualisation standards finalised by [FERC Orders 918 and 919 in March 2026](https://www.certrec.com/blog/most-significant-nerc-cip-updates-for-2026/)), so a chiodos passport that maps to a CIP-tagged BES Cyber System has natural compliance hooks. The downstream-natural-gas and oil subsectors run separate ISACs (DNG-ISAC, ONG-ISAC). The friction is structural: E-ISAC's governance is intertwined with NERC's enforcement function, which the [E-ISAC 2025 report itself flags as a chilling factor on incident sharing](https://ampyxcyber.com/blog/the-e-isacs-2025-report-real-progress-remaining-constraints), and any chiodos roster issued by E-ISAC inherits that chilling effect on the bilateral co-signing surface. Smaller utilities (municipal, co-operative) cannot afford the CIP-style operational overhead even if NERC adds a chiodos passport endpoint.

Readiness: 3 (electric IOUs in 12-18 months via E-ISAC; gas, water, smaller utilities later).

### 3.4 Telecommunications

The [Communications ISAC](https://www.cisa.gov/resources-tools/programs/communications-information-sharing-and-analysis-center-comm-isac) (also called the National Coordinating Center for Communications, NCC) is operated under Executive Order 13618 by CISA and has 80 government partners and 77 private-sector members. It is closer to a public-private clearinghouse than a sectoral consortium, and it does not currently issue PKI material. ETSI publishes standards but not roster data. Carrier-to-carrier coordination today runs over a mix of bilateral peering agreements, GSMA / 3GPP roaming PKI for mobile, and i3Forum / MEF for inter-carrier messaging; none of these issue a generic kernel-key roster. A chiodos rollout here would either ride the GSMA PKI (works for mobile-network-operator scenarios but not fixed-line) or stand up a new consortium under COMM-ISAC sponsorship.

Readiness: 2 (no clean anchor; the mobile slice can ride GSMA PKI, but the rest needs invention).

### 3.5 Defense and Intelligence

Most centralised already. The [DoD PKI cross-certifies with the Federal PKI at FBCA Medium Hardware assurance](https://www.cyber.mil/pki-pke/interoperability/), with the most recent Federal Bridge CA G4 cross-certificate to the DoD Interoperability Root CA 2 [issued 2026-01-27 valid through 2029](https://www.idmanagement.gov/fpki/notifications/), and the FBCA Cross-Certification Evaluation Framework v5.0 (Sept 2024) defines the onboarding gate. A chiodos kernel that pins DoD PKI as a trust source can bootstrap via the existing CAC/PIV-I issuance pipeline; the FBCA bridge gives transitive trust to FedRAMP-authorised vendor kernels. The friction is not the bootstrap (it is in production today) but the destination policy: most defense scenarios are classified-network or controlled-unclassified, and chiodos-style bilateral co-signing will run into accreditation-boundary review under DODI 8520.02 before it sees production traffic.

Readiness: 5 on the bootstrap, 2 on the destination policy. Net 3.

### 3.6 Transportation (aviation, maritime, freight)

Three subsectors with very different maturity. Aviation has [Aviation-ISAC](https://www.a-isac.com/) (founded 2014; airlines, airports, OEMs, IFE/SatCom providers); maritime has [MTS-ISAC](https://www.nationalisacs.org/members) covering ocean carriers, cruise lines, ports, terminals, and logistics; surface freight has [Surface Transportation, Public Transportation, and Over-the-Road Bus ISAC (ST-ISAC, PT-ISAC)](https://www.nationalisacs.org/members) plus [Auto-ISAC](https://automotiveisac.com/) for vehicle OEMs and suppliers (now extended to commercial vehicles after the [2026-Q1 ENX Association MoU](https://automotiveisac.com/press-news) and [Google Cloud's Innovator Partner status from January 2026](https://automotiveisac.com/press-news)). None of these ISACs currently runs a PKI. The friction is fragmentation: a freight forwarder is plausibly a member of three different ISACs (aviation, maritime, ground) and has no canonical roster. Auto-ISAC has the highest concentration of effective control over its membership (the OEMs do drive supplier behaviour), but the supply chain extends well beyond ISAC reach.

Readiness: 3 for aviation, 2 for maritime, 2 for ground freight, 4 for vehicle-OEM (Auto-ISAC plus the Alliance for Automotive Innovation can move).

### 3.7 Retail and E-commerce

[RH-ISAC](https://rhisac.org/) connects 300+ Core Members across retail, hospitality, restaurants, hotels, gaming, food retail, and consumer products, with 2,000+ analysts contributing intel and a [2026 partnership with the Retail Council of Canada](https://www.prnewswire.com/news-releases/retail--hospitality-isac-and-retail-council-of-canada-announce-strategic-partnership-to-strengthen-cybersecurity-across-canadian-retail-sector-302712956.html). Payments compliance overlays this with PCI DSS v4.0.1, but PCI is a controls publisher, not a PKI issuer. Retail does not have a sectoral PKI; the closest analogues are the card-network token-service-provider keys (Visa TR-31, Mastercard MDES) which are payment-scoped and not generalisable. The friction is the long tail: RH-ISAC's 300 Core Members are a small fraction of US retail by entity count, and chiodos adoption would likely be concentrated in the top quartile by revenue.

Readiness: 3 (RH-ISAC can act as roster issuer for the top quartile; the long tail rides operator-mediated exchange or third-party platforms).

### 3.8 Higher Education and Research

[REN-ISAC](https://www.ren-isac.net/) serves over 700 member institutions and acts as the CSIRT for US higher education. Federated identity in this sector already runs at scale via [InCommon](https://incommon.org/) and eduGAIN, and InCommon Federation operates a metadata-distribution model that is structurally close to a chiodos roster: signed metadata aggregates, regular publication, accepted by relying parties. InCommon's metadata signing keys plus the REN-ISAC trust community give higher education the cleanest existing-infrastructure path of any non-government sector. The friction is funding (REN-ISAC dues are modest by sector standards but real for small institutions) and the long tail of community colleges that do not participate in InCommon.

Readiness: 4 (InCommon plus REN-ISAC is the cleanest civilian path; large research universities can move in 6-12 months).

### 3.9 Government (federal, state, local)

Federal government has Federal PKI and FedRAMP, both production-grade, and a chiodos kernel can pin FPKI as a trust source today. State and local government had [MS-ISAC](https://www.cisecurity.org/ms-isac), but the [federal cooperative agreement ended 2025-09-30](https://www.naco.org/news/multi-state-information-sharing-and-analysis-center-ms-isac-loses-federal-funding) and MS-ISAC has shifted to a [subscription model with the lowest tier at $1,495/year](https://insidecybersecurity.com/daily-news/state-and-local-officials-call-reinstating-ms-isac-funding-info-sharing-group-turns); CISA simultaneously [transitioned to direct SLTT support](https://www.cisa.gov/news-events/news/cisa-strengthening-our-nations-security-direct-cyber-support-state-and-local-governments). The result is a discontinuity: federal is high readiness, state/local is mid-transition with the canonical roster issuer still finding its funding model, and tribal/territorial is dependent on whatever MS-ISAC's new model can sustain. EI-ISAC (elections) is a separate subsector with its own membership.

Readiness: 5 federal, 2 state/local (transition risk), 2 tribal/territorial.

### 3.10 Summary Table

| Sector | Natural anchor | Setup cost | Maintenance | Governance friction | Scalability ceiling | Cross-sector portable | Time-to-first-handshake | Readiness |
|---|---|---|---|---|---|---|---|---|
| Banks (interbank) | SWIFT PKI | Low | Low | Low | High | Low | 1-3 months | 5 |
| Other financial services | FS-ISAC | Medium | Medium | Medium | High | Medium | 6-12 months | 4 |
| Healthcare | DirectTrust + H-ISAC | Low | Medium | High (HIPAA) | High | Low | 6-12 months | 4 |
| Electric utilities | E-ISAC / NERC | Medium | High | High (NERC enforcement) | Medium | Low | 12-18 months | 3 |
| Gas / water utilities | DNG-ISAC / WaterISAC | High | High | High | Low | Low | 18-24 months | 2 |
| Telecommunications (mobile) | GSMA PKI | Low | Low | Low | High | Medium | 3-6 months | 4 |
| Telecommunications (other) | COMM-ISAC | High | High | Medium | Medium | Low | 18-24 months | 2 |
| Defense / Intelligence | FPKI / DoD PKI | Low (exists) | Low | Very high (accreditation) | High | High (within USG) | 1-3 months bootstrap, 12-24 months destination | 3 |
| Aviation | Aviation-ISAC | Medium | Medium | Medium | Medium | Low | 12-18 months | 3 |
| Maritime | MTS-ISAC | High | High | Medium | Low | Low | 18-24 months | 2 |
| Surface freight | ST-ISAC / PT-ISAC | High | High | High (fragmentation) | Low | Low | 24+ months | 2 |
| Vehicle OEM / supplier | Auto-ISAC | Medium | Medium | Low | High | Low | 6-12 months | 4 |
| Retail / hospitality | RH-ISAC | Medium | Medium | Low | Medium | Medium | 6-12 months | 3 |
| Higher education / research | InCommon + REN-ISAC | Low | Low | Low | High | High (within EDU) | 3-6 months | 4 |
| Federal government | FPKI / FedRAMP | Low (exists) | Low | High (ATO process) | High | High (within USG) | 1-3 months | 5 |
| State / local / tribal | MS-ISAC (in transition) | High | High | High (funding) | Medium | Low | 18-24 months | 2 |

---

## 4. Cross-Sector Implications

Three groups fall out of section 3.

**Sectors that can ride existing PKI today.** Federal government (FPKI), defense (DoD PKI cross-certified with FBCA), interbank financial services (SWIFT PKI), healthcare messaging (DirectTrust), higher education (InCommon), and mobile telecommunications (GSMA PKI) all already operate production PKIs whose schemas can absorb a chiodos kernel-key endpoint with modest specification work. These sectors do not need a chiodos consortium; they need a binding profile.

**Sectors with a natural roster issuer but no PKI.** Most ISACs (FS-ISAC for non-bank financial, H-ISAC outside DirectTrust scope, E-ISAC, Auto-ISAC, RH-ISAC, REN-ISAC outside InCommon scope, Aviation-ISAC, MTS-ISAC) have the membership relationships and could plausibly issue or sign a roster, but none currently does. The work is data-type addition and governance: each ISAC has to decide that publishing a signed kernel-key roster is in its members' interest, and its admission and revocation gates have to extend to that data type. This is the modal sector posture.

**Sectors where the trust-anchor problem is genuinely unsolved.** Gas and water utilities, surface freight (ground), the non-mobile slice of telecommunications, and the state / local / tribal slice of government all lack both production PKI and a sectoral roster issuer with the funding and governance to act as one. These sectors can run operator-mediated exchange for early adopters but cannot be sequenced into a federated graph without first standing up the anchor itself.

The cross-sector portability dimension is the harshest. Almost every entry in section 3.10 rates "Low" or "Medium" portability. A bank that joins via SWIFT PKI cannot reuse that bootstrap to handshake with a hospital that joined via DirectTrust; they would need to either issue a second kernel passport bound to a different anchor, or rely on whichever side is willing to operator-mediate the relationship. Section 5 addresses this directly.

---

## 5. Roster Federation: Multi-Sector Participants

A real participant rarely lives inside one sector. A payments processor handles healthcare data on behalf of a clearinghouse; a supply-chain platform spans automotive, aviation, and maritime; a research university hospital is in higher education and healthcare simultaneously. The bootstrap-layer question becomes: can two roster issuers coexist in one kernel passport?

[CHIODOS_CONCEPT.md section 2.5](CHIODOS_CONCEPT.md) anticipates this. The relevant property is that "a chiodos participant declares its accepted bootstrap roots in its passport, and any peer can verify whether the roots match its own expectations before the handshake completes." The passport is set-valued at the trust-root layer, not single-valued.

The recommended posture is:

1. **Multiple bootstrap roots per passport are permitted at the protocol layer.** A passport may declare `accepted_bootstrap_roots = [SWIFT_PKI_root, DirectTrust_root]` and any peer verifying the passport accepts it if at least one root is also accepted by the verifying kernel.

2. **The bootstrap layer remains per-sector.** A bank-to-hospital handshake is governed by the union of the anchor sets, not by a new third anchor. Neither side has to migrate; the chiodos handshake completes if the intersection is non-empty.

3. **Cross-sector handshake intent is declared explicitly in the treaty scope.** A handshake that crosses sector boundaries should declare the action classes valid in both sectors, mirroring the `ladder_intersection` discipline from [CHIODOS_CONCEPT.md section 4.2](CHIODOS_CONCEPT.md). Action classes valid in only one sector fall back to `default_unmapped_mode = receipt_backed`.

4. **Roster-divergence is a renewable contract, not a fork.** If a payments processor's healthcare clearinghouse counterparty later requires DirectTrust onboarding, the processor adds a second bootstrap root to its passport at the next anchor epoch. No replay required.

5. **No federation of roster issuers themselves at the protocol layer.** A chiodos kernel does not have to know that SWIFT PKI and FS-ISAC overlap in members; it just has to accept both as trust sources. Cross-issuer reconciliation (which member is the "same" entity in two rosters) is an out-of-band exercise, the same as today's identity-resolution problem in vendor management.

This works because chiodos handshakes are bilateral. There is no global trust set that has to be reconciled. The federation graph emerges from successful bilateral handshakes, each of which only requires the two participants to share at least one accepted bootstrap root.

The cost is operational duplication: a multi-sector participant pays the onboarding cost in each sector it federates with. That is acceptable. The protocol layer should not subsidise that cost by inventing a meta-roster; doing so would re-centralise the bootstrap that section 2.5 deliberately decentralises.

---

## 6. Recommended Sequencing

A three-tier rollout based on the readiness ratings in section 3.10.

### Tier 1 (6-12 months): existing-infrastructure adopters

These sectors can bootstrap chiodos on infrastructure that already exists in production, requires only a binding profile rather than a new consortium, and has a budget line and governance regime that can absorb a new endpoint type quickly.

- **Banks (interbank), via SWIFT PKI.** The CSP v2026 attestation cycle is already operating; binding a chiodos kernel key to a BIC is schema work, not infrastructure work.
- **Federal government, via FPKI / FedRAMP.** FPKI is in production; the binding profile is small.
- **Defense (bootstrap only), via DoD PKI cross-certified with FBCA.** Bootstrap is short; destination policy is Tier 3.
- **Healthcare messaging, via DirectTrust.** 2.7M endpoints already issued; the 2026 accreditation refresh is a natural integration moment.
- **Higher education, via InCommon + REN-ISAC.** InCommon's signed metadata model is the closest existing analogue to a chiodos roster.
- **Mobile telecommunications, via GSMA PKI.** Roaming PKI is mature.

Hero pitch in this tier is the [CHIODOS_CONCEPT.md section 2](CHIODOS_CONCEPT.md) cross-vendor agent action attestation use case, applied first to financial services agent compositions (vendor risk and AI/ML compliance budget lines) and second to healthcare messaging-flavoured workflows (DirectTrust accreditation surface area).

### Tier 2 (12-24 months): chiodos-specific consortium build-out

These sectors have a credible roster issuer but no published roster. The work is governance, data-type addition to ISAC publication pipelines, and member education. The expected outcome is each named ISAC publishing a signed roster as a first-class data type.

- **Non-bank financial services**, via FS-ISAC.
- **Healthcare clinical / payor / pharma scenarios**, via H-ISAC (DirectTrust covers messaging, not clinical-data scenarios).
- **Electric utilities**, via E-ISAC, with explicit care to avoid coupling to NERC's enforcement function.
- **Vehicle OEMs and suppliers**, via Auto-ISAC (the Alliance for Automotive Innovation governance overlay is already comfortable with this kind of cross-OEM standardisation).
- **Aviation**, via Aviation-ISAC.
- **Retail and hospitality top quartile**, via RH-ISAC.

Pitch in this tier shifts from "ride existing PKI" to "publish a signed roster as part of your existing membership service." The fixed cost per ISAC is moderate (under $500K to stand up the data type, signing infrastructure, and revocation pipeline) and the marginal cost per member is negligible.

### Tier 3 (24+ months): trust-anchor invention required

These sectors lack both production PKI and a sectoral roster issuer with the funding and governance to act as one. Either chiodos waits for the anchor to materialise, or a chiodos-specific consortium has to be stood up alongside.

- **Gas and water utilities**, where DNG-ISAC, ONG-ISAC, and WaterISAC exist but lack the budget and governance maturity of E-ISAC.
- **Surface freight (ground)**, where the ISAC landscape is fragmented and no organisation controls the supply chain end-to-end.
- **Non-mobile telecommunications**, where the COMM-ISAC is a coordination body rather than a roster issuer.
- **Maritime**, where MTS-ISAC's funding and governance maturity is lower than the aviation analogue.
- **State / local / tribal government**, blocked by the MS-ISAC funding transition.
- **Defense destination policy** (the bootstrap is Tier 1; the accreditation surface for chiodos-style cross-org bilateral co-signing under DODI 8520.02 is Tier 3).

In Tier 3, the protocol design should keep operator-mediated exchange explicitly first-class, because it is the only viable bootstrap for the next several years.

---

## 7. Risks

Five concrete failure modes, in rough order of likelihood.

### 7.1 Regulator-published rosters become regulatory-capture vectors

Where a regulator publishes the canonical roster (the likely outcome for finance and healthcare), the roster issuer is a high-value target for both incumbent capture (preferential admission for legacy participants) and adverse policy expansion (admission preconditions creep into substantive policy). FERC's relationship to NERC enforcement, which the [E-ISAC 2025 report flags as a chilling factor on incident sharing](https://ampyxcyber.com/blog/the-e-isacs-2025-report-real-progress-remaining-constraints), is the closest in-production analogue. Mitigation: chiodos kernels should accept multiple bootstrap roots and treat regulator-published rosters as one input among several, not the trust singleton.

### 7.2 Consortium rosters create de facto cartels

ISAC membership today gates access to threat intelligence and peer support. If ISAC membership also gates publication of the canonical roster, then non-members are excluded from the federation graph entirely. This is the [CHIODOS_CONCEPT.md section 1](CHIODOS_CONCEPT.md) "no roster to capture" property failing in operations even though it succeeds at the protocol layer. Mitigation: ISACs that issue rosters should commit to non-discriminatory admission for any participant who meets published criteria, with a published appeals process. The 2026 RH-ISAC / Retail Council of Canada partnership and Auto-ISAC's expansion to commercial vehicles are positive precedents for non-discriminatory admission expansion.

### 7.3 Operator-mediated exchange does not scale past the early adopters

Operator-mediated exchange is the universal default for Tier 3 sectors, but it caps at maybe 50-100 peers per kernel before operations can no longer track key rotations and revocations. Sectors that get stuck on operator-mediated exchange will federate only within small cliques and will not reach the network effects the cross-vendor pitch depends on. Mitigation: explicit Tier 2 budget for ISAC roster publication, on a roadmap with named target dates, so Tier 3 sectors do not become a permanent backwater.

### 7.4 Competing roster issuers in the same sector fragment the federation graph

A sector with two competing ISACs, or an ISAC plus a vendor-issued roster (e.g., a major cloud provider issuing a "trusted automotive supplier" roster competing with Auto-ISAC's), can produce a fragmented federation graph where two participants both think they are in the sector but cannot handshake because their trust sources do not intersect. Section 5 mitigates this by making multiple bootstrap roots per passport a first-class property, but only if the participants actually pin both roots. Mitigation: chiodos governance should publicly recommend that ISACs in adjacent or overlapping scope cross-sign each other's roots, the same way Federal PKI cross-certifies external PKIs at FBCA Medium Hardware.

### 7.5 Sectoral PKI key compromise is high-blast-radius

A SWIFT PKI compromise, a DirectTrust root compromise, or an FPKI cross-certification path compromise affects the entire federation grounded on that root. Chiodos's bilateral revocation gossip does not save the root itself; it only revokes individual kernel passports. Mitigation: roster issuers should adopt key-rotation cadences appropriate to their blast radius (annual at minimum for sectoral roots), and chiodos kernels should accept a moving root set from each issuer rather than pinning a single root. The Federal PKI's 2026-Q1 cross-certification refresh is a healthy precedent.

---

## 8. What This Document Does Not Do

It does not propose a chiodos protocol change. The protocol-layer work to support the postures recommended in section 5 is small (set-valued bootstrap roots in passports, intersection check at handshake) and lives in the existing [chio-credentials](../../crates/chio-credentials/) and [chio-federation::trust_establishment](../../crates/chio-federation/src/trust_establishment.rs) surfaces.

It does not commit to a sequencing decision. Section 6 is a recommendation grounded in current institutional readiness; the actual sequencing is a go-to-market decision that depends on commercial relationships and budget cycles outside the scope of this research.

It does not enumerate every sector. The nine sectors here cover the bulk of the cross-vendor agent attestation budget line as it exists in 2026. Adjacent sectors (legal, accounting, real estate, agriculture, manufacturing-other-than-automotive) follow the same framework but are deferred.

---

## 9. Sources

Institutional and PKI grounding:

- FS-ISAC: [fsisac.com](https://www.fsisac.com/), [Wikipedia](https://en.wikipedia.org/wiki/Financial_Services_Information_Sharing_and_Analysis_Center).
- SWIFT and CSP v2026: [swift.com onboarding](https://www.swift.com/myswift/join-swift), [SWIFT CSP 2026 changes summary](https://worldinformatixcs.com/2025/10/16/swift-csp-2026-changes-you-need-to-know/), [Deloitte 2025 CSP assessment commentary](https://www.deloitte.com/ca/en/Industries/consumer/perspectives/swift-csp-compliance.html).
- Health-ISAC: [health-isac.org](https://health-isac.org/), [membership page](https://health-isac.org/h-isac-membership/).
- DirectTrust: [trust framework](https://directtrust.org/what-we-do/trust-framework), [2026 accreditation criteria announcement](https://www.financialcontent.com/article/accwirecq-2026-1-5-directtrustr-announces-2026-accreditation-criteria-versions-for-all-accreditation-programs).
- E-ISAC and NERC CIP 2026: [E-ISAC at nerc.com](https://www.nerc.com/programs/e-isac), [2026 NERC CIP updates](https://www.certrec.com/blog/most-significant-nerc-cip-updates-for-2026/), [E-ISAC 2025 report commentary](https://ampyxcyber.com/blog/the-e-isacs-2025-report-real-progress-remaining-constraints).
- Auto-ISAC: [automotiveisac.com](https://automotiveisac.com/), [press releases](https://automotiveisac.com/press-news), [Google Cloud partner announcement](https://cloud.google.com/blog/products/identity-security/auto-isac-google-partner-to-boost-automotive-sector-cybersecurity).
- Aviation-ISAC: [a-isac.com](https://www.a-isac.com/).
- COMM-ISAC: [CISA program page](https://www.cisa.gov/resources-tools/programs/communications-information-sharing-and-analysis-center-comm-isac).
- REN-ISAC: [ren-isac.net](https://www.ren-isac.net/index.html).
- RH-ISAC: [rhisac.org](https://rhisac.org/), [Retail Council of Canada partnership](https://www.prnewswire.com/news-releases/retail--hospitality-isac-and-retail-council-of-canada-announce-strategic-partnership-to-strengthen-cybersecurity-across-canadian-retail-sector-302712956.html).
- MS-ISAC funding transition: [NACo announcement](https://www.naco.org/news/multi-state-information-sharing-and-analysis-center-ms-isac-loses-federal-funding), [InsideCyberSecurity coverage](https://insidecybersecurity.com/daily-news/state-and-local-officials-call-reinstating-ms-isac-funding-info-sharing-group-turns), [CISA SLTT support announcement](https://www.cisa.gov/news-events/news/cisa-strengthening-our-nations-security-direct-cyber-support-state-and-local-governments).
- Federal PKI / DoD PKI: [cyber.mil PKI/PKE interoperability](https://www.cyber.mil/pki-pke/interoperability/), [IDManagement FPKI](https://www.idmanagement.gov/fpki/), [FPKI ecosystem changes notifications](https://www.idmanagement.gov/fpki/notifications/).
- National Council of ISACs: [nationalisacs.org](https://www.nationalisacs.org/), [member list](https://www.nationalisacs.org/members).

Internal references:

- [CHIODOS_CONCEPT.md](CHIODOS_CONCEPT.md), section 2.5 "Trust Anchor Honesty" and section 4.2 "Action-Class to Governance-Mode Mapping (with consistency model)."
- [chio-federation::trust_establishment](../../crates/chio-federation/src/trust_establishment.rs).
- [chio-credentials](../../crates/chio-credentials/).
