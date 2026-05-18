# Iteration 5

Focus: execute the iter-4 synthesizer's directive to act on the MISSED category (C). Three of the eight (C) items already crossed off mid-iteration-4 (the code archaeologist hit C2 partially and C7 fully; Compound 289 case study cross-fertilized iter-1's regulator-example ask). Five (C) items remain. Iteration 5 picks three orthogonal ones:

- C3: BBS deployment-story examiner (cryptographic-protocol reviewer) -- the ETSI TR 119 476-1 citation is in but EUDI Wallet deployment realism is untested
- C4: Multi-lane anchor adversarial reviewer (chain-reorg / witness-bribery / cross-lane-independence) -- iter-2 adversarial enumerated 15 attacks but did not touch cross-lane witness independence specifically
- C8: §1 contribution bullets vs TOC flow argument-coherence auditor -- has the rewrite of §1 bullet 2 ("two load-bearing + two definitional bridges") landed cleanly against the actual flow of §4 through §10?

Agent sections appended below.

## Persona: Multi-lane anchor adversary (C4 cross-lane independence)

The single most damaging cross-lane attack is **n-of-m policy silence**: §3's anchor paragraph normalizes "multi-lane evidence" across Rekor / OTS / Solana / EVM without ever specifying whether the verifier admits a receipt on 1-of-4, k-of-4, or 4-of-4 lane attestations, so an attacker who compromises any single lane carries the receipt under the most permissive reading every existing implementation will default to. The Lean model does not encode the lane-quorum predicate; the Rust anchor crate's prose says "normalizes" without exposing per-lane weights to the verifier-owned store; §9's "anchor lane unevenness" bullet treats this as a maturity gap, not as a missing policy field.

Five cross-lane attacks the iter-2 single-lane enumeration did not cover:

1. **Lane-substitution / weakest-link admission.** Attacker presents only the Solana memo lane (millisecond finality, lowest unilateral compromise cost) when the verifier's pinned-lane policy admits "any of Rekor, OTS, Solana, EVM." Existing predicates: **no** -- §3 calls anchoring a "witness service" but exposes no per-lane policy granularity. Fix: a `lane_quorum_predicate(receipt_class, required_lanes_set, k)` bound into the treaty scope plus `\thm{anchor_admission_iff_lane_quorum_satisfied}` so admission falls open the moment k lanes converge, never on one.

2. **Inter-lane bribery (Rekor witness + OTS calendar operator collude).** Attacker pays one Rekor witness and one OTS calendar to attest contradictory roots for the same checkpoint epoch, producing two internally-valid 2-of-4 bundles. Table 4 assumes "public witness clients verify the statement they claim to verify" but **assumes cross-witness independence implicitly**; existing predicates: **no**. Fix: a `witness_independence_attestation` per lane (operator identity, jurisdiction, key-rotation epoch) bound into the anchor proof bundle, plus a theorem `lane_witnesses_distinct_operators_required_for_quorum`.

3. **Confirmation-latency-mismatch race (slow-lane TOCTOU).** Solana finalizes in ~400 ms, EVM in ~13 s, Rekor instantly, Bitcoin-via-OTS in ~1-6 h. Attacker anchors a fraudulent receipt to the three fast lanes, opens admission under k=3-of-4, then double-spends or revokes before the OTS calendar commits the contradicting Bitcoin block. Existing predicates: **partial** -- the SET binds Rekor entry time but no predicate enforces a *cross-lane settlement floor* before receipt-backed-class admission. Fix: an `anchor_settlement_floor_unix_ms` per receipt class (e.g., destructive actions require OTS Bitcoin confirmation lag) bound into the subject digest, with `\thm{receipt_backed_admission_requires_slowest_pinned_lane_settled}`.

4. **Tile-log boundary inclusion-proof manipulation (trillianTessera surface inherited).** The added \cite{trillianTessera} citation imports the tile-log architecture; tile boundaries are a new equivocation surface because a witness can sign tile-N consistent with two distinct tile-(N+1) extensions that share the same boundary leaf set. The paper inherits this attack without acknowledgement. Existing predicates: **no** -- §3 says inclusion-proof verification is "follow-up". Fix: a `tile_boundary_consistency_proof` per anchor epoch plus `\thm{tile_log_inclusion_admits_only_unique_extension`, with explicit citation of the Tessera witness-cosigning protocol the paper currently treats as a black box.

5. **ZK-lane sequencer-compromise substitution.** If the round-3 ZK-comparison agent's recommendation lands and the EVM lane migrates to a ZK rollup validity proof, the new attack surface is sequencer-induced equivocation: a compromised sequencer produces validity proofs over an attacker-chosen state diff that no base-layer reorg can dispute. Existing predicates: **no** -- the anchor crate has no ZK-lane proof obligation today. Fix (pre-emptive): a `zk_lane_sequencer_independence_attestation` plus a theorem requiring sequencer-set diversity matching the lane-quorum predicate.

Cross-cutting: §9's "anchor lane unevenness" bullet flattens these into "maturity variance" rather than naming any one of the five as a missing predicate. The verifier-owned store is described as pinning *which lanes* the verifier trusts (\S3 paragraph 5) but not *how many of them must converge*, nor with what *witness-set diversity*, nor with what *settlement-floor delay*.

**Highest-priority follow-up:** introduce a single `lane_quorum_policy` field in the treaty-scope schema carrying `(required_lanes, k_of_n, witness_independence_required, settlement_floor_unix_ms)` and prove `\thm{anchor_admission_iff_lane_quorum_satisfied}` -- this closes attacks 1, 2, and 3 in one structural move and gives the tile-log (4) and ZK-lane (5) attacks a syntactic slot to land in when their respective proof obligations are added, converting "multi-lane anchoring" from a normalization aspiration into a policy-checkable predicate.

## Persona: BBS deployment-story reviewer (C3)

The single most damaging discrepancy is that \S8 cites ETSI TR 119 476-1 v1.3.1 (Aug 2025) as if it endorsed BBS for EUDI deployment, when that document is a *comparative analysis* of SD-JWT, mdoc salted hashes, BBS+, BBS\#, and zk-SNARK overlays, and the ARF mandates SD-JWT VC plus ISO mdoc, not BBS; BBS+ is an optional Data-Integrity overlay most ARF-compliant wallets have not implemented.

Five protocol-reviewer findings:

1. **The deployment claim is inverted.** The dominant 2025 EUDI pilot schemes (APTITUDE, EWC, POTENTIAL, DC4EU) are SD-JWT VC for remote flows and ISO mdoc for proximity flows. BBS+ lives in W3C VC Data Integrity 1.0 (Candidate Rec) and MATTR's stack, not the EUDI baseline. \S8's "deployable selective-disclosure building block at the policy level" overreads what ETSI actually recommends (multi-format pluralism).

2. **Issuer-holder-verifier triangle conflict.** \S3 makes Ed25519 over canonical receipt bytes authoritative and BBS a secondary commitment. EUDI inverts this: the issuer signs the credential (BBS-, SD-JWT-, or mdoc-formatted) and the holder derives the disclosure -- no separate authoritative record. The paper does not acknowledge it uses BBS unlike the credential ecosystem.

3. **The iter-2 issuer-rotation race is a real gap in `draft-irtf-cfrg-bbs-signatures-10`.** Draft-10 standardizes message-vector signing, generator derivation, and proof verification; it has no binding of derivation-epoch to verifier-replay-epoch. Nothing tells a verifier which key-epoch to bind to a derived proof. The attack iter-2 flagged is a standards gap, not Chio-specific.

4. **Threshold BBS literature exists but is uncited.** Doerner-Kondi-Lee-shelat (IEEE S\&P 2023) and Nof-Goyal (CT-RSA 2025 non-interactive threshold BBS+) supply t-of-n issuer-key constructions that map onto iter-3's FROST/ROAST replacement for the two-key DSSE binding. No production EUDI wallet deploys them; the paper could cite either as the canonical "key custody at scale" answer (\S9) but does not.

5. **The \S6 latency is off by an order of magnitude.** Production BBS verification (mattrglobal/bbs-signatures, zkcrypto BLS12-381) is 6-7 ms; the paper's 161,824 us (162 ms) p50 is a debug-profile harness, ~25x slower. \S6 labels it "measured" without noting release-profile lands in single-digit-ms. A pairing-crypto reviewer reads 162 ms and concludes Chio uses a uniquely slow library.

Cross-cutting: the \S9 PQC bullet asserts BBS "will require a transparent-SNARK or equivalent replacement." ETSI TR 119 476-1 v1.3.1's actual PQC framing is that BBS+ and SD-JWT-on-P256 are both quantum-vulnerable; the recommended migration is salted-hash formats (mdoc, SD-JWT) signed under PQC algorithms -- a path that obviates BBS rather than upgrading it. The paper names one option without flagging it as ETSI's non-preferred path.

**Highest-priority follow-up:** rewrite the \S8 BBS paragraph and \S9 PQC bullet to (a) acknowledge BBS is one of several ETSI-analyzed schemes, not the EUDI-mandated one, (b) cite Doerner-Kondi-Lee-shelat threshold BBS+ as the construction that closes iter-3's FROST/ROAST gap for the BBS issuer key, and (c) name salted-hash-plus-PQC alongside transparent-SNARK as the real 2026-2030 BBS migration question -- otherwise a reviewer writes "the authors cite ETSI TR 119 476-1 to support a BBS deployment story it does not endorse."

## Persona: §1-vs-flow coherence auditor (C8 post-pass-5)

The worst slip: \S1 bullet 2's "two load-bearing + two definitional refinement bridges" framing is only half-honored in \S4 -- line 71 labels the two amendment theorems "definitional refinement bridges rather than load-bearing proofs," but the intersection and ladder-stability theorems are never reciprocally labeled "load-bearing" in their paragraphs, and line 62 reuses "load-bearing" in a third sense (federated-deployment composition obligations). A reader following \S1's pointer finds only the definitional half plus a conflicting usage.

1. **Bullet 2 vs. \S4.** \S1 promises "two load-bearing + two definitional bridges"; \S4 line 71 delivers the bridges cleanly, but the load-bearing side is asserted only in \S1, and line 62's federated-deployment usage muddies the term. **Wobble.**

2. **Bullet 3 vs. \S5 five components.** \S1 promises treaty scope and ladder intersection, pre-dispatch admission, strict bilateral DSSE, and a multi-lane anchor with lane-varying maturity; \S5 has paragraphs for Treaty primitive, Admission hook, Strict DSSE verifier, but **no dedicated paragraph for the multi-lane anchor** -- it survives only in \S5 line 4's enumeration and Table 1's `AnchorWitnessPolicy` row ("Rekor SET stronger than OTS advisory; lane-specific limitations remain"). "Maturity varies by lane" appears in \S1 with no \S5 prose honoring it. **Wobble.**

3. **Bullet 4 vs. \S5 + \S6 generator framing.** \S1 says "demonstration built on a fixture-backed generator, exercising every load-bearing predicate"; \S5 line 44 says "generator... emits buyer-auditor proof packages... and runtime-spine fixtures" and \S6 line 48 says "buyer-closure generator [that] emits signed positive and negative packages." Iter-4 code archaeologist found `chio-chiodos-loopback` also runs the strict verifier in-process (simulator); neither \S5 nor \S6 say "simulation." **Aligns -- bullet phrasing matches body prose; the undersold simulator dimension isn't promised.**

4. **Bullet 5 vs. \S6 naming.** \S1 promises naming; \S6 line 38 names "Receipt signing, receipt verification, and anchor inclusion require dedicated measurement harnesses" in prose, plus three table rows marked `[unreported]`. **Aligns.**

5. **\S10 vs. \S1 bullets.** \S1 distinguishes load-bearing from definitional theorems; \S10 collapses to "Lean theorems anchor the treaty-intersection and amendment-refinement obligations" without the distinction, and the pass-5 Hart-nod restored symmetric framing that elides the \S1 honesty move. **Wobble -- asymmetric framing via the Hart nod.**

6. **Cross-paper "definitional refinement bridges".** \S1 bullet 2 and \S4 line 71 use the identical phrase; \S4's positive description (\emph{rfl}, type-level invariant, proof-inventory entries) matches "anchoring the type-level enactment invariant." **Aligns -- the half \S4 owns is owned cleanly.**

Cross-cutting: "load-bearing" carries three referents (\S1 bullet 2's two theorems; \S4 line 62 composition obligations; \S5 line 4 six components). A hostile reviewer will flag the shifting referent.

**Highest-priority follow-up:** add one sentence each to \S4's treaty-intersection paragraph (after line 45) and ladder-stability paragraph (after line 57) positively labeling each "load-bearing for cross-kernel admission" -- this mirrors line 71's negative labeling of the amendment theorems, gives \S1 bullet 2 a destination in \S4 prose, and lets \S10 be tightened to "two load-bearing theorems plus the type-level amendment invariant" without breaking the abstract's count-free framing.

## Iteration summary

Convergent meta-finding across all three agents: **pass 5 introduced three independent regressions** on three different surfaces. (1) Anchor: the pass-5 `trillianTessera` citation imports the tile-log architecture and a new tile-boundary inclusion-proof attack surface the paper does not acknowledge. (2) BBS: the pass-5 `etsiSelectiveDisclosure2025` citation misrepresents ETSI TR 119 476-1 -- the document is a comparative analysis, not an endorsement, and the EU ARF actually mandates SD-JWT + mdoc, not BBS. (3) \S1 coherence: the pass-5 \S10 Hart-nod and \S4 re-anchor introduced "load-bearing" with three different referents, and \S1 bullet 2's "two load-bearing theorems" claim has no destination in \S4 prose. Divergent / orthogonal: each finding maps to a distinct surgical fix -- introduce a `lane_quorum_policy` treaty-scope field (anchor); rewrite \S8 BBS paragraph and \S9 PQC bullet to acknowledge ETSI's comparative framing and the SD-JWT+mdoc EUDI mandate, plus add threshold-BBS citations (BBS); add positive "load-bearing for cross-kernel admission" labels to \S4's intersection and ladder-stability paragraphs (coherence). The three stack rather than conflict and collectively unwind the pass-5 regressions without touching the substantive pass-5 wins (Hart paragraph, AI safety paragraph, Omega citation, Lean enactAmendment fix).
