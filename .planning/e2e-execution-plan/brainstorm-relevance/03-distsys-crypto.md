# Brainstorm B3: Distributed Systems + Cryptography

Date: 2026-05-19
Scope: BFT consensus, formal protocol verification, signed-receipt cryptography, threshold/aggregate signatures

## Threads found

### Thread 1: Sigstore CCS 2022 paper (Newman, Meyers, Torres-Arias)
- **Primary references**:
  - Newman, Meyers, Torres-Arias. "Sigstore: Software Signing for Everybody." ACM CCS 2022. doi:10.1145/3548606.3560596.
- **What the thread is about**: A peer-reviewed paper describing Sigstore's keyless-signing security model, a formal attacker model for the ecosystem, and the OIDC-plus-Fulcio-plus-Rekor architecture that the parent paper currently leans on only via the project documentation reference `sigstoreSecurity`. The paper articulates the trust assumptions on Fulcio (root CA), Rekor (transparency log), and the witness model.
- **Bears on which Chio paper or which engineering milestone**: Parent paper, §8 (Related Work), the "Transparency and supply-chain systems" paragraph. The current cite stack uses `dsse`, `torres2019intoto`, `rekorGithub`, `sigstoreSecurity`; the Newman-Meyers-Torres-Arias CCS paper is the canonical peer-reviewed Sigstore citation and should sit next to `torres2019intoto`.
- **Leverage**: cite-in-§8. The §8 paragraph names Sigstore and Rekor but cites only the project docs; a peer-reviewed reference materially strengthens the supply-chain comparison without changing the paper's claims. Torres-Arias is also a plausible adversarial-reader candidate.
- **One-line action**: Add the CCS 2022 Sigstore paper to `bib.bib` and cite it in the §8 paragraph immediately after `sigstoreSecurity`.

### Thread 2: Sigsum and the witness-cosigning tlog ecosystem
- **Primary references**:
  - C2SP `tlog-witness` specification (active 2024-2025).
  - Sigsum log specification and witness protocol (sigsum.org).
  - "Can I Get A Witness (Network)?" transparency.dev blog (2024) covering ArmoredWitness deployment.
  - Syta et al. "Keeping Authorities Honest or Bust with Decentralized Witness Cosigning." IEEE S&P 2016, arXiv:1503.08768.
- **What the thread is about**: A working transparency-log ecosystem in which a checkpoint is only valid once a quorum of independently-operated witnesses has cosigned it, after each witness verifies the append-only consistency proof. Witness quorum policies are expressed client-side as "k of n from this witness set." ArmoredWitness ships purpose-built hardware witness nodes. The Sigsum design explicitly factors the trust root into log + witness quorum, separating "logged" from "globally consistent."
- **Bears on which Chio paper or which engineering milestone**: Parent paper §5 multi-lane anchor quorum and §8 supply-chain paragraph. The anchor-quorum design described in the paper is structurally the same idea as Sigsum's witness-quorum policy: a verifier-owned predicate over independent attestations of inclusion. Sensor-grounded paper §3 also benefits if the substrate attestation appeals to a witness-quorum trust root.
- **Leverage**: cite-in-§8. This is the closest production analog of the parent paper's multi-lane anchor design and is currently uncited. Filippo Valsorda (litetlog) and the C2SP authors are plausible adversarial-reader candidates if anyone in the witness-cosigning community reviews. Possibly sleeper-tier if a future follow-up wants to claim Chio's anchor quorum is a Sigsum-policy specialization.
- **One-line action**: Add the Syta et al. CoSi reference and the C2SP tlog-witness spec to `bib.bib`; cite both in the multi-lane-anchor paragraph of §8.

### Thread 3: Threshold Schnorr (FROST, ROAST, dynamic FROST)
- **Primary references**:
  - Komlo, Goldberg. "FROST: Flexible Round-Optimized Schnorr Threshold Signatures." SAC 2020, eprint 2020/852.
  - RFC 9591. "Flexible Round-Optimized Schnorr Threshold (FROST) Protocol for Two-Round Schnorr Signatures." 2024.
  - Ruffing, Ronge, Jin, Schneider-Bensch, Schroeder. "ROAST: Robust Asynchronous Schnorr Threshold Signatures." ACM CCS 2022.
  - "Dynamic-FROST: Schnorr Threshold Signatures with a Flexible Committee." 2024, eprint 2024/896.
- **What the thread is about**: FROST is the now-standardized two-round threshold Schnorr signature scheme. ROAST wraps FROST with a robustness layer that tolerates malicious signers under asynchronous network assumptions. Dynamic-FROST handles committee rotation. RFC 9591 is the IETF standardization. Together they are the natural path for replacing bilateral DSSE cosigning with threshold cosigning.
- **Bears on which Chio paper or which engineering milestone**: V7 deferred-future-work threshold cosigning (named in the parent paper as a deferred item; not currently cited). Also bears on V8 issuer rotation (Dynamic-FROST's committee rotation primitives map almost directly).
- **Leverage**: cite-in-§8 and co-author-candidate. The §8 limitations / future-work paragraph should name FROST + ROAST as the V7 path. Komlo or Ruffing are plausible adversarial-reader candidates for any future V7-bearing paper. Sleeper-tier value: when Paper 5 (V2 / threshold-cosigning) needs a wire-protocol citation chain, this is the chain.
- **One-line action**: Add Komlo-Goldberg FROST (SAC 2020), RFC 9591, and Ruffing et al. ROAST to `bib.bib`; cite in the §8 deferred-work or §10 limitations passage if V7 is named.

### Thread 4: Polygraph and accountable Byzantine agreement
- **Primary references**:
  - Civit, Gilbert, Gramoli. "Polygraph: Accountable Byzantine Agreement." IEEE ICDCS 2021 (extended from DISC 2020 brief), eprint 2019/587.
  - Civit, Gilbert, Gramoli, Komatovic, Monti, Vukolic. "All Byzantine Agreement Problems Are Expensive." PODC 2024.
- **What the thread is about**: An accountable BFT protocol that, when more than n/3 nodes equivocate, produces a cryptographic proof identifying at least n/3 of them. This is the formal correspondence to Chio's "denial is auditable in the same canonical format as an allow" property: denials carry forensic evidence, not just an opaque reject.
- **Bears on which Chio paper or which engineering milestone**: V2 tier-1 federation. The two-kernel scenarios (especially "adversarial peer" and "divergent admit/deny") are exactly the Polygraph fault-detection setting. The paper's signed-negative-package construction in §6 (buyer-closure denial fixtures) is a single-actor, predicate-level analog of Polygraph's collective-evidence story.
- **Leverage**: sleeper-tier for the parent paper; cite-in-§8 candidate for V2 / Paper 5. The parent paper's correctness contract does not require consensus, so this is not a load-bearing §8 cite for the current submission. But the V2 work that hardens the federation tier should engage Polygraph explicitly, because Polygraph names the property the Chio negative-package design quietly inherits.
- **One-line action**: Note this as a Paper-5 follow-up cite; do not add to the current parent-paper submission. Add Civit-Gilbert to the V2 tier-1 design memo's related-work section.

### Thread 5: Ivy decidable-fragment verification (Padon, McMillan, Sagiv)
- **Primary references**:
  - Padon, McMillan, Panda, Sagiv, Shoham. "Ivy: Safety Verification by Interactive Generalization." PLDI 2016.
  - Padon, Losa, Sagiv, Shoham. "Paxos Made EPR: Decidable Reasoning about Distributed Protocols." OOPSLA 2017.
  - Padon thesis. "Verification of Distributed Protocols: Decidable Modeling and Inductive Invariants." TU Wien 2022.
- **What the thread is about**: Ivy frames distributed-protocol verification as inductive-invariant inference inside a decidable first-order fragment (EPR). Once a protocol fits the fragment, Z3 discharges the verification conditions automatically. It has been used to verify Paxos, Multi-Paxos, and primary-backup.
- **Bears on which Chio paper or which engineering milestone**: V2 tier-1 verification ambition. The V2 design memo names a Lean theorem `admission_idempotent_under_replay` as the operational dimension to add; Ivy is the better-fit tool if the obligation is "gossip-event-list-permutation invariance." Lean is the right tool for the constitutional refinement obligations; Ivy or an EPR-friendly TLA+ encoding is the better tool for the network-level scenarios. This is a structural tooling note, not a paper-edit note.
- **Leverage**: not-cite-worthy for the parent paper (the parent paper's claims are about admission predicates, not consensus). Sleeper-tier for V2 / Paper 5 where the network-level operational invariants live.
- **One-line action**: Append a brief tooling-options note to the V2 tier-1 design memo (under "Lean formalization") naming Ivy and Apalache as alternatives for the gossip-permutation invariants.

### Thread 6: Verdi and IronFleet (verified distributed implementations)
- **Primary references**:
  - Wilcox, Woos, Panchekha, Tatlock, Wang, Ernst, Anderson. "Verdi: A Framework for Implementing and Formally Verifying Distributed Systems." PLDI 2015.
  - Hawblitzel, Howell, Kapritsos, Lorch, Parno, Roberts, Setty, Zill. "IronFleet: Proving Practical Distributed Systems Correct." SOSP 2015. (Already cited as `hawblitzel2015ironfleet`.)
  - Sergey, Wilcox, Tatlock. "Programming and Proving with Distributed Protocols." POPL 2018 (Disel).
- **What the thread is about**: Verdi proves Raft linearizable in Coq, extracts a running OCaml implementation, and supports fault-model refinement (idealized -> realistic). IronFleet pairs TLA-style refinement with implementation-level Dafny proofs. Disel adds a separation-logic dialect for compositional protocol verification.
- **Bears on which Chio paper or which engineering milestone**: Parent paper §8 already cites IronFleet; Verdi and Disel are the two natural neighbors. The §8 verified-systems paragraph lists CompCert, VST, IronFleet, Everest, Lean 4, Cedar, SampCert; Verdi (Raft + extraction) and Disel (compositional distributed) belong in the same enumeration because the V2 tier-1 work will produce a verified-implementation analog that this lineage describes.
- **Leverage**: cite-in-§8. James Wilcox / Zachary Tatlock are co-author candidates for a future V2-companion paper; Tatlock has been a referee for the verified-systems neighborhood and would be a knowledgeable adversarial reader for the V2 / Paper 5 submission.
- **One-line action**: Add Verdi (PLDI 2015) and Disel (POPL 2018) to `bib.bib`; cite both in the §8 verified-systems sentence, next to `hawblitzel2015ironfleet`.

### Thread 7: TLA+ specifications of HotStuff and Tendermint
- **Primary references**:
  - Buchman, Kwon, Milosevic. "Correctness and Fairness of Tendermint-core Blockchains." 2018, arXiv:1805.08429.
  - Berenwinkel et al. "Verification of HotStuff BFT Consensus Protocol with TLA+/TLC in an Industrial Setting." (Industry track 2020-2021.)
  - Konnov, Kukovec, Tran. Apalache symbolic model checker for TLA+. Multiple papers 2019-2023.
- **What the thread is about**: TLA+ specifications and model-checked safety / accountable-safety properties for the two production BFT engines (Tendermint and HotStuff). Apalache extends TLA+ from finite-state model checking to bounded symbolic checking.
- **Bears on which Chio paper or which engineering milestone**: V2 tier-1 federation. The two-kernel gossip protocol is a candidate target for a TLA+ + Apalache encoding once the wire protocol stabilizes. The parent paper does not claim consensus, so this is V2-only.
- **Leverage**: sleeper-tier for V2 / Paper 5. Not a parent-paper cite.
- **One-line action**: Note in V2 tier-1 design memo that Apalache + TLA+ is the recommended model-checking path before any Lean operational theorems are attempted.

### Thread 8: BLS aggregate signatures (Boneh-Drijvers-Neven, subset-optimized BLS)
- **Primary references**:
  - Boneh, Drijvers, Neven. "Compact Multi-Signatures for Smaller Blockchains." ASIACRYPT 2018.
  - Boneh, Gorbunov, Wahby, Wee, Zhang. "BLS Signatures (CFRG draft)." IETF.
  - "Subset-Optimized BLS Multi-signature with Key Aggregation." Mysten Labs / SAC 2024, eprint 2023/498.
- **What the thread is about**: BLS aggregate signatures compress n signatures over a single message into one constant-size signature, with rogue-key resistance via proof-of-possession or hash-based domain separation. Subset-optimized BLS adds key-aggregation efficiency for the "k of n" case. This is the alternative path to FROST for V7 cosigning, with different round-complexity and post-quantum migration shape.
- **Bears on which Chio paper or which engineering milestone**: V7 alternative path. Less interesting for §6 selective disclosure (BBS already cited) but very relevant if V7 chooses BLS over Schnorr.
- **Leverage**: cite-when-V7-design-lands. Not currently load-bearing.
- **One-line action**: Note in V7 design memo (when written) that BLS-aggregate vs FROST is a real design choice; bibliography preparation is premature.

### Thread 9: in-toto and supply-chain attestation formal semantics
- **Primary references**:
  - Torres-Arias, Afzali, Kuppusamy, Curtmola, Cappos. "in-toto: Providing Farm-to-Table Guarantees for Bits and Bytes." USENIX Security 2019. (Already cited.)
  - SLSA Framework v1.0. (Already cited.)
  - "Supply Chain Levels for Software Artifacts" SLSA v1.0 spec + recent (2024-2025) blog posts on in-toto-SLSA composition.
- **What the thread is about**: in-toto models the supply chain as a DAG of cryptographically signed "steps," each governed by a layout that names authorized actors and rules. Chio's bilateral DSSE statement is structurally a two-actor in-toto step whose "rules" are the constitutional predicates of two polities; this is exactly the comparison the parent paper §8 already draws.
- **Bears on which Chio paper or which engineering milestone**: Parent paper §8. Already cited. The thread is mentioned for completeness, not for a new cite.
- **Leverage**: not-cite-worthy as a new cite (already present); Justin Cappos is a plausible adversarial-reader candidate for the parent paper because in-toto is the closest production analog of the receipt-graph idea.
- **One-line action**: Add Cappos to the "potential reviewers" pool for the USENIX submission cover note if one is solicited.

### Thread 10: Raft and the "in-practice baseline" line
- **Primary references**:
  - Ongaro, Ousterhout. "In Search of an Understandable Consensus Algorithm." USENIX ATC 2014.
  - Ongaro PhD thesis. "Consensus: Bridging Theory and Practice." Stanford 2014.
- **What the thread is about**: The pedagogical and most-deployed crash-fault-tolerant consensus algorithm. Cited mainly for the V2 tier-1 transport / leader-election design when (if) the federation crosses into multi-node-per-polity territory.
- **Bears on which Chio paper or which engineering milestone**: V2 tier-2 or V2 tier-3 only (multi-host per polity). Not the parent paper.
- **Leverage**: not-cite-worthy for current papers. Mentioned only to document a decision: Chio's federation is not a Raft cluster; it is a two-actor coordination problem, and Raft is the wrong baseline.
- **One-line action**: Drop. Documented as rejected.

## What's NOT relevant

- **zkSNARKs and Groth16 / PLONK / Halo / STARK construction details.** ETSI TR 119 476-1 already cites them as a candidate selective-disclosure overlay, and the parent paper correctly notes this without endorsing a SNARK substitution. A deeper SNARK literature dive does not bear on either current paper; the SNARK case for selective disclosure is a future-paper question, not a §8 cite.
- **Asynchronous BFT (HoneyBadgerBFT, DAG-BFT line: Narwhal, Bullshark, Mysticeti).** These solve the consensus throughput problem under asynchronous adversaries and are tangential to Chio's bilateral two-party admission. The DAG-BFT family is the wrong fit for a two-actor treaty primitive; cite-worthy only when V2 grows to a "polity = quorum of kernels" model (deferred to Paper 5 or later).
- **Blockchain interoperability beyond IBC.** Chio §8 cites IBC for the policy-layer-vs-chain-layer comparison; the broader bridge / rollup / wormhole / LayerZero literature is downstream protocol engineering, not foundational research. No additional cite warranted.
- **Hash-based signatures and post-quantum migration (XMSS, LMS, Dilithium, Falcon).** The parent paper correctly defers PQC migration to a future revision and aligns with ETSI's salted-hash-under-PQC recommendation. The PQC literature is real and large but does not change the current submission's claims; revisit when ETSI's PQC profile lands.
- **Smart contract verification beyond the Move / Solidity comparative analysis already cited.** `schneiderFMBC2025` covers the Move Prover / Solidity verifier comparison; deeper Move Prover papers or Certora-internal verification work do not strengthen the parent paper's argument that "proof-carrying constitutional change is a distinct obligation from chain-settled governance."
