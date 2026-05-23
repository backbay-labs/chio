# Wave 7B: Threat-Model Completeness Audit

Date: 2026-05-18

## Headline finding

The threat model is DEFENSIBLE for USENIX-tier review, but three gaps require explicit acknowledgement before submission to forestall a "scope-undeclared" writeup. The single most damaging miss is the absent adaptive-adversary treatment of the rejection-code oracle (§3's flat `log_2 5` bound), which Wave 2 (S2) and Wave 4 (m4) both flagged and which remains unchanged. The two next gaps are silence on the malicious-verifier adversary and silence on side-channel resistance. None requires new construction; each is a one-to-three sentence acknowledgement.

## Currently-defended attacks (verification)

The six §7 attack classes are honestly defended. Spot checks:

- **Sibling-treaty cross-receipt substitution (A1)**: claim holds. The subject digest commits to treaty-scope and ladder-intersection hashes; rebinding without re-signing produces a hash miss. Residual risk (trust-store misconfiguration) is correctly named.
- **BBS stub-vs-real (A2)**: defense is correct but the attack motivation remains thin per Wave 2 T1; §3's binding tuple has no BBS slot, so the §7 paragraph is defending a presentation-time concern from the substrate paper.
- **Single-lane witness compromise (A3)**: claim is honest; the residual risk (a single-lane treaty policy collapses to single-lane trust) is acknowledged.
- **Error-message oracles (A4)**: claim **overstates** in the adaptive model. §3's `log_2 5` bound holds against a non-adaptive adversary only; the leak rises in adaptive sequencing. Flagged below.
- **Constitutional ratchet (A5)**: cleanly punted to the companion paper; defensible.
- **Schema-version downgrade (A6)**: strict-match defense holds in the single-version case; multi-version coexistence is explicitly out of scope (correctly).

## Currently-acknowledged gaps

§9 names three limits: no live federation, single-vendor key custody, observability gap. §4 names four Lean gaps: Ed25519 byte soundness, SHA-256 collision resistance / JCS injectivity, Rust-Lean refinement, polity-level admission. The parent paper's §9 ledger covers PQC trajectory, regulator accreditation, key custody / rotation, schema evolution, override authority. The short paper inherits these through the "polity-level questions sit in the companion paper" closing sentence, but the inheritance is implicit, not enumerated.

## Adversary classes the paper does NOT currently address

Ranked by severity for USENIX-tier review:

| Class | Status | Severity |
|---|---|---|
| A1 Adaptive-oracle bound | partial defense, claim overstates | **HIGH** |
| B9 Side-channel (timing / cache) | undefined scope | **HIGH** |
| C12 Malicious verifier | undefined scope | **HIGH** |
| A3 In-window replay (intra-lease) | partial defense, dependence on continuation-hash | MEDIUM |
| B8 Audit-log post-decision tamper | undefined scope | MEDIUM |
| C11 Quantum adversary | inherited from parent, not localised | MEDIUM |
| A4 One-sided cosigner compromise | partial defense, graceful-degradation unspecified | MEDIUM |
| C13 Network adversary on lease oracle | partial defense (verifier-owned epoch) | LOW |
| B6 Confused-deputy at predicate | defended (signer-reuse gate, §3) | LOW |
| C15 Compromised JCS library | inherited from parent ledger | LOW |
| C14 Insider at issuer | defended (trust-store curation, §3) | LOW |
| D16 Prompt-injection at model | out of scope, correctly | NONE |
| D17 Agent confused-deputy cross-org | partially defended (sibling-treaty closure, §7 #1) | LOW |
| D18 Multi-agent collusion | inherited from party-independence | LOW |
| A2 Subject-digest collision | axiomatic primitive (§4) | NONE |
| A5 Both-sided cosigner compromise | acknowledged (§9) | NONE |
| B7 Trust-store poisoning | inherited from parent | LOW |
| B10 Concurrent signing race | undefined scope | LOW |

Top three deserve targeted prose; the rest are inherited or defensibly out of scope.

## Recommended additions (priority order)

**R1. Adaptive-adversary scope sentence in §3 (HIGH; Wave 2 S2, Wave 4 m4).** §3 line 65 currently asserts `log_2 5 ≈ 2.32` bits per attempt without qualifying the adversary model. A reviewer with oracle-attack background will note that left-to-right gate evaluation gives an adaptive adversary structural localization: each rejection code names the first gate that refused, so chaining N probes lets the adversary bisect which conjunct fails on a target. Suggested addition (one sentence) at the end of §3's rejection-code paragraph: "The bound holds against a non-adaptive adversary submitting probes without conditioning on prior rejection codes; an adaptive adversary chaining probes can localize the failing conjunct in $O(5)$ queries, since left-to-right gate ordering reveals which earlier conjuncts passed. Adaptive bounds against the gate-ordering oracle remain open." *Expands §9*, not §7 (it is a residual-risk acknowledgement, not a new defense).

**R2. Side-channel scope sentence in §9 (HIGH; not in parent ledger).** The paper currently makes no claim about constant-time signature verification, cache-resident key material, or timing leaks on the canonicalization path. UncoreBleed, Hertzbleed, and prior EdDSA-timing literature give a PC reviewer a stock objection. The verifier is a wire-format primitive, not a hardware-isolated module, so side-channel defense is correctly out of scope but the silence reads as oversight rather than scope. Suggested addition (one paragraph) in §9 after "Observability gap": "**Side-channel resistance.** The verifier is specified at the wire layer; timing, cache, and microarchitectural side channels on the Ed25519 verification path or the canonicalization implementation are outside the construction. A constant-time Ed25519 implementation and a side-channel-hardened JCS canonicalizer are deployment concerns. The receipt-graph evidence captures the verifier's accept-reject verdict, not the byte-level execution trace the adversary observes." *Expands §9*.

**R3. Malicious-verifier scope sentence in §9 (HIGH).** The paper assumes an honest verifier throughout. A malicious receiving kernel can deny valid envelopes (DoS) or admit envelopes outside its declared policy by mutating its own trust store. The defense (the parent paper's "verifier-owned stores are actually verifier-owned" operational discipline) is inherited but not localised. Suggested addition (one paragraph) in §9: "**Verifier honesty.** The construction assumes the receiving kernel evaluates the six gates as specified and reports its rejection code honestly. A malicious verifier with control of its own trust store can deny valid envelopes (denial-of-service against the issuer) or admit envelopes outside its declared policy (by injecting attacker-controlled keys). External assurance that a verifier evaluates the predicate it claims to evaluate is a kernel-attestation problem, addressed in the companion paper as future work." *Expands §9*.

**R4. Intra-lease replay clarification (MEDIUM).** §3 gate G5 catches stale-lease (post-revocation replay). Within the lease window, replay protection depends on the continuation hash that the receiving kernel enforces during graph append, but Wave 2 N1 noted continuation-hash points backward. One sentence in §3 near the lease paragraph clarifying that envelope-level replay protection against same-lease re-submission is a graph-state property rather than a verifier-local one. Marginal; deferrable if R1-R3 land.

**R5. PQC trajectory cross-reference in §9 (MEDIUM).** The parent paper's §9 names Ed25519/BBS/SHA-256 PQC migration; the short paper is silent. One inheritance sentence in §9 closes the gap. "The construction commits to Ed25519 and SHA-256; the PQC migration path inherited from the parent paper's assumption ledger applies here unchanged."

Total recommended additions: **5** (three high-priority, two medium).

## Defensible scope decisions

The following adversary classes are correctly out of scope and need no acknowledgement:

- **Prompt-injection at the model layer (D16)**: the paper's wedge is admission at the kernel boundary, not model-layer defense. The kernel admits or denies; what the model emits upstream is governance, not envelope verification.
- **Subject-digest collision (A2)**: SHA-256 collision resistance is a foundational axiom across the entire DSSE / in-toto / SLSA ecosystem; §4 names it explicitly.
- **Compromised JCS library (C15)**: the parent paper's assumption ledger covers this; the short paper inherits it.
- **Concurrent signing race (B10)**: the signing protocol is the issuer's concern, not the verifier's; two cosigners producing two different valid envelopes is a polity-layer divergence problem.
- **Insider at issuer (C14)**: defended by the §3 trust-store gate when curated; the curation policy is operational.

## Paper-killer risk assessment

The single highest-severity gap is **R1 (adaptive-adversary oracle bound)**. It is the only finding that points to an existing claim in §3 being technically wrong rather than scope-deferred. A USENIX PC reviewer working in side-channel / oracle-attack theory will flag the `log_2 5` bound on first read, because flat per-attempt bounds against multi-gate predicates are a well-known mismodelling pattern. Both Wave 2 (S2) and Wave 4 (m4) flagged this; neither landed in the paper. R1 is the single most likely cause of a "technical-precision" reviewer writeup at submission. R2 (side-channel) and R3 (malicious verifier) are scope-disclosure issues rather than technical errors; their absence is defensible but their disclosure costs three sentences.

## Report-back summary

1. **Most damaging miss**: the adaptive-adversary oracle bound on the rejection-code taxonomy (§3 `log_2 5` claim). Flagged twice in prior waves; still in the paper unchanged.
2. **Total recommended additions**: 5 (three high-priority, two medium-priority).
3. **Verdict**: The threat model is defensible for USENIX Sec 2027 Cycle 2 review provided R1-R3 land as one paragraph each in §9 (or, for R1, as a one-sentence qualification in §3); the paper does not need new defenses, only honest scope acknowledgement on three adversary classes it currently leaves silent.
