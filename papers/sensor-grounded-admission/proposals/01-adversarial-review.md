# Adversarial Review of v0 Draft

## Single most damaging finding

**The sensor about which the kernel attests does not exist in production.** The headline claim is that every receipt embeds a signed attestation of which sensors were installed, active, healthy, and degraded at decision time. The substrate that backs the §6 empirical claim is `Monitor.swift`, a 339-line state-accounting file with zero `es_new_client`, zero `es_subscribe`, and zero `ES_EVENT_*` calls (verified via grep over `clawdstrike/apps/agent/src-tauri/macos/system-extension/endpoint-security/`). The `kernelCallout` provider kind enumerated in §5 has no kernel callout. The `behavioralTelemetry` provider has no telemetry source. The attestation thus signs flags about an entity that does not observe the host: it is a signed claim about a fictional provider's health. A USENIX Security reviewer who reads §6's deployed-kernel framing and then runs `grep es_new_client` finds the substrate's most distinguishing claim is an attestation over a stub. The paper inherits this gap from the prior integration adversarial pass and does not name it.

## Critical findings (formal-methods / Lean reviewer)

**1. The supporting theorem `partition_contingency_mode_iff_degraded_subset` collapses to one rewrite step.** `partitionContingencyMode decl a` (line 190) is defined as `decide ((attestedHealthy decl a).length < decl.required.length)`. The theorem (line 253) states `partitionContingencyMode decl a = true ↔ (attestedHealthy decl a).length < decl.required.length`. This is `Bool.decide_eq_true` after one `unfold`. The docstring claims "the forward direction requires inducting on the provider list," but the function is not defined by recursion on the provider list — it is one `decide` over a length comparison. The induction story is fiction. This is the BEA paper's constructor-preconditions-as-theorems trap repeated at the supporting layer.

**2. The headline theorem `admission_under_degraded_state_distinguishable_from_healthy` survives non-`rfl` status, but barely.** The LHS is a Σ-type over `r, a_h, a_d` requiring construction of two attestations. The proof IS constructive (pick a singleton attestation with healthy=true, then the same with healthy=false), and the case analysis on `List.all` over a singleton plus `List.find?` is real but small. The honest discharge is closer to `⟨_, _, _, by decide⟩` than to "case analysis on the attestation constructor" as the docstring promises. The prose in §4 paragraph "Headline theorem" and the README both overstate the proof obligation. Survives, but the framing is overclaimed.

**3. `bodyAdmits` inherits the parent paper's opaque-closure problem.** `bodyPredicates` (line 127) is `List (ReceiptId -> Bool)` — opaque function values. The headline's `h_body` hypothesis is unconstructable for any production constitution for the same reason the parent's amendment-refinement proof is unconstructable. The proof goes through; the theorem is vacuous when `c` carries non-trivial body predicates.

**4. `ReAttestationWitness` (line 205) carries the coverage proof as a Prop field.** The supporting theorem `degraded_sensor_admission_requires_re_attestation` (line 284) returns an existential whose witness's substantive content is in the constructor preconditions, not the theorem statement. The theorem says nothing the constructor does not already enforce. Constructor-preconditions-as-theorem trap, repeated.

## Critical findings (systems / security reviewer)

**5. Single-key signing makes the attestation cryptographically vacuous.** §3 paragraph "Falsifiable but not externally audited" admits: "the attestation is signed by the same key that signs the receipt body." A kernel whose receipt-signing key is compromised signs body and attestation together — the attacker forges honest-looking attestations at will. The "strict strengthening" claim collapses unless the attestation key is held somewhere the body-signing key isn't. The paper concedes this in one sentence in §9 and does not work the threat-model arithmetic. A real strengthening requires TEE-rooted attestation key separate from receipt-signing key (Intel TDX quote key, AMD SEV-SNP VCEK, AWS Nitro NSM, Apple PRA platform key) or per-provider signing. Neither appears in §5.

**6. The two-state sensor model in §3 does not match production reality.** A sensor that delivered 99.7% of events in a decision window has no canonical mapping to healthy/degraded. The `droppedEventCount` and `deadlineMissCount` fields record scalars but the *transition* between healthy and degraded within a decision window is not modeled. A sensor flapping at 10 Hz within a 100 ms decision produces an attestation that records totals but does not represent within-window oscillation. The decision window itself is not in the schema. ICS/SCADA sensor-tamper detection literature (Cárdenas, Amin, Sastry 2008; Krotofil et al. 2015) addresses exactly this and is not cited.

**7. §6 reports no numbers.** "Partition-contingency frequency" claims "a non-trivial fraction" without naming the fraction. "Structural distinction is decidable" reports the absence of an undecided verdict — a definitional property of the predicate, not a measurement. "Receipt-body stability under attestation variation" says "the corpus contains pairs that confirm the prediction" without naming pair counts, body-collision rates, or decision-window distributions. The "What is not measured" paragraph honestly defers latency and false-attestation rate to future work, but the paragraphs that DO claim measurement carry zero numbers. §6 is not an evaluation; it is a description of the predicate's structural properties.

**8. The wire-compatibility predicate in §5 is a downgrade-attack vector.** A polity operating mixed-schema kernels admits pre-extension receipts under "observation mode only." An attacker who compromises any pre-extension kernel produces observation-mode receipts that bypass the sensor-state check. The amendment that "narrows admission to extension-bearing receipts" is itself a constitutional event with a backward-refinement obligation. §9 notes schema versioning without naming the downgrade path explicitly.

## Critical findings (threat-model angle)

**9. No adversary game is defined.** USENIX Security expects threat models with capability sets and adversary goals. The paper says the adversary "previously had a silent-degradation path now has a signed-false-attestation path" and does not specify the adversary's goal, capabilities, or what wins the game. Force admission of a destructive receipt under degraded substrate? Suppress a denial? Force a verifier into partition-contingency mode against its will? Each is a distinct adversary capability with a distinct security property. The paper collapses them into "structural distinguishability" — a safety property, not a security property.

**10. The verifier's chain-of-trust on the attestation key is unspecified.** §5 says canonical-JSON follows RFC 8785 and the digest is SHA-256, but does not say which key signs the attestation, who controls rotation, or how the verifier knows the key is the kernel's at the captured timestamp. An attacker who rotates `K_kernel` and re-signs an old attestation produces something the constitution accepts under the new key without re-attesting the original sensors.

**11. The captured-timestamp is kernel-controlled.** The clock record is the only claim about *when* sensor state was captured, and the kernel is sole signer. Backdating or forward-dating makes stale attestations look fresh. The constitution can declare a max age, but the constitution's clock is also kernel-provided. §9 hedges with "the clock-attestation discipline is the same as the sensor-attestation discipline" — true and insufficient: staleness is unenforced when the clock is freely controllable. The BEA paper's TTL-requires-trusted-clock attack applies unchanged.

## Critical findings (related work depth)

**12. Behavioral attestation literature missing.** Sailer et al. "Design and Implementation of a TCG-based Integrity Measurement Architecture" (USENIX Security 2004); Coker et al. "Principles of Remote Attestation" (Int. J. Info. Sec. 2011); Asokan et al. "SEDA: Scalable Embedded Device Attestation" (CCS 2015). §8 cites `TODO_behavioral_attestation` as a single placeholder against fifteen years of work.

**13. OS integrity attestation literature missing.** Linux IMA, macOS code signing + AMFI, Windows ELAM — runtime claims about installed and healthy sensors. None cited. The contribution boundary against IMA's runtime-measurement-list is unargued: IMA aggregates ARE runtime claims about attestation policy, TPM-signed. The paper's attestation is structurally similar.

**14. in-toto / SLSA / Sigstore not cited.** The paper relies on DSSE for canonical-attestation-binding (cited as `TODO_dsse`), but DSSE originated in in-toto (Torres-Arias et al. USENIX Security 2019), which is uncited. SLSA build provenance and Sigstore Rekor witness anchoring are missing entirely.

**15. TEE specs cited as TODO placeholders only.** Eight `\cite{TODO_*}` placeholders in §8 (verified with grep). The related-work section is a placeholder map, not a defended contribution boundary.

## Voice leaks found

The voice is mostly clean — README's discipline carried through. Specific leaks:

- "The previous arrangement" recurs across §3, §4, §7, §10. Engineering-meta in thin disguise: a project-history reference dressed as theory talk. Stronger as "constructions that do not condition admission on substrate state."
- §6 line 4: "the substrate already produces sensor-attested receipts under deployment" and "without additional instrumentation" — project-status.
- §6 line 7: "the schema version under which the corpus was collected" — engineering-meta.
- §9 line 19: "the parent paper's operational-observability row in the assumption ledger" — gestures toward an undisclosed internal document.
- §9 line 31: "the substrate's schema is published" — engineering-meta. Either name the schema and URL or remove.
- Eight `\cite{TODO_*}` placeholders, including the headline parent-paper cite (`TODO_chio_2027`).

The "construction defended here," "live implementation," "release-engineering matrix," and "v1 / v2" patterns do not appear. The "v1/v2" language in §5 is on-topic schema-version semantics, not engineering-meta.

## Novel attacks I'm adding

**16. Cross-vendor treaty admission is structurally un-admissible.** §7 claims the headline composes with bilateral-treaty admission. A treaty between polity A (requires kernelCallout + networkFlow) and polity B (requires signatureDrift + supplyChainGuard) requires every kernel to attest all four. A polity-A kernel without B's required sensors installed cannot be admitted by the treaty even when polity A admits it. §9 names "union of required sets" as the default but does not handle the cross-vendor case where one polity's required sensor is unavailable on the other's kernels.

**17. The §6 identical-body-different-attestation finding is ambiguous on direction.** If such pairs are rare, the body bytes carry decision-relevant information and the finding is small. If common — paragraph 16 notes "a frequent occurrence on observation-mode receipts that record state hashes" — then the body is largely redundant and the receipt is mostly sensor-state. Useful to claim explicitly; the paper does not.

**18. The "strict strengthening" claim is conditional on an unnamed auditor.** §3 admits the strengthening only holds "if a sensor-coverage auditor exists, and the paper does not specify the auditor." §9 hedges honestly; §1 and §10 still claim strengthening without conditioning. Promise/delivery gap is real.

**19. `ReceiptFamily` taxonomy is closed.** The Lean inductive (line 37) lists five families. A real EDR has dozens (alerts, audit-mode detections, code-signature events, network egress decisions, persistence-mechanism changes, credential-access events). Per-family required set does not scale until the taxonomy is opened or the family axis is replaced with richer dimensionality. §9 defers this as "a separate extension" — the load-bearing scalability question.

## What survives the worst critique

Even granting findings 1, 5, 10, and 16, the abstract contribution stands: lifting a substrate's claim about its own state into a signed field that the admission predicate evaluates is a real placement choice with formal consequences. The headline theorem is non-`rfl` (finding 2, weakly). The connection to the parent paper's ladder (partition-contingency mode gaining a structural definition) is a genuine refinement.

The irreducible-good core:

- A canonical-JSON sensor-state schema with installed/active/healthy/degraded flags, drop and miss counts, plus a clock record. Useful as an in-toto-style attestation predicate; publishable as a short systems note with proper citations.
- The headline theorem (existence of body-identical receipts with opposite admission verdicts) as a worked Lean example with one constitution and three required-set declarations.
- The partition-contingency mode getting a structural definition as a subset relation between attested-healthy and required sensors.

## Minimum patch to make the paper publishable

Take finding 1 (no ES client) as a hard constraint:

1. **Drop §6 as written.** Replace with a worked example: one constitution requiring Network Extension egress + agent-API caller, one healthy attestation, one degraded attestation, Lean proof that admission verdicts differ. No multi-month deployment claim. No "non-trivial fraction" without numbers.

2. **Promote signing-key separation from §3 footnote to §5 first-class requirement.** Name the TEE attestation root (Intel TDX, AMD SEV-SNP, Azure MAA, Apple PRA, or AWS NSM) or restrict the claim to syntactic strengthening only.

3. **Strip `kernelCallout` and `behavioralTelemetry` from §5's provider-kind enumeration** until an ES client lands and a real behavioral-telemetry provider exists. Replace with what ships: Network Extension egress filter, agent-API caller.

4. **Rewrite §6 as "Worked Example" not "Evaluation".** Pick the venue accordingly — CSF 2027 or POPL 2028 for a formal-methods paper with a worked example; not USENIX Security as written.

5. **Restate the supporting theorem `partition_contingency_mode_iff_degraded_subset`.** Either prove a stronger statement (e.g., the mode flips at exactly the first required provider whose attestation is unhealthy, with the witness identified) or fold it into a definitional remark and not a theorem.

6. **Bibliography pass.** Eight TODO citations is a v0 marker; before submission, in-toto, IMA, Coker et al., Asokan et al., Cárdenas et al., and the four TEE specs need real citations.

After this patch: a 10-12 page CSF 2027 or HotSec 2027 paper with one substantive theorem, one worked example, and a defensible contribution boundary against in-toto and TEE attestation. Defensible, scoped, and unexciting — but ships.

---

(1) Single most damaging finding: the macOS ES client is a stub; the attestation signs flags about a sensor that does not observe the host. (2) Verdict: serious patch. Salvageable only if §6, the signing-key model, and the provider-kind enumeration are honest about what ships. (3) Headline non-`rfl` status: survives weakly. The proof is one Σ-intro plus `decide` over a singleton, not the "case analysis on the attestation constructor" the prose promises. The supporting partition-contingency theorem does NOT survive — it is one `Bool.decide_eq_true` rewrite from `rfl`.
