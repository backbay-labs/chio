# Adversarial Review (Cycle 2)

## Single most damaging finding (uniquely new to this cycle)

**§1 and §10 say "six host-snapshot sites out of thirteen surveyed, with the remaining seven covered by a placeholder," but §5 and §6 say six host-snapshot sites plus thirteen placeholder sites (nineteen total).** §1:21 ("six out of thirteen surveyed, remaining seven placeholder") flatly contradicts §5:19 ("Thirteen sites consume the constant") and §6:12 ("Thirteen further sites"). §10:6 repeats the §1 phrasing. The bookends are arithmetically incompatible with the body.

Unique to cycle 2: §1 contribution bullets were expanded in cycle-2 FIX-1 and the contradiction was introduced then. Cycle-1 flagged the placeholder population (S4) but not as arithmetic. The paper's only empirical anchor is "the deployment instance," described in two incompatible numerical breakdowns within ten pages. More damaging than S1 (anticipated) because it is a factual error any reviewer flags in thirty seconds.

## Critical findings (formal-methods reviewer)

**F-C2-1. Theorem 1's name still implies a Π-separation; the rename has not happened.** STATUS.md is honest, §4 prose is honest (Σ-construction over fixed witnesses), §10 prose is honest, but the Lean identifier `admission_under_degraded_state_distinguishable_from_healthy` is unchanged at `SensorGroundedAdmission.lean:350`. §1:17 cites it under this name; §10:6 cites it under this name. A reviewer who opens the Lean file and reads "distinguishable from healthy" expects a universal-quantified separation, finds a two-witness existential, and concludes the canonical theorem name is rhetorically inflated. The cycle-2 RESEARCH file `headline-theorem-candidates.md` recommended the rename to `admission_predicate_separates_healthy_and_degraded_witnesses`. Not done.

**F-C2-2. Theorem 3's inert `_h_destructive` and Theorem 4's inert `_h_prev_decl` hollow out two of four supporting theorems.** STATUS.md at lines 80-88 and 126-129 admits both. §1:19 calls Theorem 3 "a destructive-admission-witnesses-coverage projection" but the Lean never inspects `destructiveAdmissionFamily r.body.family`. §1:20 calls Theorem 4 "an amendment-improvement theorem" but `_h_prev_decl` is also unused. The §9:28 row mentions only Theorem 3; Theorem 4's inert binder is undisclosed. A reviewer counting structural work concludes the paper has one theorem (T2), one Σ-existence (T1), and two `Bool.and`-style projections (T3, T4); the "four supporting theorems" framing softens this.

**F-C2-3. The body-admission premise on Theorem 1 remains vacuously satisfiable.** `bodyPredicates : List (ReceiptId -> Bool)` (line 130) takes opaque functions; the headline premises `∃ r, bodyAdmits c r = true`, satisfied by any constitution with `bodyPredicates = []`. Cycle-1 F2 flagged this; the cycle-2 honesty pass clarified prose but did not strengthen the Lean. A reviewer who tries to instantiate the headline against a non-trivial body predicate cannot construct the witness from the theorem's premises.

## Critical findings (systems / security reviewer)

**S-C2-1. S1 single-key collapse is unmentioned in §9 despite being confirmed damaging.** §9 has no row labeled "body-signing and attestation-signing keys are the same kernel key." §3:18 and §4:59 each carry one sentence, both buried mid-paragraph. §9, where a USENIX-tier reviewer expects the structural-vs-cryptographic gap row, is silent. REVIEW intake names this as item 1. Not done.

The §9 row alone is necessary but not sufficient. A §3 paragraph naming the TEE-rooted extension axis (Intel TDX QE/PCE, AMD SEV-SNP VCEK, Apple SEP UIK, Microsoft Pluton AK, TPM 2.0 AK certified by EK) makes the row recoverable rather than fatal: the fix is available in commodity hardware, so the gap is a deployment choice. Without it, the §9 row reads as self-criticism. The Lean stub `sensor_attestation_marginal_trust_requires_separate_key` makes §4:59's prose load-bearing in mechanized content; without it the §4 prose is a verbal hedge the formal layer does not back.

**S-C2-2. Bilateral cosignature has an asymmetric-trust cross-product attack.** A bilateral deployment where one polity runs on a TEE platform with hardware-enforced attestation-key separation, the other on commodity hardware with single-key signing. The admission predicate succeeds; both required sets are covered. But the marginal trust contributed by the second polity's attestation is structurally lower. §3:24 treats cosignatures symmetrically. §7:11's "strictly tighter than the parent paper's predicate alone" is true in isolation but does not address heterogeneous trust. A treaty between a TEE-rooted polity and a single-key polity gets the strength of the weakest cosigner; the paper does not say this.

**S-C2-3. §6 is empirically thinner than parent §6 by an order of magnitude.** Parent §6 reports treaty-intersection p50/p99 (measured), selective-disclosure proof-size and verify p50/p99 (measured BBS+), names a baseline machine (M1 Max), and runs Criterion benches. Sensor-grounded §6 reports: one mutation-rejection test (verifier-self-consistency, no latency), zero p50/p99 numbers, zero machine specification, Criterion bench admittedly withheld. The honest "absent measurements are marked" framing does not compensate for the chapter delivering a single qualitative check where the parent delivered measured percentiles. The empirical content is below the standard the parent set.

## Critical findings (threat-model angle)

**T-C2-1. The decision-window framing in §3 does not address attestation-timing skew.** §3:21 captures within-window flapping via drop and miss counts; §9:16 admits dominant-state discretization. Neither addresses the case where the attestation is HONESTLY signed but signed AFTER the receipt body's decision time, with the sensor degrading in the gap. Kernel attests at T_a, body decided at T_d < T_a; between T_d and T_a a healthy sensor degrades. Attestation reports degraded; body was decided under healthy sensors. §3:11's clock state has `capturedAt` on the attestation but not a separate `decided_at` on the body. The predicate evaluates as-of `capturedAt`, not as-of `decided_at`. §9:18 does not flag this timing gap as a separate axis.

**T-C2-2. Clock attestation is self-attested under the same kernel key.** §3:12 introduces the clock record; §9:18 admits no external validation. A kernel that lies about its sensors can lie about its clock; both signed by one key. The single-key-collapse argument applies twice (sensor data + clock) but the paper treats it as one gap. A separate-attestation-key extension axis hardens both; §9's row treatment of clock attestation as parallel to sensor attestation misses that single-key collapse is the COMMON failure mode.

## Critical findings (voice / engineering-meta)

**V-C2-1. §6:9 cites the test name `endpoint_sensor_state_receipt_binds_provider_health` directly in prose.** Cycle-1 V2 flagged this; FIX-4 stripped path citations but the test identifier survives. The §6 paragraph also names `validate()`, `Err`, `providerCount`, `providerIds`, `activeProviderCount`, `sensorStateHash`, `healthyProviderCount`, `degradedProviderCount` (implementation-API names, not field labels a paper would use to describe the contribution). The chapter reads as an internal engineering note.

**V-C2-2. §5:10 names `validateTreatyScope`; §5:19, §6:12, §6:15 cite Rust function symbols verbatim** (`endpoint_sensor_state_from_macos_host`, `EndpointSensorState::single_active_agent("agent-api")`, `endpoint_sensor_state_content_hash`). A paper introduces concepts with symbolic names but does not cite Rust function symbols verbatim. Cycle-1 stripped paths but left function symbols.

**V-C2-3. §6:18 cites `es_new_client` and `es_subscribe`** as Apple API symbols the system extension does not call. Less severe (real Apple ES entry points), but the prose pattern "the substrate's system extension does not call [internal-API name]" is engineering-meta posture.

## Novel attacks I'm adding

**N-C2-1. The §1 bullets and §10 closing paragraph disagree subtly on Theorem 3.** §1:19 says "any admitted receipt, viewed through the admission predicate's three-conjunct shape, carries a declared required-set and an attestation covering that set" (honest about the projection). §10:6 says "any admitted receipt has a declared required set and an attestation covering it" (drops "three-conjunct shape," reads stronger). Neither §1 nor §10 acknowledges Theorem 3's `_h_destructive` is inert; only §9:28 mentions it. A reviewer who reads §1 and skips §9 takes away "destructive-admission-witnesses-coverage" as substantive; §10 reinforces this misreading.

**N-C2-2. The four-theorem rhetoric understates that only Theorem 2 does load-bearing inductive work.** Cycle-2 RESEARCH file `headline-theorem-candidates.md` ranks weakest-to-strongest: T1's proof is mechanical once support lemmas are in hand; T3's is `Bool.and` decomposition; T4 relies on `partitionContingencyMode_false_of_covered`, one application of `List.filter_eq_self`. Only T2 composes three named list lemmas in both directions of a biconditional. The §1 bullets / §9:28 / §10:6 treat all four as peers. A formal-methods reviewer writes "the structural content is thinner than the four-theorem framing implies."

**N-C2-3. The wire-compatibility paragraph (§5:21-22) and §9:21-22 are still present; Case-A/Case-B ambiguity is unresolved.** Cycle-2 `amendment-cycle-paradox.md` concluded the framing fits Case B but is silent. REVIEW intake item 2 names this as needing one disambiguating sentence. Not done. §5:21 ("removable by an amendment that narrows the admission predicate") plus §9:22 ("should be retired by an amendment that narrows admission to extension-bearing receipts") together treat the compatibility predicate as if it were itself the result of a prior amendment that widened admission, triggering the N1 backward-refinement objection. Fix: one sentence declaring the construction is a fresh constitution, not an amendment of the parent.

## What survives the worst critique

1. **Theorem 2 survives.** Proper-sublist biconditional with `filter_sublist` + `length_le` + `eq_of_length` is real structural work in both directions; load-bearing formal piece.
2. **The §3 four-flag schema with drop/miss counts and clock record is coherent.** Defensible against RFC 9334 framing.
3. **The §4 worked example is concrete.** A reader follows the predicate evaluation by hand.
4. **The §8 placement argument vs TEE attestation survives.** Primary-source citations in place; "what wire formats structurally cannot express" reframing carries the contribution boundary.
5. **The §3:21 within-window-discretization paragraph and §9:16 flapping row land cycle-1's constructive patches honestly.**

Everything else is conditional. The headline theorem survives but its name overpromises; two of four supporting theorems have inert binders; the empirical chapter is a single-test verifier-self-consistency note.

## Minimum patch to make the paper publishable

**Priority 1: arithmetic correction (most damaging).** Fix §1:21 and §10:6 to say "six host-snapshot emitter sites out of nineteen surveyed, with the remaining thirteen covered by a placeholder single-active-agent attestation." One-word fix (thirteen → nineteen, seven → thirteen) removes the abstract-vs-body contradiction. Not making this fix is a 30-second reviewer flag.

**Priority 2: S1 closure (three-part).** (a) Add §9 row "body-signing and attestation-signing keys are the same kernel key" in three-column format. (b) Add §3 paragraph naming the TEE-rooted attestation-key extension axis so the §9 row reads as contribution boundary rather than self-criticism. (c) Add Lean stub `sensor_attestation_marginal_trust_requires_separate_key` to make §4:59 load-bearing. (a) alone is the floor; (a)+(b)+(c) is full closure.

**Priority 3: Theorem 1 rename plus N1 disambiguation.** Rename Theorem 1 to `admission_predicate_separates_healthy_and_degraded_witnesses` in `SensorGroundedAdmission.lean:350`, §1:17, §10:6, §4:36. Add one sentence to §5:21 or §9:22: "The sensor-attestation construction is a fresh constitution, not an amendment of the parent paper's body-only constitution; the backward-refinement obligation applies to amendments within the new constitution, not to its introduction." Closes N1.

**Priority 4: cycle-2 voice-leak pass.** Strip the test identifier `endpoint_sensor_state_receipt_binds_provider_health` from §6:9. Strip Rust function-symbol citations in §5:10 (`validateTreatyScope`), §5:19 / §6:12 / §6:15. §6:18 Apple API names are borderline.

**Priority 5 (defer if tight): Theorem 3 hypothesis fix.** Drop `_h_destructive` from Theorem 3 (half-day) or strengthen the proof body (one day Lean plus one day prose).

After P1+P2+P3+P4 the paper is arithmetically correct, has its S1 row, Theorem 1 renamed, N1 disambiguated, §6 voice leak closed. Remaining gaps (Theorem 3 binder, §6 thinness, heterogeneous-trust cosignature) are honest limitations that do not block submission.

---

(1) Single most damaging finding: §1:21 / §10:6 say "thirteen surveyed / seven placeholder," but §5:19 / §6:12 say six host-snapshot + thirteen placeholder = nineteen sites. The bookends contradict the body on the only empirical anchor. (2) Verdict: serious patch needed. Priority 1 is a 30-second reviewer flag and must be fixed; Priority 2 closes the cycle-1 S1 finding research confirmed damaging; the rest is achievable in one FIX cycle. (3) Top-3 priority items for the next FIX cycle: (a) fix §1/§10 arithmetic to nineteen total; (b) land the S1 closure three-piece (§9 row + §3 TEE extension paragraph + Lean stub theorem); (c) rename Theorem 1 and add one N1 disambiguation sentence to §5 or §9.
