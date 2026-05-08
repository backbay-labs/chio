# Position 01 - Substrate Hardening Hawk

**Author role**: Substrate Hardening Hawk
**Date**: 2026-05-07
**Thesis**: release work must NOT start anything new. The wave plan for trj4 closeout (Wave 0-16, ~30 P0/P1 issues) must be fully consumed first. Any new lane is dishonest until the structural-framing-vs-hot-path-wiring gap is closed.

---

## 1. Ground truth: trj4 is reopened, and the gap is structural

`/.planning/trajectory-4/TRAJECTORY-4-CLOSEOUT-ERRATUM.md` line 11 is the load-bearing sentence for this entire debate:

> "structural framing landed (types, schemas, registry entries, doc generators) but runtime wiring did not (kernel/verifier hot paths, separate-file negative conformance tests, real proof artifacts behind theorem-inventory rows). Approximately 30 P0/P1 issues were filed against artifacts that the prior closeout summary lists under 'Closed' or 'Validation'."

`releases.toml [trajectory_4]` (lines around `trj4_release_status`) records `trj4_release_status = "reopened"` and points at the erratum. The `trj4_release_tag` line is retired. We do not yet have a tagged trj4 release. The `CLOSE-BAR-TRACKER.md` ledger - which `scripts/check-close-bar-tracker.sh` grades against and which asserts >= 153 rows - currently has **16 DONE rows against 141 PARTIAL/NONE rows** (grep over `.planning/trajectory-4/closeout/CLOSE-BAR-TRACKER.md`). The `README.md` mutation banner still reads `Mutation kill: 31% - six-crate trust-boundary mutation baseline ... 2026-04-29` - i.e. roughly half of the trust-boundary kill-rate floor we promised in `audits/T0.B-substrate-hardening.md` (>= 65% per crate, >= 80% on `chio-attest-verify`).

This is not a bookkeeping problem. It is a credibility-of-evidence problem. The whole pitch of Chio is "auditable outcomes": proven theorems, signed receipts, pinned conformance. Calling trj4 done while 9/20 threat rows have weak or meta-only coverage (`docs/security/threat-coverage.md` line 5: "9 of the 20 covered rows currently pass the gate on file-exists + no-`unimplemented!()` alone, with weak or meta-only assertions in the backing test") is the exact bait-and-switch the whole project is supposed to refuse.

## 2. Quote sheet: ten unresolved items by file/line/wave

These are not vague "lots of P0s." Each one has a file, a wave id, and a tracker row.

1. **CLOSE-BAR row #2 (Wave 02, PARTIAL)**: `CLOSE-BAR-TRACKER.md` row `close-bar-#2` - "hosted nightly cargo-mutants exists; per-crate kill-rate not yet >= thresholds". The README banner still says 31%. We promised >= 65% per trust-boundary crate, >= 80% on `chio-attest-verify`.

2. **CLOSE-BAR row #3 (Wave 02, PARTIAL)**: `close-bar-#3` - "Kani harnesses present for some trust-boundary crates; 6/6 nightly green not yet". `TRJ4-012`/`TRJ4-013`/`TRJ4-014` (Kani for `chio-attest-verify`, `chio-anchor`, `chio-weights`) are all open per `EXECUTION-BOARD.md` Phase B.

3. **CLOSE-BAR row #4 (Wave 02, PARTIAL)**: `close-bar-#4` - "TLA+ rewrites pending; RevocationEventuallySeen apalache lane currently optional". `TRJ4-015..018` are open. `apalache-temporal.yml` is still advisory, not required - which means a temporal-encoding bug in the revocation lane can ship and CI will not catch it.

4. **CLOSE-BAR row #6 (Wave 02, PARTIAL)**: `close-bar-#6` - `trust_control_cluster_multi_region_partition_qualification` flake-fix in progress. `TRJ4-020` requires a real concurrency/replication-lag root-cause, not a retry loop.

5. **CLOSE-BAR row #7 (Wave 02, NONE)**: `close-bar-#7` - "Apple App Attest + Play Integrity verifiers return AttestationUnavailable; xcframework binary missing". `T0.C-mobile-attestation.md` is reopened; the live verifier was added but only against deterministic fixtures - "Real-device App Attest fixtures from an internal iOS test fleet are not present in-repo" (audit lines 65-66). We accepted fixture-only evidence as production once already; that is the failure mode.

6. **CLOSE-BAR row #11 (Wave 02, NONE)**: `close-bar-#11` - "HttpEgressContract not yet defined in chio-http-core" was the original audit finding; recent commit `708c7bb33 feat(trj4/W2.2): wire HttpEgressContract into 16 production callers` advances W2.2 wiring but the per-row SSRF negative-conformance suite (`TRJ4-045`) remains explicitly gated on T0.B/D coordination.

7. **CLOSE-BAR row #12 (Wave 02, NONE)**: `close-bar-#12` - "policy/manifest semantic-diff CI gate not yet built". `TRJ4-024`. Without this we cannot detect a silent newly-allow widening on a `chio-policy` PR.

8. **CLOSE-BAR row #18 (Wave 04, NONE)**: `close-bar-#18` - "lineage v1 single-parent; v2 multi-parent + dag_ordinal not yet shipped". `TRJ4-126..130` open. The Lean theorem on body-hash input set (`TRJ4-130`) is `proposed`, not `proven`, per the post-Wave-0 E0.1 demotion noted in CLOSE-BAR-TRACKER lines 28-29.

9. **CLOSE-BAR row #22 (Wave 13, PARTIAL)**: `close-bar-#22` - "exemption count 819 today; no net-new gate not yet in CI; top-50 burn-down not yet started". `TRJ4-159`/`TRJ4-160`. Supply-chain trust at 819 exemptions is incompatible with our threat model.

10. **CLOSE-BAR row #25 (Wave 06, NONE)**: `close-bar-#25` - "chio-log-redact crate not yet authored; redacted!() macro not yet defined". `T1.5-sre-foundations.md` line 41-42 makes this MANDATORY because PHI-in-PagerDuty is the zero-tolerance failure mode for healthcare.

Bonus eleventh: **CLOSE-BAR row #19 (Wave 05, PARTIAL)** - `close-bar-#19` "anchor batch type substrate exists in chio-anchor; chio.anchor_batch.v1 wire artifact + witness + Evidence Gate items NONE." Recent `7ee1ddbcc BREAKING: feat(chio-anchor): wire AnchorWitnessClient + WitnessState (W2.3)` lands the witness state machine but the four T1.3 negative-conformance tests (forged batch root, mis-ordered inclusion proof, witness-lane impersonation, stale-witness fallback - per `EXECUTION-BOARD.md` `TRJ4-T1.3.E`) are not in.

The scoreboard: of 30 close-bar rows, only #9, #10, #13, #14, #15, #16, #17, #20 are DONE. That is **8 of 30**. Calling trj4 finished and starting release work says we are willing to ship 22/30 items as PARTIAL/NONE.

## 3. Why deferring closeout is a credibility-destroying move

Chio's customer pitch (`docs/README.md`, `spec/PROTOCOL.md`, every milestone audit doc) rests on three claims: "fail-closed by default," "every claim has a backing theorem or negative-conformance test," and "auditable outcomes." The trj4 erratum is what happens when an LLM-driven closeout mistakes structural framing for runtime wiring once. Doing it twice destroys the brand. Specifically:

- We **already published** `TRAJECTORY-4-FINAL.md`, `releases.toml` had a `trj4_release_tag`, `audits/T*.md` rows said "closed". External readers who indexed any of that have to reload context every time we relitigate. A second over-claim would not be a recoverable error.

- The `check-threat-coverage-mutants.sh` script and the new `weak_coverage` enum state (`docs/security/threat-coverage.md` lines 12-18) exist precisely because we found `assert!(true)` in the trees. If we move on to release work lanes before backfilling real cargo-mutants evidence at `audits/evidence/threats/<id>.json` (per the doc), the new gate is itself a paper tiger.

- Wave 1.5 just landed (commit `05fd0c56e fix(trj4): wave-1.5 hot-path-wire chain-binding + negotiation + sibling-sum across 5 surfaces`). The W1.5 hot-path wire on capability negotiation, attenuation chain-binding, and budget sibling-sum is the proof point that wave-by-wave hot-path wiring works. It would be perverse to abandon the cadence the moment it started producing real DONE rows.

## 4. Rebuttals

### (a) "Ship guard SDK + WASM v4 in release work"

Counter: every guard SDK customer expects threat-row backing tests to be real. CLOSE-BAR rows `C-1` (PromptInjectionGuard), `C-2` (AgentLoopBoundsGuard), `C-3` (CapabilityAttenuationGuard), `C-5..C-10` are all currently NONE/PARTIAL. Releasing a guard SDK over a substrate that says "9 of 20 threats are weak coverage" is selling exposed wire as armor. Also: WASM v4 lands on `chio-wasm-guards` (CLOSE-BAR row `C-2`/`A-3` adjacent). The current `wasm_guard_resource_exhaustion` row (`TRJ4-046`) was only just promoted out of stub state in audit T0.D lines 49-50; pinning it as v4 before Wave 4's per-row mutant gate is unsafe.

### (b) "Decompose the kernel"

Counter: you cannot decompose what you have not pinned. `T1.0-capability-negotiation.md` lines 39-46 list the Evidence Gate items - PROTOCOL.md update, schema files at `spec/schemas/chio-wire/v1/capability/{capabilities,token}.schema.json`, claim registry, proof manifest, theorem inventory, generated proof report, plus the `capability_v2_unknown_schema_rejected.rs` negative conformance test. Without these, a kernel decomposition would distribute partially-verified primitives across more crates - increasing the surface area for the same structural-vs-hot-path drift the erratum names. The 81 KLOC `chio-cli` god module (CLOSE-BAR row `X-7`) is a real problem, but it is a Wave 13 problem, not a release work lane.

### (c) "Pivot to product / dogfood"

Counter: dogfooding is exactly what `feat: add local Chio knowledge base stack` (commit `f35189be7`) and the kb-mcp work (`6de68c9d6`, `1ea076a94`, `cc11f0110`) already do. Dogfood is great but it does not need a release work banner. Meanwhile, T1.5 log-redaction (CLOSE-BAR row #25, NONE) is the load-bearing safety property for any healthcare deployment - dogfood that emits PHI to PagerDuty is worse than no dogfood. We do not get to pivot to product when the operability story is still PARTIAL.

## 5. Honest concession: what could slip to release work

If the council insists release work must include something new, the minimum acceptable concession is:

- **Defer Wave 13 archaeology backlog (CLOSE-BAR rows X-3..X-15)** to release work entry. The `chio-cli` decomposition, the README backfill across 62 crates without one, the `println!`/`eprintln!` migration, and the `chio-anchor` web3 feature gate are all real but they are not load-bearing for any verifier. They can ride a refactor-only release work lane in parallel.

- **Defer Wave 11 H/T-lens hardware-attestation buffet (H-1..H-12 and T-2..T-12)** beyond TRJ4-030/031/032/033. We get App Attest + Play Integrity real, plus xcframework reproducible build. Apple Secure Enclave kernel-key backend (H-1), TPM 2.0 (H-2), Azure MAA (H-3), GCP Confidential Space (H-4) - all stay catalog-only.

That is the floor. Anything that slips Wave 0-7 (the actual erratum coverage) is unacceptable.

## 6. If the hawk view loses: release work shape that minimizes new surface

If release work must launch with new content alongside trj4 closeout:

- **Lane Z (mandatory, blocking)**: Waves 0-7 of `local trajectory-4 closeout plan` complete. Each wave's E gate signed off. `releases.toml` `trj4_release_status` flips to `closed` on real evidence, with a real tag.

- **Lane A (one strategic add)**: T1.6 `chio explain <receipt-id>` CLI shipped. It is `S` effort (`EXECUTION-BOARD.md` TRJ4-180..183), it consumes the now-pinned receipt v2 + attenuation chain + batch witness, and it is the load-bearing demonstration that the substrate is real. This is the "audit a receipt end-to-end" demo we owe customers.

- **Lane B (one defensive add)**: a *single* hardware attestation row from H-lens chosen by deployment partner pull, NOT by catalog parity. Pick one of {Nitro PCR-set policy, TPM 2.0 quote backend, Apple Secure Enclave kernel-key} based on which actual customer is asking. Reject the buffet.

- **No new lanes for**: kernel decomposition, guard SDK general release, WASM v4, multi-modal receipts, agentic-deception detector, Rekor TransparencyLogReceiptExporter. Catalog only.

This shape adds two strategic surfaces. It does not pretend trj4 is closed. It admits one customer-visible deliverable (`chio explain`) and one customer-driven hardware row, and it gates everything else behind the wave-plan close.

## 7. Bottom line

The trj4 erratum was a near-miss credibility incident. The wave plan is the correction. The correction is not finished. Until `releases.toml` `trj4_release_status` reads `closed` over real evidence - 20/0/0 threat coverage with real cargo-mutants per-row evidence, >= 65% trust-boundary kill rate published in `releases.toml`, all four `T1.x.E` Evidence Gates green, six Kani harnesses nightly green, mobile real-device fixtures in tree - "release work" should mean "the trj4 closeout we promised, finished honestly." Anything else is the second LLM-driven over-claim, and we do not get a third.
