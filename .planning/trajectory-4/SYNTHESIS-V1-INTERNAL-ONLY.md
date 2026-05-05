# Trajectory-4 Synthesis v1 - Internal-Only Code Trajectory

**Status:** working synthesis from the 5-agent perspective debate (engineer-rigor, security-paranoid, compliance-vendor, customer-velocity, devil's-advocate), filtered to internal code work. Superseded by `SYNTHESIS-V2-INTEGRATED-PLAN.md` after the wider brainstorm landed (and v2 was revised after reviewer feedback). Kept here as the perspective-debate record.

## Scope rule

Trajectory-4 is internal-only. Out of scope:

- M01 30-day production-traffic pilot (needs partner)
- M02 real partner cosign-OIDC sig (needs partner)
- M08 vendor crypto review (needs vendor)
- M09 HITRUST cert (needs assessor)
- M10 AWS Marketplace + MCP Registry publication (operator action)
- Customer demos / TestFlight cohorts / design partner #2

These remain in `CLOSEOUT-BLOCKERS.md` as carry-forward to a later trajectory.

## Phase A (W1-2) - trj3 closeout finalization

1. Drive remaining trj3.2 PRs through CI cascade-merge to main (currently ~30 open, all carry auto-merge).
2. Tag `v3.18.1-trj3.1`; trigger `release-binaries.yml` + `slsa.yml` + `reproducible-build.yml`.
3. Commit produced artifacts:
 - `releases/provenance/v3.18.1-trj3.1.intoto.jsonl`
 - `releases/reproducible-builds/v3.18.1-trj3.1.json`
 - `supply-chain/checksums/v3.18.1-trj3.1.txt`
4. Replace TODO markers in `TRAJECTORY-FINAL.md` + `CI-DEBT.md` with the real close SHA and consolidated CI run URL.
5. Drain remaining trj3.2 P2 backlog (items reviewers logged but didn't fix in scope).

## Phase B (W2-6) - substrate hardening (engineer-rigor + security-paranoid overlap)

6. **Unblock hosted nightly cargo-mutants.** PR #519's fuzz-budget warn-mode didn't reach the nightly full-sweep step. Drive each trust-boundary crate's measured kill rate to **>= 65%** on full sweep; **>= 80%** on `chio-attest-verify` with explicit `# unreachable: <justification>` annotations on residual survivors.
7. **Three deferred Kani harnesses**: `chio-attest-verify`, `chio-anchor`, `chio-weights`. Modeled on `chio-kernel-core::kani_public_harnesses.rs`. Wire into `nightly.yml` Kani lane.
8. **TLA+ rewrites and apalache lane fixes**:
 - `RevocationCutCompleteness`: bounded transitive-closure unrolling (W6E P1).
 - `ReceiptBeforeAllow`: split `Allow` into `LogReceipt` + `PublishAllow` so the property stops being tautological (W6E P1).
 - Bump `EpochMax` from 4 to 6 so length=6 fully utilizes apalache run budget.
 - Fix `RevocationEventuallySeen` apalache 0.50.1 temporal-encoding bug; promote `apalache-temporal.yml` from advisory back to required.
9. **Hosted-vs-portable equivalence test**. New `crates/chio-equivalence-tests/` workspace member with `proptest` strategies generating policy scopes / tool-execution payloads / guard inputs. Assert byte-equal verdicts between hosted and portable matchers. CI: 10k cases per PR + 1M nightly. Zero divergence allowed.
10. **`trust_control_cluster_multi_region_partition_qualification` root-cause fix.** Real concurrency / replication-lag fix, not a retry loop.
11. **`chio-tee-frame::validate` real signature verification.** Currently regex-checks `tenant_sig` but never verifies it cryptographically. Wire a real verifier alongside the signer.
12. **`chio-tee-frame::schema::validate_timestamp` real RFC-3339 parse.** Shape-only today (accepts `2026-13-99T25:99:99.999Z`).

## Phase C (W6-8) - mobile attestation real verifiers (no vendor needed; just code)

13. **Apple App Attest** in `chio-custody-hw/src/attestation/app_attest.rs`: CBOR parse + cert-chain validation against pinned Apple App Attest root + counter monotonicity + nonce binding + KeyId binding. Replace `AttestationUnavailable` returns at `chio-kernel-mobile/src/lib.rs:433`.
14. **Play Integrity** in `chio-custody-hw/src/attestation/play_integrity.rs`: real JWS validation against Google JWKS (with rotation), audience claim check, server nonce binding, verdict verification (`MEETS_DEVICE_INTEGRITY` etc.). Replace `AttestationUnavailable` at `chio-kernel-mobile/src/lib.rs:454`.
15. **Real `ChioKernel.xcframework` binary** in `Frameworks/`. Reproducible-build attestation to prove provenance.
16. **Threat-coverage flip** for `mobile_attestation_replay`, `device_key_extraction`, `play_integrity_token_replay` from `pending+deferred_to` back to `covered` with real conformance tests in `crates/chio-conformance/tests/threats/`.

## Phase D (W8-10) - meta-improvements

17. **Threat-coverage cargo-mutants per-row gate.** Every threat marked `covered` must have a cargo-mutants sweep proving its named test actually kills relevant survivors. Auto-downgrade to `weak_coverage` on zero kills.
18. **Feature archeology.** Grep the 89 `chio-*` crates plus workspace tools, integrations, examples, SDKs, and provider adapters for surfaces with zero in-tree call sites or zero test coverage. Deprecate or document.
19. **Fail-closed philosophy audit doc.** Inventory every `?` propagation crossing a trust boundary; confirm it lands at a `Deny` not a `pass-through`. Code-style guide entry.
20. **CI-DEBT.md final pass.** Confirm zero entries remain in `requires-individual-replay-or-deferral` once cascade settles.

## Trj4 close bar (all internal, all measurable)

1. CI-DEBT fully reconciled.
2. Hosted nightly cargo-mutants runs to completion (no fuzz-budget skip); kill rate >= 65% per trust-boundary crate, >= 80% on `chio-attest-verify`, recorded in `releases.toml`.
3. 6/6 trust-boundary crates have Kani harnesses passing in nightly.
4. `RevocationCutCompleteness` transitive + `ReceiptBeforeAllow` split landed; `RevocationEventuallySeen` apalache lane back to required.
5. Equivalence property test passing 1M cases nightly, zero divergence.
6. `trust_control_cluster_multi_region_partition_qualification` 100/100 runs at 20 partition/heal cycles.
7. Mobile attestation entry points return real verdicts (no `AttestationUnavailable`); xcframework binary in tree.
8. 3 mobile threats back to `covered` in spec/security with real test backing.
9. `v3.18.1-trj3.1` tag shipped with green release-binaries + slsa + reproducible-build artifacts.
10. `TRAJECTORY-FINAL.md` committed with real close SHA.
11. Threat-coverage cargo-mutants per-row gate live.
12. Feature archeology doc committed; deprecation candidates filed as trajectory-5+ tickets.

## Estimated calendar

8-10 weeks single-track (engineer-rigor's bound) with the parallel CI cascade in W1.

## What this synthesis is NOT

This is the **floor** for trj4 - the substrate-hardening + closeout work that earns the right to add anything else. The user has correctly observed it is narrow. A wider brainstorm round (separate doc) explores high-value features that could be added on top of this floor, given everything trj1-trj3 already built.
