# Position 04 - Quality, Mutation, and Formal-Verification Skeptic

**Author role**: Quality, Mutation, and Formal-Verification Skeptic
**Date**: 2026-05-07
**Thesis**: Chio's positioning is "auditable outcomes" and "cryptographic proof artifacts." The verification floor under those slogans is currently a Potemkin village - a 31% mutation kill rate, a 20/0/0 threat-coverage gate held up by 21 bootstrap-placeholder evidence files where every `caught == 0`, four Lean theorems that prove `f x = f x` by `rfl`, and a TLA+ lane where the temporal-encoding bug fixes are still unowned tickets. Until that floor is real, every other lane (decomposition, productization, vision) is hollow. **Trj5 must be the assurance-floor trajectory: drive trust-boundary mutation kill to >= 70%, ship real Kani harnesses on `chio-attest-verify` / `chio-anchor` / `chio-weights`, rewrite the four broken/tautological TLA+ properties, and replace meta-only threat tests with real failure-path bodies and real cargo-mutants evidence.** The `RELEASE_AUDIT.md` decision must stop hiding gaps behind "compatibility-only" boxes.

---

## 1. Quantify the gap - the numbers don't sustain the slogans

### 1a. Mutation kill: 31% on six trust-boundary crates

`README.md` line 17: "Mutation kill: 31% - six-crate trust-boundary mutation baseline, mixed sweep/shard n=375 viable mutants - 2026-04-29". The six crates per `releases.toml [trust_boundary_crates]`: `chio-policy`, `chio-credentials`, `chio-attest-verify`, `chio-kernel-core`, `chio-guards`, `chio-anchor`. The `[per_crate_kill_rate_percent]` block reports `pending trajectory-3.1 phase 4.2 full-sweep measurement` for **all six** - no published per-crate numbers, just a 31% aggregate. Trj4 close-bar target (`audits/T0.B-substrate-hardening.md` line 16): >= 65% per crate, >= 80% on `chio-attest-verify`. We are at less than half, on a baseline pre-dating recent W2.x hot-path rewires - survivor count likely went up.

### 1b. Threat coverage: 20/0/0 PASS, but 21 of 21 evidence files are bootstrap placeholders

The headline state in `docs/security/threat-coverage.md` line 5:

> "the gate reports 20 covered / 0 pending / 0 uncovered (PASS)."

The line 7 footnote:

> "9 of the 20 covered rows currently pass the gate on file-exists + no-`unimplemented!()` alone, with weak or meta-only assertions in the backing test."

I checked every file in `audits/evidence/threats/`. **Every single one** of the 21 JSON files (one per threat ID, including `weights_hash_spoof.json`) has:

```json
{ "caught": 0, "needs_real_run": true, "ran_at": "1970-01-01T00:00:00Z", "survivors": [] }
```

Read that again: the `check-threat-coverage-mutants.sh` runtime backstop the team built specifically to catch the `assert!(true)` failure mode is being satisfied by 21 epoch-zero placeholder files. The only thing keeping those rows green is the `needs_real_run: true` bootstrap-bypass clause in `docs/security/threat-coverage.md` line 20. That clause was a one-week-window concession; trj4 wave 4 was supposed to backfill, and it has not.

Concrete examples of meta-only test bodies:

- `tests/threats/native_channel_replay.rs` (41 lines): calls `assert_threat_covered_by_corpus(...)` and asserts the corpus has `>= 2` distinct attack classes. Never instantiates a verifier, never feeds a replayed nonce, never observes a deny.
- `tests/threats/pq_signature_downgrade.rs` (52 lines): does `assert_file_contains` on four other test files to grep for test-function names. It is a glorified `grep -F`.
- `tests/threats/weights_hash_spoof.rs` IS a real failure-path test (`Err(WeightsError::CardMismatch)`), but `audits/evidence/threats/weights_hash_spoof.json` is still the bootstrap placeholder. Even when the test is real, the mutation-gate is empty.

### 1c. TLA+: four open temporal-encoding / tautology bugs (TRJ4-015..018)

Per `EXECUTION-BOARD.md`, all four are open:

- **TRJ4-015** - `RevocationCutCompleteness` rewrite with bounded transitive-closure unrolling.
- **TRJ4-016** - Split `Allow` into `LogReceipt` + `PublishAllow` so `ReceiptBeforeAllow` stops being **tautological** (`audits/T0.B-substrate-hardening.md` line 20).
- **TRJ4-017** - Bump `EpochMax` from 4 to 6.
- **TRJ4-018** - Fix `RevocationEventuallySeen` apalache 0.50.1 temporal-encoding bug; promote `apalache-temporal.yml` from advisory to required.

`formal/tla/RevocationPropagation.tla` lines 17-25 document a forced workaround for an Apalache encoding limitation (`WF_vars(\E ...)` rejected, lifted into a named `PropagateAny` action). The liveness lane is still **advisory** per CLOSE-BAR-#4; a regression on the load-bearing revocation property would never block CI.

### 1d. Lean theorems: 75 IDs, 0 proven, 4 explicitly `assumed`, 71 with no `status`

`formal/theorem-inventory.json` lists 75 `id` entries; only 4 carry a `status` field, all `"assumed"`. 71 carry no `status` at all. The headline `negotiation_safety` theorem in `formal/lean4/Chio/Chio/Proofs/HandshakeNegotiation.lean` lines 77-84 says `schemaCeilingCheck x y = (if le x y then admit else reject)` and is proven by `rfl` - the function definition is literally that expression. Tautology proven by definitional unfolding, not refinement against the Rust verifier. The file admits (lines 10-12) the Lean toolchain is unavailable in CI; nobody has type-checked the proof. `AttenuationWitness.lean` and `SiblingSumBudget.lean` carry the same disclaimer.

### 1e. Kani: zero harnesses on the three deferred trust-boundary crates

`grep -lr "kani::"` over `crates/chio-attest-verify`, `crates/chio-anchor`, `crates/chio-weights` returns **zero files**. The only Kani harnesses live in `chio-kernel-core/src/{kani_harnesses,kani_public_harnesses}.rs` (12 + 18 attribute hits). `EXECUTION-BOARD.md` TRJ4-012/013/014 - Kani harnesses on attest-verify / anchor / weights - are all open.

### 1f. RELEASE_AUDIT framing hides this behind "bounded" language

`docs/release/RELEASE_AUDIT.md` lines 60-73 list as "not qualified by the formal lane" the following: "first-principles theorem-prover completion for concrete crypto, OS, storage, transport, subprocess, hosted-registry, chain, or settlement implementations" and "broad Lean 4 verification claims beyond the implementation-linked proof manifest, theorem inventory, assumption registry, and claim registry." Translation: every concrete property that a real auditor would care about is explicitly out of scope. The "Decision: Local go, external release hold" (line 95-96) is then a green light for the bounded surface, with the formal gap quietly demoted to a non-blocker.

## 2. The credibility math - what auditor signs off on this?

Chio claims (per `README.md`, `spec/PROTOCOL.md`, `docs/release/CHIO_WEB3_PARTNER_PROOF.md`, M07 provider-native evidence in root `RELEASE_AUDIT.md`): regulatory-aligned governance, portable trust, cross-org evidence, fail-closed denial, signed receipts. Pair those with: 31% kill rate, 21/21 `caught:0` files, four open TLA+ bugs, 71/75 theorems with no `status`, a Lean-toolchain disclaimer admitting nothing is type-checked, zero Kani on three deferred crates, 819 cargo-vet exemptions.

**No HIPAA-aligned auditor, no SOC2 Type 2 reviewer, no AI-lab eval-pack consumer signs off on a "verifier" with these numbers.** `compliance/hitrust/` exists; the mutation evidence to back a HITRUST claim does not. The slogan that distinguishes Chio from a regular policy-engine SDK is the proof artifact - and the proof artifact is where the gap is widest.

## 3. The release work quality lane - what to ship

I propose six concrete deliverables. Each is measurable, each has an existing failing/empty artifact today, each can be backed by a numerical close-bar.

### Q-1. Per-crate mutation budgets, two consecutive green nightlies

Targets: `chio-policy`, `chio-credentials`, `chio-kernel-core`, `chio-guards`, `chio-anchor` >= 70%; `chio-attest-verify` >= 80% with `# unreachable:` annotations on residuals. Per-crate numbers published in `releases.toml [per_crate_kill_rate_percent]` (today: six "pending..." strings). Two `status_at_capture: success` nightly runs, JSON artifacts under `audits/evidence/mutants/<crate>/<date>.json`.

### Q-2. Real Kani harnesses on attest-verify / anchor / weights

Three new `kani_harnesses.rs` files (today: zero), each with >= 4 `#[kani::proof]` functions covering signature-verification soundness, batch-root inclusion, weights-card hash binding. Pass in `nightly.yml`. Closes CLOSE-BAR-#3.

### Q-3. Real cargo-mutants evidence under `audits/evidence/threats/`

Twenty-one files, each with `caught >= 1`, `needs_real_run: false`, real ISO-8601 `ran_at`, residual `survivors` justified. Promote `check-threat-coverage-mutants.sh` from advisory to required. Closes CLOSE-BAR-#8 honestly.

### Q-4. Hardened threat-row test bodies on the 9 weak rows

Replace `assert_threat_covered_by_corpus` and `assert_file_contains` with concrete failure-path bodies on the model of `cumulative_data_exfiltration.rs`. Each must (a) build a minimum verifier/guard fixture, (b) feed an attack input from `crates/chio-adversarial-suite/cases/`, (c) assert `Verdict::Deny`. Targets: `native_channel_replay`, `kernel_impersonation`, `tool_server_escape`, `pq_signature_downgrade`, `tee_quote_forgery`, `mobile_attestation_replay`, `device_key_extraction`, `play_integrity_token_replay`, `passkey_credential_theft`.

### Q-5. TLA+ rewrites (TRJ4-015..018)

`RevocationCutCompleteness` with bounded transitive-closure unrolling at depth >= 3; `Allow` split into `LogReceipt` + `PublishAllow` so `ReceiptBeforeAllow` is non-tautological; `EpochMax` raised to 6; `RevocationEventuallySeen` working under apalache 0.50.x; `apalache-temporal.yml` promoted from advisory to required.

### Q-6. RELEASE_AUDIT honesty pass

Replace the "Bounded Chio Ship Addendum" framing (`docs/release/RELEASE_AUDIT.md` lines 32-92) with a single matrix: claim, mutation kill, Kani harness, TLA+ status, threat-row state. No more "compatibility-only" demoted boxes hiding gaps. Add a `verification_floor` table to `releases.toml`. The `Decision: Local go` line stays only if every cell reads green.

## 4. Counter to anticipated rebuttals

### (a) "Quality is unshippable - give me features"

Wrong frame. A guard SDK, a kernel decomposition, a chiodome vision, a productization push - none differentiate Chio from the other policy-engines in the agent space. **The only thing Chio uniquely sells is the proof artifact** - the receipt an auditor can re-verify, the threat row with a real failure-path test, the Lean theorem that pins a property. Every Chio doc - `spec/PROTOCOL.md`, `docs/reference/CLAIM_REGISTRY.md`, `formal/MAPPING.md`, the `chio.attestation.v1` profile - points at this. Ship features over a 31% / 21-placeholder substrate and the differentiator vanishes. Without verified outcomes, we lose to a five-line LLM chain.

### (b) "Trj4 wave 0/4 already cover this"

Two problems. (1) Wave 0 (E0.4 mutants gate) and Wave 4 (test quality) are one wave each of a 16-wave plan. By the 8-of-30 close-bar DONE rate, Wave 4 will land alongside Waves 5-7 (anchor witness, federation hybrid, T1.5 SRE) - and those are themselves load-bearing for assurance claims. Treating mutation kill as one wave inside a closeout is exactly what produced the trj4 erratum: structural framing got prioritized, runtime wiring got deferred. (2) Scope. Wave 4's E0.4 ticket is "land the per-row cargo-mutants evidence gate" - a CI plumbing task. It does not by itself drive any of the 21 `caught:0` placeholders to `caught >= 1`, does not deliver Kani harnesses on attest-verify/anchor/weights, does not rewrite the four TLA+ properties, does not raise per-crate kill rates. The wave plan should be **subsumed** into release work-quality, not deferred under a release work product lane.

### (c) "Bronze conformance tier is enough for v1"

`audits/T2.1-hybrid-pq-cross-surface.md` defines Bronze as ">= 8000 bps threat / >= 5000 bps mutation / Kani on >= 2 crates"; Silver as ">= 9000 / 6500 / 4". We are at 31% mutation (3100 bps) on a 20/0/0 threat that is 9/20 weak (effective 5500 bps). We are not yet at Bronze. Selling Bronze before Bronze is reachable is the same failure mode.

## 5. Concession - what is genuinely nice-to-have

Not every assurance row is ship-blocking for release work:

- **Lean toolchain proven in CI** is nice-to-have; four-line `rfl` theorems against the model do not change the credibility math. Aeneas-equivalence refinement is correctly out of scope for one trajectory.
- **Apalache liveness at PROCS=6, CAPS=16** (nightly) is nice-to-have if the PR-tier safety lane goes green at PROCS=4, CAPS=8.
- **Symbolic-crypto theorems** (7 rows) can stay `assumed` if mutation kill on `chio-credentials` / `chio-attest-verify` clears the >= 70% / >= 80% bar.
- **Kani harnesses on every trust-boundary crate** are nice-to-have. Three (attest-verify, anchor, weights) plus existing kernel-core is defensible.
- **Reproducible-build to TEE-measurement binding** (CLOSE-BAR H-10) is a Wave 11 hardware lane; not blocking.

What is NOT a concession: the 21 `caught:0` files, tautological Lean theorems labelled `proven`, the apalache-temporal lane being advisory, the 31% README banner, or the `RELEASE_AUDIT.md` framing that demotes the formal gap.

---

**Bottom line**: Chio's slogans require a real assurance floor. The current floor is a placeholder. Trj5 is the trajectory that turns the placeholder into the substance, and only when that substance is in does any other lane (decomposition, products, vision) get to claim "auditable outcomes" on the same surface.
