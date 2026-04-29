# Milestone 05: Adversarial Receipts + Guard Escape + Threat-Model-as-Code

## Lens

Single lens: adversarial quality. Trajectory-1's libFuzzer baseline (M02) hardened the byte-decoder boundary. Trajectory-1's capability-algebra properties (M03) hardened the logical-identity layer. Between those two layers sits the *semantically valid attack* band: receipts that decode cleanly, inputs that satisfy the type system, modules that pass the manifest verifier, but that nonetheless represent a hostile state. M05 attacks that band with three interlocking corpora and a load-bearing threat-model registry.

The lens is deliberately narrow. M05 does not invent new fuzz mutators (that is M02 in both trajectories). It does not extend Kani harnesses (that is trajectory-1 M03). It does not redesign the Sigstore single-source-of-truth (that is trajectory-1 M06). It curates the *answer key* that the rest of the suite is missing: a registry of attacks each labelled with its expected verdict, expected reason, and threat-model ID, plus a CI gate that fails closed when any threat is uncovered.

## Why this is on the trajectory

Trajectory-1 closed the structural surfaces. M02 (`fuzz/fuzz_targets/`) is at twenty libFuzzer targets and a ClusterFuzzLite + cargo-mutants lane. M06 (`crates/chio-attest-verify/`) shipped cosign bundle verification, with the single-source-of-truth invariant enforced at module level (`crate::sigstore::SigstoreVerifier`). M03 (capability algebra) shipped the property suite under `formal/diff-tests/`. M10 (TEE corpus) shipped hash-pinned attest samples.

What none of those crates currently produce is a *curated adversarial answer key*. The libFuzzer corpora at `fuzz/corpus/` are coverage artifacts; they are not annotated with `expected_verdict` and are not consumed by the cross-SDK matrix as a verdict oracle. The `expected_identity` matching surface in `crates/chio-attest-verify/src/lib.rs:48` is a single per-call regex with no per-tenant policy file, so an operator who uses the verifier across multiple tenants has to splice regexes inline in calling code and there is no signed audit trail of what was expected. And `spec/security/chio-threat-model.v1.json` exists (six threats, one transport-requirements block) but is not consumed by any test; threats are documentation rather than CI assertions.

M05 turns each of those gaps into a load-bearing artifact. The adversarial corpus becomes the verdict oracle that trajectory-2 M02's cross-SDK differential consumes. The escape harness becomes the regression net that trajectory-2 M07's new provider adapters and trajectory-2 M08's arena-promoted scenarios trip against. The threat-model registry becomes a CI gate that fails the build when a threat ID lacks a green test stub, which means that adding a threat to the JSON forces a corresponding test to land in the same PR.

## Prior-art reckoning

Trajectory-1 deliverables that overlap the M05 surface, with a precise statement of what is preserved versus what is added.

- **M02 (`02-fuzzing-post-pr13.md`).** Trajectory-1 owns *bit-flip mutation* of byte streams and the crash-to-issue plumbing. The twenty `fuzz/fuzz_targets/*.rs` files cover decoder boundaries: `a2a_envelope_decode.rs`, `acp_envelope_decode.rs`, `anchor_bundle_verify.rs`, `attest_verify.rs`, `canonical_json.rs`, `capability_receipt.rs`, `chio_yaml_parse.rs`, `did_resolve.rs`, `jwt_vc_verify.rs`, `manifest_roundtrip.rs`, `mcp_envelope_decode.rs`, `merkle_checkpoint.rs`, `oid4vp_presentation.rs`, `openapi_ingest.rs`, `policy_parse_compile.rs`, `receipt_log_replay.rs`, `sql_parser.rs`, `tool_action.rs`, `wasm_preinstantiate_validate.rs`, `wit_host_call_boundary.rs`. M05 does NOT add new mutation runs against those targets. M05 ADDS exactly one new target (`wasm_guard_escape.rs`) because no existing target hits the runtime-execution surface, and a curated semantic-attack corpus that is independent of fuzzer-discovered crashes. M05 ALSO adds a one-way promotion path (`scripts/promote_fuzz_seed.sh --mode adversarial`) so that any libFuzzer crash that decodes cleanly but fails on a logical assertion auto-promotes into the M05 corpus with a placeholder `expected_verdict: DENY` for human triage.
- **M06 (`crates/chio-attest-verify/`).** Trajectory-1 owns the *single-source-of-truth* sigstore invocation; the crate-level rustdoc forbids any other crate from calling `sigstore-rs` directly, and the lint surface (`#![forbid(clippy::unwrap_used)]`, `#![forbid(clippy::expect_used)]`, `#![forbid(unsafe_code)]`) makes the trust boundary structural rather than a review convention. M05 does NOT fork that invocation. M05 hardens the `ExpectedIdentity` surface: the per-call regex (`certificate_identity_regexp` field defined inside the `ExpectedIdentity` struct at `crates/chio-attest-verify/src/lib.rs:48`, with the field itself at `:51`) is augmented with a per-tenant policy file at `policies/attest/<tenant>.toml`, signed with the same Sigstore surface, version-stamped, and loaded once at startup rather than per call.
- **M03 (`03-capability-algebra-properties.md`).** Trajectory-1 owns *logical-identity proofs* on well-formed inputs. The proofs live under `formal/diff-tests/` and `crates/chio-policy/proptest-regressions/`. M05 ADDS adversarial vectors at the *boundaries* of those properties (e.g. a clock-rewound capability whose attenuation under M03's lemma should still deny; a delegation chain whose parent revocation propagates across the trajectory-2 M04 root). The vectors carry an `// algebra-oracle: <invariant_name>` header pointing back at the M03 invariant they exercise; mutation of an algebra invariant therefore breaks at least one M05 vector, closing a feedback loop M03 alone cannot close.
- **M10 (`10-tee-replay.md`).** Trajectory-1 owns the *pinning pattern* (TEE sample shaped artifacts, hash-locked). M05 reuses that pattern shape but ships its own corpus tree under `crates/chio-adversarial-suite/cases/`.
- **trajectory-2 M02 (mutation + cross-SDK verdict differential).** That milestone owns the cross-language verdict matrix. M05's adversarial vectors flow through the matrix as an oracle. The dependency runs in soft form: M02 must be merged before M05.P5 can declare full coverage, but earlier M05 phases proceed in parallel.
- **`spec/security/chio-threat-model.v1.json`.** The file exists today with six threat objects and a `boundary` block listing surfaces (`native_chio`, `hosted_mcp`, `trust_control`, `kernel_to_tool`) and assets (`capability_tokens`, `delegation_state`, `session_sender_binding`, `kernel_authenticity`, `tool_execution_confinement`, `receipts`, `runtime_availability`). M05 does NOT rewrite the file. M05 ADDS a JSON-schema validator, a codegen entrypoint, and a `coveredBy` cross-link from threat to test, turning the file from documentation into a CI input.

## Hard counts (measured 2026-04-29)

Reproduce with the commands in parentheses. Update the date and numbers if you re-run; do not silently let them drift.

- `fuzz/fuzz_targets/`: 20 libFuzzer targets (`ls fuzz/fuzz_targets/ | wc -l`). M05 adds exactly ONE: `wasm_guard_escape.rs`.
- `fuzz/corpus/`: 23 corpus directories (some legacy `fuzz_*` aliases retained from PR #13's pre-rename layout). M05 adds `wasm_guard_escape/`.
- `crates/chio-attest-verify/src/lib.rs`: `ExpectedIdentity` is one struct, two fields (`certificate_identity_regexp`, `certificate_oidc_issuer`), constructed inline at every call site. The struct definition begins at line 48 and the regex field is declared at line 51. Zero per-tenant policy infrastructure (`grep -rE 'ExpectedIdentity\s*\{' crates/`).
- `crates/chio-wasm-guards/src/`: 18 modules (`ls crates/chio-wasm-guards/src/*.rs | wc -l`): `abi.rs`, `blocklist.rs`, `bundle_store.rs`, `component.rs`, `config.rs`, `epoch.rs`, `error.rs`, `fuzz.rs`, `host.rs`, `hot_reload.rs`, `incident.rs`, `lib.rs`, `manifest.rs`, `metrics.rs`, `observability.rs`, `placeholders.rs`, `runtime.rs`, `wiring.rs`. The escape harness lives alongside `host.rs`, `wiring.rs`, `component.rs` but does not modify them; it only consumes their public APIs.
- `spec/security/chio-threat-model.v1.json`: 6 existing threat IDs (`capability_token_theft`, `kernel_impersonation`, `tool_server_escape`, `native_channel_replay`, `resource_exhaustion_dos`, `delegation_chain_abuse`), 0 currently linked to a passing test (`grep -rE 'capability_token_theft|kernel_impersonation' crates/ | grep -v target | wc -l` returns documentation hits only). The file's top-level keys are `schema` (`chio.threat-model.v1`), `updatedAt` (`2026-04-13`), `boundary` (focus + 4 surfaces + 7 assets), and `threats` (the six-element array). Each threat object today carries `id`, `name`, `surfaces`, `mitigations`, `residualRisk`. M05 adds an optional `coveredBy: [test_path]` field at P5.T6.
- `crates/chio-conformance/tests/`: 22 existing test files today, none under a `threats/` sub-directory (`ls crates/chio-conformance/tests/`). The closest neighbours are `vectors_oracle.rs`, `vectors_schema_pair.rs`, `wit_0_2_0_fixtures.rs`, plus the live cross-language matrices (`auth_*_live.rs`, `mcp_core_*_live.rs`, `nested_callbacks_*_live.rs`, `notifications_*_live.rs`, `tasks_*_live.rs`, `cpp_peer_p0.rs`, `native_suite.rs`). M05 creates `crates/chio-conformance/tests/threats/` and emits one stub file per threat ID into it.
- `crates/chio-spec-codegen/src/`: 2 files (`lib.rs`, `main.rs`). The threat-model codegen entrypoint reuses this crate's existing JSON-schema-to-Rust pipeline; M05 adds one input source and one generator function.
- `scripts/promote_fuzz_seed.sh`: exists (trajectory-1 M02.P4.T2). Currently supports `--mode {libfuzzer,proptest}`. M05 adds `--mode adversarial`.
- `crates/chio-adversarial-suite/`: does not exist. M05 creates it.

The nine numbers above are the measurable starting points. Re-run the commands and edit the file if any of them shift before P0 lands.

## Workspace dependency state

Pinned at `[workspace.dependencies]` today and reused by M05:

- `wasmtime` (already pinned for `chio-wasm-guards`); M05 reuses `Config::consume_fuel`, `Engine::default()`, and the existing `Linker::func_wrap` registrations rather than forking a runtime.
- `serde`, `serde_json` (already pinned); M05 corpus is JSON, decoded via the same canonical-JSON entrypoint M01 vectors use.
- `sigstore-rs` (only invoked through `chio-attest-verify`); M05's per-tenant policy signing reuses this surface.
- `jsonschema` (already pinned for spec validation); M05.P5.T1 reuses it to validate `chio-threat-model.v1.json` at codegen time and at CI gate time.
- `thiserror` (already pinned); M05's new error types in `chio-adversarial-suite` and the `TenantPolicy` loader reuse it for fail-closed deny reasons.

Not pinned anywhere; M05 adds them at P0:

- `toml = "0.8"` already present transitively; M05's policy files are TOML and require it as a direct dependency of `chio-attest-verify`.
- `arbitrary = "1"` (already pinned in `fuzz/Cargo.toml`); the WASM guard escape harness reuses it for structured input generation in `crates/chio-wasm-guards/tests/escape/` companion fixtures.

No new workspace-level pins beyond the TOML direct-dep promotion and the `arbitrary` reuse.

## Scope

In:

- `crates/chio-adversarial-suite/`: a new crate hosting curated *malicious-but-well-formed* receipts in JSON (forty initial vectors), each annotated with `{ class, expected_verdict: "DENY", expected_reason, threat_id }`. Eight attack classes ship across P1: clock-rewound, future-dated, replayed-nonce, partial-signature, scope-superset, revocation-rollback, anchor-grafted, sigstore-bundle-payload-mismatch.
- `fuzz/fuzz_targets/wasm_guard_escape.rs`: a single libFuzzer target that drives 8 named escape classes (undeclared host imports, oversized linear memory, fuel-budget exhaustion, table grow/abuse, stack overflow via deep recursion, host reentry, malformed component-model encoding, signed-but-malicious modules) through the existing `chio-wasm-guards` runtime. Every escape attempt yields a typed `GuardError`; never panics; never escapes linear memory; never exceeds declared imports.
- `crates/chio-wasm-guards/tests/escape/`: hand-curated companion fixtures for the same escape classes, structured so the escape proof is reproducible without the fuzzer.
- `crates/chio-attest-verify/`: `expected_identity` per-tenant policy file loader, signed at the same Sigstore surface, replacing inline regex composition at call sites.
- `spec/security/chio-threat-model.v1.json` becomes load-bearing: `chio-spec-codegen` generates one test stub per threat ID under `crates/chio-conformance/tests/threats/<id>.rs`. CI gate `threat-model-coverage` fails if any threat ID lacks a green test.
- `docs/security/threat-coverage.md`: generated coverage report cross-linking adversarial vectors and escape classes to threat IDs.
- Cross-promotion plumbing: `scripts/promote_fuzz_seed.sh --mode adversarial`; corpus minimization; metadata file `fuzz/corpus_metadata.toml` indexing every corpus seed by source (libFuzzer crash, hand-curated, M03 counterexample, trajectory-2 M02 verdict-matrix divergence).

Out:

- New libFuzzer mutation runs. trajectory-2 M02 owns mutation; M05 only adds *one* new fuzz target (wasm guard escape) because no existing target hits that surface.
- `dudect` timing-leak harness expansions. Side-channel work is out of scope for M05; trajectory-1 M02 P3 owns that surface.
- `miri` or `shuttle` runs. Concurrency-correctness harnesses for the kernel are owned by trajectory-1 M05 (loom). M05 does not extend them.
- New Kani harnesses. Trajectory-1 M03 owns bounded-input identity proofs; M05 cites them, does not widen them.
- Replacing `chio-policy` evaluator semantics. M05 adversarial vectors test deny paths against the existing evaluator.
- New cosign bundle verification primitives. M06 (trajectory-1) is the single source of truth. M05 only hardens the *expected-identity* policy file surface above it.
- Threat-model schema evolution beyond `coveredBy`. The existing `mitigations[].status` enum and `surfaces` taxonomy stay frozen for trajectory-2; new mitigations are recorded as additional array entries, not as schema changes.

## Phases

Six phases total. P0 is the wave-opener pin bump; P1 ships the adversarial corpus crate; P2 plumbs cross-promotion; P3 adds the WASM escape harness; P4 hardens the per-tenant policy surface; P5 closes the threat-model gate.

### P0: Wave-opener `Cargo.lock` bump (S, 0.5 days, 1 ticket)

- M05.P0.T1 - Pin `toml` as a direct dep of `chio-attest-verify` and `arbitrary` as a direct dep of `chio-wasm-guards/tests`; update `Cargo.lock`.

### P1: `chio-adversarial-suite` crate genesis (M, 6 days, 6 tickets)

- M05.P1.T1 - Genesis `chio-adversarial-suite` crate with case schema and cases directory layout (`Cargo.toml`, `src/lib.rs`, `cases/` skeleton).
- M05.P1.T2 - Ship clock-rewound, future-dated, and replayed-nonce adversarial classes (15 vectors); expected-deny assertions wired through the existing kernel-core test harness.
- M05.P1.T3 - Ship partial-signature, scope-superset, and revocation-rollback adversarial classes (15 vectors); cross-link to M03 algebra invariants via `// algebra-oracle: <invariant>` comment headers.
- M05.P1.T4 - Ship anchor-grafted and sigstore-bundle-payload-mismatch adversarial classes (10 vectors); cross-link to `chio-attest-verify`.
- M05.P1.T5 - Wire the suite into `chio-kernel-core` test runs (`cargo test -p chio-kernel-core --test adversarial_suite`).
- M05.P1.T6 - Wire the suite into `chio-attest-verify` test runs (`cargo test -p chio-attest-verify --test adversarial_suite`).

### P2: Cross-promotion plumbing (S, 3 days, 4 tickets)

- M05.P2.T1 - Add `--mode adversarial` to `scripts/promote_fuzz_seed.sh` with pending-flag triage gate; survives a libFuzzer crash that decodes cleanly into `crates/chio-adversarial-suite/cases/<class>/<sha>.json` with `expected_verdict: "DENY"` placeholder for triage.
- M05.P2.T2 - Add `fuzz/corpus_metadata.toml` indexing every corpus seed by `{ source, class, threat_id }`.
- M05.P2.T3 - Corpus minimization sweep: run `cargo fuzz cmin` on each adversarial-promoted corpus and record the minimization report in `docs/security/corpus-minimization.md`.
- M05.P2.T4 - Cross-SDK consumption stub: emit a manifest `crates/chio-adversarial-suite/manifest.json` that trajectory-2 M02's verdict matrix consumes. The stub ships even though the matrix runner lands in M02; M05 owns the producer side.

### P3: WASM guard escape harness (M, 6 days, 5 tickets)

- M05.P3.T1 - Create `fuzz/fuzz_targets/wasm_guard_escape.rs` and the `fuzz/corpus/wasm_guard_escape/` seed directory (8 hand-curated seeds drawn from the eight escape classes below).
- M05.P3.T2 - First batch of escape classes: undeclared host imports, oversized linear memory, fuel-budget exhaustion mid-call. Companion fixtures at `crates/chio-wasm-guards/tests/escape/{undeclared_imports,oversize_memory,fuel_exhaustion}.rs`.
- M05.P3.T3 - Second batch: table grow/abuse, stack overflow via deep recursion, host reentry. Companion fixtures.
- M05.P3.T4 - Third batch: malformed component-model encoding; signed-but-malicious modules sourced from `chio-guard-registry` cosign-verified fixtures. Companion fixtures.
- M05.P3.T5 - Determinism gate: every escape attempt yields a typed `GuardError`; assert via a `cargo test -p chio-wasm-guards --test escape` harness that aggregates all classes.

### P4: `expected_identity` policy hardening (M, 4 days, 4 tickets)

- M05.P4.T1 - Define the per-tenant policy schema at `crates/chio-attest-verify/src/policy.rs`: `TenantPolicy { tenant_id, version, identity_regexps, oidc_issuers, signed_at, signature, pq_identity_regexps }`. TOML on disk; canonical JSON for signing. Reserved `pq_identity_regexps` field is empty until trajectory-2 M03 lands ML-DSA cert identities.
- M05.P4.T2 - Implement the policy loader: load-once at startup, signed with the same `SigstoreVerifier` surface, fail-closed on missing or stale signatures, 90-day staleness horizon by default.
- M05.P4.T3 - Replace inline `ExpectedIdentity { certificate_identity_regexp: ... }` construction at every call site in the workspace with `verifier.expected_for_tenant(tenant_id)`. The inline regex API stays available for tests but is gated behind a `#[doc(hidden)]` constructor.
- M05.P4.T4 - Migration audit doc: `docs/security/expected-identity-migration.md` lists every call site, before-and-after, and the per-tenant policy file shipped for each.

### P5: Threat-model-as-code (M, 6 days, 6 tickets)

- M05.P5.T1 - Author `spec/security/chio-threat-model.schema.json` validating the existing `chio-threat-model.v1.json`. Schema asserts the four top-level keys, the `boundary.surfaces` enum, the `boundary.assets` enum, and the per-threat object shape (id, name, surfaces, mitigations, residualRisk, optional coveredBy).
- M05.P5.T2 - Extend `chio-spec-codegen` with a `--threat-model` flag; emits one stub test per threat ID into `crates/chio-conformance/tests/threats/<id>.rs`.
- M05.P5.T3 - Implement the six initial test bodies, one per threat ID. Each test asserts that the relevant adversarial vector or escape class denies in the expected way and cites the threat ID in a comment header.
- M05.P5.T4 - CI gate `threat-model-coverage`: fails the build if any threat ID lacks a green test (i.e. the codegen stub still has `unimplemented!()`).
- M05.P5.T5 - Generate `docs/security/threat-coverage.md` linking each threat ID to its corpus entries and escape-class test names.
- M05.P5.T6 - Cross-link adversarial vectors and escape classes back into the threat-model JSON via a `coveredBy` field; add a CI assertion that every adversarial vector with `pending: false` (i.e. human-triaged per D14) cites at least one threat ID. Vectors with `pending: true` are excepted from the citation gate but blocked from declaring trajectory close until triage strips the flag.

## Cross-milestone interactions

The dependencies below are split into trajectory-1 (already shipped, treated as fixed surface) and trajectory-2 (sibling milestones in flight, treated as soft dependencies).

### Trajectory-1 dependencies (shipped; treated as fixed surface)

- **trajectory-1 M02 P4.T2** (`scripts/promote_fuzz_seed.sh` skeleton) is the file M05.P2.T1 extends. The script must remain backward-compatible with `--mode {libfuzzer,proptest}`; the new `adversarial` mode is additive. The corpus directories under `fuzz/corpus/` (23 today) are the destination for the new metadata file at `fuzz/corpus_metadata.toml`.
- **trajectory-1 M06 P3** (`crates/chio-attest-verify/` Sigstore single source of truth) is the surface M05.P4 builds on. M05 must NOT introduce any direct `sigstore::` import outside `chio-attest-verify`. The `#![forbid(...)]` lint set (`unsafe_code`, `clippy::unwrap_used`, `clippy::expect_used`) at the top of the crate's `lib.rs` is preserved verbatim by M05's additions; the new `policy.rs` module inherits the same forbid set.
- **trajectory-1 M03** (capability algebra properties) is the algebra oracle. M05.P1.T3 vectors carry an `// algebra-oracle: <invariant_name>` comment per the M02 vs M03 oracle ownership table. The proof artifacts under `formal/diff-tests/` are not re-run by M05; they are cited.
- **trajectory-1 M01** (canonical JSON vectors) is the canonical-JSON oracle. Adversarial vectors are themselves canonical JSON and are validated against the M01 schema before they are loaded.
- **trajectory-1 M10** (TEE replay) is the prior art for hash-pinned corpora. M05 reuses the pinning shape but ships its corpus tree under `crates/chio-adversarial-suite/cases/`; there is no shared file between the two corpora.

### Trajectory-2 sibling dependencies

- **trajectory-2 M02** (mutation gate + cross-SDK verdict differential) consumes `crates/chio-adversarial-suite/manifest.json` as one of the cross-language oracles. M05.P2.T4 ships the producer; the consumer ships in M02. Order: M05.P2.T4 must merge before M02 wires the matrix runner, or M02 will fail with a missing-input error rather than a missing-coverage error.
- **trajectory-2 M03** (PQ + TEE quote verifier) shares the verifier surface that M05.P4 hardens. The per-tenant policy file format at P4.T1 must accommodate ML-DSA cert identities once M03 lands; the schema reserves a `pq_identity_regexps` field for forward compatibility. Order: M05.P4 lands first; M03 fills in the reserved field once the ML-DSA certificate format stabilises.
- **trajectory-2 M04** (recursive delegation + revocation oracle) is cited by the `revocation-rollback` adversarial class (P1.T3) and by the `delegation_chain_abuse` threat ID (P5.T3). The vectors do NOT depend on M04 landing first; they ride on the trajectory-1 revocation surface and add additional vectors when M04's sparse-Merkle root is available.
- **trajectory-2 M08** (chio-arena replay coliseum) auto-promotes adversarial scenarios discovered by simulated agents back into the M05 corpus. M05.P2.T1's `--mode adversarial` promoter is the entry point; M08 invokes it as a post-tournament step. This makes M05 the regression net for arena divergence findings.

## Risks and mitigations

Seven concrete risks; each has a named mitigation that is owned by an explicit ticket or file.

- **Adversarial corpus rot.** Vectors that pass today may stop catching the bug class they were written for if the kernel evaluator tightens its deny path elsewhere. Mitigation: every vector carries an `expected_reason` string that the test harness asserts on; if the deny reason changes, the test fails loudly rather than silently passing. Owner: M05.P1.T2 case schema and M05.P1.T5 / P1.T6 wiring.
- **Escape harness false negatives from runtime config drift.** wasmtime fuel and memory limits are configured in `chio-wasm-guards`; if those limits widen, escape vectors that previously denied may start succeeding for legitimate reasons. Mitigation: every escape companion fixture in `tests/escape/` asserts against a *frozen* config snapshot loaded from `crates/chio-wasm-guards/tests/escape/config.frozen.toml`; any change to that file requires a CODEOWNERS review. Owner: M05.P3.T5 determinism gate.
- **Threat-model coverage gate spam.** A poorly written threat description forces a contrived test. Mitigation: the codegen stub at P5.T2 is `unimplemented!()` until P5.T3 fills it; the CI gate fires only when a threat ID exists with no test mapping at all, not on every churn. Owner: M05.P5.T4 CI gate.
- **Per-tenant policy file drift.** Operators with many tenants may forget to rotate signed policies. Mitigation: P4.T2 loader fails closed on `signed_at` older than a configurable horizon (default 90 days); rotation is a ops procedure, not a code path. Owner: M05.P4.T2 loader.
- **Cross-promotion noise.** A libFuzzer crash that happens to decode cleanly is not necessarily a useful adversarial vector; promoting it without triage pollutes the corpus. Mitigation: P2.T1 adds a `pending: true` flag to auto-promoted vectors; the threat-coverage gate treats `pending` vectors as not-yet-covered until a human strips the flag. Owner: M05.P2.T1 promoter and M05.P5.T4 gate, jointly.
- **WASM escape harness host-call drift.** trajectory-1 M06 (`bindgen!` async host wiring) may shift host call signatures. Mitigation: the escape harness at P3.T1 imports through the public `chio-wasm-guards` re-exports; the harness fails to compile rather than silently drift if a host signature moves. Owner: M05.P3.T1 harness genesis.
- **Sigstore policy signing recursion.** Per-tenant policy files are signed with the same Sigstore surface those policies authorize. Bootstrapping the first policy is a chicken-and-egg problem. Mitigation: P4.T2 ships a static `bootstrap` policy that is signed by the workspace release identity (the same identity M06 uses for binary releases); operators inherit the bootstrap and override per tenant. Owner: M05.P4.T2 loader, with the bootstrap policy file hash recorded in the M05 audit doc.

## Success criteria

Each criterion is a measurable artifact whose presence and green status indicates M05 is complete. Order matches the phases.

- **Adversarial corpus shipped.** `crates/chio-adversarial-suite/cases/` ships at least 40 vectors across the eight attack classes named in P1 (clock-rewound, future-dated, replayed-nonce, partial-signature, scope-superset, revocation-rollback, anchor-grafted, sigstore-bundle-payload-mismatch). Every vector deny-asserted by `chio-kernel-core` and `chio-attest-verify` test runs. `cargo test -p chio-kernel-core --test adversarial_suite` and `cargo test -p chio-attest-verify --test adversarial_suite` are both green and required-on-PR.
- **WASM guard escape harness shipped.** `fuzz/fuzz_targets/wasm_guard_escape.rs` exists, runs in the trajectory-2 M02 ClusterFuzzLite matrix, and the corresponding `crates/chio-wasm-guards/tests/escape/` harness covers the 8 named escape classes enumerated in P3.T2-T4 (undeclared imports, oversize memory, fuel exhaustion, table grow, deep recursion, host reentry, malformed component-model, signed-but-malicious) that all yield a typed `GuardError`. `cargo test -p chio-wasm-guards --test escape` is green; the frozen config snapshot at `crates/chio-wasm-guards/tests/escape/config.frozen.toml` is checked in. The aggregate test (P3.T5) prints `class_count = 8` and the M05 audit doc pins the count at milestone close.
- **Per-tenant policy surface migrated.** `crates/chio-attest-verify/src/policy.rs` ships; every workspace call site of `ExpectedIdentity` is migrated to `verifier.expected_for_tenant(_)`. The migration audit doc at `docs/security/expected-identity-migration.md` enumerates every call site with before-and-after.
- **Threat-model gate green.** `chio-spec-codegen` emits one test per threat ID under `crates/chio-conformance/tests/threats/`; the `threat-model-coverage` CI gate is green and required-on-PR. All six initial threat IDs (`capability_token_theft`, `kernel_impersonation`, `tool_server_escape`, `native_channel_replay`, `resource_exhaustion_dos`, `delegation_chain_abuse`) have populated test bodies and `coveredBy` cross-links in the JSON.
- **Coverage report generated.** `docs/security/threat-coverage.md` is generated and links every threat ID to its corpus entries and escape-class test names. The report is regenerated on every PR that touches the threat model or the corpus.
- **Cross-promotion plumbing green.** `scripts/promote_fuzz_seed.sh --mode adversarial` round-trips a synthetic crash into `crates/chio-adversarial-suite/cases/<class>/<sha>.json` with `pending: true`, and the `threat-model-coverage` gate treats it as not-yet-covered until the flag is stripped. `fuzz/corpus_metadata.toml` indexes every corpus seed by source, class, and threat ID.
- **Workspace-wide build and lint green.** `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, and `cargo fmt --all -- --check` are green at every phase boundary.
- **Manifest producer ready for trajectory-2 M02.** `crates/chio-adversarial-suite/manifest.json` exists with the agreed schema; trajectory-2 M02's verdict-matrix runner can consume it without further changes to M05 code.
