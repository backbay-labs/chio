# M05 P0/P1/P2 Sweep Fix List

| Source | Severity | File path | Intended fix | Gate command |
|--------|----------|-----------|--------------|--------------|
| PR #364 comment `3170863106` | P2 | `crates/chio-kernel-core/tests/adversarial_suite.rs` | Already addressed in `82638f1c9`: filter to M05 kernel classes before converting to coverage cases. | `cargo test -p chio-kernel-core --test adversarial_suite` |
| PR #364 comments `3169733514`, `3169733525`, `3170857993`, `3170863110` | P1/P2 | `.planning/trajectory-2/EXECUTION-STATE.json`, `.planning/trajectory-2/tickets/manifest.yml` | Carried forward to `.planning/trajectory/sweep/M05-FOLLOWUPS.md` under LEDGER-R ownership because sweep instructions prohibit editing these files. | `test -f .planning/trajectory/sweep/M05-FOLLOWUPS.md` |
| PR #399 comment `3171412014` | P2 | `crates/chio-wasm-guards/tests/escape/common.rs` | Assert frozen `max_module_size` against the live Wasmtime backend default constant. | `cargo test -p chio-wasm-guards --test escape` |
| PR #399 comment `3171414308` | P2 | `infra/oss-fuzz/build.sh` | Add `wasm_guard_escape` to the OSS-Fuzz target list to match ClusterFuzzLite. | `bash -n infra/oss-fuzz/build.sh .clusterfuzzlite/build.sh` |
| PR #402 comment `3171594497` | P1 | `crates/chio-attest-verify/src/policy.rs` | Encode tenant-policy signing bytes through RFC 8785 canonical JSON. | `cargo test -p chio-attest-verify --test policy_schema` |
| PR #402 comments `3171594499`, `3171599421` | P2 | `crates/chio-attest-verify/src/policy.rs` | Reject impossible calendar dates while preserving leap-day support. | `cargo test -p chio-attest-verify --test policy_schema` |
| PR #402 comment `3171633743` | P2 | `crates/chio-attest-verify/src/lib.rs` | Compose multi-regex policy identities and reject multiple OIDC issuers fail-closed. | `cargo test -p chio-attest-verify --test tenant_policy_resolver` |
| PR #406 comment `3171685812` | P2 | `crates/chio-spec-codegen/src/threat_coverage_doc.rs` | Fail closed on unknown `coverage_state` values instead of treating them as covered. | `cargo test -p chio-spec-codegen threat_coverage_doc` |
| PR #406 comment `3171685814` | P2 | `crates/chio-spec-codegen/src/threat_model.rs` | Detect live `unimplemented!` calls only, not mentions in comments. | `cargo test -p chio-spec-codegen threat_model` |
| PR #406 comment `3171880408` | P1 | `spec/security/chio-threat-model.schema.json` | Allow legacy `covered_by_tests` arrays used by existing v1 threat rows. | `cargo test -p chio-spec-codegen --test threat_model_schema_test` |
| `.planning/audits/M05-adversarial-escape-threat-model.md` phase handoffs | P2 | `.planning/trajectory/sweep/M05-FOLLOWUPS.md` | Record current closure against shipped P1/P2/P5 gates. | `test -f .planning/trajectory/sweep/M05-FOLLOWUPS.md` |
| `.planning/audits/M05-async-kernel.md` cargo-mutants baseline | P2 | `.planning/trajectory/sweep/M05-FOLLOWUPS.md` | Carry forward the CI-only mutants baseline refresh while local source gates are used as the merge signal. | `test -f .planning/trajectory/sweep/M05-FOLLOWUPS.md` |
