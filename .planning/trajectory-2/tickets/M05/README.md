# M05: Adversarial Receipts + Guard Escape + Threat-Model-as-Code

**Wave:** W2  |  **Trust-boundary:** yes  |  **Tickets:** 26  |  **Effort:** 32.75 days

## In one paragraph

M05 ships `chio-adversarial-suite` (eight attack classes, 40+ deny-asserted vectors), a WASM guard escape libFuzzer harness covering eight escape classes, hardens `expected_identity` into a per-tenant signed `TenantPolicy`, and turns `chio-threat-model.v1.json` into CI-load-bearing code via a `threat-model-coverage` gate that fails build on uncovered threat IDs. M02 mutants test against the corpus; M08 arena auto-promotes findings into it.

## Phases at a glance

| Phase | Tickets | One-liner |
|---|---|---|
| P0 | 1 | Pin `toml` direct dep on chio-attest-verify and `arbitrary` on chio-wasm-guards tests |
| P1 | 6 | Genesis `chio-adversarial-suite` crate + ship 40 vectors across 8 attack classes |
| P2 | 4 | Cross-promotion: `--mode adversarial` promoter, corpus_metadata.toml, manifest stub for M02 |
| P3 | 5 | WASM guard escape harness + 8 escape-class fixtures + frozen config snapshot |
| P4 | 4 | `TenantPolicy` schema + signed loader + `expected_for_tenant` migration |
| P5 | 6 | threat-model schema + codegen stubs + 6 initial test bodies + coverage gate |

## Load-bearing artifacts

- `crates/chio-adversarial-suite/cases/<class>/<sha>.json` (M05.P1.T1 ships layout)
- `crates/chio-adversarial-suite/manifest.json` (M05.P2.T4; consumed by M02)
- `fuzz/fuzz_targets/wasm_guard_escape.rs` (M05.P3.T1)
- `crates/chio-wasm-guards/tests/escape/config.frozen.toml` (M05.P3.T5)
- `crates/chio-attest-verify/src/policy.rs` `TenantPolicy` (M05.P4.T1)
- `spec/security/chio-threat-model.schema.json` (M05.P5.T1)
- `crates/chio-conformance/tests/threats/<id>.rs` codegen stubs (M05.P5.T2)
- `threat-model-coverage` CI gate (M05.P5.T4)

## Cross-trajectory deps

- trajectory-1 M02 fuzz infra (`scripts/promote_fuzz_seed.sh`) - extended additively in M05.P2.T1
- trajectory-1 M06 `chio-attest-verify` Sigstore SSOT - hardened in M05.P4 (no new sigstore imports outside the crate)
- trajectory-1 M03 capability algebra - oracle for P1.T3 vectors via `// algebra-oracle:` comments
- trajectory-2 M02 verdict-matrix - consumes `manifest.json` (soft_dep)
- trajectory-2 M03, M10 - producers append threat rows in their P0 wave-openers; M05 owns the gate
- trajectory-2 M08 arena - auto-promotes adversarial scenarios via `--mode adversarial` (soft_dep)

## Locked decisions

- D13 Adversarial vectors are JSON at `crates/chio-adversarial-suite/cases/<class>/<sha>.json` with `{class, expected_verdict, expected_reason}` envelope
- D14 Auto-promoted vectors land with `pending: true`; threat-model coverage gate treats pending as not-yet-covered until manual triage

## Active freezes

- `m05-adversarial-corpus-pivot` (`crates/chio-adversarial-suite/**`, `fuzz/fuzz_targets/wasm_guard_escape.rs`, `crates/chio-wasm-guards/tests/escape/**`, `crates/chio-attest-verify/src/policy.rs`, `spec/security/chio-threat-model.v1.json`, `crates/chio-conformance/tests/threats/**`): opens at M05.P1.T1, closes at M05.P5.T6

## When this milestone is done

- `crates/chio-adversarial-suite/cases/` ships >= 40 vectors across 8 attack classes; `cargo test -p chio-kernel-core --test adversarial_suite` and `cargo test -p chio-attest-verify --test adversarial_suite` green and required-on-PR.
- `fuzz/fuzz_targets/wasm_guard_escape.rs` runs in the M02 fuzz matrix; `cargo test -p chio-wasm-guards --test escape` aggregates 8 classes that all yield typed `GuardError`.
- Every workspace `ExpectedIdentity` call site migrated to `verifier.expected_for_tenant(_)`; migration audit at `docs/security/expected-identity-migration.md`.
- `threat-model-coverage` gate green and required-on-PR; six initial threat IDs have populated test bodies and `coveredBy` cross-links.
- `docs/security/threat-coverage.md` regenerated on every relevant PR.
- Cross-promotion plumbing green; `manifest.json` consumable by trajectory-2 M02 verdict-matrix.
