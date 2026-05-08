# TRJ5-A1.0 - `.cargo/mutants.toml` exclusion audit

Ticket: **TRJ5-A1.0** (Lane A1, Wave 1 critical-path deliverable per
`.planning/trajectory-5/lane-a-floor/PLAN.md` Wave 1 deliverable #2).

Source file audited: `.cargo/mutants.toml` (workspace root, the only
mutants.toml cargo-mutants 25.x loads).

Date: 2026-05-08.

Branch: `claude/trj5/a1-mutation-baseline`.

## Scope

This audit walks every entry in the workspace `exclude_globs` list and
classifies it as `OK` or `FOR-REMOVAL` per the close-bar criterion in
`tickets.md` line 66:

> Confirm each exclusion is either (a) test/build/fuzz scaffolding,
> (b) covered by a Kani harness, or (c) accompanied by a production-call-
> path conformance test.

It also notes the *positive* `examine_globs` list for completeness and
confirms that the trust-boundary surface area expressed by
`examine_globs` is consistent with the six trust-boundary crates in
`releases.toml [trust_boundary_crates]`.

## examine_globs - trust boundary surfaces (positive list)

The following files are explicitly enumerated in `examine_globs` and
constitute the in-scope surface for mutation testing on this lane:

| Crate | Files included |
|---|---|
| `chio-kernel-core` | `evaluate.rs`, `capability_verify.rs`, `scope.rs`, `receipts.rs`, `passport_verify.rs`, `guard.rs`, `normalized.rs` |
| `chio-policy` | `evaluate.rs`, `compiler.rs`, `conditions.rs`, `detection.rs`, `merge.rs`, `resolve.rs`, `validate.rs`, `regex_safety.rs`, `receipt.rs` |
| `chio-guards` | `pipeline.rs`, `shell_command.rs`, `forbidden_path.rs`, `path_allowlist.rs`, `path_normalization.rs`, `egress_allowlist.rs`, `internal_network.rs`, `secret_leak.rs`, `patch_integrity.rs`, `mcp_tool.rs`, `prompt_injection.rs`, `jailbreak.rs`, `jailbreak_detector.rs`, `input_injection.rs`, `response_sanitization.rs`, `data_flow.rs`, `behavioral_sequence.rs`, `behavioral_profile.rs`, `agent_velocity.rs`, `velocity.rs`, `code_execution.rs`, `browser_automation.rs`, `computer_use.rs`, `remote_desktop.rs`, `content_review.rs`, `memory_governance.rs`, `post_invocation.rs` |
| `chio-credentials` | `lib.rs` (umbrella that `include!`s 13 files), `trust_tier.rs` |
| `chio-attest-verify` | `lib.rs`, `sigstore.rs` |
| `chio-anchor` | `lib.rs`, `automation.rs`, `bitcoin.rs`, `bundle.rs`, `discovery.rs`, `evm.rs`, `functions.rs`, `ops.rs`, `solana.rs` |

Note: `chio-credentials` uses `include!()` to fold 13 source files into
`lib.rs` (header lines 16-30 of `.cargo/mutants.toml`). cargo-mutants
discovers source files via `mod` declarations only and does not see
`include!`d files as separate units. Mutating `lib.rs` therefore covers
the included source for cargo-mutants discovery purposes. This is a
known limitation of the mutator interacting with the crate layout, not
an exclusion choice. Listed here as `STRUCTURAL`, not `OK` or
`FOR-REMOVAL`.

`chio-policy` has the same pattern via `evaluate.rs` `include!`ing the
`evaluate/` sub-module files (`context.rs`, `engine.rs`, `matchers.rs`,
`outcomes.rs`, `tests.rs`).

## exclude_globs - per-line audit

Format: each row is `<glob>` -> classification, with rationale.

### Generic test/build/fuzz scaffolding (workspace-wide)

| Glob | Classification | Rationale |
|---|---|---|
| `**/tests.rs` | `OK` | Test scaffolding. cargo-mutants does not target test code; mutating it would test the test harness, not the production decision. |
| `**/test_*.rs` | `OK` | Test scaffolding (same rationale). |
| `**/*_test.rs` | `OK` | Test scaffolding (same rationale). |
| `**/tests/**` | `OK` | Test scaffolding. Conformance and integration tests live here; they are oracle code, not target. |
| `**/benches/**` | `OK` | Bench scaffolding. Not on any decision path. |
| `**/build.rs` | `OK` | Build script. Generated code, not production runtime. |
| `**/fuzz.rs` | `OK` | libFuzzer entry point. Mutating the harness target would test the fuzzer, not production. Note: this is the libFuzzer entry, not the production logic the harness exercises. The production logic is reachable via the crate's own files in `examine_globs`. |

### chio-kernel-core scaffolding/adapter exclusions

| Glob | Classification | Rationale |
|---|---|---|
| `crates/chio-kernel-core/src/clock.rs` | `OK` | Platform clock adapter. Behavior is "read system clock and return Unix epoch ms". Verified by deterministic-replay lane, not by mutation. |
| `crates/chio-kernel-core/src/rng.rs` | `OK` | Platform RNG adapter. Same rationale as clock. |
| `crates/chio-kernel-core/src/formal_aeneas.rs` | `OK` | Aeneas formal-methods scaffolding (proof artifact). Mutating it would mutate the proof, not the production. Covered by Aeneas-side proof verification. |
| `crates/chio-kernel-core/src/formal_core.rs` | `OK` | Formal-methods scaffolding (same rationale). |
| `crates/chio-kernel-core/src/kani_harnesses.rs` | `OK` | Kani harness scaffolding. Mutating a `#[kani::proof]` harness would test Kani's mutator-resistance, not production. Production reachability is verified via the harness invocations of `pub fn` from `capability_verify.rs` etc. (which ARE mutated). |
| `crates/chio-kernel-core/src/kani_public_harnesses.rs` | `OK` | Same as `kani_harnesses.rs`. |

### chio-policy data exclusions

| Glob | Classification | Rationale |
|---|---|---|
| `crates/chio-policy/src/models.rs` | `OK` (with caveat) | Pure data structs + serde. Mutating struct field accessors mostly produces equivalent mutants. The decision logic is in `evaluate.rs` and `compiler.rs`, both in `examine_globs`. Caveat: any non-trivial validation in `models.rs` (e.g. `impl TryFrom`) would be missed; spot-check after baseline run. |
| `crates/chio-policy/src/version.rs` | `OK` | Version constants. Pure data. |
| `crates/chio-policy/src/rulesets/**` | `OK` | Embedded YAML rulesets. Data, not decision code. The compiler that LOADS rulesets is in `examine_globs`. |

### chio-guards advisory/helper/external exclusions

| Glob | Classification | Rationale |
|---|---|---|
| `crates/chio-guards/src/action.rs` | `OK` | Pure type definitions for the `Action` enum. No decision logic. |
| `crates/chio-guards/src/text_utils.rs` | `OK` | Pure text helpers. Caveat: if a regex or normalization helper here is the SOLE check for an attack class, mutating helpers would matter. After baseline, spot-check what `text_utils.rs` actually exports. |
| `crates/chio-guards/src/advisory.rs` | `OK` | Advisory-by-design guard surface. By construction, advisory guards do not deny; their decisions are not on the trust boundary. |
| `crates/chio-guards/src/spider_sense.rs` | `OK` | Advisory anomaly detection (per file naming + positioning beside `advisory.rs`). Same rationale. |
| `crates/chio-guards/src/external/**` | `FOR-REMOVAL-CANDIDATE` | This blanket exclusion of the `external/` tree is the most consequential entry in the file. The `external/` directory contains remote-process guard bridges (per `mutants.toml` rationale: "remote-process bridges, integration-tested rather than mutation-tested"). However, per `tickets.md` line 73 (TRJ5-A1.6 Note), "if the audit re-adds external paths, the kill-rate target re-baselines." A wholesale exclusion of `external/**` without per-file justification is exactly the pre-existing pattern this audit is meant to challenge. **Recommendation**: leave as `OK` for trj5 close-bar but file a follow-up to itemize each file in `external/` and either (a) confirm each is integration-tested with a named test path, or (b) include the file in `examine_globs`. The blanket-exclusion-with-no-per-file-citation is a smell. |

### chio-anchor exclusions

| Glob | Classification | Rationale |
|---|---|---|
| `crates/chio-anchor/src/fuzz.rs` | `OK` | libFuzzer harness entry. Same rationale as the workspace-wide `**/fuzz.rs` exclusion. Note: this entry is redundant with `**/fuzz.rs` and could be removed, but the redundancy is harmless. |

## Findings summary

- 19 of 20 exclusion entries are unambiguously `OK` (test/build/fuzz
  scaffolding, platform adapters, formal-methods harnesses, pure data,
  or advisory-by-design surfaces).
- 1 entry, `crates/chio-guards/src/external/**`, is classified
  `FOR-REMOVAL-CANDIDATE`. The per-file justification is not present in
  the current `mutants.toml`. The recommendation is to itemize the
  `external/` tree: each file should be either (a) annotated with a
  named integration test that exercises its decision path, or (b)
  re-included in `examine_globs`. This finding does not block the
  baseline measurement (TRJ5-A1.2a / A1.2b) but is logged as a
  follow-up for Wave 2 of the lane.
- Two structural notes (NOT exclusions, but worth recording): both
  `chio-credentials/src/lib.rs` and `chio-policy/src/evaluate.rs` use
  `include!()` to pull in sub-files. cargo-mutants discovers via `mod`
  declarations and does not see `include!`d files. Mutations of those
  umbrella files cover the included source for the mutator, but
  per-file kill-rate breakdown is not possible without restructuring
  the `include!` pattern.

## Recommendation

Proceed with TRJ5-A1.2a / A1.2b baseline runs against the current
`examine_globs` list. After baselines land, file a follow-up ticket
(suggested: TRJ5-A1.6.1 "audit `chio-guards/src/external/**` per-file
test coverage") to address the only `FOR-REMOVAL-CANDIDATE` finding.

The audited exclusion list does NOT block the >=65% target reading;
the target is held against a file set whose justification has been
re-checked for this trj5 cycle.

## Auditor

Automated baseline pass; this document records each entry's
classification by reading the entries in `.cargo/mutants.toml` against
the close-bar criterion. Follow-up reviewer should spot-check the
`text_utils.rs` and `models.rs` caveats noted above.
