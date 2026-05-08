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
| `crates/chio-policy/src/models.rs` | `FOR-REMOVAL-CANDIDATE` | Codex review on PR #603 flagged: `HushSpec::parse` at lines 129-154 runs fail-closed YAML validation (non-mapping rejection, unterminated-scalar checks, libyaml whitespace-overflow checks, panic containment). That is decision code, not pure data. The original audit downgraded this to "pure data structs + serde", which is WRONG. **Recommendation**: re-include `models.rs` in `examine_globs` and re-run the chio-policy baseline. The kill-rate target re-baselines accordingly. (Documented as a follow-up so the trj5 close-bar is held against the current `examine_globs`; the BASELINE-GAP bar for chio-policy still needs measurement either way.) |
| `crates/chio-policy/src/version.rs` | `OK` | Version constants. Pure data. |
| `crates/chio-policy/src/rulesets/**` | `OK` | Embedded YAML rulesets. Data, not decision code. The compiler that LOADS rulesets is in `examine_globs`. |

### chio-guards advisory/helper/external exclusions

| Glob | Classification | Rationale |
|---|---|---|
| `crates/chio-guards/src/action.rs` | `OK` | Pure type definitions for the `Action` enum. No decision logic. |
| `crates/chio-guards/src/text_utils.rs` | `FOR-REMOVAL-CANDIDATE` | Codex review on PR #603 flagged: `canonicalize` (`pub fn` at line 29) is imported and used by prompt-injection and jailbreak guards before they make their deny decisions. Mutations that stop stripping zero-width characters or folding homoglyphs can let obfuscated payloads evade the trust-boundary guards. The original audit downgraded this to "pure text helpers"; that is WRONG for `canonicalize`. **Recommendation**: re-include `text_utils.rs` in `examine_globs`. The chio-guards baseline re-baselines. |
| `crates/chio-guards/src/advisory.rs` | `OK` | Advisory-by-design guard surface. By construction, advisory guards do not deny; their decisions are not on the trust boundary. |
| `crates/chio-guards/src/spider_sense.rs` | `FOR-REMOVAL-CANDIDATE` | Codex review on PR #603 flagged: `SpiderSenseGuard` returns `Verdict::Deny` for dimension mismatch (line 290), non-finite embeddings (line 293), high similarity scores, and ambiguous-deny policy (line 299). The file's module-level doc-comment lists three explicit `Verdict::Deny` paths (lines 10-28). The original audit grouped this with `advisory.rs` "by file naming"; that is WRONG. **Recommendation**: re-include `spider_sense.rs` in `examine_globs`. The chio-guards baseline re-baselines. |
| `crates/chio-guards/src/external/**` | `FOR-REMOVAL-CANDIDATE` | This blanket exclusion of the `external/` tree is the most consequential entry in the file. The `external/` directory contains remote-process guard bridges (per `mutants.toml` rationale: "remote-process bridges, integration-tested rather than mutation-tested"). However, per `tickets.md` line 73 (TRJ5-A1.6 Note), "if the audit re-adds external paths, the kill-rate target re-baselines." A wholesale exclusion of `external/**` without per-file justification is exactly the pre-existing pattern this audit is meant to challenge. **Recommendation**: itemize each file in `external/` and either (a) confirm each is integration-tested with a named test path, or (b) include the file in `examine_globs`. |

### chio-anchor exclusions

| Glob | Classification | Rationale |
|---|---|---|
| `crates/chio-anchor/src/fuzz.rs` | `OK` | libFuzzer harness entry. Same rationale as the workspace-wide `**/fuzz.rs` exclusion. Note: this entry is redundant with `**/fuzz.rs` and could be removed, but the redundancy is harmless. |

## Findings summary

(Revised after Codex P2 review on PR #603 corrected three rows.)

- **16 of 20** exclusion entries are unambiguously `OK`
  (test/build/fuzz scaffolding, platform adapters, formal-methods
  harnesses, pure data, or advisory-by-design surfaces).
- **4 entries are `FOR-REMOVAL-CANDIDATE`**, all involving
  decision-capable code that the original draft of this audit
  classified incorrectly:
  - `crates/chio-policy/src/models.rs` (HushSpec::parse runs
    fail-closed YAML validation; not pure data).
  - `crates/chio-guards/src/text_utils.rs` (canonicalize is the
    canonical-form input to prompt-injection / jailbreak guards;
    mutations to it can let obfuscated payloads through).
  - `crates/chio-guards/src/spider_sense.rs` (SpiderSenseGuard
    returns Verdict::Deny on multiple paths; not advisory).
  - `crates/chio-guards/src/external/**` (blanket exclusion with
    no per-file justification; remote-process bridges).
- The chio-policy and chio-guards baselines therefore re-baseline
  if these four entries are re-included in `examine_globs` (per
  TRJ5-A1.6 Note in `tickets.md` line 73). The trj5 close bar
  should hold against the post-fix `examine_globs`, not the current
  one. **This is a real consequence of the original mis-audit**:
  any kill-rate number measured against the current
  `examine_globs` may be inflated relative to what the
  decision-capable code actually deserves.
- Three structural notes (NOT exclusions, but worth recording):
  - `chio-credentials/src/lib.rs` uses `include!()` to pull in 13
    sub-files. cargo-mutants discovers via `mod` declarations and
    does not see `include!`d files. The committed
    `chio-credentials` baseline (PR #603 commit 5bc230799) only
    mutated `lib.rs` (top-level functions, ~4 lines) and
    `trust_tier.rs`. **Codex P2 review correctly flagged that this
    means the published 74.1% kill rate does NOT cover the
    `include!`d files (`registry.rs`, `oid4vp.rs`, etc.), even
    though those files contain credential
    verification/validation logic.** A follow-up should either
    (a) restructure the `include!` pattern into real `mod`
    declarations (which makes per-file mutation testing possible)
    or (b) explicitly cite the published number as covering only
    the umbrella file.
  - `chio-policy/src/evaluate.rs` has the same `include!` pattern
    for the `evaluate/` sub-files (`context.rs`, `engine.rs`,
    etc.). Same caveat applies once the chio-policy baseline lands.
  - The fuzz harness path `crates/chio-anchor/src/fuzz.rs` is
    redundant with the workspace-wide `**/fuzz.rs` exclusion;
    redundancy is harmless but could be removed for tidiness.

## Recommendation

The TRJ5-A1.2a / A1.2b baseline runs in this PR were conducted
against the current `examine_globs`. The chio-credentials baseline
(74.1% kill rate, committed in 5bc230799) is therefore measured
against an `examine_globs` whose chio-credentials surface is just
`lib.rs` (umbrella) + `trust_tier.rs`; it does NOT mutate the 13
`include!`d files.

**P0-022 cleanup-wave update (2026-05-08)**: the chio-credentials
baseline JSON now carries a machine-readable `examine_scope` caveat
(`"exclude-13-included-files"`) plus a `result_label: "PARTIAL"`
field with the 13 uncovered file paths enumerated. The README at
`audits/evidence/mutants/chio-credentials/README.md` and the
aggregate baseline at
`audits/mutation/2026-05-08-per-crate-baseline.md` mark this run as
PARTIAL. Crate-level target satisfaction is NOT claimed; restructuring
`include!()` into `mod` declarations is a trj6 follow-up that will
allow cargo-mutants to scan the 13 files.

For the chio-policy and chio-guards baselines (deferred to a
follow-up PR), the `examine_globs` should FIRST be revised per the
four `FOR-REMOVAL-CANDIDATE` findings above, THEN the baseline run.
This avoids publishing a number against a file set that excludes
known decision-capable code.

A follow-up audit ticket (suggested: TRJ5-A1.6.1 "audit
`chio-guards/src/external/**` per-file test coverage" plus the
three other re-classified entries) should track this work.

## Auditor

Initial pass: automated grep against `.cargo/mutants.toml` entries.
Codex P2 review on PR #603 (commits 04:44Z and 05:00Z) corrected the
classification of `models.rs`, `text_utils.rs`, and `spider_sense.rs`
from `OK` to `FOR-REMOVAL-CANDIDATE` based on a reading of the actual
production decision logic in those files. The corrections are
incorporated above; the original misclassification is documented in
this audit's revision history (this file's git log).
