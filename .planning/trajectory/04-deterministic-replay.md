# Milestone 04: Deterministic Replay and Receipt Byte-Equivalence Gate

## Why this milestone

Non-repudiation is a load-bearing Chio claim. Today the kernel signs every
decision via `crates/chio-kernel/src/receipt_support.rs` (1494 lines, canonical
JSON via `canonical_json_bytes`, ed25519 signatures), and
`crates/chio-anchor/src/lib.rs` commits checkpoint Merkle roots through
`KernelCheckpoint` / `ReceiptInclusionProof` to external chains. Yet nothing in
CI proves that two builds of the kernel, run against the same inputs, produce
byte-identical receipts, and nothing proves that a receipt issued at v0.1.0
still verifies against `main`. The protocol-purist lens flags this as a silent
regression surface; the testing lens flags it as the missing oracle that all
later performance and refactor work needs in order to land safely.

This milestone produces the regression detector: a frozen scenario corpus, a
golden-receipt CI gate, a cross-version compatibility matrix, an auditor-facing
`chio replay` command, and a property-based fuzzer that asserts replay
invariance across randomised receipt sequences. The receipt-log Merkle
integrity story (anchored-root verification across implementations) is folded
in as the closing phase boundary.

## Tooling decisions (consolidated)

- **Snapshot lib**: `insta` 1.x for the structured diff renderer. Bless flow
  piggy-backs on `cargo insta review` for pre-merge UX; the byte-equivalence
  gate proper bypasses snapshot review and uses raw byte comparison.
- **Property lib**: `proptest` 1.10, already vendored at workspace
  `Cargo.toml:146`. Bolero was considered and rejected (the failure surface
  here is structured tuples, not byte-level fuzz).
- **JSON canonicalizer**: reuse `chio_core_types::canonical::canonical_json_bytes`
  (RFC 8785). No new canonicalizer is introduced; the gate fails closed if the
  scenario driver imports any other canonicalizer.
- **Golden file format**: per-scenario directory under
  `tests/replay/goldens/<family>/<name>/` with `receipts.ndjson`,
  `checkpoint.json`, `root.hex`. NDJSON keeps M10 tee streams byte-compatible
  with goldens; raw hex root makes diffs human-readable.

## Scope

In scope:

- A scenario corpus under `tests/replay/fixtures/` of 50 named cases (see
  fixture list below) organised into 10 families, driving the same kernel
  surface exercised by `tests/e2e/tests/full_flow.rs` (`InMemoryReceiptStore`,
  fixed signing key, fixed clock, fixed nonce source) and emitting signed
  receipt bundles plus checkpoint roots.
- A `chio-replay-gate` CI job that runs each scenario against the current build
  and diffs canonical-JSON payloads, signatures, and Merkle roots against
  checked-in goldens. Mismatches fail. `--bless` (gated, see below) regenerates
  goldens for an intentional change.
- A cross-version harness keyed off
  `tests/replay/release_compat_matrix.toml` (schema below) that records the
  last N tagged releases and re-verifies their bundled receipts against
  current code. Today the table contains `v0.1.0` and `v2.0`; the ratchet
  starts at `v3.0` and backfills `v2.0` lazily; `v0.1.0` is best-effort.
- A `chio replay <log>` subcommand in `crates/chio-cli` (full CLI surface
  below). Composes with M10 tee captures.
- A property fuzzer at `crates/chio-kernel/tests/replay_proptest.rs`.
- A differential check between the Rust kernel and the TypeScript SDK on
  anchored-root verification (`formal/diff-tests/anchored_root_tamper.rs`).

Out of scope:

- New receipt fields or schema changes. This milestone freezes the current
  format; schema evolution gets its own milestone.
- Anchoring to additional chains beyond what `chio-anchor` already supports.
- SDK parity beyond TypeScript. Python and JVM follow once the gate is green.

## Fixture list (50 named files)

Authoritative manifest. File paths are exact; each `.json` file is the
scenario manifest, with input artifacts in a sibling `inputs/` directory and
goldens under `tests/replay/goldens/<family>/<name>/`.

`allow_simple` (8):

- `tests/replay/fixtures/allow_simple/01_basic_capability.json`
- `tests/replay/fixtures/allow_simple/02_min_scope.json`
- `tests/replay/fixtures/allow_simple/03_unicode_argv.json`
- `tests/replay/fixtures/allow_simple/04_empty_args.json`
- `tests/replay/fixtures/allow_simple/05_long_payload_64k.json`
- `tests/replay/fixtures/allow_simple/06_nested_json_payload.json`
- `tests/replay/fixtures/allow_simple/07_clock_at_grant_start.json`
- `tests/replay/fixtures/allow_simple/08_clock_at_grant_end.json`

`allow_with_delegation` (6):

- `tests/replay/fixtures/allow_with_delegation/01_single_hop.json`
- `tests/replay/fixtures/allow_with_delegation/02_two_hop.json`
- `tests/replay/fixtures/allow_with_delegation/03_three_hop_max.json`
- `tests/replay/fixtures/allow_with_delegation/04_attenuated_scope.json`
- `tests/replay/fixtures/allow_with_delegation/05_attenuated_ttl.json`
- `tests/replay/fixtures/allow_with_delegation/06_cross_authority.json`

`allow_metered` (5):

- `tests/replay/fixtures/allow_metered/01_quote_under_budget.json`
- `tests/replay/fixtures/allow_metered/02_quote_at_budget.json`
- `tests/replay/fixtures/allow_metered/03_quote_with_redactions.json`
- `tests/replay/fixtures/allow_metered/04_quote_zero_cost.json`
- `tests/replay/fixtures/allow_metered/05_quote_credit_split.json`

`deny_expired` (5):

- `tests/replay/fixtures/deny_expired/01_one_second_past.json`
- `tests/replay/fixtures/deny_expired/02_one_day_past.json`
- `tests/replay/fixtures/deny_expired/03_clock_skew_neg.json`
- `tests/replay/fixtures/deny_expired/04_long_lived_capability.json`
- `tests/replay/fixtures/deny_expired/05_post_revocation_expiry.json`

`deny_scope_mismatch` (6):

- `tests/replay/fixtures/deny_scope_mismatch/01_wrong_resource.json`
- `tests/replay/fixtures/deny_scope_mismatch/02_wrong_action.json`
- `tests/replay/fixtures/deny_scope_mismatch/03_path_prefix_miss.json`
- `tests/replay/fixtures/deny_scope_mismatch/04_method_excluded.json`
- `tests/replay/fixtures/deny_scope_mismatch/05_argument_oob.json`
- `tests/replay/fixtures/deny_scope_mismatch/06_attenuation_undershoot.json`

`deny_revoked` (4):

- `tests/replay/fixtures/deny_revoked/01_authority_revoked.json`
- `tests/replay/fixtures/deny_revoked/02_delegate_revoked.json`
- `tests/replay/fixtures/deny_revoked/03_revoked_then_expired.json`
- `tests/replay/fixtures/deny_revoked/04_revocation_propagated.json`

`guard_rewrite` (6):

- `tests/replay/fixtures/guard_rewrite/01_pii_redact_email.json`
- `tests/replay/fixtures/guard_rewrite/02_pii_redact_ssn.json`
- `tests/replay/fixtures/guard_rewrite/03_url_normalize.json`
- `tests/replay/fixtures/guard_rewrite/04_arg_clamp_numeric.json`
- `tests/replay/fixtures/guard_rewrite/05_chain_two_rewrites.json`
- `tests/replay/fixtures/guard_rewrite/06_idempotent_rewrite.json`

`replay_attack` (4):

- `tests/replay/fixtures/replay_attack/01_immediate_reuse.json`
- `tests/replay/fixtures/replay_attack/02_delayed_reuse.json`
- `tests/replay/fixtures/replay_attack/03_stale_nonce.json`
- `tests/replay/fixtures/replay_attack/04_concurrent_reuse.json`

`tampered_signature` (3):

- `tests/replay/fixtures/tampered_signature/01_flipped_byte.json`
- `tests/replay/fixtures/tampered_signature/02_wrong_signer.json`
- `tests/replay/fixtures/tampered_signature/03_truncated_sig.json`

`tampered_canonical_json` (3):

- `tests/replay/fixtures/tampered_canonical_json/01_field_reordered.json`
- `tests/replay/fixtures/tampered_canonical_json/02_whitespace_added.json`
- `tests/replay/fixtures/tampered_canonical_json/03_dup_key_last_wins.json`

Total: 50.

## Phases

### Phase 1: corpus and golden infrastructure

Build `tests/replay/` as a sibling of `tests/conformance/` and `tests/e2e/`.
Define a `Scenario` driver wrapping the kernel surface from
`tests/e2e/tests/full_flow.rs` (`InMemoryReceiptStore`, fixed Ed25519 signing
key from `tests/replay/test-key.seed`, canonical clock, deterministic nonce).
Each scenario is the JSON manifest plus an `inputs/` directory; output is a
per-scenario directory of signed receipt JSON, an anchor checkpoint, and a
Merkle root.

#### First commit

- Message: `feat(replay): scaffold tests/replay corpus driver and 8-family layout`
- Files touched:
  - `tests/replay/Cargo.toml` (new test crate `chio-replay-gate`)
  - `tests/replay/src/driver.rs` (Scenario driver, fixed clock/nonce)
  - `tests/replay/src/main.rs` (binary entry, default reads fixtures dir)
  - `tests/replay/test-key.seed` (32-byte deterministic seed; non-production)
  - `tests/replay/README.md` (how to add a fixture, bless flow)
  - `Cargo.toml` (workspace member registration)
  - `tests/replay/fixtures/allow_simple/01_basic_capability.json` (one
    canary fixture so CI has a green path on day 1)

#### Tasks (atomic)

1. Add `chio-replay-gate` workspace member skeleton.
2. Implement `Scenario` and `ScenarioDriver` (fixed clock, deterministic nonce
   counter, signer loaded from `test-key.seed`).
3. Implement golden writer: NDJSON receipts, JSON checkpoint, hex root.
4. Implement golden reader and byte-comparison harness (raw `Vec<u8>`, no
   serde round-trip).
5. Author all 50 fixture manifests (manifest only, goldens land in Phase 2 via
   first official `--bless`).
6. Add `cargo test -p chio-replay-gate` glue.
7. Wire `LC_ALL=C` and explicit directory-listing sort into the driver.

#### Sizing: M, ~5 days

#### Exit test

`cargo test -p chio-replay-gate --test corpus_smoke -- --nocapture` passes.
Specifically `chio_replay_gate::corpus_smoke::all_50_fixtures_load_and_run`
must enumerate exactly 50 manifests, run each, and produce a non-empty
goldens tree without panicking. (The byte-equivalence assertion lights up in
Phase 2 once goldens are blessed.)

### Phase 2: CI gate and bless workflow

Add `.github/workflows/chio-replay-gate.yml` that runs the corpus on every PR
and on `main`. Failure surfaces a structured diff (scenario, receipt index,
JSON pointer, expected vs. observed). The `--bless` path is the only way to
update goldens; it is gated by the rules in "CHIO_BLESS gate logic" below.

#### First commit

- Message: `feat(replay): add chio-replay-gate CI job and bless helper`
- Files touched:
  - `.github/workflows/chio-replay-gate.yml`
  - `scripts/bless-replay-goldens.sh`
  - `tests/replay/src/bless.rs` (gate logic)
  - `tests/replay/goldens/**` (50 scenario directories, blessed once)
  - `docs/replay-compat.md` (bootstrap entry: "initial bless of corpus at SHA
    `<hash>`")
  - `.github/CODEOWNERS` (entry for `tests/replay/goldens/**`)

#### Tasks (atomic)

1. Implement `--bless` flag with the gate-logic checks (branch, env, audit log).
2. Write the workflow YAML (Linux-only, `LC_ALL=C`, required-on-main).
3. Add a macOS smoke job that runs the gate read-only.
4. Author `scripts/bless-replay-goldens.sh` (calls the binary, refuses if
   working tree dirty in `crates/chio-core/src/` or
   `crates/chio-kernel/src/receipt_support.rs` without a `docs/replay-compat.md`
   delta).
5. Bless all 50 goldens once and commit.
6. Add CODEOWNERS lock on `tests/replay/goldens/**`.

#### Sizing: M, ~4 days

#### Exit test

GitHub Actions workflow job `chio-replay-gate / replay-gate` is green on a
PR and is required-to-merge on `main`. Locally:
`cargo test -p chio-replay-gate --test golden_byte_equivalence` must produce
zero diffs against the blessed goldens.

### Phase 3: cross-version compatibility

Maintain `tests/replay/release_compat_matrix.toml` with one row per known
tag plus the receipt-bundle artifact URL produced by
`release-qualification.yml`. A workflow step fetches bundles for the last
N=5 tags and re-verifies signatures and anchor inclusion proofs with current
code. Today the table contains `v0.1.0` and `v2.0`; new tags auto-append via
a `release-tagged` GitHub Actions trigger that opens a PR adding the row.

#### First commit

- Message: `feat(replay): add cross-version release_compat_matrix and harness`
- Files touched:
  - `tests/replay/release_compat_matrix.toml`
  - `tests/replay/src/cross_version.rs`
  - `.github/workflows/chio-replay-gate.yml` (add `cross-version` job)
  - `.github/workflows/release-tagged.yml` (auto-append PR on tag)
  - `docs/replay-compat.md` (cross-version table)

#### Tasks (atomic)

1. Define TOML schema (see "Cross-version policy file" below).
2. Implement matrix loader with strict TOML deserialisation.
3. Implement bundle fetch + cache (artifact URL, sha256 pin).
4. Implement re-verify path against current `chio-kernel` build.
5. Add `release-tagged.yml` automation that opens a PR adding a row when
   `release-qualification.yml` publishes a new tag.
6. Document the ratchet rule (last N=5 tags supported; `v3.0` is the floor for
   the strict ratchet).

#### Sizing: M, ~4 days

#### Exit test

`cargo test -p chio-replay-gate --test cross_version_replay` re-verifies every
row in `release_compat_matrix.toml` whose `compat = "supported"` and asserts
all signatures and anchor proofs match. CI job
`chio-replay-gate / cross-version` is green.

### Phase 4: `chio replay` subcommand

Slot a new variant into the `Commands` enum consumed by
`crates/chio-cli/src/cli/dispatch.rs` (alongside `Run`, `Check`, `Init`,
`Api`, `Mcp`). Full surface in "chio replay subcommand surface" below.

#### First commit

- Message: `feat(cli): add chio replay subcommand for receipt-log re-evaluation`
- Files touched:
  - `crates/chio-cli/src/cli/dispatch.rs` (add `Replay` variant)
  - `crates/chio-cli/src/cli/replay.rs` (handler)
  - `crates/chio-cli/src/main.rs` (route)
  - `crates/chio-cli/tests/replay.rs` (integration tests for codes 0/10/20/30/40/50)
  - `crates/chio-cli/Cargo.toml` (add deps if any)
  - `docs/cli/replay.md` (user-facing docs)

#### Tasks (atomic)

1. Add `Replay` variant and `clap` parser.
2. Implement log reader (NDJSON stream and directory mode).
3. Implement signature re-verify and incremental Merkle root recompute.
4. Implement verdict re-derive against current build (drives exit 10).
5. Implement structured JSON output (`--json`) with a stable schema.
6. Author 6 integration tests (one per exit code: 0, 10, 20, 30, 40, 50).
7. Document `--from-tee` interplay with M10.

#### Sizing: M, ~4 days

#### Exit test

`cargo test -p chio-cli --test replay` covers all six exit codes.
Specifically the named tests
`replay::clean_log_exits_zero`,
`replay::verdict_drift_exits_ten`,
`replay::bad_signature_exits_twenty`,
`replay::malformed_json_exits_thirty`,
`replay::schema_mismatch_exits_forty`,
`replay::redaction_mismatch_exits_fifty` must all pass.

### Phase 5: property-based replay invariance

Add `crates/chio-kernel/tests/replay_proptest.rs` using the workspace
`proptest = "1.10"` dep. Strategies generate sequences of `(decision,
payload, clock, nonce)` tuples; the test asserts signing is a function (same
input, same bytes) and that replaying the receipt log twice yields the same
anchored root. Bound test time to 30 seconds in CI; archive seeds on failure
under `tests/replay/proptest-regressions/`.

#### First commit

- Message: `test(replay): add proptest replay-invariance suite for kernel`
- Files touched:
  - `crates/chio-kernel/tests/replay_proptest.rs`
  - `crates/chio-kernel/Cargo.toml` (dev-dependency on `proptest`)
  - `tests/replay/proptest-regressions/.gitkeep`
  - `.github/workflows/chio-replay-gate.yml` (add `proptest` job)

#### Tasks (atomic)

1. Define `arbitrary_receipt_tuple()` strategy.
2. Property: signing is a pure function (same inputs -> same bytes).
3. Property: re-playing the receipt log twice yields the same root.
4. Property: shuffling unrelated independent receipts (no shared nonce) does
   not change per-receipt bytes.
5. Add 30-second budget and regression archival.

#### Sizing: S, ~2 days

#### Exit test

`cargo test -p chio-kernel --test replay_proptest` passes within the 30s
budget. The property tests
`signing_is_a_function` and `replay_root_is_idempotent` are the named
exit-criterion tests.

### Phase 6: differential anchored-root verification

Reuse the Phase 1 corpus to drive the TypeScript SDK
(`sdks/typescript/packages/conformance`) through the same scenarios alongside
the harness in `formal/diff-tests/`. The Merkle inclusion proof realised by
`KernelCheckpoint` / `ReceiptInclusionProof` (re-exported through
`chio-anchor`) is the structure under test: each scenario emits a
`(receipt_id, leaf_hash, inclusion_proof, root)` tuple from both
implementations, and the differential test asserts byte equality on the
anchored root and structural equality on the proof path. The tamper test
lives at `formal/diff-tests/anchored_root_tamper.rs`.

#### First commit

- Message: `test(replay): differential anchored-root verification (rust vs ts)`
- Files touched:
  - `formal/diff-tests/anchored_root.rs`
  - `formal/diff-tests/anchored_root_tamper.rs`
  - `sdks/typescript/packages/conformance/src/replay.ts`
  - `sdks/typescript/packages/conformance/test/replay.spec.ts`
  - `.github/workflows/chio-replay-gate.yml` (add `differential` job)

#### Tasks (atomic)

1. Add TS-side scenario runner that consumes the same fixture manifests.
2. Emit `(receipt_id, leaf_hash, inclusion_proof, root)` tuples from both
   implementations.
3. Diff harness: byte equality on root, structural equality on proof path.
4. Tamper test: mutate a leaf byte; both implementations must return
   `Err(AnchorError::Verification(_))`.
5. Wire `differential` CI job (Linux only, both Rust and TS toolchains).

#### Sizing: L, ~6 days

#### Exit test

`cargo test --test anchored_root` and `bun test sdks/typescript/packages/conformance/test/replay.spec.ts`
both pass. CI job `chio-replay-gate / differential` is green. The tamper
test `formal::anchored_root_tamper::single_byte_flip_fails_closed_on_both`
is the named exit-criterion case.

## chio replay subcommand surface

```text
chio replay <log> [OPTIONS]

ARGS:
  <log>                Path to a receipt-log directory or NDJSON stream.

OPTIONS:
  --from-tee           Treat <log> as an M10 tee NDJSON stream (default: auto-detect).
  --expect-root <hex>  Assert the recomputed root matches this hex string.
  --json               Emit a structured JSON report on stdout (instead of human text).
  --bless              (Restricted) Convert <log> into a goldens directory.
                       Requires CHIO_BLESS=1, BLESS_REASON, feature branch, audit log.
  -h, --help           Print help.
  -V, --version        Print version.

EXIT CODES (canonical registry; M04 is the source of truth, M10 consumes verbatim):
  0   All receipts (or tee frames) verify and root matches expectation (or no
      expectation given).
  10  Verdict drift: a receipt's allow/deny decision differs from what the
      current build would issue for the same input.
  20  Signature mismatch: Ed25519 verification failed on at least one receipt
      or frame `tenant_sig`.
  30  Parse error: malformed JSON or a missing required field (structural
      failure before schema validation).
  40  Schema mismatch: unsupported `schema_version`, or schema validation
      failed against the M01 canonical-JSON schema set.
  50  Redaction mismatch: the recorded `redaction_pass_id` is unavailable, or
      rerunning the redaction manifest produces a different result.
```

`--help` sketch:

```text
chio replay - re-evaluate a captured receipt log against the current build

Usage: chio replay <log> [OPTIONS]

Reads a directory of signed receipts (or an NDJSON tee stream), re-verifies
every signature, recomputes the Merkle root incrementally, and reports the
first divergence by byte offset and JSON pointer. Composes with `chio tee`
output (see milestone M10).

Examples:
  chio replay ./receipts/                       # verify a goldens directory
  chio replay capture.ndjson --from-tee         # verify an M10 tee stream
  chio replay ./receipts/ --expect-root 7af9... # assert the root
  chio replay capture.ndjson --json             # machine-readable report
```

JSON output schema (stable; emitted on `--json` regardless of exit code):

```json
{
  "schema": "chio.replay.report/v1",
  "log_path": "string",
  "receipts_checked": 0,
  "computed_root": "hex",
  "expected_root": "hex|null",
  "first_divergence": {
    "kind": "verdict_drift|signature_mismatch|parse_error|null",
    "receipt_index": 0,
    "json_pointer": "/path/to/field",
    "byte_offset": 0,
    "expected": "raw bytes (base64)",
    "observed": "raw bytes (base64)"
  },
  "exit_code": 0
}
```

## CHIO_BLESS gate logic

`--bless` overwrites a golden if and only if all of the following hold. The
gate is fail-closed: any failure aborts before any file is written.

1. `CHIO_BLESS=1` is set in the environment.
2. `BLESS_REASON` env var is set and non-empty (free-form rationale; recorded
   in the audit entry).
3. The current branch is not `main` and not `release/*` (verified via
   `git rev-parse --abbrev-ref HEAD`).
4. The working tree is clean except for `tests/replay/goldens/**` and
   `docs/replay-compat.md`.
5. `stderr` is a TTY (`isatty(stderr)`). CI runners do not have a TTY by
   default; this combined with the `CI` env var check banning auto-bless
   ensures CI cannot bless.
6. The env var `CI` (commonly set by GitHub Actions, GitLab CI, etc.) is unset
   or `false`. If `CI=true`, the gate refuses unconditionally.
7. The bless writes a one-line audit entry to
   `tests/replay/.bless-audit.log` with: ISO-8601 timestamp, `git config
   user.name` and `user.email`, current branch, current SHA, fixture path
   touched, `BLESS_REASON` value. The same commit must include the audit-log
   line; the gate refuses to run if the audit log is dirty but the goldens
   are not, or vice versa.
8. CODEOWNERS review on `tests/replay/goldens/**` is enforced by branch
   protection on the PR side; this is the human gate on top of the
   programmatic gate.

CI is explicitly banned from blessing: the CI job sets `CHIO_BLESS=0` and the
binary refuses any bless invocation when `CI=true`. There is no "auto-bless on
green" path.

## Cross-version policy file

`tests/replay/release_compat_matrix.toml` shape:

```toml
# Cross-version receipt-compatibility matrix.
# Ratchet: the last N=5 tagged releases are supported by current main.
# Earlier tags are best-effort; see docs/replay-compat.md.

schema = "chio.replay.compat/v1"
window = 5

[[entry]]
tag = "v0.1.0"
released_at = "2025-08-12"
bundle_url = "https://github.com/bb-connor/chio/releases/download/v0.1.0/replay-bundle.tgz"
bundle_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
compat = "best_effort"      # one of: supported | best_effort | broken
supported_until = "v3.0"    # honoured strictly while compat = "supported"
notes = "pre-canonicalization-freeze; sigs verify, root format pre-dates v2 layout"

[[entry]]
tag = "v2.0"
released_at = "2026-02-04"
bundle_url = "https://github.com/bb-connor/chio/releases/download/v2.0/replay-bundle.tgz"
bundle_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
compat = "best_effort"
supported_until = "v6.0"
notes = "ratchet floor candidate; promote to supported after v3.0 tag lands"

# Future entries follow this pattern (auto-appended by release-tagged.yml):
# [[entry]]
# tag = "v3.0"
# released_at = "YYYY-MM-DD"
# bundle_url = "..."
# bundle_sha256 = "..."
# compat = "supported"
# supported_until = "v8.0"   # tag + 5 minor releases
# notes = ""
```

`compat = "broken"` requires a corresponding `docs/replay-compat.md` entry
with rationale; the cross-version job skips broken rows but the docs gate
asserts each broken row has a documented rationale.

## Test signing key management

`tests/replay/test-key.seed` is a 32-byte Ed25519 seed checked into the repo.
It is explicitly NOT a real signing key: the file is prefixed with a
`README.txt`-style sibling at `tests/replay/test-key.seed.README` warning that
this seed is public and must never sign production receipts. The kernel's
production signer code path refuses to load any key whose seed bytes match the
test seed (a constant-time compare in `chio-kernel::signer::load_key`).

Regeneration ban: a CI guard
(`.github/workflows/chio-replay-gate.yml` job `seed-immutable`) hashes the
seed file at every PR and fails closed if the hash differs from the
checked-in value at `tests/replay/test-key.seed.sha256`. To rotate the seed,
the project must (a) update the SHA file, (b) re-bless the entire corpus,
(c) ship an explicit `feat!:` commit. Routine PRs cannot change the seed.

Permissions: the gate refuses to run if the seed file is missing or
world-writable (mode `0o002` set), to catch a hostile mutation in a contributor's
checkout before any signature work happens.

## New sub-tasks

These three items are not present in the current doc and are added under M04
scope.

- **(NEW) Determinism canary on duplicate builds**: a CI step that builds the
  workspace twice on the same commit (clean cache vs. warm cache) and runs the
  gate against both build outputs, asserting byte equality on every receipt.
  This catches non-determinism that the single-build gate would miss (build
  cache, codegen ordering, link-time stamps). Lives in
  `.github/workflows/chio-replay-gate.yml` job `determinism-canary`.

- **(NEW) Receipt-log fuzzer corpus seeding**: the proptest regression
  archive (`tests/replay/proptest-regressions/`) is wired as a seed corpus
  for M02's libfuzzer harness so any property-replay regression that lands
  here also becomes a libfuzzer seed. One-line link in M02; concrete glue
  in `crates/chio-kernel/fuzz/seeds/replay.rs`.

- **(NEW) Goldens-size budget**: a CI assertion that the total size of
  `tests/replay/goldens/**` stays under 5MB. Larger budgets require an
  explicit override in `tests/replay/goldens.budget.toml` with rationale.
  This keeps the corpus reviewable in PR diff and prevents a future fixture
  from accidentally landing a multi-MB payload.

## Cross-doc references

- **M01 (conformance vectors)** is upstream: drift in canonical JSON or
  signing surfaces in M01's vector tests first, then in M04's golden gate.
  Concretely, M04 goldens validate against M01 Phase 1 receipt schemas
  (`spec/schemas/chio-wire/v1/receipt/{record,inclusion-proof}.schema.json`,
  landed in M01 P1.T3): the Phase 2 byte-equivalence gate runs `chio
  spec-validate tests/replay/goldens/**/receipts.ndjson` and `chio
  spec-validate tests/replay/goldens/**/checkpoint.json` before any byte
  comparison. The two artifacts are different serializations of the same
  schema, not different schemas: M01 owns
  `tests/bindings/vectors/receipt/v1.json` (case-table form, single JSON file
  per domain) and M04 owns
  `tests/replay/goldens/<family>/<name>/receipts.ndjson` (streaming form, one
  signed receipt per line, byte-compatible with M10 tee streams). A schema
  change in M01 that does not have a paired M04 golden-bless fails M04's gate
  first. The `inclusion-proof.schema.json` is the explicit M01-to-M04
  contract: every `KernelCheckpoint` and `ReceiptInclusionProof` emitted by
  the Phase 1 driver round-trips through it.
- **M05 (kernel async refactor)** is the primary M04 customer: M04 is the
  regression net that lets M05 land without silently changing receipt bytes.
- **M07 (provider-native adapters)** drives the bulk of new corpus growth:
  each new adapter family (OpenAI Responses, Anthropic Tools, Bedrock
  Converse, plus the existing MCP / A2A / ACP / AG-UI families) adds at
  least one scenario per decision class. New M07 fixtures land via the same
  `--bless` flow defined in this milestone (CHIO_BLESS=1, BLESS_REASON,
  feature branch, audit-log entry) and live under
  `tests/replay/fixtures/<adapter_family>/...`. M07's
  `chio-provider-conformance` harness emits the NDJSON shape that
  `chio replay --from-tee` consumes; bless converts a captured session into
  a goldens directory after CODEOWNERS review.
- **M10 (tee captures)** feeds M04: production tee outputs graduate into M04
  fixtures via `chio replay --bless`, which converts a tee stream into a
  goldens directory after CODEOWNERS review.

## Exit criteria

- `tests/replay/fixtures/` contains the 50 named scenarios above with
  checked-in goldens.
- `chio-replay-gate` job is required on `main` and green.
- `chio replay <log>` ships in `chio-cli` with passing integration tests
  covering exit codes 0, 10, 20, 30, 40, 50 (named tests above). M04 owns
  the canonical exit-code registry; M10 consumes it verbatim.
- `docs/replay-compat.md` and `tests/replay/release_compat_matrix.toml`
  record last-5-tag compatibility (current entries: `v0.1.0`, `v2.0`; the
  ratchet picks up at v3.0 going forward).
- Differential test confirms the Rust kernel and the TypeScript SDK agree on
  the anchored root for every scenario in the corpus, and the tamper test at
  `formal/diff-tests/anchored_root_tamper.rs` fails closed on both.
- `proptest` replay-invariance suite runs under `cargo test --workspace`
  with a 30s budget and archives regressions.
- Determinism canary, fuzzer-seed link, and goldens-size budget jobs are all
  green on `main`.

## Risks and mitigations

- **Hidden non-determinism** (timestamps, HashMap iteration, RNG). Mitigation:
  fixed clock, fixed signer, deterministic nonce; the determinism canary job
  hashes outputs across two builds on the same commit.
- **OS-level non-determinism** (directory iteration order, tmp paths,
  locale-sensitive sorts). Mitigation: scenarios never read from `/tmp`; the
  driver sorts directory listings explicitly and pins `LC_ALL=C` in the gate
  workflow.
- **Test-fixture drift across machines** (line endings, file modes, path
  separators). Mitigation: NDJSON goldens are written with `\n` regardless of
  platform; CI runs the gate only on Linux runners; a smoke job on macOS
  asserts the same hashes.
- **Receipt schema evolution invalidates goldens**. Mitigation: the bless
  workflow blocks on an accompanying `docs/replay-compat.md` entry, and
  schema changes that break the gate must ship behind an explicit
  conventional-commit `feat!:` or `fix!:` with a compat-table row.
- **Signing-key management for goldens**: see "Test signing key management"
  above; CI guard pins the seed hash.
- **`CHIO_BLESS` misuse**: see "CHIO_BLESS gate logic" above; CI cannot
  bless, audit log is mandatory.
- **Cross-version drift before more tags exist**. Mitigation: the matrix is
  sized to "last N up to 5" and ratchets up as `release-qualification.yml`
  publishes new tags; v0.1.0 is best-effort, v2.0 is the practical floor.
