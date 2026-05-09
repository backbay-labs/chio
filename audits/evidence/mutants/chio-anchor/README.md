# chio-anchor mutation baseline - PARTIAL

Status: **PARTIAL -- 214/262 evaluated (81.7% surface), kill rate
69.4% on partial; target NOT satisfied pending full run**.

This directory holds the per-mutant cargo-mutants output for the
`chio-anchor` crate. The 69.4% kill rate measured here is on the
214 mutants evaluated under a 60-min wall-clock cap; 48 mutants
remain unevaluated. The crate-level `>= 65%` target is NOT retired
by a partial run, regardless of the rate observed on the evaluated
subset. Aggregate documents now record this row as
`PARTIAL -- 69.4% on 214/262`. The next CI hosted-nightly run
completes the remaining 48 mutants without budget cap; until that
lands the row remains PARTIAL.

The kill rate reported below is observed (not extrapolated) on the
evaluated subset; the remaining 48 mutants are flagged for the
rerun-after-merge follow-up (see "Open follow-ups" below).

## Run metadata

| Field | Value |
|---|---|
| Crate | `chio-anchor` |
| Date | 2026-05-08 |
| Branch | `PR branch` |
| Base SHA | `708c7bb33df43594f5e76542b05fca7a56d9689e` (main baseline used for this run) |
| Tool | cargo-mutants 25.3.1 (matches the workspace pin in `.cargo/mutants.toml`) |
| Wall clock | 60m 31s (capped; partial) |
| Run started | 2026-05-08T12:07:59Z |
| Run finished | 2026-05-08T13:08:30Z (terminated by 60-minute operator-imposed cap) |
| Mutants discovered | 262 |
| Mutants evaluated | 214 |
| Mutants remaining | 48 |

## Command

```sh
cargo mutants \
  --config audits/mutation/per-crate-configs/chio-anchor.toml \
  -p chio-anchor --in-place \
  --baseline=skip \
  --output audits/evidence/mutants/chio-anchor
```

The `--config audits/mutation/per-crate-configs/chio-anchor.toml`
override is necessary to scope the per-mutant test invocation to
`--package chio-anchor` (rationale below) AND to skip a known
pre-existing failing test inside chio-anchor itself.

`--baseline=skip` is used because a clean cargo test run on
`chio-anchor` currently fails (see "Test-scope deviation"); skipping
the baseline allows the per-mutant test invocation to use `--skip`
filtering on the failing test.

## Test-scope deviation

This run deviates from the workspace-scope chio-credentials baseline
(PR #603) for two reasons:

### 1. Pre-existing chio-acp-proxy test failure

Same root cause as the chio-attest-verify run (PR #619). The workspace
test harness contains a pre-existing failing test
`chio-acp-proxy::attestation_and_telemetry_tests::
kernel_capability_checker_rejects_untrusted_and_tampered_tokens`
unrelated to chio-anchor. If the chio-anchor mutation run used
workspace test scope, every mutant would be marked CAUGHT because the
chio-acp-proxy assertion always fails before chio-anchor mutations are
exercised.

### 2. Pre-existing chio-anchor test failure

Empirically verified on commit `708c7bb33` (main) at the start of this
run: the test
`crates/chio-anchor/src/evm.rs::evm::tests::validate_rpc_egress_contract_accepts_hostname_rpc`
panics with "hostname RPC dispatch is resolver-enforced". The test
calls `validate_rpc_egress_contract` with a hostname-only URL
(`https://rpc.example`); the function returns `Err` (resolver-enforced
dispatch) and the test calls `.test_expect("...")` which panics on
`Err`.

This failure means a package-only `cargo test --package chio-anchor`
ALSO fails clean, so cargo-mutants would mark every mutant CAUGHT for
the same reason as the workspace-scope failure above.

The fix in this run is to scope `additional_cargo_test_args` to:

```toml
additional_cargo_test_args = [
    "--package", "chio-anchor",
    "--",
    "--skip", "evm::tests::validate_rpc_egress_contract_accepts_hostname_rpc",
]
```

Both deviations are **methodology fixes**, not test fixes. The
pre-existing failures are out of scope for the A1 mutation baseline.

The `test_scope` field in `2026-05-08.json` records the exact scope
used (`package-only (--package chio-anchor; --skip evm::tests::validate_rpc_egress_contract_accepts_hostname_rpc)`),
distinguishing this from the workspace-scope chio-credentials run and
signaling to the aggregator that the comparison is not apples-to-
apples until both pre-existing tests are fixed (out of scope for
this PR; flagged as a follow-up).

## Result

**262 mutants discovered, 214 evaluated, 48 remaining (capped).**

| Outcome | Count |
|---|---|
| Caught | 125 |
| Missed | 50 |
| Timeout | 5 |
| Unviable | 34 |

Kill rate (cargo-mutants 25.x convention; unviable excluded from
denominator): **125 / (125 + 50 + 5) = 125 / 180 = 69.44%**.

## Target satisfaction

Per the contract (`>=65%` for chio-anchor at this stage),
chio-anchor measured **69.44%** on the 214-of-262 evaluated subset
(81.7% surface).

**Crate-level target NOT satisfied by this run.** A partial run at
81.7% surface coverage cannot retire the crate-level `>= 65%`
target. The 69.4% kill rate is honest for the evaluated subset but
does not generalize to a "target met" claim until the full 262
mutants are evaluated. Aggregate documents now record this row as
`PARTIAL -- 69.4% on 214/262 evaluated; target NOT satisfied pending
full run`.

The remaining 48 mutants are concentrated in the same function
families that already missed (discovery, evm, ops, etc.) so the
rerun-after-merge result is expected to land within ~5 percentage
points of the partial number, but that expectation is NOT a basis
for claiming the target is met today.

**Follow-up**: the next CI hosted-nightly mutants.yml run
(4-hour-per-crate budget; no operator wall-clock cap) completes the
remaining 48 mutants. Once that lands, the row gets updated from
`PARTIAL` to the full-sweep status.

## Surviving-mutant categorization

The 50 missed mutants distribute across files as:

| File | Missed | Note |
|---|---|---|
| `discovery.rs` | 16 | Highest concentration: classify_discovery_status (9), select_primary_lane_for_chain (3), build_current_freshness_state (1), freshness_status_rank (2), verify_proof_bundle_with_discovery (1) |
| `evm.rs` | 9 | confirm_root_publication boolean ops (2), operator_key_hash + hex (2), validate_rpc_egress_contract (1), devnet_rpc_egress_contract_for_url arithmetic (2), hash_to_b256 (1), 1 misc |
| `ops.rs` | 8 | classify_anchor_lane (6), AnchorEmergencyControls::allows (1), anchor_incident_is_conflict (1) |
| `functions.rs` | 7 | prepare_functions_batch_verification boundary (5), assess_functions_verification (2) |
| `automation.rs` | 5 | assess_anchor_automation_execution boundary (5) |
| `bitcoin.rs` | 3 | verify_bitcoin_anchor_for_proof boundary (3) |
| `bundle.rs` | 2 | verify_checkpoint_publication_records (2) |

By function (top-5):

| Surface | Missed | Note |
|---|---|---|
| `classify_discovery_status` (discovery.rs:489-522) | 9 | Boundary `>` / `<` operator + match-guard mutants on freshness ranking |
| `classify_anchor_lane` (ops.rs:355-370) | 6 | Match-guard + comparison operator mutants on anchor-lane classification |
| `prepare_functions_batch_verification` (functions.rs:163-215) | 5 | Boolean-or and `>` boundary mutants on batch-size guards |
| `assess_anchor_automation_execution` (automation.rs:129-162) | 5 | Boundary `>` and `!=` mutants on automation gating |
| `verify_bitcoin_anchor_for_proof` (bitcoin.rs:183-184) | 3 | `<` / `>` and `||` mutants on anchor-proof verification |

The full list is at `2026-05-08.json` field `missed_mutants`.

## Categorization (test gaps vs unreachable vs reachable-but-uncovered)

All 50 missed mutants are in the **"reachable-but-uncovered"** category.
None are flagged unviable (those are tracked separately as 34 unviable).
None are flake-driven; the test suite is deterministic.

The pattern is concentrated on:
1. **Discovery / freshness classification boundary checks**
   (`classify_discovery_status`, `freshness_status_rank`) - 11 missed
   mutants. Tests do not assert specific rank values across the boundary
   (lagging, stale, fresh), so `<` / `>` / `==` flips survive. A
   boundary test (rank = boundary, rank = boundary+1, rank = boundary-1)
   would close most of these.
2. **Anchor-lane classification match guards**
   (`classify_anchor_lane`) - 6 missed mutants. The match guards
   `lane == AnchorLaneKind::EvmPrimary` are exercised but specific
   true/false outcomes are not asserted by tests.
3. **Batch verification boundary checks**
   (`prepare_functions_batch_verification`,
   `assess_functions_verification`) - 7 missed. Boundary tests not
   present.
4. **Automation gating boundary checks**
   (`assess_anchor_automation_execution`) - 5 missed. Pre-condition
   guards are not specifically asserted.
5. **Boolean-operator mutants in evm.rs `confirm_root_publication`** -
   2 missed. The `||` -> `&&` mutants survive because tests cover
   only the happy path.
6. **Identity functions** (`hash_to_b256`, `operator_key_hash`,
   `operator_key_hash_hex`) - 4 missed. Tests exercise the function
   but do not assert the *value* across the call.

Closing these would require adding boundary-value tests in
`crates/chio-anchor/tests/mutation_gap_closure.rs` (the file already
exists at 2 KB; this run shows where it needs to grow). This work
is **deferred to a follow-up**.

## Timeouts (5)

Five mutants timed out (300-second per-mutant default with
`--baseline=skip`):

- `evm.rs:426:5: replace verify_inclusion_onchain -> Result<bool, AnchorError> with Ok(true)`
- `evm.rs:426:5: replace verify_inclusion_onchain -> Result<bool, AnchorError> with Ok(false)`
- `evm.rs:496:5: replace rpc_call -> Result<Value, AnchorError> with Ok(Default::default())`
- `evm.rs:583:39: replace * with / in devnet_rpc_egress_contract_for_url`
- `evm.rs:279:15: replace != with == in confirm_root_publication`

The first three bypass the inclusion-on-chain check or the RPC
dispatch to return a no-op result; some downstream test apparently
spins waiting for either a true result or a non-empty RPC response.
The fourth replaces a multiplication with a division in the devnet
egress-contract size derivation; the result is presumably a 0 or
extreme value that triggers downstream retry. The fifth flips an
inequality inside `confirm_root_publication`, exercising a path
that retries indefinitely. Per cargo-mutants 25.x convention,
timeouts do NOT count as caught.

## What's NOT in this PR

- Test additions to close the 48 missed mutants (deferred to A1.8).
- The chio-acp-proxy unrelated test fix; that is its own concern and
  is filed as a follow-up (see chio-attest-verify README for context).
- The chio-anchor `validate_rpc_egress_contract_accepts_hostname_rpc`
  test fix; the test asserts a hostname URL is accepted by the egress
  contract, but the runtime now rejects hostname URLs (resolver-
  enforced dispatch). This is a pre-existing test/runtime drift
  similar to the chio-acp-proxy case.
- The remaining 48-of-262 mutants. The rerun-after-merge will pick
  these up; partial-state caveat is documented above.
- A workspace-scope re-run; once both pre-existing failures are
  fixed, the CI hosted-nightly mutants lane (mutants.yml, 4-hour-per-
  crate budget) will produce the authoritative workspace-scope number.
- `releases.toml [per_crate_kill_rate_percent]` update (a partial
  3-of-6 update would weaken audit signal; will land once all six
  trust-boundary crates have measured baselines).

## B3 (anchor-batch async-only) and A3 (Kani anchor harnesses) note

PR #609 (B3 anchor-batch async-only) and PR #613 (Kani anchor
harnesses) both touch chio-anchor and are not yet merged at the time
of this run. This baseline measurement is against current main
(commit `708c7bb33`), pre-B3 and pre-A3. Once B3 and A3 merge, the
chio-anchor surface and test density change non-trivially. The kill
rate in this baseline is therefore expected to *increase* on the
post-merge rerun (more deterministic async-only paths, more Kani-
constrained surfaces). The CI hosted-nightly will provide the
authoritative post-merge number; this 69.44% is the pre-B3/A3 seed.

## Files in this directory

- `2026-05-08.json` - per-crate JSON summary (the authoritative
  machine-readable result; consumed by `audits/mutation/aggregate.sh`).
  Includes the `partial: true` flag and `evaluated: 214, total_discovered: 262`.
- `mutants.out/caught.txt` - 125 lines, one per caught mutant.
- `mutants.out/missed.txt` - 50 lines, one per missed mutant.
- `mutants.out/timeout.txt` - 5 lines.
- `mutants.out/unviable.txt` - 34 lines.
- `mutants.out/mutants.json` - 262-entry mutant catalogue (full surface).
- `mutants.out/outcomes.json` - per-mutant outcome record (214 entries).
  Intentionally not committed; regenerate locally when argv-level replay
  evidence is needed.
- `mutants.out/lock.json` - run start time + tool version. Intentionally
  not committed because cargo-mutants records operator identity and
  workspace-absolute paths in this file.
- `mutants.out/diff/*.diff` - per-mutant source diff (one per evaluated
  mutant).

The `mutants.out/log/` and `mutants.out/debug.log` are NOT committed
per `audits/evidence/mutants/.gitignore` (29MB+ per crate, contain
absolute paths).

## Reproducibility

`mutants.out/lock.json` and `mutants.out/outcomes.json` are intentionally
omitted by `audits/evidence/mutants/.gitignore`: cargo-mutants records
operator identity, hostnames, workspace-absolute paths, argv paths, and
per-mutant console transcripts in those files. The committed evidence is
the dated JSON summary plus `caught.txt`, `missed.txt`, `timeout.txt`,
`unviable.txt`, `mutants.json`, and per-mutant `diff/` patches.

To regenerate the omitted files locally, rerun:

```sh
cargo mutants \
  --config audits/mutation/per-crate-configs/chio-anchor.toml \
  -p chio-anchor \
  --in-place \
  --output audits/evidence/mutants/chio-anchor
```

Then compare the regenerated counts against
`audits/evidence/mutants/chio-anchor/2026-05-08.json`; do not commit
the regenerated `lock.json`, `outcomes.json`, `log/`, or `debug.log`.
