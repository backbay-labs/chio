# chio-attest-verify mutation baseline (mutation evidence item/A1.8)

This directory holds the per-mutant cargo-mutants output for the
`chio-attest-verify` crate; the seed measurement that retires the
`BASELINE-GAP` row in `audits/mutation/2026-05-08-per-crate-baseline.md`.

## Run metadata

| Field | Value |
|---|---|
| Crate | `chio-attest-verify` |
| Date | 2026-05-08 |
| Evidence scope | local evidence run |
| Base SHA | `c7590b2603164a94c85d9fd3108909c8a290f289` |
| Tool | cargo-mutants 25.3.1 (matches the workspace pin in `.cargo/mutants.toml`) |
| Wall clock | 41m 4s |
| Run started | 2026-05-08T10:40:26Z |
| Run finished | 2026-05-08T11:21:30Z (approx; cargo-mutants summary line) |

## Command

```sh
cargo mutants \
  --config audits/mutation/per-crate-configs/chio-attest-verify.toml \
  -p chio-attest-verify \
  --in-place \
  --output audits/evidence/mutants/chio-attest-verify
```

The `--config audits/mutation/per-crate-configs/chio-attest-verify.toml` override is necessary
to scope the per-mutant test invocation to `--package chio-attest-verify`
rather than the full workspace. Rationale below.

## Test-scope deviation from the chio-credentials run

The `chio-credentials` baseline ran with the workspace
`.cargo/mutants.toml` (which sets
`additional_cargo_test_args = ["--workspace", "--exclude", "chio-cpp-kernel-ffi"]`).
That works for `chio-credentials` because its lib.rs mutations affect
relatively few downstream packages.

For `chio-attest-verify`, the workspace-wide test harness contains a
**pre-existing failing test** unrelated to this crate:

```
chio-acp-proxy::attestation_and_telemetry_tests::
  kernel_capability_checker_rejects_untrusted_and_tampered_tokens
  -- panicked: assertion failed: verdict.reason.contains("signature")
                                  || verdict.reason.contains("untrusted")
  -- actual reason: "capability verification failed:
                     capability issuer is not a trusted CA"
```

This failure exists on `main` at SHA `708c7bb33` and on the `release branch
a1-mutation-baseline` branch tip. It is a pre-existing test/runtime drift
where the runtime now returns a "trusted CA" message instead of the
"signature"/"untrusted" wording the test expects.

If the chio-attest-verify mutation run used the workspace test scope,
**every single mutant would be marked CAUGHT** because the chio-acp-proxy
test would always fail before any chio-attest-verify mutation could be
exercised by the test harness. The kill rate would be ~100% but the
measurement would be meaningless: cargo-mutants would attribute the
chio-acp-proxy unrelated failure to each chio-attest-verify mutant.

To produce an honest signal, this run scopes the per-mutant test
invocation to `--package chio-attest-verify` only, via the override
config at `audits/mutation/per-crate-configs/chio-attest-verify.toml`. The `examine_globs`
in that config matches the workspace `.cargo/mutants.toml`
(lib.rs + sigstore.rs).

The `test_scope` field in `2026-05-08.json` is `"package-only
(--test-package chio-attest-verify)"`, distinguishing this from the
workspace-scope chio-credentials run and signaling to the aggregator
that the comparison is not apples-to-apples until the chio-acp-proxy
test is fixed (out of scope for this PR; flagged as a follow-up).

## Result

86 mutants discovered, 86 evaluated.

| Outcome | Count |
|---|---|
| Caught | 30 |
| Missed | 38 |
| Timeout | 0 |
| Unviable | 18 |

Kill rate (cargo-mutants 25.x convention; unviable excluded from
denominator): **30 / (30 + 38 + 0) = 30/68 = 44.12%**.

## Target

Per `lane-a-floor/mutation-budget.md` and `audits/T0.B-substrate-
hardening.md` line 16: chio-attest-verify is the >=80% target crate
("highest-effort"; T0.B audit line 16).

**Measured 44.12%; target >=80%; gap of 35.88 percentage points remains.**

## Surviving-mutant categorization

All 38 missed mutants and the file/function distribution:

```
36 of 38 missed mutants are in crates/chio-attest-verify/src/sigstore.rs
 2 of 38 missed mutants are in crates/chio-attest-verify/src/lib.rs
```

By function (sigstore.rs):

| Surface | Missed | Note |
|---|---|---|
| `sigstore_protobuf_specs_compat::rekor_metadata` (line 579) | 7 | Rekor inclusion-promise extraction; not exercised by any current test |
| `<impl AttestVerifier for SigstoreVerifier>::verify_bytes` boundary checks (line 163) | 6 | `<` / `>` comparison-operator mutants on signature length pre-check |
| `sigstore_protobuf_specs_compat::leaf_der` (line 564) | 4 | Bundle leaf-cert extraction; no test asserts the alternative branches |
| `bundle_rekor_metadata` boundary `>` checks (line 507) | 3 | Same Rekor metadata path, different layer |
| `bundle_leaf_certificate_der` (line 500) | 3 | Bundle-leaf vec values; tests do not check the byte content |
| `certificate_validity` arithmetic `+`/`-` (lines 480, 481) | 2 | Time-window arithmetic; tests do not stress boundary values |
| `match_identity` SAN/OID guard (line 414) | 3 | OID guard match-arm and `==` operator |
| `map_webpki_error` arm deletion (lines 377, 380) | 2 | Error-mapping arms not covered by negative tests |
| `verify_signature_bytes` (line 491) | 1 | Replace -> Ok(()) is missed (signature-verify is bypassed if test does not check the verdict path) |
| `verify_bytes` `||` -> `&&` (line 163) | 1 | Boolean operator on length pre-check |
| Other miscellaneous in sigstore.rs | 4 | |
| `StaticTenantPolicyMap::is_empty` -> true (lib.rs:176) | 1 | No test asserts is_empty() on a populated map |
| `StaticTenantPolicyMap::len` -> 0 (lib.rs:170) | 1 | No test asserts len() on a populated map |

The full list is at `2026-05-08.json` field `missed_mutants`.

## Categorization (test gaps vs unreachable vs reachable-but-uncovered)

All 38 are in the **"reachable-but-uncovered"** category. None are
"unreachable code" (cargo-mutants would have flagged them as unviable
in that case). None are flake-driven; the test suite is deterministic
and the run produced 0 timeouts.

The pattern is: **`crates/chio-attest-verify/tests/sigstore_negative.rs`
exists but is short (103 lines, see `tests/sigstore_negative.rs` line
count in the chio-credentials evidence) and exercises only a small subset of the
sigstore verification surface**. The surface that is genuinely
exercised by the existing test:
- `lib.rs::StaticTenantPolicyMap::from_verified` constructor
  (caught: 8 lib.rs mutants).
- A subset of sigstore.rs paths (caught: 22 sigstore.rs mutants).

The test gaps are concentrated in:
1. **Bundle parsing internals** (`leaf_der`, `bundle_leaf_certificate_der`,
   `bundle_rekor_metadata`, `rekor_metadata`) - a bundle-fixture-based
   negative test that asserts the extracted values would close most of
   these.
2. **Boundary comparisons in `verify_bytes`** (signature length pre-check
   at line 163) - one boundary test (length = expected, length = expected+1,
   length = expected-1) would close 6+ mutants.
3. **`certificate_validity` time arithmetic** (lines 480-481) - testing
   the not_before / not_after derivation against a fixture certificate
   would close 2 mutants.
4. **`match_identity` SAN/OID guard** (line 414) - a test that builds an
   OtherName SAN with the OTHERNAME_OID and asserts it is matched would
   close 3 mutants.
5. **`StaticTenantPolicyMap::is_empty/len` smoke tests** - 2 trivial
   fixes.

Closing these would land ~17 of the 38 missed easily and likely push
the kill rate to ~62% (47/(68)). To reach 80% requires closing ~24
more, which means a more thorough sigstore_negative test suite plus
explicit `# unreachable: <justification>` annotations on the residual
pass-through mutants per the T0.B audit convention. This work is
**deferred to mutation evidence item follow-up**.

## What's NOT in this PR

- Test additions to close the 38 missed mutants (deferred to A1.8).
- The chio-acp-proxy unrelated test fix; that is its own concern and
  is filed as a follow-up (the test expectation predates a refactor
  that changed the verdict.reason wording from "signature"/"untrusted"
  to "trusted CA").
- A workspace-scope re-run; once chio-acp-proxy is fixed, the
  CI hosted-nightly mutants lane (`mutants.yml`, 4-hour-per-crate
  budget) will produce the authoritative workspace-scope number.
- `releases.toml [per_crate_kill_rate_percent]` update (a partial
  2-of-6 update would weaken audit signal; will land once all six
  trust-boundary crates have measured baselines).

## Files in this directory

- `2026-05-08.json` - per-crate JSON summary (the authoritative
  machine-readable result; consumed by `audits/mutation/aggregate.sh`).
- `mutants.out/caught.txt` - 30 lines, one per caught mutant.
- `mutants.out/missed.txt` - 38 lines, one per missed mutant.
- `mutants.out/timeout.txt` - 0 lines.
- `mutants.out/unviable.txt` - 18 lines.
- `mutants.out/outcomes.json` - per-mutant outcome record. Intentionally
  not committed; regenerate locally when argv-level replay evidence is
  needed.
- `mutants.out/lock.json` - run start time + tool version. Intentionally
  not committed because cargo-mutants records local process metadata in this file.
- `mutants.out/diff/*.diff` and `mutants.out/mutants.json` - per-mutant
  source diffs and mutant catalogue. These are produced per-run and
  published as release artifacts rather than committed to the repository.

The `mutants.out/log/` and `mutants.out/debug.log` are NOT committed
per `audits/evidence/mutants/.gitignore` (29MB+ per crate, contain
absolute paths).

## Reproducibility

`mutants.out/lock.json` and `mutants.out/outcomes.json` are intentionally
omitted by `audits/evidence/mutants/.gitignore`: cargo-mutants records
local process metadata and per-mutant console transcripts in those files. The committed evidence is
the dated JSON summary plus `caught.txt`, `missed.txt`, `timeout.txt`,
`unviable.txt`. The per-mutant `diff/` patches and `mutants.json` catalogue
are produced per-run and published as release artifacts rather than
committed to the repository.

To regenerate the omitted files locally, rerun:

```sh
cargo mutants \
  --config audits/mutation/per-crate-configs/chio-attest-verify.toml \
  -p chio-attest-verify \
  --in-place \
  --output audits/evidence/mutants/chio-attest-verify
```

Then compare the regenerated counts against
`audits/evidence/mutants/chio-attest-verify/2026-05-08.json`; do not
commit the regenerated `lock.json`, `outcomes.json`, `log/`, or
`debug.log`.
