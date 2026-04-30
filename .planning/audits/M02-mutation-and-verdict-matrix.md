# M02 Mutation And Verdict Matrix Audit Baseline

This audit opens trajectory-2 M02, "Mutation Gate + Cross-SDK Verdict
Differential". It is a documentation-only baseline for P0.T1. No CI,
lockfile, code, or workflow behavior is changed here.

Source-of-truth: `.planning/trajectory-2/02-mutation-and-cross-sdk-differential.md`.
Ticket: `M02.P0.T1`.
Snapshot date: 2026-04-29.

## Purpose

M02 has two quality surfaces:

- Mutation testing asks whether existing trust-boundary tests actually kill
  meaningful source-level changes.
- The verdict matrix asks whether SDK and kernel surfaces agree on the same
  `(verdict, reason_code, scope_set)` tuple for the same scenario.

This P0 audit records the starting state before M02 changes either surface.
Later M02 phases should update this file with kill scores, before and after
counts, scenario counts, and corpus hashes.

## Source References

| Reference | Baseline note |
|-----------|---------------|
| `.planning/trajectory-2/02-mutation-and-cross-sdk-differential.md` | Defines M02 scope: promote deferred trajectory-1 mutation work, widen mutation coverage to six trust-boundary crates, and add `crates/chio-conformance/verdict_matrix/`. |
| `.planning/trajectory/02-fuzzing-post-pr13.md` | Defines the original mutation-testing approach: `cargo-mutants` 25.x, four trust-boundary crates, >= 80% catch ratio, advisory for one release cycle, then blocking. |
| `.planning/trajectory/EXECUTION-STATE.json` | Records trajectory-1 M02 mutation config and advisory workflow as merged: M02.P2.T1 at `92f1b71c848db6f2bd54165195309bc4a9d22f4f`, M02.P2.T2 at `386290d26880705259d694eaf1bd3e746e9d213d`. |
| `.planning/trajectory-2/tickets/M02/P0.yml` | Defines this ticket gate: create this audit doc and include the phrase `trajectory-1 M02.P3 advisory state`. |

## trajectory-1 M02.P3 advisory state

The live repository starts M02 with trajectory-1's mutation lane present but
not yet load-bearing as a required gate.

| Surface | Live state | M02 implication |
|---------|------------|-----------------|
| `.cargo/mutants.toml` | Present as the workspace-root cargo-mutants config. It sets `additional_cargo_test_args = ["--workspace", "--exclude", "chio-cpp-kernel-ffi"]`, `timeout_multiplier = 3.0`, and `minimum_test_timeout = 60`. Its `examine_globs` cover `chio-kernel-core`, `chio-policy`, `chio-guards`, and `chio-credentials`. | P1 and P3 must widen the trust-boundary set to include `chio-attest-verify` and `chio-anchor` before the lane can satisfy trajectory-2 M02. |
| Per-crate `mutants.toml` files | None found in the live worktree with `find crates -path '*/mutants.toml' -print`. The workspace config explicitly says cargo-mutants 25.x does not auto-discover per-crate files. | Treat per-crate skip-list scaffolding as not live. P3.T4 must either create rationale-bearing skip-list files with a checker or update the process so rationale stays in the workspace config. |
| `.github/workflows/mutants.yml` | Present with `mutants-pr` and `mutants-nightly` jobs. The matrix covers the four trajectory-1 crates. The workflow installs `cargo-mutants` 25.3.1, captures PR diffs for `--in-diff`, calls `scripts/mutants-gate.sh`, posts summaries through `scripts/mutants-comment.sh`, and uploads reports. | This is an advisory shell today. M02 must extend the matrix and then flip enforcement only after kill scores are measured and stable. |
| `releases.toml` | Present with `phase3_merge_tag = ""` and `cycle_end_tag = ""`. `scripts/mutants-gate.sh` reads `cycle_end_tag`; empty means advisory pass. | The required-CI transition is not active. P3 owns the release-cycle flip and any fail-closed behavior changes around missing or malformed release state. |
| `scripts/mutants-gate.sh` | Present. With empty `cycle_end_tag`, it exits 0 regardless of the upstream cargo-mutants exit. With non-empty `cycle_end_tag`, it fails on surviving mutants unless an override reason is supplied. | Current state is intentionally advisory. Promotion must preserve auditable overrides and should avoid silent fail-open behavior after the gate is declared required. |
| `scripts/mutants-comment.sh` | Present. It posts a per-PR Markdown summary and top five missed mutants when `outcomes.json` exists, and a no-mutants one-liner otherwise. | P3.T2 owns any blocking-label wording changes. P3.T3 owns issue filing beyond the per-PR cap. |
| `docs/fuzzing/mutants.md` | Present. It documents the 25.x pin, the single workspace config, the advisory-to-blocking release-cycle model, override paths, and survivor triage. | The doc already describes future P3 mechanics, but M02 still needs live enforcement and score data before claiming required status. |
| `README.md` kill-score headline | No M02 kill-score banner is part of this P0 snapshot. | P3.T5 owns the README headline and nightly auto-update PR flow. |
| `mutants-baseline.toml` | Not present in this P0 snapshot. | P1.T6 owns the aggregate baseline file and the first measured kill-score update here. |

## Mutation Scope Delta

Trajectory-1 covered four crates:

| Crate | Current trajectory-1 status | trajectory-2 M02 target |
|-------|-----------------------------|--------------------------|
| `chio-kernel-core` | Included in `.cargo/mutants.toml` and workflow matrix. | Measure baseline, raise to >= 80%, keep required once promoted. |
| `chio-policy` | Included in `.cargo/mutants.toml` and workflow matrix. | Measure baseline, raise to >= 80%, keep required once promoted. |
| `chio-guards` | Included in `.cargo/mutants.toml` and workflow matrix. | Measure baseline, raise to >= 80%, keep required once promoted. |
| `chio-credentials` | Included in `.cargo/mutants.toml` and workflow matrix. | Measure baseline, raise to >= 80%, keep required once promoted. |

Trajectory-2 adds two crates because they carry fail-closed verification
decisions that were not mutation-calibrated in trajectory-1:

| Crate | Starting state | M02 target |
|-------|----------------|------------|
| `chio-attest-verify` | Tests and sigstore-root fixture are present, but the crate is not in the trajectory-1 mutation config or workflow matrix. | Add to mutation scope, baseline, raise to >= 80%, and include in required gating. |
| `chio-anchor` | Tests are present, but the crate is not in the trajectory-1 mutation config or workflow matrix. | Add to mutation scope, baseline, raise to >= 80%, and include in required gating. |

## Verdict Matrix Starting State

No `crates/chio-conformance/verdict_matrix/` subtree exists in this P0
snapshot. The reusable inputs are present:

| Input | Live state | M02 target |
|-------|------------|------------|
| `crates/chio-conformance/` | Existing conformance crate with native suite runner sources, peer lockfile, binaries, and tests including `tests/vectors_oracle.rs`. | Add `verdict_matrix/` with scenario spec, manifest, scenario corpus, drivers, and diff oracle. |
| `crates/chio-provider-conformance/fixtures/` | Provider fixtures exist under `anthropic`, `bedrock`, and `openai`. | Reuse fixtures as scenario inputs where they express the same kernel decision across providers. |
| `sdks/python/chio-sdk-python` | Present. | P5.T1 driver target. |
| `sdks/typescript/packages/node-http` | Present. | P5.T2 driver target. |
| `crates/chio-kernel-browser/` | Present. | P5.T3 WASM browser kernel driver target. |
| `sdks/go/chio-go-http` | Present. | P5.T4 driver target. |
| Rust kernel path | Present through in-tree kernel crates. | P4.T3 first driver target. |

M02 should keep the verdict oracle semantic, not byte-for-byte only. The
expected comparison tuple is `(verdict, reason_code, scope_set)`. Extra
driver metadata can be logged as advisory until a scenario marks a field as
asserted.

## Preserved Prior Work

- Do not touch trajectory-1 libFuzzer targets, ClusterFuzzLite, corpus
  handling, or crash triage automation.
- Do not widen Kani or Apalache proof surfaces. M02 consumes formal checks as
  backstops and leaves `proofs/` surfaces alone.
- Reuse trajectory-1 M01 canonical JSON vector coverage as byte-equality
  support under the verdict matrix.
- Reuse trajectory-1 M07 provider-conformance fixtures and reason-code
  concepts, but diff along the cross-SDK axis rather than the cross-provider
  axis.

## Open Handoffs

1. Per-crate skip-list scaffolding is a planning discrepancy. The trajectory-2
   narrative says it exists, but the live repo has consolidated the config
   into `.cargo/mutants.toml` and has no `crates/**/mutants.toml` files.
2. The mutation workflow currently covers four crates. Widening to
   `chio-attest-verify` and `chio-anchor` is required before required-CI
   claims are valid.
3. No kill scores are measured in this P0 ticket. P1 must record per-crate
   baseline counts and missed-mutant classes.
4. No verdict-matrix scenario count or corpus hash exists yet. P4 and P5 must
   add those and update this audit.
5. Promotion from advisory to blocking should be reviewed against the
   fail-closed project rule before P3 flips the gate.

## Reproduction Commands

These commands reproduce the P0 snapshot checks:

```bash
sed -n '1,260p' .planning/trajectory-2/02-mutation-and-cross-sdk-differential.md
sed -n '80,130p' .planning/trajectory/02-fuzzing-post-pr13.md
sed -n '540,572p' .planning/trajectory/EXECUTION-STATE.json
sed -n '1,220p' .cargo/mutants.toml
sed -n '1,260p' .github/workflows/mutants.yml
find crates -path '*/mutants.toml' -print | sort
rg -n "cycle_end_tag|mutants" releases.toml docs/fuzzing/mutants.md .planning/trajectory/EXECUTION-STATE.json
find crates/chio-conformance -maxdepth 4 -type f | sort
find crates/chio-provider-conformance/fixtures -maxdepth 3 -type f | sort
find sdks -maxdepth 3 -type d | sort
```

## Audit-Local Phase Tracking

- [x] P0.T1: Open this audit doc and snapshot trajectory-1 M02.P3 advisory
  state.
- [ ] P0.T2: Verify Cargo.lock bump and cargo-mutants 25.x re-pin.
- [x] P1: Capture mutation baseline and missed-mutant classes per crate.
- [x] P1.T3: Capture `chio-attest-verify` mutation baseline.
- [x] P1.T5: Capture `chio-guards` and `chio-anchor` bounded baseline.
- [x] P1.T6: Aggregate the six D06 crate baselines in
  `mutants-baseline.toml`.
- [ ] P2: Raise each target crate to >= 80% kill rate.
- [ ] P3: Flip mutation gate, PR comment, issue filing, skip rationale, and
  README headline.
- [ ] P4: Add verdict-matrix harness, Rust driver, manifest, and CI.
- [ ] P5: Add Python, TypeScript, WASM browser, and Go drivers plus required
  cross-language diff.

## Aggregate Mutation Baseline Status

Snapshot date: 2026-04-30.

Source: `.planning/trajectory-2/mutants-baseline.toml`.

M02.P1.T6 aggregates the existing per-crate baseline entries only. No
additional `cargo-mutants` campaign was run for this bookkeeping ticket. The
aggregate file contains exactly six D06 crate entries.

| Crate | Listed mutants | Baseline coverage |
|-------|----------------|-------------------|
| `chio-policy` | 418 | Bounded shard 1/16 |
| `chio-credentials` | 28 | Full sweep |
| `chio-attest-verify` | 72 | Full sweep |
| `chio-kernel-core` | 304 | Full sweep |
| `chio-guards` | 1298 | Bounded shard 1/32 with partial outcomes |
| `chio-anchor` | 249 | Bounded shard 1/32 with partial outcomes |

| Aggregate metric | Count |
|------------------|-------|
| Crate entries | 6 |
| Listed mutants | 2369 |
| Evaluated mutants | 442 |
| Caught | 115 |
| Missed | 259 |
| Unviable | 65 |
| Timeout | 1 |
| Measured kill rate, excluding unviable | 30.7% |

The aggregate kill rate is a measured-status summary, not the final M02 gate
score, because the file combines full sweeps with bounded shard baselines.
P2 owns the targeted test work that raises each crate to the required >= 80%
kill rate before P3 promotes the lane to required CI.

## chio-policy Mutation Baseline

Snapshot date: 2026-04-29.

Command:

```bash
cargo mutants --config crates/chio-policy/mutants.toml --package chio-policy --shard 1/16 --jobs 4 --timeout 120 --no-shuffle --output target/mutants/chio-policy-p1-t1
```

The full candidate list contains 418 mutants. This baseline records the
completed first shard because it is enough to identify immediate survivor
classes without blocking the rest of Wave 1.

| Metric | Count |
|--------|-------|
| Shard candidates | 27 |
| Caught | 14 |
| Missed | 11 |
| Unviable | 2 |
| Timeout | 0 |
| Kill rate, excluding unviable | 56.0% |

Missed mutants:

| File | Mutation |
|------|----------|
| `crates/chio-policy/src/compiler.rs:826:24` | `==` to `!=` in `tool_patterns_overlap` |
| `crates/chio-policy/src/conditions.rs:102:69` | `+` to `*` in `evaluate_condition_depth` |
| `crates/chio-policy/src/conditions.rs:178:9` | delete match arm `5` in `day_abbreviation` |
| `crates/chio-policy/src/conditions.rs:218:9` | delete match arm `"US/Eastern" | "EST"` in `parse_timezone_offset` |
| `crates/chio-policy/src/compiler.rs:702:5` | replace `compile_output_sanitizer_config` with `Default::default()` |
| `crates/chio-policy/src/compiler.rs:776:57` | `&&` to `||` in `compile_velocity_rule` |
| `crates/chio-policy/src/conditions.rs:220:42` | `*` to `+` in `parse_timezone_offset` |
| `crates/chio-policy/src/merge.rs:421:5` | replace `merge_chio` with `Some(Default::default())` |
| `crates/chio-policy/src/validate.rs:234:26` | `<` to `<=` in `validate_posture` |
| `crates/chio-policy/src/validate.rs:465:22` | `>` to `>=` in `validate_reputation` |
| `crates/chio-policy/src/validate.rs:606:30` | `-` to `/` in `is_valid_duration` |

## chio-credentials Mutation Baseline

Snapshot date: 2026-04-29.

Command:

```bash
cargo mutants --config crates/chio-credentials/mutants.toml --package chio-credentials --jobs 4 --timeout 120 --no-shuffle --output target/mutants/chio-credentials-p1-t2
```

The full candidate list contains 28 mutants. This baseline records the
completed full sweep.

| Metric | Count |
|--------|-------|
| Listed mutants | 28 |
| Evaluated mutants | 28 |
| Caught | 11 |
| Missed | 16 |
| Unviable | 1 |
| Timeout | 0 |
| Kill rate, excluding unviable | 40.7% |

Missed mutants:

| File | Mutation |
|------|----------|
| `crates/chio-credentials/src/lib.rs:57:5` | replace `is_supported_passport_schema` with `true` |
| `crates/chio-credentials/src/lib.rs:57:41` | `==` to `!=` in `is_supported_passport_schema` |
| `crates/chio-credentials/src/lib.rs:61:5` | replace `is_supported_passport_verifier_policy_schema` with `true` |
| `crates/chio-credentials/src/lib.rs:57:31` | `||` to `&&` in `is_supported_passport_schema` |
| `crates/chio-credentials/src/lib.rs:57:12` | `==` to `!=` in `is_supported_passport_schema` |
| `crates/chio-credentials/src/lib.rs:61:57` | `==` to `!=` in `is_supported_passport_verifier_policy_schema` |
| `crates/chio-credentials/src/lib.rs:61:47` | `||` to `&&` in `is_supported_passport_verifier_policy_schema` |
| `crates/chio-credentials/src/lib.rs:61:12` | `==` to `!=` in `is_supported_passport_verifier_policy_schema` |
| `crates/chio-credentials/src/lib.rs:65:5` | replace `is_supported_passport_presentation_challenge_schema` with `true` |
| `crates/chio-credentials/src/lib.rs:65:12` | `==` to `!=` in `is_supported_passport_presentation_challenge_schema` |
| `crates/chio-credentials/src/lib.rs:66:9` | `||` to `&&` in `is_supported_passport_presentation_challenge_schema` |
| `crates/chio-credentials/src/lib.rs:66:19` | `==` to `!=` in `is_supported_passport_presentation_challenge_schema` |
| `crates/chio-credentials/src/lib.rs:71:9` | `||` to `&&` in `is_supported_passport_presentation_response_schema` |
| `crates/chio-credentials/src/lib.rs:70:5` | replace `is_supported_passport_presentation_response_schema` with `true` |
| `crates/chio-credentials/src/lib.rs:70:12` | `==` to `!=` in `is_supported_passport_presentation_response_schema` |
| `crates/chio-credentials/src/lib.rs:71:19` | `==` to `!=` in `is_supported_passport_presentation_response_schema` |

## chio-attest-verify Mutation Baseline

Snapshot date: 2026-04-29.

Command:

```bash
cargo mutants --config crates/chio-attest-verify/mutants.toml --package chio-attest-verify --jobs 4 --timeout 120 --no-shuffle --output target/mutants/chio-attest-verify-p1-t3
```

The full candidate list contains 72 mutants. This baseline records the
completed full sweep. `cargo-mutants` exited 2 because missed mutants
survived, which is expected for a baseline run.

| Metric | Count |
|--------|-------|
| Listed mutants | 72 |
| Evaluated mutants | 72 |
| Caught | 0 |
| Missed | 57 |
| Unviable | 15 |
| Timeout | 0 |
| Kill rate, excluding unviable | 0.0% |

Missed mutants:

| File | Mutation |
|------|----------|
| `crates/chio-attest-verify/src/sigstore.rs:160:16` | replace `<` with `==` in `<impl AttestVerifier for SigstoreVerifier>::verify_bytes` |
| `crates/chio-attest-verify/src/sigstore.rs:160:16` | replace `<` with `>` in `<impl AttestVerifier for SigstoreVerifier>::verify_bytes` |
| `crates/chio-attest-verify/src/sigstore.rs:160:16` | replace `<` with `<=` in `<impl AttestVerifier for SigstoreVerifier>::verify_bytes` |
| `crates/chio-attest-verify/src/sigstore.rs:160:36` | replace `>` with `==` in `<impl AttestVerifier for SigstoreVerifier>::verify_bytes` |
| `crates/chio-attest-verify/src/sigstore.rs:160:36` | replace `>` with `<` in `<impl AttestVerifier for SigstoreVerifier>::verify_bytes` |
| `crates/chio-attest-verify/src/sigstore.rs:160:36` | replace `>` with `>=` in `<impl AttestVerifier for SigstoreVerifier>::verify_bytes` |
| `crates/chio-attest-verify/src/sigstore.rs:320:5` | replace `parse_certificate_to_der` with `Ok(vec![])` |
| `crates/chio-attest-verify/src/sigstore.rs:320:5` | replace `parse_certificate_to_der` with `Ok(vec![0])` |
| `crates/chio-attest-verify/src/sigstore.rs:320:5` | replace `parse_certificate_to_der` with `Ok(vec![1])` |
| `crates/chio-attest-verify/src/sigstore.rs:321:25` | replace `==` with `!=` in `parse_certificate_to_der` |
| `crates/chio-attest-verify/src/sigstore.rs:327:22` | replace `==` with `!=` in `parse_certificate_to_der` |
| `crates/chio-attest-verify/src/sigstore.rs:340:5` | replace `validate_against_fulcio` with `Ok(())` |
| `crates/chio-attest-verify/src/sigstore.rs:375:9` | delete match arm `webpki::Error::CertNotValidYet{..} \| webpki::Error::CertExpired{..}` in `map_webpki_error` |
| `crates/chio-attest-verify/src/sigstore.rs:378:9` | delete match arm `webpki::Error::UnknownIssuer` in `map_webpki_error` |
| `crates/chio-attest-verify/src/sigstore.rs:388:5` | replace `match_identity` with `Ok(String::new())` |
| `crates/chio-attest-verify/src/sigstore.rs:388:5` | replace `match_identity` with `Ok("xyzzy".into())` |
| `crates/chio-attest-verify/src/sigstore.rs:389:15` | replace `!=` with `==` in `match_identity` |
| `crates/chio-attest-verify/src/sigstore.rs:160:29` | replace `\|\|` with `&&` in `<impl AttestVerifier for SigstoreVerifier>::verify_bytes` |
| `crates/chio-attest-verify/src/sigstore.rs:410:13` | delete match arm `GeneralName::Rfc822Name(s)` in `match_identity` |
| `crates/chio-attest-verify/src/sigstore.rs:411:13` | delete match arm `GeneralName::UniformResourceIdentifier(s)` in `match_identity` |
| `crates/chio-attest-verify/src/sigstore.rs:412:46` | replace match guard `other.type_id == OTHERNAME_OID` with `true` in `match_identity` |
| `crates/chio-attest-verify/src/sigstore.rs:412:46` | replace match guard `other.type_id == OTHERNAME_OID` with `false` in `match_identity` |
| `crates/chio-attest-verify/src/sigstore.rs:412:60` | replace `==` with `!=` in `match_identity` |
| `crates/chio-attest-verify/src/sigstore.rs:431:5` | replace `read_oidc_issuer_extension` with `Ok("xyzzy".into())` |
| `crates/chio-attest-verify/src/sigstore.rs:431:5` | replace `read_oidc_issuer_extension` with `Ok(String::new())` |
| `crates/chio-attest-verify/src/sigstore.rs:438:24` | replace `==` with `!=` in `read_oidc_issuer_extension` |
| `crates/chio-attest-verify/src/sigstore.rs:458:5` | replace `decode_oidc_issuer_value` with `Ok(String::new())` |
| `crates/chio-attest-verify/src/sigstore.rs:458:5` | replace `decode_oidc_issuer_value` with `Ok("xyzzy".into())` |
| `crates/chio-attest-verify/src/sigstore.rs:466:31` | replace `&&` with `\|\|` in `decode_oidc_issuer_value` |
| `crates/chio-attest-verify/src/sigstore.rs:466:57` | delete `!` in `decode_oidc_issuer_value` |
| `crates/chio-attest-verify/src/sigstore.rs:466:12` | delete `!` in `decode_oidc_issuer_value` |
| `crates/chio-attest-verify/src/sigstore.rs:478:33` | replace `+` with `-` in `certificate_validity` |
| `crates/chio-attest-verify/src/sigstore.rs:479:32` | replace `+` with `-` in `certificate_validity` |
| `crates/chio-attest-verify/src/sigstore.rs:489:5` | replace `verify_signature_bytes` with `Ok(())` |
| `crates/chio-attest-verify/src/sigstore.rs:498:5` | replace `bundle_leaf_certificate_der` with `Ok(vec![])` |
| `crates/chio-attest-verify/src/sigstore.rs:498:5` | replace `bundle_leaf_certificate_der` with `Ok(vec![0])` |
| `crates/chio-attest-verify/src/sigstore.rs:498:5` | replace `bundle_leaf_certificate_der` with `Ok(vec![1])` |
| `crates/chio-attest-verify/src/sigstore.rs:505:35` | replace `>` with `==` in `bundle_rekor_metadata` |
| `crates/chio-attest-verify/src/sigstore.rs:505:35` | replace `>` with `<` in `bundle_rekor_metadata` |
| `crates/chio-attest-verify/src/sigstore.rs:506:20` | replace `+` with `-` in `bundle_rekor_metadata` |
| `crates/chio-attest-verify/src/sigstore.rs:505:35` | replace `>` with `>=` in `bundle_rekor_metadata` |
| `crates/chio-attest-verify/src/sigstore.rs:552:9` | replace `sigstore_protobuf_specs_compat::leaf_der` with `None` |
| `crates/chio-attest-verify/src/sigstore.rs:552:9` | replace `sigstore_protobuf_specs_compat::leaf_der` with `Some(vec![])` |
| `crates/chio-attest-verify/src/sigstore.rs:552:9` | replace `sigstore_protobuf_specs_compat::leaf_der` with `Some(vec![1])` |
| `crates/chio-attest-verify/src/sigstore.rs:552:9` | replace `sigstore_protobuf_specs_compat::leaf_der` with `Some(vec![0])` |
| `crates/chio-attest-verify/src/sigstore.rs:554:13` | delete match arm `verification_material::Content::X509CertificateChain(chain)` in `sigstore_protobuf_specs_compat::leaf_der` |
| `crates/chio-attest-verify/src/sigstore.rs:558:13` | delete match arm `verification_material::Content::Certificate(cert)` in `sigstore_protobuf_specs_compat::leaf_der` |
| `crates/chio-attest-verify/src/sigstore.rs:567:9` | replace `sigstore_protobuf_specs_compat::rekor_metadata` with `None` |
| `crates/chio-attest-verify/src/sigstore.rs:567:9` | replace `sigstore_protobuf_specs_compat::rekor_metadata` with `Some((0, 0))` |
| `crates/chio-attest-verify/src/sigstore.rs:567:9` | replace `sigstore_protobuf_specs_compat::rekor_metadata` with `Some((0, 1))` |
| `crates/chio-attest-verify/src/sigstore.rs:567:9` | replace `sigstore_protobuf_specs_compat::rekor_metadata` with `Some((1, 0))` |
| `crates/chio-attest-verify/src/sigstore.rs:567:9` | replace `sigstore_protobuf_specs_compat::rekor_metadata` with `Some((0, -1))` |
| `crates/chio-attest-verify/src/sigstore.rs:567:9` | replace `sigstore_protobuf_specs_compat::rekor_metadata` with `Some((1, 1))` |
| `crates/chio-attest-verify/src/sigstore.rs:567:9` | replace `sigstore_protobuf_specs_compat::rekor_metadata` with `Some((1, -1))` |
| `crates/chio-attest-verify/src/sigstore.rs:594:28` | replace `==` with `!=` in `<impl VerificationPolicy for IssuerOnlyPolicy>::verify` |
| `crates/chio-attest-verify/src/sigstore.rs:585:9` | replace `<impl VerificationPolicy for IssuerOnlyPolicy>::verify` with `Ok(())` |
| `crates/chio-attest-verify/src/sigstore.rs:608:27` | replace `==` with `!=` in `<impl VerificationPolicy for IssuerOnlyPolicy>::verify` |

## chio-kernel-core Mutation Baseline

Snapshot date: 2026-04-29.

Command:

```bash
cargo mutants --config crates/chio-kernel-core/mutants.toml --package chio-kernel-core --jobs 4 --timeout 120 --no-shuffle --output target/mutants/chio-kernel-core-p1-t4
```

The full candidate list contains 304 mutants. This baseline records the
completed full sweep. `cargo-mutants` exited 3 because missed mutants and one
timeout survived, which is expected for a baseline run.

| Metric | Count |
|--------|-------|
| Listed mutants | 304 |
| Evaluated mutants | 304 |
| Caught | 87 |
| Missed | 175 |
| Unviable | 41 |
| Timeout | 1 |
| Kill rate, excluding unviable | 33.1% |

Missed mutant classes:

| Class | Count |
|-------|-------|
| comparison rewrite | 54 |
| boolean connective rewrite | 35 |
| boolean return rewrite | 35 |
| negation deletion | 18 |
| arithmetic rewrite | 15 |
| match arm deletion | 7 |
| other rewrite | 5 |
| string return rewrite | 4 |
| structured return rewrite | 2 |

Timeout mutant classes:

| Class | Count |
|-------|-------|
| arithmetic rewrite | 1 |

Timeout mutants:

| File | Mutation |
|------|----------|
| `crates/chio-kernel-core/src/passport_verify.rs:240:17` | `replace += with *= in payload_bytes_hex::decode_hex` |

Missed mutants:

| File | Mutation |
|------|----------|
| `crates/chio-kernel-core/src/evaluate.rs:96:9` | `replace EvaluationVerdict::is_deny -> bool with true` |
| `crates/chio-kernel-core/src/evaluate.rs:90:9` | `replace EvaluationVerdict::is_allow -> bool with true` |
| `crates/chio-kernel-core/src/normalized.rs:102:9` | `replace NormalizedToolGrant::is_subset_of -> bool with true` |
| `crates/chio-kernel-core/src/normalized.rs:154:38` | `replace == with != in NormalizedToolGrant::is_subset_of` |
| `crates/chio-kernel-core/src/normalized.rs:166:9` | `replace NormalizedToolGrant::is_subset_of_bounded_kani -> bool with true` |
| `crates/chio-kernel-core/src/normalized.rs:166:9` | `replace NormalizedToolGrant::is_subset_of_bounded_kani -> bool with false` |
| `crates/chio-kernel-core/src/normalized.rs:169:12` | `delete ! in NormalizedToolGrant::is_subset_of_bounded_kani` |
| `crates/chio-kernel-core/src/normalized.rs:166:12` | `delete ! in NormalizedToolGrant::is_subset_of_bounded_kani` |
| `crates/chio-kernel-core/src/normalized.rs:172:12` | `delete ! in NormalizedToolGrant::is_subset_of_bounded_kani` |
| `crates/chio-kernel-core/src/normalized.rs:175:12` | `delete ! in NormalizedToolGrant::is_subset_of_bounded_kani` |
| `crates/chio-kernel-core/src/normalized.rs:186:12` | `delete ! in NormalizedToolGrant::is_subset_of_bounded_kani` |
| `crates/chio-kernel-core/src/normalized.rs:183:12` | `delete ! in NormalizedToolGrant::is_subset_of_bounded_kani` |
| `crates/chio-kernel-core/src/normalized.rs:192:12` | `delete ! in NormalizedToolGrant::is_subset_of_bounded_kani` |
| `crates/chio-kernel-core/src/normalized.rs:198:12` | `delete ! in NormalizedToolGrant::is_subset_of_bounded_kani` |
| `crates/chio-kernel-core/src/normalized.rs:199:34` | `replace == with != in NormalizedToolGrant::is_subset_of_bounded_kani` |
| `crates/chio-kernel-core/src/normalized.rs:200:32` | `replace == with != in NormalizedToolGrant::is_subset_of_bounded_kani` |
| `crates/chio-kernel-core/src/normalized.rs:219:9` | `replace NormalizedResourceGrant::is_subset_of -> bool with true` |
| `crates/chio-kernel-core/src/normalized.rs:237:9` | `replace NormalizedPromptGrant::is_subset_of -> bool with true` |
| `crates/chio-kernel-core/src/normalized.rs:220:13` | `replace && with \|\| in NormalizedResourceGrant::is_subset_of` |
| `crates/chio-kernel-core/src/normalized.rs:238:13` | `replace && with \|\| in NormalizedPromptGrant::is_subset_of` |
| `crates/chio-kernel-core/src/normalized.rs:257:9` | `replace NormalizedScope::is_subset_of -> bool with true` |
| `crates/chio-kernel-core/src/normalized.rs:262:17` | `replace \|\| with && in NormalizedScope::is_subset_of` |
| `crates/chio-kernel-core/src/normalized.rs:261:17` | `replace \|\| with && in NormalizedScope::is_subset_of` |
| `crates/chio-kernel-core/src/normalized.rs:260:17` | `replace \|\| with && in NormalizedScope::is_subset_of` |
| `crates/chio-kernel-core/src/normalized.rs:259:16` | `delete ! in NormalizedScope::is_subset_of` |
| `crates/chio-kernel-core/src/normalized.rs:260:20` | `delete ! in NormalizedScope::is_subset_of` |
| `crates/chio-kernel-core/src/normalized.rs:261:20` | `delete ! in NormalizedScope::is_subset_of` |
| `crates/chio-kernel-core/src/normalized.rs:269:39` | `replace && with \|\| in NormalizedScope::is_subset_of` |
| `crates/chio-kernel-core/src/normalized.rs:262:20` | `delete ! in NormalizedScope::is_subset_of` |
| `crates/chio-kernel-core/src/normalized.rs:269:34` | `replace == with != in NormalizedScope::is_subset_of` |
| `crates/chio-kernel-core/src/normalized.rs:269:62` | `replace == with != in NormalizedScope::is_subset_of` |
| `crates/chio-kernel-core/src/normalized.rs:287:16` | `replace && with \|\| in NormalizedScope::is_subset_of` |
| `crates/chio-kernel-core/src/normalized.rs:282:16` | `replace && with \|\| in NormalizedScope::is_subset_of` |
| `crates/chio-kernel-core/src/normalized.rs:569:5` | `replace monetary_cap_is_subset -> bool with true` |
| `crates/chio-kernel-core/src/normalized.rs:592:25` | `replace && with \|\| in normalized_operations_subset_bounded_kani` |
| `crates/chio-kernel-core/src/normalized.rs:589:5` | `replace normalized_operations_subset_bounded_kani -> bool with false` |
| `crates/chio-kernel-core/src/normalized.rs:592:20` | `replace == with != in normalized_operations_subset_bounded_kani` |
| `crates/chio-kernel-core/src/normalized.rs:589:5` | `replace normalized_operations_subset_bounded_kani -> bool with true` |
| `crates/chio-kernel-core/src/normalized.rs:593:25` | `replace == with != in normalized_operations_subset_bounded_kani` |
| `crates/chio-kernel-core/src/normalized.rs:592:41` | `replace == with != in normalized_operations_subset_bounded_kani` |
| `crates/chio-kernel-core/src/normalized.rs:603:5` | `replace normalized_constraints_subset_bounded_kani -> bool with true` |
| `crates/chio-kernel-core/src/normalized.rs:603:5` | `replace normalized_constraints_subset_bounded_kani -> bool with false` |
| `crates/chio-kernel-core/src/normalized.rs:611:5` | `replace monetary_cap_is_subset_bounded_kani -> bool with false` |
| `crates/chio-kernel-core/src/normalized.rs:611:5` | `replace monetary_cap_is_subset_bounded_kani -> bool with true` |
| `crates/chio-kernel-core/src/normalized.rs:615:29` | `replace <= with > in monetary_cap_is_subset_bounded_kani` |
| `crates/chio-kernel-core/src/normalized.rs:615:49` | `replace && with \|\| in monetary_cap_is_subset_bounded_kani` |
| `crates/chio-kernel-core/src/normalized.rs:615:71` | `replace == with != in monetary_cap_is_subset_bounded_kani` |
| `crates/chio-kernel-core/src/normalized.rs:621:5` | `replace pattern_covers -> bool with true` |
| `crates/chio-kernel-core/src/passport_verify.rs:164:32` | `replace > with >= in verify_parsed_passport` |
| `crates/chio-kernel-core/src/passport_verify.rs:182:12` | `replace < with <= in verify_parsed_passport` |
| `crates/chio-kernel-core/src/passport_verify.rs:239:32` | `replace \| with ^ in payload_bytes_hex::decode_hex` |
| `crates/chio-kernel-core/src/passport_verify.rs:253:13` | `delete match arm b'A'..= b'F' in payload_bytes_hex::from_hex_nibble` |
| `crates/chio-kernel-core/src/passport_verify.rs:253:43` | `replace + with - in payload_bytes_hex::from_hex_nibble` |
| `crates/chio-kernel-core/src/passport_verify.rs:253:36` | `replace - with + in payload_bytes_hex::from_hex_nibble` |
| `crates/chio-kernel-core/src/passport_verify.rs:253:36` | `replace - with / in payload_bytes_hex::from_hex_nibble` |
| `crates/chio-kernel-core/src/scope.rs:76:12` | `delete ! in resolve_matching_grants` |
| `crates/chio-kernel-core/src/scope.rs:74:27` | `replace == with != in resolve_matching_grants` |
| `crates/chio-kernel-core/src/scope.rs:84:13` | `replace && with \|\| in resolve_matching_grants` |
| `crates/chio-kernel-core/src/scope.rs:83:13` | `replace && with \|\| in resolve_matching_grants` |
| `crates/chio-kernel-core/src/scope.rs:117:42` | `replace == with != in resolve_matching_grants` |
| `crates/chio-kernel-core/src/scope.rs:124:22` | `replace <= with > in resolve_matching_grants` |
| `crates/chio-kernel-core/src/scope.rs:204:66` | `replace \|\| with && in constraint_matches` |
| `crates/chio-kernel-core/src/scope.rs:216:16` | `delete ! in constraint_matches` |
| `crates/chio-kernel-core/src/scope.rs:208:16` | `delete ! in constraint_matches` |
| `crates/chio-kernel-core/src/scope.rs:216:36` | `replace && with \|\| in constraint_matches` |
| `crates/chio-kernel-core/src/scope.rs:216:79` | `replace == with != in constraint_matches` |
| `crates/chio-kernel-core/src/scope.rs:226:91` | `replace <= with > in constraint_matches` |
| `crates/chio-kernel-core/src/scope.rs:227:72` | `replace <= with > in constraint_matches` |
| `crates/chio-kernel-core/src/scope.rs:222:17` | `replace && with \|\| in constraint_matches` |
| `crates/chio-kernel-core/src/scope.rs:221:16` | `delete ! in constraint_matches` |
| `crates/chio-kernel-core/src/scope.rs:261:26` | `replace == with != in matches_pattern` |
| `crates/chio-kernel-core/src/scope.rs:261:45` | `replace == with != in matches_pattern` |
| `crates/chio-kernel-core/src/scope.rs:261:31` | `replace && with \|\| in matches_pattern` |
| `crates/chio-kernel-core/src/scope.rs:267:26` | `replace == with != in matches_pattern` |
| `crates/chio-kernel-core/src/scope.rs:264:26` | `replace != with == in matches_pattern` |
| `crates/chio-kernel-core/src/scope.rs:268:31` | `replace == with != in matches_pattern` |
| `crates/chio-kernel-core/src/scope.rs:277:5` | `replace pattern_exact -> bool with false` |
| `crates/chio-kernel-core/src/scope.rs:281:26` | `replace != with == in pattern_exact` |
| `crates/chio-kernel-core/src/scope.rs:277:5` | `replace pattern_exact -> bool with true` |
| `crates/chio-kernel-core/src/scope.rs:284:26` | `replace == with != in pattern_exact` |
| `crates/chio-kernel-core/src/scope.rs:285:31` | `replace == with != in pattern_exact` |
| `crates/chio-kernel-core/src/scope.rs:289:13` | `replace == with != in pattern_exact` |
| `crates/chio-kernel-core/src/scope.rs:293:5` | `replace path_has_prefix -> bool with false` |
| `crates/chio-kernel-core/src/scope.rs:302:30` | `replace > with == in path_has_prefix` |
| `crates/chio-kernel-core/src/scope.rs:299:30` | `replace != with == in path_has_prefix` |
| `crates/chio-kernel-core/src/scope.rs:302:30` | `replace > with < in path_has_prefix` |
| `crates/chio-kernel-core/src/scope.rs:302:30` | `replace > with >= in path_has_prefix` |
| `crates/chio-kernel-core/src/scope.rs:309:44` | `replace == with != in path_has_prefix` |
| `crates/chio-kernel-core/src/scope.rs:319:5` | `replace normalize_path -> Option<NormalizedPath> with None` |
| `crates/chio-kernel-core/src/scope.rs:319:45` | `replace \|\| with && in normalize_path` |
| `crates/chio-kernel-core/src/scope.rs:322:31` | `replace \|\| with && in normalize_path` |
| `crates/chio-kernel-core/src/scope.rs:325:20` | `replace == with != in normalize_path` |
| `crates/chio-kernel-core/src/scope.rs:382:5` | `replace collect_string_leaves_inner with ()` |
| `crates/chio-kernel-core/src/scope.rs:402:5` | `replace is_path_key -> bool with true` |
| `crates/chio-kernel-core/src/scope.rs:402:5` | `replace is_path_key -> bool with false` |
| `crates/chio-kernel-core/src/scope.rs:404:9` | `replace \|\| with && in is_path_key` |
| `crates/chio-kernel-core/src/scope.rs:411:5` | `replace looks_like_path -> bool with true` |
| `crates/chio-kernel-core/src/scope.rs:411:5` | `replace looks_like_path -> bool with false` |
| `crates/chio-kernel-core/src/scope.rs:412:9` | `replace && with \|\| in looks_like_path` |
| `crates/chio-kernel-core/src/scope.rs:417:13` | `replace \|\| with && in looks_like_path` |
| `crates/chio-kernel-core/src/scope.rs:416:13` | `replace \|\| with && in looks_like_path` |
| `crates/chio-kernel-core/src/scope.rs:415:13` | `replace \|\| with && in looks_like_path` |
| `crates/chio-kernel-core/src/scope.rs:411:5` | `delete ! in looks_like_path` |
| `crates/chio-kernel-core/src/scope.rs:414:13` | `replace \|\| with && in looks_like_path` |
| `crates/chio-kernel-core/src/scope.rs:413:13` | `replace \|\| with && in looks_like_path` |
| `crates/chio-kernel-core/src/scope.rs:428:5` | `replace parse_domain -> Option<String> with None` |
| `crates/chio-kernel-core/src/scope.rs:428:5` | `replace parse_domain -> Option<String> with Some("xyzzy".into())` |
| `crates/chio-kernel-core/src/scope.rs:428:5` | `replace parse_domain -> Option<String> with Some(String::new())` |
| `crates/chio-kernel-core/src/scope.rs:454:9` | `replace \|\| with && in parse_domain` |
| `crates/chio-kernel-core/src/scope.rs:453:19` | `replace == with != in parse_domain` |
| `crates/chio-kernel-core/src/scope.rs:456:13` | `replace && with \|\| in parse_domain` |
| `crates/chio-kernel-core/src/scope.rs:455:13` | `replace && with \|\| in parse_domain` |
| `crates/chio-kernel-core/src/scope.rs:454:13` | `delete ! in parse_domain` |
| `crates/chio-kernel-core/src/scope.rs:457:71` | `replace \|\| with && in parse_domain` |
| `crates/chio-kernel-core/src/scope.rs:457:51` | `replace \|\| with && in parse_domain` |
| `crates/chio-kernel-core/src/scope.rs:457:64` | `replace == with != in parse_domain` |
| `crates/chio-kernel-core/src/scope.rs:467:5` | `replace normalize_domain -> String with String::new()` |
| `crates/chio-kernel-core/src/scope.rs:457:84` | `replace == with != in parse_domain` |
| `crates/chio-kernel-core/src/scope.rs:471:5` | `replace wildcard_matches -> bool with true` |
| `crates/chio-kernel-core/src/scope.rs:467:5` | `replace normalize_domain -> String with "xyzzy".into()` |
| `crates/chio-kernel-core/src/scope.rs:471:5` | `replace wildcard_matches -> bool with false` |
| `crates/chio-kernel-core/src/scope.rs:476:25` | `replace < with == in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:476:25` | `replace < with > in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:478:13` | `replace && with \|\| in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:476:25` | `replace < with <= in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:477:24` | `replace < with == in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:477:24` | `replace < with > in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:477:24` | `replace < with <= in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:479:17` | `replace \|\| with && in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:478:44` | `replace == with != in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:481:43` | `replace == with != in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:479:47` | `replace == with != in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:484:29` | `replace += with -= in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:484:29` | `replace += with *= in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:486:29` | `replace += with *= in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:486:29` | `replace += with -= in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:487:31` | `replace += with *= in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:487:31` | `replace += with -= in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:490:41` | `replace + with * in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:490:41` | `replace + with - in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:491:23` | `replace += with -= in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:498:45` | `replace && with \|\| in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:491:23` | `replace += with *= in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:498:23` | `replace < with == in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:498:23` | `replace < with > in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:498:23` | `replace < with <= in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:498:75` | `replace == with != in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:499:21` | `replace += with *= in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:499:21` | `replace += with -= in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:502:17` | `replace == with != in wildcard_matches` |
| `crates/chio-kernel-core/src/scope.rs:508:31` | `replace && with \|\| in argument_contains_custom` |
| `crates/chio-kernel-core/src/scope.rs:509:17` | `replace \|\| with && in argument_contains_custom` |
| `crates/chio-kernel-core/src/scope.rs:506:5` | `replace argument_contains_custom -> bool with true` |
| `crates/chio-kernel-core/src/scope.rs:508:24` | `replace == with != in argument_contains_custom` |
| `crates/chio-kernel-core/src/scope.rs:506:5` | `replace argument_contains_custom -> bool with false` |
| `crates/chio-kernel-core/src/scope.rs:529:71` | `replace == with != in audience_allowlist_matches` |
| `crates/chio-kernel-core/src/scope.rs:522:5` | `replace audience_allowlist_matches -> bool with false` |
| `crates/chio-kernel-core/src/scope.rs:508:49` | `replace == with != in argument_contains_custom` |
| `crates/chio-kernel-core/src/scope.rs:522:5` | `replace audience_allowlist_matches -> bool with true` |
| `crates/chio-kernel-core/src/scope.rs:533:5` | `replace collect_audience_values with ()` |
| `crates/chio-kernel-core/src/scope.rs:543:9` | `delete match arm serde_json::Value::Array(values) in collect_audience_values` |
| `crates/chio-kernel-core/src/scope.rs:534:9` | `delete match arm serde_json::Value::Object(map) in collect_audience_values` |
| `crates/chio-kernel-core/src/scope.rs:553:5` | `replace is_audience_key -> bool with true` |
| `crates/chio-kernel-core/src/scope.rs:560:5` | `replace collect_string_values with ()` |
| `crates/chio-kernel-core/src/scope.rs:562:9` | `delete match arm serde_json::Value::Array(values) in collect_string_values` |
| `crates/chio-kernel-core/src/scope.rs:561:9` | `delete match arm serde_json::Value::String(s) in collect_string_values` |
| `crates/chio-kernel-core/src/scope.rs:553:5` | `replace is_audience_key -> bool with false` |
| `crates/chio-kernel-core/src/scope.rs:579:71` | `replace == with != in memory_store_allowlist_matches` |
| `crates/chio-kernel-core/src/scope.rs:572:5` | `replace memory_store_allowlist_matches -> bool with true` |
| `crates/chio-kernel-core/src/scope.rs:572:5` | `replace memory_store_allowlist_matches -> bool with false` |
| `crates/chio-kernel-core/src/scope.rs:583:5` | `replace collect_memory_store_values with ()` |
| `crates/chio-kernel-core/src/scope.rs:593:9` | `delete match arm serde_json::Value::Array(values) in collect_memory_store_values` |
| `crates/chio-kernel-core/src/scope.rs:584:9` | `delete match arm serde_json::Value::Object(map) in collect_memory_store_values` |
| `crates/chio-kernel-core/src/scope.rs:603:5` | `replace is_memory_store_key -> bool with false` |
| `crates/chio-kernel-core/src/scope.rs:603:5` | `replace is_memory_store_key -> bool with true` |

## chio-guards Mutation Baseline

Snapshot date: 2026-04-30.

Commands:

```bash
cargo mutants --config crates/chio-guards/mutants.toml --package chio-guards --list
cargo mutants --config crates/chio-guards/mutants.toml --package chio-guards --shard 1/32 --jobs 4 --timeout 120 --no-shuffle --output target/mutants/chio-guards-p1-t5-shard
```

The candidate list contains 1298 mutants. This baseline records a bounded
first shard attempt. The unmutated baseline was clean, then the run was stopped
after the first completed mutant outcomes because the cold scratch build cost
exceeded the ticket close-out budget.

| Metric | Count |
|--------|-------|
| Shard candidates | 41 |
| Evaluated mutants | 5 |
| Caught | 1 |
| Missed | 0 |
| Unviable | 4 |
| Timeout | 0 |
| Kill rate, excluding unviable | 100.0% |
| Baseline build | 400.8 seconds |
| Baseline test | 91.1 seconds |

Caught mutants:

| File | Mutation |
|------|----------|
| `crates/chio-guards/src/path_normalization.rs:16:5` | replace `normalize_path_for_policy` with `"xyzzy".into()` |

Unviable mutants:

| File | Mutation |
|------|----------|
| `crates/chio-guards/src/behavioral_sequence.rs:92:38` | replace `&&` with `||` in `<impl Guard for BehavioralSequenceGuard>::evaluate` |
| `crates/chio-guards/src/behavioral_profile.rs:295:9` | replace `BehavioralProfileGuard::current_window_start` with `1` |
| `crates/chio-guards/src/forbidden_path.rs:141:9` | replace `<impl chio_kernel::Guard for ForbiddenPathGuard>::name` with `""` |
| `crates/chio-guards/src/behavioral_profile.rs:118:9` | replace `InMemoryReceiptFeed::push` with `Ok(())` |

## chio-anchor Mutation Baseline

Snapshot date: 2026-04-30.

Commands:

```bash
cargo mutants --config crates/chio-anchor/mutants.toml --package chio-anchor --list
cargo mutants --config crates/chio-anchor/mutants.toml --package chio-anchor --shard 1/32 --jobs 4 --timeout 120 --no-shuffle --output target/mutants/chio-anchor-p1-t5-shard
```

The candidate list contains 249 mutants. This baseline records a bounded first
shard attempt. The unmutated baseline was clean, then the run was stopped after
the first completed mutant outcomes because the cold scratch build cost
exceeded the ticket close-out budget.

| Metric | Count |
|--------|-------|
| Shard candidates | 8 |
| Evaluated mutants | 6 |
| Caught | 2 |
| Missed | 0 |
| Unviable | 4 |
| Timeout | 0 |
| Kill rate, excluding unviable | 100.0% |
| Baseline build | 381.4 seconds |
| Baseline test | 20.4 seconds |

Caught mutants:

| File | Mutation |
|------|----------|
| `crates/chio-anchor/src/discovery.rs:554:5` | replace `freshness_status_label` with `"xyzzy"` |
| `crates/chio-anchor/src/evm.rs:390:8` | delete `!` in `ensure_publication_ready` |

Unviable mutants:

| File | Mutation |
|------|----------|
| `crates/chio-anchor/src/lib.rs:125:5` | replace `kernel_checkpoint_from_statement` with `Default::default()` |
| `crates/chio-anchor/src/discovery.rs:167:68` | replace `!=` with `==` in `build_anchor_discovery_artifact` |
| `crates/chio-anchor/src/functions.rs:255:27` | replace `!=` with `==` in `assess_functions_verification` |
| `crates/chio-anchor/src/bitcoin.rs:132:5` | replace `verify_ots_proof_for_submission` with `Ok(Default::default())` |
