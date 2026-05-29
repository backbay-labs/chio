# Adversarial corpus minimization report

Owner: maintainers.
Last sweep: 2026-04-30.

This report records the result of running `cargo fuzz cmin` over each
fuzz corpus that feeds the trust-boundary adversarial pipeline.
Minimization runs as a maintenance task before every release close;
later sweeps append to the same table rather than
rewriting prior rows so the audit trail stays linear.

Methodology, fail-closed:

1. The sweep enumerates each `fuzz/corpus/<target>/` directory
   listed in `fuzz/owners.toml` (currently 23 corpora; see
   `fuzz/corpus_metadata.toml` for the seed-by-seed index).
2. For each target, run `cargo +nightly fuzz cmin <target>` from a
   clean checkout. Cmin discards seeds that do not increase coverage
   beyond the smaller surviving set.
3. Compare seed counts and total byte size before vs. after; record
   the delta and any seeds that the run dropped.
4. A seed dropped by cmin is an information-redundant input rather
   than a coverage hole; the corpus_metadata.toml entry for that
   seed must be removed in the same commit so the corpus-metadata gate
   stays green.

The table below pins the **pre-minimization baseline** at the date
above. Future cmin sweeps overwrite the `seeds_after` and
`bytes_after` columns and append a row to the changelog at the
bottom; the `seeds_before` and `bytes_before` columns are frozen.

| target | seeds_before | bytes_before | seeds_after | bytes_after | delta_seeds | delta_bytes | last_swept |
| ------ | -----------: | -----------: | ----------: | ----------: | ----------: | ----------: | ---------- |
| a2a_envelope_decode | 8 | 4595 | 8 | 4595 | 0 | 0 | 2026-04-30 |
| acp_envelope_decode | 7 | 4672 | 7 | 4672 | 0 | 0 | 2026-04-30 |
| anchor_bundle_verify | 6 | 614 | 6 | 614 | 0 | 0 | 2026-04-30 |
| attest_verify | 1 | 0 | 1 | 0 | 0 | 0 | 2026-04-30 |
| canonical_json | 3 | 49 | 3 | 49 | 0 | 0 | 2026-04-30 |
| capability_receipt | 1 | 2 | 1 | 2 | 0 | 0 | 2026-04-30 |
| chio_yaml_parse | 7 | 5085 | 7 | 5085 | 0 | 0 | 2026-04-30 |
| did_resolve | 6 | 347 | 6 | 347 | 0 | 0 | 2026-04-30 |
| fuzz_canonical_json | 2 | 1580 | 2 | 1580 | 0 | 0 | 2026-04-30 |
| fuzz_capability_receipt | 13 | 22421 | 13 | 22421 | 0 | 0 | 2026-04-30 |
| fuzz_manifest_roundtrip | 6 | 17940 | 6 | 17940 | 0 | 0 | 2026-04-30 |
| fuzz_merkle_checkpoint | 1 | 968 | 1 | 968 | 0 | 0 | 2026-04-30 |
| fuzz_policy_parse_compile | 6 | 6917 | 6 | 6917 | 0 | 0 | 2026-04-30 |
| fuzz_sql_parser | 10 | 637 | 10 | 637 | 0 | 0 | 2026-04-30 |
| fuzz_tool_action | 12 | 1891 | 12 | 1891 | 0 | 0 | 2026-04-30 |
| jwt_vc_verify | 5 | 1314 | 5 | 1314 | 0 | 0 | 2026-04-30 |
| manifest_roundtrip | 1 | 2 | 1 | 2 | 0 | 0 | 2026-04-30 |
| mcp_envelope_decode | 7 | 4624 | 7 | 4624 | 0 | 0 | 2026-04-30 |
| oid4vp_presentation | 4 | 1377 | 4 | 1377 | 0 | 0 | 2026-04-30 |
| openapi_ingest | 9 | 5169 | 9 | 5169 | 0 | 0 | 2026-04-30 |
| receipt_log_replay | 7 | 5186 | 7 | 5186 | 0 | 0 | 2026-04-30 |
| wasm_preinstantiate_validate | 7 | 113 | 7 | 113 | 0 | 0 | 2026-04-30 |
| wit_host_call_boundary | 7 | 4309 | 7 | 4309 | 0 | 0 | 2026-04-30 |

## Adversarial-promoted seeds

`scripts/promote_fuzz_seed.sh --mode adversarial` lands triage-
pending crashes under `crates/chio-adversarial-suite/cases/<class>/`
and adds the underlying byte seed to `fuzz/corpus/<target>/`. The
cmin sweep above covers the byte-side corpora; the JSON case files
are not fed through cmin (they are coverage artifacts of the
trust-boundary harness, not libFuzzer mutation inputs).

Pending adversarial-promoted seeds at 2026-04-30: 0 (no auto-promotions
have landed yet; the wasm_guard_escape corpus is the first sink for
adversarial-mode promotions).

## Changelog

- 2026-04-30: baseline recorded; table pinned to the 23 corpora present
  at the baseline sweep. No seeds dropped.
