# Eval-Receipt Evidence Export Contract

**Schema id:** `chio.eval-report.bundle.v1`
**Partner:** METR

This contract defines how a `verdict_matrix` scenario run becomes an
unsigned eval-report bundle before schema validation and outer signature
verification land. The source verdict-matrix manifest remains read-only
while the bundle/export surface is being built, so the shared matrix is
not moved underneath it.

## Inputs

| Input | Source | Contract requirement |
|-------|--------|----------------------|
| Scenario corpus | `crates/chio-conformance/verdict_matrix/manifest.toml` | Read-only. `scenario_count` must be 48 and `corpus_sha256` must be `47e8d5394c807196d9567d97515e786cb1abfb0c7676e54db269ca82c735422f`. |
| Scenario metadata | `crates/chio-conformance/verdict_matrix/scenarios/**` | Scenario id, category, and expected verdict are copied into each receipt wrapper. |
| Inner receipt | Rust verdict-matrix driver output | Preserved byte-for-byte as the inner Chio receipt payload. The export helper hashes the receipt payload and does not reinterpret its signature. |
| Eval run metadata | Partner pipeline output | Mapped into the bundle `eval_run` block. METR P1 Q&A locks this to a Python vivaria trace post-processing path. |

## Output Bundle

The exporter produces an unsigned bundle with these top-level fields:

- `schema`: constant `chio.eval-report.bundle.v1`.
- `bundle_id`: producer-assigned id for this exported run.
- `created_at`: UTC timestamp supplied by the caller.
- `producer`: repository, commit, and workflow or local-run evidence.
- `eval_run`: partner-facing run metadata.
- `corpus`: verdict-matrix corpus metadata, including `corpus_sha256`.
- `receipts`: one wrapper per scenario receipt.
- `signatures`: empty in P2. P3 fills and verifies outer signatures.

## Field Mapping

| Bundle field | Source field | Notes |
|--------------|--------------|-------|
| `eval_run.run_id` | Partner pipeline run id | Stable across retry of the same eval run. |
| `eval_run.partner` | Partner identity | `METR`. |
| `eval_run.partner_slug` | Partner slug | `metr`. |
| `eval_run.pipeline` | Partner pipeline output | `vivaria-trace-postprocess` for the first sample. |
| `eval_run.pipeline_language` | Partner pipeline Q&A | `python`. |
| `eval_run.model_under_eval` | Partner pipeline output | Partner-owned model label. |
| `eval_run.scorer_name` | Partner pipeline output | Rubric or scorer name. |
| `eval_run.scorer_version` | Partner pipeline output | Rubric or scorer version. |
| `corpus.scenario_count` | verdict_matrix manifest | Must be 48 for the reference corpus. |
| `corpus.corpus_sha256` | verdict_matrix manifest | Must match `47e8d5394c807196d9567d97515e786cb1abfb0c7676e54db269ca82c735422f`. |
| `receipts[].scenario_id` | Scenario file `id` | Copied from the scenario JSON. |
| `receipts[].category` | Scenario file category or tag | Normalized to the manifest category id. |
| `receipts[].verdict` | Rust driver emitted verdict | The export helper does not change `allow` or `deny`. |
| `receipts[].receipt_sha256` | Inner receipt bytes | Lowercase hex SHA-256 over the preserved receipt payload. |
| `receipts[].receipt_payload` | Rust driver emitted receipt | Stored as opaque text until P3 wires JSON schema verification. |

## Export Helper Contract

`crates/chio-eval-receipt/src/export.rs` exposes:

```rust
pub fn export_scenario_run(receipts: &[Receipt], run_meta: EvalRunMeta) -> Bundle
```

The helper is intentionally an unsigned exporter. It must:

1. Copy `EvalRunMeta` into `bundle.eval_run` without inventing partner
   metadata.
2. Pin `bundle.corpus.corpus_sha256` to the P0 manifest hash.
3. Hash every inner receipt payload and expose the hash as
   `receipt_sha256`.
4. Preserve each inner receipt payload byte-for-byte.
5. Leave `bundle.signatures` empty so callers cannot confuse P2 output
   with a signed P3 bundle.

Invalid or missing scenario data is rejected before the helper is
called by using constructors that refuse empty ids, categories, verdicts,
and receipt payloads. P3 may add schema-level validation, but P2 already
keeps the export path fail-closed at the typed boundary.

## partner-side mapping

For METR, the first partner-side mapping is:

| METR pipeline value | `EvalRunMeta` field |
|---------------------|---------------------|
| Vivaria run id | `run_id` |
| Vivaria trace export job name | `pipeline` |
| Python post-processing script version | `scorer_version` |
| Eval task suite or rubric name | `scorer_name` |
| Target model label | `model_under_eval` |
| Trace sample id | Receipt `evidence.trace_id` |

The P4 sample must demonstrate this mapping without requiring live METR
infrastructure. It can read static fixture traces and produce the same
`EvalRunMeta` and receipt wrappers that a vivaria post-run export would
produce.

### P4 sample handoff

The P4 METR sample should treat this table as the compatibility
contract. The sample may use local JSON fixtures, but its output must
populate the same `EvalRunMeta` fields and receipt evidence fields that
the partner's vivaria trace post-processing job would provide:

- `run_id`: partner trace export id.
- `pipeline`: `vivaria-trace-postprocess`.
- `pipeline_language`: `python`.
- `scorer_name` and `scorer_version`: partner rubric metadata.
- `model_under_eval`: partner model label.
- `trace_id` and `sample_id`: per-receipt evidence anchors.

The audit doc links this contract so P5 can show how the signed memo
connects back to the exact export surface reviewed by the partner.

## Non-Goals

- Do not edit `crates/chio-conformance/verdict_matrix/**` in P2.
- Do not add outer signatures in P2.
- Do not change the inner Chio receipt schema.
- Do not claim public partner publication until P5 evidence exists.
