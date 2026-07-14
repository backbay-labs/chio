# chio-spec-codegen

The Rust target of Chio's four-language schema-to-code pipeline (Rust,
Python, TypeScript, Go). Given repository-tracked spec inputs, it runs four
independent, deterministic generator passes: chio-wire/v1 Rust types, the
Chio error-code registry, per-threat stub tests, and the threat-coverage
markdown report.

`cargo xtask codegen` drives the wire-type and error-registry passes
in-process; the threat-model and threat-coverage-doc passes run through this
crate's own `chio-spec-codegen` binary instead. It generates code and docs
from schemas; `chio-spec-validate` does the opposite, validating instance
documents against schemas for conformance scenarios and wire artifacts.

## Responsibilities

- Walk `spec/schemas/chio-wire/v1/**/*.schema.json`, inline local `$ref`s,
  register every schema with one `typify::TypeSpace`, and emit a single
  formatted `chio_wire_v1.rs` plus a header-only `mod.rs`
  (`codegen_rust`, `render_chio_wire_v1`).
- Parse `spec/errors/registry.yaml` with a hand-rolled indentation parser,
  validate it, and emit the `ErrorCodeSpec` table and lookup functions
  consumed by `chio-errors` (`codegen_error_codes`, `render_error_codes`).
- Load and optionally schema-validate `spec/security/chio-threat-model.v1.json`,
  then emit one idempotent stub test per threat ID under
  `crates/tooling/chio-conformance/tests/threats/` (`codegen_threat_model`).
- Join the threat model, the adversarial-suite manifest, and existing stub
  files into `docs/security/threat-coverage.md`, grouped by coverage state
  (`codegen_threat_coverage_doc`).
- Stamp every generated file with the canonical `GENERATED_HEADER` and skip
  rewriting when the bytes are unchanged (`write_if_changed`), so `--check`
  drift detection stays exact and unrelated regenerations produce no git diff.

## Public API

Root (`lib.rs`):

- `codegen_rust(schemas_dir: &Path, out_dir: &Path) -> Result<()>` /
  `render_chio_wire_v1(schemas_dir: &Path) -> Result<String>` - the wire-type pass.
- `CodegenError`, `Result<T>` - shared error type and alias used by all four passes.
- `GENERATED_HEADER`, `CHIO_WIRE_V1_OUTPUT`, `MOD_FILE`.

Error registry (`errors_pass`, a private module re-exported at the crate root):

- `codegen_error_codes(registry_path: &Path, out_dir: &Path) -> Result<()>` /
  `render_error_codes(registry_path: &Path) -> Result<String>`.
- `ERROR_REGISTRY_INPUT`, `ERRORS_GENERATED_DIR`, `ERROR_CODES_OUTPUT`.

Threat-model stubs (`threat_model`):

- `codegen_threat_model(threat_model_path: &Path, out_dir: &Path) -> Result<Vec<(String, PathBuf)>, CodegenError>`.
- `load_threat_model`, `render_threat_stub`, `render_threats_mod`,
  `validate_threat_model_against_schema`.
- `ThreatEntry`, `ThreatModelDoc`, `THREAT_MODEL_INPUT`, `THREAT_MODEL_SCHEMA`,
  `THREAT_STUBS_OUTPUT`.

Threat-coverage doc (`threat_coverage_doc`):

- `codegen_threat_coverage_doc_default(repo_root: &Path) -> Result<PathBuf, CodegenError>` -
  the canonical entry point; resolves every input path from `repo_root`.
- `codegen_threat_coverage_doc(inputs, out_path)`, `render_threat_coverage_doc(inputs)`,
  `ThreatCoverageInputs`.
- `ADVERSARIAL_MANIFEST`, `ESCAPE_HARNESS_DIR`, `THREAT_COVERAGE_DOC`, `THREAT_STUBS_DIR`.

Binary (`chio-spec-codegen`):

```text
chio-spec-codegen <schemas-dir> <out-dir>
chio-spec-codegen --errors-only
chio-spec-codegen --threat-model <input.json> --out <stubs-dir>
chio-spec-codegen --threat-model-doc [--repo-root <path>]
```

## Testing

`cargo test -p chio-spec-codegen`

This includes `tests/threat_model_schema_test.rs`, a dedicated
schema-conformance check on the checked-in `chio-threat-model.v1.json`
instance; CI runs it by name
(`cargo test -p chio-spec-codegen --test threat_model_schema_test`).

## See also

- `chio-spec-validate` - validates JSON instances against schemas; this
  crate generates code and docs from schemas instead.
- `chio-core-types` - holds the generated `src/_generated/chio_wire_v1.rs`
  output (quarantined, not yet part of the public API).
- `chio-errors` - holds the generated `error_codes.rs` output.
- `chio-conformance` - holds the generated per-threat stub tests under
  `tests/threats/`.
- `xtask` - drives the wire-type and error-registry passes
  (`cargo xtask codegen rust`, `cargo xtask errors regen`); see
  `xtask/src/codegen/rust.rs`.
