# chio-runtime-harness Architecture

## Boundary

`chio-runtime-harness` drives live runtime loopback scenarios through admission, kernel execution, treaty context construction, proof assembly, and evidence output. It is a test and tooling crate, but it still owns security-sensitive evidence shape because its artifacts are consumed as regenerated proof material.

The harness coordinates existing runtime, kernel, and proof primitives. It does not define production kernel policy, mutate persistent stores, or create new protocol schemas. Its job is to make fixture execution reproducible and to write evidence that downstream verifiers can consume.

## Scenario Model

Scenario normalization accepts exactly one input shape: either the top-level single-step single-step fields or the explicit `steps` list. The harness rejects ambiguous mixed scenarios so a fixture cannot carry ignored top-level admission data while executing a different step list.

Each step carries an admission profile, admission bundle, runtime request binding, and optional tool arguments. The harness preserves step order because later proof assembly and receipt binding depend on deterministic scenario replay.

## Evidence Output

Evidence output is written through the local JSON helpers. Those helpers canonicalize hashes where needed, record manifest entries, and reject unsafe relative paths before writing artifacts below the output directory.

Output paths must be plain relative paths under the selected evidence directory. Absolute paths, parent traversal, duplicate separators, Windows drive prefixes, and backslash paths are rejected before any write happens.

## Invariants

- Scenario run ids must be non-empty and unpadded.
- Top-level single-step inputs and explicit step lists are mutually exclusive.
- Evidence hashes are derived from the exact bytes written.
- Manifest entries record role, relative path, SHA-256, and byte count.
- Harness failures must stop fixture generation rather than producing partial trusted evidence.
