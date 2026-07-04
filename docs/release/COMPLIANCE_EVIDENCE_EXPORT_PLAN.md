# Compliance Evidence Export Plan

## Goal

Produce a turnkey export that a regulated operator can hand to an auditor and
independently verify without a running Chio node.

The first implementation target is a filesystem package generated from local
SQLite state. Remote trust-control export can follow the same manifest shape
later.

## Initial Implementation Boundary

This plan was the pulled-forward foundation work for the later roadmap item. The
first coding pass shipped:

- one CLI entry point for local export
- one package manifest format
- receipt, child-receipt, checkpoint, and capability-lineage export
- inclusion-proof generation for every exported tool receipt covered by a
  checkpoint
- retention metadata and export query metadata
- optional policy source attachment when the operator provides `--policy-file`

It still explicitly defers:

- remote trust-control export over HTTP
- automatic policy-source recovery when only `policy_hash` is known
- signed package attestations
- compression/encryption modes beyond plain directory or tarball output

## Proposed CLI

```sh
chio evidence export \
  --receipt-db receipts.sqlite3 \
  --output ./evidence-package \
  --since 1700000000 \
  --until 1700600000 \
  --policy-file ./policy.yaml
```

Optional follow-on flags:

- `--archive-db <path>` include archived receipts/checkpoints in the same package
- `--require-proofs` fail if any exported receipt is not covered by a checkpoint
- `--format dir|tar` output as directory (default) or tarball
- `--capability <id>` restrict export to one delegation chain
- `--agent-subject <key>` restrict export to one operator-visible principal

## Package Layout

```text
evidence-package/
  manifest.json
  receipts.ndjson
  child-receipts.ndjson
  checkpoints.ndjson
  capability-lineage.ndjson
  inclusion-proofs.ndjson
  retention.json
  query.json
  policy/
    source.yaml              # only when --policy-file is provided
    metadata.json
  README.txt
```

## Manifest Contents

`manifest.json` should include:

- package schema version
- generated-at timestamp
- host/kernel public key if available
- receipt database path basename
- archive database basename when used
- query scope (`since`, `until`, `capabilityId`, `agentSubject`)
- counts for each exported artifact
- proof coverage summary:
  - receipts covered by checkpoint proof
  - receipts not yet checkpointed
- hashes of every emitted file

## Data Acquisition Plan

### Receipts

- Reuse `SqliteReceiptStore::query_receipts` for scoped tool receipts.
- Add a child-receipt query path in the exporter module so nested-flow audit
  records are not dropped from the package.

### Checkpoints

- Add a receipt-store helper to list checkpoints whose batches intersect the
  exported receipt seq range.
- Export the signed checkpoint statement and signature exactly as stored.

### Inclusion proofs

- For each exported tool receipt, locate the checkpoint batch covering its seq.
- Rebuild the Merkle leaf set for that checkpoint batch from stored receipt
  bytes.
- Call `build_inclusion_proof` and emit one NDJSON record containing:
  - receipt id
  - seq
  - checkpoint seq
  - leaf index
  - proof path
  - checkpoint root
- If no checkpoint covers the receipt:
  - include a manifest count under `uncheckpointed_receipts`
  - fail only when `--require-proofs` is set

### Policy attachment

- Chio receipts persist `policy_hash`, but not the source policy artifact.
- The first exporter version should accept `--policy-file` and emit:
  - raw source file
  - source hash
  - runtime hash if the CLI can load it through the existing policy loader
- If no policy file is supplied, the package must still export the `policy_hash`
  values already embedded in receipts and checkpoints.

### Retention metadata

- Export the active retention configuration used for the live DB when known.
- If exporting against an archive DB, include archive path metadata and a note
  that records remain verifiable post-rotation.

## Suggested Code Layout

- `crates/kernel/chio-kernel/src/evidence_export.rs`
  - package manifest types
  - inclusion-proof record types
  - local SQLite export helpers
- `crates/products/chio-cli`
  - CLI orchestration
  - output directory/tar writing
  - policy-file attachment handling
- `crates/products/chio-cli/src/main.rs`
  - new `evidence export` subcommand wiring

## Acceptance Criteria For The First Coding Pass

- a local operator can generate a complete evidence package from SQLite
- every exported receipt either has an inclusion proof or is explicitly marked
  uncheckpointed
- package contents verify against stored checkpoint signatures
- nested-flow child receipts are included
- docs explain how the package maps to the Colorado and EU compliance documents

## Immediate Follow-On After First Implementation

1. Add remote trust-control export over authenticated HTTP.
2. Add package verification tooling (`chio evidence verify`).
3. Add signed package manifests for chain-of-custody workflows.
4. Add compliance-specific report views on top of the exported package.

## Tenant-Scoped Disclosure

Tenant-scoped evidence exports (`chio evidence export --tenant <id>`) carry an
explicit `disclosureNotice` field on the manifest with schema
`chio.evidence_export_disclosure_notice.v1`. The notice documents which
cross-tenant aggregate fields the exported checkpoint set inherently reveals.
Admin-all exports do not attach the notice because the operator already
requested cross-tenant visibility.

### What is disclosed and why

`KernelCheckpointBody` is signed by the kernel and covers the full per-batch
Merkle tree. Inclusion-proof verification against the signed checkpoint root
requires the body fields to remain authentic. As a result, even an export
scoped to one tenant retains the following signed-body fields:

- `batch_start_seq`, `batch_end_seq`: full batch seq range across all tenants
- `tree_size`: number of leaves in the batch's Merkle tree (cross-tenant
  count)
- `merkle_root`: the signed root that authenticates the entire batch
- `checkpoint_seq`, `issued_at`, `previous_checkpoint_sha256`: chain identity
  and timing across the cross-tenant checkpoint stream

`CheckpointPublication` records (`checkpoint-publications.ndjson`) mirror
these fields as `entry_start_seq`, `entry_end_seq`, and `log_tree_size`.
Verifiers re-derive them from the signed checkpoint body, so omitting the
file would not narrow the disclosure surface; the published copies are kept
for deterministic verifier ergonomics.

### What is narrowed

- `retention.liveDbSizeBytes` is omitted in tenant-scoped exports because the
  live database aggregates all tenants. It is only populated in admin-all
  exports.
- `retention.oldestLiveReceiptTimestamp` is restricted to the requesting
  tenant's receipts.

### Why option (b) instead of option (a)

A truly cross-tenant-isolated export would require protocol-level per-tenant
subtree proofs (option (a)). The SQLite store does not currently track
tenant-scoped subtree roots, so option (a) cannot be implemented without a
schema and protocol change. Until that lands, tenant exports use option (b):
narrow what is narrowable (retention metadata) and document the inherent
disclosure boundary with a structured, verifiable notice.

The verifier enforces that:

- a tenant-scoped manifest MUST carry the disclosure notice
- an admin-all manifest MUST NOT carry a tenant-scoped disclosure notice
- the notice content MUST match the canonical disclosure boundary for the
  current protocol version (tampering or selective omission is rejected)
