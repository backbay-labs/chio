# Chio Wire Schema Wording Boundary

## Goal

Prevent active Chio schema files from exposing stale Chiodos wording in
titles, descriptions, or other schema text.

## Scope

- `scripts/check-chio-schema-registry.sh`
- `spec/schemas/chio-wire/v1/federation/bilateral-signature-slice.schema.json`
- `spec/schemas/MANIFEST.sha256`
- `docs/architecture/CHIO_FINAL_ARCHITECTURE.md`

## Red Test

- Extend `scripts/check-chio-schema-registry.sh` with an active Chio schema text
  hygiene scan that includes `spec/schemas/chio-wire/`.
- The gate should fail on the current bilateral signature-slice description
  because it still says `CHIODOS`.

## Implementation

- Rewrite the active schema description to Chio/legacy-neutral wording.
- Refresh the manifest hash for the touched schema file.

## Verification

- `bash scripts/check-chio-schema-registry.sh`
- Focused stale-wording grep over active Chio schema roots.
- `git diff --check`
