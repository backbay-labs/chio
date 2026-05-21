# Chio Treaty Negative Corpus Schema Cutover Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development and superpowers:verification-before-completion. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the active Chio treaty-bound provenance negative corpus off `chio.chiodos.*` and onto a Chio federation schema ID.

**Architecture:** Mutable active gate fixtures must use Chio-native schema IDs. Legacy `chio.chiodos.*` treaty corpus schemas remain read-compatible only for historical artifacts.

**Tech Stack:** JSON Schema, `spec/schemas/registry.json`, `spec/schemas/MANIFEST.sha256`, Bash gate scripts, `chio-spec-validate`.

---

### Task 1: Prove The Active Treaty Gate Still Uses A Legacy Corpus

**Files:**
- `scripts/check-chio-treaty-bound-provenance.sh`
- `spec/schemas/chio-federation/v1`

- [x] **Step 1: Prove the active Chio treaty gate still emits the legacy corpus ID**

Run:

```bash
if rg -n 'chio\.chiodos\.treaty-negative-fixture-corpus|legacy_schema_dir=.*/chiodos|legacy_schema_dir/.*/treaty-negative-fixture-corpus' scripts/check-chio-treaty-bound-provenance.sh; then
  echo "active Chio treaty gate still depends on the legacy treaty negative corpus schema" >&2
  exit 1
fi
```

Expected: fail before the cutover.

- [x] **Step 2: Prove the Chio federation corpus schema is missing**

Run:

```bash
test -f spec/schemas/chio-federation/v1/treaty-negative-fixture-corpus.schema.json
```

Expected: fail before the cutover.

### Task 2: Add The Chio Federation Corpus Schema

**Files:**
- Create: `spec/schemas/chio-federation/v1/treaty-negative-fixture-corpus.schema.json`
- Modify: `spec/schemas/registry.json`
- Modify: `spec/schemas/MANIFEST.sha256`

- [x] **Step 1: Add Chio schema ID**

Use:

```text
chio.federation.treaty-negative-fixture-corpus.v1
```

- [x] **Step 2: Register and manifest the schema**

Add an active `chio_federation_treaty_negative_fixture_corpus` registry entry and a matching manifest hash.

- [x] **Step 3: Preserve legacy read compatibility**

Do not delete the existing `spec/schemas/chiodos/v1/treaty-negative-fixture-corpus.schema.json` entry.

### Task 3: Cut The Active Treaty Gate To Chio Federation

**Files:**
- Modify: `scripts/check-chio-treaty-bound-provenance.sh`

- [x] **Step 1: Update generated negative corpus fixture**

The fixture must use `chio.federation.treaty-negative-fixture-corpus.v1`.

- [x] **Step 2: Validate against Chio federation schema directory**

The active Chio gate must validate the negative corpus against `spec/schemas/chio-federation/v1`.

### Task 4: Verify

**Files:**
- All files above

- [x] **Step 1: Run focused treaty gate modes**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-treaty-bound-provenance.sh --schema-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-treaty-bound-provenance.sh --negative-only
```

- [x] **Step 2: Run registry and hygiene checks**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-schema-registry.sh
bash -n scripts/check-chio-treaty-bound-provenance.sh
if rg -n 'chio\.chiodos\.treaty-negative-fixture-corpus|legacy_schema_dir=.*/chiodos|legacy_schema_dir/.*/treaty-negative-fixture-corpus' scripts/check-chio-treaty-bound-provenance.sh; then
  echo "active Chio treaty gate still depends on the legacy treaty negative corpus schema" >&2
  exit 1
fi
git diff --check
git diff --cached --check
rg -n $'\xE2\x80\x94|\xE2\x80\x93' docs/superpowers/plans/2026-05-21-chio-treaty-negative-corpus-schema-cutover.md scripts/check-chio-treaty-bound-provenance.sh spec/schemas/chio-federation/v1/treaty-negative-fixture-corpus.schema.json spec/schemas/registry.json spec/schemas/MANIFEST.sha256
```

Expected: all pass, except the dash scan exits 1 with no output.
