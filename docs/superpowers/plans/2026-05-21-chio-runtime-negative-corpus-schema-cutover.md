# Chio Runtime Negative Corpus Schema Cutover Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development and superpowers:verification-before-completion. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move active Chio runtime ops and orchestration negative-corpus validation off mutable `chio.chiodos.*` schemas and onto Chio-runtime schema IDs.

**Architecture:** New emitted artifacts must use Chio-native schema IDs where permitted. `chio.chiodos.*` runtime schemas remain readable only for deprecated historical compatibility. Runtime proof verifier reports may continue to use explicit historical verifier schema IDs when they represent byte-preserving legacy proof verification.

**Tech Stack:** JSON Schema, `spec/schemas/registry.json`, `spec/schemas/MANIFEST.sha256`, Bash gate scripts, `chio-spec-validate`, Chio CLI runtime gates.

---

### Task 1: Prove Active Gates Still Depend On Legacy Mutable Runtime Schemas

**Files:**
- `scripts/check-chio-runtime-ops-hardening.sh`
- `scripts/check-chio-runtime-orchestration.sh`
- `spec/schemas/chio-runtime/v1`

- [x] **Step 1: Prove active Chio scripts still emit legacy negative/failure schema IDs**

Run:

```bash
if rg -n 'chio\.chiodos\.runtime-(ops-negative-fixture-corpus|failure-code-registry|orchestration-negative-fixture-corpus)' scripts/check-chio-runtime-ops-hardening.sh scripts/check-chio-runtime-orchestration.sh; then
  echo "active Chio runtime gates still emit legacy mutable runtime schemas" >&2
  exit 1
fi
```

Expected: fail before the cutover.

- [x] **Step 2: Prove Chio-runtime replacements are missing**

Run:

```bash
test -f spec/schemas/chio-runtime/v1/ops-negative-fixture-corpus.schema.json
test -f spec/schemas/chio-runtime/v1/failure-code-registry.schema.json
test -f spec/schemas/chio-runtime/v1/orchestration-negative-fixture-corpus.schema.json
```

Expected: fail before the cutover.

### Task 2: Add Chio-Runtime Schema Replacements

**Files:**
- Create: `spec/schemas/chio-runtime/v1/ops-negative-fixture-corpus.schema.json`
- Create: `spec/schemas/chio-runtime/v1/failure-code-registry.schema.json`
- Create: `spec/schemas/chio-runtime/v1/orchestration-negative-fixture-corpus.schema.json`
- Modify: `spec/schemas/registry.json`
- Modify: `spec/schemas/MANIFEST.sha256`

- [x] **Step 1: Add Chio schema IDs**

Use:

```text
chio.runtime.ops-negative-fixture-corpus.v1
chio.runtime.failure-code-registry.v1
chio.runtime.orchestration-negative-fixture-corpus.v1
```

- [x] **Step 2: Register the Chio schemas**

Add active registry entries with `chio_runtime_*` artifact kinds and Chio-runtime schema files.

- [x] **Step 3: Keep legacy schemas read-compatible**

Do not delete the existing `spec/schemas/chiodos/v1` entries. They remain historical readers.

### Task 3: Cut Active Runtime Gates To Chio Schemas

**Files:**
- Modify: `scripts/check-chio-runtime-ops-hardening.sh`
- Modify: `scripts/check-chio-runtime-orchestration.sh`

- [x] **Step 1: Update runtime ops fixture documents**

`negative-corpus.json` and `failure-code-registry.json` must use `chio.runtime.*` schema IDs and validate against `spec/schemas/chio-runtime/v1`.

- [x] **Step 2: Update runtime orchestration negative corpus**

`negative-corpus.json` must use `chio.runtime.orchestration-negative-fixture-corpus.v1` and validate against `spec/schemas/chio-runtime/v1`.

- [x] **Step 3: Preserve historical proof verifier schema**

Do not rename `chio.chiodos.verifier-report.v2` inside generated verifier-report fixtures in this pass. That is historical verifier evidence, not a mutable active Chio runtime corpus.

### Task 4: Verify

**Files:**
- All files above

- [x] **Step 1: Run focused Chio runtime schema modes**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-ops-hardening.sh --schema-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-ops-hardening.sh --negative-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-ops-hardening.sh --failure-codes-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-orchestration.sh --schema-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-orchestration.sh --negative-only
```

- [x] **Step 2: Run schema registry and script hygiene checks**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-schema-registry.sh
bash -n scripts/check-chio-runtime-ops-hardening.sh scripts/check-chio-runtime-orchestration.sh
if rg -n 'chio\.chiodos\.runtime-(ops-negative-fixture-corpus|failure-code-registry|orchestration-negative-fixture-corpus)|legacy_schema_dir=.*/chiodos|legacy_schema_dir/.*/runtime-(ops-negative-fixture-corpus|failure-code-registry|orchestration-negative-fixture-corpus)' scripts/check-chio-runtime-ops-hardening.sh scripts/check-chio-runtime-orchestration.sh; then
  echo "active Chio runtime gates still depend on legacy mutable runtime schemas" >&2
  exit 1
fi
git diff --check
rg -n $'\xE2\x80\x94|\xE2\x80\x93' docs/superpowers/plans/2026-05-21-chio-runtime-negative-corpus-schema-cutover.md scripts/check-chio-runtime-ops-hardening.sh scripts/check-chio-runtime-orchestration.sh spec/schemas/chio-runtime/v1/ops-negative-fixture-corpus.schema.json spec/schemas/chio-runtime/v1/failure-code-registry.schema.json spec/schemas/chio-runtime/v1/orchestration-negative-fixture-corpus.schema.json spec/schemas/registry.json spec/schemas/MANIFEST.sha256
```

Expected: all pass, except the dash scan exits 1 with no output.
