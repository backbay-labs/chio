# Chio Attest Negative Corpus Cutover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the active Chio buyer proof negative fixture corpus off the historical Chiodos schema ID without rewriting signed proof artifacts.

**Architecture:** The active `examples/chio-3vendor` negative corpus is mutable test policy material, not byte-preserving signed history. It should validate against a Chio attest schema and use Chio-native names, while historical proof packages and verifier reports remain readable only through explicit legacy verification.

**Tech Stack:** Bash, JSON Schema, `chio-spec-validate`, Chio schema registry, manifest hash gate.

---

### Task 1: Add Active Fixture Red Gate

**Files:**
- Create: `scripts/check-chio-attest-buyer-fixtures.sh`

- [ ] **Step 1: Add the failing gate**

Create a shell gate that scans `examples/chio-3vendor/fixtures/negative-cases.json` for `chio.chiodos`, `chiodos_`, and `chiodos:` and validates it against `spec/schemas/chio-attest/v1/buyer-proof-negative-fixture-corpus.schema.json`.

- [ ] **Step 2: Verify red**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-attest-buyer-fixtures.sh
```

Expected: fail because the active fixture still uses `chio.chiodos.negative-fixture-corpus.v1`.

### Task 2: Cut Active Negative Corpus To Chio

**Files:**
- Create: `spec/schemas/chio-attest/v1/buyer-proof-negative-fixture-corpus.schema.json`
- Modify: `examples/chio-3vendor/fixtures/negative-cases.json`
- Modify: `spec/schemas/registry.json`
- Modify: `spec/schemas/MANIFEST.sha256`

- [ ] **Step 1: Add Chio schema**

Define `chio.attest.buyer-proof-negative-fixture-corpus.v1` with required `schema`, `cases`, `id`, `target`, `mutation`, and `expectedFailureCode`.

- [ ] **Step 2: Convert fixture**

Change the fixture schema ID to `chio.attest.buyer-proof-negative-fixture-corpus.v1` and replace active Chiodos consistency/workflow strings with Chio equivalents.

- [ ] **Step 3: Register and manifest**

Add a registry entry with Chio-native `artifactKind` and add the schema file hash to `spec/schemas/MANIFEST.sha256`.

### Task 3: Verify Focused Gates

**Files:**
- Modify: files from Tasks 1 and 2 only

- [ ] **Step 1: Run focused gate**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-attest-buyer-fixtures.sh
```

Expected: pass.

- [ ] **Step 2: Run schema registry and hygiene**

Run:

```bash
bash scripts/check-chio-schema-registry.sh
cargo fmt --all -- --check
git diff --check
rg -n $'\xE2\x80\x94|\xE2\x80\x93' scripts/check-chio-attest-buyer-fixtures.sh spec/schemas/chio-attest/v1/buyer-proof-negative-fixture-corpus.schema.json examples/chio-3vendor/fixtures/negative-cases.json spec/schemas/registry.json spec/schemas/MANIFEST.sha256
```

Expected: registry and formatting pass; dash scan exits 1 with no matches.
