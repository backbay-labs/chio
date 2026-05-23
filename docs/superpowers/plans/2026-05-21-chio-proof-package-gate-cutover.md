# Chio Proof Package Gate Cutover Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the proof-package release gate from `check-chio-proof-package.sh` and the active `chio-proof-package` workflow to Chio-named ownership.

**Architecture:** `scripts/check-chio-proof-package.sh` is the active gate. It validates the committed Chio fixture tree under `examples/chio-3vendor/fixtures`, keeps the explicit legacy proof-package and verifier-report schemas where those artifact schemas remain named `Chio-native schema IDs`, uses Chio federation and Chio attest schemas for renamed trust/context/negative corpus artifacts, and runs public Chio CLI verification through `chio attest buyer verify-proof`. The Chio-named script and workflow may remain only as manual compatibility wrappers.

**Tech Stack:** Bash gate scripts, Python fixture assertions, `chio-spec-validate`, Chio CLI attest verification, Cargo test filters, GitHub Actions workflow YAML.

---

### Task 1: Add Red Drift Checks

**Files:**
- Create: `scripts/check-chio-proof-package.sh`
- Modify: `scripts/check-chio-proof-package.sh`
- Create: `.github/workflows/chio-proof-package.yml`
- Modify: `.github/workflows/chio-proof-package.yml`

- [x] **Step 1: Prove the Chio proof package gate is missing**

Run:

```bash
test -x scripts/check-chio-proof-package.sh
```

Expected: fail because the Chio-owned proof-package gate does not exist.

- [x] **Step 2: Prove the old proof package path still owns active implementation**

Run:

```bash
if rg -n 'examples/chio-3vendor|check-chio-authority-issuance|generate-chio-proof-package|cargo test -p chio-cli chio|scripts/check-chio-proof-package.sh' scripts/check-chio-proof-package.sh .github/workflows/chio-proof-package.yml; then
  echo "legacy proof-package gate still owns active implementation" >&2
  exit 1
fi
```

Expected: fail because the old script and workflow still point at Chio fixture paths, Chio helper scripts, old generator names, and active old CI.

### Task 2: Add Chio-Owned Proof Package Gate

**Files:**
- Create: `scripts/check-chio-proof-package.sh`

- [x] **Step 1: Implement mode parsing**

Support:

```text
--schema-only
--negative-only
```

Default mode validates schemas and metadata, runs focused proof package tests, validates authority issuance, verifies the committed Chio proof package, and runs the negative corpus.

- [x] **Step 2: Point the active gate at Chio fixtures and helpers**

Use:

```bash
examples/chio-3vendor/fixtures
scripts/check-chio-authority-issuance.sh
cargo run -p chio-three-vendor-example --bin generate-chio-three-vendor-fixtures
```

The package crate name is still historical; the active binary and fixture paths must be Chio-named.

- [x] **Step 3: Preserve explicit legacy proof artifact boundaries**

Keep legacy Chio schema validation only for the artifact schemas that are still explicitly named legacy proof artifacts:

```bash
spec/schemas/chio-attest/v1/selective-disclosure-proof.schema.json
spec/schemas/chio-attest/v1/proof-package.schema.json
spec/schemas/chio-attest/v1/verifier-report.schema.json
```

Use Chio federation and Chio attest schema directories for trust bundle, verification context, authority, and negative corpus files.

### Task 3: Convert Old Entrypoints To Compatibility Wrappers

**Files:**
- Modify: `scripts/check-chio-proof-package.sh`
- Create: `.github/workflows/chio-proof-package.yml`
- Modify: `.github/workflows/chio-proof-package.yml`

- [x] **Step 1: Replace old script implementation with delegation**

Make the file delegate to `scripts/check-chio-proof-package.sh`.

- [x] **Step 2: Add active Chio workflow**

Create a Chio-named workflow that invokes:

```bash
bash scripts/check-chio-proof-package.sh
```

- [x] **Step 3: Disable old workflow as active CI**

Make `.github/workflows/chio-proof-package.yml` manual-only and delegate to the Chio script.

### Task 4: Verify

**Files:**
- All files above

- [x] **Step 1: Run focused proof package modes**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-proof-package.sh --schema-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-proof-package.sh --negative-only
```

- [x] **Step 2: Run wrapper compatibility and default gates**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-proof-package.sh --schema-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-proof-package.sh
```

- [x] **Step 3: Run drift and hygiene checks**

Run:

```bash
bash -n scripts/check-chio-proof-package.sh scripts/check-chio-proof-package.sh
test -x scripts/check-chio-proof-package.sh
if rg -n 'examples/chio-3vendor|check-chio-authority-issuance|generate-chio-proof-package|cargo test -p chio-cli chio' scripts/check-chio-proof-package.sh; then
  echo "Chio proof-package gate still points at Chio implementation paths" >&2
  exit 1
fi
if rg -n 'pull_request:|push:' .github/workflows/chio-proof-package.yml; then
  echo "legacy proof-package workflow is still active on PR or push" >&2
  exit 1
fi
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo fmt --all -- --check
git diff --check
rg -n $'\xE2\x80\x94|\xE2\x80\x93' docs/superpowers/plans/2026-05-21-chio-proof-package-gate-cutover.md scripts/check-chio-proof-package.sh scripts/check-chio-proof-package.sh .github/workflows/chio-proof-package.yml .github/workflows/chio-proof-package.yml
```

Expected: all pass, except the dash scan exits 1 with no output.
