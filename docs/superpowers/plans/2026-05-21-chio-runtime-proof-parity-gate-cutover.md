# Chio Runtime Proof Parity Gate Cutover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move runtime proof parity validation to a Chio-named script and workflow while preserving explicit historical fixture tests.

**Architecture:** The active gate must be `scripts/check-chio-runtime-proof-parity.sh`. It delegates runtime fixture, regeneration, parity, and negative coverage through Chio-owned runtime-spine validation and Chio runtime CLI tests. The only Chiodos-named package allowed inside the new gate is `chiodos-three-vendor-example`, because that package owns historical fixture generation. Legacy Chiodos proof schemas and `chio attest legacy chiodos-v1 verify` are allowed only for schema compatibility and verifier replay of those generated fixtures.

**Tech Stack:** Bash gate scripts, GitHub Actions workflow YAML, Cargo test filters, Chio runtime-spine gate.

---

### Task 1: Add Red Drift Checks

**Files:**
- Create: `scripts/check-chio-runtime-proof-parity.sh`
- Modify: `scripts/check-chiodos-runtime-proof-parity.sh`
- Create: `.github/workflows/chio-runtime-proof-parity.yml`
- Modify: `.github/workflows/chiodos-runtime-proof-parity.yml`

- [x] **Step 1: Prove the Chio runtime proof parity gate is missing**

Run:

```bash
test -x scripts/check-chio-runtime-proof-parity.sh
```

Expected: fail because the active Chio-named runtime proof parity gate does not exist.

- [x] **Step 2: Prove the old runtime proof parity path still owns implementation**

Run:

```bash
if rg -n 'check-chiodos-runtime-(proof-parity|spine)|spec/schemas/chiodos|chiodos_runtime' scripts/check-chiodos-runtime-proof-parity.sh .github/workflows/chiodos-runtime-proof-parity.yml; then
  echo "legacy runtime proof parity gate still owns Chiodos implementation" >&2
  exit 1
fi
```

Expected: fail because the old script and workflow still call Chiodos gate names, Chiodos runtime CLI filters, and Chiodos schema paths.

### Task 2: Add Chio-Owned Runtime Proof Parity Gate

**Files:**
- Create: `scripts/check-chio-runtime-proof-parity.sh`

- [x] **Step 1: Implement mode parsing**

Support:

```text
--schema-only
--negative-only
--regenerate-only
--parity-only
--fixtures-only
```

Default mode runs focused proof tests, historical fixture compatibility tests, focused Chio runtime CLI tests, and the full Chio runtime-spine gate.

- [x] **Step 2: Route runtime-spine modes through Chio gate**

Use:

```bash
bash "$repo_root/scripts/check-chio-runtime-spine.sh" --schema-only
bash "$repo_root/scripts/check-chio-runtime-spine.sh" --negative-only
bash "$repo_root/scripts/check-chio-runtime-spine.sh"
```

- [x] **Step 3: Add zero-match-safe focused test runner**

Use a local `run_cargo_test_filter` helper that fails if cargo returns no nonzero passed test result for a filtered command.

- [x] **Step 4: Run focused proof parity tests**

Use Chio runtime ownership filters:

```bash
cargo test -p chio-chiodos-runtime runtime_workflow_report
cargo test -p chio-chiodos-runtime proof_regeneration_report
cargo test -p chio-chiodos-runtime runtime_proof_regeneration
cargo test -p chio-cli --bin chio chio_runtime
```

- [x] **Step 5: Preserve historical fixture compatibility tests**

Keep:

```bash
cargo run -p chiodos-three-vendor-example --bin generate-chio-three-vendor-fixtures -- --out-dir "$tmpdir/fixtures"
cargo run -p chio-spec-validate -- "$repo_root/spec/schemas/chiodos/v1/proof-package.schema.json" "$tmpdir/fixtures/buyer-auditor-proof-package.json"
cargo run -p chio-spec-validate -- "$repo_root/spec/schemas/chio-federation/v1/verifier-trust-bundle.schema.json" "$tmpdir/fixtures/verifier-trust-bundle.json"
cargo run -p chio-cli --bin chio -- attest legacy chiodos-v1 verify --package "$tmpdir/fixtures/buyer-auditor-proof-package.json" --trust-bundle "$tmpdir/fixtures/verifier-trust-bundle.json" --context "$tmpdir/fixtures/verification-context.json" --report "$tmpdir/fixtures/verifier-report-rerun.json"
```

This is an explicit historical fixture exception, not active Chiodos command ownership.

### Task 3: Convert The Old Script To A Wrapper

**Files:**
- Modify: `scripts/check-chiodos-runtime-proof-parity.sh`

- [x] **Step 1: Replace old implementation with delegation**

Make the file:

```bash
#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$repo_root/scripts/check-chio-runtime-proof-parity.sh" "$@"
```

### Task 4: Rename The Workflow

**Files:**
- Create: `.github/workflows/chio-runtime-proof-parity.yml`
- Modify: `.github/workflows/chiodos-runtime-proof-parity.yml`

- [x] **Step 1: Add active Chio workflow**

Create a Chio-named workflow that watches Chio runtime and attest schemas, Chio runtime gates, runtime crates, CLI, kernel, Chio fixtures, and the historical fixture package. Invoke:

```bash
bash scripts/check-chio-runtime-proof-parity.sh
```

- [x] **Step 2: Disable the old workflow as active CI**

Make the old workflow manual-only and delegate to the Chio-named gate. It should not run on pull requests or pushes.

### Task 5: Verify

**Files:**
- All files above

- [x] **Step 1: Run focused gates**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-proof-parity.sh --schema-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-proof-parity.sh --parity-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-proof-parity.sh --fixtures-only
```

- [x] **Step 2: Run compatibility wrapper check**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chiodos-runtime-proof-parity.sh --schema-only
```

- [x] **Step 3: Run default workflow-equivalent gate**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-runtime-proof-parity.sh
```

- [x] **Step 4: Run drift and hygiene checks**

Run:

```bash
test -x scripts/check-chio-runtime-proof-parity.sh
if rg -n 'check-chiodos-runtime-(proof-parity|spine)|spec/schemas/chiodos/v1/runtime|chiodos_runtime' scripts/check-chio-runtime-proof-parity.sh; then
  echo "Chio runtime proof parity gate still points at Chiodos runtime implementation paths" >&2
  exit 1
fi
if rg -n 'pull_request:|push:' .github/workflows/chiodos-runtime-proof-parity.yml; then
  echo "legacy runtime proof parity workflow is still active on PR or push" >&2
  exit 1
fi
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo fmt --all -- --check
git diff --check
rg -n $'\xE2\x80\x94|\xE2\x80\x93' docs/superpowers/plans/2026-05-21-chio-runtime-proof-parity-gate-cutover.md scripts/check-chio-runtime-proof-parity.sh scripts/check-chiodos-runtime-proof-parity.sh .github/workflows/chio-runtime-proof-parity.yml .github/workflows/chiodos-runtime-proof-parity.yml
```

Expected: all pass, except the dash scan exits 1 with no output.
