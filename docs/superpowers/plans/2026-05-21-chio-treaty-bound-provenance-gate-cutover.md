# Chio Treaty-Bound Provenance Gate Cutover Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move treaty-bound provenance validation to `scripts/check-chio-treaty-bound-provenance.sh` and a Chio-named workflow.

**Architecture:** The active gate must use Chio federation schemas for treaty scope, ladders, continuations, lineage, bilateral invocation, ladder intersections, and cross-boundary admission reports; Chio attest schemas for buyer packets and packet verification reports; and public `chio federation treaty ...` commands. The Chio-named script and workflow may remain only as compatibility wrappers. Legacy Chio schema references are allowed only for the local `treaty-negative-fixture-corpus.schema.json` exception until it has a Chio replacement.

**Tech Stack:** Bash gate scripts, Chio federation schemas, Chio attest schemas, Chio CLI federation treaty commands, GitHub Actions workflow YAML.

---

### Task 1: Add Red Drift Checks

**Files:**
- Create: `scripts/check-chio-treaty-bound-provenance.sh`
- Modify: `scripts/check-chio-treaty-bound-provenance.sh`
- Create: `.github/workflows/chio-treaty-bound-provenance.yml`
- Modify: `.github/workflows/chio-treaty-bound-provenance.yml`

- [x] **Step 1: Prove the Chio treaty provenance gate is missing**

Run:

```bash
test -x scripts/check-chio-treaty-bound-provenance.sh
```

Expected: fail because the Chio-named treaty provenance gate does not exist.

- [x] **Step 2: Prove the old treaty provenance path still owns active implementation**

Run:

```bash
if rg -n 'retired-federation-schema-prefix|retired-attest-schema-prefix|scripts/check-chio-treaty-bound-provenance.sh' scripts/check-chio-treaty-bound-provenance.sh .github/workflows/chio-treaty-bound-provenance.yml; then
  echo "legacy treaty provenance gate still owns active implementation" >&2
  exit 1
fi
```

Expected: fail because the old script owns Chio treaty schemas and the old workflow is active.

### Task 2: Add Chio-Owned Treaty Provenance Gate

**Files:**
- Create: `scripts/check-chio-treaty-bound-provenance.sh`

- [x] **Step 1: Implement Chio federation and attest fixture schemas**

Use Chio schema values such as:

```text
chio.federation.governance-ladder-manifest.v1
chio.federation.treaty-scope.v1
chio.federation.cross-kernel-continuation.v1
chio.federation.receipt-lineage-statement.v1
chio.federation.bilateral-invocation.v1
chio.attest.buyer-attestation-packet.v1
```

- [x] **Step 2: Validate against Chio schema files**

Use `spec/schemas/chio-federation/v1` for treaty/federation artifacts and `spec/schemas/chio-attest/v1` for buyer attestation packet artifacts.

- [x] **Step 3: Preserve the legacy-only negative corpus exception**

Use `spec/schemas/chio-federation/v1/treaty-negative-fixture-corpus.schema.json` only for the local negative corpus fixture.

### Task 3: Convert Old Entrypoints To Compatibility Wrappers

**Files:**
- Modify: `scripts/check-chio-treaty-bound-provenance.sh`
- Create: `.github/workflows/chio-treaty-bound-provenance.yml`
- Modify: `.github/workflows/chio-treaty-bound-provenance.yml`

- [x] **Step 1: Replace old script implementation with delegation**

Make the old script delegate to `scripts/check-chio-treaty-bound-provenance.sh`.

- [x] **Step 2: Add active Chio workflow**

Create a Chio-named workflow that invokes:

```bash
bash scripts/check-chio-treaty-bound-provenance.sh
```

- [x] **Step 3: Disable old workflow as active CI**

Make the old workflow manual-only and delegate to the Chio script.

### Task 4: Verify

**Files:**
- All files above

- [x] **Step 1: Run focused modes**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-treaty-bound-provenance.sh --schema-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-treaty-bound-provenance.sh --negative-only
```

- [x] **Step 2: Run wrapper and default gates**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-treaty-bound-provenance.sh --schema-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-treaty-bound-provenance.sh
```

- [x] **Step 3: Run drift and hygiene checks**

Run:

```bash
bash -n scripts/check-chio-treaty-bound-provenance.sh scripts/check-chio-treaty-bound-provenance.sh
test -x scripts/check-chio-treaty-bound-provenance.sh
if rg -n 'chio\\.chio\\.(governance-ladder|treaty-scope|cross-kernel|receipt-lineage|bilateral|buyer-attestation)|check-chio-treaty-bound-provenance' scripts/check-chio-treaty-bound-provenance.sh; then
  echo "Chio treaty provenance gate still points at Chio implementation paths" >&2
  exit 1
fi
if rg -n 'pull_request:|push:' .github/workflows/chio-treaty-bound-provenance.yml; then
  echo "legacy treaty provenance workflow is still active on PR or push" >&2
  exit 1
fi
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo fmt --all -- --check
git diff --check
rg -n $'\xE2\x80\x94|\xE2\x80\x93' docs/superpowers/plans/2026-05-21-chio-treaty-bound-provenance-gate-cutover.md scripts/check-chio-treaty-bound-provenance.sh scripts/check-chio-treaty-bound-provenance.sh .github/workflows/chio-treaty-bound-provenance.yml .github/workflows/chio-treaty-bound-provenance.yml
```

Expected: all pass, except the dash scan exits 1 with no output.
