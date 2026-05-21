# Chio Live Treaty DSSE Filter Cutover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep the live treaty buyer closure gate aligned with the Chio-named
strict DSSE signer test.

**Architecture:** Active Chio gates should select Chio-named tests. Historical
test names must not make a zero-match filter look like successful validation.

**Tech Stack:** Bash gate script and architecture evidence.

---

### Task 1: Live Treaty DSSE Test Filter

**Files:**
- Modify: `scripts/check-chio-live-treaty-buyer-closure.sh`
- Modify: `docs/architecture/CHIO_FINAL_ARCHITECTURE.md`

- [x] **Step 1: Capture failing gate**

Run: `bash scripts/check-chio-live-treaty-buyer-closure.sh`

Observed: the gate fails because
`strict_chiodos_signer_binds_treaty_runtime_refs` matches zero tests in
`chio-federation`.

- [x] **Step 2: Update gate filter**

Change the DSSE gate filter to the Chio-named
`strict_chio_signer_binds_treaty_runtime_refs` test.

- [x] **Step 3: Run green**

Run: `bash scripts/check-chio-live-treaty-buyer-closure.sh`

- [x] **Step 4: Verify hygiene**

Run `git diff --check` and touched-file unicode dash scans.
