# Chio Protocol Historical Verifier Wording Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep active Chio protocol prose free of stale Chiodos verifier
wording while preserving literal deprecated schema IDs required for historical
verification.

**Architecture:** `spec/PROTOCOL.md` is an active Chio protocol document. It may
name deprecated wire IDs such as `chio.chiodos.proof-package.v1`, but live
assurance prose should use legacy-neutral verifier wording.

**Tech Stack:** Bash gate script, Markdown protocol spec, focused `rg` drift
checks.

---

### Task 1: Active Protocol Drift Gate

**Files:**
- Modify: `scripts/check-chio-live-treaty-buyer-closure.sh`
- Modify: `spec/PROTOCOL.md`
- Modify: `docs/architecture/CHIO_FINAL_ARCHITECTURE.md`

- [ ] **Step 1: Add failing gate**

Add a focused drift check in
`scripts/check-chio-live-treaty-buyer-closure.sh` that rejects stale Chiodos
verifier wording in `spec/PROTOCOL.md` without rejecting literal schema IDs.

- [ ] **Step 2: Run red**

Run: `bash scripts/check-chio-live-treaty-buyer-closure.sh --schema-only`

Expected: failure listing the current protocol prose references.

- [ ] **Step 3: Rewrite protocol prose**

Rewrite the active protocol paragraphs to use legacy-neutral predicate and
verifier language while preserving exact deprecated schema IDs.

- [ ] **Step 4: Run green**

Run: `bash scripts/check-chio-live-treaty-buyer-closure.sh --schema-only`

Expected: pass.

- [ ] **Step 5: Verify docs hygiene**

Run focused stale wording checks, unicode dash scans, and `git diff --check`.
