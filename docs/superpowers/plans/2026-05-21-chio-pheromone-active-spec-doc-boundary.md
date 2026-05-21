# Chio Pheromone Active Spec Doc Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep the active Chio pheromone spec Chio-native by preventing
Chiodos-named citations outside archive or migration notes.

**Architecture:** `spec/CHIO_PHEROMONE.md` is an active Chio contract, not an
archive note. Historical research can remain in archive docs, but active Chio
spec prose should use Chio-native design-source wording and deprecated-id
language rather than named Chiodos sources.

**Tech Stack:** Bash gate script, Markdown spec, focused `rg` drift checks.

---

### Task 1: Active Spec Drift Gate

**Files:**
- Modify: `scripts/check-chio-pheromone-transit.sh`
- Modify: `spec/CHIO_PHEROMONE.md`
- Modify: `docs/architecture/CHIO_FINAL_ARCHITECTURE.md`

- [ ] **Step 1: Add failing gate**

Add a grep check in `scripts/check-chio-pheromone-transit.sh` that rejects
`Chiodos`, `CHIODOS`, or `chiodos` in `spec/CHIO_PHEROMONE.md`.

- [ ] **Step 2: Run red**

Run: `bash scripts/check-chio-pheromone-transit.sh --schema-only`

Expected: failure listing the current Chiodos-named references in the active
spec.

- [ ] **Step 3: Rewrite active spec**

Rewrite `spec/CHIO_PHEROMONE.md` so design-source and legacy references use
Chio-native wording, deprecated-id wording, or archive-neutral descriptions.

- [ ] **Step 4: Run green**

Run: `bash scripts/check-chio-pheromone-transit.sh --schema-only`

Expected: pass.

- [ ] **Step 5: Verify docs hygiene**

Run focused `rg` and unicode dash scans on touched files plus `git diff
--check`.
