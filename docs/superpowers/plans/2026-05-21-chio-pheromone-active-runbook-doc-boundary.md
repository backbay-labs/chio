# Chio Pheromone Active Runbook Doc Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep the active Chio pheromone relay runbook free of Chiodos-named
public-doc wording.

**Architecture:** The active runbook should teach Chio operator commands only.
Legacy command information belongs in compatibility notes, not in the active
operator runbook.

**Tech Stack:** Bash gate script, Markdown runbook, focused `rg` drift checks.

---

### Task 1: Active Runbook Drift Gate

**Files:**
- Modify: `scripts/check-chio-pheromone-relay.sh`
- Modify: `docs/release/CHIO_PHEROMONE_RELAY_RUNBOOK.md`
- Modify: `docs/architecture/CHIO_FINAL_ARCHITECTURE.md`

- [ ] **Step 1: Add failing gate**

Add a grep check in `scripts/check-chio-pheromone-relay.sh` that rejects
`Chiodos`, `CHIODOS`, or `chiodos` in
`docs/release/CHIO_PHEROMONE_RELAY_RUNBOOK.md`.

- [ ] **Step 2: Run red**

Run: `bash scripts/check-chio-pheromone-relay.sh --schema-only`

Expected: failure listing the current runbook compatibility paragraph.

- [ ] **Step 3: Rewrite runbook**

Rewrite the active runbook paragraph to direct operators to Chio-native commands
without naming the legacy command family.

- [ ] **Step 4: Run green**

Run: `bash scripts/check-chio-pheromone-relay.sh --schema-only`

Expected: pass.

- [ ] **Step 5: Verify docs hygiene**

Run focused `rg` and unicode dash scans on touched files plus `git diff
--check`.
