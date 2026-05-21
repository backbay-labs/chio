# Chio Relay Drill Fixture Wording Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep active Chio relay lifecycle fixtures free of Chiodos-named
operator wording.

**Architecture:** Relay drill fixtures are Chio operator evidence, not signed
historical proof packages. Legacy names may remain in explicit compatibility
artifacts, but active relay fixture details should describe Chio paths.

**Tech Stack:** Bash gate script, JSON fixture, focused `rg` drift checks.

---

### Task 1: Active Relay Fixture Drift Gate

**Files:**
- Modify: `scripts/check-chio-pheromone-directory-lifecycle.sh`
- Modify: `examples/chio-3vendor/fixtures/pheromone/relay/relay-drill-report.json`
- Modify: `docs/architecture/CHIO_FINAL_ARCHITECTURE.md`

- [ ] **Step 1: Add failing gate**

Add a drift check to `scripts/check-chio-pheromone-directory-lifecycle.sh` that
rejects `Chiodos`, `CHIODOS`, or `chiodos` in the active Chio relay fixture
directory.

- [ ] **Step 2: Run red**

Run: `bash scripts/check-chio-pheromone-directory-lifecycle.sh --schema-only`

Expected: failure listing `relay-drill-report.json`.

- [ ] **Step 3: Rewrite fixture detail**

Change the relay drill detail to name the Chio pheromone path prefix.

- [ ] **Step 4: Run green**

Run: `bash scripts/check-chio-pheromone-directory-lifecycle.sh --schema-only`

Expected: pass.

- [ ] **Step 5: Verify docs and fixture hygiene**

Run focused stale wording checks, unicode dash scans, and `git diff --check`.
