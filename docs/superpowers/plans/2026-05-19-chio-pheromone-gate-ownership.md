# Chio Pheromone Gate Ownership Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move pheromone runtime/transit gate ownership to Chio-named scripts while preserving Chiodos-named compatibility wrappers.

**Architecture:** The final architecture requires gate scripts to use Chio names, with Chiodos names retained only as compatibility wrappers. The Chio-named scripts keep the current schema, fixture, test, and negative-corpus logic unchanged; wrappers delegate without emitting artifacts or owning validation logic.

**Tech Stack:** Bash, GitHub Actions workflow YAML, Rust cargo gates, Python metadata checks embedded in shell scripts.

---

### Task 1: Add Chio-Named Gate Scripts

**Files:**
- Create: `scripts/check-chio-pheromone-transit.sh`
- Create: `scripts/check-chio-pheromone-runtime.sh`
- Modify: `scripts/check-chiodos-pheromone-transit.sh`
- Modify: `scripts/check-chiodos-pheromone-runtime.sh`

- [x] **Step 1: Verify the red state**

Run:

```bash
test -x scripts/check-chio-pheromone-transit.sh && test -x scripts/check-chio-pheromone-runtime.sh
```

Expected: fail because the Chio-named gate scripts do not exist yet.

- [x] **Step 2: Move current gate logic into Chio-named scripts**

Copy the current bodies of:

```text
scripts/check-chiodos-pheromone-transit.sh
scripts/check-chiodos-pheromone-runtime.sh
```

to:

```text
scripts/check-chio-pheromone-transit.sh
scripts/check-chio-pheromone-runtime.sh
```

Then make the new files executable.

- [x] **Step 3: Replace Chiodos-named scripts with compatibility wrappers**

Replace each old script with:

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$ROOT/scripts/check-chio-pheromone-runtime.sh" "$@"
```

and:

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$ROOT/scripts/check-chio-pheromone-transit.sh" "$@"
```

- [x] **Step 4: Verify the Chio and wrapper gates**

Run:

```bash
bash scripts/check-chio-pheromone-transit.sh --schema-only
bash scripts/check-chiodos-pheromone-transit.sh --schema-only
bash scripts/check-chio-pheromone-runtime.sh --schema-only
bash scripts/check-chiodos-pheromone-runtime.sh --schema-only
```

Expected: all pass and produce the same validation behavior as before.

### Task 2: Update Workflow and Documentation References

**Files:**
- Move: `.github/workflows/chiodos-pheromone-transit.yml` to `.github/workflows/chio-pheromone-transit.yml`
- Move: `.github/workflows/chiodos-pheromone-runtime.yml` to `.github/workflows/chio-pheromone-runtime.yml`
- Modify: `docs/architecture/CHIO_FINAL_ARCHITECTURE.md`
- Modify: `docs/superpowers/plans/2026-05-18-chio-final-architecture-p0.md`
- Modify: any current docs/scripts references found with `rg -n "check-chiodos-pheromone-(runtime|transit)"`

- [x] **Step 1: Update workflows to run Chio-named scripts**

Replace workflow `run:` commands and path filters for the runtime/transit gate scripts with:

```yaml
scripts/check-chio-pheromone-runtime.sh
scripts/check-chio-pheromone-transit.sh
```

Keep wrapper script paths in filters only when wrapper changes should trigger the same workflows.

- [x] **Step 2: Update architecture and plan docs**

State that `scripts/check-chio-pheromone-runtime.sh` and `scripts/check-chio-pheromone-transit.sh` own validation, while Chiodos-named scripts are compatibility wrappers.

- [x] **Step 3: Verify references and hygiene**

Run:

```bash
rg -n "check-chiodos-pheromone-(runtime|transit)" .github docs scripts spec examples crates
cargo fmt --all -- --check
git diff --check
rg -n "\x{2014}|\x{2013}" $(git diff --name-only --diff-filter=ACM)
```

Expected: remaining Chiodos-named references are compatibility-wrapper references or historical notes only; formatting and whitespace checks pass; dash scan prints no matches.
