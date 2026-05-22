# Chio Pheromone Relay Gate Ownership Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move pheromone relay gate and workflow ownership from Chio-named paths to Chio-named paths while preserving old paths as compatibility wrappers.

**Architecture:** Chio pheromone relay is a Chio-native product surface. The owning gate scripts and GitHub workflow files should therefore use Chio names; Chio names may remain only as thin wrappers or historical compatibility references.

**Tech Stack:** Bash, GitHub Actions workflow YAML, Rust cargo gates, existing Chio pheromone relay validation scripts.

---

### Task 1: Add Chio-Named Relay Gate Scripts

**Files:**
- Move: `scripts/check-chio-pheromone-relay.sh` to `scripts/check-chio-pheromone-relay.sh`
- Move: `scripts/check-chio-pheromone-relay-alert-assurance.sh` to `scripts/check-chio-pheromone-relay-alert-assurance.sh`
- Move: `scripts/check-chio-pheromone-relay-alert-assurance-archive.sh` to `scripts/check-chio-pheromone-relay-alert-assurance-archive.sh`
- Move: `scripts/check-chio-pheromone-relay-alert-assurance-export.sh` to `scripts/check-chio-pheromone-relay-alert-assurance-export.sh`
- Move: `scripts/check-chio-pheromone-relay-alert-delivery.sh` to `scripts/check-chio-pheromone-relay-alert-delivery.sh`
- Move: `scripts/check-chio-pheromone-relay-alert-handoff.sh` to `scripts/check-chio-pheromone-relay-alert-handoff.sh`
- Move: `scripts/check-chio-pheromone-relay-alert-routing.sh` to `scripts/check-chio-pheromone-relay-alert-routing.sh`
- Move: `scripts/check-chio-pheromone-relay-observability.sh` to `scripts/check-chio-pheromone-relay-observability.sh`
- Move: `scripts/check-chio-pheromone-relay-ops.sh` to `scripts/check-chio-pheromone-relay-ops.sh`

- [x] **Step 1: Verify red state**

Run:

```bash
test -x scripts/check-chio-pheromone-relay.sh
```

Expected: fail because Chio-named relay gate scripts do not own validation yet.

- [x] **Step 2: Move current gate logic into Chio-named scripts**

Move each Chio-named relay gate body to the matching Chio-named script listed above.

- [x] **Step 3: Replace old scripts with executable wrappers**

Each old `scripts/check-chio-pheromone-relay*.sh` file should contain only:

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$ROOT/scripts/check-chio-pheromone-relay*.sh" "$@"
```

where the `check-chio-...` target exactly matches the old suffix.

- [x] **Step 4: Verify script ownership**

Run:

```bash
test -x scripts/check-chio-pheromone-relay.sh
test -x scripts/check-chio-pheromone-relay.sh
rg -n "check-chio-pheromone-relay" scripts/check-chio-pheromone-relay*.sh
```

Expected: the executable checks pass and the final search prints no matches.

### Task 2: Move Relay Workflows to Chio Names

**Files:**
- Move: `.github/workflows/chio-pheromone-relay.yml` to `.github/workflows/chio-pheromone-relay.yml`
- Move: `.github/workflows/chio-pheromone-relay-alert-assurance.yml` to `.github/workflows/chio-pheromone-relay-alert-assurance.yml`
- Move: `.github/workflows/chio-pheromone-relay-alert-assurance-archive.yml` to `.github/workflows/chio-pheromone-relay-alert-assurance-archive.yml`
- Move: `.github/workflows/chio-pheromone-relay-alert-assurance-export.yml` to `.github/workflows/chio-pheromone-relay-alert-assurance-export.yml`
- Move: `.github/workflows/chio-pheromone-relay-alert-delivery.yml` to `.github/workflows/chio-pheromone-relay-alert-delivery.yml`
- Move: `.github/workflows/chio-pheromone-relay-alert-handoff.yml` to `.github/workflows/chio-pheromone-relay-alert-handoff.yml`
- Move: `.github/workflows/chio-pheromone-relay-alert-routing.yml` to `.github/workflows/chio-pheromone-relay-alert-routing.yml`
- Move: `.github/workflows/chio-pheromone-relay-observability.yml` to `.github/workflows/chio-pheromone-relay-observability.yml`
- Move: `.github/workflows/chio-pheromone-relay-ops.yml` to `.github/workflows/chio-pheromone-relay-ops.yml`

- [x] **Step 1: Update workflow names, job ids, paths, and run commands**

For each moved workflow:
- `name:` uses `Chio`.
- job id uses `chio-`.
- `run:` calls the Chio-named script.
- `paths:` include the Chio-named owning script, the old Chio wrapper script, and the moved workflow path.

- [x] **Step 2: Verify workflow YAML and references**

Run:

```bash
ruby -e 'require "yaml"; ARGV.each { |path| YAML.load_file(path); puts "#{path}: ok" }' .github/workflows/chio-pheromone-relay*.yml
rg -n "run: bash scripts/check-chio-pheromone-relay|Check Chio pheromone relay|^  chio-pheromone-relay" .github/workflows/chio-pheromone-relay*.yml
```

Expected: YAML parse succeeds and the executable ownership search prints no
matches. Historical docs/example paths and old wrapper script path filters may
still contain Chio names.

### Task 3: Focused Validation

**Files:**
- Existing touched scripts and workflow files

- [x] **Step 1: Run fast relay gate smoke checks**

Run:

```bash
bash scripts/check-chio-pheromone-relay.sh --schema-only
bash scripts/check-chio-pheromone-relay.sh --schema-only
```

Expected: both pass and exercise the same validation behavior.

- [x] **Step 2: Run hygiene checks**

Run:

```bash
cargo fmt --all -- --check
git diff --check
rg -n "\x{2014}|\x{2013}" $(git diff --name-only --diff-filter=ACM) .github/workflows/chio-pheromone-relay*.yml scripts/check-chio-pheromone-relay*.sh
```

Expected: all checks pass and the dash scan prints no matches.
