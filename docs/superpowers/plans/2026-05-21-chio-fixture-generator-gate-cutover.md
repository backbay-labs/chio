# Chio Fixture Generator Gate Cutover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop active Chio gate scripts from invoking Chiodos-named fixture generation or writing Chiodos-named temporary files.

**Architecture:** Historical signed proof material can still contain Chiodos workflow IDs because those values are byte-bound to old signed packages. Active Chio gates should use a Chio-named generator entry point and Chio-named temp outputs while preserving the same fixture bytes where legacy signed evidence is required.

**Tech Stack:** Bash gate scripts, Cargo bin aliases, Rust example fixture generator.

---

### Task 1: Add The Red Gate

**Files:**
- Modify: `scripts/check-chio-pheromone-runtime.sh`

- [ ] **Step 1: Write the failing gate**

Add a metadata preflight that scans active Chio gate scripts for non-signed Chiodos naming drift:

```python
gate_paths = [
    root / "scripts/check-chio-authority-issuance.sh",
    root / "scripts/check-chio-pheromone-runtime.sh",
    root / "scripts/check-chio-pheromone-transit.sh",
]
legacy_markers = [
    "generate-" + "chiodos-proof-package",
    "/tmp/" + "chiodos-pheromone",
]
for path in gate_paths:
    text = path.read_text(encoding="utf-8")
    for marker in legacy_markers:
        if marker in text:
            raise SystemExit(f"active Chio gate {path.relative_to(root)} uses legacy marker {marker}")
```

- [ ] **Step 2: Run red**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-pheromone-runtime.sh --schema-only
```

Expected: FAIL naming `generate-chiodos-proof-package` or `/tmp/chiodos-pheromone`.

### Task 2: Add Chio-Named Generator Alias

**Files:**
- Modify: `examples/chiodos-3vendor/Cargo.toml`
- Modify: `examples/chiodos-3vendor/src/main.rs`

- [ ] **Step 1: Add alias bin**

Add:

```toml
[[bin]]
name = "generate-chio-three-vendor-fixtures"
path = "src/main.rs"
```

- [ ] **Step 2: Make usage use argv[0]**

Replace the hard-coded usage string with a helper that reports the executable name.

### Task 3: Switch Active Chio Gates

**Files:**
- Modify: `scripts/check-chio-authority-issuance.sh`
- Modify: `scripts/check-chio-pheromone-runtime.sh`
- Modify: `scripts/check-chio-pheromone-transit.sh`

- [ ] **Step 1: Replace active generator calls**

Use:

```bash
cargo run -p chiodos-three-vendor-example --bin generate-chio-three-vendor-fixtures -- ...
```

- [ ] **Step 2: Rename temp stderr/stdout paths**

Use:

```bash
/tmp/chio-pheromone-replay.out
/tmp/chio-pheromone-replay.err
/tmp/chio-pheromone-recipient.out
/tmp/chio-pheromone-recipient.err
```

### Task 4: Verify

**Files:**
- All files above

- [ ] **Step 1: Run focused gates**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-pheromone-runtime.sh --schema-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-pheromone-transit.sh --schema-only
CARGO_TARGET_DIR=/private/tmp/chio-985a-target bash scripts/check-chio-authority-issuance.sh
```

- [ ] **Step 2: Run hygiene checks**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo fmt --all -- --check
git diff --check
rg -n $'\xE2\x80\x94|\xE2\x80\x93' docs/superpowers/plans/2026-05-21-chio-fixture-generator-gate-cutover.md examples/chiodos-3vendor/Cargo.toml examples/chiodos-3vendor/src/main.rs scripts/check-chio-authority-issuance.sh scripts/check-chio-pheromone-runtime.sh scripts/check-chio-pheromone-transit.sh
```

Expected: all pass, except the dash scan exits 1 with no output.
