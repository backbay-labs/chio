# Phase 1 (Keystone): crate-path go-dark guard + Phase 0 quick wins - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the `cargo xtask check-crate-paths` fail-closed guard that asserts every literal `crates/chio-*` path reference in the repo's config files resolves to a real file, plus the zero-risk Phase 0 cleanup, so the risky later migration phases cannot silently go dark.

**Architecture:** A new self-contained `xtask` module (`crate_paths.rs`) wired as one new arm in the existing hand-rolled dispatcher. Pure, unit-tested extraction and normalization functions feed a resolver that reads a curated set of structured config files (CI path filters, CODEOWNERS, mutation/kani/threat configs, formal manifests, qualification matrices) and reports any reference whose path prefix does not exist. No new dependencies; no clap conversion (deferred to its own plan).

**Tech Stack:** Rust (std only), the existing `xtask` crate, GitHub Actions YAML.

---

## Scope and plan set

This is the first of seven per-phase plans derived from
`docs/superpowers/specs/2026-06-08-repo-architecture-design.md`. The spec is a
multi-subsystem migration; per the writing-plans scope rule each phase is its own
plan (later phases depend on this one executing and on per-gate discovery, so
pre-writing them would require forbidden placeholders).

| Plan | Phase | Status |
| --- | --- | --- |
| THIS | Phase 1 keystone: crate-paths guard + Phase 0 cleanup | written |
| next | Phase 1b: `xtask` clap conversion + noun-verb tree (needs a `clap` workspace-dep decision) | to write when scheduled |
| next | Phase 0b: README rewrite (prose; independent) | to write when scheduled |
| next | Phase 2: `[workspace.dependencies]` centralization | to write when scheduled |
| next | Phase 3: script -> xtask consolidation (per-cluster) | to write when scheduled |
| next | Phase 4: CI workflow rebuild | to write when scheduled |
| next | Phase 5: root consolidation | to write when scheduled |
| next | Phase 6: crate folder move (gated by THIS guard) | to write when scheduled |

Deviation from the spec's exact spelling (intentional, YAGNI): the spec names the
guard `cargo xtask check crate-paths` (noun-verb). Introducing the noun-verb tree
requires the `clap` conversion (its own plan and a dependency decision). To ship
the keystone now with zero new dependencies, this plan implements it as the single
hyphenated subcommand `check-crate-paths`, matching the existing dispatcher style
(`validate-scenarios`, `freeze-vectors`, `eval-receipt-regen`). It is renamed to
`check crate-paths` when the clap conversion lands; update the one CI call site at
that time.

House rules: no em dashes; fail-closed (a non-resolving reference is an error, not
a skip); `unwrap_used` / `expect_used` are denied, so test code matches on `Err`
and `panic!`s explicitly (the existing `xtask/src/tests.rs` pattern).

---

## File structure

- Create: `xtask/src/crate_paths.rs` - the entire guard (extraction, normalization,
  resolution, target discovery, and the `run` entry point) plus its `#[cfg(test)]`
  test module. One file, one responsibility.
- Modify: `xtask/src/main.rs` - one `mod crate_paths;` declaration, one dispatcher
  match arm, one help line.
- Modify: `.github/workflows/ci.yml` - one new step in the `check` job.
- Delete: 8 orphan scripts (Phase 0).
- Modify: `.gitignore`; move `coverage/README.md` (Phase 0).

---

## Task A: Phase 0 quick wins (mechanical, no code)

**Files:**
- Delete: the 8 scripts listed below
- Modify: `.gitignore`
- Move: `coverage/README.md` -> `docs/operations/coverage.md`

- [ ] **Step A1: Re-confirm the 8 orphans are still unreferenced (fail-closed gate before deletion)**

Run (from repo root):
```bash
for s in check-adversarial-threat-link check-chio-attest-buyer-fixtures \
         check-docker-deployable-experience check-framework-integration-examples \
         check-tool-server-async measure_chio_core_rebuild \
         kani-changed-harnesses rebuild-from-source; do
  echo "== $s =="
  grep -rn --exclude-dir=.git --exclude-dir=target --exclude-dir=.worktrees \
       --exclude-dir=node_modules --exclude-dir=docs/superpowers "$s" . \
  | grep -v "scripts/$s.sh:" || echo "  (no references)"
done
```
Expected: every script reports only doc-only hits under `docs/superpowers/` (this
session's research) or "(no references)". If any operational reference appears
(`.github/`, `Makefile`, another `scripts/*`, `sdks/`), STOP and remove that script
from the deletion set.

- [ ] **Step A2: Delete the 8 confirmed orphans and the pycache**

```bash
git rm scripts/check-adversarial-threat-link.sh \
       scripts/check-chio-attest-buyer-fixtures.sh \
       scripts/check-docker-deployable-experience.sh \
       scripts/check-framework-integration-examples.sh \
       scripts/check-tool-server-async.sh \
       scripts/measure_chio_core_rebuild.sh \
       scripts/kani-changed-harnesses.sh \
       scripts/rebuild-from-source.sh
rm -rf scripts/__pycache__
```

- [ ] **Step A3: Verify the workspace still builds and the gate scripts still resolve**

Run:
```bash
cargo build -p xtask
bash scripts/ci-workspace.sh --list 2>/dev/null || echo "ci-workspace has no --list; skip"
```
Expected: `cargo build -p xtask` succeeds (no script is referenced by Rust). The
ci-workspace check is best-effort; the real proof is no broken references from A1.

- [ ] **Step A4: Commit**

```bash
git add -A scripts/
git commit -m "chore: delete 8 unreferenced orphan scripts"
```

- [ ] **Step A5: Gitignore agent scratch + tracked coverage dir; relocate its README**

Append to `.gitignore` (under the existing "Local planning / orchestration state"
block), if not already present:
```gitignore
# Local agent scratch (untracked; never commit)
.codex/
# Coverage output is generated; keep docs, not the dir
/coverage/
```

Then move the one tracked file out of the about-to-be-ignored dir:
```bash
mkdir -p docs/operations
git mv coverage/README.md docs/operations/coverage.md
```

- [ ] **Step A6: Commit**

```bash
git add .gitignore docs/operations/coverage.md
git commit -m "chore: gitignore .codex and coverage output, move coverage README to docs"
```

---

## Task 1: Extraction function (TDD)

**Files:**
- Create: `xtask/src/crate_paths.rs`
- Modify: `xtask/src/main.rs` (add `mod crate_paths;`)

- [ ] **Step 1: Write the failing test**

Create `xtask/src/crate_paths.rs` with ONLY this content:
```rust
//! `cargo xtask check-crate-paths` - fail-closed guard against crate-path drift.
//!
//! Scans config files that embed literal `crates/chio-*` path references (CI path
//! filters, CODEOWNERS, mutation/kani/threat configs, formal manifests,
//! qualification matrices) and asserts every reference resolves to an existing
//! file or directory. A reference that no longer resolves is an error: after a
//! crate move such a reference would silently match nothing, and the gate or
//! required-reviewer rule it encodes would go dark while CI stayed green.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_captures_paths_and_stops_at_delimiters() {
        let content = concat!(
            "paths:\n",
            "  - \"crates/chio-kernel/**\"\n",
            "x: crates/chio-anchor/src/authority.rs::Symbol\n"
        );
        let got = extract_crate_paths(content);
        assert!(got.contains(&"crates/chio-kernel/**".to_string()), "got: {got:?}");
        assert!(
            got.contains(&"crates/chio-anchor/src/authority.rs".to_string()),
            "stops before `::`; got: {got:?}"
        );
    }
}
```

Then add the module declaration in `xtask/src/main.rs` next to the existing module
declarations (after line 86, `mod snippets_subcommand;`):
```rust
mod crate_paths;
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p xtask crate_paths -- --nocapture`
Expected: FAIL to compile with "cannot find function `extract_crate_paths`".

- [ ] **Step 3: Write minimal implementation**

Add to the top of `xtask/src/crate_paths.rs` (above the `#[cfg(test)] mod tests`):
```rust
/// Extract every `crates/chio-*` path literal from `content`. Matching starts at
/// each `crates/chio-` occurrence and continues over path bytes, stopping at the
/// first character that cannot be part of a path reference (quote, whitespace,
/// `:`, comma). Trailing glob/symbol decoration is preserved here and stripped by
/// `normalize_for_resolution`.
pub fn extract_crate_paths(content: &str) -> Vec<String> {
    let bytes = content.as_bytes();
    let needle = b"crates/chio-";
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let start = i;
            let mut j = i + needle.len();
            while j < bytes.len() && is_path_byte(bytes[j]) {
                j += 1;
            }
            if let Ok(text) = std::str::from_utf8(&bytes[start..j]) {
                out.push(text.to_string());
            }
            i = j.max(start + 1);
        } else {
            i += 1;
        }
    }
    out
}

fn is_path_byte(b: u8) -> bool {
    matches!(
        b,
        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'/' | b'-' | b'_' | b'.' | b'*'
    )
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p xtask crate_paths -- --nocapture`
Expected: PASS (`extract_captures_paths_and_stops_at_delimiters`).

- [ ] **Step 5: Commit**

```bash
git add xtask/src/crate_paths.rs xtask/src/main.rs
git commit -m "feat(xtask): add crate-path extraction for the go-dark guard"
```

---

## Task 2: Normalization function (TDD)

**Files:**
- Modify: `xtask/src/crate_paths.rs`

- [ ] **Step 1: Write the failing tests**

Add these tests inside the existing `mod tests` block in `xtask/src/crate_paths.rs`:
```rust
    #[test]
    fn normalize_strips_globs_keeps_concrete_prefix() {
        assert_eq!(
            normalize_for_resolution("crates/chio-kernel/**").as_deref(),
            Some("crates/chio-kernel")
        );
        assert_eq!(
            normalize_for_resolution("crates/chio-anchor/src/*.rs").as_deref(),
            Some("crates/chio-anchor/src")
        );
        assert_eq!(
            normalize_for_resolution("crates/chio-core/src/lib.rs").as_deref(),
            Some("crates/chio-core/src/lib.rs")
        );
    }

    #[test]
    fn normalize_rejects_bare_or_nameless_prefixes() {
        assert_eq!(normalize_for_resolution("crates/chio-"), None);
        assert_eq!(normalize_for_resolution("crates/**"), None);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p xtask crate_paths`
Expected: FAIL to compile with "cannot find function `normalize_for_resolution`".

- [ ] **Step 3: Write minimal implementation**

Add to `xtask/src/crate_paths.rs` (above `mod tests`):
```rust
/// Reduce a raw literal to the path prefix that must exist on disk. Drops a
/// trailing `::Symbol`, then strips trailing path segments that are empty or
/// contain a glob `*`. Returns `None` when nothing more specific than a crate
/// name remains (so a bare `crates/**` or a truncated `crates/chio-` is not
/// treated as a resolvable path).
pub fn normalize_for_resolution(raw: &str) -> Option<String> {
    let head = raw.split("::").next().unwrap_or(raw);
    let mut segments: Vec<&str> = head.split('/').collect();
    while let Some(last) = segments.last() {
        if last.is_empty() || last.contains('*') {
            segments.pop();
        } else {
            break;
        }
    }
    if segments.len() < 2 {
        return None;
    }
    if segments[1].len() <= "chio-".len() {
        return None;
    }
    Some(segments.join("/"))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p xtask crate_paths`
Expected: PASS (both normalize tests + the extraction test).

- [ ] **Step 5: Commit**

```bash
git add xtask/src/crate_paths.rs
git commit -m "feat(xtask): normalize crate-path literals to resolvable prefixes"
```

---

## Task 3: Resolver against the filesystem (TDD)

**Files:**
- Modify: `xtask/src/crate_paths.rs`

- [ ] **Step 1: Write the failing test**

Add the `Violation` reference and this test. First add the import at the top of the
`mod tests` block (after `use super::*;`):
```rust
    use crate::TempDir;
    use std::fs;
    use std::path::PathBuf;
```
Then add the test inside `mod tests`:
```rust
    #[test]
    fn find_violations_flags_only_missing_paths() {
        let temp = match TempDir::new("xtask-crate-paths") {
            Ok(t) => t,
            Err(err) => panic!("temp dir: {err}"),
        };
        let root = temp.path();
        if let Err(err) = fs::create_dir_all(root.join("crates/chio-kernel/src")) {
            panic!("mkdir: {err}");
        }
        if let Err(err) = fs::write(root.join("crates/chio-kernel/src/lib.rs"), "") {
            panic!("write lib: {err}");
        }
        let cfg_rel = PathBuf::from("config.toml");
        let cfg = concat!(
            "a = \"crates/chio-kernel/**\"\n",
            "b = \"crates/chio-ghost/src/lib.rs\"\n"
        );
        if let Err(err) = fs::write(root.join(&cfg_rel), cfg) {
            panic!("write cfg: {err}");
        }
        let violations = match find_violations(root, &[cfg_rel]) {
            Ok(v) => v,
            Err(err) => panic!("find_violations: {err}"),
        };
        assert_eq!(violations.len(), 1, "got: {violations:?}");
        assert_eq!(violations[0].resolved, "crates/chio-ghost/src/lib.rs");
        assert_eq!(violations[0].source, "config.toml");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p xtask crate_paths`
Expected: FAIL to compile with "cannot find type `Violation`" / "cannot find
function `find_violations`".

- [ ] **Step 3: Write minimal implementation**

Add to `xtask/src/crate_paths.rs` (above `mod tests`), and add the needed imports
at the very top of the file (below the module doc comment):
```rust
use std::fs;
use std::path::{Path, PathBuf};

use crate::{workspace_root, XtaskError};

/// A crate-path reference that does not resolve on disk.
#[derive(Debug, PartialEq, Eq)]
pub struct Violation {
    /// Repo-relative file the literal was found in.
    pub source: String,
    /// The raw literal exactly as written.
    pub raw: String,
    /// The normalized prefix we attempted to resolve.
    pub resolved: String,
}

/// Read each file in `files` (relative to `root`), extract its crate-path
/// literals, and record one `Violation` per literal whose normalized prefix does
/// not exist under `root`. A file in `files` that cannot be read is skipped (its
/// presence in the set is the caller's contract, not this resolver's concern).
pub fn find_violations(root: &Path, files: &[PathBuf]) -> Result<Vec<Violation>, XtaskError> {
    let mut violations = Vec::new();
    for rel in files {
        let content = match fs::read_to_string(root.join(rel)) {
            Ok(text) => text,
            Err(_) => continue,
        };
        for raw in extract_crate_paths(&content) {
            if let Some(prefix) = normalize_for_resolution(&raw) {
                if !root.join(&prefix).exists() {
                    violations.push(Violation {
                        source: rel.display().to_string(),
                        raw,
                        resolved: prefix,
                    });
                }
            }
        }
    }
    Ok(violations)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p xtask crate_paths`
Expected: PASS (all four crate_paths tests).

- [ ] **Step 5: Commit**

```bash
git add xtask/src/crate_paths.rs
git commit -m "feat(xtask): resolve crate-path literals against the filesystem"
```

---

## Task 4: Target discovery + `run` entry point + dispatcher wiring

**Files:**
- Modify: `xtask/src/crate_paths.rs`
- Modify: `xtask/src/main.rs:122-134` (dispatcher), `:144-159` (help)

- [ ] **Step 1: Write the failing test for target discovery**

Add inside `mod tests`:
```rust
    #[test]
    fn scan_targets_includes_existing_workflows_and_skips_absent_files() {
        let temp = match TempDir::new("xtask-crate-paths-targets") {
            Ok(t) => t,
            Err(err) => panic!("temp dir: {err}"),
        };
        let root = temp.path();
        if let Err(err) = fs::create_dir_all(root.join(".github/workflows")) {
            panic!("mkdir wf: {err}");
        }
        if let Err(err) = fs::write(root.join(".github/workflows/ci.yml"), "name: ci\n") {
            panic!("write wf: {err}");
        }
        if let Err(err) = fs::write(root.join(".github/CODEOWNERS"), "* @team\n") {
            panic!("write codeowners: {err}");
        }
        let targets = scan_targets(root);
        assert!(targets.contains(&PathBuf::from(".github/workflows/ci.yml")), "{targets:?}");
        assert!(targets.contains(&PathBuf::from(".github/CODEOWNERS")), "{targets:?}");
        // a path that does not exist must not be included
        assert!(!targets.contains(&PathBuf::from(".cargo/mutants.toml")), "{targets:?}");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p xtask crate_paths`
Expected: FAIL to compile with "cannot find function `scan_targets`".

- [ ] **Step 3: Write minimal implementation**

Add to `xtask/src/crate_paths.rs` (above `mod tests`):
```rust
/// Curated set of structured config files that embed `crates/chio-*` literals.
/// These are the files where a stale reference goes dark silently (path filters,
/// CODEOWNERS, mutation/kani/threat configs, formal manifests, qualification
/// matrices). Prose docs are deliberately excluded: their crate-path mentions are
/// cosmetic and would produce false positives.
fn scan_targets(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for rel in [
        ".github/CODEOWNERS",
        ".cargo/mutants.toml",
        ".kani/harnesses.toml",
        "spec/security/coverage.yaml",
        "spec/security/chio-threat-model.v1.json",
        "formal/proof-manifest.toml",
        "formal/aeneas/production.toml",
        "formal/theorem-inventory.json",
        "contracts/release/CHIO_WEB3_CONTRACT_RELEASE.json",
    ] {
        let rel = PathBuf::from(rel);
        if root.join(&rel).is_file() {
            out.push(rel);
        }
    }
    push_dir(root, ".github/workflows", &["yml", "yaml"], &mut out);
    push_dir(root, "audits/mutation/per-crate-configs", &["toml"], &mut out);
    push_dir(root, "docs/standards", &["json"], &mut out);
    out
}

fn push_dir(root: &Path, rel: &str, exts: &[&str], out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(root.join(rel)) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str());
        if let Some(ext) = ext {
            if exts.contains(&ext) {
                if let Ok(relative) = path.strip_prefix(root) {
                    out.push(relative.to_path_buf());
                }
            }
        }
    }
}

/// `check-crate-paths` entry point. Scans the curated target set and exits
/// non-zero (fail-closed) if any crate-path literal does not resolve.
pub fn run(args: Vec<String>) -> Result<(), XtaskError> {
    if let Some(arg) = args.into_iter().next() {
        return Err(XtaskError::Usage(format!(
            "check-crate-paths: unexpected argument: {arg}"
        )));
    }
    let root = workspace_root()?;
    let targets = scan_targets(&root);
    let violations = find_violations(&root, &targets)?;
    if violations.is_empty() {
        println!(
            "check-crate-paths: OK ({} config files scanned, all crate-path references resolve)",
            targets.len()
        );
        Ok(())
    } else {
        for v in &violations {
            eprintln!("  unresolved: {} -> {} (in {})", v.raw, v.resolved, v.source);
        }
        Err(XtaskError::Validation(format!(
            "{} crate-path reference(s) do not resolve; a crate move likely went dark",
            violations.len()
        )))
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p xtask crate_paths`
Expected: PASS (all five crate_paths tests).

- [ ] **Step 5: Wire the dispatcher and help**

In `xtask/src/main.rs`, add a match arm to the `match cmd.as_str()` block (after
the `"snippets"` arm at line 128):
```rust
        "check-crate-paths" => crate_paths::run(args.collect()),
```
And add a help line to `print_help()` (after the `snippets regen` line at 150):
```rust
    println!("  check-crate-paths");
```

- [ ] **Step 6: Run the full xtask gate to verify nothing regressed**

Run:
```bash
cargo build -p xtask
cargo test -p xtask
cargo clippy -p xtask -- -D warnings
cargo fmt -p xtask -- --check
```
Expected: all four succeed (clippy clean confirms no `unwrap`/`expect`).

- [ ] **Step 7: Run the guard against the real repo**

Run: `cargo xtask check-crate-paths`
Expected: `check-crate-paths: OK (...)`.

If instead it prints `unresolved:` lines, those are PRE-EXISTING stale references
(a real finding, not a plan failure). Triage each: fix the stale reference in its
config file, or if it is intentionally a non-path string, tighten the curated
target set or the extractor. Do not weaken the guard to pass. Re-run until OK,
committing any stale-reference fixes separately with `fix:` messages.

- [ ] **Step 8: Commit**

```bash
git add xtask/src/crate_paths.rs xtask/src/main.rs
git commit -m "feat(xtask): add check-crate-paths go-dark guard subcommand"
```

---

## Task 5: Wire the guard into CI

**Files:**
- Modify: `.github/workflows/ci.yml` (the `check` job)

- [ ] **Step 1: Add the step**

In `.github/workflows/ci.yml`, inside the `check` job's `steps:` list, add this
step adjacent to the other `cargo xtask` / script gate steps (after the existing
codegen/freeze-vectors steps so the workspace is already set up):
```yaml
      - name: crate-path go-dark guard
        run: cargo xtask check-crate-paths
```

- [ ] **Step 2: Verify the step command works in a CI-equivalent shell locally**

Run (from repo root, the same cwd CI uses after checkout):
```bash
cargo xtask check-crate-paths && echo "EXIT_OK"
```
Expected: `check-crate-paths: OK (...)` then `EXIT_OK`. Confirm the exit code is 0:
`echo $?` prints `0`. Introduce a temporary fake to prove fail-closed:
```bash
printf 'x = "crates/chio-does-not-exist/src/lib.rs"\n' >> .cargo/mutants.toml
cargo xtask check-crate-paths; echo "exit=$?"
git checkout -- .cargo/mutants.toml
```
Expected: prints an `unresolved:` line and `exit=1`, then the checkout restores the
file. This proves the gate fails closed.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: run check-crate-paths guard in the check job"
```

- [ ] **Step 4: Run the full workspace gate (clean-tree confirmation)**

Run:
```bash
cargo build --workspace && cargo test --workspace \
  && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check
```
Expected: all pass. (Per project memory, reproduce gates locally; CI logs
truncate.) This is the phase exit criterion.

---

## Self-Review

**Spec coverage (vs `2026-06-08-repo-architecture-design.md`):**
- Spec Phase 0 (delete 8 orphans, `rm __pycache__`, gitignore `.codex/`, gitignore
  `coverage/` + move README) -> Task A. Covered.
- Spec Phase 1 keystone (`check crate-paths` guard built and wired into CI before
  any move) -> Tasks 1-5. Covered (named `check-crate-paths`; rename deferred with
  the documented clap deviation).
- Spec Phase 1 items NOT in this plan (clap conversion, `external_tool()` helper,
  noun-verb parents) are explicitly deferred to the Phase 1b plan in the plan-set
  table. Intentional scope split, not a gap.

**Placeholder scan:** no TBD/TODO; every code step shows complete code; every
command shows expected output. Clean.

**Type/name consistency:** `extract_crate_paths` (Task 1) -> used in
`find_violations` (Task 3); `normalize_for_resolution` (Task 2) -> used in
`find_violations`; `Violation { source, raw, resolved }` defined in Task 3 ->
asserted in Task 3 test and printed in `run` (Task 4); `scan_targets` /`push_dir`
(Task 4) -> used in `run`; `run` (Task 4) -> wired in dispatcher (Task 4 Step 5)
and CI (Task 5). `crate::{workspace_root, XtaskError}` and `crate::TempDir` are the
real symbols in `xtask/src/main.rs` (verified: `workspace_root` at :1168,
`XtaskError::{Usage,Validation}` at :89, `TempDir` at :1952, accessible to the
sibling module). Consistent.
