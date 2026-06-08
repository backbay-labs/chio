//! `cargo xtask check-crate-paths` - fail-closed guard against crate-path drift.
//!
//! Scans config files that embed literal `crates/chio-*` path references (CI path
//! filters, CODEOWNERS, mutation/kani/threat configs, formal manifests,
//! qualification matrices) and asserts every reference resolves to an existing
//! file or directory. A reference that no longer resolves is an error: after a
//! crate move such a reference would silently match nothing, and the gate or
//! required-reviewer rule it encodes would go dark while CI stayed green.

use std::fs;
use std::path::{Path, PathBuf};

use crate::{workspace_root, XtaskError};

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
    let joined = segments.join("/");
    let trimmed = joined.trim_end_matches('.');
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

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
    push_dir(
        root,
        "audits/mutation/per-crate-configs",
        &["toml"],
        &mut out,
    );
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
            eprintln!(
                "  unresolved: {} -> {} (in {})",
                v.raw, v.resolved, v.source
            );
        }
        Err(XtaskError::Validation(format!(
            "{} crate-path reference(s) do not resolve; a crate move likely went dark",
            violations.len()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TempDir;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn extract_captures_paths_and_stops_at_delimiters() {
        let content = concat!(
            "paths:\n",
            "  - \"crates/chio-kernel/**\"\n",
            "x: crates/chio-anchor/src/authority.rs::Symbol\n"
        );
        let got = extract_crate_paths(content);
        assert!(
            got.contains(&"crates/chio-kernel/**".to_string()),
            "got: {got:?}"
        );
        assert!(
            got.contains(&"crates/chio-anchor/src/authority.rs".to_string()),
            "stops before `::`; got: {got:?}"
        );
    }

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

    #[test]
    fn normalize_strips_trailing_sentence_period() {
        assert_eq!(
            normalize_for_resolution("crates/chio-kernel/src/lib.rs.").as_deref(),
            Some("crates/chio-kernel/src/lib.rs")
        );
        assert_eq!(
            normalize_for_resolution("crates/chio-foo.").as_deref(),
            Some("crates/chio-foo")
        );
    }

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
        assert!(
            targets.contains(&PathBuf::from(".github/workflows/ci.yml")),
            "{targets:?}"
        );
        assert!(
            targets.contains(&PathBuf::from(".github/CODEOWNERS")),
            "{targets:?}"
        );
        // a path that does not exist must not be included
        assert!(
            !targets.contains(&PathBuf::from(".cargo/mutants.toml")),
            "{targets:?}"
        );
    }
}
