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

/// How a raw literal must be resolved on disk.
#[derive(Debug, PartialEq, Eq)]
pub enum Resolution {
    /// A concrete path (exact file, or a directory prefix derived from a
    /// trailing `/**` or `**`) that must `exists()` under the root.
    Path(String),
    /// A final-segment glob such as `capability*.rs`: `dir` must exist AND the
    /// `pattern` must match at least one entry inside it. A pattern that
    /// matches no files is a violation, even when `dir` exists, so a stale
    /// rule does not silently go dark after the file it targeted is moved.
    GlobInDir { dir: String, pattern: String },
}

/// Reduce a raw literal to the on-disk check it implies. Drops a trailing
/// `::Symbol`, then classifies by the final path segment:
///
/// - a final segment containing `*` but not exactly `**`, whose parent path is
///   glob-free (e.g. `capability*.rs`), yields `GlobInDir`, which requires at
///   least one match;
/// - a trailing `**` or empty segment (a `dir/**` or `dir/` prefix), or a
///   recursive glob whose parent itself contains a wildcard (e.g.
///   `_generated/**/*.rs`), strips the wildcard tail and yields a `Path`
///   directory-existence check;
/// - any other final segment yields an exact `Path`.
///
/// Returns `None` when nothing more specific than a crate name remains (so a
/// bare `crates/**` or a truncated `crates/chio-` is not treated as a path).
pub fn normalize_for_resolution(raw: &str) -> Option<Resolution> {
    let head = raw.split("::").next().unwrap_or(raw);
    let segments: Vec<&str> = head.split('/').collect();

    // A final-segment glob (e.g. `capability*.rs`) is a match-at-least-one
    // check against its parent directory, but only when that parent is a
    // concrete (glob-free) directory. `**` is not a final-segment glob: it is
    // the recursive dir-prefix wildcard. A recursive glob whose parent path
    // contains a wildcard (e.g. `_generated/**/*.rs`) cannot be resolved by a
    // single `read_dir`, so it falls through to the dir-prefix existence check.
    if let Some(last) = segments.last() {
        let parent = &segments[..segments.len() - 1];
        let parent_has_glob = parent.iter().any(|s| s.contains('*'));
        if last.contains('*') && *last != "**" && !parent_has_glob {
            let dir = concrete_prefix(parent)?;
            let pattern = last.trim_end_matches('.');
            if pattern.is_empty() {
                return None;
            }
            return Some(Resolution::GlobInDir {
                dir,
                pattern: pattern.to_string(),
            });
        }
    }

    // Trailing `**` / `/` (a directory prefix) or an exact path: strip empty
    // and wildcard tail segments and require the remaining prefix to exist.
    let mut prefix_segments = segments;
    while let Some(last) = prefix_segments.last() {
        if last.is_empty() || last.contains('*') {
            prefix_segments.pop();
        } else {
            break;
        }
    }
    let path = concrete_prefix(&prefix_segments)?;
    Some(Resolution::Path(path))
}

/// Join `segments` into a `crates/chio-<name>/...` prefix, returning `None`
/// when nothing more specific than a bare crate name (or a truncated
/// `crates/chio-`) remains. Trims a trailing sentence period.
fn concrete_prefix(segments: &[&str]) -> Option<String> {
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

/// Translate a final-segment glob `pattern` (the only metacharacter is `*`,
/// matching any run of characters including none) into a check against a single
/// directory entry `name`. A `*` may appear anywhere; the surrounding literal
/// fragments must match in order with no overlap.
fn glob_segment_matches(pattern: &str, name: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == name;
    }
    let mut cursor = 0usize;
    for (idx, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if idx == 0 {
            if !name[cursor..].starts_with(part) {
                return false;
            }
            cursor += part.len();
        } else if idx == parts.len() - 1 {
            // Final literal fragment must anchor to the end of `name`, in the
            // span not already consumed by earlier fragments (so the suffix
            // cannot overlap the prefix).
            if !name[cursor..].ends_with(part) {
                return false;
            }
        } else {
            match name[cursor..].find(part) {
                Some(found) => cursor += found + part.len(),
                None => return false,
            }
        }
    }
    true
}

/// Whether `dir` (relative to `root`) contains at least one entry whose name
/// matches the final-segment `pattern`. Returns `false` when `dir` is missing
/// or unreadable, so a stale rule pointing at a vanished directory is flagged.
fn dir_has_glob_match(root: &Path, dir: &str, pattern: &str) -> bool {
    let entries = match fs::read_dir(root.join(dir)) {
        Ok(entries) => entries,
        Err(_) => return false,
    };
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            if glob_segment_matches(pattern, name) {
                return true;
            }
        }
    }
    false
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
            let Some(resolution) = normalize_for_resolution(&raw) else {
                continue;
            };
            let (resolves, resolved) = match resolution {
                Resolution::Path(path) => {
                    let resolves = root.join(&path).exists();
                    (resolves, path)
                }
                Resolution::GlobInDir { dir, pattern } => {
                    let resolves = dir_has_glob_match(root, &dir, &pattern);
                    (resolves, format!("{dir}/{pattern}"))
                }
            };
            if !resolves {
                violations.push(Violation {
                    source: rel.display().to_string(),
                    raw,
                    resolved,
                });
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
    fn normalize_classifies_dir_prefix_glob_and_exact() {
        // A trailing `/**` strips to a directory-existence check.
        assert_eq!(
            normalize_for_resolution("crates/chio-kernel/**"),
            Some(Resolution::Path("crates/chio-kernel".to_string()))
        );
        // A final-segment glob keeps its parent dir and pattern so the guard
        // can require at least one match.
        assert_eq!(
            normalize_for_resolution("crates/chio-anchor/src/*.rs"),
            Some(Resolution::GlobInDir {
                dir: "crates/chio-anchor/src".to_string(),
                pattern: "*.rs".to_string(),
            })
        );
        // A final-segment glob with a literal stem (e.g. `capability*.rs`).
        assert_eq!(
            normalize_for_resolution("crates/chio-core-types/src/capability*.rs"),
            Some(Resolution::GlobInDir {
                dir: "crates/chio-core-types/src".to_string(),
                pattern: "capability*.rs".to_string(),
            })
        );
        // A recursive glob whose parent path itself contains `**` cannot be
        // resolved by a single read_dir, so it strips to a dir-prefix check.
        assert_eq!(
            normalize_for_resolution("crates/chio-core-types/src/_generated/**/*.rs"),
            Some(Resolution::Path(
                "crates/chio-core-types/src/_generated".to_string()
            ))
        );
        // An exact path is a plain existence check.
        assert_eq!(
            normalize_for_resolution("crates/chio-core/src/lib.rs"),
            Some(Resolution::Path("crates/chio-core/src/lib.rs".to_string()))
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
            normalize_for_resolution("crates/chio-kernel/src/lib.rs."),
            Some(Resolution::Path(
                "crates/chio-kernel/src/lib.rs".to_string()
            ))
        );
        assert_eq!(
            normalize_for_resolution("crates/chio-foo."),
            Some(Resolution::Path("crates/chio-foo".to_string()))
        );
    }

    #[test]
    fn glob_segment_matches_handles_prefix_suffix_and_middle() {
        assert!(glob_segment_matches("capability*.rs", "capability.rs"));
        assert!(glob_segment_matches(
            "capability*.rs",
            "capability_token.rs"
        ));
        assert!(glob_segment_matches("*.rs", "lib.rs"));
        assert!(glob_segment_matches("receipt_*.rs", "receipt_store.rs"));
        assert!(!glob_segment_matches("capability*.rs", "scope.rs"));
        assert!(!glob_segment_matches("capability*.rs", "capability"));
        assert!(!glob_segment_matches("*.rs", "lib.toml"));
    }

    #[test]
    fn find_violations_glob_requires_at_least_one_match() {
        let temp = match TempDir::new("xtask-crate-paths-glob") {
            Ok(t) => t,
            Err(err) => panic!("temp dir: {err}"),
        };
        let root = temp.path();
        if let Err(err) = fs::create_dir_all(root.join("crates/chio-core-types/src")) {
            panic!("mkdir: {err}");
        }
        // A matching file makes the `name*.rs` glob resolve.
        if let Err(err) = fs::write(
            root.join("crates/chio-core-types/src/capability_token.rs"),
            "",
        ) {
            panic!("write match: {err}");
        }
        let cfg_rel = PathBuf::from("config.toml");
        let cfg = concat!(
            "a = \"crates/chio-core-types/src/capability*.rs\"\n",
            "b = \"crates/chio-core-types/src/scope*.rs\"\n"
        );
        if let Err(err) = fs::write(root.join(&cfg_rel), cfg) {
            panic!("write cfg: {err}");
        }
        let violations = match find_violations(root, &[cfg_rel]) {
            Ok(v) => v,
            Err(err) => panic!("find_violations: {err}"),
        };
        // `capability*.rs` matches `capability_token.rs` (no violation);
        // `scope*.rs` matches nothing (a go-dark glob -> violation).
        assert_eq!(violations.len(), 1, "got: {violations:?}");
        assert_eq!(
            violations[0].resolved,
            "crates/chio-core-types/src/scope*.rs"
        );
    }

    #[test]
    fn find_violations_dir_prefix_and_exact_still_resolve() {
        let temp = match TempDir::new("xtask-crate-paths-dir") {
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
            "b = \"crates/chio-kernel/src/lib.rs\"\n"
        );
        if let Err(err) = fs::write(root.join(&cfg_rel), cfg) {
            panic!("write cfg: {err}");
        }
        let violations = match find_violations(root, &[cfg_rel]) {
            Ok(v) => v,
            Err(err) => panic!("find_violations: {err}"),
        };
        assert!(violations.is_empty(), "got: {violations:?}");
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
