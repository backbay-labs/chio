//! Shared path normalization for policy path matching.
//!
//! Normalizes a path into a canonical form for policy glob matching.

use std::path::Path;

/// Normalize a path for policy glob matching.
///
/// Rules:
/// - Convert `\` to `/`
/// - Collapse repeated separators
/// - Remove `.` segments
/// - Resolve `..` segments lexically (without filesystem access)
pub fn normalize_path_for_policy(path: &str) -> String {
    let path = path.replace('\\', "/");
    let is_absolute = path.starts_with('/');

    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }

        if segment == ".." {
            if let Some(last) = segments.last().copied() {
                if last != ".." {
                    segments.pop();
                    continue;
                }
            }
            if !is_absolute {
                segments.push(segment);
            }
            continue;
        }

        segments.push(segment);
    }

    if is_absolute {
        if segments.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", segments.join("/"))
        }
    } else if segments.is_empty() {
        ".".to_string()
    } else {
        segments.join("/")
    }
}

/// Normalize a path to an absolute lexical path without resolving symlinks.
///
/// - Absolute inputs are normalized as-is.
/// - Relative inputs are joined against the current working directory.
pub fn normalize_path_for_policy_lexical_absolute(path: &str) -> Option<String> {
    let raw = Path::new(path);
    if raw.is_absolute() {
        return Some(normalize_path_for_policy(path));
    }

    let cwd = std::env::current_dir().ok()?;
    let joined = cwd.join(raw);
    Some(normalize_path_for_policy(&joined.to_string_lossy()))
}

/// Normalize a path for policy matching, preferring filesystem-resolved targets when possible.
///
/// - For existing paths, this resolves symlinks via `canonicalize`.
/// - For non-existing write targets, this resolves the parent directory and rejoins the filename.
/// - Falls back to lexical normalization when resolution is not possible.
pub fn normalize_path_for_policy_with_fs(path: &str) -> String {
    resolve_path_for_policy(path).unwrap_or_else(|| normalize_path_for_policy(path))
}

fn resolve_path_for_policy(path: &str) -> Option<String> {
    let raw = Path::new(path);
    if let Ok(canonical) = std::fs::canonicalize(raw) {
        return Some(normalize_path_for_policy(&canonical.to_string_lossy()));
    }

    let parent = raw.parent()?;
    let canonical_parent = std::fs::canonicalize(parent).ok()?;
    let candidate = match raw.file_name() {
        Some(name) => canonical_parent.join(name),
        None => canonical_parent,
    };
    Some(normalize_path_for_policy(&candidate.to_string_lossy()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn looks_like_windows_absolute(path: &str) -> bool {
        let bytes = path.as_bytes();
        bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'/' || bytes[2] == b'\\')
    }

    fn normalized_path_within_root(root: &str, candidate: &str) -> bool {
        let normalized_root = normalize_path_for_policy(root);
        let normalized_candidate = if looks_like_windows_absolute(candidate) {
            normalize_path_for_policy(candidate)
        } else {
            normalize_path_for_policy_lexical_absolute(candidate)
                .expect("candidate should normalize to an absolute path")
        };
        let root_prefix = if normalized_root == "/" {
            "/".to_string()
        } else {
            format!("{normalized_root}/")
        };

        normalized_candidate == normalized_root || normalized_candidate.starts_with(&root_prefix)
    }

    #[test]
    fn normalizes_separators_and_dots() {
        assert_eq!(
            normalize_path_for_policy(r"C:\repo\src\.\main.rs"),
            "C:/repo/src/main.rs"
        );
        assert_eq!(normalize_path_for_policy("/tmp///foo//bar"), "/tmp/foo/bar");
    }

    #[test]
    fn resolves_parent_segments_lexically() {
        assert_eq!(
            normalize_path_for_policy("/workspace/a/b/../c/./file.txt"),
            "/workspace/a/c/file.txt"
        );
        assert_eq!(normalize_path_for_policy("a/b/../../c"), "c");
        assert_eq!(normalize_path_for_policy("../a/../b"), "../b");
    }

    #[test]
    fn lexical_absolute_normalization_uses_cwd_for_relative_paths() {
        let cwd = std::env::current_dir().expect("cwd should be available");
        let expected = normalize_path_for_policy(&cwd.join("src/../Cargo.toml").to_string_lossy());

        assert_eq!(
            normalize_path_for_policy_lexical_absolute("src/../Cargo.toml").as_deref(),
            Some(expected.as_str())
        );
    }

    #[test]
    fn root_containment_examples_follow_normalized_boundaries() {
        assert!(normalized_path_within_root(
            "/workspace/project",
            "/workspace/project/src/../Cargo.toml"
        ));
        assert!(!normalized_path_within_root(
            "/workspace/project",
            "/workspace/project/../../etc/passwd"
        ));
        assert!(normalized_path_within_root(
            "C:/repo/project",
            "C:/repo/project/src/../Cargo.toml"
        ));
        assert!(!normalized_path_within_root(
            "C:/repo/project",
            "C:/repo/other/file.txt"
        ));
    }
}
