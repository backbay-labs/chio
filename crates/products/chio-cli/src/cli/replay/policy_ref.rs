// Policy-reference parser and resolver for `chio replay traffic --against`.
//
// Only workspace-local YAML policy paths are accepted. Manifest-hash and
// package-version refs are rejected: there is no registry-backed resolver to
// materialize a verified LoadedPolicy from them.

use super::*;

/// Parsed and discriminated policy reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyRef {
    /// Absolute or relative workspace filesystem path to a policy file.
    WorkspacePath(PathBuf),
}

/// Errors surfaced by [`PolicyRef::parse`] and [`PolicyRef::resolve`].
#[derive(Debug, thiserror::Error)]
pub enum PolicyRefError {
    /// The supplied string requested an unsupported policy-ref shape.
    #[error("policy-ref does not parse: {0}")]
    Parse(String),

    /// The workspace path arm pointed at a file that could not be
    /// loaded by the underlying [`load_policy`] flow.
    #[error("workspace policy path failed to load: {0}")]
    Load(String),
}

/// Resolved-policy summary used by reports. For the full materialized
/// [`policy::LoadedPolicy`] use [`PolicyRef::load_workspace_policy`].
#[derive(Debug, Clone)]
pub struct ResolvedPolicy {
    /// Path on disk the policy was loaded from.
    pub source_path: Option<PathBuf>,
    /// Stable identity (source_hash + runtime_hash) of the loaded
    /// policy.
    pub identity: policy::PolicyIdentity,
    /// Display label used in human reports; matches the original input
    /// to `--against` so logs round-trip cleanly.
    pub label: String,
}

impl PolicyRef {
    /// Parse a `--against` argument into a discriminated [`PolicyRef`].
    ///
    /// Accepted shape: `path:<file>` or any path-like string that does not
    /// match a deliberately unsupported registry-backed ref shape.
    pub fn parse(s: &str) -> Result<Self, PolicyRefError> {
        if s.strip_prefix("sha256:").is_some() {
            return Err(unsupported_manifest_hash_ref());
        }
        if s.strip_prefix("version:").is_some() {
            return Err(unsupported_package_version_ref());
        }
        if let Some(rest) = s.strip_prefix("path:") {
            return Ok(Self::WorkspacePath(PathBuf::from(rest)));
        }

        if is_lower_hex_64(s) {
            return Err(unsupported_manifest_hash_ref());
        }
        if looks_like_package_version_ref(s) {
            return Err(unsupported_package_version_ref());
        }
        Ok(Self::WorkspacePath(PathBuf::from(s)))
    }

    /// Render the canonical string form of a parsed policy-ref.
    pub fn label(&self) -> String {
        match self {
            Self::WorkspacePath(path) => path.display().to_string(),
        }
    }

    /// Resolve the policy reference into a [`ResolvedPolicy`] summary.
    pub fn resolve(&self) -> Result<ResolvedPolicy, PolicyRefError> {
        match self {
            Self::WorkspacePath(path) => {
                let loaded = load_policy(path).map_err(|e| {
                    PolicyRefError::Load(format!(
                        "failed to load policy from {}: {e}",
                        path.display()
                    ))
                })?;
                Ok(ResolvedPolicy {
                    source_path: Some(path.clone()),
                    identity: loaded.identity.clone(),
                    label: self.label(),
                })
            }
        }
    }

    /// Resolve the workspace-path arm into a fully materialized
    /// [`policy::LoadedPolicy`].
    pub fn load_workspace_policy(&self) -> Result<policy::LoadedPolicy, PolicyRefError> {
        match self {
            Self::WorkspacePath(path) => load_policy(path).map_err(|e| {
                PolicyRefError::Load(format!(
                    "failed to load policy from {}: {e}",
                    path.display()
                ))
            }),
        }
    }
}

fn unsupported_manifest_hash_ref() -> PolicyRefError {
    PolicyRefError::Parse(
        "manifest-hash policy refs are not supported by `chio replay traffic --against`; supply `path:<workspace-policy.yaml>`"
            .to_string(),
    )
}

fn unsupported_package_version_ref() -> PolicyRefError {
    PolicyRefError::Parse(
        "package-version policy refs are not supported by `chio replay traffic --against`; supply `path:<workspace-policy.yaml>`"
            .to_string(),
    )
}

fn looks_like_package_version_ref(s: &str) -> bool {
    let Some((name, version)) = s.rsplit_once('@') else {
        return false;
    };
    !name.is_empty() && semver::Version::parse(version).is_ok()
}

/// `s.len() == 64 && s.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))`.
fn is_lower_hex_64(s: &str) -> bool {
    if s.len() != 64 {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_policy_ref_tests {
    use super::*;

    #[test]
    fn rejects_bare_64_char_lower_hex_manifest_ref() {
        let s = "deadbeef".repeat(8);
        let err = PolicyRef::parse(&s).unwrap_err();
        assert!(matches!(err, PolicyRefError::Parse(_)));
        assert!(err.to_string().contains("manifest-hash"));
    }

    #[test]
    fn rejects_explicit_sha256_prefix() {
        let s = format!("sha256:{}", "ab".repeat(32));
        let err = PolicyRef::parse(&s).unwrap_err();
        assert!(matches!(err, PolicyRefError::Parse(_)));
        assert!(err.to_string().contains("manifest-hash"));
    }

    #[test]
    fn rejects_uppercase_hex_to_keep_canonical_lower_only() {
        // Uppercase hex is non-canonical; falls through to path arm.
        let s = "DEADBEEF".repeat(8);
        let parsed = PolicyRef::parse(&s).unwrap();
        assert!(matches!(parsed, PolicyRef::WorkspacePath(_)));
    }

    #[test]
    fn rejects_short_hex_with_explicit_prefix() {
        let err = PolicyRef::parse("sha256:abcdef").unwrap_err();
        assert!(matches!(err, PolicyRefError::Parse(_)));
        assert!(err.to_string().contains("manifest-hash"));
    }

    #[test]
    fn rejects_package_at_semver() {
        let err = PolicyRef::parse("chio-policy@1.4.0").unwrap_err();
        assert!(matches!(err, PolicyRefError::Parse(_)));
        assert!(err.to_string().contains("package-version"));
    }

    #[test]
    fn rejects_package_with_explicit_version_prefix() {
        let err = PolicyRef::parse("version:my-policy@2.0.0-rc.1").unwrap_err();
        assert!(matches!(err, PolicyRefError::Parse(_)));
        assert!(err.to_string().contains("package-version"));
    }

    #[test]
    fn explicit_version_prefix_with_bad_semver_errors() {
        let err = PolicyRef::parse("version:foo@not.a.semver").unwrap_err();
        assert!(matches!(err, PolicyRefError::Parse(_)));
        assert!(err.to_string().contains("package-version"));
    }

    #[test]
    fn bare_at_token_falls_through_to_path_when_semver_invalid() {
        // `policy@latest` is not a valid package-version coordinate, so it
        // parses as an ordinary path-like token rather than erroring.
        let parsed = PolicyRef::parse("policy@latest").unwrap();
        assert!(matches!(parsed, PolicyRef::WorkspacePath(_)));
    }

    #[test]
    fn parses_explicit_path_prefix() {
        let parsed = PolicyRef::parse("path:/etc/chio/policies/strict.yaml").unwrap();
        match parsed {
            PolicyRef::WorkspacePath(p) => {
                assert_eq!(p, PathBuf::from("/etc/chio/policies/strict.yaml"));
            }
        }
    }

    #[test]
    fn parses_relative_path_default_arm() {
        let parsed = PolicyRef::parse("./policies/strict.yaml").unwrap();
        match parsed {
            PolicyRef::WorkspacePath(p) => {
                assert_eq!(p, PathBuf::from("./policies/strict.yaml"));
            }
        }
    }

    #[test]
    fn workspace_path_resolve_load_failure_surfaces_load_error() {
        // Path that cannot exist; resolver surfaces Load error not
        // a parse error, so callers can distinguish unsupported ref
        // shapes from "your file is missing".
        let parsed = PolicyRef::parse("path:/definitely/does/not/exist.yaml").unwrap();
        let err = parsed.resolve().unwrap_err();
        assert!(matches!(err, PolicyRefError::Load(_)), "got {err:?}");
    }

    #[test]
    fn label_round_trips_for_workspace_path() {
        let parsed = PolicyRef::parse("./policies/strict.yaml").unwrap();
        let label = parsed.label();
        assert_eq!(label, "./policies/strict.yaml");
        let reparsed = PolicyRef::parse(&label).unwrap();
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn empty_string_falls_through_to_empty_path() {
        // Edge case: empty string. We treat this as a path (empty
        // PathBuf) so the resolve step surfaces the file-not-found
        // error, rather than swallowing the input silently as a Parse
        // failure.
        let parsed = PolicyRef::parse("").unwrap();
        assert!(matches!(parsed, PolicyRef::WorkspacePath(_)));
    }

    #[test]
    fn is_lower_hex_64_helper_rejects_off_by_one_lengths() {
        assert!(!is_lower_hex_64(&"a".repeat(63)));
        assert!(!is_lower_hex_64(&"a".repeat(65)));
        assert!(is_lower_hex_64(&"a".repeat(64)));
        assert!(!is_lower_hex_64(&"A".repeat(64)));
        assert!(!is_lower_hex_64(&"g".repeat(64))); // out of [0-9a-f]
    }
}
