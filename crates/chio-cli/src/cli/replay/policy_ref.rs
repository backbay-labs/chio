// Policy-reference parser and resolver for `chio replay traffic --against`.
//
// Three discriminated shapes:
// 1. Manifest hash: 64-char lower-hex sha256 (optionally prefixed `sha256:`).
//    Resolution requires the manifest registry; surfaces NotResolvable until
//    that registry lands.
// 2. Package version: `<name>@<semver>` (e.g. `chio-policy@1.4.0`).
//    Same: NotResolvable until the package registry is wired.
// 3. Workspace path: absolute or relative filesystem path to a YAML policy.
//    Fully resolvable now.

/// Parsed and discriminated policy reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyRef {
    /// 32-byte sha256 digest of a policy manifest (lower-hex on the wire).
    ManifestHash([u8; 32]),
    /// `<name>@<semver>` package coordinate.
    PackageVersion(String, semver::Version),
    /// Absolute or relative workspace filesystem path to a policy file.
    WorkspacePath(PathBuf),
}

/// Errors surfaced by [`PolicyRef::parse`] and [`PolicyRef::resolve`].
#[derive(Debug, thiserror::Error)]
pub enum PolicyRefError {
    /// The supplied string did not match any of the three accepted
    /// shapes (hash / package@version / path), or matched an explicit
    /// prefix that subsequently failed to validate.
    #[error("policy-ref does not parse: {0}")]
    Parse(String),

    /// The workspace path arm pointed at a file that could not be
    /// loaded by the underlying [`load_policy`] flow.
    #[error("workspace policy path failed to load: {0}")]
    Load(String),

    /// Manifest-hash and package-version arms require registry integration
    /// that is not yet wired. Callers can fall back to the workspace-path arm.
    #[error("policy-ref shape not yet resolvable in chio-cli: {0}")]
    NotResolvable(String),
}

/// Resolved-policy summary used by reports. For the full materialized
/// [`policy::LoadedPolicy`] use [`PolicyRef::load_workspace_policy`].
#[derive(Debug, Clone)]
pub struct ResolvedPolicy {
    /// Path on disk the policy was loaded from, when applicable. `None`
    /// for hash and package-version arms once they are wired up.
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
    /// Discriminator order:
    ///
    /// 1. Explicit prefix wins: `sha256:` -> `ManifestHash`,
    ///    `version:` -> `PackageVersion`, `path:` -> `WorkspacePath`.
    /// 2. Otherwise the input is fingerprinted by shape:
    ///    - 64 lower-hex characters -> `ManifestHash`.
    ///    - Contains `@` and the suffix parses as `semver::Version` ->
    ///      `PackageVersion`.
    ///    - Anything else falls through to `WorkspacePath`.
    pub fn parse(s: &str) -> Result<Self, PolicyRefError> {
        if let Some(rest) = s.strip_prefix("sha256:") {
            return Self::parse_manifest_hash(rest);
        }
        if let Some(rest) = s.strip_prefix("version:") {
            return Self::parse_package_version(rest);
        }
        if let Some(rest) = s.strip_prefix("path:") {
            return Ok(Self::WorkspacePath(PathBuf::from(rest)));
        }

        if is_lower_hex_64(s) {
            return Self::parse_manifest_hash(s);
        }
        if let Some((name, version)) = s.rsplit_once('@') {
            // `@` could appear in path-on-NFS shapes; only treat as
            // package coordinate when the suffix parses as semver and
            // the name is a non-empty identifier.
            if !name.is_empty() {
                if let Ok(parsed) = semver::Version::parse(version) {
                    return Ok(Self::PackageVersion(name.to_string(), parsed));
                }
            }
        }
        Ok(Self::WorkspacePath(PathBuf::from(s)))
    }

    fn parse_manifest_hash(s: &str) -> Result<Self, PolicyRefError> {
        if !is_lower_hex_64(s) {
            return Err(PolicyRefError::Parse(format!(
                "manifest hash must be 64 lowercase hex characters, got {} char(s)",
                s.len()
            )));
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).map_err(|e| {
            PolicyRefError::Parse(format!("hex decode failed for manifest hash: {e}"))
        })?;
        Ok(Self::ManifestHash(out))
    }

    fn parse_package_version(s: &str) -> Result<Self, PolicyRefError> {
        let (name, version) = s.rsplit_once('@').ok_or_else(|| {
            PolicyRefError::Parse(format!(
                "package-version ref expects `<name>@<semver>`, got {s:?}"
            ))
        })?;
        if name.is_empty() {
            return Err(PolicyRefError::Parse(
                "package-version ref has empty name".to_string(),
            ));
        }
        let parsed = semver::Version::parse(version).map_err(|e| {
            PolicyRefError::Parse(format!(
                "package-version semver parse failed for {version:?}: {e}"
            ))
        })?;
        Ok(Self::PackageVersion(name.to_string(), parsed))
    }

    /// Render the canonical string form of a parsed policy-ref. The
    /// output round-trips through [`PolicyRef::parse`] when the input
    /// was a workspace path or a 64-char hex hash. Package-version refs
    /// emit the `<name>@<semver>` shape (no `version:` prefix) so the
    /// label matches Cargo conventions.
    pub fn label(&self) -> String {
        match self {
            Self::ManifestHash(bytes) => format!("sha256:{}", hex::encode(bytes)),
            Self::PackageVersion(name, version) => format!("{name}@{version}"),
            Self::WorkspacePath(path) => path.display().to_string(),
        }
    }

    /// Resolve the policy reference into a [`ResolvedPolicy`] summary.
    ///
    /// Only the [`Self::WorkspacePath`] arm fully resolves; the other two
    /// surface [`PolicyRefError::NotResolvable`] until registry integration
    /// lands.
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
            Self::ManifestHash(_) => Err(PolicyRefError::NotResolvable(format!(
                "manifest-hash policy-refs require the manifest registry; \
                 supply `path:<workspace-path>` instead until the registry \
                 lands. Ref: {}",
                self.label()
            ))),
            Self::PackageVersion(name, version) => Err(PolicyRefError::NotResolvable(format!(
                "package-version policy-refs ({name}@{version}) require the \
                 package registry integration; supply `path:<workspace-path>` \
                 instead until the registry lands."
            ))),
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
            Self::ManifestHash(_) | Self::PackageVersion(_, _) => {
                Err(PolicyRefError::NotResolvable(format!(
                    "non-path policy-refs cannot materialize a kernel \
                     in T2; supply `path:<workspace-path>` instead. Ref: {}",
                    self.label()
                )))
            }
        }
    }
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
    fn parses_bare_64_char_lower_hex_as_manifest_hash() {
        let s = "deadbeef".repeat(8);
        let parsed = PolicyRef::parse(&s).unwrap();
        match parsed {
            PolicyRef::ManifestHash(bytes) => {
                assert_eq!(bytes.len(), 32);
                let mut expected = [0u8; 32];
                hex::decode_to_slice(&s, &mut expected).unwrap();
                assert_eq!(bytes, expected);
            }
            other => panic!("expected ManifestHash, got {other:?}"),
        }
    }

    #[test]
    fn parses_explicit_sha256_prefix() {
        let s = format!("sha256:{}", "ab".repeat(32));
        let parsed = PolicyRef::parse(&s).unwrap();
        assert!(matches!(parsed, PolicyRef::ManifestHash(_)));
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
    }

    #[test]
    fn parses_package_at_semver() {
        let parsed = PolicyRef::parse("chio-policy@1.4.0").unwrap();
        match parsed {
            PolicyRef::PackageVersion(name, version) => {
                assert_eq!(name, "chio-policy");
                assert_eq!(version, semver::Version::parse("1.4.0").unwrap());
            }
            other => panic!("expected PackageVersion, got {other:?}"),
        }
    }

    #[test]
    fn parses_package_with_explicit_version_prefix() {
        let parsed = PolicyRef::parse("version:my-policy@2.0.0-rc.1").unwrap();
        match parsed {
            PolicyRef::PackageVersion(name, version) => {
                assert_eq!(name, "my-policy");
                assert_eq!(version, semver::Version::parse("2.0.0-rc.1").unwrap());
            }
            other => panic!("expected PackageVersion, got {other:?}"),
        }
    }

    #[test]
    fn explicit_version_prefix_with_bad_semver_errors() {
        let err = PolicyRef::parse("version:foo@not.a.semver").unwrap_err();
        assert!(matches!(err, PolicyRefError::Parse(_)));
    }

    #[test]
    fn bare_at_token_falls_through_to_path_when_semver_invalid() {
        // `policy@latest` is not semver; treat as a path so users can't
        // accidentally route an alias through the package-version arm.
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
            other => panic!("expected WorkspacePath, got {other:?}"),
        }
    }

    #[test]
    fn parses_relative_path_default_arm() {
        let parsed = PolicyRef::parse("./policies/strict.yaml").unwrap();
        match parsed {
            PolicyRef::WorkspacePath(p) => {
                assert_eq!(p, PathBuf::from("./policies/strict.yaml"));
            }
            other => panic!("expected WorkspacePath, got {other:?}"),
        }
    }

    #[test]
    fn manifest_hash_resolve_returns_not_resolvable() {
        let s = "0123456789abcdef".repeat(4);
        let parsed = PolicyRef::parse(&s).unwrap();
        let err = parsed.resolve().unwrap_err();
        assert!(
            matches!(err, PolicyRefError::NotResolvable(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn package_version_resolve_returns_not_resolvable() {
        let parsed = PolicyRef::parse("chio-policy@1.0.0").unwrap();
        let err = parsed.resolve().unwrap_err();
        assert!(
            matches!(err, PolicyRefError::NotResolvable(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn workspace_path_resolve_load_failure_surfaces_load_error() {
        // Path that cannot exist; resolver surfaces Load error not
        // NotResolvable, so callers can distinguish "registry not wired"
        // from "your file is missing".
        let parsed = PolicyRef::parse("path:/definitely/does/not/exist.yaml").unwrap();
        let err = parsed.resolve().unwrap_err();
        assert!(matches!(err, PolicyRefError::Load(_)), "got {err:?}");
    }

    #[test]
    fn label_round_trips_for_manifest_hash() {
        let s = "deadbeef".repeat(8);
        let parsed = PolicyRef::parse(&s).unwrap();
        let label = parsed.label();
        assert_eq!(label, format!("sha256:{s}"));
        // Round-trip: the label parses back to the same shape.
        let reparsed = PolicyRef::parse(&label).unwrap();
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn label_round_trips_for_package_version() {
        let parsed = PolicyRef::parse("chio-policy@1.4.0").unwrap();
        let label = parsed.label();
        assert_eq!(label, "chio-policy@1.4.0");
        let reparsed = PolicyRef::parse(&label).unwrap();
        assert_eq!(parsed, reparsed);
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

    #[test]
    fn load_workspace_policy_errors_for_non_path_arm() {
        let s = "0123456789abcdef".repeat(4);
        let parsed = PolicyRef::parse(&s).unwrap();
        // `LoadedPolicy` is not Debug, so we destructure manually
        // instead of calling `.unwrap_err()`.
        match parsed.load_workspace_policy() {
            Err(PolicyRefError::NotResolvable(_)) => {}
            Err(other) => panic!("expected NotResolvable, got {other:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }
}
