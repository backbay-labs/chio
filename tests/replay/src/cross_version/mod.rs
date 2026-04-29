//! Cross-version receipt-compatibility matrix loader (M04 Phase 3 T2).
//!
//! Parses `tests/replay/release_compat_matrix.toml` (authored in T1) into
//! typed structs with strict validation. Strictness is enforced at three
//! layers:
//!
//! 1. `#[serde(deny_unknown_fields)]` on every struct so a typo in the
//!    TOML (e.g. `bunlde_url`) errors at load time instead of silently
//!    dropping. Fail-closed by construction.
//! 2. `CompatLevel` is a typed enum (`supported | best_effort | broken`)
//!    so a bogus value (`"sorta"`) is rejected by serde before any
//!    domain validation runs.
//! 3. A `validate()` pass on every entry checks shape-level invariants
//!    that serde cannot express on its own: tag regex, sha256 hex shape,
//!    `https://` URL scheme, and `YYYY-MM-DD` date format.
//!
//! The schema field MUST equal `"chio.replay.compat/v1"`. Any other value
//! - including the empty string - is rejected.
//!
//! `window` defaults to 5 (the ratchet floor specified in the source-of-truth
//! document and the matrix file's leading comment).
//!
//! Phase 3 T3 extends this module with a [`fetch`] submodule that hits
//! `bundle_url`, pins the response by `bundle_sha256`, and caches the bundle
//! on disk under `$CHIO_REPLAY_CACHE_DIR` (default: `$HOME/.cache/chio/
//! replay-bundles/<tag>/replay-bundle.tgz`). T4 adds the [`reverify`]
//! submodule that drives the current `chio-kernel` verifier over a fetched
//! bundle.

use std::collections::HashSet;
use std::path::Path;

use serde::Deserialize;

pub mod fetch;
pub mod reverify;

/// Required schema tag at the top of `release_compat_matrix.toml`.
pub const SCHEMA_TAG: &str = "chio.replay.compat/v1";

/// Default ratchet window (last N tagged releases supported by current main).
pub const DEFAULT_WINDOW: u32 = 5;

/// Top-level compatibility-matrix document.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompatMatrix {
    /// Schema tag. MUST equal [`SCHEMA_TAG`].
    pub schema: String,
    /// Ratchet window: how many recent tags are `supported` by current main.
    /// Defaults to [`DEFAULT_WINDOW`] when absent.
    #[serde(default = "default_window")]
    pub window: u32,
    /// Per-release compatibility entries (the `[[entry]]` array of tables).
    #[serde(default)]
    pub entry: Vec<CompatEntry>,
}

/// One row of the compatibility matrix.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompatEntry {
    /// Release tag. MUST match `^v\d+\.\d+(\.\d+)?$`.
    pub tag: String,
    /// Release date as `YYYY-MM-DD`.
    pub released_at: String,
    /// Bundle download URL. MUST be `https://`.
    pub bundle_url: String,
    /// Lowercase hex SHA-256 digest of the bundle (64 chars).
    pub bundle_sha256: String,
    /// Compatibility level (typed enum, not a free string).
    pub compat: CompatLevel,
    /// Optional cap tag honoured strictly while `compat == Supported`.
    pub supported_until: Option<String>,
    /// Free-form release-engineering note. Defaults to empty.
    #[serde(default)]
    pub notes: String,
}

/// Compatibility level for a tagged release vs current main.
#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum CompatLevel {
    /// Within the ratchet window; current main MUST replay this bundle byte-for-byte.
    Supported,
    /// Outside the ratchet window; current main SHOULD replay but failures are non-blocking.
    BestEffort,
    /// Known-incompatible. Skipped by the cross-version harness.
    Broken,
}

/// Errors surfaced by [`CompatMatrix::load`].
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// Failed to read the file (missing, permission denied, etc.).
    #[error("read failure: {0}")]
    Read(#[from] std::io::Error),
    /// File contained non-UTF-8 bytes.
    #[error("invalid utf-8 in matrix file: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),
    /// TOML parse failed (syntax error, type mismatch, unknown field, ...).
    #[error("toml parse failure: {0}")]
    Parse(#[from] toml::de::Error),
    /// `schema` field did not equal [`SCHEMA_TAG`].
    #[error("schema must equal {expected:?}, was {actual:?}")]
    SchemaMismatch {
        /// Expected schema tag.
        expected: &'static str,
        /// Actual value found in the file.
        actual: String,
    },
    /// `tag` did not match `^v\d+\.\d+(\.\d+)?$`.
    #[error("invalid tag {0:?}: must match v<major>.<minor>(.<patch>)?")]
    InvalidTag(String),
    /// `supported_until` did not match `^v\d+\.\d+(\.\d+)?$`.
    #[error("invalid supported_until {0:?}: must match v<major>.<minor>(.<patch>)?")]
    InvalidSupportedUntil(String),
    /// Two `[[entry]]` blocks declared the same `tag`.
    #[error("duplicate tag {0:?}: each release must appear at most once")]
    DuplicateTag(String),
    /// `bundle_sha256` was not 64 chars of lowercase hex.
    #[error("invalid bundle_sha256 {0:?}: must be 64-char lowercase hex")]
    InvalidSha256(String),
    /// `bundle_url` did not start with `https://`.
    #[error("invalid bundle_url {0:?}: must use https:// scheme")]
    InvalidUrl(String),
    /// `released_at` was not `YYYY-MM-DD`.
    #[error("invalid released_at {0:?}: must be YYYY-MM-DD")]
    InvalidDate(String),
}

impl CompatMatrix {
    /// Load and validate the matrix from `path`.
    ///
    /// Returns a [`LoadError`] on the first failure (read, UTF-8, TOML
    /// parse, unknown field, schema mismatch, or any per-entry shape
    /// violation).
    pub fn load(path: &Path) -> Result<Self, LoadError> {
        let bytes = std::fs::read(path)?;
        let text = std::str::from_utf8(&bytes)?;
        Self::from_toml_str(text)
    }

    /// Parse and validate the matrix from an in-memory TOML string.
    ///
    /// Exposed for unit tests that construct synthetic inputs. Named
    /// `from_toml_str` (not `from_str`) to avoid clashing with the
    /// `std::str::FromStr` trait method, since this constructor is
    /// fallible with a domain-specific error type rather than a
    /// blanket `FromStr::Err`.
    pub fn from_toml_str(text: &str) -> Result<Self, LoadError> {
        let matrix: Self = toml::from_str(text)?;
        matrix.validate()?;
        Ok(matrix)
    }

    fn validate(&self) -> Result<(), LoadError> {
        if self.schema != SCHEMA_TAG {
            return Err(LoadError::SchemaMismatch {
                expected: SCHEMA_TAG,
                actual: self.schema.clone(),
            });
        }
        // Track seen tags so duplicate `[[entry]]` blocks reject at load
        // time. A duplicate tag could carry conflicting compat / sha256 /
        // bundle_url values for a single release, leaving downstream
        // consumers ambiguous about which row to honour.
        let mut seen_tags: HashSet<&str> = HashSet::with_capacity(self.entry.len());
        for entry in &self.entry {
            entry.validate()?;
            if !seen_tags.insert(entry.tag.as_str()) {
                return Err(LoadError::DuplicateTag(entry.tag.clone()));
            }
        }
        Ok(())
    }
}

impl CompatEntry {
    fn validate(&self) -> Result<(), LoadError> {
        if !is_valid_tag(&self.tag) {
            return Err(LoadError::InvalidTag(self.tag.clone()));
        }
        if !is_valid_sha256(&self.bundle_sha256) {
            return Err(LoadError::InvalidSha256(self.bundle_sha256.clone()));
        }
        if !self.bundle_url.starts_with("https://") {
            return Err(LoadError::InvalidUrl(self.bundle_url.clone()));
        }
        if !is_valid_date(&self.released_at) {
            return Err(LoadError::InvalidDate(self.released_at.clone()));
        }
        // `supported_until` is optional, but when present it must obey the
        // same `^v\d+\.\d+(\.\d+)?$` shape as `tag`. A bogus value such as
        // "v3.beta" would otherwise pass through the loader and corrupt
        // compatibility-window decisions downstream.
        if let Some(cap) = self.supported_until.as_deref() {
            if !is_valid_tag(cap) {
                return Err(LoadError::InvalidSupportedUntil(cap.to_string()));
            }
        }
        Ok(())
    }
}

fn default_window() -> u32 {
    DEFAULT_WINDOW
}

/// Return `true` iff `s` matches `^v\d+\.\d+(\.\d+)?$`.
///
/// Hand-rolled instead of pulling in `regex` to keep dependency surface
/// small and to avoid the workspace-wide `regex` build cost.
fn is_valid_tag(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('v') else {
        return false;
    };
    let parts: Vec<&str> = rest.split('.').collect();
    if !(parts.len() == 2 || parts.len() == 3) {
        return false;
    }
    parts
        .iter()
        .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

/// Return `true` iff `s` is exactly 64 chars of lowercase ASCII hex.
fn is_valid_sha256(s: &str) -> bool {
    s.len() == 64
        && s.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// Return `true` iff `s` is a strict `YYYY-MM-DD` calendar date.
///
/// Uses `chrono::NaiveDate::parse_from_str`, which is already a
/// `tests/replay` dependency. Catches leap-year and out-of-range edge
/// cases that a regex would miss (`2026-02-30` would pass a regex but
/// fails chrono).
///
/// `parse_from_str` is padding-agnostic for `%m` and `%d` (it accepts
/// `2026-1-1`), so an explicit length-and-shape pre-check enforces the
/// strict zero-padded `YYYY-MM-DD` form before delegating to chrono.
fn is_valid_date(s: &str) -> bool {
    if s.len() != 10 {
        return false;
    }
    let bytes = s.as_bytes();
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let digits_only = bytes
        .iter()
        .enumerate()
        .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit());
    if !digits_only {
        return false;
    }
    chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok()
}

#[cfg(test)]
mod loader_tests {
    //! Loader unit tests. `expect`/`expect_err` are allowed in this
    //! module so test failures surface readable messages; this matches
    //! the established pattern in `driver::tests` and `fs_iter::tests`.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::path::Path;

    /// A known-good TOML body used as a base for the rejection-path tests.
    /// Each negative test starts from this and mutates exactly one field.
    const VALID_BASE: &str = r#"
schema = "chio.replay.compat/v1"
window = 5

[[entry]]
tag = "v0.1.0"
released_at = "2025-08-12"
bundle_url = "https://example.test/v0.1.0.tgz"
bundle_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
compat = "best_effort"
supported_until = "v3.0"
notes = "fixture"
"#;

    /// Sanity-check the base fixture itself is accepted, otherwise the
    /// rejection-path tests below would all be vacuously passing.
    #[test]
    fn valid_base_loads() {
        CompatMatrix::from_toml_str(VALID_BASE).expect("base fixture must load");
    }

    /// Happy path: load the actual file authored in T1 and assert the
    /// shape we expect (>=2 entries, schema tag, two known versions).
    #[test]
    fn happy_path_loads_real_file() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("release_compat_matrix.toml");
        let m = CompatMatrix::load(&path).expect("real matrix file must load");
        assert_eq!(m.schema, SCHEMA_TAG);
        assert_eq!(m.window, 5);
        assert!(
            m.entry.len() >= 2,
            "expected at least v0.1.0 and v2.0 entries, got {}",
            m.entry.len()
        );
        let tags: Vec<&str> = m.entry.iter().map(|e| e.tag.as_str()).collect();
        assert!(tags.contains(&"v0.1.0"), "expected v0.1.0 in {tags:?}");
        assert!(tags.contains(&"v2.0"), "expected v2.0 in {tags:?}");
    }

    /// Unknown root-level field rejected by `deny_unknown_fields`.
    #[test]
    fn rejects_unknown_field_at_root() {
        let bad = r#"
schema = "chio.replay.compat/v1"
window = 5
extra_field = "not allowed"
"#;
        let err = CompatMatrix::from_toml_str(bad).expect_err("unknown root field must reject");
        assert!(
            matches!(err, LoadError::Parse(_)),
            "expected Parse error from deny_unknown_fields, got {err:?}"
        );
    }

    /// Unknown per-entry field rejected by `deny_unknown_fields`.
    #[test]
    fn rejects_unknown_field_in_entry() {
        let bad = VALID_BASE.replace(
            "notes = \"fixture\"",
            "notes = \"fixture\"\nbunlde_url = \"typo\"",
        );
        let err = CompatMatrix::from_toml_str(&bad).expect_err("typo must reject");
        assert!(
            matches!(err, LoadError::Parse(_)),
            "expected Parse error from deny_unknown_fields, got {err:?}"
        );
    }

    /// Wrong schema tag rejected with a structured `SchemaMismatch`.
    #[test]
    fn rejects_bad_schema_tag() {
        let bad = VALID_BASE.replace(
            "schema = \"chio.replay.compat/v1\"",
            "schema = \"chio.replay.compat/v2\"",
        );
        let err = CompatMatrix::from_toml_str(&bad).expect_err("wrong schema must reject");
        match err {
            LoadError::SchemaMismatch { expected, actual } => {
                assert_eq!(expected, SCHEMA_TAG);
                assert_eq!(actual, "chio.replay.compat/v2");
            }
            other => panic!("expected SchemaMismatch, got {other:?}"),
        }
    }

    /// SHA-256 not exactly 64 lowercase hex chars rejected.
    #[test]
    fn rejects_malformed_sha256_short() {
        let bad = VALID_BASE.replace(
            "bundle_sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"",
            "bundle_sha256 = \"deadbeef\"",
        );
        let err = CompatMatrix::from_toml_str(&bad).expect_err("short sha256 must reject");
        assert!(
            matches!(&err, LoadError::InvalidSha256(s) if s == "deadbeef"),
            "expected InvalidSha256(deadbeef), got {err:?}"
        );
    }

    /// Uppercase-hex SHA-256 rejected (fail-closed: lowercase only).
    #[test]
    fn rejects_uppercase_sha256() {
        let bad = VALID_BASE.replace(
            "bundle_sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"",
            "bundle_sha256 = \"DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF\"",
        );
        let err = CompatMatrix::from_toml_str(&bad).expect_err("uppercase hex must reject");
        assert!(
            matches!(err, LoadError::InvalidSha256(_)),
            "expected InvalidSha256, got {err:?}"
        );
    }

    /// Non-`https://` URL rejected (no `http://`, no `file://`, no relative paths).
    #[test]
    fn rejects_non_https_url() {
        let bad = VALID_BASE.replace(
            "bundle_url = \"https://example.test/v0.1.0.tgz\"",
            "bundle_url = \"http://example.test/v0.1.0.tgz\"",
        );
        let err = CompatMatrix::from_toml_str(&bad).expect_err("http:// must reject");
        assert!(
            matches!(&err, LoadError::InvalidUrl(s) if s.starts_with("http://")),
            "expected InvalidUrl for http://, got {err:?}"
        );
    }

    /// Tag without leading `v` rejected.
    #[test]
    fn rejects_malformed_tag_missing_v() {
        let bad = VALID_BASE.replace("tag = \"v0.1.0\"", "tag = \"0.1.0\"");
        let err = CompatMatrix::from_toml_str(&bad).expect_err("tag without v must reject");
        assert!(
            matches!(&err, LoadError::InvalidTag(s) if s == "0.1.0"),
            "expected InvalidTag(0.1.0), got {err:?}"
        );
    }

    /// Tag with non-numeric component rejected.
    #[test]
    fn rejects_malformed_tag_alpha_component() {
        let bad = VALID_BASE.replace("tag = \"v0.1.0\"", "tag = \"v0.1.beta\"");
        let err = CompatMatrix::from_toml_str(&bad).expect_err("alpha tag must reject");
        assert!(
            matches!(err, LoadError::InvalidTag(_)),
            "expected InvalidTag, got {err:?}"
        );
    }

    /// Date in wrong format rejected.
    #[test]
    fn rejects_malformed_date_wrong_separator() {
        let bad = VALID_BASE.replace(
            "released_at = \"2025-08-12\"",
            "released_at = \"2025/08/12\"",
        );
        let err = CompatMatrix::from_toml_str(&bad).expect_err("slash date must reject");
        assert!(
            matches!(&err, LoadError::InvalidDate(s) if s == "2025/08/12"),
            "expected InvalidDate(2025/08/12), got {err:?}"
        );
    }

    /// Calendar-impossible date rejected (chrono catches what regex misses).
    #[test]
    fn rejects_malformed_date_impossible_day() {
        let bad = VALID_BASE.replace(
            "released_at = \"2025-08-12\"",
            "released_at = \"2026-02-30\"",
        );
        let err = CompatMatrix::from_toml_str(&bad).expect_err("Feb 30 must reject");
        assert!(
            matches!(&err, LoadError::InvalidDate(s) if s == "2026-02-30"),
            "expected InvalidDate(2026-02-30), got {err:?}"
        );
    }

    /// Strict YYYY-MM-DD: padding-light forms must reject. `chrono`'s
    /// `%m`/`%d` are padding-agnostic and will accept `2026-1-1`; the
    /// loader pre-checks the literal `YYYY-MM-DD` shape first so a
    /// human-typed unpadded date is caught up front.
    #[test]
    fn rejects_unpadded_month_and_day() {
        for unpadded in ["2026-1-1", "2026-1-01", "2026-01-1", "2026-1-15"] {
            let bad = VALID_BASE.replace(
                "released_at = \"2025-08-12\"",
                &format!("released_at = \"{unpadded}\""),
            );
            let err =
                CompatMatrix::from_toml_str(&bad).expect_err("unpadded month/day must reject");
            assert!(
                matches!(&err, LoadError::InvalidDate(s) if s == unpadded),
                "expected InvalidDate({unpadded}), got {err:?}"
            );
        }
    }

    /// Unknown `compat` enum variant rejected by serde at parse time.
    #[test]
    fn rejects_invalid_compat_level() {
        let bad = VALID_BASE.replace("compat = \"best_effort\"", "compat = \"sorta\"");
        let err = CompatMatrix::from_toml_str(&bad).expect_err("bogus compat must reject");
        assert!(
            matches!(err, LoadError::Parse(_)),
            "expected Parse error from enum mismatch, got {err:?}"
        );
    }

    /// `window` defaults to 5 when absent (matches the matrix-file comment).
    #[test]
    fn window_defaults_to_5_when_absent() {
        let no_window = r#"
schema = "chio.replay.compat/v1"
"#;
        let m = CompatMatrix::from_toml_str(no_window).expect("schema-only must load");
        assert_eq!(m.window, DEFAULT_WINDOW);
        assert_eq!(m.window, 5);
        assert!(m.entry.is_empty());
    }

    /// `notes` defaults to empty string when absent.
    #[test]
    fn notes_defaults_to_empty_when_absent() {
        let no_notes = r#"
schema = "chio.replay.compat/v1"

[[entry]]
tag = "v1.0"
released_at = "2025-12-01"
bundle_url = "https://example.test/v1.0.tgz"
bundle_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
compat = "supported"
"#;
        let m = CompatMatrix::from_toml_str(no_notes).expect("entry without notes must load");
        assert_eq!(m.entry[0].notes, "");
        assert_eq!(m.entry[0].supported_until, None);
        assert_eq!(m.entry[0].compat, CompatLevel::Supported);
    }

    /// `supported_until` must obey the same tag shape as `tag` itself.
    /// A value like `"v3.beta"` would otherwise corrupt compatibility-
    /// window decisions further downstream.
    #[test]
    fn rejects_malformed_supported_until() {
        let bad = VALID_BASE.replace(
            "supported_until = \"v3.0\"",
            "supported_until = \"v3.beta\"",
        );
        let err =
            CompatMatrix::from_toml_str(&bad).expect_err("malformed supported_until must reject");
        assert!(
            matches!(&err, LoadError::InvalidSupportedUntil(s) if s == "v3.beta"),
            "expected InvalidSupportedUntil(v3.beta), got {err:?}"
        );
    }

    /// `supported_until` without the leading `v` is rejected (mirrors the
    /// `tag` rule).
    #[test]
    fn rejects_supported_until_missing_v_prefix() {
        let bad = VALID_BASE.replace("supported_until = \"v3.0\"", "supported_until = \"3.0\"");
        let err =
            CompatMatrix::from_toml_str(&bad).expect_err("supported_until missing v must reject");
        assert!(
            matches!(&err, LoadError::InvalidSupportedUntil(s) if s == "3.0"),
            "expected InvalidSupportedUntil(3.0), got {err:?}"
        );
    }

    /// Two `[[entry]]` blocks sharing the same `tag` must reject at load
    /// time. Otherwise downstream consumers can disagree about which row
    /// describes the release (first-match vs all-rows iteration).
    #[test]
    fn rejects_duplicate_tag_entries() {
        let bad = r#"
schema = "chio.replay.compat/v1"

[[entry]]
tag = "v1.0"
released_at = "2025-12-01"
bundle_url = "https://example.test/v1.0-a.tgz"
bundle_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
compat = "supported"

[[entry]]
tag = "v1.0"
released_at = "2025-12-02"
bundle_url = "https://example.test/v1.0-b.tgz"
bundle_sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
compat = "best_effort"
"#;
        let err = CompatMatrix::from_toml_str(bad).expect_err("duplicate tag must reject");
        assert!(
            matches!(&err, LoadError::DuplicateTag(s) if s == "v1.0"),
            "expected DuplicateTag(v1.0), got {err:?}"
        );
    }

    /// All three CompatLevel variants round-trip through the snake_case
    /// serde rename (regression guard against accidental rename changes).
    #[test]
    fn all_compat_levels_parse() {
        for (raw, expected) in [
            ("supported", CompatLevel::Supported),
            ("best_effort", CompatLevel::BestEffort),
            ("broken", CompatLevel::Broken),
        ] {
            let body = format!(
                r#"
schema = "chio.replay.compat/v1"

[[entry]]
tag = "v1.0"
released_at = "2025-12-01"
bundle_url = "https://example.test/x.tgz"
bundle_sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
compat = "{raw}"
"#
            );
            let m = CompatMatrix::from_toml_str(&body)
                .unwrap_or_else(|e| panic!("variant {raw} must parse: {e}"));
            assert_eq!(m.entry[0].compat, expected, "variant {raw}");
        }
    }
}
