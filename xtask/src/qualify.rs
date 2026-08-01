//! Release / profile qualification gates (`cargo xtask qualify <profile>`).
//!
//! Each profile is a leaf that asserts a machine-readable contract.
//!
//! Fail-closed contract:
//! - [`KNOWN_PROFILES`] enumerates every implemented profile at compile time;
//!   an unknown profile on the CLI is an error, never a skip.
//! - A profile whose contract document is missing, malformed, or drifted from
//!   the asserted shape fails the gate. Nothing is silently tolerated.
//!
//! `bounded-chio` is the ship-facing bounded release boundary. It asserts the
//! structural shape of `docs/standards/CHIO_BOUNDED_QUALIFICATION_MATRIX.json`:
//! it must be valid JSON, declare the bounded scope, carry a non-empty set of
//! gate conditions, point its `entrypoint` at the live gate, and reference its
//! operational profile document, which must exist on disk.

use std::fs;
use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use crate::XtaskError;

/// Relative path (from the workspace root) of the bounded qualification matrix.
pub(crate) const BOUNDED_MATRIX_PATH: &str =
    "docs/standards/CHIO_BOUNDED_QUALIFICATION_MATRIX.json";

/// The canonical entrypoint string the bounded matrix must advertise. The gate
/// asserts the matrix stays pointed at this live gate.
pub(crate) const BOUNDED_ENTRYPOINT: &str = "cargo xtask qualify bounded-chio";

/// The bounded matrix scope discriminator. A drift here means the matrix no
/// longer describes the ship-facing bounded release boundary.
const BOUNDED_SCOPE: &str = "bounded_chio_release_qualification";

const REQUIRED_COGNITION_MARKET_GATES: [&str; 3] = ["COGM9-01", "COGM9-02", "COGM9-03"];

/// The implemented qualification profiles. Compile-time fail-closed
/// enumeration: the CLI rejects anything not listed here.
pub(crate) const KNOWN_PROFILES: [&str; 1] = ["bounded-chio"];

/// Run a qualification profile by name. Fail-closed: an unknown profile is an
/// error, not a skip.
pub(crate) fn run(profile: &str) -> Result<(), XtaskError> {
    let root = crate::workspace_root()?;
    match profile {
        "bounded-chio" => bounded_chio(&root),
        other => Err(XtaskError::Usage(format!(
            "unknown qualification profile: {other} (known: {})",
            KNOWN_PROFILES.join(", ")
        ))),
    }
}

/// Assert the bounded qualification matrix contract. See the module docs for
/// the shape this enforces.
fn bounded_chio(root: &Path) -> Result<(), XtaskError> {
    let matrix_path = root.join(BOUNDED_MATRIX_PATH);
    let raw = fs::read_to_string(&matrix_path)
        .map_err(|err| XtaskError::Io(display(&matrix_path), err))?;
    let matrix: Value =
        serde_json::from_str(&raw).map_err(|err| XtaskError::Json(display(&matrix_path), err))?;

    assert_bounded_matrix(&matrix)?;

    // The matrix names its operational profile document; the bounded release
    // boundary is incoherent if that document is absent, so assert it exists on
    // disk.
    let profile_doc = matrix
        .get("profile")
        .and_then(|p| p.get("document"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            XtaskError::Validation(format!(
                "{}: profile.document is missing or not a string",
                display(&matrix_path)
            ))
        })?;
    // Reject an absolute or escaping profile path before resolving it. A
    // `profile.document` that points outside the repo would make the bounded
    // boundary unverifiable.
    let profile_path = resolve_repo_relative(root, profile_doc)?;
    if !profile_path.is_file() {
        return Err(XtaskError::Validation(format!(
            "bounded operational profile document is missing on disk: {profile_doc}"
        )));
    }

    let conditions = matrix
        .get("gateConditions")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            XtaskError::Validation("bounded matrix has no gateConditions array".into())
        })?;
    for condition in conditions {
        let id = condition
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>");
        let witnesses = condition
            .get("witnesses")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                XtaskError::Validation(format!(
                    "bounded matrix gate condition {id} has no witnesses array"
                ))
            })?;
        if witnesses.is_empty() {
            return Err(XtaskError::Validation(format!(
                "bounded matrix gate condition {id} has no witnesses"
            )));
        }
        for witness in witnesses {
            let path = witness.as_str().ok_or_else(|| {
                XtaskError::Validation(format!(
                    "bounded matrix gate condition {id} has a non-string witness"
                ))
            })?;
            if !resolve_repo_relative(root, path)?.is_file() {
                return Err(XtaskError::Validation(format!(
                    "bounded matrix gate condition {id} witness is missing: {path}"
                )));
            }
        }
    }

    let conditions = matrix
        .get("gateConditions")
        .and_then(Value::as_array)
        .map(|c| c.len())
        .unwrap_or(0);
    println!(
        "qualify bounded-chio: {} in sync (scope={BOUNDED_SCOPE}, {conditions} gate conditions, entrypoint={BOUNDED_ENTRYPOINT}, profile={profile_doc})",
        display(&matrix_path)
    );
    Ok(())
}

/// Structural assertions over the bounded matrix value. Kept separate so a unit
/// test can exercise the fail-closed branches against in-memory fixtures
/// without touching the filesystem.
fn assert_bounded_matrix(matrix: &Value) -> Result<(), XtaskError> {
    match matrix.get("scope").and_then(Value::as_str) {
        Some(BOUNDED_SCOPE) => {}
        other => {
            return Err(XtaskError::Validation(format!(
                "bounded matrix scope drifted: expected {BOUNDED_SCOPE}, found {other:?}"
            )));
        }
    }
    match matrix.get("entrypoint").and_then(Value::as_str) {
        Some(BOUNDED_ENTRYPOINT) => {}
        other => {
            return Err(XtaskError::Validation(format!(
                "bounded matrix entrypoint drifted: expected {BOUNDED_ENTRYPOINT:?}, found {other:?}"
            )));
        }
    }
    let conditions = matrix
        .get("gateConditions")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            XtaskError::Validation("bounded matrix has no gateConditions array".into())
        })?;
    if conditions.is_empty() {
        return Err(XtaskError::Validation(
            "bounded matrix gateConditions is empty".into(),
        ));
    }
    // Every gate condition must carry an id and a summary; an unlabeled gate
    // condition cannot be reasoned about, so reject it rather than tolerate it.
    for (index, condition) in conditions.iter().enumerate() {
        if condition.get("id").and_then(Value::as_str).is_none() {
            return Err(XtaskError::Validation(format!(
                "bounded matrix gate condition {index} has no id"
            )));
        }
        if condition.get("summary").and_then(Value::as_str).is_none() {
            return Err(XtaskError::Validation(format!(
                "bounded matrix gate condition {index} has no summary"
            )));
        }
    }
    for required in REQUIRED_COGNITION_MARKET_GATES {
        if !conditions
            .iter()
            .any(|condition| condition.get("id").and_then(Value::as_str) == Some(required))
        {
            return Err(XtaskError::Validation(format!(
                "bounded matrix is missing cognition-market gate {required}"
            )));
        }
    }
    Ok(())
}

/// Resolve a matrix-supplied document path against the workspace root, failing
/// closed on anything that is not a plain repo-relative path. Rejects absolute
/// paths and any `..` / root component so a drifted matrix cannot point the
/// bounded profile at a file outside the repository; the resolved path is then
/// asserted to stay under `root`.
fn resolve_repo_relative(root: &Path, rel: &str) -> Result<PathBuf, XtaskError> {
    let candidate = Path::new(rel);
    for component in candidate.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => {
                return Err(XtaskError::Validation(format!(
                    "bounded profile document path escapes the repository (parent component): {rel}"
                )));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(XtaskError::Validation(format!(
                    "bounded profile document path must be repo-relative, not absolute: {rel}"
                )));
            }
        }
    }
    let joined = root.join(candidate);
    // Defense in depth: assert the lexical join still starts at the root prefix.
    // (The component scan already rejects `..`/absolute, so the join cannot climb
    // out; this guards against a future change to the scan.)
    if !joined.starts_with(root) {
        return Err(XtaskError::Validation(format!(
            "bounded profile document path resolves outside the repository: {rel}"
        )));
    }
    Ok(joined)
}

fn display(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn matrix_path() -> PathBuf {
        let root = crate::workspace_root().unwrap_or_else(|err| panic!("workspace root: {err}"));
        root.join(BOUNDED_MATRIX_PATH)
    }

    #[test]
    fn committed_bounded_matrix_satisfies_the_contract() {
        let raw = fs::read_to_string(matrix_path())
            .unwrap_or_else(|err| panic!("bounded matrix must read: {err}"));
        let matrix: Value = serde_json::from_str(&raw)
            .unwrap_or_else(|err| panic!("bounded matrix must parse: {err}"));
        assert_bounded_matrix(&matrix).unwrap_or_else(|err| {
            panic!("committed bounded matrix must satisfy the contract: {err}")
        });
    }

    #[test]
    fn committed_bounded_gate_passes_end_to_end() {
        // The full leaf (matrix contract + profile-document existence) must pass
        // against the committed tree.
        let root = crate::workspace_root().unwrap_or_else(|err| panic!("workspace root: {err}"));
        bounded_chio(&root).unwrap_or_else(|err| panic!("bounded-chio gate must pass: {err}"));
    }

    #[test]
    fn wrong_scope_fails_closed() {
        let matrix = serde_json::json!({
            "scope": "something_else",
            "entrypoint": BOUNDED_ENTRYPOINT,
            "gateConditions": [{ "id": "X", "summary": "y" }],
        });
        match assert_bounded_matrix(&matrix) {
            Ok(()) => panic!("wrong scope passed"),
            Err(XtaskError::Validation(_)) => {}
            Err(other) => panic!("expected Validation, got {other}"),
        }
    }

    #[test]
    fn drifted_entrypoint_fails_closed() {
        let matrix = serde_json::json!({
            "scope": BOUNDED_SCOPE,
            "entrypoint": "./scripts/qualify-bounded-chio.sh",
            "gateConditions": [{ "id": "X", "summary": "y" }],
        });
        match assert_bounded_matrix(&matrix) {
            Ok(()) => panic!("drifted entrypoint passed"),
            Err(XtaskError::Validation(_)) => {}
            Err(other) => panic!("expected Validation, got {other}"),
        }
    }

    #[test]
    fn empty_gate_conditions_fail_closed() {
        let matrix = serde_json::json!({
            "scope": BOUNDED_SCOPE,
            "entrypoint": BOUNDED_ENTRYPOINT,
            "gateConditions": [],
        });
        match assert_bounded_matrix(&matrix) {
            Ok(()) => panic!("empty gate conditions passed"),
            Err(XtaskError::Validation(_)) => {}
            Err(other) => panic!("expected Validation, got {other}"),
        }
    }

    #[test]
    fn gate_condition_without_id_fails_closed() {
        let matrix = serde_json::json!({
            "scope": BOUNDED_SCOPE,
            "entrypoint": BOUNDED_ENTRYPOINT,
            "gateConditions": [{ "summary": "no id here" }],
        });
        match assert_bounded_matrix(&matrix) {
            Ok(()) => panic!("idless gate condition passed"),
            Err(XtaskError::Validation(_)) => {}
            Err(other) => panic!("expected Validation, got {other}"),
        }
    }

    #[test]
    fn missing_cognition_market_gate_fails_closed() {
        let matrix = serde_json::json!({
            "scope": BOUNDED_SCOPE,
            "entrypoint": BOUNDED_ENTRYPOINT,
            "gateConditions": [
                { "id": "COGM9-01", "summary": "flow" },
                { "id": "COGM9-02", "summary": "proof bundle" }
            ],
        });
        match assert_bounded_matrix(&matrix) {
            Ok(()) => panic!("matrix missing COGM9-03 passed"),
            Err(XtaskError::Validation(_)) => {}
            Err(other) => panic!("expected Validation, got {other}"),
        }
    }

    #[test]
    fn resolve_repo_relative_accepts_plain_path() {
        let root = Path::new("/repo");
        let resolved = resolve_repo_relative(root, "docs/standards/PROFILE.md")
            .unwrap_or_else(|err| panic!("plain repo-relative path must resolve: {err}"));
        assert_eq!(resolved, root.join("docs/standards/PROFILE.md"));
    }

    #[test]
    fn resolve_repo_relative_rejects_absolute() {
        match resolve_repo_relative(Path::new("/repo"), "/etc/passwd") {
            Ok(path) => panic!("absolute path resolved to {}", path.display()),
            Err(XtaskError::Validation(_)) => {}
            Err(other) => panic!("expected Validation, got {other}"),
        }
    }

    #[test]
    fn resolve_repo_relative_rejects_parent_escape() {
        match resolve_repo_relative(Path::new("/repo"), "../outside/PROFILE.md") {
            Ok(path) => panic!("parent-escape path resolved to {}", path.display()),
            Err(XtaskError::Validation(_)) => {}
            Err(other) => panic!("expected Validation, got {other}"),
        }
        match resolve_repo_relative(Path::new("/repo"), "docs/../../escape.md") {
            Ok(path) => panic!("embedded parent-escape resolved to {}", path.display()),
            Err(XtaskError::Validation(_)) => {}
            Err(other) => panic!("expected Validation, got {other}"),
        }
    }

    #[test]
    fn unknown_profile_is_an_error_not_a_skip() {
        match run("does-not-exist") {
            Ok(()) => panic!("unknown profile resolved to a pass"),
            Err(XtaskError::Usage(_)) => {}
            Err(other) => panic!("expected Usage error, got {other}"),
        }
    }

    #[test]
    fn known_profiles_are_nonempty_and_kebab_case() {
        assert!(!KNOWN_PROFILES.is_empty());
        for name in KNOWN_PROFILES {
            assert!(
                name.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "profile {name} must be kebab-case"
            );
        }
    }
}
