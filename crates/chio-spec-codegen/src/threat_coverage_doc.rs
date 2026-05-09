//! Generator for `docs/security/threat-coverage.md`.
//!
//! Reads:
//!
//! - `spec/security/chio-threat-model.v1.json` (threats and per-ID
//!   `coverage_state`),
//! - `crates/chio-adversarial-suite/manifest.json` (corpus
//!   entries with `threat_id` cross-link),
//! - `crates/chio-conformance/tests/threats/<id>.rs` (presence
//!   alone is the test-mapping evidence; the threat-coverage gate
//!   handles the unimplemented! check separately).
//!
//! Emits a markdown report grouping threats by coverage state.
//! Each `## Threat: <id>` heading lists corpus cases and the
//! escape-class fixture pointers. The gate accepts `partial` as PASS
//! but the doc generator surfaces partial IDs under a separate Partial
//! heading.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::{write_if_changed, CodegenError};

/// Default docs output path.
pub const THREAT_COVERAGE_DOC: &str = "docs/security/threat-coverage.md";

/// Default location of the adversarial-suite manifest.
pub const ADVERSARIAL_MANIFEST: &str = "crates/chio-adversarial-suite/manifest.json";

/// Default location of the threats stub directory.
pub const THREAT_STUBS_DIR: &str = "crates/chio-conformance/tests/threats";

/// Default location of the wasm-guard escape harness directory.
pub const ESCAPE_HARNESS_DIR: &str = "crates/chio-wasm-guards/tests/escape";

/// Coverage state surfaced in the generated doc.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CoverageState {
    Covered,
    Partial,
    Pending,
    /// A backing test file exists but mutation-testing evidence is
    /// missing or shows zero kills, so the row is treated as
    /// gameable until real mutants are run. The
    /// `check-threat-coverage-mutants.sh` gate is the runtime
    /// backstop that elevates a row from `covered` to
    /// `weak_coverage` when its evidence file is missing or
    /// records zero kills.
    WeakCoverage,
}

impl CoverageState {
    fn parse(raw: Option<&str>, source_path: &Path) -> Result<Self, CodegenError> {
        match raw.unwrap_or("covered") {
            "covered" => Ok(Self::Covered),
            "partial" => Ok(Self::Partial),
            "pending" => Ok(Self::Pending),
            "weak_coverage" => Ok(Self::WeakCoverage),
            other => Err(CodegenError::Registry(
                source_path.to_path_buf(),
                format!("unknown coverage_state {other:?}"),
            )),
        }
    }

    fn heading(self) -> &'static str {
        match self {
            Self::Covered => "Covered",
            Self::Partial => "Partial",
            Self::Pending => "Pending",
            Self::WeakCoverage => "Weak Coverage",
        }
    }
}

#[derive(Debug, Deserialize)]
struct ThreatModelDoc {
    threats: Vec<ThreatRow>,
}

#[derive(Debug, Deserialize)]
struct ThreatRow {
    id: String,
    name: String,
    surfaces: Vec<String>,
    #[serde(default)]
    coverage_state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ManifestDoc {
    cases: Vec<ManifestCase>,
}

#[derive(Debug, Deserialize)]
struct ManifestCase {
    id: String,
    class: String,
    expected_reason: String,
    threat_id: String,
    path: String,
}

/// Inputs the doc generator pulls together. Public so callers can
/// preview without writing to disk.
#[derive(Debug)]
pub struct ThreatCoverageInputs<'a> {
    pub threat_model_path: &'a Path,
    pub manifest_path: &'a Path,
    pub stubs_dir: &'a Path,
    pub escape_dir: &'a Path,
}

/// Render the `threat-coverage.md` body without touching the file
/// system.
pub fn render_threat_coverage_doc(
    inputs: &ThreatCoverageInputs<'_>,
) -> Result<String, CodegenError> {
    let threat_raw = fs::read_to_string(inputs.threat_model_path)
        .map_err(|err| CodegenError::Io(inputs.threat_model_path.to_path_buf(), err))?;
    let threat_doc: ThreatModelDoc = serde_json::from_str(&threat_raw)
        .map_err(|err| CodegenError::Json(inputs.threat_model_path.to_path_buf(), err))?;

    let manifest_doc: ManifestDoc = if inputs.manifest_path.exists() {
        let raw = fs::read_to_string(inputs.manifest_path)
            .map_err(|err| CodegenError::Io(inputs.manifest_path.to_path_buf(), err))?;
        serde_json::from_str(&raw)
            .map_err(|err| CodegenError::Json(inputs.manifest_path.to_path_buf(), err))?
    } else {
        ManifestDoc { cases: Vec::new() }
    };

    // Index manifest cases by threat ID for O(1) lookup.
    let mut by_threat: BTreeMap<String, Vec<&ManifestCase>> = BTreeMap::new();
    for case in &manifest_doc.cases {
        by_threat
            .entry(case.threat_id.clone())
            .or_default()
            .push(case);
    }
    for cases in by_threat.values_mut() {
        cases.sort_by(|a, b| a.id.cmp(&b.id));
    }

    let mut sections: BTreeMap<CoverageState, Vec<&ThreatRow>> = BTreeMap::new();
    for threat in &threat_doc.threats {
        let state =
            CoverageState::parse(threat.coverage_state.as_deref(), inputs.threat_model_path)?;
        sections.entry(state).or_default().push(threat);
    }
    let total_count = threat_doc.threats.len();
    let covered_count = sections.get(&CoverageState::Covered).map_or(0, Vec::len);
    let partial_count = sections.get(&CoverageState::Partial).map_or(0, Vec::len);
    let pending_count = sections.get(&CoverageState::Pending).map_or(0, Vec::len);
    let weak_count = sections
        .get(&CoverageState::WeakCoverage)
        .map_or(0, Vec::len);
    let partial_ids = sections
        .get(&CoverageState::Partial)
        .map(|threats| {
            threats
                .iter()
                .map(|threat| format!("`{}`", threat.id))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|ids| !ids.is_empty())
        .unwrap_or_else(|| "none".to_string());
    let status_label = if partial_count > 0 {
        "PARTIAL"
    } else if pending_count > 0 || weak_count > 0 {
        "INCOMPLETE"
    } else {
        "COVERED"
    };

    let mut body = String::new();
    body.push_str("# Chio Threat Coverage\n\n");
    body.push_str(&format!(
        "**Status: {status_label}.** {covered_count}/{total_count} \
         threat-model rows are fully covered (`Covered`); \
         {partial_count}/{total_count} are partially covered (`Partial`) \
         with deferred sub-vectors ({partial_ids}), tracked through \
         follow-up milestones. Release notes that reference \
         this page MUST NOT claim full threat closure while any \
         `Partial`, `Pending`, or `Weak Coverage` rows remain; the \
         closure language is reserved for the release that retires those \
         rows.\n\n"
    ));
    body.push_str(
        "Generated by `chio-spec-codegen --threat-model-doc`. \
         Each threat ID is grouped by coverage state. Re-run the generator \
         after editing `spec/security/chio-threat-model.v1.json` or the \
         `crates/chio-adversarial-suite/cases/` corpus.\n\n",
    );
    body.push_str(&format!(
        "Live gate state is tracked by two fail-closed scripts: \
         `scripts/check-threat-coverage.sh` validates coverage-state, \
         partial-row, and test-body shape, while \
         `scripts/check-threat-coverage-mutants.sh` validates per-row \
         mutation evidence. The current threat model renders \
         {covered_count} covered / {partial_count} partial / \
         {pending_count} pending / {weak_count} weak coverage rows. \
         Partial rows ({partial_ids}) are honest reporting per \
         partial-coverage rationale: one sub-vector of each is closed by \
         an in-tree conformance test and caught-mutant evidence today, \
         while the other sub-vector is deferred to follow-up coverage \
         (see the `deferred_follow_up` field in each row's \
         `audits/evidence/threats/<id>.json`).\n\n"
    ));
    body.push_str(
        "**Hardening note**: 9 of the originally-claimed 20 covered rows \
         passed the gate on file-exists + no-`unimplemented!()` alone, \
         with weak or meta-only assertions in the backing test. The \
         hardening pass adds per-row cargo-mutants requirements and \
         real negative-conformance bodies; two of those rows were \
         further demoted to `Partial` because the test only exercises \
         one sub-vector of the named threat (see the `deferred_to` \
         field in each row's threat-model entry and the partial \
         evidence file in `audits/evidence/threats/<id>.json`).\n\n",
    );
    body.push_str(
        "Coverage states:\n\
         - `Covered` - the threat ID has a populated test body at \
           `crates/chio-conformance/tests/threats/<id>.rs` AND a \
           mutation-testing evidence file at \
           `audits/evidence/threats/<id>.json` recording at least \
           one caught mutant.\n\
         - `Partial` - a backing test exists and the defended sub-vector \
           has a mutation evidence file with `caught >= 1`, but the row \
           defends only part of the attack surface; the residual gap is \
           documented in the follow-up evidence record that owns the \
           partial coverage.\n\
         - `Pending` - no backing test yet; the threat-model-coverage \
           CI gate accepts the entry because it is explicitly marked \
           `pending` in the JSON, but a green test must land before \
           the owning milestone closes.\n\
         - `Weak Coverage` - a backing test file exists but mutation-\
           testing evidence is missing or shows zero kills. The row \
           must be raised to `Covered` with real evidence under \
           `audits/evidence/threats/<id>.json` or downgraded to \
           `Pending` with a `deferred_to` reference before the \
           threat-model-coverage gate accepts it.\n\n",
    );

    for state in [
        CoverageState::Covered,
        CoverageState::Partial,
        CoverageState::Pending,
        CoverageState::WeakCoverage,
    ] {
        let Some(threats) = sections.get(&state) else {
            continue;
        };
        body.push_str(&format!("# {} ({})\n\n", state.heading(), threats.len()));
        for threat in threats {
            render_threat_section(
                &mut body,
                threat,
                state,
                by_threat
                    .get(&threat.id)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]),
                inputs.stubs_dir,
                inputs.escape_dir,
            );
        }
    }

    while body.ends_with("\n\n") {
        body.pop();
    }
    if !body.ends_with('\n') {
        body.push('\n');
    }
    Ok(body)
}

fn render_threat_section(
    out: &mut String,
    threat: &ThreatRow,
    state: CoverageState,
    cases: &[&ManifestCase],
    stubs_dir: &Path,
    escape_dir: &Path,
) {
    out.push_str(&format!("## Threat: {}\n\n", threat.id));
    out.push_str(&format!("- **Name:** {}\n", threat.name));
    out.push_str(&format!("- **State:** {}\n", state.heading()));
    out.push_str(&format!("- **Surfaces:** {}\n", threat.surfaces.join(", ")));

    let stub_path = stubs_dir.join(format!("{}.rs", threat.id));
    if stub_path.exists() {
        out.push_str(&format!(
            "- **Test stub:** `crates/chio-conformance/tests/threats/{}.rs`\n",
            threat.id
        ));
    } else {
        out.push_str("- **Test stub:** (not yet emitted)\n");
    }

    // Cite escape-class harness directory for runtime exhaustion threats.
    if matches!(
        threat.id.as_str(),
        "resource_exhaustion_dos" | "tool_server_escape" | "wasm_guard_resource_exhaustion"
    ) && escape_dir.exists()
    {
        out.push_str("- **Escape harness:** `crates/chio-wasm-guards/tests/escape/`\n");
    }

    if cases.is_empty() {
        out.push_str("- **Corpus cases:** (none cite this threat ID)\n\n");
    } else {
        out.push_str("- **Corpus cases:**\n");
        for case in cases {
            out.push_str(&format!(
                "  - `{}` (class `{}`, reason `{}`, path `{}`)\n",
                case.id, case.class, case.expected_reason, case.path
            ));
        }
        out.push('\n');
    }
}

/// Top-level entry point: render the doc and write to `out_path`,
/// returning the rendered body.
pub fn codegen_threat_coverage_doc(
    inputs: &ThreatCoverageInputs<'_>,
    out_path: &Path,
) -> Result<String, CodegenError> {
    let body = render_threat_coverage_doc(inputs)?;
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).map_err(|err| CodegenError::Io(parent.to_path_buf(), err))?;
    }
    write_if_changed(out_path, body.as_bytes())?;
    Ok(body)
}

/// Convenience wrapper that pulls every input from its canonical
/// repository-relative path. Used by the CLI and tests.
pub fn codegen_threat_coverage_doc_default(repo_root: &Path) -> Result<PathBuf, CodegenError> {
    let inputs = ThreatCoverageInputs {
        threat_model_path: &repo_root.join(crate::THREAT_MODEL_INPUT),
        manifest_path: &repo_root.join(ADVERSARIAL_MANIFEST),
        stubs_dir: &repo_root.join(THREAT_STUBS_DIR),
        escape_dir: &repo_root.join(ESCAPE_HARNESS_DIR),
    };
    let out_path = repo_root.join(THREAT_COVERAGE_DOC);
    codegen_threat_coverage_doc(&inputs, &out_path)?;
    Ok(out_path)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repo root")
    }

    #[test]
    fn coverage_state_parses_known_values() {
        assert_eq!(
            CoverageState::parse(Some("covered"), Path::new("threat-model.json")).unwrap(),
            CoverageState::Covered
        );
        assert_eq!(
            CoverageState::parse(Some("partial"), Path::new("threat-model.json")).unwrap(),
            CoverageState::Partial
        );
        assert_eq!(
            CoverageState::parse(Some("pending"), Path::new("threat-model.json")).unwrap(),
            CoverageState::Pending
        );
        assert_eq!(
            CoverageState::parse(Some("weak_coverage"), Path::new("threat-model.json")).unwrap(),
            CoverageState::WeakCoverage
        );
        assert_eq!(
            CoverageState::parse(None, Path::new("threat-model.json")).unwrap(),
            CoverageState::Covered
        );
    }

    #[test]
    fn coverage_state_rejects_unknown_values() {
        let err = CoverageState::parse(Some("nonsense"), Path::new("threat-model.json"))
            .expect_err("unknown coverage_state must fail closed");
        assert!(err.to_string().contains("unknown coverage_state"));
    }

    #[test]
    fn rendered_doc_contains_six_initial_threat_headings() {
        let root = repo_root();
        let inputs = ThreatCoverageInputs {
            threat_model_path: &root.join(crate::THREAT_MODEL_INPUT),
            manifest_path: &root.join(ADVERSARIAL_MANIFEST),
            stubs_dir: &root.join(THREAT_STUBS_DIR),
            escape_dir: &root.join(ESCAPE_HARNESS_DIR),
        };
        let body = render_threat_coverage_doc(&inputs).expect("render");
        for tid in [
            "capability_token_theft",
            "kernel_impersonation",
            "tool_server_escape",
            "native_channel_replay",
            "resource_exhaustion_dos",
            "delegation_chain_abuse",
        ] {
            assert!(
                body.contains(&format!("## Threat: {tid}\n")),
                "rendered doc must contain heading for {tid}"
            );
        }
    }
}
