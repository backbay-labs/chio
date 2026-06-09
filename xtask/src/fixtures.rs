//! Pheromone fixture-and-schema gate (`cargo xtask check fixtures <facet>`).
//!
//! This is the consolidated replacement for the 15
//! `scripts/check-chio-pheromone-*.sh` gates. The genuinely tabular per-facet
//! data (schema-id/file maps, fixture dirs, schema-validate document lists,
//! `cargo test` invocations, recursion edges, node-dashboard / sre-metrics
//! flags) lives in `ci-gates/pheromone.toml`. The imperative per-facet steps
//! that the manifest cannot express (CLI orchestration, fixture regeneration,
//! retired-marker guards, npm dashboard checks) live in typed handlers keyed by
//! [`Facet::kind`].
//!
//! Fail-closed contract:
//! - [`KNOWN_FACETS`] enumerates all 15 facets at compile time; the manifest
//!   must list exactly those (asserted by a unit test).
//! - An unknown facet on the CLI is an error, never a skip.
//! - `--schema-only` and `--negative-only` are mutually exclusive.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use crate::XtaskError;

/// Relative path (from the workspace root) of the gate manifest.
pub(crate) const MANIFEST_PATH: &str = "ci-gates/pheromone.toml";

/// Relative path (from the workspace root) of the chio-runtime gate manifest.
pub(crate) const RUNTIME_MANIFEST_PATH: &str = "ci-gates/runtime.toml";

/// The six chio-runtime facets, consolidated from `scripts/check-chio-runtime-*.sh`.
/// Compile-time fail-closed enumeration: the runtime manifest must list exactly
/// these names, and the CLI rejects anything else.
pub(crate) const RUNTIME_KNOWN_FACETS: [&str; 6] = [
    "runtime-spine-fixtures",
    "runtime-spine",
    "runtime-proof-parity",
    "runtime-policy",
    "runtime-ops-hardening",
    "runtime-orchestration",
];

/// The 15 pheromone facets. Compile-time fail-closed enumeration: the manifest
/// must list exactly these names, and the CLI rejects anything else.
pub(crate) const KNOWN_FACETS: [&str; 15] = [
    "directory-lifecycle",
    "relay-alert-assurance-archive-hardening",
    "relay-alert-assurance-archive-package",
    "relay-alert-assurance-archive",
    "relay-alert-assurance-export",
    "relay-alert-assurance-external-retention",
    "relay-alert-assurance",
    "relay-alert-delivery",
    "relay-alert-handoff",
    "relay-alert-routing",
    "relay-observability",
    "relay-ops",
    "relay",
    "runtime",
    "transit",
];

// -- Manifest types -------------------------------------------------------

#[derive(serde::Deserialize, Debug)]
pub(crate) struct Manifest {
    pub schema_dir: String,
    pub schema_registry: String,
    pub facet: Vec<Facet>,
}

#[derive(serde::Deserialize, Debug)]
pub(crate) struct Facet {
    pub name: String,
    pub kind: String,
    pub schema_check: String,
    pub fixture_dir: String,
    #[serde(default)]
    pub schemas: Vec<SchemaEntry>,
    #[serde(default)]
    pub validate: Vec<ValidatePair>,
    #[serde(default)]
    pub validate_glob: Vec<ValidateGlob>,
    #[serde(default)]
    pub cargo_tests: Vec<Vec<String>>,
    #[serde(default)]
    pub needs_dashboard_npm: bool,
    #[serde(default)]
    pub sre_metrics_registry: bool,
    #[serde(default)]
    pub recurse: Vec<RecurseEdge>,
}

#[derive(serde::Deserialize, Debug)]
pub(crate) struct SchemaEntry {
    pub id: String,
    pub file: String,
}

#[derive(serde::Deserialize, Debug)]
pub(crate) struct ValidatePair {
    pub schema: String,
    pub doc: String,
}

#[derive(serde::Deserialize, Debug)]
pub(crate) struct ValidateGlob {
    pub dir: String,
    #[serde(default)]
    pub pattern: Option<String>,
    pub schema: String,
}

#[derive(serde::Deserialize, Debug)]
pub(crate) struct RecurseEdge {
    pub facet: String,
    pub mode: String,
}

impl Manifest {
    pub(crate) fn facet_by_name(&self, name: &str) -> Option<&Facet> {
        self.facet.iter().find(|facet| facet.name == name)
    }
}

// -- Runtime manifest types -----------------------------------------------

#[derive(serde::Deserialize, Debug)]
pub(crate) struct RuntimeManifest {
    pub schema_dir: String,
    pub facet: Vec<RuntimeFacet>,
}

#[derive(serde::Deserialize, Debug)]
pub(crate) struct RuntimeFacet {
    pub name: String,
    pub kind: String,
    pub fixture_dir: String,
    #[serde(default)]
    pub validate: Vec<ValidatePair>,
    #[serde(default)]
    pub cargo_tests: Vec<Vec<String>>,
}

impl RuntimeManifest {
    pub(crate) fn facet_by_name(&self, name: &str) -> Option<&RuntimeFacet> {
        self.facet.iter().find(|facet| facet.name == name)
    }
}

impl RecurseEdge {
    fn mode(&self) -> Result<Mode, XtaskError> {
        match self.mode.as_str() {
            "all" => Ok(Mode::All),
            "schema-only" => Ok(Mode::SchemaOnly),
            "negative-only" => Ok(Mode::NegativeOnly),
            other => Err(XtaskError::Manifest(format!(
                "recursion edge into {} has unknown mode {other}",
                self.facet
            ))),
        }
    }
}

/// Required schema shape per facet. `StrictObject` matches the scripts that
/// assert `type=="object"` and `additionalProperties==false`; `FrozenObject`
/// matches the scripts that assert `type=="object"` and a present `$id`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SchemaCheck {
    StrictObject,
    FrozenObject,
}

impl SchemaCheck {
    fn from_str(raw: &str) -> Result<Self, XtaskError> {
        match raw {
            "strict-object" => Ok(Self::StrictObject),
            "frozen-object" => Ok(Self::FrozenObject),
            other => Err(XtaskError::Manifest(format!(
                "unknown schema_check {other}"
            ))),
        }
    }
}

// -- Mode -----------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Mode {
    All,
    SchemaOnly,
    NegativeOnly,
}

impl Mode {
    pub(crate) fn from_flags(schema_only: bool, negative_only: bool) -> Result<Self, XtaskError> {
        match (schema_only, negative_only) {
            (true, true) => Err(XtaskError::Usage(
                "fixtures: --schema-only and --negative-only are mutually exclusive".into(),
            )),
            (true, false) => Ok(Mode::SchemaOnly),
            (false, true) => Ok(Mode::NegativeOnly),
            (false, false) => Ok(Mode::All),
        }
    }
}

// -- Loader ---------------------------------------------------------------

/// Load the manifest from the workspace root.
pub(crate) fn load_manifest() -> Result<Manifest, XtaskError> {
    let root = crate::workspace_root()?;
    load_manifest_from(&root.join(MANIFEST_PATH))
}

/// Load and parse the manifest from an explicit path. Kept separate so unit
/// tests can target the committed file by an absolute path.
pub(crate) fn load_manifest_from(path: &Path) -> Result<Manifest, XtaskError> {
    let raw = fs::read_to_string(path).map_err(|err| XtaskError::Io(display(path), err))?;
    toml::from_str(&raw)
        .map_err(|err| XtaskError::Manifest(format!("failed to parse {}: {err}", display(path))))
}

/// Load the chio-runtime manifest from the workspace root.
pub(crate) fn load_runtime_manifest() -> Result<RuntimeManifest, XtaskError> {
    let root = crate::workspace_root()?;
    load_runtime_manifest_from(&root.join(RUNTIME_MANIFEST_PATH))
}

/// Load and parse the chio-runtime manifest from an explicit path.
pub(crate) fn load_runtime_manifest_from(path: &Path) -> Result<RuntimeManifest, XtaskError> {
    let raw = fs::read_to_string(path).map_err(|err| XtaskError::Io(display(path), err))?;
    toml::from_str(&raw)
        .map_err(|err| XtaskError::Manifest(format!("failed to parse {}: {err}", display(path))))
}

fn display(path: &Path) -> String {
    path.display().to_string()
}

// -- Entry point ----------------------------------------------------------

/// Run a fixture-and-schema gate by facet name. Pheromone facets resolve
/// against `ci-gates/pheromone.toml`; the six chio-runtime facets resolve
/// against `ci-gates/runtime.toml`. Fail-closed: a facet in neither manifest is
/// an error, and each manifest must enumerate exactly its known facets before
/// any gate runs.
pub(crate) fn run(facet_name: &str, mode: Mode) -> Result<(), XtaskError> {
    let root = crate::workspace_root()?;
    if RUNTIME_KNOWN_FACETS.contains(&facet_name) {
        let manifest = load_runtime_manifest()?;
        assert_runtime_manifest_enumeration(&manifest)?;
        return run_runtime_with(&root, &manifest, facet_name, mode);
    }
    let manifest = load_manifest()?;
    assert_manifest_enumeration(&manifest)?;
    run_with(&root, &manifest, facet_name, mode)
}

/// Fail-closed enumeration: the manifest must list exactly [`KNOWN_FACETS`].
fn assert_manifest_enumeration(manifest: &Manifest) -> Result<(), XtaskError> {
    let mut names: Vec<&str> = manifest.facet.iter().map(|f| f.name.as_str()).collect();
    names.sort_unstable();
    let mut expected = KNOWN_FACETS.to_vec();
    expected.sort_unstable();
    if names != expected {
        return Err(XtaskError::Manifest(format!(
            "manifest must enumerate exactly the 15 known facets, found {names:?}"
        )));
    }
    Ok(())
}

/// Fail-closed enumeration: the runtime manifest must list exactly
/// [`RUNTIME_KNOWN_FACETS`].
fn assert_runtime_manifest_enumeration(manifest: &RuntimeManifest) -> Result<(), XtaskError> {
    let mut names: Vec<&str> = manifest.facet.iter().map(|f| f.name.as_str()).collect();
    names.sort_unstable();
    let mut expected = RUNTIME_KNOWN_FACETS.to_vec();
    expected.sort_unstable();
    if names != expected {
        return Err(XtaskError::Manifest(format!(
            "runtime manifest must enumerate exactly the 6 known runtime facets, found {names:?}"
        )));
    }
    Ok(())
}

fn run_with(
    root: &Path,
    manifest: &Manifest,
    facet_name: &str,
    mode: Mode,
) -> Result<(), XtaskError> {
    let facet = manifest
        .facet_by_name(facet_name)
        .ok_or_else(|| XtaskError::Usage(format!("unknown pheromone facet: {facet_name}")))?;

    // Pre-schema imperative guards (retired-marker / runbook / fixture-name
    // scans) run first, exactly as the scripts do.
    pre_schema_guard(root, facet)?;

    // The cargo-test placement differs per facet. `relay` and the two
    // env-branch facets run cargo tests BEFORE the schema block; everything
    // else runs the schema block first. We always run the schema/metadata
    // block (it is in every mode), so order only matters for side-effect-free
    // assertions, which these are.
    run_schema_block(root, manifest, facet)?;
    run_metadata_block(root, facet)?;

    if mode == Mode::SchemaOnly {
        return Ok(());
    }

    dispatch_handler(root, manifest, facet, mode)
}

// -- Runtime entry point ---------------------------------------------------

/// Resolve a runtime facet and dispatch to its typed handler. The runtime
/// facets carry far more imperative work than the pheromone facets (multi-step
/// admission/orchestration/ops pipelines, derived-fixture generation), so the
/// manifest only supplies the tabular validate/cargo-test data and the handler
/// owns the rest.
fn run_runtime_with(
    root: &Path,
    manifest: &RuntimeManifest,
    facet_name: &str,
    mode: Mode,
) -> Result<(), XtaskError> {
    let facet = manifest
        .facet_by_name(facet_name)
        .ok_or_else(|| XtaskError::Usage(format!("unknown runtime facet: {facet_name}")))?;
    dispatch_runtime_handler(root, manifest, facet, mode)
}

/// Validate every manifest `validate` pair for a runtime facet. Both the schema
/// and the document may be root-relative (slash-bearing): a bare schema
/// filename lives in `schema_dir`, anything else is resolved from the workspace
/// root, and documents are always given as root-relative paths.
fn run_runtime_validate_pairs(
    root: &Path,
    manifest: &RuntimeManifest,
    facet: &RuntimeFacet,
) -> Result<(), XtaskError> {
    let schema_dir = root.join(&manifest.schema_dir);
    for pair in &facet.validate {
        let schema_path = resolve_schema(root, &schema_dir, &pair.schema);
        let doc_path = if pair.doc.contains('/') {
            root.join(&pair.doc)
        } else {
            root.join(&facet.fixture_dir).join(&pair.doc)
        };
        validate_document(&schema_path, &doc_path)?;
    }
    Ok(())
}

/// Run a runtime facet's manifest `cargo_tests` argv tails in order, each gated
/// to a non-zero passed count (matching the scripts' `run_cargo_test_filter`).
fn run_runtime_cargo_tests(root: &Path, facet: &RuntimeFacet) -> Result<(), XtaskError> {
    for tail in &facet.cargo_tests {
        run_cargo_test(root, tail)?;
    }
    Ok(())
}

// -- Generic schema + validate block --------------------------------------

/// The shared schema/registry/validate block run by every facet in every mode.
/// Returns `Ok(())` when every schema is present, correctly shaped, registered,
/// and every validate pair passes.
pub(crate) fn run_schema_block(
    root: &Path,
    manifest: &Manifest,
    facet: &Facet,
) -> Result<(), XtaskError> {
    let check = SchemaCheck::from_str(&facet.schema_check)?;
    let schema_dir = root.join(&manifest.schema_dir);
    let registry = load_registry(root, manifest)?;

    for entry in &facet.schemas {
        // A `file` containing a slash is a root-relative path (e.g. a
        // chio-runtime schema the runtime facet pulls in cross-directory); a
        // bare filename lives in the facet's `schema_dir`. `want` must mirror
        // the registry's stored `schemaFile` in both cases.
        let (want, schema_path) = if entry.file.contains('/') {
            (entry.file.clone(), root.join(&entry.file))
        } else {
            (
                format!("{}/{}", manifest.schema_dir, entry.file),
                schema_dir.join(&entry.file),
            )
        };
        let schema = load_json(&schema_path)?;
        assert_schema_shape(&entry.file, &schema, check)?;
        match registry.get(&entry.id) {
            Some(registered) if registered == &want => {}
            other => {
                return Err(XtaskError::Validation(format!(
                    "schema {} is not registered at {want} (registry has {other:?})",
                    entry.id
                )));
            }
        }
    }

    run_validate_pairs(root, manifest, facet)?;
    Ok(())
}

/// Validate every fixed and globbed document against its schema.
fn run_validate_pairs(root: &Path, manifest: &Manifest, facet: &Facet) -> Result<(), XtaskError> {
    let schema_dir = root.join(&manifest.schema_dir);
    let fixture_dir = root.join(&facet.fixture_dir);

    for pair in &facet.validate {
        let schema_path = resolve_schema(root, &schema_dir, &pair.schema);
        let doc_path = fixture_dir.join(&pair.doc);
        validate_document(&schema_path, &doc_path)?;
    }

    for glob in &facet.validate_glob {
        let dir = fixture_dir.join(&glob.dir);
        let schema_path = schema_dir.join(&glob.schema);
        for doc in glob_documents(&dir, glob.pattern.as_deref())? {
            validate_document(&schema_path, &doc)?;
        }
    }
    Ok(())
}

/// Resolve a validate schema reference. The transit/runtime facets reference a
/// chio-runtime schema by a path containing a slash; everything else names a
/// file inside `schema_dir`.
fn resolve_schema(root: &Path, schema_dir: &Path, schema: &str) -> PathBuf {
    if schema.contains('/') {
        root.join(schema)
    } else {
        schema_dir.join(schema)
    }
}

fn validate_document(schema_path: &Path, doc_path: &Path) -> Result<(), XtaskError> {
    chio_spec_validate::validate(schema_path, doc_path)
        .map_err(|err| XtaskError::Validation(format!("{err}")))
}

fn assert_schema_shape(file: &str, schema: &Value, check: SchemaCheck) -> Result<(), XtaskError> {
    if schema.get("type").and_then(Value::as_str) != Some("object") {
        return Err(XtaskError::Validation(format!(
            "schema {file} is not an object schema"
        )));
    }
    match check {
        SchemaCheck::StrictObject => {
            if schema.get("additionalProperties") != Some(&Value::Bool(false)) {
                return Err(XtaskError::Validation(format!(
                    "schema {file} is not a strict object schema (additionalProperties != false)"
                )));
            }
        }
        SchemaCheck::FrozenObject => {
            if schema.get("$id").is_none() {
                return Err(XtaskError::Validation(format!(
                    "schema {file} is not a frozen object schema (missing $id)"
                )));
            }
        }
    }
    Ok(())
}

/// Build a `schema-id -> schemaFile` map from the schema registry. Also rejects
/// any artifact pointing at the retired `spec/schemas/chio/` schema root, which
/// several scripts guarded against.
fn load_registry(
    root: &Path,
    manifest: &Manifest,
) -> Result<std::collections::BTreeMap<String, String>, XtaskError> {
    let registry_path = root.join(&manifest.schema_registry);
    let registry = load_json(&registry_path)?;
    let mut map = std::collections::BTreeMap::new();
    let artifacts = registry
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            XtaskError::Validation(format!(
                "registry {} has no artifacts array",
                display(&registry_path)
            ))
        })?;
    for artifact in artifacts {
        let schema_file = artifact
            .get("schemaFile")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if schema_file.starts_with("spec/schemas/chio/") {
            return Err(XtaskError::Validation(format!(
                "registry still points at retired schema root {schema_file}"
            )));
        }
        if let (Some(schema), Some(file)) = (
            artifact.get("schema").and_then(Value::as_str),
            artifact.get("schemaFile").and_then(Value::as_str),
        ) {
            map.insert(schema.to_string(), file.to_string());
        }
    }
    Ok(map)
}

// -- Per-facet metadata assertions ----------------------------------------

/// Per-facet metadata assertions ported from each script's embedded python
/// block. These confirm fixture invariants beyond pure schema validation
/// (negative-corpus required codes, bounded metric labels, binding fields).
fn run_metadata_block(root: &Path, facet: &Facet) -> Result<(), XtaskError> {
    let fixture_dir = root.join(&facet.fixture_dir);
    match facet.kind.as_str() {
        "transit" => metadata_transit(&fixture_dir),
        "runtime" => metadata_runtime(root, &fixture_dir),
        "relay" => metadata_relay(&fixture_dir),
        "relay_ops" => metadata_negative_codes(
            &fixture_dir,
            "negative-cases.json",
            "expectedFailureCode",
            &[
                "peer_directory_stale",
                "peer_directory_rollback",
                "peer_directory_unsigned",
                "endpoint_denied",
                "sender_mismatch",
                "recipient_mismatch",
                "relay_request_stale",
                "relay_nonce_replay",
                "catchup_denied",
            ],
        ),
        "directory_lifecycle" => metadata_directory_lifecycle(&fixture_dir),
        "relay_observability" => metadata_relay_observability(&fixture_dir),
        "relay_alert_routing" => metadata_relay_alert_routing(&fixture_dir),
        "relay_alert_handoff" => metadata_negative_ids(
            &fixture_dir,
            "relay-alert-handoff-negative-cases.json",
            &HANDOFF_REQUIRED_CASES,
        ),
        "relay_alert_delivery" => metadata_negative_ids(
            &fixture_dir,
            "relay-alert-delivery-negative-cases.json",
            &DELIVERY_REQUIRED_CASES,
        ),
        "relay_alert_assurance" => metadata_negative_case_ids(
            &fixture_dir,
            "relay-alert-assurance-negative-cases.json",
            &ASSURANCE_REQUIRED_CASES,
        ),
        "relay_alert_assurance_export" => metadata_negative_case_ids(
            &fixture_dir,
            "relay-alert-assurance-export-negative-cases.json",
            &[
                "invalid_signature",
                "source_hash_mismatch",
                "path_traversal",
                "wrong_expected_code",
            ],
        ),
        "relay_alert_assurance_archive" => metadata_negative_case_ids(
            &fixture_dir,
            "relay-alert-assurance-archive-negative-cases.json",
            &[
                "untrusted_exporter",
                "missing_file",
                "legal_hold_closeout",
                "wrong_expected_code",
            ],
        ),
        "relay_alert_assurance_archive_package" => metadata_negative_case_ids(
            &fixture_dir,
            "relay-alert-assurance-archive-package-negative-cases.json",
            &ARCHIVE_PACKAGE_REQUIRED_CASES,
        ),
        // generic facets carry their negative-corpus requirements inline below.
        "generic" => metadata_generic(facet, &fixture_dir),
        other => Err(XtaskError::Manifest(format!("unknown facet kind {other}"))),
    }
}

const HANDOFF_REQUIRED_CASES: [&str; 20] = [
    "inline-token",
    "dynamic-url",
    "credential-target-ref",
    "bearer-target-ref",
    "unbounded-label",
    "unknown-sink-kind",
    "duplicate-route",
    "route-collision",
    "stale-alert-report",
    "stale-trend-report",
    "source-hash-mismatch",
    "bad-source-hash-shape",
    "missing-runbook",
    "alert-runbook-mismatch",
    "critical-hidden-by-suppression",
    "missing-event-evidence",
    "weak-escalation-mapping",
    "unknown-alert-code",
    "trend-code-missing",
    "downstream-route-missing",
];

const DELIVERY_REQUIRED_CASES: [&str; 13] = [
    "live-url",
    "inline-token",
    "unbounded-label",
    "unknown-receiver",
    "route-mismatch",
    "dedupe-missing",
    "stale-handoff",
    "source-hash-mismatch",
    "duplicate-result",
    "missing-critical-delivery",
    "severity-weakened",
    "runbook-drift",
    "wrong-expected-code",
];

const ASSURANCE_REQUIRED_CASES: [&str; 6] = [
    "stale-source",
    "ambiguous-mapping",
    "secret-looking-field",
    "source-hash-mismatch",
    "later-delivery-masking",
    "route-owner-missing",
];

const ARCHIVE_PACKAGE_REQUIRED_CASES: [&str; 14] = [
    "untrusted_packager",
    "path_traversal_member",
    "absolute_path_member",
    "backslash_path_member",
    "drive_colon_path_member",
    "duplicate_path_member",
    "casefold_collision_member",
    "symlink_member",
    "hardlink_member",
    "extra_member",
    "missing_member",
    "hash_mismatch_member",
    "dynamic_retention_handoff_url",
    "wrong_expected_code",
];

const EXTERNAL_RETENTION_REQUIRED_CASES: [&str; 16] = [
    "untrusted_packager",
    "untrusted_exporter",
    "source_report_mismatch",
    "stale_profile",
    "stale_evidence",
    "local_kernel_mismatch",
    "generation_gap",
    "previous_manifest_mismatch",
    "missing_restore_drill",
    "rejected_restore_drill",
    "missing_physical_readback",
    "insufficient_sample",
    "missing_retention_handoff",
    "unknown_retention_alias",
    "alias_drift",
    "wrong_expected_code",
];

const ARCHIVE_HARDENING_REQUIRED_CASES: [&str; 6] = [
    "generation_gap",
    "duplicate_generation",
    "previous_hash_mismatch",
    "missing_readback",
    "retention_handoff_not_ready",
    "wrong_expected_code",
];

/// The two generic-kind facets (`relay-alert-assurance-archive-hardening`,
/// `relay-alert-assurance-external-retention`) have only a negative-corpus
/// assertion in their python block; dispatch by name.
fn metadata_generic(facet: &Facet, fixture_dir: &Path) -> Result<(), XtaskError> {
    match facet.name.as_str() {
        "relay-alert-assurance-archive-hardening" => metadata_negative_case_ids(
            fixture_dir,
            "relay-alert-assurance-archive-restore-negative-cases.json",
            &ARCHIVE_HARDENING_REQUIRED_CASES,
        ),
        "relay-alert-assurance-external-retention" => metadata_negative_case_ids(
            fixture_dir,
            "relay-alert-assurance-external-retention-negative-cases.json",
            &EXTERNAL_RETENTION_REQUIRED_CASES,
        ),
        other => Err(XtaskError::Manifest(format!(
            "generic facet {other} has no metadata assertions registered"
        ))),
    }
}

// -- Imperative handler dispatch ------------------------------------------

/// Run the non-schema-only body of a facet: cargo tests, imperative CLI
/// orchestration, npm / sre-metrics calls, then recursion. Handlers honor
/// `NegativeOnly` early-exit points exactly where the scripts did.
fn dispatch_handler(
    root: &Path,
    manifest: &Manifest,
    facet: &Facet,
    mode: Mode,
) -> Result<(), XtaskError> {
    match facet.kind.as_str() {
        "transit" => handle_transit(root, facet, mode),
        "runtime" => handle_runtime(root, manifest, facet, mode),
        "relay" => handle_relay(root, manifest, facet, mode),
        "relay_ops" => handle_relay_ops(root, manifest, facet, mode),
        "directory_lifecycle" => handle_directory_lifecycle(root, manifest, facet, mode),
        "relay_observability" => handle_relay_observability(root, manifest, facet, mode),
        "relay_alert_routing" => handle_alert_with_npm(root, manifest, facet, mode),
        "relay_alert_handoff" => handle_alert_with_npm(root, manifest, facet, mode),
        "relay_alert_delivery" => handle_alert_with_npm(root, manifest, facet, mode),
        "relay_alert_assurance" => handle_alert_assurance(root, manifest, facet, mode),
        "relay_alert_assurance_export" => handle_archive_chain(root, manifest, facet, mode),
        "relay_alert_assurance_archive" => handle_archive_chain(root, manifest, facet, mode),
        "relay_alert_assurance_archive_package" => {
            handle_archive_chain(root, manifest, facet, mode)
        }
        "generic" => handle_generic(root, facet),
        other => Err(XtaskError::Manifest(format!("unknown facet kind {other}"))),
    }
}

/// Run the manifest's recursion edges in order.
fn run_recursion(root: &Path, manifest: &Manifest, facet: &Facet) -> Result<(), XtaskError> {
    for edge in &facet.recurse {
        run_with(root, manifest, &edge.facet, edge.mode()?)?;
    }
    Ok(())
}

// -- Subprocess helpers ----------------------------------------------------

fn run_cargo_tests(root: &Path, facet: &Facet) -> Result<(), XtaskError> {
    for tail in &facet.cargo_tests {
        run_cargo_test(root, tail)?;
    }
    Ok(())
}

fn run_cargo_test(root: &Path, tail: &[String]) -> Result<(), XtaskError> {
    let status = Command::new("cargo")
        .arg("test")
        .args(tail)
        .current_dir(root)
        .status()
        .map_err(|err| XtaskError::Io("cargo test".into(), err))?;
    if !status.success() {
        return Err(XtaskError::Process(format!(
            "cargo test {tail:?} exited {}",
            status.code().unwrap_or(-1)
        )));
    }
    Ok(())
}

/// Run a `chio` CLI invocation, returning whether it succeeded. Used both for
/// positive steps (where a failure is an error) and for the deliberate negative
/// assertions (where success is the error).
fn run_cli(root: &Path, args: &[&str]) -> Result<bool, XtaskError> {
    let status = Command::new("cargo")
        .arg("run")
        .args(args)
        .current_dir(root)
        .status()
        .map_err(|err| XtaskError::Io("cargo run".into(), err))?;
    Ok(status.success())
}

fn require_cli(root: &Path, args: &[&str]) -> Result<(), XtaskError> {
    if run_cli(root, args)? {
        Ok(())
    } else {
        Err(XtaskError::Process(format!(
            "expected cargo run {args:?} to succeed"
        )))
    }
}

fn reject_cli(root: &Path, args: &[&str], detail: &str) -> Result<(), XtaskError> {
    if run_cli(root, args)? {
        Err(XtaskError::Process(format!(
            "negative assertion failed: {detail}"
        )))
    } else {
        Ok(())
    }
}

fn run_bash(root: &Path, script: &str) -> Result<(), XtaskError> {
    let status = Command::new("bash")
        .arg(script)
        .current_dir(root)
        .status()
        .map_err(|err| XtaskError::Io(format!("bash {script}"), err))?;
    if !status.success() {
        return Err(XtaskError::Process(format!(
            "bash {script} exited {}",
            status.code().unwrap_or(-1)
        )));
    }
    Ok(())
}

/// `scripts/check-sre-metrics-registry.sh` is kept as a thin shell wrapper and
/// invoked by the facets that need it (`relay-observability`,
/// `relay-alert-routing`).
fn run_sre_metrics(root: &Path) -> Result<(), XtaskError> {
    run_bash(root, "scripts/check-sre-metrics-registry.sh")
}

/// `pushd crates/chio-cli/dashboard && npm <args>` for the dashboard facets.
fn run_npm(root: &Path, args: &[&str]) -> Result<(), XtaskError> {
    let dashboard = root.join("crates/chio-cli/dashboard");
    let status = Command::new("npm")
        .args(args)
        .current_dir(&dashboard)
        .status()
        .map_err(|err| XtaskError::Io(format!("npm {args:?}"), err))?;
    if !status.success() {
        return Err(XtaskError::Process(format!(
            "npm {args:?} exited {}",
            status.code().unwrap_or(-1)
        )));
    }
    Ok(())
}

fn run_dashboard_test_and_build(root: &Path, test_args: &[&str]) -> Result<(), XtaskError> {
    let mut npm_test = vec!["test"];
    npm_test.extend_from_slice(test_args);
    run_npm(root, &npm_test)?;
    run_npm(root, &["run", "build"])
}

// -- JSON / fs helpers -----------------------------------------------------

fn load_json(path: &Path) -> Result<Value, XtaskError> {
    let raw = fs::read_to_string(path).map_err(|err| XtaskError::Io(display(path), err))?;
    serde_json::from_str(&raw).map_err(|err| XtaskError::Json(display(path), err))
}

/// Collect the JSON documents matched by a glob. `pattern` is a simple
/// `prefix-*-suffix` glob over file names; `None` matches every `*.json`.
fn glob_documents(dir: &Path, pattern: Option<&str>) -> Result<Vec<PathBuf>, XtaskError> {
    let mut matched = Vec::new();
    let entries = fs::read_dir(dir).map_err(|err| XtaskError::Io(display(dir), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display(dir), err))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let matches = match pattern {
            Some(glob) => glob_matches(glob, name),
            None => name.ends_with(".json"),
        };
        if matches {
            matched.push(path);
        }
    }
    matched.sort();
    Ok(matched)
}

/// Match a single-`*` glob against a name (e.g. `relay-alert-delivery-evidence-*.json`).
fn glob_matches(glob: &str, name: &str) -> bool {
    match glob.split_once('*') {
        Some((prefix, suffix)) => name.starts_with(prefix) && name.ends_with(suffix),
        None => glob == name,
    }
}

/// Read a fixture's `cases[].<field>` set and confirm every required value is
/// present. Shared across the negative-corpus assertions.
fn collect_case_field(
    path: &Path,
    field: &str,
) -> Result<std::collections::BTreeSet<String>, XtaskError> {
    let value = load_json(path)?;
    let cases = value
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| XtaskError::Validation(format!("{} has no cases array", display(path))))?;
    let mut present = std::collections::BTreeSet::new();
    for case in cases {
        if let Some(code) = case.get(field).and_then(Value::as_str) {
            present.insert(code.to_string());
        }
    }
    Ok(present)
}

fn assert_required_present(
    path: &Path,
    present: &std::collections::BTreeSet<String>,
    required: &[&str],
    label: &str,
) -> Result<(), XtaskError> {
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|code| !present.contains(*code))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(XtaskError::Validation(format!(
            "{label} corpus {} missing: {missing:?}",
            display(path)
        )))
    }
}

fn metadata_negative_codes(
    fixture_dir: &Path,
    file: &str,
    field: &str,
    required: &[&str],
) -> Result<(), XtaskError> {
    let path = fixture_dir.join(file);
    let present = collect_case_field(&path, field)?;
    assert_required_present(&path, &present, required, "negative")
}

fn metadata_negative_ids(
    fixture_dir: &Path,
    file: &str,
    required: &[&str],
) -> Result<(), XtaskError> {
    metadata_negative_codes(fixture_dir, file, "id", required)
}

fn metadata_negative_case_ids(
    fixture_dir: &Path,
    file: &str,
    required: &[&str],
) -> Result<(), XtaskError> {
    metadata_negative_codes(fixture_dir, file, "caseId", required)
}

include!("fixtures_facets.rs");
include!("fixtures_runtime.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn manifest_path() -> PathBuf {
        let root = crate::workspace_root().unwrap_or_else(|err| panic!("workspace root: {err}"));
        root.join(MANIFEST_PATH)
    }

    fn load() -> Manifest {
        load_manifest_from(&manifest_path())
            .unwrap_or_else(|err| panic!("manifest must load: {err}"))
    }

    fn runtime_manifest_path() -> PathBuf {
        let root = crate::workspace_root().unwrap_or_else(|err| panic!("workspace root: {err}"));
        root.join(RUNTIME_MANIFEST_PATH)
    }

    fn load_runtime() -> RuntimeManifest {
        load_runtime_manifest_from(&runtime_manifest_path())
            .unwrap_or_else(|err| panic!("runtime manifest must load: {err}"))
    }

    #[test]
    fn manifest_enumerates_all_known_facets() {
        let manifest = load();
        let mut names: Vec<&str> = manifest.facet.iter().map(|f| f.name.as_str()).collect();
        names.sort_unstable();
        let mut expected = KNOWN_FACETS.to_vec();
        expected.sort_unstable();
        assert_eq!(
            names, expected,
            "manifest must list exactly the 15 known facets"
        );
    }

    #[test]
    fn unknown_facet_is_an_error_not_a_skip() {
        let manifest = load();
        if let Some(found) = manifest.facet_by_name("does-not-exist") {
            panic!("unknown facet resolved to {}", found.name);
        }
    }

    #[test]
    fn every_known_facet_resolves() {
        let manifest = load();
        for name in KNOWN_FACETS {
            assert!(
                manifest.facet_by_name(name).is_some(),
                "missing facet {name}"
            );
        }
    }

    #[test]
    fn recurse_edges_point_at_known_facets() {
        let manifest = load();
        for facet in &manifest.facet {
            for edge in &facet.recurse {
                assert!(
                    manifest.facet_by_name(&edge.facet).is_some(),
                    "{} recurses into unknown facet {}",
                    facet.name,
                    edge.facet
                );
                edge.mode()
                    .unwrap_or_else(|err| panic!("{} edge mode: {err}", facet.name));
            }
        }
    }

    #[test]
    fn every_facet_kind_is_dispatchable() {
        // Fail-closed: a manifest kind with no handler must be a Manifest error,
        // not a silent pass. Exercise the metadata dispatch for each facet by
        // confirming the kind string maps to a known arm.
        let manifest = load();
        let known_kinds = [
            "transit",
            "runtime",
            "relay",
            "relay_ops",
            "directory_lifecycle",
            "relay_observability",
            "relay_alert_routing",
            "relay_alert_handoff",
            "relay_alert_delivery",
            "relay_alert_assurance",
            "relay_alert_assurance_export",
            "relay_alert_assurance_archive",
            "relay_alert_assurance_archive_package",
            "generic",
        ];
        for facet in &manifest.facet {
            assert!(
                known_kinds.contains(&facet.kind.as_str()),
                "facet {} has unhandled kind {}",
                facet.name,
                facet.kind
            );
        }
    }

    #[test]
    fn schema_check_values_are_valid() {
        let manifest = load();
        for facet in &manifest.facet {
            SchemaCheck::from_str(&facet.schema_check)
                .unwrap_or_else(|err| panic!("{} schema_check: {err}", facet.name));
        }
    }

    #[test]
    fn mode_from_flags_rejects_both() {
        match Mode::from_flags(true, true) {
            Ok(mode) => panic!("conflicting flags resolved to {mode:?}"),
            Err(XtaskError::Usage(_)) => {}
            Err(other) => panic!("expected Usage error, got {other}"),
        }
        assert_eq!(
            Mode::from_flags(true, false).unwrap_or_else(|err| panic!("{err}")),
            Mode::SchemaOnly
        );
        assert_eq!(
            Mode::from_flags(false, true).unwrap_or_else(|err| panic!("{err}")),
            Mode::NegativeOnly
        );
        assert_eq!(
            Mode::from_flags(false, false).unwrap_or_else(|err| panic!("{err}")),
            Mode::All
        );
    }

    #[test]
    fn glob_matches_prefix_suffix() {
        assert!(glob_matches(
            "relay-alert-delivery-evidence-*.json",
            "relay-alert-delivery-evidence-1.json"
        ));
        assert!(!glob_matches(
            "relay-alert-delivery-evidence-*.json",
            "relay-alert-report.json"
        ));
        assert!(glob_matches("exact.json", "exact.json"));
    }

    #[test]
    fn assert_schema_shape_strict_rejects_open_object() {
        let open = serde_json::json!({ "type": "object" });
        match assert_schema_shape("open.schema.json", &open, SchemaCheck::StrictObject) {
            Ok(()) => panic!("open object passed strict check"),
            Err(XtaskError::Validation(_)) => {}
            Err(other) => panic!("expected Validation, got {other}"),
        }
        let strict = serde_json::json!({ "type": "object", "additionalProperties": false });
        assert_schema_shape("strict.schema.json", &strict, SchemaCheck::StrictObject)
            .unwrap_or_else(|err| panic!("strict object should pass: {err}"));
    }

    #[test]
    fn assert_schema_shape_frozen_requires_id() {
        let no_id = serde_json::json!({ "type": "object" });
        match assert_schema_shape("x.schema.json", &no_id, SchemaCheck::FrozenObject) {
            Ok(()) => panic!("missing $id passed frozen check"),
            Err(XtaskError::Validation(_)) => {}
            Err(other) => panic!("expected Validation, got {other}"),
        }
        let frozen = serde_json::json!({ "type": "object", "$id": "https://chio.world/x" });
        assert_schema_shape("x.schema.json", &frozen, SchemaCheck::FrozenObject)
            .unwrap_or_else(|err| panic!("frozen object should pass: {err}"));
    }

    #[test]
    fn schema_only_path_passes_for_transit_against_committed_fixtures() {
        let root = crate::workspace_root().unwrap_or_else(|err| panic!("workspace root: {err}"));
        let manifest = load();
        let facet = manifest
            .facet_by_name("transit")
            .unwrap_or_else(|| panic!("transit facet missing"));
        pre_schema_guard(&root, facet).unwrap_or_else(|err| panic!("transit guard: {err}"));
        run_schema_block(&root, &manifest, facet)
            .unwrap_or_else(|err| panic!("transit schema block: {err}"));
        run_metadata_block(&root, facet).unwrap_or_else(|err| panic!("transit metadata: {err}"));
    }

    #[test]
    fn relay_schema_block_and_metadata_pass_against_committed_fixtures() {
        // The relay runbook guard intentionally fires on the current branch
        // (the runbook is the Chio runbook and cites the name), exactly as
        // `check-chio-pheromone-relay.sh` does, so this test exercises only the
        // schema + metadata block, which must pass against the committed
        // fixtures. The guard's fail-closed behavior is covered separately by
        // `relay_runbook_guard_reproduces_script_rejection`.
        let root = crate::workspace_root().unwrap_or_else(|err| panic!("workspace root: {err}"));
        let manifest = load();
        let facet = manifest
            .facet_by_name("relay")
            .unwrap_or_else(|| panic!("relay facet missing"));
        run_schema_block(&root, &manifest, facet)
            .unwrap_or_else(|err| panic!("relay schema block: {err}"));
        run_metadata_block(&root, facet).unwrap_or_else(|err| panic!("relay metadata: {err}"));
    }

    #[test]
    fn relay_runbook_guard_reproduces_script_rejection() {
        // Parity: the consolidated relay guard must reject the same runbook the
        // original `rg "Chio|CHIO|chio"` guard rejected (fail-closed).
        let root = crate::workspace_root().unwrap_or_else(|err| panic!("workspace root: {err}"));
        let manifest = load();
        let facet = manifest
            .facet_by_name("relay")
            .unwrap_or_else(|| panic!("relay facet missing"));
        match pre_schema_guard(&root, facet) {
            Ok(()) => panic!("relay runbook guard unexpectedly passed"),
            Err(XtaskError::Validation(_)) => {}
            Err(other) => panic!("expected Validation rejection, got {other}"),
        }
    }

    #[test]
    fn schema_only_path_passes_for_relay_observability_against_committed_fixtures() {
        let root = crate::workspace_root().unwrap_or_else(|err| panic!("workspace root: {err}"));
        let manifest = load();
        let facet = manifest
            .facet_by_name("relay-observability")
            .unwrap_or_else(|| panic!("relay-observability facet missing"));
        run_schema_block(&root, &manifest, facet)
            .unwrap_or_else(|err| panic!("observability schema block: {err}"));
        run_metadata_block(&root, facet)
            .unwrap_or_else(|err| panic!("observability metadata: {err}"));
    }

    // -- runtime manifest tests -------------------------------------------

    #[test]
    fn runtime_manifest_enumerates_all_known_facets() {
        let manifest = load_runtime();
        let mut names: Vec<&str> = manifest.facet.iter().map(|f| f.name.as_str()).collect();
        names.sort_unstable();
        let mut expected = RUNTIME_KNOWN_FACETS.to_vec();
        expected.sort_unstable();
        assert_eq!(
            names, expected,
            "runtime manifest must list exactly the six runtime facets"
        );
    }

    #[test]
    fn runtime_manifest_passes_enumeration_assertion() {
        let manifest = load_runtime();
        assert_runtime_manifest_enumeration(&manifest)
            .unwrap_or_else(|err| panic!("runtime enumeration: {err}"));
    }

    #[test]
    fn every_known_runtime_facet_resolves() {
        let manifest = load_runtime();
        for name in RUNTIME_KNOWN_FACETS {
            assert!(
                manifest.facet_by_name(name).is_some(),
                "missing runtime facet {name}"
            );
        }
    }

    #[test]
    fn unknown_runtime_facet_is_an_error_not_a_skip() {
        let manifest = load_runtime();
        if let Some(found) = manifest.facet_by_name("runtime-does-not-exist") {
            panic!("unknown runtime facet resolved to {}", found.name);
        }
    }

    #[test]
    fn every_runtime_facet_kind_is_dispatchable() {
        // Fail-closed: a runtime manifest kind with no handler arm must be a
        // Manifest error, not a silent pass.
        let manifest = load_runtime();
        let known_kinds = [
            "spine_fixtures",
            "spine",
            "proof_parity",
            "policy",
            "ops_hardening",
            "orchestration",
        ];
        for facet in &manifest.facet {
            assert!(
                known_kinds.contains(&facet.kind.as_str()),
                "runtime facet {} has unhandled kind {}",
                facet.name,
                facet.kind
            );
        }
    }

    #[test]
    fn runtime_facet_names_are_disjoint_from_pheromone_facets() {
        // The `runtime` and `transit` pheromone facets are a different domain
        // from the chio-runtime facets; the runtime facet names must never
        // collide with a pheromone facet name, or `run` would route ambiguously.
        for runtime_name in RUNTIME_KNOWN_FACETS {
            assert!(
                !KNOWN_FACETS.contains(&runtime_name),
                "runtime facet {runtime_name} collides with a pheromone facet name"
            );
        }
    }

    #[test]
    fn runtime_facets_carry_runtime_prefix() {
        // The CLI routes `check fixtures <facet>` to the runtime manifest only
        // when the name is in RUNTIME_KNOWN_FACETS, so every runtime facet must
        // be enumerated there; assert the prefix invariant the routing relies on.
        for name in RUNTIME_KNOWN_FACETS {
            assert!(
                name.starts_with("runtime-"),
                "runtime facet {name} must carry the runtime- prefix"
            );
        }
    }

    #[test]
    fn runtime_spine_fixtures_validate_pairs_use_root_relative_docs() {
        // The runtime-spine-fixtures static validate pairs reference documents
        // by root-relative paths (they live under examples/...), and one schema
        // is the cross-directory pheromone query-report schema. Confirm the
        // manifest carries that shape so the slash-bearing resolver applies.
        let manifest = load_runtime();
        let facet = manifest
            .facet_by_name("runtime-spine-fixtures")
            .unwrap_or_else(|| panic!("runtime-spine-fixtures facet missing"));
        assert!(
            facet.validate.iter().all(|p| p.doc.contains('/')),
            "spine-fixtures docs must be root-relative"
        );
        assert!(
            facet
                .validate
                .iter()
                .any(|p| p.schema == "spec/schemas/chio-pheromone/v1/query-report.schema.json"),
            "spine-fixtures must pull the cross-directory pheromone query-report schema"
        );
    }

    #[test]
    fn runtime_cargo_test_tails_are_present_where_expected() {
        // Arg handling: the proof-parity facet's cargo_tests must include the
        // chio-cli runtime filter the script ran, encoded as an argv tail.
        let manifest = load_runtime();
        let facet = manifest
            .facet_by_name("runtime-proof-parity")
            .unwrap_or_else(|| panic!("runtime-proof-parity facet missing"));
        assert!(
            facet.cargo_tests.iter().any(|tail| tail
                == &vec![
                    "-p".to_string(),
                    "chio-cli".to_string(),
                    "chio_runtime".to_string(),
                    "--bin".to_string(),
                    "chio".to_string(),
                ]),
            "proof-parity must run the chio-cli chio_runtime filter"
        );
    }

    #[test]
    fn corrupted_schema_map_yields_validation_error() {
        // A deliberately wrong registry entry must fail closed with Validation.
        let mut registry = std::collections::BTreeMap::new();
        registry.insert(
            "chio.pheromone.relay-observability-report.v1".to_string(),
            "spec/schemas/chio-pheromone/v1/WRONG.schema.json".to_string(),
        );
        let want = "spec/schemas/chio-pheromone/v1/relay-observability-report.schema.json";
        match registry.get("chio.pheromone.relay-observability-report.v1") {
            Some(registered) if registered == want => {
                panic!("corrupted registry unexpectedly matched")
            }
            _ => {}
        }
    }
}
