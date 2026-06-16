use super::*;
use chio_core_types::{
    receipt::body::{ChioReceipt, ChioReceiptBody},
    Keypair,
};
use std::{collections::BTreeSet, ffi::OsString};

const PROOF_FIXTURE_ROOT_ENV: &str = "CHIO_PROOF_FIXTURE_ROOT";
const PROOF_FIXTURE_CATALOG_FILE: &str = "catalog.json";
const PROOF_FIXTURE_CATALOG_SCHEMA: &str = "chio.proof-room.fixture-root-catalog.v1";
const COMMERCE_TRANSACTION_PASSPORT_FIXTURE_ID: &str = "commerce-transaction-passport";
const COMMERCE_TRANSACTION_PASSPORT_FIXTURE_SOURCE: &str =
    "generated:commerce-payments/offline-psp-valid+public-settlement/valid-offline-finality";
const DISCLOSURE_AGENT_WEB_FIXTURE_ID: &str = "disclosure-and-agent-web-envelope";
const DISCLOSURE_AGENT_WEB_FIXTURE_SOURCE: &str =
    "generated:disclosure-lineage/valid-lineage-ledger+agent-web/valid-webhook-cloudevents";
const RECURSIVE_RUNTIME_SWARM_FIXTURE_ID: &str = "recursive-runtime-swarm";
const RUNTIME_SWARM_LOOPBACK_NOW_UNIX_MS: u64 = 1_800_000_001_000;
const RUNTIME_SWARM_LOOPBACK_SCENARIO: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../examples/chio-3vendor/fixtures/runtime-spine/scenario.json"
));
const RUNTIME_SWARM_LOOPBACK_ARTIFACTS: &[(&str, &str)] = &[
    ("proof-package.json", "runtime-proof-package"),
    ("verifier-report.json", "runtime-verifier-report"),
    ("verifier-trust-bundle.json", "runtime-verifier-trust-bundle"),
    ("verification-context.json", "runtime-verification-context"),
    ("workflow-receipt.json", "runtime-workflow-receipt"),
    (
        "proof-regeneration-report.json",
        "runtime-proof-regeneration-report",
    ),
    (
        "runtime-proof-parity-report.json",
        "runtime-proof-parity-report",
    ),
    (
        "runtime-evidence-manifest.json",
        "runtime-evidence-manifest",
    ),
    (
        "runtime-proof-regeneration-input.json",
        "runtime-proof-regeneration-input",
    ),
    ("workflow-run-report.json", "runtime-workflow-run-report"),
];
const EMBEDDED_PROOF_FIXTURE_CATALOG: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../fixtures/proof-room/catalog.json"
));

struct EmbeddedProofFixtureFile {
    path: &'static str,
    contents: &'static [u8],
}

include!(concat!(env!("OUT_DIR"), "/proof_fixture_files.rs"));

#[derive(serde::Serialize)]
struct ProofFixtureListReport {
    schema: &'static str,
    fixtures: Vec<ProofFixtureDescriptor>,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub(super) struct ProofFixtureDescriptor {
    pub(super) id: String,
    pub(super) kind: String,
    pub(super) path: String,
    description: String,
}

#[derive(serde::Deserialize)]
struct ProofFixtureCatalog {
    schema: String,
    fixtures: Vec<ProofFixtureDescriptor>,
}

#[derive(serde::Deserialize)]
struct ProofFixtureNegativeCase {
    expected_failure_code: String,
    #[serde(default)]
    claim_ref: Option<String>,
}

#[derive(serde::Serialize)]
struct ProofFixtureGenerateReport {
    schema: &'static str,
    fixture_id: String,
    source: String,
    out: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_verdict: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_failure: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verify_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verifier_report_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preflight_plan_path: Option<String>,
}


pub(super) fn dispatch_proof_fixture(
    command: ProofFixtureCommands,
    json_output: bool,
) -> Result<(), CliError> {
    match command {
        ProofFixtureCommands::List => list_proof_fixtures(json_output),
        ProofFixtureCommands::Generate { fixture_id, out } => {
            generate_proof_fixture(&fixture_id, &out, json_output)
        }
    }
}

fn list_proof_fixtures(json_output: bool) -> Result<(), CliError> {
    let fixtures = proof_fixtures()?;
    let report = ProofFixtureListReport {
        schema: "chio.proof.fixture-list.v1",
        fixtures,
    };
    let mut stdout = std::io::stdout();
    if json_output {
        serde_json::to_writer(&mut stdout, &report)?;
        stdout.write_all(b"\n")?;
    } else {
        for fixture in &report.fixtures {
            writeln!(
                stdout,
                "{}\t{}\t{}",
                fixture.id, fixture.kind, fixture.description
            )?;
        }
    }
    Ok(())
}

fn generate_proof_fixture(
    fixture_id: &str,
    out: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let descriptor = proof_fixture(fixture_id)?;
    if descriptor.id == COMMERCE_TRANSACTION_PASSPORT_FIXTURE_ID {
        generate_commerce_transaction_passport_fixture(out)?;
    } else if descriptor.id == DISCLOSURE_AGENT_WEB_FIXTURE_ID {
        generate_disclosure_agent_web_fixture(out)?;
    } else if descriptor.id == RECURSIVE_RUNTIME_SWARM_FIXTURE_ID {
        generate_recursive_runtime_swarm_fixture(out)?;
    } else if let Some(root) = installed_fixture_root() {
        let source = installed_fixture_source(&root, &descriptor)?;
        copy_dir_contents(&source, out)?;
    } else {
        copy_embedded_fixture(installed_fixture_path(&descriptor), out)?;
    }
    if descriptor.kind == "transaction-passport"
        && descriptor.id != RECURSIVE_RUNTIME_SWARM_FIXTURE_ID
    {
        collect::seal_collected_proof_bundle(ProofCollectKind::TransactionPassport, out)?;
    }
    let verifier_report_path = proof_fixture_generated_verifier_report_path(&descriptor, out);
    if let Some(verifier_report_path) = verifier_report_path.as_deref() {
        write_generated_verifier_report(&descriptor, out, verifier_report_path)?;
    }
    let verify_path = proof_fixture_verify_path(&descriptor, out);
    let preflight_plan_path = proof_fixture_preflight_plan_path(&descriptor, out);
    let expected_failure = proof_fixture_expected_failure(
        &descriptor,
        verify_path.as_deref(),
        verifier_report_path.as_deref(),
        preflight_plan_path.as_deref(),
    )?;
    let expected_verdict = proof_fixture_expected_verdict(&descriptor, expected_failure.as_ref());
    let report = ProofFixtureGenerateReport {
        schema: "chio.proof.fixture-generate-report.v1",
        fixture_id: descriptor.id.clone(),
        source: descriptor.path.clone(),
        out: out.to_string_lossy().into_owned(),
        expected_verdict,
        expected_failure,
        verify_path: verify_path.map(|path| path.to_string_lossy().into_owned()),
        verifier_report_path: verifier_report_path.map(|path| path.to_string_lossy().into_owned()),
        preflight_plan_path: preflight_plan_path.map(|path| path.to_string_lossy().into_owned()),
    };

    let mut stdout = std::io::stdout();
    if json_output {
        serde_json::to_writer(&mut stdout, &report)?;
        stdout.write_all(b"\n")?;
    } else {
        writeln!(
            stdout,
            "generated {} at {}",
            descriptor.id,
            out.to_string_lossy()
        )?;
        if let Some(expected_failure) = &report.expected_failure {
            writeln!(stdout, "expected: failed ({expected_failure})")?;
        }
    }
    Ok(())
}

fn proof_fixture_expected_failure(
    descriptor: &ProofFixtureDescriptor,
    verify_path: Option<&Path>,
    verifier_report_path: Option<&Path>,
    preflight_plan_path: Option<&Path>,
) -> Result<Option<String>, CliError> {
    if descriptor.kind == "workflow-preflight" {
        let Some(preflight_plan_path) = preflight_plan_path else {
            return Err(CliError::cli_other_error(format!(
                "workflow preflight fixture has no preflight entrypoint: {}",
                descriptor.id
            )));
        };
        return workflow_preflight_expected_failure(preflight_plan_path);
    }
    if descriptor.kind == "negative-transaction-passport" {
        let verify_path = verify_path.ok_or_else(|| {
            CliError::cli_other_error(format!(
                "negative proof fixture has no verifier entrypoint: {}",
                descriptor.id
            ))
        })?;
        return negative_transaction_passport_expected_failure(descriptor, verify_path);
    }
    if descriptor.kind == "negative-disclosure-crypto-context" {
        let verifier_report_path = verifier_report_path.ok_or_else(|| {
            CliError::cli_other_error(format!(
                "negative crypto context fixture has no verifier report: {}",
                descriptor.id
            ))
        })?;
        return crypto_context_expected_failure(verifier_report_path);
    }
    Ok(None)
}

fn negative_transaction_passport_expected_failure(
    descriptor: &ProofFixtureDescriptor,
    verify_path: &Path,
) -> Result<Option<String>, CliError> {
    let expected_failure = proof_fixture_negative_expected_failure(descriptor)?;
    match verify_transaction_passport_file(verify_path) {
        Ok(_) => Err(CliError::cli_other_error(format!(
            "negative proof fixture unexpectedly verified: {}",
            descriptor.id
        ))),
        Err(error) => {
            let observed_failure = semantic_negative_failure_code(&error.to_string());
            if !negative_failure_code_matches(&observed_failure, &expected_failure) {
                return Err(CliError::cli_other_error(format!(
                    "negative proof fixture failed for the wrong reason: {}: expected {}, got {}",
                    descriptor.id, expected_failure, observed_failure
                )));
            }
            Ok(Some(expected_failure))
        }
    }
}

pub(super) fn proof_fixture_negative_expected_failure(
    descriptor: &ProofFixtureDescriptor,
) -> Result<String, CliError> {
    Ok(proof_fixture_negative_case(descriptor)?.expected_failure_code)
}

pub(super) fn proof_fixture_negative_claim_ref(
    descriptor: &ProofFixtureDescriptor,
) -> Result<Option<String>, CliError> {
    Ok(proof_fixture_negative_case(descriptor)?.claim_ref)
}

fn proof_fixture_negative_case(
    descriptor: &ProofFixtureDescriptor,
) -> Result<ProofFixtureNegativeCase, CliError> {
    let metadata_path = negative_fixture_metadata_path(descriptor)?;
    let raw = if let Some(root) = installed_fixture_root() {
        read_installed_negative_fixture_metadata(&root, &metadata_path, descriptor)?
    } else {
        read_embedded_negative_fixture_metadata(&metadata_path, descriptor)?
    };
    let negative_case: ProofFixtureNegativeCase = serde_json::from_slice(&raw).map_err(|error| {
        CliError::cli_other_error(format!(
            "invalid negative proof fixture metadata for {}: {}",
            descriptor.id, error
        ))
    })?;
    Ok(negative_case)
}

fn negative_fixture_metadata_path(descriptor: &ProofFixtureDescriptor) -> Result<PathBuf, CliError> {
    let fixture_path = Path::new(installed_fixture_path(descriptor));
    if fixture_path.is_absolute()
        || fixture_path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(CliError::cli_other_error(format!(
            "unsafe negative proof fixture path: {}",
            descriptor.path
        )));
    }
    let fixture_name = fixture_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "negative proof fixture path has no fixture name: {}",
                descriptor.path
            ))
        })?;
    let family = fixture_path.parent().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "negative proof fixture path has no family: {}",
            descriptor.path
        ))
    })?;
    Ok(family
        .join("negatives")
        .join(format!("{fixture_name}.json")))
}

fn read_installed_negative_fixture_metadata(
    root: &Path,
    metadata_path: &Path,
    descriptor: &ProofFixtureDescriptor,
) -> Result<Vec<u8>, CliError> {
    let root = fs::canonicalize(root)?;
    let metadata_path = root.join(metadata_path);
    let metadata_path = fs::canonicalize(&metadata_path).map_err(|error| {
        CliError::cli_io_error(format!(
            "negative proof fixture missing expected failure metadata for {} at {}: {}",
            descriptor.id,
            metadata_path.display(),
            error
        ))
    })?;
    if !metadata_path.starts_with(&root) {
        return Err(CliError::cli_other_error(format!(
            "negative proof fixture metadata path escapes root: {}",
            descriptor.path
        )));
    }
    Ok(fs::read(metadata_path)?)
}

fn read_embedded_negative_fixture_metadata(
    metadata_path: &Path,
    descriptor: &ProofFixtureDescriptor,
) -> Result<Vec<u8>, CliError> {
    let metadata_path = metadata_path.to_str().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "negative proof fixture metadata path is not utf8: {}",
            descriptor.path
        ))
    })?;
    EMBEDDED_PROOF_FIXTURE_FILES
        .iter()
        .find(|file| file.path == metadata_path)
        .map(|file| file.contents.to_vec())
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "negative proof fixture missing expected failure metadata: {}",
                descriptor.id
            ))
        })
}

fn proof_fixture_expected_verdict(
    descriptor: &ProofFixtureDescriptor,
    expected_failure: Option<&String>,
) -> Option<&'static str> {
    if descriptor.kind == "negative-disclosure-crypto-context" && expected_failure.is_some() {
        Some("rejected")
    } else {
        expected_failure.map(|_| "failed")
    }
}

fn crypto_context_expected_failure(path: &Path) -> Result<Option<String>, CliError> {
    let report: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
    let Some(check) = report
        .get("rejected_checks")
        .and_then(serde_json::Value::as_array)
        .and_then(|checks| checks.first())
    else {
        return Err(CliError::cli_other_error(format!(
            "negative crypto context fixture has no rejected checks: {}",
            path.display()
        )));
    };
    let code = check
        .get("code")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("crypto_context_rejected");
    let message = check
        .get("message")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("crypto context rejected");
    Ok(Some(format!("{code}: {message}")))
}

fn workflow_preflight_expected_failure(path: &Path) -> Result<Option<String>, CliError> {
    let bytes = fs::read(path)?;
    let plan: chio_workflow::WorkflowPreflightPlan = serde_json::from_slice(&bytes)?;
    let report = chio_workflow::evaluate_workflow_preflight(&plan)
        .map_err(|error| CliError::cli_other_error(format!("workflow preflight: {error}")))?;

    if report.verdict != chio_workflow::WorkflowPreflightVerdict::Rejected {
        return Ok(None);
    }

    let failure = report
        .rejected_checks
        .first()
        .map(|check| format!("{}: {}", check.code, check.message))
        .unwrap_or_else(|| "workflow preflight rejected the plan".to_string());
    Ok(Some(failure))
}

fn proof_fixture_verify_path(descriptor: &ProofFixtureDescriptor, out: &Path) -> Option<PathBuf> {
    if descriptor.id == RECURSIVE_RUNTIME_SWARM_FIXTURE_ID {
        return Some(out.join("proof-room-bundle"));
    }
    match descriptor.kind.as_str() {
        "proof-room" => Some(out.join("proof-room-bundle")),
        "transaction-passport" => Some(out.to_path_buf()),
        "negative-transaction-passport" => Some(out.join("transaction-passport.json")),
        _ => None,
    }
}

fn proof_fixture_preflight_plan_path(
    descriptor: &ProofFixtureDescriptor,
    out: &Path,
) -> Option<PathBuf> {
    match descriptor.kind.as_str() {
        "workflow-preflight" => Some(out.join("preflight-plan.json")),
        _ => None,
    }
}

fn proof_fixture_generated_verifier_report_path(
    descriptor: &ProofFixtureDescriptor,
    out: &Path,
) -> Option<PathBuf> {
    if descriptor.id == RECURSIVE_RUNTIME_SWARM_FIXTURE_ID {
        return Some(out.join("verifier-report.json"));
    }
    match descriptor.kind.as_str() {
        "transaction-passport" => Some(out.join("verifier/report.json")),
        "negative-disclosure-crypto-context" => Some(out.join("verifier-report.json")),
        _ => None,
    }
}

fn write_generated_verifier_report(
    descriptor: &ProofFixtureDescriptor,
    out: &Path,
    verifier_report_path: &Path,
) -> Result<(), CliError> {
    if descriptor.kind != "negative-disclosure-crypto-context" {
        return Ok(());
    }
    let context_path = out.join("verification-context.json");
    let context_bytes = fs::read(&context_path)?;
    let report_bytes =
        chio_proof_room::crypto_context_rejection_report_bytes(&context_bytes, &descriptor.id)
            .map_err(CliError::cli_other_error)?;
    fs::write(verifier_report_path, report_bytes)?;
    Ok(())
}

fn proof_fixture(fixture_id: &str) -> Result<ProofFixtureDescriptor, CliError> {
    proof_fixtures()?
        .into_iter()
        .find(|fixture| fixture.id == fixture_id)
        .ok_or_else(|| {
            CliError::cli_other_error(format!("unknown proof fixture id: {fixture_id}"))
        })
}

pub(super) fn proof_fixtures() -> Result<Vec<ProofFixtureDescriptor>, CliError> {
    let mut fixtures = if let Some(catalog) = installed_fixture_catalog()? {
        catalog.fixtures
    } else {
        parse_fixture_catalog(
            EMBEDDED_PROOF_FIXTURE_CATALOG.as_bytes(),
            "embedded proof fixture catalog",
        )?
        .fixtures
    };
    append_generated_public_stage_fixtures(&mut fixtures);
    Ok(fixtures)
}

fn append_generated_public_stage_fixtures(fixtures: &mut Vec<ProofFixtureDescriptor>) {
    if !fixtures
        .iter()
        .any(|fixture| fixture.id == COMMERCE_TRANSACTION_PASSPORT_FIXTURE_ID)
        && commerce_transaction_passport_sources_exist()
    {
        fixtures.push(commerce_transaction_passport_fixture_descriptor());
    }
    if !fixtures
        .iter()
        .any(|fixture| fixture.id == DISCLOSURE_AGENT_WEB_FIXTURE_ID)
        && disclosure_agent_web_sources_exist()
    {
        fixtures.push(disclosure_agent_web_fixture_descriptor());
    }
}

fn commerce_transaction_passport_sources_exist() -> bool {
    generated_fixture_sources_exist(&[
        "commerce-payments/offline-psp-valid",
        "public-settlement/valid-offline-finality",
    ])
}

fn disclosure_agent_web_sources_exist() -> bool {
    generated_fixture_sources_exist(&[
        "disclosure-lineage/valid-lineage-ledger",
        "agent-web/valid-webhook-cloudevents",
    ])
}

fn generated_fixture_sources_exist(relative_sources: &[&str]) -> bool {
    let fixture_root = proof_fixture_source_root();
    relative_sources
        .iter()
        .all(|relative_source| fixture_root.join(relative_source).is_dir())
}

fn commerce_transaction_passport_fixture_descriptor() -> ProofFixtureDescriptor {
    ProofFixtureDescriptor {
        id: COMMERCE_TRANSACTION_PASSPORT_FIXTURE_ID.to_string(),
        kind: "proof-room".to_string(),
        path: COMMERCE_TRANSACTION_PASSPORT_FIXTURE_SOURCE.to_string(),
        description: "Generated Proof Room bundle for commerce and public settlement evidence"
            .to_string(),
    }
}

fn disclosure_agent_web_fixture_descriptor() -> ProofFixtureDescriptor {
    ProofFixtureDescriptor {
        id: DISCLOSURE_AGENT_WEB_FIXTURE_ID.to_string(),
        kind: "proof-room".to_string(),
        path: DISCLOSURE_AGENT_WEB_FIXTURE_SOURCE.to_string(),
        description: "Generated Proof Room bundle for disclosure lineage and Agent Web envelope evidence"
            .to_string(),
    }
}

pub(super) fn copy_proof_fixture(fixture_id: &str, out: &Path) -> Result<(), CliError> {
    let descriptor = proof_fixture(fixture_id)?;
    if descriptor.id == COMMERCE_TRANSACTION_PASSPORT_FIXTURE_ID {
        return generate_commerce_transaction_passport_fixture(out);
    }
    if descriptor.id == DISCLOSURE_AGENT_WEB_FIXTURE_ID {
        return generate_disclosure_agent_web_fixture(out);
    }
    if descriptor.id == RECURSIVE_RUNTIME_SWARM_FIXTURE_ID {
        return generate_recursive_runtime_swarm_fixture(out);
    }
    if let Some(root) = installed_fixture_root() {
        let source = installed_fixture_source(&root, &descriptor)?;
        copy_dir_contents(&source, out)
    } else {
        copy_embedded_fixture(installed_fixture_path(&descriptor), out)
    }
}

fn generate_commerce_transaction_passport_fixture(out: &Path) -> Result<(), CliError> {
    if path_exists_or_is_symlink(out)? {
        return Err(CliError::cli_other_error(format!(
            "proof output directory already exists: {}",
            out.display()
        )));
    }

    let fixture_root = proof_fixture_source_root();
    let commerce_source = fixture_root.join("commerce-payments/offline-psp-valid");
    let settlement_source = fixture_root.join("public-settlement/valid-offline-finality");
    let bundle = out.join("proof-room-bundle");
    copy_dir_contents(&commerce_source, &bundle)?;
    merge_public_settlement_fixture(&bundle, &settlement_source)?;
    add_commerce_terminal_receipts(&bundle)?;
    collect::seal_collected_public_fixture_bundle(
        ProofCollectKind::IoaWeb3,
        &bundle,
        COMMERCE_TRANSACTION_PASSPORT_FIXTURE_ID,
    )?;
    fs::copy(
        bundle.join("verifier/report.json"),
        out.join("verifier-report.json"),
    )?;
    Ok(())
}

fn add_commerce_terminal_receipts(bundle: &Path) -> Result<(), CliError> {
    let policy_sha256 = sha256_file(&bundle.join("verifier-policy.json"))?;
    let receipts = [
        (
            "commerce-terminal-allow-receipt.json",
            "commerce-terminal-allow-receipt",
            "receipt-commerce-terminal-allow",
            "allowed_executed",
        ),
        (
            "commerce-terminal-denial-receipt.json",
            "commerce-terminal-denial-receipt",
            "receipt-commerce-terminal-denial",
            "denied_guard_request",
        ),
    ];
    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph = read_json_value(&evidence_graph_path)?;
    let nodes = json_array_mut(&mut evidence_graph, "nodes", &evidence_graph_path)?;
    for (path, node_id, receipt_id, terminal_status) in receipts {
        let receipt_path = bundle.join(path);
        write_signed_terminal_receipt(&receipt_path, receipt_id, terminal_status, &policy_sha256)?;
        upsert_fixture_graph_node(
            nodes,
            node_id,
            path,
            "chio.receipt.v1",
            "receipt",
            &sha256_file(&receipt_path)?,
        );
    }
    write_json_line_file(&evidence_graph_path, &evidence_graph)?;
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport = read_json_value(&passport_path)?;
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    write_json_line_file(&passport_path, &passport)?;
    Ok(())
}

fn write_signed_terminal_receipt(
    destination: &Path,
    receipt_id: &str,
    terminal_status: &str,
    policy_sha256: &str,
) -> Result<(), CliError> {
    let keypair = Keypair::from_seed(&[29u8; 32]);
    let mut receipt = serde_json::json!({
        "schema": "chio.receipt.v1",
        "receipt_id": receipt_id,
        "terminal_status": terminal_status,
        "policy_digest": policy_sha256,
        "kernel_key": keypair.public_key().to_hex()
    });
    let (signature, _) = keypair.sign_canonical(&receipt).map_err(|error| {
        CliError::cli_other_error(format!("proof fixture receipt signing failed: {error}"))
    })?;
    receipt["signature"] = serde_json::Value::String(signature.to_hex());
    write_json_line_file(destination, &receipt)
}

fn generate_disclosure_agent_web_fixture(out: &Path) -> Result<(), CliError> {
    if path_exists_or_is_symlink(out)? {
        return Err(CliError::cli_other_error(format!(
            "proof output directory already exists: {}",
            out.display()
        )));
    }

    let fixture_root = proof_fixture_source_root();
    let disclosure_source = fixture_root.join("disclosure-lineage/valid-lineage-ledger");
    let agent_web_source = fixture_root.join("agent-web/valid-webhook-cloudevents");
    let bundle = out.join("proof-room-bundle");
    copy_dir_contents(&disclosure_source, &bundle)?;
    merge_agent_web_fixture(&bundle, &agent_web_source)?;
    collect::seal_collected_public_fixture_bundle(
        ProofCollectKind::DisclosureAgentWebEnvelope,
        &bundle,
        DISCLOSURE_AGENT_WEB_FIXTURE_ID,
    )?;
    fs::copy(
        bundle.join("verifier/report.json"),
        out.join("verifier-report.json"),
    )?;
    Ok(())
}

fn generate_recursive_runtime_swarm_fixture(out: &Path) -> Result<(), CliError> {
    if path_exists_or_is_symlink(out)? {
        return Err(CliError::cli_other_error(format!(
            "proof output directory already exists: {}",
            out.display()
        )));
    }

    let fixture_root = proof_fixture_source_root();
    let swarm_source = fixture_root.join("swarm-authority/valid-recursive-delegation");
    let bundle = out.join("proof-room-bundle");
    copy_dir_contents(&swarm_source, &bundle)?;
    add_runtime_swarm_parity_evidence(&bundle)?;
    collect::seal_collected_public_fixture_bundle(
        ProofCollectKind::RuntimeSpine,
        &bundle,
        RECURSIVE_RUNTIME_SWARM_FIXTURE_ID,
    )?;
    fs::copy(
        bundle.join("verifier/report.json"),
        out.join("verifier-report.json"),
    )?;
    Ok(())
}

fn add_runtime_swarm_parity_evidence(bundle: &Path) -> Result<(), CliError> {
    let temp_root = runtime_swarm_loopback_temp_root()?;
    let result = add_runtime_swarm_loopback_evidence(bundle, &temp_root);
    let cleanup_result = fs::remove_dir_all(&temp_root);
    match (result, cleanup_result) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) if error.kind() != std::io::ErrorKind::NotFound => {
            Err(CliError::cli_other_error(format!(
                "proof fixture runtime loopback cleanup failed: {}: {error}",
                temp_root.display()
            )))
        }
        (Ok(()), _) => Ok(()),
    }
}

fn add_runtime_swarm_loopback_evidence(bundle: &Path, temp_root: &Path) -> Result<(), CliError> {
    fs::create_dir_all(temp_root)?;
    let scenario_path = temp_root.join("scenario.json");
    write_executable_runtime_swarm_scenario(&scenario_path)?;
    let store_dir = temp_root.join("store");
    let out_dir = temp_root.join("out");
    chio_runtime_harness::run_runtime_loopback_scenario(
        &scenario_path,
        &store_dir,
        RUNTIME_SWARM_LOOPBACK_NOW_UNIX_MS,
        &out_dir,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("proof fixture runtime loopback failed: {error}"))
    })?;

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph = read_json_value(&evidence_graph_path)?;
    let nodes = json_array_mut(&mut evidence_graph, "nodes", &evidence_graph_path)?;
    for (file_name, role) in RUNTIME_SWARM_LOOPBACK_ARTIFACTS {
        let source = out_dir.join(file_name);
        let destination = bundle.join(file_name);
        fs::copy(&source, &destination)?;
        let artifact = read_json_value(&destination)?;
        let schema = required_json_string(&artifact, "schema", &destination)?;
        let artifact_sha256 = sha256_file(&destination)?;
        upsert_runtime_swarm_graph_node(nodes, file_name, &schema, role, &artifact_sha256);
    }
    write_json_line_file(&evidence_graph_path, &evidence_graph)?;
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport = read_json_value(&passport_path)?;
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    write_json_line_file(&passport_path, &passport)?;
    Ok(())
}

fn runtime_swarm_loopback_temp_root() -> Result<PathBuf, CliError> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| {
            CliError::cli_other_error(format!("proof fixture runtime loopback clock failed: {error}"))
        })?;
    Ok(std::env::temp_dir().join(format!(
        "chio-recursive-runtime-swarm-{}-{}",
        std::process::id(),
        duration.as_nanos()
    )))
}

fn write_executable_runtime_swarm_scenario(destination: &Path) -> Result<(), CliError> {
    let mut scenario: serde_json::Value = serde_json::from_str(RUNTIME_SWARM_LOOPBACK_SCENARIO)?;
    let arguments = [
        serde_json::json!({
            "caseRef": "refund-250",
            "tool": "read_refund_case",
            "workflowId": "wf-chio-refund-001"
        }),
        serde_json::json!({
            "caseRef": "refund-250",
            "tool": "verify_customer",
            "workflowId": "wf-chio-refund-001"
        }),
        serde_json::json!({
            "caseRef": "refund-250",
            "tool": "stage_refund",
            "workflowId": "wf-chio-refund-001"
        }),
    ];
    let tool_arg_sha256s = [
        "3f31b68cde492ccb216e04bb62d975141dbed7b3c4f96a73d21398eaa88fb5cc",
        "5e9312cae8fac5f26d60c004f5e371a48d649b1c5fb234803727f478d18a0ccd",
        "47e6e096b5d5888a3f90d057de3bce595d8ea5dd8624ccde387bb739d5a6464b",
    ];
    let host_kernel_ids = [
        "did:chio:vendor-a",
        "did:chio:vendor-b",
        "did:chio:vendor-c",
    ];
    let capability_ids = [
        "lease-vendor-a-read",
        "lease-vendor-b-kyc",
        "lease-vendor-c-refund",
    ];
    let steps = json_array_mut(&mut scenario, "steps", destination)?;
    if steps.len() != arguments.len() {
        return Err(CliError::cli_other_error(format!(
            "proof fixture runtime loopback scenario has {} steps, expected {}",
            steps.len(),
            arguments.len()
        )));
    }
    for (index, step) in steps.iter_mut().enumerate() {
        let step_object = step.as_object_mut().ok_or_else(|| {
            CliError::cli_other_error(format!(
                "proof fixture runtime loopback step {index} is not an object"
            ))
        })?;
        step_object.insert("arguments".to_string(), arguments[index].clone());

        let request = step_object
            .get_mut("request")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "proof fixture runtime loopback step {index} has no request"
                ))
            })?;
        request.insert(
            "toolArgsSha256".to_string(),
            serde_json::Value::String(tool_arg_sha256s[index].to_string()),
        );
        request.insert(
            "hostKernelId".to_string(),
            serde_json::Value::String(host_kernel_ids[index].to_string()),
        );
        request.insert(
            "capabilityId".to_string(),
            serde_json::Value::String(capability_ids[index].to_string()),
        );

        let binding = step_object
            .get_mut("admissionBundle")
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|bundle| bundle.get_mut("binding"))
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "proof fixture runtime loopback step {index} has no admission bundle binding"
                ))
            })?;
        binding.insert(
            "toolArgsSha256".to_string(),
            serde_json::Value::String(tool_arg_sha256s[index].to_string()),
        );
        binding.insert(
            "hostKernelId".to_string(),
            serde_json::Value::String(host_kernel_ids[index].to_string()),
        );
        binding.insert(
            "capabilityId".to_string(),
            serde_json::Value::String(capability_ids[index].to_string()),
        );

        let profile = step_object
            .get_mut("admissionProfile")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "proof fixture runtime loopback step {index} has no admission profile"
                ))
            })?;
        profile.insert(
            "localKernelId".to_string(),
            serde_json::Value::String(host_kernel_ids[index].to_string()),
        );
    }
    let mut bytes = serde_json::to_vec_pretty(&scenario)?;
    bytes.push(b'\n');
    fs::write(destination, bytes)?;
    Ok(())
}

fn upsert_runtime_swarm_graph_node(
    nodes: &mut Vec<serde_json::Value>,
    path: &str,
    schema: &str,
    role: &str,
    sha256: &str,
) {
    upsert_fixture_graph_node(nodes, role, path, schema, role, sha256);
}

fn upsert_fixture_graph_node(
    nodes: &mut Vec<serde_json::Value>,
    node_id: &str,
    path: &str,
    schema: &str,
    role: &str,
    sha256: &str,
) {
    nodes.retain(|node| {
        node.get("id").and_then(serde_json::Value::as_str) != Some(node_id)
            && node.get("path").and_then(serde_json::Value::as_str) != Some(path)
    });
    nodes.push(serde_json::json!({
        "id": node_id,
        "schema": schema,
        "path": path,
        "sha256": sha256,
        "role": role
    }));
}

fn proof_fixture_source_root() -> PathBuf {
    installed_fixture_root().unwrap_or_else(|| {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fixtures/proof-room")
    })
}

fn merge_public_settlement_fixture(bundle: &Path, settlement_source: &Path) -> Result<(), CliError> {
    let settlement_passport_path = settlement_source.join("transaction-passport.json");
    let settlement_passport = read_json_value(&settlement_passport_path)?;
    let passport_id = required_json_string(&settlement_passport, "id", &settlement_passport_path)?;

    let policy_path = bundle.join("verifier-policy.json");
    let mut policy = read_json_value(&policy_path)?;
    append_required_claims_from_policy(&mut policy, &settlement_source.join("verifier-policy.json"))?;
    write_json_line_file(&policy_path, &policy)?;
    let policy_sha256 = sha256_file(&policy_path)?;

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph = read_json_value(&evidence_graph_path)?;
    append_graph_artifacts_from_fixture(
        bundle,
        settlement_source,
        &mut evidence_graph,
        &[("passport-public-settlement-valid", &passport_id)],
    )?;
    refresh_graph_node_hashes(bundle, &mut evidence_graph)?;
    write_json_line_file(&evidence_graph_path, &evidence_graph)?;
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport = read_json_value(&passport_path)?;
    passport["id"] = serde_json::Value::String(passport_id);
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    passport["verifier_policy_sha256"] = serde_json::Value::String(policy_sha256);
    write_json_line_file(&passport_path, &passport)?;
    Ok(())
}

fn merge_agent_web_fixture(bundle: &Path, agent_web_source: &Path) -> Result<(), CliError> {
    let agent_web_passport_path = agent_web_source.join("transaction-passport.json");
    let agent_web_passport = read_json_value(&agent_web_passport_path)?;
    let agent_web_passport_id =
        required_json_string(&agent_web_passport, "id", &agent_web_passport_path)?;

    let policy_path = bundle.join("verifier-policy.json");
    let mut policy = read_json_value(&policy_path)?;
    append_required_claims_from_policy(&mut policy, &agent_web_source.join("verifier-policy.json"))?;
    write_json_line_file(&policy_path, &policy)?;
    let policy_sha256 = sha256_file(&policy_path)?;

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph = read_json_value(&evidence_graph_path)?;
    let passport_path = bundle.join("transaction-passport.json");
    let disclosure_passport = read_json_value(&passport_path)?;
    let disclosure_passport_id = required_json_string(&disclosure_passport, "id", &passport_path)?;
    replace_json_strings_in_graph_artifacts(
        bundle,
        &evidence_graph,
        &[(&disclosure_passport_id, &agent_web_passport_id)],
    )?;
    refresh_signed_lineage_subgraph_digest(bundle)?;
    append_graph_artifacts_from_fixture(
        bundle,
        agent_web_source,
        &mut evidence_graph,
        &[],
    )?;
    resign_agent_web_receipts_for_policy(bundle, &policy_sha256)?;
    refresh_graph_node_hashes(bundle, &mut evidence_graph)?;
    write_json_line_file(&evidence_graph_path, &evidence_graph)?;
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

    let mut passport = disclosure_passport;
    passport["id"] = serde_json::Value::String(agent_web_passport_id);
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    passport["verifier_policy_sha256"] = serde_json::Value::String(policy_sha256);
    write_json_line_file(&passport_path, &passport)?;
    Ok(())
}

fn refresh_signed_lineage_subgraph_digest(bundle: &Path) -> Result<(), CliError> {
    let path = bundle.join("signed-lineage-subgraph.json");
    let mut lineage = read_json_value(&path)?;
    let digest_material = serde_json::json!({
        "id": lineage["id"].clone(),
        "transaction_passport_ref": lineage["transaction_passport_ref"].clone(),
        "root_receipt_ids": lineage["root_receipt_ids"].clone(),
        "nodes": lineage["nodes"].clone(),
        "edges": lineage["edges"].clone(),
        "redactions": lineage["redactions"].clone()
    });
    let canonical = chio_core::canonical::canonical_json_bytes(&digest_material).map_err(|error| {
        CliError::cli_other_error(format!("lineage digest canonicalization failed: {error}"))
    })?;
    let digest = chio_core::sha256_hex(&canonical);
    lineage["subgraph_sha256"] = serde_json::Value::String(digest.clone());
    lineage["signature"] = serde_json::Value::String(format!("sig-sha256:{digest}"));
    write_json_line_file(&path, &lineage)?;
    Ok(())
}

fn resign_agent_web_receipts_for_policy(bundle: &Path, policy_sha256: &str) -> Result<(), CliError> {
    let receipts_dir = bundle.join("receipts");
    if !receipts_dir.is_dir() {
        return Ok(());
    }
    let keypair = Keypair::from_seed(&[17u8; 32]);
    for entry in fs::read_dir(&receipts_dir)? {
        let entry = entry?;
        let receipt_path = entry.path();
        if receipt_path.extension().and_then(std::ffi::OsStr::to_str) != Some("json") {
            continue;
        }
        let receipt: ChioReceipt = serde_json::from_slice(&fs::read(&receipt_path)?)?;
        let Some(receipt_ref) = receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("agent_web_receipt_ref"))
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let body = ChioReceiptBody {
            id: receipt_ref.to_string(),
            timestamp: receipt.timestamp,
            capability_id: receipt.capability_id,
            tool_server: receipt.tool_server,
            tool_name: receipt.tool_name,
            action: receipt.action,
            decision: receipt.decision,
            receipt_kind: receipt.receipt_kind,
            boundary_class: receipt.boundary_class,
            observation_outcome: receipt.observation_outcome,
            tool_origin: receipt.tool_origin,
            redaction_mode: receipt.redaction_mode,
            actor_chain: receipt.actor_chain,
            content_hash: receipt.content_hash,
            policy_hash: policy_sha256.to_string(),
            evidence: receipt.evidence,
            metadata: receipt.metadata,
            trust_level: receipt.trust_level,
            tenant_id: receipt.tenant_id,
            kernel_key: keypair.public_key(),
            bbs_projection_version: receipt.bbs_projection_version,
        };
        let signed_receipt = ChioReceipt::sign(body, &keypair).map_err(|error| {
            CliError::cli_other_error(format!(
                "proof fixture Agent Web receipt signing failed: {}: {error}",
                receipt_path.display()
            ))
        })?;
        write_json_line_file(&receipt_path, &signed_receipt)?;
    }
    Ok(())
}

fn append_required_claims_from_policy(
    policy: &mut serde_json::Value,
    source_policy_path: &Path,
) -> Result<(), CliError> {
    let source_policy = read_json_value(source_policy_path)?;
    let source_claims = source_policy
        .get("required_claims")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "proof fixture policy required_claims missing: {}",
                source_policy_path.display()
            ))
        })?;
    let required_claims = json_array_mut(policy, "required_claims", source_policy_path)?;
    for claim in source_claims {
        if !required_claims.contains(claim) {
            required_claims.push(claim.clone());
        }
    }
    Ok(())
}

fn append_graph_artifacts_from_fixture(
    bundle: &Path,
    source: &Path,
    evidence_graph: &mut serde_json::Value,
    replacements: &[(&str, &str)],
) -> Result<(), CliError> {
    let source_graph_path = source.join("evidence-graph.json");
    let source_graph = read_json_value(&source_graph_path)?;
    let source_nodes =
        json_array(&source_graph, "nodes", &source_graph_path)?.clone();
    let mut retained_ids = BTreeSet::new();

    for node in source_nodes {
        let path = required_json_string(&node, "path", &source_graph_path)?;
        if matches!(
            path.as_str(),
            "transaction-passport.json" | "evidence-graph.json" | "verifier-policy.json"
        ) {
            continue;
        }
        let destination_path = bundle.join(&path);
        if let Some(parent) = destination_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if replacements.is_empty() {
            fs::copy(source.join(&path), &destination_path)?;
        } else {
            let mut artifact = read_json_value(&source.join(&path))?;
            for (from, to) in replacements {
                replace_json_string(&mut artifact, from, to);
            }
            write_json_line_file(&destination_path, &artifact)?;
        }

        let mut node = node;
        node["sha256"] = serde_json::Value::String(sha256_file(&destination_path)?);
        retained_ids.insert(required_json_string(&node, "id", &source_graph_path)?);
        json_array_mut(evidence_graph, "nodes", &source_graph_path)?.push(node);
    }

    let source_edges =
        json_array(&source_graph, "edges", &source_graph_path)?.clone();
    let retained_edges = source_edges
        .into_iter()
        .filter(|edge| {
            let from = edge.get("from").and_then(serde_json::Value::as_str);
            let to = edge.get("to").and_then(serde_json::Value::as_str);
            from.is_some_and(|from| retained_ids.contains(from))
                && to.is_some_and(|to| retained_ids.contains(to))
        })
        .collect::<Vec<_>>();
    json_array_mut(evidence_graph, "edges", &source_graph_path)?.extend(retained_edges);
    Ok(())
}

fn replace_json_strings_in_graph_artifacts(
    bundle: &Path,
    evidence_graph: &serde_json::Value,
    replacements: &[(&str, &str)],
) -> Result<(), CliError> {
    for node in json_array(evidence_graph, "nodes", &bundle.join("evidence-graph.json"))? {
        let path = required_json_string(node, "path", &bundle.join("evidence-graph.json"))?;
        let artifact_path = bundle.join(&path);
        let mut artifact = read_json_value(&artifact_path)?;
        for (from, to) in replacements {
            replace_json_string(&mut artifact, from, to);
        }
        write_json_line_file(&artifact_path, &artifact)?;
    }
    Ok(())
}

fn refresh_graph_node_hashes(bundle: &Path, evidence_graph: &mut serde_json::Value) -> Result<(), CliError> {
    for node in json_array_mut(evidence_graph, "nodes", &bundle.join("evidence-graph.json"))? {
        let path = node
            .get("path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "proof fixture evidence node path missing: {}",
                    bundle.display()
                ))
            })?;
        node["sha256"] = serde_json::Value::String(sha256_file(&bundle.join(path))?);
    }
    Ok(())
}

fn replace_json_string(value: &mut serde_json::Value, from: &str, to: &str) {
    match value {
        serde_json::Value::String(text) if text == from => {
            *text = to.to_string();
        }
        serde_json::Value::Array(items) => {
            for item in items {
                replace_json_string(item, from, to);
            }
        }
        serde_json::Value::Object(entries) => {
            for item in entries.values_mut() {
                replace_json_string(item, from, to);
            }
        }
        _ => {}
    }
}

fn read_json_value(path: &Path) -> Result<serde_json::Value, CliError> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(CliError::from)
}

fn required_json_string(
    value: &serde_json::Value,
    field: &str,
    path: &Path,
) -> Result<String, CliError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "proof fixture JSON field missing: {}: {field}",
                path.display()
            ))
        })
}

fn json_array<'a>(
    value: &'a serde_json::Value,
    field: &str,
    path: &Path,
) -> Result<&'a Vec<serde_json::Value>, CliError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "proof fixture JSON array missing: {}: {field}",
                path.display()
            ))
        })
}

fn json_array_mut<'a>(
    value: &'a mut serde_json::Value,
    field: &str,
    path: &Path,
) -> Result<&'a mut Vec<serde_json::Value>, CliError> {
    value
        .get_mut(field)
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "proof fixture JSON array missing: {}: {field}",
                path.display()
            ))
        })
}

fn sha256_file(path: &Path) -> Result<String, CliError> {
    let bytes = fs::read(path)?;
    Ok(chio_core::sha256_hex(&bytes))
}

fn installed_fixture_catalog() -> Result<Option<ProofFixtureCatalog>, CliError> {
    let Some(root) = installed_fixture_root() else {
        return Ok(None);
    };
    let catalog_path = root.join(PROOF_FIXTURE_CATALOG_FILE);
    if !catalog_path.is_file() {
        return Err(CliError::cli_other_error(format!(
            "proof fixture catalog missing: {}",
            catalog_path.display()
        )));
    }
    read_fixture_catalog_file(&catalog_path).map(Some)
}

fn read_fixture_catalog_file(catalog_path: &Path) -> Result<ProofFixtureCatalog, CliError> {
    let raw = fs::read(catalog_path)?;
    parse_fixture_catalog(&raw, &catalog_path.display().to_string())
}

fn parse_fixture_catalog(raw: &[u8], source: &str) -> Result<ProofFixtureCatalog, CliError> {
    let catalog: ProofFixtureCatalog = serde_json::from_slice(raw).map_err(|error| {
        CliError::cli_other_error(format!("invalid proof fixture catalog {source}: {error}"))
    })?;
    if catalog.schema != PROOF_FIXTURE_CATALOG_SCHEMA {
        return Err(CliError::cli_other_error(format!(
            "unsupported proof fixture catalog schema {} in {}",
            catalog.schema, source
        )));
    }
    Ok(catalog)
}

pub(super) fn installed_fixture_root() -> Option<PathBuf> {
    std::env::var_os(PROOF_FIXTURE_ROOT_ENV).and_then(|root| {
        if root.is_empty() {
            None
        } else {
            Some(PathBuf::from(root))
        }
    })
}

fn installed_fixture_path(descriptor: &ProofFixtureDescriptor) -> &str {
    descriptor
        .path
        .strip_prefix("fixtures/proof-room/")
        .unwrap_or(descriptor.path.as_str())
}

fn installed_fixture_source(
    root: &Path,
    descriptor: &ProofFixtureDescriptor,
) -> Result<PathBuf, CliError> {
    let root = fs::canonicalize(root)?;
    let source = fs::canonicalize(root.join(installed_fixture_path(descriptor)))?;
    if !source.starts_with(&root) {
        return Err(CliError::cli_other_error(format!(
            "installed proof fixture path escapes root: {}",
            descriptor.path
        )));
    }
    Ok(source)
}

fn copy_embedded_fixture(fixture_path: &str, destination: &Path) -> Result<(), CliError> {
    if path_exists_or_is_symlink(destination)? {
        return Err(CliError::cli_other_error(format!(
            "proof output directory already exists: {}",
            destination.display()
        )));
    }
    let destination_root = new_destination_root(destination)?;
    if let Some(parent) = destination_root.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir(&destination_root)?;
    let mut copied = false;
    for file in EMBEDDED_PROOF_FIXTURE_FILES {
        let Some(relative_path) = embedded_fixture_member_path(fixture_path, file.path) else {
            continue;
        };
        let destination_path = destination_root.join(relative_path);
        if let Some(parent) = destination_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(destination_path, file.contents)?;
        copied = true;
    }
    if !copied {
        return Err(CliError::cli_other_error(format!(
            "embedded proof fixture not found: {fixture_path}"
        )));
    }
    Ok(())
}

fn embedded_fixture_member_path<'a>(fixture_path: &str, file_path: &'a str) -> Option<&'a str> {
    let fixture_path = fixture_path.trim_end_matches('/');
    if file_path == fixture_path {
        return Path::new(file_path).file_name()?.to_str();
    }
    file_path
        .strip_prefix(fixture_path)?
        .strip_prefix('/')
}

pub(super) fn copy_dir_contents(source: &Path, destination: &Path) -> Result<(), CliError> {
    if !source.is_dir() {
        return Err(CliError::cli_io_error(format!(
            "proof source directory does not exist: {}",
            source.display()
        )));
    }
    let source_root = fs::canonicalize(source)?;
    if path_exists_or_is_symlink(destination)? {
        return Err(CliError::cli_other_error(format!(
            "proof output directory already exists: {}",
            destination.display()
        )));
    }
    let destination_root = new_destination_root(destination)?;
    if destination_root.starts_with(&source_root) || source_root.starts_with(&destination_root) {
        return Err(CliError::cli_other_error(format!(
            "proof copy source and destination overlap: {} -> {}",
            source.display(),
            destination.display()
        )));
    }
    if let Some(parent) = destination_root.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir(&destination_root)?;
    for entry in fs::read_dir(&source_root)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination_root.join(entry.file_name());
        copy_dir_entry(&source_path, &destination_path)?;
    }
    Ok(())
}

fn path_exists_or_is_symlink(path: &Path) -> Result<bool, CliError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(CliError::from(error)),
    }
}

fn new_destination_root(destination: &Path) -> Result<PathBuf, CliError> {
    let destination = if destination.is_absolute() {
        destination.to_path_buf()
    } else {
        std::env::current_dir()?.join(destination)
    };
    let mut missing_components = Vec::<OsString>::new();
    let mut existing_ancestor = destination.as_path();
    while !path_exists_or_is_symlink(existing_ancestor)? {
        let component = existing_ancestor.file_name().ok_or_else(|| {
            CliError::cli_other_error(format!(
                "proof output directory must name a new directory: {}",
                destination.display()
            ))
        })?;
        missing_components.push(component.to_os_string());
        existing_ancestor = existing_ancestor.parent().ok_or_else(|| {
            CliError::cli_other_error(format!(
                "proof output directory parent does not exist: {}",
                destination.display()
            ))
        })?;
    }
    let mut destination_root = fs::canonicalize(existing_ancestor)?;
    for component in missing_components.iter().rev() {
        destination_root.push(component);
    }
    Ok(destination_root)
}

fn copy_dir_entry(source: &Path, destination: &Path) -> Result<(), CliError> {
    let file_type = fs::symlink_metadata(source)?.file_type();
    if file_type.is_dir() {
        fs::create_dir_all(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            copy_dir_entry(&entry.path(), &destination.join(entry.file_name()))?;
        }
        Ok(())
    } else if file_type.is_file() {
        fs::copy(source, destination)?;
        Ok(())
    } else {
        Err(CliError::cli_other_error(format!(
            "unsupported proof fixture file type: {}",
            source.display()
        )))
    }
}
