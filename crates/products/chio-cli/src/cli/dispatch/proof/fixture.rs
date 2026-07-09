use super::*;
use chio_core_types::{
    receipt::body::{ChioReceipt, ChioReceiptBody},
    receipt::decision::{Decision, ToolCallAction},
    receipt::kinds::{BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel},
    receipt::metadata::ActorRef,
    Keypair,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
};

#[path = "fixture_agent_web.rs"]
mod fixture_agent_web;
use fixture_agent_web::{
    normalize_agent_web_bilateral_in_toto_statement, refresh_agent_web_envelopes_for_subjects,
    resign_agent_web_receipts_for_policy,
};
#[path = "fixture_cleanup.rs"]
mod fixture_cleanup;
use fixture_cleanup::strip_collected_bundle_outputs;
#[path = "fixture_public_settlement_runtime.rs"]
mod fixture_public_settlement_runtime;
use fixture_public_settlement_runtime::public_settlement_runtime_hashes;

const PROOF_FIXTURE_ROOT_ENV: &str = "CHIO_PROOF_FIXTURE_ROOT";
const PROOF_FIXTURE_CATALOG_FILE: &str = "catalog.json";
const PROOF_FIXTURE_CATALOG_SCHEMA: &str = "chio.proof-room.fixture-root-catalog.v1";
const SINGLE_CALL_AUTHORITY_FIXTURE_ID: &str = "single-call-authority";
const COMMERCE_TRANSACTION_PASSPORT_FIXTURE_ID: &str = "commerce-transaction-passport";
const COMMERCE_TRANSACTION_PASSPORT_FIXTURE_SOURCE: &str =
    "generated:commerce-payments/offline-psp-valid+public-settlement/valid-offline-finality";
const COMMERCE_TRANSACTION_TRUST_MARKET_SOURCE: &str = "trust-market/valid-marketplace-context";
const DISCLOSURE_AGENT_WEB_FIXTURE_ID: &str = "disclosure-and-agent-web-envelope";
const DISCLOSURE_AGENT_WEB_FIXTURE_SOURCE: &str =
    "generated:disclosure-lineage/valid-lineage-ledger+agent-web/valid-webhook-cloudevents";
const RECURSIVE_RUNTIME_SWARM_FIXTURE_ID: &str = "recursive-runtime-swarm";
const RUNTIME_SWARM_LOOPBACK_NOW_UNIX_MS: u64 = 1_800_000_001_000;
const DISCLOSURE_LINEAGE_SIGNATURE_SEED: [u8; 32] = [29; 32];
const COMMERCE_PROVIDER_TRUST_SIGNATURE_SEED: [u8; 32] = [8; 32];
const TRUST_MARKET_AUTHORITY_SIGNATURE_SEED: [u8; 32] = [59; 32];
const ENTERPRISE_RISK_COMPTROLLER_SIGNATURE_SEED: [u8; 32] = [63; 32];
const PUBLIC_SETTLEMENT_BUNDLE_SIGNATURE_SEED: [u8; 32] = [9; 32];
const PUBLIC_SETTLEMENT_BUNDLE_SIGNATURE_ALGORITHM: &str = "ed25519-rfc8785-v1";
const PUBLIC_SETTLEMENT_ORACLE_SIGNATURE_SEED: [u8; 32] = [15; 32];
const PUBLIC_SETTLEMENT_ANCHOR_SIGNATURE_SEED: [u8; 32] = [7; 32];
const PUBLIC_SETTLEMENT_OPERATOR_KEY_HASH: &str =
    "0x0791868d8f29ea735f26a17a9aea038cd4255baac26eac5a74e58a07ed2f1975";
const PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON";
const PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL";
const PUBLIC_SETTLEMENT_ANCHOR_PROOF_BUNDLE_PATH: &str = "anchor-proof-bundle.json";
const CHIO_ANCHOR_PROOF_BUNDLE_SCHEMA: &str = "chio.anchor-proof-bundle.v1";
const SOLANA_MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const PUBLIC_SETTLEMENT_REORGED_INDEPENDENT_CHAIN_HEAD_JSON: &str =
    "{\"chain_id\":\"eip155:8453\",\"observed_block_number\":12345678,\"observed_block_hash\":\"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"latest_block_number\":12345701}";
const CHIO_WEB3_CONTRACT_PACKAGE_PATH: &str = "docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json";
const RUNTIME_TOOL_SERVER_SIGNATURE_SEED: [u8; 32] = [45; 32];
const RUNTIME_JOIN_RECEIPT_SIGNATURE_SEED: [u8; 32] = [46; 32];
const DISCLOSURE_AGENT_WEB_BBS_KEY_MATERIAL: &[u8] = b"chio-proof-disclosure-agent-web-bbs-key";
const DISCLOSURE_AGENT_WEB_BBS_KEY_INFO: &[u8] = b"chio-proof-disclosure-agent-web";
const DISCLOSURE_AGENT_WEB_BBS_NONCE: &[u8] = b"nonce-disclosure-agent-web";
const DISCLOSURE_NEGATIVE_CASES: &[(&str, &str)] = &[
    (
        "forbidden-disclosed-field",
        "disclosure-lineage-forbidden-disclosed-field",
    ),
    (
        "undeclared-hidden-predicate",
        "disclosure-lineage-undeclared-hidden-predicate",
    ),
    (
        "projection-manifest-id-mismatch",
        "disclosure-lineage-projection-manifest-id-mismatch",
    ),
    (
        "privacy-profile-not-bound-to-transaction",
        "disclosure-lineage-privacy-profile-not-bound-to-transaction",
    ),
    ("nonce-replay", "disclosure-lineage-nonce-replay"),
];
const DISCLOSURE_DERIVED_LEAKAGE_FACTS: &[(&str, &str)] = &[
    ("derived.crypto.issuer_status", "runtime_assurance"),
    ("derived.crypto.revocation_freshness", "runtime_assurance"),
    ("derived.crypto.presentation_timing", "timing"),
];
const RUNTIME_SWARM_LOOPBACK_SCENARIO: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../examples/chio-3vendor/fixtures/runtime-spine/scenario.json"
));
const RUNTIME_SWARM_LOOPBACK_ARTIFACTS: &[(&str, &str)] = &[
    ("proof-package.json", "runtime-proof-package"),
    ("verifier-report.json", "runtime-verifier-report"),
    (
        "verifier-trust-bundle.json",
        "runtime-verifier-trust-bundle",
    ),
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
    #[serde(default)]
    verifier_context: ProofFixtureVerifierContext,
}

#[derive(Default, serde::Deserialize, serde::Serialize)]
struct ProofFixtureVerifierContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_settlement_independent_chain_head: Option<PublicSettlementIndependentChainHeadContext>,
}

#[derive(Clone, Copy, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum PublicSettlementIndependentChainHeadContext {
    Missing,
    BlockHashMismatch,
}

struct EnvVarOverride {
    name: &'static str,
    previous: Option<OsString>,
}

impl EnvVarOverride {
    fn remove(name: &'static str) -> Self {
        let previous = std::env::var_os(name);
        std::env::remove_var(name);
        Self { name, previous }
    }

    fn set(name: &'static str, value: &'static str) -> Self {
        let previous = std::env::var_os(name);
        std::env::set_var(name, value);
        Self { name, previous }
    }
}

impl Drop for EnvVarOverride {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => std::env::set_var(self.name, value),
            None => std::env::remove_var(self.name),
        }
    }
}

impl ProofFixtureVerifierContext {
    fn apply(&self) -> Vec<EnvVarOverride> {
        match self.public_settlement_independent_chain_head {
            Some(PublicSettlementIndependentChainHeadContext::Missing) => vec![
                EnvVarOverride::remove(PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON_ENV),
                EnvVarOverride::remove(PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV),
            ],
            Some(PublicSettlementIndependentChainHeadContext::BlockHashMismatch) => vec![
                EnvVarOverride::set(
                    PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON_ENV,
                    PUBLIC_SETTLEMENT_REORGED_INDEPENDENT_CHAIN_HEAD_JSON,
                ),
                EnvVarOverride::remove(PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV),
            ],
            None => Vec::new(),
        }
    }
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

#[derive(serde::Serialize)]
struct ProofFixtureCheckpointStatementBody {
    schema: String,
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    tree_size: u64,
    merkle_root: chio_web3::hashing::Hash,
    issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_checkpoint_sha256: Option<String>,
    kernel_key: chio_core_types::PublicKey,
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

fn generate_proof_fixture(fixture_id: &str, out: &Path, json_output: bool) -> Result<(), CliError> {
    let descriptor = proof_fixture(fixture_id)?;
    if descriptor.id == COMMERCE_TRANSACTION_PASSPORT_FIXTURE_ID {
        generate_commerce_transaction_passport_fixture(out)?;
    } else if descriptor.id == DISCLOSURE_AGENT_WEB_FIXTURE_ID {
        generate_disclosure_agent_web_fixture(out)?;
    } else if descriptor.id == RECURSIVE_RUNTIME_SWARM_FIXTURE_ID {
        generate_recursive_runtime_swarm_fixture(out)?;
    } else if let Some((case, _id)) = disclosure_negative_case_for_descriptor(&descriptor) {
        copy_disclosure_negative_fixture(case, out)?;
    } else if let Some(root) = installed_fixture_root() {
        let source = installed_fixture_source(&root, &descriptor)?;
        copy_dir_contents(&source, out)?;
    } else {
        copy_embedded_fixture(installed_fixture_path(&descriptor), out)?;
    }
    if descriptor.kind == "transaction-passport" || descriptor.kind == "negative-transaction-passport"
    {
        remove_generated_negative_catalog(out)?;
    }
    normalize_enterprise_risk_lifecycle_replay(&descriptor, out)?;
    normalize_enterprise_claim_payout_capital_instructions(&descriptor, out)?;
    normalize_enterprise_preobserved_capital_instruction(&descriptor, out)?;
    normalize_public_settlement_deployment_provenance(&descriptor, out)?;
    normalize_enterprise_disclosure_projection_ref(&descriptor, out)?;
    normalize_enterprise_export_verifier_report_ref(&descriptor, out)?;
    normalize_enterprise_telemetry_passport_mismatch(&descriptor, out)?;
    normalize_disclosure_lineage_bbs_material(&descriptor, out)?;
    normalize_runtime_join_receipt_signature(&descriptor, out)?;
    normalize_runtime_reused_nonce_fixture(&descriptor, out)?;
    normalize_agent_web_fixture_material(&descriptor, out)?;
    normalize_commerce_mandate_projection_edges(out)?;
    normalize_commerce_order_passport_binding(&descriptor, out)?;
    normalize_declared_evidence_graph_node_ids(&descriptor, out)?;
    if descriptor.kind != "negative-transaction-passport" {
        refresh_proof_room_bundle_source_reports(out)?;
    }
    refresh_proof_room_bundle_manifests(out)?;
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

fn normalize_declared_evidence_graph_node_ids(
    descriptor: &ProofFixtureDescriptor,
    out: &Path,
) -> Result<(), CliError> {
    let mut evidence_graph_paths = Vec::new();
    collect_evidence_graph_paths(out, &mut evidence_graph_paths)?;
    for evidence_graph_path in evidence_graph_paths {
        let mut evidence_graph = read_json_value(&evidence_graph_path)?;
        let artifact_root = evidence_graph_artifact_root(&evidence_graph_path)?;
        refresh_graph_node_hashes(&artifact_root, &mut evidence_graph)?;
        write_json_line_file(&evidence_graph_path, &evidence_graph)?;
        let passport_path = evidence_graph_path.with_file_name("transaction-passport.json");
        if passport_path.is_file()
            && !preserves_evidence_graph_digest_mismatch(
                descriptor,
                out,
                &evidence_graph_path,
            )
        {
            let mut passport = read_json_value(&passport_path)?;
            passport["evidence_graph_sha256"] =
                serde_json::Value::String(sha256_file(&evidence_graph_path)?);
            write_fixture_signed_transaction_passport(&passport_path, passport)?;
        }
    }
    Ok(())
}

fn normalize_commerce_mandate_projection_edges(out: &Path) -> Result<(), CliError> {
    let mut evidence_graph_paths = Vec::new();
    collect_evidence_graph_paths(out, &mut evidence_graph_paths)?;
    for evidence_graph_path in evidence_graph_paths {
        let mut evidence_graph = read_json_value(&evidence_graph_path)?;
        let Some(mandate_id) = graph_node_primary_id_by_path(
            &evidence_graph,
            &evidence_graph_path,
            "mandate-allowance-ledger.json",
        )?
        else {
            continue;
        };
        let Some(chio_projection_id) = graph_node_primary_id_by_path(
            &evidence_graph,
            &evidence_graph_path,
            "protocol-payloads/chio-authority-projection.json",
        )?
        else {
            continue;
        };
        upsert_fixture_graph_edge(
            json_array_mut(&mut evidence_graph, "edges", &evidence_graph_path)?,
            &mandate_id,
            &chio_projection_id,
            "projects-to",
        );
        write_json_line_file(&evidence_graph_path, &evidence_graph)?;
    }
    Ok(())
}

fn evidence_graph_artifact_root(evidence_graph_path: &Path) -> Result<PathBuf, CliError> {
    let graph_dir = evidence_graph_path.parent().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "proof fixture evidence graph has no parent: {}",
            evidence_graph_path.display()
        ))
    })?;
    if graph_dir.file_name().and_then(|name| name.to_str()) == Some("roots") {
        return graph_dir.parent().map(Path::to_path_buf).ok_or_else(|| {
            CliError::cli_other_error(format!(
                "proof fixture roots evidence graph has no bundle parent: {}",
                evidence_graph_path.display()
            ))
        });
    }
    Ok(graph_dir.to_path_buf())
}

fn collect_evidence_graph_paths(root: &Path, paths: &mut Vec<PathBuf>) -> Result<(), CliError> {
    if !root.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_evidence_graph_paths(&path, paths)?;
        } else if file_type.is_file()
            && path.file_name().and_then(|name| name.to_str()) == Some("evidence-graph.json")
        {
            paths.push(path);
        }
    }
    Ok(())
}

fn preserves_evidence_graph_digest_mismatch(
    descriptor: &ProofFixtureDescriptor,
    out: &Path,
    evidence_graph_path: &Path,
) -> bool {
    if descriptor.id.ends_with("evidence-graph-digest-mismatch") {
        return true;
    }
    evidence_graph_path
        .strip_prefix(out)
        .ok()
        .is_some_and(|relative_path| {
            relative_path.components().any(|component| {
                component.as_os_str() == "evidence-graph-digest-mismatch"
            })
        })
}

fn refresh_proof_room_bundle_manifests(root: &Path) -> Result<(), CliError> {
    let mut manifest_paths = Vec::new();
    collect_named_file_paths(root, "manifest.json", &mut manifest_paths)?;
    for manifest_path in manifest_paths {
        refresh_proof_room_bundle_manifest(&manifest_path)?;
    }
    Ok(())
}

fn remove_generated_negative_catalog(root: &Path) -> Result<(), CliError> {
    let catalog = root.join("negatives/catalog");
    if catalog.exists() {
        fs::remove_dir_all(catalog)?;
    }
    Ok(())
}

fn refresh_proof_room_bundle_source_reports(root: &Path) -> Result<(), CliError> {
    let mut manifest_paths = Vec::new();
    collect_named_file_paths(root, "manifest.json", &mut manifest_paths)?;
    for manifest_path in manifest_paths {
        let bundle = manifest_path.parent().ok_or_else(|| {
            CliError::cli_other_error(format!(
                "proof room manifest has no bundle directory: {}",
                manifest_path.display()
            ))
        })?;
        refresh_proof_room_bundle_source_report(bundle)?;
    }
    Ok(())
}

fn refresh_proof_room_bundle_source_report(bundle: &Path) -> Result<(), CliError> {
    let passport_path = bundle.join("roots/transaction-passport.json");
    let verifier_report_path = bundle.join("verifier/report.json");
    if !passport_path.is_file() || !verifier_report_path.is_file() {
        return Ok(());
    }

    let report = verify_transaction_passport_file(&passport_path)?;
    write_json_line_file(&verifier_report_path, &report)?;
    refresh_proof_room_ui_report_source_ref(bundle, &verifier_report_path)
}

fn refresh_proof_room_ui_report_source_ref(
    bundle: &Path,
    verifier_report_path: &Path,
) -> Result<(), CliError> {
    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    if !ui_report_path.is_file() {
        return Ok(());
    }
    let mut ui_report = read_json_value(&ui_report_path)?;
    ui_report["source_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(sha256_file(verifier_report_path)?);
    write_json_line_file(&ui_report_path, &ui_report)
}

fn collect_named_file_paths(
    root: &Path,
    file_name: &str,
    paths: &mut Vec<PathBuf>,
) -> Result<(), CliError> {
    if !root.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_named_file_paths(&path, file_name, paths)?;
        } else if file_type.is_file()
            && path.file_name().and_then(|name| name.to_str()) == Some(file_name)
        {
            paths.push(path);
        }
    }
    Ok(())
}

fn refresh_proof_room_bundle_manifest(manifest_path: &Path) -> Result<(), CliError> {
    let bundle = manifest_path.parent().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "proof room manifest has no bundle directory: {}",
            manifest_path.display()
        ))
    })?;
    let mut manifest = read_json_value(manifest_path)?;
    let original_manifest = manifest.clone();
    for field in [
        "transaction_passport_ref",
        "evidence_graph_ref",
        "verifier_report_ref",
        "proof_room_verifier_report_ref",
    ] {
        refresh_manifest_artifact_ref(bundle, &mut manifest[field])?;
    }
    if let Some(artifacts) = manifest
        .get_mut("artifacts")
        .and_then(serde_json::Value::as_array_mut)
    {
        for artifact in artifacts {
            refresh_manifest_artifact_ref(bundle, artifact)?;
        }
    }
    if manifest != original_manifest {
        write_json_line_file(manifest_path, &manifest)?;
    }
    refresh_proof_room_bundle_signature_if_stale(bundle)
}

fn refresh_proof_room_bundle_signature_if_stale(bundle: &Path) -> Result<(), CliError> {
    let signature_path = bundle.join("bundle-signature.dsse.json");
    if signature_path.is_file() {
        let signature = read_json_value(&signature_path)?;
        let expected_sha256 = sha256_file(&bundle.join("manifest.json"))?;
        let actual_sha256 = signature
            .get("payloadRef")
            .and_then(|payload_ref| payload_ref.get("sha256"))
            .and_then(serde_json::Value::as_str);
        if actual_sha256 == Some(expected_sha256.as_str()) {
            return Ok(());
        }
        let keypair = collect::proof_collect_bundle_signer_from_env()?;
        collect::write_bundle_signature(bundle, &keypair)?;
    }
    Ok(())
}

fn refresh_manifest_artifact_ref(
    bundle: &Path,
    artifact_ref: &mut serde_json::Value,
) -> Result<(), CliError> {
    let Some(path) = artifact_ref
        .get("path")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
    else {
        return Ok(());
    };
    let artifact_path = bundle.join(&path);
    if !artifact_path.is_file() {
        return Ok(());
    }
    artifact_ref["sha256"] = serde_json::Value::String(sha256_file(&artifact_path)?);
    Ok(())
}

fn normalize_runtime_reused_nonce_fixture(
    _descriptor: &ProofFixtureDescriptor,
    out: &Path,
) -> Result<(), CliError> {
    let mut evidence_graph_paths = Vec::new();
    collect_evidence_graph_paths(out, &mut evidence_graph_paths)?;
    for evidence_graph_path in evidence_graph_paths {
        let Some(bundle) = evidence_graph_path.parent() else {
            continue;
        };
        if !bundle.join("tool-server-ack.json").is_file() {
            continue;
        }
        let evidence_graph = read_json_value(&evidence_graph_path)?;
        let has_replay_node = json_array(&evidence_graph, "nodes", &evidence_graph_path)?
            .iter()
            .any(|node| {
                node.get("path").and_then(serde_json::Value::as_str)
                    == Some("tool-server-ack-replay.json")
                    || node.get("id").and_then(serde_json::Value::as_str)
                        == Some("ack-runtime-replay")
            });
        let is_reused_nonce_case = evidence_graph_path.components().any(|component| {
            component.as_os_str() == std::ffi::OsStr::new("runtime-reused-nonce")
                || component.as_os_str() == std::ffi::OsStr::new("reused-nonce")
        });
        if has_replay_node || is_reused_nonce_case {
            normalize_runtime_reused_nonce_bundle(bundle, &evidence_graph_path, evidence_graph)?;
        }
    }
    Ok(())
}

fn normalize_runtime_join_receipt_signature(
    descriptor: &ProofFixtureDescriptor,
    out: &Path,
) -> Result<(), CliError> {
    if !installed_fixture_path(descriptor).starts_with("runtime-security/") {
        return Ok(());
    }
    let join_receipt_path = out.join("join-receipt.json");
    if !join_receipt_path.is_file() {
        return Ok(());
    }
    let mut join_receipt = read_json_value(&join_receipt_path)?;
    if join_receipt
        .get("schema")
        .and_then(serde_json::Value::as_str)
        != Some("chio.swarm.join-receipt.v1")
    {
        return Ok(());
    }
    sign_runtime_join_receipt(&mut join_receipt)?;
    write_json_line_file(&join_receipt_path, &join_receipt)
}

fn sign_runtime_join_receipt(join_receipt: &mut serde_json::Value) -> Result<(), CliError> {
    let keypair = Keypair::from_seed(&RUNTIME_JOIN_RECEIPT_SIGNATURE_SEED);
    let public_key = keypair.public_key().to_hex();
    join_receipt["issuer"] = serde_json::Value::String(format!("did:chio:{public_key}"));
    let signature = runtime_join_receipt_signature(join_receipt, &keypair)?;
    join_receipt["signature"] = serde_json::Value::String(signature);
    Ok(())
}

fn runtime_join_receipt_signature(
    join_receipt: &serde_json::Value,
    keypair: &Keypair,
) -> Result<String, CliError> {
    let mut body = join_receipt.clone();
    let object = body.as_object_mut().ok_or_else(|| {
        CliError::cli_other_error("runtime join receipt signature body invalid".to_string())
    })?;
    object.remove("signature");
    Ok(keypair
        .sign_canonical(&body)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "runtime join receipt signing failed: {error}"
            ))
        })?
        .0
        .to_hex())
}

fn normalize_runtime_reused_nonce_bundle(
    bundle: &Path,
    evidence_graph_path: &Path,
    mut evidence_graph: serde_json::Value,
) -> Result<(), CliError> {
    let source_ack_path = bundle.join("tool-server-ack.json");
    let replay_ack_path = bundle.join("tool-server-ack-replay.json");
    let mut replay_ack = read_json_value(&source_ack_path)?;
    replay_ack["ack_id"] = serde_json::Value::String("ack-runtime-replay".to_string());
    replay_ack["issued_at"] = serde_json::Value::String("2026-06-10T00:00:03Z".to_string());
    replay_ack["signature"] =
        serde_json::Value::String(sign_runtime_tool_server_ack(&replay_ack)?);
    write_json_line_file(&replay_ack_path, &replay_ack)?;

    let replay_sha256 = sha256_file(&replay_ack_path)?;
    let nodes = json_array_mut(&mut evidence_graph, "nodes", evidence_graph_path)?;
    let replay_node = if let Some(index) = nodes.iter().position(|node| {
        node.get("path").and_then(serde_json::Value::as_str)
            == Some("tool-server-ack-replay.json")
            || node.get("id").and_then(serde_json::Value::as_str) == Some("ack-runtime-replay")
    }) {
        &mut nodes[index]
    } else {
        nodes.push(serde_json::json!({
            "id": replay_sha256,
            "path": "tool-server-ack-replay.json",
            "role": "tool-server-ack",
            "schema": "chio.runtime.tool-server-ack.v1",
            "sha256": replay_sha256
        }));
        nodes
            .last_mut()
            .ok_or_else(|| CliError::cli_other_error("runtime replay ack node missing".to_string()))?
    };
    let old_id = replay_node
        .get("id")
        .and_then(serde_json::Value::as_str)
        .map(std::string::ToString::to_string);
    let old_sha256 = replay_node
        .get("sha256")
        .and_then(serde_json::Value::as_str)
        .map(std::string::ToString::to_string);
    replay_node["id"] = serde_json::Value::String(replay_sha256.clone());
    replay_node["path"] = serde_json::Value::String("tool-server-ack-replay.json".to_string());
    replay_node["sha256"] = serde_json::Value::String(replay_sha256.clone());
    for edge in json_array_mut(&mut evidence_graph, "edges", evidence_graph_path)? {
        for field in ["from", "to"] {
            let Some(current) = edge.get(field).and_then(serde_json::Value::as_str) else {
                continue;
            };
            if old_id.as_deref() == Some(current) || old_sha256.as_deref() == Some(current) {
                edge[field] = serde_json::Value::String(replay_sha256.clone());
            }
        }
    }
    write_json_line_file(evidence_graph_path, &evidence_graph)?;
    Ok(())
}

fn sign_runtime_tool_server_ack(ack: &serde_json::Value) -> Result<String, CliError> {
    let keypair = Keypair::from_seed(&RUNTIME_TOOL_SERVER_SIGNATURE_SEED);
    let body = serde_json::json!({
        "schema": "chio.runtime.tool-server-ack-signature.v1",
        "ackId": ack["ack_id"],
        "leaseId": ack["lease_id"],
        "toolServerId": ack["tool_server_id"],
        "toolInstanceId": ack["tool_instance_id"],
        "sandboxAttestationRef": ack["sandbox_attestation_ref"],
        "nonce": ack["nonce"],
        "terminalStatus": ack["terminal_status"],
        "issuedAt": ack["issued_at"],
    });
    Ok(keypair
        .sign_canonical(&body)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "runtime tool-server acknowledgement signing failed: {error}"
            ))
        })?
        .0
        .to_hex())
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
    let negative_case = proof_fixture_negative_case(descriptor)?;
    let expected_failure = negative_case.expected_failure_code;
    let _env_overrides = negative_case.verifier_context.apply();
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

pub(super) fn proof_fixture_negative_verifier_context(
    descriptor: &ProofFixtureDescriptor,
) -> Result<Option<serde_json::Value>, CliError> {
    let negative_case = proof_fixture_negative_case(descriptor)?;
    let value = serde_json::to_value(negative_case.verifier_context).map_err(CliError::from)?;
    if value
        .as_object()
        .is_some_and(|object| !object.is_empty())
    {
        Ok(Some(value))
    } else {
        Ok(None)
    }
}

pub(super) fn with_proof_fixture_negative_verifier_context<T>(
    descriptor: &ProofFixtureDescriptor,
    f: impl FnOnce() -> Result<T, CliError>,
) -> Result<T, CliError> {
    let negative_case = proof_fixture_negative_case(descriptor)?;
    let _env_overrides = negative_case.verifier_context.apply();
    f()
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
    let negative_case: ProofFixtureNegativeCase =
        serde_json::from_slice(&raw).map_err(|error| {
            CliError::cli_other_error(format!(
                "invalid negative proof fixture metadata for {}: {}",
                descriptor.id, error
            ))
        })?;
    Ok(negative_case)
}

fn negative_fixture_metadata_path(
    descriptor: &ProofFixtureDescriptor,
) -> Result<PathBuf, CliError> {
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
        "proof-room" => Some(out.join("verifier-report.json")),
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
    if descriptor.id == SINGLE_CALL_AUTHORITY_FIXTURE_ID {
        let valid_passport = proof_fixture_source_root()
            .join("minimal-passport/valid/transaction-passport.json");
        let report = verify_transaction_passport_file(&valid_passport)?;
        write_json_line_file(verifier_report_path, &report)?;
        return Ok(());
    }
    if descriptor.kind == "proof-room" {
        let source_report_path = out.join("proof-room-bundle/verifier/report.json");
        if source_report_path.is_file() {
            fs::copy(source_report_path, verifier_report_path)?;
        }
        return Ok(());
    }
    if descriptor.kind != "negative-disclosure-crypto-context" {
        return Ok(());
    }
    let context_path = out.join("verification-context.json");
    let context_bytes = fs::read(&context_path)?;
    let proof_bytes = fs::read(out.join("selective-disclosure-proof.json"))?;
    let privacy_profile_bytes = fs::read(out.join("verifier-privacy-profile.json"))?;
    let report_bytes = chio_proof_room::crypto_context_rejected_report_bytes_with_bbs(
        &context_bytes,
        &proof_bytes,
        &privacy_profile_bytes,
        &descriptor.id,
    )
    .map_err(CliError::cli_other_error)?;
    fs::write(verifier_report_path, report_bytes)?;
    Ok(())
}

fn proof_fixture(fixture_id: &str) -> Result<ProofFixtureDescriptor, CliError> {
    proof_fixtures()?
        .into_iter()
        .find(|fixture| fixture.id == fixture_id)
        .ok_or_else(|| CliError::cli_other_error(format!("unknown proof fixture id: {fixture_id}")))
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
        description:
            "Generated Proof Room bundle for disclosure lineage and Agent Web envelope evidence"
                .to_string(),
    }
}

pub(super) fn copy_proof_fixture(fixture_id: &str, out: &Path) -> Result<(), CliError> {
    let descriptor = proof_fixture(fixture_id)?;
    if let Some((case, _id)) = disclosure_negative_case_for_descriptor(&descriptor) {
        copy_disclosure_negative_fixture(case, out)?;
        return Ok(());
    }
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
        copy_dir_contents(&source, out)?;
    } else {
        copy_embedded_fixture(installed_fixture_path(&descriptor), out)?;
    }
    normalize_enterprise_risk_lifecycle_replay(&descriptor, out)?;
    normalize_enterprise_claim_payout_capital_instructions(&descriptor, out)?;
    normalize_enterprise_preobserved_capital_instruction(&descriptor, out)?;
    normalize_public_settlement_deployment_provenance(&descriptor, out)?;
    normalize_enterprise_disclosure_projection_ref(&descriptor, out)?;
    normalize_enterprise_export_verifier_report_ref(&descriptor, out)?;
    normalize_enterprise_telemetry_passport_mismatch(&descriptor, out)?;
    normalize_disclosure_lineage_bbs_material(&descriptor, out)?;
    normalize_runtime_join_receipt_signature(&descriptor, out)?;
    normalize_runtime_reused_nonce_fixture(&descriptor, out)?;
    normalize_agent_web_fixture_material(&descriptor, out)?;
    normalize_commerce_mandate_projection_edges(out)?;
    normalize_commerce_order_passport_binding(&descriptor, out)?;
    normalize_declared_evidence_graph_node_ids(&descriptor, out)?;
    if descriptor.kind != "negative-transaction-passport" {
        refresh_proof_room_bundle_source_reports(out)?;
    }
    refresh_proof_room_bundle_manifests(out)?;
    Ok(())
}

fn disclosure_negative_case_for_descriptor(
    descriptor: &ProofFixtureDescriptor,
) -> Option<(&'static str, &'static str)> {
    DISCLOSURE_NEGATIVE_CASES
        .iter()
        .copied()
        .find(|(_case, id)| descriptor.id == *id)
}

pub(super) fn is_generated_disclosure_negative_fixture_id(fixture_id: &str) -> bool {
    DISCLOSURE_NEGATIVE_CASES
        .iter()
        .any(|(_case, id)| fixture_id == *id)
}

fn copy_disclosure_negative_fixture(case: &str, out: &Path) -> Result<(), CliError> {
    if path_exists_or_is_symlink(out)? {
        return Err(CliError::cli_other_error(format!(
            "proof output directory already exists: {}",
            out.display()
        )));
    }
    let source = proof_fixture_source_root().join("disclosure-lineage/valid-lineage-ledger");
    copy_dir_contents(&source, out)?;
    strip_collected_bundle_outputs(out)?;
    normalize_disclosure_lineage_bbs_material_for_bundle(out)?;
    apply_disclosure_negative_case(out, case)?;
    sync_transaction_root_artifacts(out)?;
    Ok(())
}

fn apply_disclosure_negative_case(bundle: &Path, case: &str) -> Result<(), CliError> {
    match case {
        "forbidden-disclosed-field" => {
            let path = bundle.join("privacy-profile.json");
            let mut profile = read_json_value(&path)?;
            append_unique_json_strings(
                &mut profile,
                "forbidden_disclosed_fields",
                &["tool_name".to_string()],
            )?;
            write_json_line_file(&path, &profile)?;
            refresh_disclosure_negative_graph_and_passport(bundle)
        }
        "undeclared-hidden-predicate" => {
            let path = bundle.join("bbs-projection-manifest.json");
            let mut manifest = read_json_value(&path)?;
            manifest["hidden_predicates"] = serde_json::Value::Array(Vec::new());
            write_json_line_file(&path, &manifest)?;
            refresh_disclosure_negative_graph_and_passport(bundle)
        }
        "projection-manifest-id-mismatch" => {
            let capsule_path = bundle.join("capsule.json");
            let mut capsule = read_json_value(&capsule_path)?;
            capsule["projection_manifest_ref"] =
                serde_json::Value::String("chio.bbs-projection.other.v1".to_string());
            write_json_line_file(&capsule_path, &capsule)?;

            let report_path = bundle.join("crypto-context-report.json");
            let mut report = read_json_value(&report_path)?;
            report["projection_manifest_ref"] =
                serde_json::Value::String("chio.bbs-projection.other.v1".to_string());
            sign_disclosure_crypto_report_json(&mut report)?;
            write_json_line_file(&report_path, &report)?;
            refresh_disclosure_negative_graph_and_passport(bundle)
        }
        "privacy-profile-not-bound-to-transaction" => {
            let path = bundle.join("privacy-profile.json");
            let mut profile = read_json_value(&path)?;
            profile["transaction_passport_ref"] =
                serde_json::Value::String("passport-disclosure-other".to_string());
            write_json_line_file(&path, &profile)?;
            refresh_disclosure_negative_graph_and_passport(bundle)
        }
        "nonce-replay" => {
            let context_path = bundle.join("verification-context.json");
            let mut context = read_json_value(&context_path)?;
            context["nonce_replay_status"] = serde_json::Value::String("replayed".to_string());
            write_json_line_file(&context_path, &context)?;
            refresh_disclosure_negative_graph_and_passport(bundle)
        }
        _ => Err(CliError::cli_other_error(format!(
            "unknown disclosure negative fixture case: {case}"
        ))),
    }
}

fn normalize_disclosure_lineage_bbs_material_for_bundle(bundle: &Path) -> Result<(), CliError> {
    if bundle.join("capsule.json").is_file() && bundle.join("crypto-context-report.json").is_file()
    {
        add_disclosure_bbs_material_to_bundle_with_fixture_signer(bundle)?;
    }
    Ok(())
}

fn add_disclosure_bbs_material_to_bundle_with_fixture_signer(bundle: &Path) -> Result<(), CliError> {
    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph = read_json_value(&evidence_graph_path)?;
    add_disclosure_agent_web_crypto_context_material(bundle, &mut evidence_graph)?;
    refresh_signed_lineage_subgraph_digest(bundle)?;
    refresh_graph_node_hashes(bundle, &mut evidence_graph)?;
    write_json_line_file(&evidence_graph_path, &evidence_graph)?;
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport = read_json_value(&passport_path)?;
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    write_fixture_signed_transaction_passport(&passport_path, passport)?;
    sync_transaction_root_artifacts(bundle)?;
    Ok(())
}

fn refresh_disclosure_negative_graph_and_passport(bundle: &Path) -> Result<(), CliError> {
    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph = read_json_value(&evidence_graph_path)?;
    refresh_graph_node_hashes(bundle, &mut evidence_graph)?;
    write_json_line_file(&evidence_graph_path, &evidence_graph)?;
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;
    let passport_path = bundle.join("transaction-passport.json");
    let mut passport = read_json_value(&passport_path)?;
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    write_fixture_signed_transaction_passport(&passport_path, passport)
}

fn sign_disclosure_crypto_report_json(report: &mut serde_json::Value) -> Result<(), CliError> {
    report["signature"] = serde_json::Value::Null;
    let mut typed_report: chio_selective_disclosure::DisclosureCryptoContextReport =
        serde_json::from_value(report.clone()).map_err(|error| {
            CliError::cli_other_error(format!(
                "proof fixture crypto context report parse failed: {error}"
            ))
        })?;
    typed_report.signature = Some(
        chio_selective_disclosure::sign_crypto_context_report(
            &typed_report,
            &Keypair::from_seed(&DISCLOSURE_LINEAGE_SIGNATURE_SEED),
        )
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "proof fixture crypto context report signing failed: {error}"
            ))
        })?,
    );
    *report = serde_json::to_value(typed_report).map_err(CliError::from)?;
    Ok(())
}

fn normalize_agent_web_fixture_material(
    descriptor: &ProofFixtureDescriptor,
    out: &Path,
) -> Result<(), CliError> {
    if !path_has_component(Path::new(installed_fixture_path(descriptor)), "agent-web") {
        return Ok(());
    }
    if descriptor.id == "agent-web-external-digest-mismatch" {
        return Ok(());
    }
    let mut evidence_graph_paths = Vec::new();
    collect_evidence_graph_paths(out, &mut evidence_graph_paths)?;
    for evidence_graph_path in evidence_graph_paths {
        let artifact_root = evidence_graph_artifact_root(&evidence_graph_path)?;
        if path_has_component(&artifact_root, "agent-web-external-digest-mismatch") {
            continue;
        }
        let verifier_policy_path = artifact_root.join("verifier-policy.json");
        if !verifier_policy_path.is_file() {
            continue;
        }

        let policy_sha256 = sha256_file(&verifier_policy_path)?;
        let mut evidence_graph = read_json_value(&evidence_graph_path)?;
        normalize_agent_web_bilateral_in_toto_statement(&artifact_root)?;
        refresh_agent_web_envelopes_for_subjects(&artifact_root, &mut evidence_graph)?;
        resign_agent_web_receipts_for_policy(&artifact_root, &policy_sha256)?;
        refresh_graph_node_hashes(&artifact_root, &mut evidence_graph)?;
        write_json_line_file(&evidence_graph_path, &evidence_graph)?;

        let passport_path = evidence_graph_path.with_file_name("transaction-passport.json");
        if passport_path.is_file()
            && !preserves_evidence_graph_digest_mismatch(descriptor, out, &evidence_graph_path)
        {
            let mut passport = read_json_value(&passport_path)?;
            passport["evidence_graph_sha256"] =
                serde_json::Value::String(sha256_file(&evidence_graph_path)?);
            passport["verifier_policy_sha256"] = serde_json::Value::String(policy_sha256);
            write_fixture_signed_transaction_passport(&passport_path, passport)?;
        }
    }
    Ok(())
}

fn path_has_component(path: &Path, component: &str) -> bool {
    path.components()
        .any(|path_component| path_component.as_os_str().to_str() == Some(component))
}

fn normalize_disclosure_lineage_bbs_material(
    descriptor: &ProofFixtureDescriptor,
    out: &Path,
) -> Result<(), CliError> {
    if disclosure_negative_case_for_descriptor(descriptor).is_some() {
        return Ok(());
    }
    if descriptor.kind != "transaction-passport"
        && descriptor.kind != "negative-transaction-passport"
    {
        return Ok(());
    }
    if !installed_fixture_path(descriptor).starts_with("disclosure-lineage/") {
        return Ok(());
    }
    if out.join("capsule.json").is_file() && out.join("crypto-context-report.json").is_file() {
        add_disclosure_bbs_material_to_bundle(out)?;
    }
    Ok(())
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
    let trust_market_source = fixture_root.join(COMMERCE_TRANSACTION_TRUST_MARKET_SOURCE);
    let bundle = out.join("proof-room-bundle");
    copy_dir_contents(&commerce_source, &bundle)?;
    strip_collected_bundle_outputs(&bundle)?;
    merge_public_settlement_fixture(&bundle, &settlement_source)?;
    merge_commerce_trust_market_fixture(&bundle, &trust_market_source)?;
    add_commerce_event_authority_receipts(&bundle)?;
    add_commerce_terminal_receipts(&bundle)?;
    normalize_commerce_mandate_projection_edges(&bundle)?;
    refresh_commerce_order_passport_bundle(&bundle)?;
    normalize_declared_evidence_graph_node_ids(&commerce_transaction_passport_fixture_descriptor(), &bundle)?;
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

fn merge_commerce_trust_market_fixture(
    bundle: &Path,
    trust_market_source: &Path,
) -> Result<(), CliError> {
    let order_context_path = bundle.join("order-context.json");
    let mut order_context = read_json_value(&order_context_path)?;
    let order_id = required_json_string(&order_context, "order_id", &order_context_path)?;
    let selected_provider_subject =
        required_json_string(&order_context, "merchant_subject", &order_context_path)?;

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport = read_json_value(&passport_path)?;
    let passport_id = required_json_string(&passport, "id", &passport_path)?;
    let issued_at = required_json_string(&passport, "issued_at", &passport_path)?;

    let policy_path = bundle.join("verifier-policy.json");
    let mut policy = read_json_value(&policy_path)?;
    merge_trust_market_policy_fields(
        &mut policy,
        &trust_market_source.join("verifier-policy.json"),
    )?;
    append_required_claims_from_policy(
        &mut policy,
        &trust_market_source.join("verifier-policy.json"),
    )?;
    write_json_line_file(&policy_path, &policy)?;
    let policy_sha256 = sha256_file(&policy_path)?;

    let trust_market_replacements = [
        ("passport-trust-market-valid", passport_id.as_str()),
        ("order-commerce-001", order_id.as_str()),
        ("did:chio:provider-alpha", selected_provider_subject.as_str()),
    ];
    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph = read_json_value(&evidence_graph_path)?;
    append_graph_artifacts_from_fixture(
        bundle,
        trust_market_source,
        &mut evidence_graph,
        &trust_market_replacements,
    )?;
    resign_trust_market_graph_artifacts(bundle, &evidence_graph)?;

    order_context["trust_market_requirement"] = serde_json::json!({
        "required": true,
        "provider_discovery_snapshot_ref": "discovery-trust-market-valid",
        "provider_selection_report_ref": "selection-trust-market-valid",
        "trust_scorecard_ref": "scorecard-trust-market-valid",
        "reputation_import_ref": "reputation-import-trust-market-valid",
        "sla_commitment_ref": "sla-commitment-trust-market-valid",
        "collateral_position_ref": "collateral-trust-market-valid",
        "guarantee_decision_ref": "guarantee-trust-market-valid",
        "adjudication_jurisdiction_ref": "jurisdiction-trust-market-valid"
    });
    add_commerce_trust_market_evidence_refs_to_event_log(bundle)?;
    order_context["event_log_sha256"] =
        serde_json::Value::String(sha256_file(&bundle.join("event-log.json"))?);
    write_json_line_file(&order_context_path, &order_context)?;

    add_public_stage_settlement_trust_market_refs(bundle, trust_market_source)?;
    let claim_set_sha256 = refresh_claim_set_for_policy(bundle, &passport_id, &issued_at, &policy)?;
    upsert_claim_set_graph_binding(&mut evidence_graph, &claim_set_sha256)?;
    refresh_graph_node_hashes(bundle, &mut evidence_graph)?;
    write_json_line_file(&evidence_graph_path, &evidence_graph)?;
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    passport["claim_set_sha256"] = serde_json::Value::String(claim_set_sha256);
    passport["claim_set_path"] = serde_json::Value::String("claim-set.json".to_string());
    passport["verifier_policy_sha256"] = serde_json::Value::String(policy_sha256);
    write_signed_transaction_passport(&passport_path, passport)?;
    Ok(())
}

fn add_public_stage_settlement_trust_market_refs(
    bundle: &Path,
    trust_market_source: &Path,
) -> Result<(), CliError> {
    let settlement_proof_path = bundle.join("settlement-proof-bundle.json");
    if !settlement_proof_path.is_file() {
        return Ok(());
    }

    let collateral_path = trust_market_source.join("collateral-position-report.json");
    let collateral = read_json_value(&collateral_path)?;
    let guarantee_path = trust_market_source.join("guarantee-decision.json");
    let guarantee = read_json_value(&guarantee_path)?;
    let sla_path = trust_market_source.join("sla-commitment.json");
    let sla = read_json_value(&sla_path)?;

    let mut settlement_proof = read_json_value(&settlement_proof_path)?;
    settlement_proof["collateral_position_ref"] = serde_json::Value::String(
        required_json_string(&collateral, "collateral_id", &collateral_path)?,
    );
    settlement_proof["guarantee_decision_ref"] = serde_json::Value::String(
        required_json_string(&guarantee, "guarantee_id", &guarantee_path)?,
    );
    settlement_proof["sla_remedy_ref"] =
        serde_json::Value::String(required_json_string(&sla, "remedy_policy_ref", &sla_path)?);
    settlement_proof["slash_authority_ref"] = serde_json::Value::String(required_json_string(
        &collateral,
        "slash_authority_ref",
        &collateral_path,
    )?);
    sign_public_settlement_proof_bundle(&mut settlement_proof, &settlement_proof_path)?;
    write_json_line_file(&settlement_proof_path, &settlement_proof)
}

fn normalize_commerce_order_passport_binding(
    descriptor: &ProofFixtureDescriptor,
    out: &Path,
) -> Result<(), CliError> {
    if !out.join("evidence-graph.json").is_file() || !out.join("order-context.json").is_file() {
        return Ok(());
    }
    if descriptor.id == "commerce-offline-psp" {
        strip_collected_bundle_outputs(out)?;
        return refresh_commerce_order_passport_bundle(out);
    }
    if descriptor.kind == "negative-transaction-passport" && descriptor.id.starts_with("commerce-")
    {
        return refresh_commerce_negative_order_passport_binding(out);
    }
    Ok(())
}

fn refresh_commerce_order_passport_bundle(bundle: &Path) -> Result<(), CliError> {
    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph = read_json_value(&evidence_graph_path)?;
    refresh_commerce_order_passport_graph_binding(bundle, &mut evidence_graph)?;
    refresh_graph_node_hashes(bundle, &mut evidence_graph)?;
    write_json_line_file(&evidence_graph_path, &evidence_graph)?;
    let passport_path = bundle.join("transaction-passport.json");
    if passport_path.is_file() {
        let mut passport = read_json_value(&passport_path)?;
        passport["evidence_graph_sha256"] =
            serde_json::Value::String(sha256_file(&evidence_graph_path)?);
        write_fixture_signed_transaction_passport(&passport_path, passport)?;
    }
    Ok(())
}

fn refresh_commerce_negative_order_passport_binding(bundle: &Path) -> Result<(), CliError> {
    let order_passport_path = bundle.join("order-passport.json");
    if !order_passport_path.is_file() {
        let source = proof_fixture_source_root().join(
            "commerce-payments/offline-psp-valid/order-passport.json",
        );
        if source.is_file() {
            fs::copy(source, &order_passport_path)?;
        } else {
            return Ok(());
        }
    }
    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph = read_json_value(&evidence_graph_path)?;
    let order_passport_sha256 = sha256_file(&order_passport_path)?;
    upsert_fixture_graph_node(
        json_array_mut(&mut evidence_graph, "nodes", &evidence_graph_path)?,
        "commerce-order-passport",
        "order-passport.json",
        chio_commerce_order::COMMERCE_ORDER_PASSPORT_SCHEMA_ID,
        "commerce-order-passport",
        &order_passport_sha256,
    );
    refresh_graph_node_hashes(bundle, &mut evidence_graph)?;
    write_json_line_file(&evidence_graph_path, &evidence_graph)?;
    let passport_path = bundle.join("transaction-passport.json");
    if passport_path.is_file() {
        let mut passport = read_json_value(&passport_path)?;
        passport["evidence_graph_sha256"] =
            serde_json::Value::String(sha256_file(&evidence_graph_path)?);
        write_fixture_signed_transaction_passport(&passport_path, passport)?;
    }
    Ok(())
}

fn refresh_commerce_order_passport_graph_binding(
    bundle: &Path,
    evidence_graph: &mut serde_json::Value,
) -> Result<(), CliError> {
    let evidence_graph_bytes = serde_json::to_vec(evidence_graph)?;
    let graph = parse_graph_artifact_paths(&evidence_graph_bytes)?;
    let order_context: chio_commerce_order::CommerceOrderContext =
        load_required_graph_json_artifact(
            bundle,
            &graph.nodes,
            "commerce-order-context",
            chio_commerce_order::COMMERCE_ORDER_CONTEXT_SCHEMA_ID,
            "commerce fixture",
        )?;
    let event_log_bytes = load_required_graph_bytes_artifact_by_path(
        bundle,
        &graph.nodes,
        &order_context.event_log_path,
        chio_commerce_order::COMMERCE_EVENT_LOG_SCHEMA_ID,
        "commerce fixture",
    )?;
    let event_authority_receipts =
        load_commerce_event_authority_receipts(bundle, &graph.nodes, &event_log_bytes)?;
    let payment_lifecycle_bytes = load_required_graph_bytes_artifact_by_path(
        bundle,
        &graph.nodes,
        &order_context.payment_lifecycle_path,
        chio_commerce_order::COMMERCE_PAYMENT_LIFECYCLE_SCHEMA_ID,
        "commerce fixture",
    )?;
    let mandate_ledger_bytes = load_required_graph_bytes_artifact_by_path(
        bundle,
        &graph.nodes,
        &order_context.mandate_ledger_path,
        chio_commerce_order::COMMERCE_MANDATE_ALLOWANCE_LEDGER_SCHEMA_ID,
        "commerce fixture",
    )?;
    let mandate_protocol_payloads =
        load_commerce_mandate_protocol_payloads(bundle, &graph.nodes, &mandate_ledger_bytes)?;
    let provider_passport_bytes = load_required_graph_bytes_artifact_by_path(
        bundle,
        &graph.nodes,
        &order_context.provider_passport_path,
        chio_commerce_order::COMMERCE_PROVIDER_PASSPORT_SCHEMA_ID,
        "commerce fixture",
    )?;
    let reputation_snapshot_bytes = load_required_graph_bytes_artifact_by_path(
        bundle,
        &graph.nodes,
        &order_context.reputation_snapshot_path,
        chio_commerce_order::COMMERCE_REPUTATION_SNAPSHOT_SCHEMA_ID,
        "commerce fixture",
    )?;
    let federation_trust_bundle_bytes = load_required_graph_bytes_artifact_by_path(
        bundle,
        &graph.nodes,
        &order_context.federation_trust_bundle_path,
        chio_commerce_order::COMMERCE_FEDERATION_TRUST_BUNDLE_SCHEMA_ID,
        "commerce fixture",
    )?;
    let settlement_packet_bytes = load_required_graph_bytes_artifact_by_path(
        bundle,
        &graph.nodes,
        &order_context.settlement_packet_path,
        chio_commerce_order::COMMERCE_SETTLEMENT_PACKET_SCHEMA_ID,
        "commerce fixture",
    )?;
    let risk_comptroller_report_bytes = if let Some(requirement) = order_context
        .coverage_requirement
        .as_ref()
        .filter(|requirement| requirement.required)
    {
        Some(load_required_graph_bytes_artifact_by_path(
            bundle,
            &graph.nodes,
            &requirement.risk_comptroller_report_path,
            "chio.risk.comptroller-report.v1",
            "commerce fixture",
        )?)
    } else {
        None
    };
    let commerce_authority_key = Keypair::from_seed(&[7u8; 32]).public_key();
    let report = chio_commerce_order::verify_commerce_order(
        &chio_commerce_order::CommerceOrderVerificationBundle {
            order_context: order_context.clone(),
            event_log_bytes,
            event_authority_receipts,
            payment_lifecycle_bytes,
            mandate_ledger_bytes,
            provider_passport_bytes,
            reputation_snapshot_bytes,
            federation_trust_bundle_bytes,
            settlement_packet_bytes,
            mandate_protocol_payloads,
            risk_comptroller_report_bytes,
            verified_trust_market_context: fixture_commerce_trust_market_context(
                bundle,
                &order_context,
            )?,
            trusted_event_authority_receipt_kernel_keys: vec![commerce_authority_key.clone()],
            trusted_payment_signer_keys: vec![commerce_authority_key],
            trusted_provider_trust_signer_keys: vec![
                Keypair::from_seed(&COMMERCE_PROVIDER_TRUST_SIGNATURE_SEED).public_key(),
            ],
            trusted_risk_comptroller_signer_keys: vec![
                Keypair::from_seed(&ENTERPRISE_RISK_COMPTROLLER_SIGNATURE_SEED).public_key(),
            ],
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "proof fixture commerce order passport generation failed: {error}"
        ))
    })?;
    let order_passport_path = bundle.join("order-passport.json");
    write_json_line_file(&order_passport_path, &serde_json::to_value(report)?)?;
    let order_passport_sha256 = sha256_file(&order_passport_path)?;
    upsert_fixture_graph_node(
        json_array_mut(evidence_graph, "nodes", &bundle.join("evidence-graph.json"))?,
        "commerce-order-passport",
        "order-passport.json",
        chio_commerce_order::COMMERCE_ORDER_PASSPORT_SCHEMA_ID,
        "commerce-order-passport",
        &order_passport_sha256,
    );
    Ok(())
}

fn fixture_commerce_trust_market_context(
    bundle: &Path,
    order_context: &chio_commerce_order::CommerceOrderContext,
) -> Result<Option<chio_commerce_order::CommerceVerifiedTrustMarketContext>, CliError> {
    let Some(requirement) = order_context
        .trust_market_requirement
        .as_ref()
        .filter(|requirement| requirement.required)
    else {
        return Ok(None);
    };
    let risk_comptroller_report_ref =
        optional_json_string(&bundle.join("risk-comptroller-report.json"), "id")?
            .unwrap_or_else(|| "risk-comptroller-market-valid".to_string());
    let selected_provider_subject =
        optional_json_string(&bundle.join("provider-selection-report.json"), "selected_provider_subject")?
            .unwrap_or_else(|| order_context.merchant_subject.clone());
    Ok(Some(
        chio_commerce_order::CommerceVerifiedTrustMarketContext {
            provider_discovery_snapshot_ref: requirement.provider_discovery_snapshot_ref.clone(),
            provider_selection_report_ref: requirement.provider_selection_report_ref.clone(),
            trust_scorecard_ref: requirement.trust_scorecard_ref.clone(),
            reputation_import_ref: requirement.reputation_import_ref.clone(),
            sla_commitment_ref: requirement.sla_commitment_ref.clone(),
            risk_comptroller_report_ref,
            collateral_position_ref: requirement.collateral_position_ref.clone(),
            guarantee_decision_ref: requirement.guarantee_decision_ref.clone(),
            adjudication_jurisdiction_ref: requirement.adjudication_jurisdiction_ref.clone(),
            selected_provider_subject,
        },
    ))
}

fn optional_json_string(path: &Path, field: &str) -> Result<Option<String>, CliError> {
    if !path.is_file() {
        return Ok(None);
    }
    Ok(read_json_value(path)?
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string))
}

fn merge_trust_market_policy_fields(
    policy: &mut serde_json::Value,
    trust_market_policy_path: &Path,
) -> Result<(), CliError> {
    let trust_market_policy = read_json_value(trust_market_policy_path)?;
    for field in [
        "unsupported_claims",
        "max_reputation_import_weight",
        "trusted_market_authority_keys",
    ] {
        if let Some(value) = trust_market_policy.get(field) {
            policy[field] = value.clone();
        }
    }
    Ok(())
}

fn add_commerce_trust_market_evidence_refs_to_event_log(bundle: &Path) -> Result<(), CliError> {
    let event_log_path = bundle.join("event-log.json");
    let mut event_log = read_json_value(&event_log_path)?;
    let events = json_array_mut(&mut event_log, "events", &event_log_path)?;
    for event in events {
        let next_state = required_json_string(event, "next_state", &event_log_path)?;
        let evidence_refs = json_array_mut(event, "evidence_refs", &event_log_path)?;
        if next_state == "provider_admitted" {
            append_unique_evidence_refs(
                evidence_refs,
                &[
                    "discovery-trust-market-valid",
                    "selection-trust-market-valid",
                    "scorecard-trust-market-valid",
                    "reputation-import-trust-market-valid",
                ],
            );
        }
        if is_commerce_settlement_lifecycle_state(&next_state) {
            append_unique_evidence_refs(
                evidence_refs,
                &[
                    "sla-commitment-trust-market-valid",
                    "collateral-trust-market-valid",
                    "guarantee-trust-market-valid",
                    "jurisdiction-trust-market-valid",
                ],
            );
        }
        seal_commerce_event(event)?;
    }
    write_json_line_file(&event_log_path, &event_log)
}

fn append_unique_evidence_refs(values: &mut Vec<serde_json::Value>, refs: &[&str]) {
    for evidence_ref in refs {
        if !values
            .iter()
            .any(|value| value.as_str() == Some(*evidence_ref))
        {
            values.push(serde_json::Value::String((*evidence_ref).to_string()));
        }
    }
}

fn is_commerce_settlement_lifecycle_state(state: &str) -> bool {
    matches!(
        state,
        "settlement_packet_assembled"
            | "settlement_dispatched"
            | "settlement_observed"
            | "settlement_reconciled"
    )
}

fn resign_trust_market_graph_artifacts(
    bundle: &Path,
    evidence_graph: &serde_json::Value,
) -> Result<(), CliError> {
    for node in json_array(evidence_graph, "nodes", &bundle.join("evidence-graph.json"))? {
        let Some(schema) = node.get("schema").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if !is_trust_market_signed_artifact_schema(schema) {
            continue;
        }
        let path = required_json_string(node, "path", &bundle.join("evidence-graph.json"))?;
        let artifact_path = bundle.join(path);
        let mut artifact = read_json_value(&artifact_path)?;
        sign_trust_market_artifact(&mut artifact)?;
        write_json_line_file(&artifact_path, &artifact)?;
    }
    Ok(())
}

fn is_trust_market_signed_artifact_schema(schema: &str) -> bool {
    matches!(
        schema,
        "chio.commerce.provider-discovery-snapshot.v1"
            | "chio.commerce.provider-selection-report.v1"
            | "chio.trust.scorecard-snapshot.v1"
            | "chio.trust.reputation-import-report.v1"
            | "chio.commerce.sla-commitment.v1"
            | "chio.commerce.sla-performance-report.v1"
            | "chio.risk.comptroller-report.v1"
            | "chio.risk.collateral-position-report.v1"
            | "chio.risk.guarantee-decision.v1"
            | "chio.risk.adjudication-jurisdiction-receipt.v1"
    )
}

fn add_commerce_event_authority_receipts(bundle: &Path) -> Result<(), CliError> {
    let event_log_path = bundle.join("event-log.json");
    let event_log = read_json_value(&event_log_path)?;
    let events = event_log
        .get("events")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "commerce event log events missing: {}",
                event_log_path.display()
            ))
        })?;
    let policy_sha256 = sha256_file(&bundle.join("verifier-policy.json"))?;
    let receipt_dir = bundle.join("authority-receipts");
    fs::create_dir_all(&receipt_dir)?;

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph = read_json_value(&evidence_graph_path)?;
    let nodes = json_array_mut(&mut evidence_graph, "nodes", &evidence_graph_path)?;
    for event in events {
        let receipt_ref = event
            .get("authority_receipt_ref")
            .and_then(serde_json::Value::as_str)
            .filter(|receipt_ref| !receipt_ref.is_empty())
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "commerce event missing authority receipt ref: {}",
                    event_log_path.display()
                ))
            })?;
        let receipt_path = format!("authority-receipts/{receipt_ref}.json");
        let destination = bundle.join(&receipt_path);
        write_commerce_event_authority_receipt(&destination, event, &policy_sha256)?;
        upsert_fixture_graph_node(
            nodes,
            receipt_ref,
            &receipt_path,
            "chio.receipt.v1",
            "receipt",
            &sha256_file(&destination)?,
        );
    }
    refresh_graph_node_hashes(bundle, &mut evidence_graph)?;
    write_json_line_file(&evidence_graph_path, &evidence_graph)?;
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport = read_json_value(&passport_path)?;
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    write_signed_transaction_passport(&passport_path, passport)?;
    Ok(())
}

fn write_commerce_event_authority_receipt(
    destination: &Path,
    event: &serde_json::Value,
    policy_sha256: &str,
) -> Result<(), CliError> {
    let receipt_ref = required_event_string(event, "authority_receipt_ref")?;
    let keypair = Keypair::from_seed(&[7u8; 32]);
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: receipt_ref.clone(),
            timestamp: 1_781_072_000,
            capability_id: format!("cap-{receipt_ref}"),
            tool_server: "chio-commerce-order-authority".to_string(),
            tool_name: required_event_string(event, "transition")?,
            action: ToolCallAction::from_parameters(serde_json::json!({
                "authority_receipt_ref": receipt_ref,
                "event_id": event["event_id"],
                "order_id": event["order_id"],
                "transition": event["transition"],
            }))
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "proof fixture commerce authority receipt action hash failed: {error}"
                ))
            })?,
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: vec![ActorRef {
                actor_id: required_event_string(event, "actor")?,
                actor_kind: Some("agent".to_string()),
            }],
            content_hash: required_event_string(event, "event_sha256")?,
            policy_hash: policy_sha256.to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "proof fixture commerce authority receipt signing failed: {error}"
        ))
    })?;
    let mut receipt_value = serde_json::to_value(receipt)?;
    receipt_value["schema"] = serde_json::Value::String("chio.receipt.v1".to_string());
    write_json_line_file(destination, &receipt_value)
}

fn required_event_string(event: &serde_json::Value, field: &str) -> Result<String, CliError> {
    event
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| CliError::cli_other_error(format!("commerce event field missing: {field}")))
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
    refresh_graph_node_hashes(bundle, &mut evidence_graph)?;
    write_json_line_file(&evidence_graph_path, &evidence_graph)?;
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport = read_json_value(&passport_path)?;
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    write_signed_transaction_passport(&passport_path, passport)?;
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
    strip_collected_bundle_outputs(&bundle)?;
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
    strip_collected_bundle_outputs(&bundle)?;
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
    let static_package_json = fs::read_to_string(bundle.join("proof-package.json"))?;
    let static_report_json = fs::read_to_string(bundle.join("verifier-report.json"))?;
    chio_runtime_harness::run_runtime_loopback_scenario_with_static_artifacts(
        &scenario_path,
        &store_dir,
        RUNTIME_SWARM_LOOPBACK_NOW_UNIX_MS,
        &out_dir,
        &static_package_json,
        &static_report_json,
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
    refresh_graph_node_hashes(bundle, &mut evidence_graph)?;
    write_json_line_file(&evidence_graph_path, &evidence_graph)?;
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport = read_json_value(&passport_path)?;
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    write_signed_transaction_passport(&passport_path, passport)?;
    Ok(())
}

fn runtime_swarm_loopback_temp_root() -> Result<PathBuf, CliError> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "proof fixture runtime loopback clock failed: {error}"
            ))
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

fn merge_public_settlement_fixture(
    bundle: &Path,
    settlement_source: &Path,
) -> Result<(), CliError> {
    let settlement_passport_path = settlement_source.join("transaction-passport.json");
    let settlement_passport = read_json_value(&settlement_passport_path)?;
    let passport_id = required_json_string(&settlement_passport, "id", &settlement_passport_path)?;
    let settlement_proof_path = settlement_source.join("settlement-proof-bundle.json");
    let settlement_proof = read_json_value(&settlement_proof_path)?;
    let commerce_order_id = required_json_string(
        &settlement_proof,
        "commerce_order_id",
        &settlement_proof_path,
    )?;
    retarget_commerce_order_id(bundle, &commerce_order_id)?;

    let policy_path = bundle.join("verifier-policy.json");
    let mut policy = read_json_value(&policy_path)?;
    append_required_claims_from_policy(
        &mut policy,
        &settlement_source.join("verifier-policy.json"),
    )?;
    write_json_line_file(&policy_path, &policy)?;
    let policy_sha256 = sha256_file(&policy_path)?;
    let passport_path = bundle.join("transaction-passport.json");
    let mut passport = read_json_value(&passport_path)?;
    passport["id"] = serde_json::Value::String(passport_id.clone());
    let claim_set_sha256 = refresh_claim_set_for_policy(
        bundle,
        &passport_id,
        required_json_string(&passport, "issued_at", &passport_path)?.as_str(),
        &policy,
    )?;

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph = read_json_value(&evidence_graph_path)?;
    upsert_claim_set_graph_binding(&mut evidence_graph, &claim_set_sha256)?;
    append_graph_artifacts_from_fixture(
        bundle,
        settlement_source,
        &mut evidence_graph,
        &[("passport-public-settlement-valid", &passport_id)],
    )?;
    add_public_settlement_deployment_provenance_to_bundle(bundle)?;
    upsert_public_settlement_anchor_proof_bundle_graph_node(
        bundle,
        &mut evidence_graph,
        &evidence_graph_path,
    )?;
    refresh_graph_node_hashes(bundle, &mut evidence_graph)?;
    write_json_line_file(&evidence_graph_path, &evidence_graph)?;
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    passport["claim_set_sha256"] = serde_json::Value::String(claim_set_sha256);
    passport["claim_set_path"] = serde_json::Value::String("claim-set.json".to_string());
    passport["verifier_policy_sha256"] = serde_json::Value::String(policy_sha256);
    write_signed_transaction_passport(&passport_path, passport)?;
    Ok(())
}

fn normalize_public_settlement_deployment_provenance(
    descriptor: &ProofFixtureDescriptor,
    out: &Path,
) -> Result<(), CliError> {
    if descriptor.kind != "transaction-passport"
        && descriptor.kind != "negative-transaction-passport"
    {
        return Ok(());
    }
    if !installed_fixture_path(descriptor).starts_with("public-settlement/") {
        return Ok(());
    }
    if !out.join("settlement-proof-bundle.json").is_file() {
        return Ok(());
    }

    strip_standalone_public_settlement_trust_market_refs(out)?;
    add_public_settlement_deployment_provenance_to_bundle(out)?;
    if descriptor.id == "public-settlement-deployment-provenance-mismatch" {
        set_public_settlement_deployment_contract_package_mismatch(out)?;
    }
    if descriptor.id == "public-settlement-advisory-witness" {
        set_public_settlement_witness_mode_advisory(out)?;
    }
    let evidence_graph_path = out.join("evidence-graph.json");
    let mut evidence_graph = read_json_value(&evidence_graph_path)?;
    upsert_public_settlement_anchor_proof_bundle_graph_node(
        out,
        &mut evidence_graph,
        &evidence_graph_path,
    )?;
    refresh_graph_node_hashes(out, &mut evidence_graph)?;
    write_json_line_file(&evidence_graph_path, &evidence_graph)?;
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

    let passport_path = out.join("transaction-passport.json");
    let mut passport = read_json_value(&passport_path)?;
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    write_signed_transaction_passport(&passport_path, passport)?;
    Ok(())
}

fn strip_standalone_public_settlement_trust_market_refs(bundle: &Path) -> Result<(), CliError> {
    let settlement_proof_path = bundle.join("settlement-proof-bundle.json");
    let mut settlement_proof = read_json_value(&settlement_proof_path)?;
    let object = settlement_proof.as_object_mut().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "public settlement proof bundle must be an object: {}",
            settlement_proof_path.display()
        ))
    })?;
    object.remove("collateral_position_ref");
    object.remove("guarantee_decision_ref");
    object.remove("sla_remedy_ref");
    object.remove("slash_authority_ref");
    write_json_line_file(&settlement_proof_path, &settlement_proof)
}

fn add_public_settlement_deployment_provenance_to_bundle(bundle: &Path) -> Result<(), CliError> {
    let settlement_proof_path = bundle.join("settlement-proof-bundle.json");
    let mut settlement_proof = read_json_value(&settlement_proof_path)?;
    reseal_public_settlement_anchor_receipt(&mut settlement_proof, &settlement_proof_path)?;
    let bundle_id = required_json_string(&settlement_proof, "bundle_id", &settlement_proof_path)?;
    let chain_id = required_json_string(&settlement_proof, "chain_id", &settlement_proof_path)?;
    let contract_package_id = required_json_pointer_string(
        &settlement_proof,
        "/settlement_receipt/dispatch/contract_package_id",
        &settlement_proof_path,
    )?;
    let root_registry_address = required_json_pointer_string(
        &settlement_proof,
        "/chain_snapshot/root_registry_address",
        &settlement_proof_path,
    )?;
    let identity_registry_address = required_json_pointer_string(
        &settlement_proof,
        "/chain_snapshot/identity_registry_address",
        &settlement_proof_path,
    )?;
    let escrow_contract = required_json_pointer_string(
        &settlement_proof,
        "/settlement_receipt/dispatch/escrow_contract",
        &settlement_proof_path,
    )?;
    let bond_vault_contract = required_json_pointer_string(
        &settlement_proof,
        "/settlement_receipt/dispatch/bond_vault_contract",
        &settlement_proof_path,
    )?;
    let settlement_token_address = settlement_proof
        .pointer("/settlement_receipt/dispatch/settlement_token_address")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or("0x735F1Ba389D9D350501dB8FBbB5b52477DcaddA8")
        .to_string();
    let registry_root = required_json_pointer_string(
        &settlement_proof,
        "/chain_snapshot/registry_root",
        &settlement_proof_path,
    )?;
    let anchor_tx_hash = required_json_pointer_string(
        &settlement_proof,
        "/settlement_receipt/reconciled_anchor_proof/chain_anchor/tx_hash",
        &settlement_proof_path,
    )?;
    let anchored_merkle_root = required_json_pointer_string(
        &settlement_proof,
        "/settlement_receipt/reconciled_anchor_proof/chain_anchor/anchored_merkle_root",
        &settlement_proof_path,
    )?;
    let anchored_checkpoint_seq = required_json_pointer_u64(
        &settlement_proof,
        "/settlement_receipt/reconciled_anchor_proof/chain_anchor/anchored_checkpoint_seq",
        &settlement_proof_path,
    )?;
    let runtime_hashes =
        public_settlement_runtime_hashes(bundle, &contract_package_id, &settlement_proof_path)?;
    let root_registry_runtime_codehash = runtime_hashes.root_registry;
    let identity_registry_runtime_codehash = runtime_hashes.identity_registry;
    let escrow_runtime_codehash = runtime_hashes.escrow;
    let bond_vault_runtime_codehash = runtime_hashes.bond_vault;
    let reviewed_manifest_hash = public_settlement_reviewed_manifest_hash(
        &chain_id,
        &contract_package_id,
        &root_registry_address,
        &root_registry_runtime_codehash,
        &identity_registry_address,
        &identity_registry_runtime_codehash,
        &escrow_contract,
        &escrow_runtime_codehash,
        &bond_vault_contract,
        &bond_vault_runtime_codehash,
        &settlement_token_address,
    )?;

    settlement_proof["settlement_receipt"]["schema"] =
        serde_json::Value::String("chio.web3-settlement-execution-receipt.v2".to_string());
    settlement_proof["settlement_receipt"]["dispatch"]["schema"] =
        serde_json::Value::String("chio.web3-settlement-dispatch.v2".to_string());
    settlement_proof["settlement_receipt"]["dispatch"]["settlement_token_address"] =
        serde_json::Value::String(settlement_token_address.clone());
    settlement_proof["settlement_receipt"]["dispatch"]["operator_key_hash"] =
        serde_json::Value::String(PUBLIC_SETTLEMENT_OPERATOR_KEY_HASH.to_string());
    settlement_proof["settlement_receipt"]["reconciled_anchor_proof"]["chain_anchor"]
        ["operator_key_hash"] =
        serde_json::Value::String(PUBLIC_SETTLEMENT_OPERATOR_KEY_HASH.to_string());
    settlement_proof["chain_snapshot"]["root_registry_runtime_codehash"] =
        serde_json::Value::String(root_registry_runtime_codehash.to_string());
    settlement_proof["chain_snapshot"]["identity_registry_address"] =
        serde_json::Value::String(identity_registry_address.to_string());
    settlement_proof["chain_snapshot"]["identity_registry_runtime_codehash"] =
        serde_json::Value::String(identity_registry_runtime_codehash.to_string());
    settlement_proof["chain_snapshot"]["escrow"]["escrow_runtime_codehash"] =
        serde_json::Value::String(escrow_runtime_codehash.to_string());
    settlement_proof["chain_snapshot"]["escrow"]["settlement_token_address"] =
        serde_json::Value::String(settlement_token_address.clone());
    settlement_proof["chain_snapshot"]["escrow"]["refunded"] = serde_json::Value::Bool(false);
    if settlement_proof["chain_snapshot"]["bond"].is_object() {
        settlement_proof["chain_snapshot"]["bond"]["bond_vault_runtime_codehash"] =
            serde_json::Value::String(bond_vault_runtime_codehash.to_string());
    }

    settlement_proof["deployment_provenance"] = serde_json::json!({
        "provenance_id": format!("deployment-provenance-{bundle_id}"),
        "chain_id": chain_id.clone(),
        "contract_package_id": contract_package_id.clone(),
        "reviewed_manifest_hash": reviewed_manifest_hash,
        "approval_hash": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "create2_factory": "0x1000000000000000000000000000000000000000",
        "salt_namespace": "chio-official-web3-stack-v1",
        "settlement_token_address": settlement_token_address.clone(),
        "root_registry_address": root_registry_address.clone(),
        "root_registry_runtime_codehash": root_registry_runtime_codehash.clone(),
        "identity_registry_address": identity_registry_address.clone(),
        "identity_registry_runtime_codehash": identity_registry_runtime_codehash.clone(),
        "escrow_contract": escrow_contract.clone(),
        "escrow_runtime_codehash": escrow_runtime_codehash.clone(),
        "bond_vault_contract": bond_vault_contract.clone(),
        "bond_vault_runtime_codehash": bond_vault_runtime_codehash.clone()
    });
    let witness_id = format!("public-witness-{bundle_id}");
    let witness_body = serde_json::json!({
        "witness_id": witness_id,
        "mode": "verified_cache",
        "chain_id": chain_id,
        "registry_root": registry_root,
        "root_registry_address": root_registry_address,
        "root_registry_runtime_codehash": root_registry_runtime_codehash,
        "identity_registry_address": identity_registry_address,
        "identity_registry_runtime_codehash": identity_registry_runtime_codehash,
        "escrow_contract": escrow_contract,
        "escrow_runtime_codehash": escrow_runtime_codehash,
        "settlement_token_address": settlement_token_address,
        "bond_vault_contract": bond_vault_contract,
        "bond_vault_runtime_codehash": bond_vault_runtime_codehash,
        "anchor_tx_hash": anchor_tx_hash,
        "anchored_merkle_root": anchored_merkle_root,
        "anchored_checkpoint_seq": anchored_checkpoint_seq,
        "observed_at": 1_743_293_500_u64
    });
    let body_hash = public_settlement_witness_body_hash(&witness_body)?;
    settlement_proof["public_witness"] = witness_body;
    settlement_proof["public_witness"]["body_hash"] = serde_json::Value::String(body_hash);
    sign_public_settlement_oracle_evidence(&mut settlement_proof, &settlement_proof_path)?;
    sign_public_settlement_proof_bundle(&mut settlement_proof, &settlement_proof_path)?;
    write_json_line_file(&settlement_proof_path, &settlement_proof)?;
    write_public_settlement_anchor_proof_bundle(bundle, &settlement_proof, &settlement_proof_path)
}

#[allow(clippy::too_many_arguments)]
fn public_settlement_reviewed_manifest_hash(
    chain_id: &str,
    contract_package_id: &str,
    root_registry_address: &str,
    root_registry_runtime_codehash: &str,
    identity_registry_address: &str,
    identity_registry_runtime_codehash: &str,
    escrow_contract: &str,
    escrow_runtime_codehash: &str,
    bond_vault_contract: &str,
    bond_vault_runtime_codehash: &str,
    settlement_token_address: &str,
) -> Result<String, CliError> {
    let reviewed_manifest = serde_json::json!({
        "schema": "chio.web3-public-settlement-fixture-reviewed-manifest.v1",
        "chain_id": chain_id,
        "contract_package_id": contract_package_id,
        "create2_factory": "0x1000000000000000000000000000000000000000",
        "salt_namespace": "chio-official-web3-stack-v1",
        "settlement_token_address": settlement_token_address,
        "contracts": {
            "root_registry": {
                "address": root_registry_address,
                "runtime_codehash": root_registry_runtime_codehash,
            },
            "identity_registry": {
                "address": identity_registry_address,
                "runtime_codehash": identity_registry_runtime_codehash,
            },
            "escrow": {
                "address": escrow_contract,
                "runtime_codehash": escrow_runtime_codehash,
            },
            "bond_vault": {
                "address": bond_vault_contract,
                "runtime_codehash": bond_vault_runtime_codehash,
            },
        },
    });
    let canonical = chio_core_types::canonical_json_bytes(&reviewed_manifest).map_err(|error| {
        CliError::cli_other_error(format!(
            "public settlement reviewed manifest canonicalization failed: {error}"
        ))
    })?;
    Ok(format!("0x{}", chio_core::sha256_hex(&canonical)))
}

fn sign_public_settlement_proof_bundle(
    settlement_proof: &mut serde_json::Value,
    settlement_proof_path: &Path,
) -> Result<(), CliError> {
    settlement_proof
        .as_object_mut()
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "public settlement proof bundle must be an object: {}",
                settlement_proof_path.display()
            ))
        })?
        .remove("bundle_signature");
    let keypair = Keypair::from_seed(&PUBLIC_SETTLEMENT_BUNDLE_SIGNATURE_SEED);
    let typed_bundle: chio_web3::settlement_proof::PublicSettlementProofBundle =
        serde_json::from_value(settlement_proof.clone()).map_err(|error| {
            CliError::cli_other_error(format!(
                "public settlement proof bundle invalid before signing: {}: {error}",
                settlement_proof_path.display()
            ))
        })?;
    let (signature, _) = keypair.sign_canonical(&typed_bundle).map_err(|error| {
        CliError::cli_other_error(format!(
            "public settlement proof bundle signing failed: {}: {error}",
            settlement_proof_path.display()
        ))
    })?;
    settlement_proof["bundle_signature"] = serde_json::json!({
        "algorithm": PUBLIC_SETTLEMENT_BUNDLE_SIGNATURE_ALGORITHM,
        "signer_key": keypair.public_key().to_hex(),
        "signature": signature.to_hex()
    });
    Ok(())
}

fn write_public_settlement_anchor_proof_bundle(
    bundle: &Path,
    settlement_proof: &serde_json::Value,
    settlement_proof_path: &Path,
) -> Result<(), CliError> {
    let primary_proof = settlement_proof
        .pointer("/settlement_receipt/reconciled_anchor_proof")
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "public settlement anchor proof missing: {}",
                settlement_proof_path.display()
            ))
        })?
        .clone();
    let checkpoint_seq = required_json_pointer_u64(
        &primary_proof,
        "/checkpoint_statement/checkpoint_seq",
        settlement_proof_path,
    )?;
    let merkle_root = required_json_pointer_string(
        &primary_proof,
        "/checkpoint_statement/merkle_root",
        settlement_proof_path,
    )?;
    let issued_at = required_json_pointer_u64(
        &primary_proof,
        "/checkpoint_statement/issued_at",
        settlement_proof_path,
    )?;
    let anchor_bundle = serde_json::json!({
        "schema": CHIO_ANCHOR_PROOF_BUNDLE_SCHEMA,
        "primary_proof": primary_proof,
        "secondary_lanes": ["solana_memo"],
        "solana_anchor": {
            "chain_id": "solana:mainnet-beta",
            "operator_pubkey": "7xKXtg2CW9Q4hN7kD6A6tVWyQGm9Xxq6u9rY2T6yQkZp",
            "memo_program_id": SOLANA_MEMO_PROGRAM_ID,
            "tx_signature": "5W8D7gF9w3mP2nL6e1c4k7T9y2V6a1b3s5d7f9g2h4j6k8m1n3p5q7r9t1u3v5w7",
            "slot": 310_045_221_u64,
            "block_time": 1_743_600_000_u64,
            "memo_data": format!("Chio:{checkpoint_seq}:{merkle_root}:{issued_at}"),
            "anchored_merkle_root": merkle_root,
            "anchored_checkpoint_seq": checkpoint_seq
        },
        "note": "Synthetic Solana memo lane fixture proving the typed anchor bundle shape."
    });
    write_json_line_file(
        &bundle.join(PUBLIC_SETTLEMENT_ANCHOR_PROOF_BUNDLE_PATH),
        &anchor_bundle,
    )
}

fn upsert_public_settlement_anchor_proof_bundle_graph_node(
    bundle: &Path,
    evidence_graph: &mut serde_json::Value,
    evidence_graph_path: &Path,
) -> Result<(), CliError> {
    let anchor_bundle_path = bundle.join(PUBLIC_SETTLEMENT_ANCHOR_PROOF_BUNDLE_PATH);
    if !anchor_bundle_path.is_file() {
        return Ok(());
    }
    let sha256 = sha256_file(&anchor_bundle_path)?;
    let nodes = json_array_mut(evidence_graph, "nodes", evidence_graph_path)?;
    upsert_fixture_graph_node(
        nodes,
        "anchor-proof-bundle",
        PUBLIC_SETTLEMENT_ANCHOR_PROOF_BUNDLE_PATH,
        CHIO_ANCHOR_PROOF_BUNDLE_SCHEMA,
        "anchor-proof-bundle",
        &sha256,
    );
    Ok(())
}

fn reseal_public_settlement_anchor_receipt(
    settlement_proof: &mut serde_json::Value,
    settlement_proof_path: &Path,
) -> Result<(), CliError> {
    if settlement_proof
        .pointer("/settlement_receipt/reconciled_anchor_proof")
        .is_none()
    {
        return Ok(());
    }
    let execution_receipt_id = required_json_pointer_string(
        settlement_proof,
        "/settlement_receipt/execution_receipt_id",
        settlement_proof_path,
    )?;
    let settlement_reference = required_json_pointer_string(
        settlement_proof,
        "/settlement_receipt/settlement_reference",
        settlement_proof_path,
    )?;
    let dispatch_id = required_json_pointer_string(
        settlement_proof,
        "/settlement_receipt/dispatch/dispatch_id",
        settlement_proof_path,
    )?;
    let governed_receipt_id = required_json_pointer_string(
        settlement_proof,
        "/settlement_receipt/dispatch/capital_instruction/body/governedReceiptId",
        settlement_proof_path,
    )?;
    let content_hash = chio_web3::settlement::settlement_anchor_receipt_content_hash_parts(
        &execution_receipt_id,
        &settlement_reference,
        &dispatch_id,
        &governed_receipt_id,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "public settlement anchor receipt binding failed: {}: {error}",
            settlement_proof_path.display()
        ))
    })?;

    let receipt_pointer = "/settlement_receipt/reconciled_anchor_proof/receipt";
    let receipt_value = settlement_proof
        .pointer(receipt_pointer)
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "public settlement anchor receipt missing: {}",
                settlement_proof_path.display()
            ))
        })?
        .clone();
    let receipt: ChioReceipt = serde_json::from_value(receipt_value).map_err(|error| {
        CliError::cli_other_error(format!(
            "public settlement anchor receipt invalid: {}: {error}",
            settlement_proof_path.display()
        ))
    })?;
    let mut receipt_body = receipt.body();
    receipt_body.id = governed_receipt_id.clone();
    receipt_body.content_hash = content_hash;
    let anchor_keypair = Keypair::from_seed(&PUBLIC_SETTLEMENT_ANCHOR_SIGNATURE_SEED);
    let signed_receipt = ChioReceipt::sign(receipt_body, &anchor_keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "public settlement anchor receipt signing failed: {}: {error}",
            settlement_proof_path.display()
        ))
    })?;
    let signed_receipt_body = signed_receipt.body();
    let receipt_body_bytes =
        chio_core_types::canonical_json_bytes(&signed_receipt_body).map_err(|error| {
            CliError::cli_other_error(format!(
                "public settlement anchor receipt canonicalization failed: {}: {error}",
                settlement_proof_path.display()
            ))
        })?;
    let tree = chio_web3::merkle::MerkleTree::from_leaves(&[receipt_body_bytes.as_slice()])
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "public settlement anchor receipt Merkle tree failed: {}: {error}",
                settlement_proof_path.display()
            ))
        })?;
    let merkle_root = tree.root();
    let checkpoint_seq = required_json_pointer_u64(
        settlement_proof,
        "/settlement_receipt/reconciled_anchor_proof/receipt_inclusion/checkpoint_seq",
        settlement_proof_path,
    )?;
    let receipt_inclusion = chio_web3::anchors::Web3ReceiptInclusion {
        checkpoint_seq,
        merkle_root,
        proof: tree.inclusion_proof(0).map_err(|error| {
            CliError::cli_other_error(format!(
                "public settlement anchor receipt inclusion failed: {}: {error}",
                settlement_proof_path.display()
            ))
        })?,
    };
    let statement_pointer = "/settlement_receipt/reconciled_anchor_proof/checkpoint_statement";
    let mut statement: chio_web3::anchors::Web3CheckpointStatement = serde_json::from_value(
        settlement_proof
            .pointer(statement_pointer)
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "public settlement checkpoint statement missing: {}",
                    settlement_proof_path.display()
                ))
            })?
            .clone(),
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "public settlement checkpoint statement invalid: {}: {error}",
            settlement_proof_path.display()
        ))
    })?;
    statement.tree_size = 1;
    statement.merkle_root = merkle_root;
    statement.kernel_key = anchor_keypair.public_key();
    let statement_body = ProofFixtureCheckpointStatementBody {
        schema: statement.schema.clone(),
        checkpoint_seq: statement.checkpoint_seq,
        batch_start_seq: statement.batch_start_seq,
        batch_end_seq: statement.batch_end_seq,
        tree_size: statement.tree_size,
        merkle_root: statement.merkle_root,
        issued_at: statement.issued_at,
        previous_checkpoint_sha256: statement.previous_checkpoint_sha256.clone(),
        kernel_key: statement.kernel_key.clone(),
    };
    let (signature, _) = anchor_keypair
        .sign_canonical(&statement_body)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "public settlement checkpoint statement signing failed: {}: {error}",
                settlement_proof_path.display()
            ))
        })?;
    statement.signature = signature;

    *settlement_proof
        .pointer_mut(receipt_pointer)
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "public settlement anchor receipt missing: {}",
                settlement_proof_path.display()
            ))
        })? = serde_json::to_value(signed_receipt).map_err(CliError::from)?;
    settlement_proof["settlement_receipt"]["reconciled_anchor_proof"]["receipt_inclusion"] =
        serde_json::to_value(receipt_inclusion).map_err(CliError::from)?;
    settlement_proof["settlement_receipt"]["reconciled_anchor_proof"]["checkpoint_statement"] =
        serde_json::to_value(statement).map_err(CliError::from)?;
    settlement_proof["settlement_receipt"]["reconciled_anchor_proof"]["chain_anchor"]
        ["anchored_merkle_root"] = serde_json::to_value(merkle_root).map_err(CliError::from)?;
    settlement_proof["chain_snapshot"]["registry_root"] =
        serde_json::to_value(merkle_root).map_err(CliError::from)?;
    Ok(())
}

fn sign_public_settlement_oracle_evidence(
    settlement_proof: &mut serde_json::Value,
    settlement_proof_path: &Path,
) -> Result<(), CliError> {
    let Some(oracle_evidence) = settlement_proof
        .pointer_mut("/settlement_receipt/oracle_evidence")
        .filter(|value| !value.is_null())
    else {
        return Ok(());
    };
    let mut evidence: chio_web3::anchors::OracleConversionEvidence =
        serde_json::from_value(oracle_evidence.clone()).map_err(|error| {
            CliError::cli_other_error(format!(
                "public settlement oracle evidence invalid: {}: {error}",
                settlement_proof_path.display()
            ))
        })?;
    chio_web3::anchors::sign_oracle_conversion_evidence(
        &mut evidence,
        &Keypair::from_seed(&PUBLIC_SETTLEMENT_ORACLE_SIGNATURE_SEED),
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "public settlement oracle evidence signing failed: {error}"
        ))
    })?;
    *oracle_evidence = serde_json::to_value(evidence).map_err(CliError::from)?;
    Ok(())
}

fn set_public_settlement_deployment_contract_package_mismatch(
    bundle: &Path,
) -> Result<(), CliError> {
    let settlement_proof_path = bundle.join("settlement-proof-bundle.json");
    let mut settlement_proof = read_json_value(&settlement_proof_path)?;
    settlement_proof["deployment_provenance"]["contract_package_id"] =
        serde_json::Value::String("chio.unreviewed-web3-contracts".to_string());
    sign_public_settlement_proof_bundle(&mut settlement_proof, &settlement_proof_path)?;
    write_json_line_file(&settlement_proof_path, &settlement_proof)
}

fn set_public_settlement_witness_mode_advisory(bundle: &Path) -> Result<(), CliError> {
    let settlement_proof_path = bundle.join("settlement-proof-bundle.json");
    let mut settlement_proof = read_json_value(&settlement_proof_path)?;
    settlement_proof["public_witness"]["mode"] = serde_json::Value::String("advisory".to_string());
    let body_hash = public_settlement_witness_body_hash(
        settlement_proof.get("public_witness").ok_or_else(|| {
            CliError::cli_other_error(format!(
                "public settlement witness missing: {}",
                settlement_proof_path.display()
            ))
        })?,
    )?;
    settlement_proof["public_witness"]["body_hash"] = serde_json::Value::String(body_hash);
    sign_public_settlement_proof_bundle(&mut settlement_proof, &settlement_proof_path)?;
    write_json_line_file(&settlement_proof_path, &settlement_proof)
}

fn public_settlement_witness_body_hash(witness: &serde_json::Value) -> Result<String, CliError> {
    let witness_body = serde_json::json!({
        "witness_id": required_public_settlement_witness_string(witness, "witness_id")?,
        "mode": required_public_settlement_witness_string(witness, "mode")?,
        "chain_id": required_public_settlement_witness_string(witness, "chain_id")?,
        "registry_root": required_public_settlement_witness_string(witness, "registry_root")?,
        "root_registry_address": required_public_settlement_witness_string(witness, "root_registry_address")?,
        "root_registry_runtime_codehash": required_public_settlement_witness_string(witness, "root_registry_runtime_codehash")?,
        "identity_registry_address": required_public_settlement_witness_string(witness, "identity_registry_address")?,
        "identity_registry_runtime_codehash": required_public_settlement_witness_string(witness, "identity_registry_runtime_codehash")?,
        "identity_registry_operator": witness.get("identity_registry_operator").cloned().unwrap_or(serde_json::Value::Null),
        "escrow_contract": required_public_settlement_witness_string(witness, "escrow_contract")?,
        "escrow_runtime_codehash": required_public_settlement_witness_string(witness, "escrow_runtime_codehash")?,
        "settlement_token_address": required_public_settlement_witness_string(witness, "settlement_token_address")?,
        "bond_vault_contract": required_public_settlement_witness_string(witness, "bond_vault_contract")?,
        "bond_vault_runtime_codehash": required_public_settlement_witness_string(witness, "bond_vault_runtime_codehash")?,
        "anchor_tx_hash": required_public_settlement_witness_string(witness, "anchor_tx_hash")?,
        "anchored_merkle_root": required_public_settlement_witness_string(witness, "anchored_merkle_root")?,
        "anchored_checkpoint_seq": required_public_settlement_witness_u64(witness, "anchored_checkpoint_seq")?,
        "observed_at": required_public_settlement_witness_u64(witness, "observed_at")?,
    });
    let canonical = chio_core_types::canonical_json_bytes(&witness_body).map_err(|error| {
        CliError::cli_other_error(format!(
            "public settlement witness canonicalization failed: {error}"
        ))
    })?;
    Ok(chio_core::sha256_hex(&canonical))
}

fn required_public_settlement_witness_string(
    witness: &serde_json::Value,
    field: &str,
) -> Result<String, CliError> {
    witness
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            CliError::cli_other_error(format!("public settlement witness field missing: {field}"))
        })
}

fn required_public_settlement_witness_u64(
    witness: &serde_json::Value,
    field: &str,
) -> Result<u64, CliError> {
    witness
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            CliError::cli_other_error(format!("public settlement witness field missing: {field}"))
        })
}

fn retarget_commerce_order_id(bundle: &Path, order_id: &str) -> Result<(), CliError> {
    let event_log_path = bundle.join("event-log.json");
    let payment_path = bundle.join("payment-lifecycle.json");
    let mandate_path = bundle.join("mandate-allowance-ledger.json");
    let settlement_packet_path = bundle.join("settlement-packet.json");
    let order_context_path = bundle.join("order-context.json");

    let mut order_context = read_json_value(&order_context_path)?;
    order_context["order_id"] = serde_json::Value::String(order_id.to_string());
    let quote_sha256 = commerce_quote_sha256(&order_context, &order_context_path)?;
    order_context["quote_sha256"] = serde_json::Value::String(quote_sha256.clone());

    let mut event_log = read_json_value(&event_log_path)?;
    event_log["order_id"] = serde_json::Value::String(order_id.to_string());
    for event in json_array_mut(&mut event_log, "events", &event_log_path)? {
        event["order_id"] = serde_json::Value::String(order_id.to_string());
        seal_commerce_event(event)?;
    }
    write_json_line_file(&event_log_path, &event_log)?;

    let mut payment_lifecycle = read_json_value(&payment_path)?;
    payment_lifecycle["order_id"] = serde_json::Value::String(order_id.to_string());
    payment_lifecycle["transfer_group"] = serde_json::Value::String(order_id.to_string());
    payment_lifecycle["quote_sha256"] = serde_json::Value::String(quote_sha256.clone());
    sign_fixture_commerce_payment_lifecycle(&mut payment_lifecycle)?;
    write_json_line_file(&payment_path, &payment_lifecycle)?;

    let mut mandate_ledger = read_json_value(&mandate_path)?;
    mandate_ledger["order_id"] = serde_json::Value::String(order_id.to_string());
    mandate_ledger["quote_sha256"] = serde_json::Value::String(quote_sha256.clone());
    retarget_commerce_mandate_projection_order_ids(&mut mandate_ledger, order_id);
    retarget_commerce_mandate_protocol_payloads(bundle, &mut mandate_ledger, order_id)?;
    write_json_line_file(&mandate_path, &mandate_ledger)?;

    let mut settlement_packet = read_json_value(&settlement_packet_path)?;
    settlement_packet["order_id"] = serde_json::Value::String(order_id.to_string());
    settlement_packet["quote_sha256"] = serde_json::Value::String(quote_sha256);
    write_json_line_file(&settlement_packet_path, &settlement_packet)?;

    sign_fixture_commerce_provider_trust_artifact(&bundle.join("provider-passport.json"))?;
    sign_fixture_commerce_provider_trust_artifact(&bundle.join("reputation-snapshot.json"))?;
    sign_fixture_commerce_provider_trust_artifact(&bundle.join("federation-trust-bundle.json"))?;

    order_context["event_log_sha256"] = serde_json::Value::String(sha256_file(&event_log_path)?);
    order_context["payment_lifecycle_sha256"] =
        serde_json::Value::String(sha256_file(&payment_path)?);
    order_context["mandate_ledger_sha256"] = serde_json::Value::String(sha256_file(&mandate_path)?);
    order_context["provider_passport_sha256"] =
        serde_json::Value::String(sha256_file(&bundle.join("provider-passport.json"))?);
    order_context["reputation_snapshot_sha256"] =
        serde_json::Value::String(sha256_file(&bundle.join("reputation-snapshot.json"))?);
    order_context["federation_trust_bundle_sha256"] =
        serde_json::Value::String(sha256_file(&bundle.join("federation-trust-bundle.json"))?);
    order_context["settlement_packet_sha256"] =
        serde_json::Value::String(sha256_file(&settlement_packet_path)?);
    write_json_line_file(&order_context_path, &order_context)?;
    Ok(())
}

fn seal_commerce_event(event: &mut serde_json::Value) -> Result<(), CliError> {
    let event_object = event.as_object_mut().ok_or_else(|| {
        CliError::cli_other_error("commerce event must be a JSON object".to_string())
    })?;
    event_object.remove("event_sha256");
    let canonical = chio_core_types::canonical_json_bytes(event).map_err(|error| {
        CliError::cli_other_error(format!("commerce event canonicalization failed: {error}"))
    })?;
    event["event_sha256"] = serde_json::Value::String(chio_core::sha256_hex(&canonical));
    Ok(())
}

fn commerce_quote_sha256(
    order_context: &serde_json::Value,
    path: &Path,
) -> Result<String, CliError> {
    let quote_amount_minor = order_context
        .get("quote_amount_minor")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "commerce order context missing quote_amount_minor: {}",
                path.display()
            ))
        })?;
    let binding = serde_json::json!({
        "amount_minor": quote_amount_minor,
        "currency": required_json_string(order_context, "quote_currency", path)?,
        "merchant_subject": required_json_string(order_context, "merchant_subject", path)?,
        "order_id": required_json_string(order_context, "order_id", path)?,
        "quote_id": required_json_string(order_context, "quote_id", path)?,
    });
    let canonical = chio_core_types::canonical_json_bytes(&binding).map_err(|error| {
        CliError::cli_other_error(format!(
            "commerce quote binding canonicalization failed: {error}"
        ))
    })?;
    Ok(chio_core::sha256_hex(&canonical))
}

fn retarget_commerce_mandate_projection_order_ids(
    mandate_ledger: &mut serde_json::Value,
    order_id: &str,
) {
    if let Some(projections) = mandate_ledger
        .get_mut("protocol_projections")
        .and_then(serde_json::Value::as_array_mut)
    {
        for projection in projections {
            projection["order_id"] = serde_json::Value::String(order_id.to_string());
        }
    }
}

fn retarget_commerce_mandate_protocol_payloads(
    bundle: &Path,
    mandate_ledger: &mut serde_json::Value,
    order_id: &str,
) -> Result<(), CliError> {
    let mandate_path = bundle.join("mandate-allowance-ledger.json");
    let projections = json_array(mandate_ledger, "protocol_projections", &mandate_path)?;
    let projection_refs = projections
        .iter()
        .enumerate()
        .map(|(index, projection)| {
            Ok((
                index,
                required_json_string(projection, "protocol", &mandate_path)?,
                required_json_string(projection, "purpose", &mandate_path)?,
                required_json_string(projection, "payload_path", &mandate_path)?,
            ))
        })
        .collect::<Result<Vec<_>, CliError>>()?;

    for (index, protocol, purpose, payload_path) in projection_refs {
        let payload_path = checked_bundle_relative_path(bundle, &payload_path)?;
        let mut payload = read_json_value(&payload_path)?;
        payload["order_id"] = serde_json::Value::String(order_id.to_string());
        write_json_line_file(&payload_path, &payload)?;
        let payload_sha256 = sha256_file(&payload_path)?;
        let projections = json_array_mut(mandate_ledger, "protocol_projections", &mandate_path)?;
        projections[index]["digest"] = serde_json::Value::String(payload_sha256.clone());
        if let Some(field) = commerce_mandate_protocol_hash_field(&protocol, &purpose) {
            mandate_ledger[field] = serde_json::Value::String(payload_sha256);
        }
    }

    Ok(())
}

fn checked_bundle_relative_path(bundle: &Path, relative_path: &str) -> Result<PathBuf, CliError> {
    let path = Path::new(relative_path);
    if path
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(CliError::cli_other_error(format!(
            "unsafe commerce mandate payload path: {relative_path}"
        )));
    }
    Ok(bundle.join(path))
}

fn commerce_mandate_protocol_hash_field(protocol: &str, purpose: &str) -> Option<&'static str> {
    match (protocol, purpose) {
        ("ap2", "checkout_mandate") => Some("ap2_checkout_mandate_hash"),
        ("ap2", "payment_mandate") => Some("ap2_payment_mandate_hash"),
        ("acp-commerce", "delegated_payment_token") => Some("acp_delegated_payment_token_hash"),
        ("x402", "payment_requirements") => Some("x402_payment_requirements_hash"),
        _ => None,
    }
}

fn sign_fixture_commerce_payment_lifecycle(
    payment_lifecycle: &mut serde_json::Value,
) -> Result<(), CliError> {
    let keypair = Keypair::from_seed(&[7u8; 32]);
    payment_lifecycle["issuer"] =
        serde_json::Value::String(format!("did:chio:{}", keypair.public_key().to_hex()));
    let body = payment_lifecycle.as_object_mut().ok_or_else(|| {
        CliError::cli_other_error("payment lifecycle fixture must be a JSON object")
    })?;
    body.remove("signature");
    let (signature, _) = keypair.sign_canonical(payment_lifecycle).map_err(|error| {
        CliError::cli_other_error(format!(
            "proof fixture payment lifecycle signing failed: {error}"
        ))
    })?;
    payment_lifecycle["signature"] = serde_json::Value::String(signature.to_hex());
    Ok(())
}

fn sign_fixture_commerce_provider_trust_artifact(path: &Path) -> Result<(), CliError> {
    let keypair = Keypair::from_seed(&COMMERCE_PROVIDER_TRUST_SIGNATURE_SEED);
    let mut artifact = read_json_value(path)?;
    let body = artifact.as_object_mut().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "commerce provider trust fixture must be a JSON object: {}",
            path.display()
        ))
    })?;
    body.remove("signature");
    let (signature, _) = keypair.sign_canonical(&artifact).map_err(|error| {
        CliError::cli_other_error(format!(
            "proof fixture commerce provider trust signing failed: {error}"
        ))
    })?;
    artifact["signature"] = serde_json::Value::String(signature.to_hex());
    write_json_line_file(path, &artifact)
}

fn merge_agent_web_fixture(bundle: &Path, agent_web_source: &Path) -> Result<(), CliError> {
    let agent_web_passport_path = agent_web_source.join("transaction-passport.json");
    let agent_web_passport = read_json_value(&agent_web_passport_path)?;
    let agent_web_passport_id =
        required_json_string(&agent_web_passport, "id", &agent_web_passport_path)?;

    let policy_path = bundle.join("verifier-policy.json");
    let mut policy = read_json_value(&policy_path)?;
    append_required_claims_from_policy(
        &mut policy,
        &agent_web_source.join("verifier-policy.json"),
    )?;
    write_json_line_file(&policy_path, &policy)?;
    let policy_sha256 = sha256_file(&policy_path)?;

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph = read_json_value(&evidence_graph_path)?;
    let passport_path = bundle.join("transaction-passport.json");
    let disclosure_passport = read_json_value(&passport_path)?;
    let disclosure_passport_id = required_json_string(&disclosure_passport, "id", &passport_path)?;
    let claim_set_sha256 = refresh_claim_set_for_policy(
        bundle,
        &agent_web_passport_id,
        required_json_string(&disclosure_passport, "issued_at", &passport_path)?.as_str(),
        &policy,
    )?;
    upsert_claim_set_graph_binding(&mut evidence_graph, &claim_set_sha256)?;
    replace_json_strings_in_graph_artifacts(
        bundle,
        &evidence_graph,
        &[(&disclosure_passport_id, &agent_web_passport_id)],
    )?;
    refresh_signed_lineage_subgraph_digest(bundle)?;
    add_disclosure_agent_web_crypto_context_material(bundle, &mut evidence_graph)?;
    append_graph_artifacts_from_fixture(bundle, agent_web_source, &mut evidence_graph, &[])?;
    normalize_agent_web_bilateral_in_toto_statement(bundle)?;
    refresh_agent_web_envelopes_for_subjects(bundle, &mut evidence_graph)?;
    resign_agent_web_receipts_for_policy(bundle, &policy_sha256)?;
    refresh_graph_node_hashes(bundle, &mut evidence_graph)?;
    write_json_line_file(&evidence_graph_path, &evidence_graph)?;
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

    let mut passport = disclosure_passport;
    passport["id"] = serde_json::Value::String(agent_web_passport_id);
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    passport["claim_set_sha256"] = serde_json::Value::String(claim_set_sha256);
    passport["claim_set_path"] = serde_json::Value::String("claim-set.json".to_string());
    passport["verifier_policy_sha256"] = serde_json::Value::String(policy_sha256);
    write_signed_transaction_passport(&passport_path, passport)?;
    Ok(())
}

fn add_disclosure_agent_web_crypto_context_material(
    bundle: &Path,
    evidence_graph: &mut serde_json::Value,
) -> Result<(), CliError> {
    let capsule_path = bundle.join("capsule.json");
    let mut capsule = read_json_value(&capsule_path)?;
    let capsule_id = required_json_string(&capsule, "id", &capsule_path)?;
    let transaction_passport_ref =
        required_json_string(&capsule, "transaction_passport_ref", &capsule_path)?;
    let report_path = bundle.join("crypto-context-report.json");
    let current_report = read_json_value(&report_path)?;
    let report_id = required_json_string(&current_report, "id", &report_path)?;
    let context_id = required_json_string(&current_report, "context_id", &report_path)?;
    let disclosed_fields = json_string_array(&current_report, "disclosed_fields", &report_path)?;
    let hidden_predicates = disclosure_hidden_predicate_ids(&capsule, &capsule_path)?;
    capsule["projection_manifest_ref"] = serde_json::Value::String(
        chio_selective_disclosure::PROJECTION_VERSION_RECEIPT_V1.to_string(),
    );
    capsule["hidden_predicates"] =
        disclosure_hidden_predicates_json(&hidden_predicates, disclosed_fields.len());
    write_json_line_file(&capsule_path, &capsule)?;
    let capsule_sha256 = sha256_file(&capsule_path)?;

    let bbs_keypair = chio_selective_disclosure::generate_bbs_keypair(
        DISCLOSURE_AGENT_WEB_BBS_KEY_MATERIAL,
        DISCLOSURE_AGENT_WEB_BBS_KEY_INFO,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("proof fixture BBS key generation failed: {error}"))
    })?;
    let projection = chio_selective_disclosure::Projection {
        version: chio_selective_disclosure::PROJECTION_VERSION_RECEIPT_V1.to_string(),
        subject_sha256_hex: capsule_sha256.clone(),
        messages: disclosure_projection_messages(&disclosed_fields, &hidden_predicates)?,
    };
    let mut projection_manifest =
        chio_selective_disclosure::bbs_projection_manifest_from_projection(&projection);
    projection_manifest.hidden_predicates =
        disclosure_projection_hidden_predicates(&hidden_predicates);
    let projection_manifest_path = bundle.join("bbs-projection-manifest.json");
    write_json_line_file(&projection_manifest_path, &projection_manifest)?;
    let signed_projection = chio_selective_disclosure::sign_projection(&projection, &bbs_keypair)
        .map_err(|error| {
        CliError::cli_other_error(format!(
            "proof fixture BBS projection signing failed: {error}"
        ))
    })?;
    let proof = chio_selective_disclosure::derive_selective_disclosure_proof(
        &signed_projection,
        &projection,
        &bbs_keypair,
        &chio_selective_disclosure::DisclosureSet(disclosure_indices(disclosed_fields.len())?),
        DISCLOSURE_AGENT_WEB_BBS_NONCE,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "proof fixture BBS proof derivation failed: {error}"
        ))
    })?;
    let proof_path = bundle.join("selective-disclosure-proof.json");
    write_json_line_file(&proof_path, &proof)?;
    let transparency_leaf_hash = chio_core::sha256_hex(proof.subject_sha256_hex.as_bytes());
    let transparency_inclusion = serde_json::json!({
        "schema": chio_selective_disclosure::TRANSPARENCY_INCLUSION_PROOF_SCHEMA_V1,
        "proof_id": "transparency-inclusion-proof-disclosure-agent-web",
        "log_id": "transparency-log-fixture",
        "artifact_ref": proof.subject_sha256_hex.clone(),
        "root_hash": transparency_leaf_hash.clone(),
        "leaf_hash": transparency_leaf_hash,
        "tree_size": 1_u64,
        "leaf_index": 0_u64,
        "checkpoint": "transparency-log-fixture:1",
        "inclusion_path": [],
        "verified_at": 1766000100_u64
    });
    let transparency_inclusion_path = bundle.join("transparency-inclusion-proof.json");
    write_json_line_file(&transparency_inclusion_path, &transparency_inclusion)?;

    let privacy_profile_path = bundle.join("privacy-profile.json");
    let mut privacy_profile = read_json_value(&privacy_profile_path)?;
    privacy_profile["transaction_passport_ref"] =
        serde_json::Value::String(transaction_passport_ref);
    privacy_profile["allowed_issuer_keys"] =
        serde_json::json!([bbs_keypair.issuer_fingerprint.clone()]);
    append_unique_json_strings(
        &mut privacy_profile,
        "allowed_disclosed_fields",
        &disclosed_fields,
    )?;
    remove_json_strings(
        &mut privacy_profile,
        "forbidden_disclosed_fields",
        &disclosed_fields,
    )?;
    privacy_profile["leakage_budget"] = serde_json::json!({
        "max_disclosed_fields": disclosed_fields.len(),
        "max_hidden_predicates": hidden_predicates.len()
    });
    privacy_profile["sensitivity_classes"] =
        disclosure_sensitivity_classes_json(&disclosed_fields, &hidden_predicates);
    write_json_line_file(&privacy_profile_path, &privacy_profile)?;
    let typed_privacy_profile: chio_selective_disclosure::DisclosureVerifierPrivacyProfile =
        serde_json::from_value(privacy_profile).map_err(|error| {
            CliError::cli_other_error(format!(
                "proof fixture privacy profile parse failed: {error}"
            ))
        })?;
    normalize_disclosure_leakage_ledger(
        bundle,
        &capsule_id,
        &typed_privacy_profile.profile_id,
        &typed_privacy_profile.required_audience,
        &capsule_sha256,
    )?;

    let context = serde_json::json!({
        "schema": chio_selective_disclosure::CRYPTO_VERIFICATION_CONTEXT_SCHEMA_V1,
        "context_id": context_id,
        "artifact_ref": capsule_id,
        "proof_mechanism": "bbs",
        "issuer": "did:chio:issuer-bbs",
        "issuer_key_ref": bbs_keypair.issuer_fingerprint,
        "key_state": {
            "schema": chio_selective_disclosure::TRUST_KEY_STATE_SCHEMA_V1,
            "key_ref": bbs_keypair.issuer_fingerprint,
            "status": "active",
            "epoch": 7,
            "valid_from": 1766000000,
            "valid_until": 1766000900
        },
        "algorithm": "bbs-bls12381-sha256",
        "suite": "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_",
        "hash_algorithm": "sha-256",
        "canonicalization": "jcs",
        "signature_ref": "selective-disclosure-proof",
        "verification_time": 1766000100_u64,
        "revocation_snapshot": {
            "schema": chio_selective_disclosure::TRUST_REVOCATION_SNAPSHOT_SCHEMA_V1,
            "snapshot_ref": "revocation-snapshot-disclosure-agent-web",
            "status": "fresh",
            "issued_at": 1766000050_u64,
            "expires_at": 1766000350_u64
        },
        "audience": "https://auditor.example/chio",
        "nonce_hex": proof.proof_nonce_hex,
        "nonce_replay_status": "fresh",
        "holder_binding_ref": "holder:buyer-agent",
        "holder_binding_status": "bound",
        "transparency_state": "anchored",
        "presentation_created_at": 1766000080_u64
    });
    let context_path = bundle.join("verification-context.json");
    write_json_line_file(&context_path, &context)?;
    let typed_context: chio_selective_disclosure::CryptoVerificationContext =
        serde_json::from_value(context).map_err(|error| {
            CliError::cli_other_error(format!(
                "proof fixture crypto context parse failed: {error}"
            ))
        })?;

    let mut registry = chio_selective_disclosure::InMemoryIssuerRegistry::default();
    registry.insert(
        proof.issuer_fingerprint.clone(),
        proof.issuer_public_key_hex.clone(),
    );
    let mut proof_context = typed_context.clone();
    proof_context.artifact_ref = proof.subject_sha256_hex.clone();
    let mut report = chio_selective_disclosure::verify_selective_disclosure_with_context(
        &proof,
        &registry,
        &proof_context,
        &typed_privacy_profile,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "proof fixture BBS proof verification failed: {error}"
        ))
    })?;
    report.id = report_id;
    report.artifact_ref = typed_context.artifact_ref;
    report.signature = Some(
        chio_selective_disclosure::sign_crypto_context_report(
            &report,
            &Keypair::from_seed(&DISCLOSURE_LINEAGE_SIGNATURE_SEED),
        )
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "proof fixture crypto context report signing failed: {error}"
            ))
        })?,
    );
    write_json_line_file(&report_path, &report)?;

    let graph_path = bundle.join("evidence-graph.json");
    let mut capsule_ids =
        graph_node_aliases(evidence_graph, &graph_path, "capsule.json", "disclosure-capsule")?;
    let mut privacy_profile_ids = graph_node_aliases(
        evidence_graph,
        &graph_path,
        "privacy-profile.json",
        "disclosure-verifier-privacy-profile",
    )?;
    let mut report_ids = graph_node_aliases(
        evidence_graph,
        &graph_path,
        "crypto-context-report.json",
        "disclosure-crypto-context-report",
    )?;
    let mut projection_manifest_ids = graph_node_aliases(
        evidence_graph,
        &graph_path,
        "bbs-projection-manifest.json",
        "bbs-projection-manifest",
    )?;
    let mut verification_context_ids = graph_node_aliases(
        evidence_graph,
        &graph_path,
        "verification-context.json",
        "crypto-verification-context",
    )?;
    let mut selective_proof_ids = graph_node_aliases(
        evidence_graph,
        &graph_path,
        "selective-disclosure-proof.json",
        "selective-disclosure-proof",
    )?;
    let mut transparency_ids = graph_node_aliases(
        evidence_graph,
        &graph_path,
        "transparency-inclusion-proof.json",
        "transparency-inclusion-proof",
    )?;
    let nodes = json_array_mut(evidence_graph, "nodes", &graph_path)?;
    upsert_fixture_graph_node(
        nodes,
        "crypto-context-report",
        "crypto-context-report.json",
        chio_selective_disclosure::DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1,
        "disclosure-crypto-context-report",
        &sha256_file(&report_path)?,
    );
    upsert_fixture_graph_node(
        nodes,
        "privacy-profile",
        "privacy-profile.json",
        chio_selective_disclosure::DISCLOSURE_VERIFIER_PRIVACY_PROFILE_SCHEMA_V1,
        "disclosure-verifier-privacy-profile",
        &sha256_file(&privacy_profile_path)?,
    );
    upsert_fixture_graph_node(
        nodes,
        "bbs-projection-manifest",
        "bbs-projection-manifest.json",
        chio_selective_disclosure::BBS_PROJECTION_MANIFEST_SCHEMA_V2,
        "bbs-projection-manifest",
        &sha256_file(&projection_manifest_path)?,
    );
    upsert_fixture_graph_node(
        nodes,
        "crypto-verification-context",
        "verification-context.json",
        chio_selective_disclosure::CRYPTO_VERIFICATION_CONTEXT_SCHEMA_V1,
        "crypto-verification-context",
        &sha256_file(&context_path)?,
    );
    upsert_fixture_graph_node(
        nodes,
        "selective-disclosure-proof",
        "selective-disclosure-proof.json",
        chio_selective_disclosure::SELECTIVE_DISCLOSURE_PROOF_SCHEMA_V1,
        "selective-disclosure-proof",
        &sha256_file(&proof_path)?,
    );
    upsert_fixture_graph_node(
        nodes,
        "transparency-inclusion-proof",
        "transparency-inclusion-proof.json",
        chio_selective_disclosure::TRANSPARENCY_INCLUSION_PROOF_SCHEMA_V1,
        "transparency-inclusion-proof",
        &sha256_file(&transparency_inclusion_path)?,
    );
    capsule_ids.extend(graph_node_aliases(
        evidence_graph,
        &graph_path,
        "capsule.json",
        "disclosure-capsule",
    )?);
    privacy_profile_ids.extend(graph_node_aliases(
        evidence_graph,
        &graph_path,
        "privacy-profile.json",
        "disclosure-verifier-privacy-profile",
    )?);
    report_ids.extend(graph_node_aliases(
        evidence_graph,
        &graph_path,
        "crypto-context-report.json",
        "disclosure-crypto-context-report",
    )?);
    projection_manifest_ids.extend(graph_node_aliases(
        evidence_graph,
        &graph_path,
        "bbs-projection-manifest.json",
        "bbs-projection-manifest",
    )?);
    verification_context_ids.extend(graph_node_aliases(
        evidence_graph,
        &graph_path,
        "verification-context.json",
        "crypto-verification-context",
    )?);
    selective_proof_ids.extend(graph_node_aliases(
        evidence_graph,
        &graph_path,
        "selective-disclosure-proof.json",
        "selective-disclosure-proof",
    )?);
    transparency_ids.extend(graph_node_aliases(
        evidence_graph,
        &graph_path,
        "transparency-inclusion-proof.json",
        "transparency-inclusion-proof",
    )?);
    let capsule_id = graph_node_primary_id(
        evidence_graph,
        &graph_path,
        "capsule.json",
        "disclosure-capsule",
    )?;
    let edges = json_array_mut(evidence_graph, "edges", &graph_path)?;
    remove_fixture_graph_edges(edges, &capsule_ids, &privacy_profile_ids, "binds");
    remove_fixture_graph_edges(edges, &capsule_ids, &report_ids, "binds");
    remove_fixture_graph_edges_from(edges, &projection_manifest_ids, "defines");
    remove_fixture_graph_edges_from(edges, &verification_context_ids, "verifies");
    remove_fixture_graph_edges_from(edges, &transparency_ids, "anchors");
    upsert_fixture_graph_edge(edges, &capsule_id, "privacy-profile", "binds");
    upsert_fixture_graph_edge(edges, &capsule_id, "crypto-context-report", "binds");
    upsert_fixture_graph_edge(
        json_array_mut(evidence_graph, "edges", &graph_path)?,
        "bbs-projection-manifest",
        "selective-disclosure-proof",
        "defines",
    );
    upsert_fixture_graph_edge(
        json_array_mut(evidence_graph, "edges", &graph_path)?,
        "crypto-verification-context",
        "selective-disclosure-proof",
        "verifies",
    );
    upsert_fixture_graph_edge(
        json_array_mut(evidence_graph, "edges", &graph_path)?,
        "transparency-inclusion-proof",
        "selective-disclosure-proof",
        "anchors",
    );
    Ok(())
}

fn disclosure_sensitivity_classes_json(
    disclosed_fields: &[String],
    hidden_predicates: &[String],
) -> serde_json::Value {
    let mut classes: Vec<(&str, Vec<String>)> = Vec::new();
    for field in disclosed_fields {
        push_sensitivity_field(
            &mut classes,
            disclosure_sensitivity_class(field, "disclosed_field"),
            field,
        );
    }
    for predicate in hidden_predicates {
        push_sensitivity_field(
            &mut classes,
            disclosure_sensitivity_class(predicate, "hidden_predicate"),
            predicate,
        );
    }
    if !disclosed_fields.is_empty() || !hidden_predicates.is_empty() {
        for (field, class_id) in DISCLOSURE_DERIVED_LEAKAGE_FACTS {
            push_sensitivity_field(&mut classes, class_id, field);
        }
    }
    serde_json::Value::Array(
        classes
            .into_iter()
            .map(|(class_id, fields)| {
                serde_json::json!({
                    "class_id": class_id,
                    "fields": fields
                })
            })
            .collect(),
    )
}

fn disclosure_hidden_predicate_ids(
    capsule: &serde_json::Value,
    capsule_path: &Path,
) -> Result<Vec<String>, CliError> {
    let values = capsule
        .get("hidden_predicates")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "hidden_predicates must be an array: {}",
                capsule_path.display()
            ))
        })?;
    let mut predicates = Vec::new();
    for value in values {
        if let Some(predicate) = value.as_str() {
            predicates.push(predicate.to_string());
            continue;
        }
        let predicate_id = value
            .get("predicate_id")
            .and_then(serde_json::Value::as_str)
            .filter(|predicate| !predicate.is_empty())
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "hidden predicate id missing: {}",
                    capsule_path.display()
                ))
            })?;
        predicates.push(predicate_id.to_string());
    }
    Ok(predicates)
}

fn disclosure_hidden_predicates_json(
    hidden_predicates: &[String],
    first_hidden_projection_slot: usize,
) -> serde_json::Value {
    serde_json::Value::Array(
        hidden_predicates
            .iter()
            .enumerate()
            .map(|(index, predicate)| {
                disclosure_hidden_predicate_json(predicate, first_hidden_projection_slot + index)
            })
            .collect(),
    )
}

fn disclosure_hidden_predicate_json(predicate: &str, projection_slot: usize) -> serde_json::Value {
    if predicate == "amount_lte_100" {
        return serde_json::json!({
            "predicate_id": "amount_lte_100",
            "kind": "amount_cap",
            "field": "amount",
            "operator": "<=",
            "operand": "100",
            "unit": "USD",
            "result": true,
            "proof_ref": "selective-disclosure-proof",
            "projection_slot": projection_slot
        });
    }
    serde_json::json!({
        "predicate_id": predicate,
        "kind": "unsupported",
        "field": predicate,
        "operator": "unsupported",
        "operand": "unsupported",
        "unit": "unsupported",
        "result": false,
        "proof_ref": "unsupported",
        "projection_slot": projection_slot
    })
}

fn disclosure_projection_hidden_predicates(
    predicates: &[String],
) -> Vec<chio_selective_disclosure::BbsProjectionHiddenPredicate> {
    predicates
        .iter()
        .map(|predicate| {
            if predicate == "amount_lte_100" {
                return chio_selective_disclosure::BbsProjectionHiddenPredicate {
                    predicate_id: "amount_lte_100".to_string(),
                    field: "amount".to_string(),
                    operator: "<=".to_string(),
                    value_sha256: Some(chio_core::sha256_hex(b"100")),
                };
            }
            chio_selective_disclosure::BbsProjectionHiddenPredicate {
                predicate_id: predicate.clone(),
                field: predicate.clone(),
                operator: "unsupported".to_string(),
                value_sha256: None,
            }
        })
        .collect()
}

fn push_sensitivity_field(
    classes: &mut Vec<(&'static str, Vec<String>)>,
    class_id: &'static str,
    field: &str,
) {
    if let Some((_, fields)) = classes
        .iter_mut()
        .find(|(existing, _)| *existing == class_id)
    {
        if !fields.iter().any(|existing| existing == field) {
            fields.push(field.to_string());
        }
        return;
    }
    classes.push((class_id, vec![field.to_string()]));
}

fn disclosure_sensitivity_class(field: &str, leakage_kind: &str) -> &'static str {
    if field == "derived.crypto.issuer_status" || field == "derived.crypto.revocation_freshness" {
        return "runtime_assurance";
    }
    if field == "derived.crypto.presentation_timing" {
        return "timing";
    }
    if leakage_kind == "hidden_predicate" || field.contains("amount") || field.contains("budget") {
        return "amount_or_budget";
    }
    if field.contains("tool") {
        return "tool_identity";
    }
    if field.contains("tenant") {
        return "tenant_identifier";
    }
    if field.contains("seller") || field.contains("merchant") || field.contains("counterparty") {
        return "commerce_counterparty";
    }
    "capability_identifier"
}

fn normalize_disclosure_leakage_ledger(
    bundle: &Path,
    capsule_id: &str,
    profile_id: &str,
    audience: &str,
    subject_artifact_sha256: &str,
) -> Result<(), CliError> {
    let ledger_path = bundle.join("leakage-ledger.json");
    if !ledger_path.is_file() {
        return Ok(());
    }
    let mut ledger = read_json_value(&ledger_path)?;
    ledger["policy_profile_id"] = serde_json::Value::String(profile_id.to_string());
    ledger["subject_artifact_sha256"] =
        serde_json::Value::String(subject_artifact_sha256.to_string());
    ledger["generated_at"] = serde_json::Value::String("2026-06-10T00:00:00Z".to_string());
    ledger["audience"] = serde_json::Value::String(audience.to_string());
    ledger["tenant_leakage_notice_ref"] =
        serde_json::Value::String(format!("tenant-leakage-notice-{capsule_id}"));
    ledger["accepted"] = serde_json::Value::Bool(true);
    let mut total_score = 0_u64;
    let mut has_disclosure_entries = false;
    let entries = json_array_mut(&mut ledger, "entries", &ledger_path)?;
    for entry in entries.iter_mut() {
        let field = entry
            .get("field")
            .and_then(serde_json::Value::as_str)
            .filter(|field| !field.is_empty())
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "leakage ledger entry field missing: {}",
                    ledger_path.display()
                ))
            })?
            .to_string();
        let leakage_kind = entry
            .get("leakage_kind")
            .and_then(serde_json::Value::as_str)
            .filter(|kind| !kind.is_empty())
            .unwrap_or("disclosed_field")
            .to_string();
        if leakage_kind != "derived_fact" {
            has_disclosure_entries = true;
        }
        let score = normalize_leakage_ledger_entry(entry, &field, &leakage_kind);
        total_score = total_score.saturating_add(score);
    }
    if has_disclosure_entries {
        for (field, sensitivity_class) in DISCLOSURE_DERIVED_LEAKAGE_FACTS {
            if entries.iter().any(|entry| {
                entry.get("field").and_then(serde_json::Value::as_str) == Some(*field)
                    && entry
                        .get("leakage_kind")
                        .and_then(serde_json::Value::as_str)
                        == Some("derived_fact")
            }) {
                continue;
            }
            let mut entry = serde_json::json!({
                "field": field,
                "leakage_kind": "derived_fact",
                "sensitivity_class": sensitivity_class
            });
            let score = normalize_leakage_ledger_entry(&mut entry, field, "derived_fact");
            total_score = total_score.saturating_add(score);
            entries.push(entry);
        }
    }
    ledger["total_leakage_score"] =
        serde_json::Value::Number(serde_json::Number::from(total_score));
    ledger["max_allowed_leakage_score"] =
        serde_json::Value::Number(serde_json::Number::from(total_score));
    write_json_line_file(&ledger_path, &ledger)?;
    Ok(())
}

fn normalize_leakage_ledger_entry(
    entry: &mut serde_json::Value,
    field: &str,
    leakage_kind: &str,
) -> u64 {
    let entry_id = format!("leakage-{field}-{leakage_kind}");
    let score = disclosure_leakage_score(field, leakage_kind);
    set_json_string_if_missing(entry, "entry_id", &entry_id);
    set_json_string_if_missing(entry, "source", "disclosure-capsule");
    set_json_string_if_missing(entry, "disclosure_kind", leakage_kind);
    set_json_string_if_missing(
        entry,
        "sensitivity_class",
        disclosure_sensitivity_class(field, leakage_kind),
    );
    set_json_string_if_missing(entry, "value_class", disclosure_value_class(leakage_kind));
    set_json_string_if_missing(entry, "reason", "required by disclosure profile");
    set_json_string_if_missing(entry, "policy_rule", "profile.allowed_disclosure");
    if entry.get("derived_inferences").is_none() {
        entry["derived_inferences"] = serde_json::Value::Array(Vec::new());
    }
    if entry.get("cross_tenant_risk").is_none() {
        entry["cross_tenant_risk"] = serde_json::Value::Bool(false);
    }
    if entry.get("allowed_by_profile").is_none() {
        entry["allowed_by_profile"] = serde_json::Value::Bool(true);
    }
    if entry.get("score").is_none() {
        entry["score"] = serde_json::Value::Number(serde_json::Number::from(score));
    }
    if (leakage_kind == "hidden_predicate" || score > 1)
        && entry.get("residual_inference_note").is_none()
    {
        entry["residual_inference_note"] =
            serde_json::Value::String("predicate reveals capped amount band".to_string());
    }
    score
}

fn disclosure_leakage_score(field: &str, leakage_kind: &str) -> u64 {
    if leakage_kind == "hidden_predicate" || field.contains("amount") || field.contains("budget") {
        2
    } else {
        1
    }
}

fn disclosure_value_class(leakage_kind: &str) -> &'static str {
    match leakage_kind {
        "hidden_predicate" => "predicate",
        "derived_fact" => "derived_fact",
        _ => "direct_field",
    }
}

pub(super) fn add_disclosure_bbs_material_to_bundle(bundle: &Path) -> Result<(), CliError> {
    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph = read_json_value(&evidence_graph_path)?;
    add_disclosure_agent_web_crypto_context_material(bundle, &mut evidence_graph)?;
    refresh_signed_lineage_subgraph_digest(bundle)?;
    refresh_graph_node_hashes(bundle, &mut evidence_graph)?;
    write_json_line_file(&evidence_graph_path, &evidence_graph)?;
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path)?;

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport = read_json_value(&passport_path)?;
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    write_signed_transaction_passport(&passport_path, passport)?;
    sync_transaction_root_artifacts(bundle)?;
    Ok(())
}

fn sync_transaction_root_artifacts(bundle: &Path) -> Result<(), CliError> {
    let roots = bundle.join("roots");
    if !roots.is_dir() {
        return Ok(());
    }
    for artifact in [
        "claim-set.json",
        "evidence-graph.json",
        "transaction-passport.json",
        "verifier-policy.json",
    ] {
        let source = bundle.join(artifact);
        if source.is_file() {
            fs::copy(&source, roots.join(artifact))?;
        }
    }
    Ok(())
}

fn disclosure_projection_messages(
    fields: &[String],
    hidden_predicates: &[String],
) -> Result<Vec<chio_selective_disclosure::ProjectionMessage>, CliError> {
    let mut messages = fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let index = u16::try_from(index).map_err(|_| {
                CliError::cli_other_error(
                    "proof fixture disclosure field index exceeds u16".to_string(),
                )
            })?;
            Ok(chio_selective_disclosure::ProjectionMessage {
                index,
                field: field.clone(),
                encoding: "S".to_string(),
                bytes_hex: hex::encode(disclosure_projection_field_value(field)),
                wholesale_only: false,
            })
        })
        .collect::<Result<Vec<chio_selective_disclosure::ProjectionMessage>, CliError>>()?;

    for predicate in hidden_predicates {
        if let Some((field, value)) = disclosure_hidden_predicate_projection_message(predicate) {
            let index = u16::try_from(messages.len()).map_err(|_| {
                CliError::cli_other_error(
                    "proof fixture disclosure field index exceeds u16".to_string(),
                )
            })?;
            messages.push(chio_selective_disclosure::ProjectionMessage {
                index,
                field: field.to_string(),
                encoding: "S".to_string(),
                bytes_hex: hex::encode(value),
                wholesale_only: true,
            });
        }
    }

    Ok(messages)
}

fn disclosure_hidden_predicate_projection_message(
    predicate: &str,
) -> Option<(&'static str, &'static [u8])> {
    match predicate {
        "amount_lte_100" => Some(("amount", b"100")),
        _ => None,
    }
}

fn disclosure_indices(count: usize) -> Result<Vec<u16>, CliError> {
    (0..count)
        .map(|index| {
            u16::try_from(index).map_err(|_| {
                CliError::cli_other_error(
                    "proof fixture disclosure field index exceeds u16".to_string(),
                )
            })
        })
        .collect()
}

fn disclosure_projection_field_value(field: &str) -> &'static [u8] {
    match field {
        "capability_id" => b"cap-disclosure-valid",
        "tool_name" => b"read_refund_case",
        "decision" => b"allow",
        "customer_email" => b"buyer@example.com",
        _ => b"disclosed-fixture-value",
    }
}

fn append_unique_json_strings(
    value: &mut serde_json::Value,
    field: &str,
    additions: &[String],
) -> Result<(), CliError> {
    let array = json_array_mut(value, field, Path::new("privacy-profile.json"))?;
    let mut existing = array
        .iter()
        .filter_map(serde_json::Value::as_str)
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    for addition in additions {
        if existing.insert(addition.clone()) {
            array.push(serde_json::Value::String(addition.clone()));
        }
    }
    Ok(())
}

fn remove_json_strings(
    value: &mut serde_json::Value,
    field: &str,
    removals: &[String],
) -> Result<(), CliError> {
    let removals = removals.iter().map(String::as_str).collect::<BTreeSet<_>>();
    json_array_mut(value, field, Path::new("privacy-profile.json"))?
        .retain(|item| item.as_str().is_none_or(|item| !removals.contains(item)));
    Ok(())
}

fn refresh_claim_set_for_policy(
    bundle: &Path,
    passport_id: &str,
    issued_at: &str,
    policy: &serde_json::Value,
) -> Result<String, CliError> {
    let claims = policy
        .get("required_claims")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .filter(|claim| !claim.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    let claims = if claims.is_empty() {
        vec!["claim.transaction.passport_root_verified".to_string()]
    } else {
        claims
    };
    let claim_set = serde_json::json!({
        "schema": "chio.transaction.claim-set.v1",
        "id": format!("claim-set-{passport_id}"),
        "issued_at": issued_at,
        "claims": claims.into_iter().map(|claim_id| {
            serde_json::json!({
                "claim_id": claim_id,
                "status": "verified",
                "required_evidence": [
                    "transaction-passport.json",
                    "evidence-graph.json",
                    "verifier-policy.json"
                ],
                "evidence_refs": [
                    "transaction-passport.json",
                    "evidence-graph.json",
                    "verifier-policy.json"
                ],
                "verifier_module": "chio proof verify"
            })
        }).collect::<Vec<_>>()
    });
    let path = bundle.join("claim-set.json");
    write_json_line_file(&path, &claim_set)?;
    sha256_file(&path)
}

fn upsert_claim_set_graph_binding(
    evidence_graph: &mut serde_json::Value,
    claim_set_sha256: &str,
) -> Result<(), CliError> {
    let graph_path = Path::new("evidence-graph.json");
    let nodes = json_array_mut(evidence_graph, "nodes", graph_path)?;
    let verifier_policy_ids = nodes
        .iter()
        .filter(|node| {
            node.get("path").and_then(serde_json::Value::as_str) == Some("verifier-policy.json")
                || node.get("role").and_then(serde_json::Value::as_str)
                    == Some("verifier-policy")
        })
        .flat_map(|node| {
            [
                node.get("id").and_then(serde_json::Value::as_str),
                node.get("sha256").and_then(serde_json::Value::as_str),
                Some("verifier-policy"),
            ]
            .into_iter()
            .flatten()
            .map(str::to_string)
            .collect::<Vec<_>>()
        })
        .collect::<BTreeSet<_>>();
    let verifier_policy_sha256 = verifier_policy_ids
        .iter()
        .find(|id| id.len() == 64 && id.chars().all(|ch| ch.is_ascii_hexdigit()))
        .cloned()
        .unwrap_or_else(|| "verifier-policy".to_string());

    let mut claim_set_ids = BTreeSet::from([
        "claim-set".to_string(),
        claim_set_sha256.to_string(),
    ]);
    for node in nodes.iter() {
        if node.get("path").and_then(serde_json::Value::as_str) == Some("claim-set.json")
            || node.get("role").and_then(serde_json::Value::as_str) == Some("claim-set")
        {
            if let Some(id) = node.get("id").and_then(serde_json::Value::as_str) {
                claim_set_ids.insert(id.to_string());
            }
            if let Some(sha256) = node.get("sha256").and_then(serde_json::Value::as_str) {
                claim_set_ids.insert(sha256.to_string());
            }
        }
    }
    upsert_fixture_graph_node(
        nodes,
        claim_set_sha256,
        "claim-set.json",
        "chio.transaction.claim-set.v1",
        "claim-set",
        claim_set_sha256,
    );
    let mut verifier_policy_ids = verifier_policy_ids;
    verifier_policy_ids.insert(verifier_policy_sha256.clone());
    json_array_mut(evidence_graph, "edges", graph_path)?.retain(|edge| {
        if edge.get("predicate").and_then(serde_json::Value::as_str) != Some("binds") {
            return true;
        }
        let Some(from) = edge.get("from").and_then(serde_json::Value::as_str) else {
            return true;
        };
        let Some(to) = edge.get("to").and_then(serde_json::Value::as_str) else {
            return true;
        };
        !(claim_set_ids.contains(from) && verifier_policy_ids.contains(to))
    });
    upsert_fixture_graph_edge(
        json_array_mut(evidence_graph, "edges", graph_path)?,
        claim_set_sha256,
        &verifier_policy_sha256,
        "binds",
    );
    Ok(())
}

fn upsert_fixture_graph_edge(
    edges: &mut Vec<serde_json::Value>,
    from: &str,
    to: &str,
    predicate: &str,
) {
    edges.retain(|edge| {
        edge.get("from").and_then(serde_json::Value::as_str) != Some(from)
            || edge.get("to").and_then(serde_json::Value::as_str) != Some(to)
            || edge.get("predicate").and_then(serde_json::Value::as_str) != Some(predicate)
    });
    edges.push(serde_json::json!({
        "evidence_class": "digest-bound-reference",
        "from": from,
        "predicate": predicate,
        "to": to
    }));
}

fn graph_node_aliases(
    evidence_graph: &serde_json::Value,
    graph_path: &Path,
    path: &str,
    role: &str,
) -> Result<BTreeSet<String>, CliError> {
    let aliases = json_array(evidence_graph, "nodes", graph_path)?
        .iter()
        .filter(|node| {
            node.get("path").and_then(serde_json::Value::as_str) == Some(path)
                || node.get("role").and_then(serde_json::Value::as_str) == Some(role)
        })
        .flat_map(|node| {
            [
                node.get("id").and_then(serde_json::Value::as_str),
                node.get("sha256").and_then(serde_json::Value::as_str),
            ]
            .into_iter()
            .flatten()
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>()
        })
        .chain([role.to_string()])
        .collect();
    Ok(aliases)
}

fn graph_node_primary_id(
    evidence_graph: &serde_json::Value,
    graph_path: &Path,
    path: &str,
    role: &str,
) -> Result<String, CliError> {
    json_array(evidence_graph, "nodes", graph_path)?
        .iter()
        .find(|node| {
            node.get("path").and_then(serde_json::Value::as_str) == Some(path)
                || node.get("role").and_then(serde_json::Value::as_str) == Some(role)
        })
        .and_then(|node| node.get("id").and_then(serde_json::Value::as_str))
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "proof fixture evidence graph node missing for {path}: {}",
                graph_path.display()
            ))
        })
}

fn graph_node_primary_id_by_path(
    evidence_graph: &serde_json::Value,
    graph_path: &Path,
    path: &str,
) -> Result<Option<String>, CliError> {
    Ok(json_array(evidence_graph, "nodes", graph_path)?
        .iter()
        .find(|node| node.get("path").and_then(serde_json::Value::as_str) == Some(path))
        .and_then(|node| node.get("id").and_then(serde_json::Value::as_str))
        .filter(|id| !id.is_empty())
        .map(str::to_string))
}

fn remove_fixture_graph_edges(
    edges: &mut Vec<serde_json::Value>,
    from_aliases: &BTreeSet<String>,
    to_aliases: &BTreeSet<String>,
    predicate: &str,
) {
    edges.retain(|edge| {
        if edge.get("predicate").and_then(serde_json::Value::as_str) != Some(predicate) {
            return true;
        }
        let Some(from) = edge.get("from").and_then(serde_json::Value::as_str) else {
            return true;
        };
        let Some(to) = edge.get("to").and_then(serde_json::Value::as_str) else {
            return true;
        };
        !(from_aliases.contains(from) && to_aliases.contains(to))
    });
}

fn remove_fixture_graph_edges_from(
    edges: &mut Vec<serde_json::Value>,
    from_aliases: &BTreeSet<String>,
    predicate: &str,
) {
    edges.retain(|edge| {
        if edge.get("predicate").and_then(serde_json::Value::as_str) != Some(predicate) {
            return true;
        }
        let Some(from) = edge.get("from").and_then(serde_json::Value::as_str) else {
            return true;
        };
        !from_aliases.contains(from)
    });
}

fn write_signed_transaction_passport(
    path: &Path,
    passport: serde_json::Value,
) -> Result<(), CliError> {
    let keypair = collect::proof_collect_bundle_signer_from_env()?;
    write_transaction_passport_with_keypair(path, passport, &keypair)
}

fn write_fixture_signed_transaction_passport(
    path: &Path,
    passport: serde_json::Value,
) -> Result<(), CliError> {
    let keypair = Keypair::from_seed(&[7u8; 32]);
    write_transaction_passport_with_keypair(path, passport, &keypair)
}

fn write_transaction_passport_with_keypair(
    path: &Path,
    mut passport: serde_json::Value,
    keypair: &Keypair,
) -> Result<(), CliError> {
    passport["issuer"] =
        serde_json::Value::String(format!("did:chio:{}", keypair.public_key().to_hex()));
    passport["signature"] = serde_json::Value::String(String::new());
    let typed_passport: chio_control_plane::transaction_passport::TransactionPassport =
        serde_json::from_value(passport.clone())?;
    passport["signature"] = serde_json::Value::String(
        chio_control_plane::transaction_passport::sign_transaction_passport(
            &typed_passport,
            keypair,
        )
        .map_err(map_proof_error)?,
    );
    write_json_line_file(path, &passport)
}

fn normalize_enterprise_risk_lifecycle_replay(
    descriptor: &ProofFixtureDescriptor,
    out: &Path,
) -> Result<(), CliError> {
    let installed_path = installed_fixture_path(descriptor);
    if !descriptor.id.starts_with("enterprise-")
        && !installed_path.starts_with("enterprise-export/")
        && !installed_path.starts_with("trust-market/")
    {
        return Ok(());
    }
    let is_trust_market_fixture = installed_path.starts_with("trust-market/");
    let risk_report_paths = enterprise_risk_report_paths(out)?;
    if risk_report_paths.is_empty() {
        return Ok(());
    }
    let mut primary_risk_report_sha256 = None;
    for risk_report_path in risk_report_paths {
        let mut risk_report = read_json_value(&risk_report_path)?;
        let policy_id = risk_policy_id_for_report(&risk_report);
        let mut changed = ensure_enterprise_risk_policy_binding(&mut risk_report, &policy_id);
        changed |= ensure_enterprise_risk_financial_invariants(&mut risk_report);
        if risk_report
            .get("facility_lifecycle")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|lifecycle| !lifecycle.is_empty())
        {
        } else {
            if risk_report
                .get("coverage")
                .and_then(|coverage| coverage.get("status"))
                .and_then(serde_json::Value::as_str)
                == Some("bound")
                && risk_report
                    .get("facility")
                    .and_then(|facility| facility.get("state"))
                    .and_then(serde_json::Value::as_str)
                    == Some("reserve_held")
            {
                risk_report["facility"]["state"] =
                    serde_json::Value::String("coverage_bound".to_string());
            }
            let facility_state = risk_report
                .get("facility")
                .and_then(|facility| facility.get("state"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let lifecycle = enterprise_risk_lifecycle_for_state(facility_state);
            if !lifecycle.is_empty() {
                risk_report["facility_lifecycle"] = serde_json::Value::Array(lifecycle);
                ensure_enterprise_risk_policy_binding(&mut risk_report, &policy_id);
                changed = true;
            }
        }
        if changed {
            if is_trust_market_fixture {
                sign_trust_market_artifact(&mut risk_report)?;
            } else {
                sign_enterprise_risk_comptroller_report(&mut risk_report)?;
            }
            write_json_line_file(&risk_report_path, &risk_report)?;
        }
        if risk_report_path.file_name().and_then(|name| name.to_str())
            == Some("risk-comptroller-report.json")
        {
            primary_risk_report_sha256 = Some(sha256_file(&risk_report_path)?);
        }
    }
    if let Some(risk_report_sha256) = primary_risk_report_sha256 {
        rebind_enterprise_risk_report_digest_refs(out, &risk_report_sha256)?;
    }
    if descriptor.id != "enterprise-export-bundle-digest-mismatch" {
        refresh_enterprise_export_bundle_digest(out)?;
    }

    refresh_enterprise_graph_and_passport(out)?;
    Ok(())
}

fn enterprise_risk_report_paths(out: &Path) -> Result<Vec<std::path::PathBuf>, CliError> {
    let mut paths = Vec::new();
    collect_enterprise_risk_report_paths(out, &mut paths)?;
    paths.sort();
    Ok(paths)
}

fn collect_enterprise_risk_report_paths(
    path: &Path,
    paths: &mut Vec<std::path::PathBuf>,
) -> Result<(), CliError> {
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            collect_enterprise_risk_report_paths(&entry?.path(), paths)?;
        }
        return Ok(());
    }
    if !path.is_file() {
        return Ok(());
    }
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(());
    };
    if file_name.starts_with("risk-comptroller-report") && file_name.ends_with(".json") {
        paths.push(path.to_path_buf());
    }
    Ok(())
}

fn risk_policy_id_for_report(risk_report: &serde_json::Value) -> String {
    if let Some(policy_id) = risk_report
        .get("facility")
        .and_then(|facility| facility.get("policy_id"))
        .and_then(serde_json::Value::as_str)
        .filter(|policy_id| !policy_id.is_empty())
    {
        return policy_id.to_string();
    }
    risk_report
        .get("facility")
        .and_then(|facility| facility.get("facility_id"))
        .and_then(serde_json::Value::as_str)
        .filter(|facility_id| !facility_id.is_empty())
        .map(|facility_id| format!("risk-policy-{facility_id}"))
        .unwrap_or_else(|| "risk-policy-enterprise-valid".to_string())
}

fn ensure_enterprise_risk_policy_binding(
    risk_report: &mut serde_json::Value,
    policy_id: &str,
) -> bool {
    let mut changed = false;
    if let Some(facility) = risk_report
        .get_mut("facility")
        .and_then(serde_json::Value::as_object_mut)
    {
        let needs_policy = facility
            .get("policy_id")
            .and_then(serde_json::Value::as_str)
            .map(str::is_empty)
            .unwrap_or(true);
        if needs_policy {
            facility.insert(
                "policy_id".to_string(),
                serde_json::Value::String(policy_id.to_string()),
            );
            changed = true;
        }
    }
    if let Some(transitions) = risk_report
        .get_mut("facility_lifecycle")
        .and_then(serde_json::Value::as_array_mut)
    {
        for transition in transitions {
            let Some(transition) = transition.as_object_mut() else {
                continue;
            };
            let needs_policy = transition
                .get("policy_id")
                .and_then(serde_json::Value::as_str)
                .map(str::is_empty)
                .unwrap_or(true);
            if needs_policy {
                transition.insert(
                    "policy_id".to_string(),
                    serde_json::Value::String(policy_id.to_string()),
                );
                changed = true;
            }
        }
    }
    changed
}

fn ensure_enterprise_risk_financial_invariants(risk_report: &mut serde_json::Value) -> bool {
    let report_id = risk_report_string(risk_report, &["id"]);
    let coverage_id = risk_report_string(risk_report, &["coverage", "coverage_id"]);
    let order_id = risk_report_string(risk_report, &["order_id"]);
    let subject = risk_report_string(risk_report, &["coverage", "subject"]);
    let currency = risk_report_string(risk_report, &["coverage", "currency"]);
    let exposure_units = risk_report_u64(risk_report, &["coverage", "exposure_units"]);
    let premium_units = exposure_units.div_ceil(100).max(1);
    let is_market_context = report_id.contains("-market-");
    let mut premium = serde_json::json!({
        "premium_id": format!("premium-{coverage_id}"),
        "quote_ref": if is_market_context {
            "provider-selection-report"
        } else {
            "data-governance-report"
        },
        "coverage_id": coverage_id,
        "order_id": order_id,
        "subject": subject,
        "currency": currency,
        "coverage_exposure_units": exposure_units,
        "quoted_premium_units": premium_units,
        "bound_premium_units": premium_units,
        "collected_premium_units": if is_market_context { 0 } else { premium_units },
        "status": if is_market_context { "bound" } else { "collected" }
    });
    if !is_market_context {
        premium["observed_payment_ref"] = serde_json::Value::String("evidence-export-bundle".into());
    }

    let committed_units = risk_report_u64(risk_report, &["facility", "capital_units"]);
    let held_units = risk_report_u64(risk_report, &["facility", "reserve_units"]);
    let settlement_units = risk_report_u64(risk_report, &["reconciliation", "settlement_units"]);
    let payout_units = risk_report_u64(risk_report, &["reconciliation", "payout_units"]);
    let drawn_units = if settlement_units == 0 { payout_units } else { 0 };
    let disbursed_units = settlement_units;
    let deductions = held_units
        .saturating_add(drawn_units)
        .saturating_add(disbursed_units);
    let source_ref = risk_report
        .get("facility_lifecycle")
        .and_then(serde_json::Value::as_array)
        .and_then(|transitions| transitions.first())
        .and_then(|transition| transition.get("authority_receipt_ref"))
        .and_then(serde_json::Value::as_str)
        .filter(|source_ref| !source_ref.is_empty())
        .unwrap_or("approval-case");
    let capital_decomposition = serde_json::json!({
        "decomposition_id": format!(
            "capital-decomposition-{}",
            risk_report_string(risk_report, &["facility", "facility_id"])
        ),
        "source_kind": "facility_commitment",
        "source_ref": source_ref,
        "currency": risk_report_string(risk_report, &["facility", "capital_currency"]),
        "committed_units": committed_units,
        "held_units": held_units,
        "drawn_units": drawn_units,
        "disbursed_units": disbursed_units,
        "impaired_units": 0,
        "available_units": committed_units.saturating_sub(deductions)
    });

    let mut changed = false;
    if risk_report.get("premium") != Some(&premium) {
        risk_report["premium"] = premium;
        changed = true;
    }
    if risk_report.get("capital_decomposition") != Some(&capital_decomposition) {
        risk_report["capital_decomposition"] = capital_decomposition;
        changed = true;
    }
    changed
}

fn risk_report_string(risk_report: &serde_json::Value, path: &[&str]) -> String {
    risk_report_path_value(risk_report, path)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn risk_report_u64(risk_report: &serde_json::Value, path: &[&str]) -> u64 {
    risk_report_path_value(risk_report, path)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default()
}

fn risk_report_path_value<'a>(
    risk_report: &'a serde_json::Value,
    path: &[&str],
) -> Option<&'a serde_json::Value> {
    let mut value = risk_report;
    for segment in path {
        value = value.get(*segment)?;
    }
    Some(value)
}

fn normalize_enterprise_claim_payout_capital_instructions(
    descriptor: &ProofFixtureDescriptor,
    out: &Path,
) -> Result<(), CliError> {
    if !descriptor.id.starts_with("enterprise-")
        && !installed_fixture_path(descriptor).starts_with("enterprise-export/")
    {
        return Ok(());
    }
    if descriptor.id == "enterprise-risk-payout-preobserved-instruction" {
        return Ok(());
    }
    let risk_report_path = out.join("risk-comptroller-report.json");
    if !risk_report_path.is_file() {
        return Ok(());
    }
    let mut risk_report = read_json_value(&risk_report_path)?;
    let Some(entries) = risk_report
        .get("reserve_ledger")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(());
    };
    let claim_payout_entries = entries
        .iter()
        .filter(|entry| {
            entry.get("lane").and_then(serde_json::Value::as_str) == Some("claim_payout")
        })
        .collect::<Vec<_>>();
    if claim_payout_entries.is_empty() {
        return Ok(());
    }
    let Some(order_id) = risk_report
        .get("order_id")
        .and_then(serde_json::Value::as_str)
    else {
        return Ok(());
    };

    let capital_instructions = claim_payout_entries
        .iter()
        .map(|entry| {
            let entry_id = entry
                .get("entry_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            serde_json::json!({
                "instruction_id": format!("capital-instruction-{entry_id}"),
                "reserve_entry_id": entry_id,
                "order_id": order_id,
                "claim_id": entry.get("claim_id").cloned().unwrap_or_default(),
                "reserve_ref": entry.get("reserve_ref").cloned().unwrap_or_default(),
                "currency": entry.get("currency").cloned().unwrap_or_default(),
                "units": entry.get("units").cloned().unwrap_or_default(),
                "settlement_ref": entry.get("settlement_ref").cloned().unwrap_or_default(),
                "intended_action": "transfer_funds",
                "source_kind": "facility_commitment",
                "intended_state": "pending_execution",
                "reconciled_state": "not_observed"
            })
        })
        .collect::<Vec<_>>();
    if risk_report
        .get("capital_instructions")
        .and_then(serde_json::Value::as_array)
        == Some(&capital_instructions)
    {
        return Ok(());
    }

    risk_report["capital_instructions"] = serde_json::Value::Array(capital_instructions);
    sign_enterprise_risk_comptroller_report(&mut risk_report)?;
    write_json_line_file(&risk_report_path, &risk_report)?;
    let risk_report_sha256 = sha256_file(&risk_report_path)?;
    rebind_enterprise_risk_report_digest_refs(out, &risk_report_sha256)?;
    if descriptor.id != "enterprise-export-bundle-digest-mismatch" {
        refresh_enterprise_export_bundle_digest(out)?;
    }
    refresh_enterprise_graph_and_passport(out)?;
    Ok(())
}

fn normalize_enterprise_preobserved_capital_instruction(
    descriptor: &ProofFixtureDescriptor,
    out: &Path,
) -> Result<(), CliError> {
    if descriptor.id != "enterprise-risk-payout-preobserved-instruction" {
        return Ok(());
    }
    let risk_report_path = out.join("risk-comptroller-report.json");
    if !risk_report_path.is_file() {
        return Ok(());
    }
    let mut risk_report = read_json_value(&risk_report_path)?;
    if risk_report
        .get("capital_instructions")
        .and_then(serde_json::Value::as_array)
        .and_then(|instructions| instructions.first())
        .and_then(|instruction| instruction.get("reconciled_state"))
        .and_then(serde_json::Value::as_str)
        == Some("matched")
        && risk_report
            .get("capital_instructions")
            .and_then(serde_json::Value::as_array)
            .and_then(|instructions| instructions.first())
            .and_then(|instruction| instruction.get("observed_execution_ref"))
            .and_then(serde_json::Value::as_str)
            .is_some()
    {
        return Ok(());
    }

    let entry = risk_report
        .get("reserve_ledger")
        .and_then(serde_json::Value::as_array)
        .and_then(|entries| {
            entries.iter().find(|entry| {
                entry.get("lane").and_then(serde_json::Value::as_str) == Some("claim_payout")
            })
        })
        .cloned()
        .ok_or_else(|| {
            CliError::cli_other_error(
                "enterprise preobserved payout fixture missing claim_payout ledger entry",
            )
        })?;
    let order_id = required_json_string(&risk_report, "order_id", &risk_report_path)?.to_string();
    risk_report["coverage"]["covered_claim_ids"] =
        serde_json::json!([entry.get("claim_id").cloned().unwrap_or_default()]);
    risk_report["appeals"] = serde_json::json!([
        {
            "appeal_id": "appeal-enterprise-preobserved",
            "claim_id": entry.get("claim_id").cloned().unwrap_or_default(),
            "status": "open",
            "blocks": ["facility_closure"]
        }
    ]);
    risk_report["capital_instructions"] = serde_json::json!([
        {
            "instruction_id": "capital-instruction-preobserved-claim-payout",
            "reserve_entry_id": entry.get("entry_id").cloned().unwrap_or_default(),
            "order_id": order_id,
            "claim_id": entry.get("claim_id").cloned().unwrap_or_default(),
            "reserve_ref": entry.get("reserve_ref").cloned().unwrap_or_default(),
            "currency": entry.get("currency").cloned().unwrap_or_default(),
            "units": entry.get("units").cloned().unwrap_or_default(),
            "settlement_ref": entry.get("settlement_ref").cloned().unwrap_or_default(),
            "intended_action": "transfer_funds",
            "source_kind": "facility_commitment",
            "intended_state": "pending_execution",
            "reconciled_state": "matched",
            "observed_execution_ref": "claim-payout-wire-preobserved"
        }
    ]);
    sign_enterprise_risk_comptroller_report(&mut risk_report)?;
    write_json_line_file(&risk_report_path, &risk_report)?;
    let risk_report_sha256 = sha256_file(&risk_report_path)?;
    rebind_enterprise_risk_report_digest_refs(out, &risk_report_sha256)?;
    refresh_enterprise_export_bundle_digest(out)?;
    refresh_enterprise_graph_and_passport(out)?;
    Ok(())
}

fn normalize_enterprise_disclosure_projection_ref(
    descriptor: &ProofFixtureDescriptor,
    out: &Path,
) -> Result<(), CliError> {
    if !descriptor.id.starts_with("enterprise-")
        && !installed_fixture_path(descriptor).starts_with("enterprise-export/")
    {
        return Ok(());
    }
    let report_path = out.join("disclosure-capsule.json");
    if !report_path.is_file() {
        return Ok(());
    }
    let mut report = read_json_value(&report_path)?;
    if report.get("schema").and_then(serde_json::Value::as_str)
        != Some(chio_selective_disclosure::DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1)
    {
        return Ok(());
    }
    if report
        .get("projection_manifest_ref")
        .and_then(serde_json::Value::as_str)
        == Some(chio_selective_disclosure::PROJECTION_VERSION_RECEIPT_V1)
    {
        return Ok(());
    }

    report["projection_manifest_ref"] = serde_json::Value::String(
        chio_selective_disclosure::PROJECTION_VERSION_RECEIPT_V1.to_string(),
    );
    write_json_line_file(&report_path, &report)?;
    let report_sha256 = sha256_file(&report_path)?;
    rebind_enterprise_artifact_digest_ref(out, "disclosure-capsule.json", &report_sha256)?;
    if descriptor.id != "enterprise-export-bundle-digest-mismatch" {
        refresh_enterprise_export_bundle_digest(out)?;
    }
    refresh_enterprise_graph_and_passport(out)?;
    Ok(())
}

fn normalize_enterprise_export_verifier_report_ref(
    descriptor: &ProofFixtureDescriptor,
    out: &Path,
) -> Result<(), CliError> {
    if !descriptor.id.starts_with("enterprise-")
        && !installed_fixture_path(descriptor).starts_with("enterprise-export/")
    {
        return Ok(());
    }
    let export_bundle_path = out.join("evidence-export-bundle.json");
    if !export_bundle_path.is_file() {
        return Ok(());
    }

    let verifier_report_path = enterprise_verifier_report_path(out)?;
    let verifier_report_sha256 = sha256_file(&out.join(&verifier_report_path))?;
    let mut export_bundle = read_json_value(&export_bundle_path)?;
    let artifacts = json_array_mut(&mut export_bundle, "artifacts", &export_bundle_path)?;
    if !ensure_enterprise_export_artifact_ref(
        artifacts,
        "verifier_report",
        &verifier_report_path,
        &verifier_report_sha256,
    ) {
        return Ok(());
    }

    write_json_line_file(&export_bundle_path, &export_bundle)?;
    if descriptor.id != "enterprise-export-bundle-digest-mismatch" {
        refresh_enterprise_export_bundle_digest(out)?;
    }
    refresh_enterprise_graph_and_passport(out)?;
    Ok(())
}

fn normalize_enterprise_telemetry_passport_mismatch(
    descriptor: &ProofFixtureDescriptor,
    out: &Path,
) -> Result<(), CliError> {
    if descriptor.id != "enterprise-telemetry-passport-mismatch" {
        return normalize_enterprise_telemetry_siem_without_receipt(descriptor, out);
    }
    let telemetry_path = out.join("telemetry-projection.json");
    if !telemetry_path.is_file() {
        return Ok(());
    }
    let mut telemetry = read_json_value(&telemetry_path)?;
    if telemetry
        .get("passport_id")
        .and_then(serde_json::Value::as_str)
        == Some("passport-enterprise-other")
    {
        return Ok(());
    }
    telemetry["passport_id"] = serde_json::Value::String("passport-enterprise-other".to_string());
    write_json_line_file(&telemetry_path, &telemetry)?;
    refresh_enterprise_graph_and_passport(out)?;
    Ok(())
}

fn normalize_enterprise_telemetry_siem_without_receipt(
    descriptor: &ProofFixtureDescriptor,
    out: &Path,
) -> Result<(), CliError> {
    if descriptor.id != "enterprise-telemetry-siem-without-receipt" {
        return Ok(());
    }
    let telemetry_path = out.join("telemetry-projection.json");
    if !telemetry_path.is_file() {
        return Ok(());
    }
    let mut telemetry = read_json_value(&telemetry_path)?;
    let Some(events) = telemetry
        .get_mut("events")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return Ok(());
    };
    if events.iter().any(|event| {
        event.get("event_kind").and_then(serde_json::Value::as_str) == Some("siem_export")
    }) {
        return Ok(());
    }
    let data_governance_path = out.join("data-governance-report.json");
    events.push(serde_json::json!({
        "event_id": "siem-export-event",
        "event_kind": "siem_export",
        "artifact_ref": "data-governance-report.json",
        "artifact_sha256": sha256_file(&data_governance_path)?
    }));
    write_json_line_file(&telemetry_path, &telemetry)?;
    refresh_enterprise_graph_and_passport(out)?;
    Ok(())
}

fn enterprise_verifier_report_path(out: &Path) -> Result<String, CliError> {
    let passport_path = out.join("transaction-passport.json");
    let passport = read_json_value(&passport_path)?;
    let passport_id = required_json_string(&passport, "id", &passport_path)?;
    let issued_at = required_json_string(&passport, "issued_at", &passport_path)
        .unwrap_or_else(|_| "2026-06-10T00:00:00Z".to_string());
    let verifier_report_path = out.join("verifier-report.json");
    let verifier_report = serde_json::json!({
        "schema": "chio.transaction.verifier-report.v1",
        "id": format!("enterprise-verifier-report-{passport_id}"),
        "issued_at": issued_at,
        "verdict": "verified",
        "passport_id": passport_id
    });
    let should_write = if verifier_report_path.is_file() {
        read_json_value(&verifier_report_path)? != verifier_report
    } else {
        true
    };
    if should_write {
        write_json_line_file(&verifier_report_path, &verifier_report)?;
    }
    Ok("verifier-report.json".to_string())
}

fn ensure_enterprise_export_artifact_ref(
    artifacts: &mut Vec<serde_json::Value>,
    role: &str,
    artifact_path: &str,
    artifact_sha256: &str,
) -> bool {
    let replacement = enterprise_export_artifact_ref(role, artifact_path, artifact_sha256);
    if let Some(existing) = artifacts
        .iter_mut()
        .find(|artifact| artifact.get("role").and_then(serde_json::Value::as_str) == Some(role))
    {
        if *existing == replacement {
            return false;
        }
        *existing = replacement;
        return true;
    }

    let insert_at = artifacts
        .iter()
        .position(|artifact| {
            artifact.get("role").and_then(serde_json::Value::as_str) == Some("transaction_passport")
        })
        .map(|index| index + 1)
        .unwrap_or(artifacts.len());
    artifacts.insert(insert_at, replacement);
    true
}

fn enterprise_export_artifact_ref(
    role: &str,
    artifact_path: &str,
    artifact_sha256: &str,
) -> serde_json::Value {
    serde_json::json!({
        "role": role,
        "path": artifact_path,
        "sha256": artifact_sha256
    })
}

fn refresh_enterprise_graph_and_passport(out: &Path) -> Result<(), CliError> {
    let evidence_graph_path = out.join("evidence-graph.json");
    if !evidence_graph_path.is_file() {
        return Ok(());
    }
    let mut evidence_graph = read_json_value(&evidence_graph_path)?;
    refresh_graph_node_hashes(out, &mut evidence_graph)?;
    write_json_line_file(&evidence_graph_path, &evidence_graph)?;

    let passport_path = out.join("transaction-passport.json");
    if !passport_path.is_file() {
        return Ok(());
    }
    let mut passport = read_json_value(&passport_path)?;
    passport["evidence_graph_sha256"] =
        serde_json::Value::String(sha256_file(&evidence_graph_path)?);
    write_fixture_signed_transaction_passport(&passport_path, passport)?;
    Ok(())
}

fn refresh_enterprise_export_bundle_digest(out: &Path) -> Result<(), CliError> {
    let export_bundle_path = out.join("evidence-export-bundle.json");
    if !export_bundle_path.is_file() {
        return Ok(());
    }
    let mut export_bundle = read_json_value(&export_bundle_path)?;
    let artifacts = export_bundle
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "proof fixture export bundle artifacts missing: {}",
                export_bundle_path.display()
            ))
        })?;
    let canonical = chio_core_types::canonical_json_bytes(artifacts).map_err(|error| {
        CliError::cli_other_error(format!(
            "proof fixture export bundle digest failed: {error}"
        ))
    })?;
    let bundle_digest = chio_core_types::sha256_hex(&canonical);
    export_bundle["bundle_digest"] = serde_json::Value::String(bundle_digest.clone());
    write_json_line_file(&export_bundle_path, &export_bundle)?;

    let approval_case_path = out.join("approval-case.json");
    if approval_case_path.is_file() {
        let mut approval_case = read_json_value(&approval_case_path)?;
        if approval_case.get("evidence_export_bundle_digest").is_some() {
            approval_case["evidence_export_bundle_digest"] =
                serde_json::Value::String(bundle_digest);
            sign_enterprise_approval_case(&mut approval_case)?;
            write_json_line_file(&approval_case_path, &approval_case)?;
        }
    }
    Ok(())
}

fn rebind_enterprise_artifact_digest_ref(
    out: &Path,
    artifact_path: &str,
    artifact_sha256: &str,
) -> Result<(), CliError> {
    let export_bundle_path = out.join("evidence-export-bundle.json");
    if !export_bundle_path.is_file() {
        return Ok(());
    }
    let mut export_bundle = read_json_value(&export_bundle_path)?;
    if rebind_artifact_digest_ref(&mut export_bundle, artifact_path, artifact_sha256) {
        write_json_line_file(&export_bundle_path, &export_bundle)?;
    }
    Ok(())
}

fn sign_enterprise_approval_case(approval_case: &mut serde_json::Value) -> Result<(), CliError> {
    if !approval_case.is_object() {
        return Err(CliError::cli_other_error(
            "proof fixture approval case must be a JSON object",
        ));
    }
    if let Some(fields) = approval_case.as_object_mut() {
        fields.remove("signature");
    }
    let keypair = Keypair::from_seed(&[62u8; 32]);
    let (signature, _) = keypair.sign_canonical(approval_case).map_err(|error| {
        CliError::cli_other_error(format!(
            "proof fixture approval case signing failed: {error}"
        ))
    })?;
    approval_case["signature"] = serde_json::Value::String(format!(
        "sig-ed25519:{}:{}",
        keypair.public_key().to_hex(),
        signature.to_hex()
    ));
    Ok(())
}

fn sign_enterprise_risk_comptroller_report(
    risk_report: &mut serde_json::Value,
) -> Result<(), CliError> {
    if !risk_report.is_object() {
        return Err(CliError::cli_other_error(
            "proof fixture risk comptroller report must be a JSON object",
        ));
    }
    if let Some(fields) = risk_report.as_object_mut() {
        fields.remove("signature");
    }
    let keypair = Keypair::from_seed(&ENTERPRISE_RISK_COMPTROLLER_SIGNATURE_SEED);
    let (signature, _) = keypair.sign_canonical(risk_report).map_err(|error| {
        CliError::cli_other_error(format!(
            "proof fixture risk comptroller report signing failed: {error}"
        ))
    })?;
    risk_report["signature"] = serde_json::Value::String(format!(
        "sig-ed25519:{}:{}",
        keypair.public_key().to_hex(),
        signature.to_hex()
    ));
    Ok(())
}

fn sign_trust_market_artifact(artifact: &mut serde_json::Value) -> Result<(), CliError> {
    if !artifact.is_object() {
        return Err(CliError::cli_other_error(
            "proof fixture trust-market artifact must be a JSON object",
        ));
    }
    if let Some(fields) = artifact.as_object_mut() {
        fields.remove("signature");
    }
    let keypair = Keypair::from_seed(&TRUST_MARKET_AUTHORITY_SIGNATURE_SEED);
    let (signature, _) = keypair.sign_canonical(artifact).map_err(|error| {
        CliError::cli_other_error(format!(
            "proof fixture trust-market artifact signing failed: {error}"
        ))
    })?;
    artifact["signature"] = serde_json::Value::String(format!(
        "sig-ed25519:{}:{}",
        keypair.public_key().to_hex(),
        signature.to_hex()
    ));
    Ok(())
}

fn rebind_artifact_digest_ref(
    value: &mut serde_json::Value,
    artifact_path: &str,
    artifact_sha256: &str,
) -> bool {
    match value {
        serde_json::Value::Array(items) => {
            let mut changed = false;
            for item in items {
                changed |= rebind_artifact_digest_ref(item, artifact_path, artifact_sha256);
            }
            changed
        }
        serde_json::Value::Object(entries) => {
            let mut changed = false;
            let references_artifact = entries
                .get("artifact_ref")
                .or_else(|| entries.get("path"))
                .and_then(serde_json::Value::as_str)
                == Some(artifact_path);
            if references_artifact {
                if entries.contains_key("artifact_sha256") {
                    entries.insert(
                        "artifact_sha256".to_string(),
                        serde_json::Value::String(artifact_sha256.to_string()),
                    );
                    changed = true;
                }
                if entries.contains_key("sha256") {
                    entries.insert(
                        "sha256".to_string(),
                        serde_json::Value::String(artifact_sha256.to_string()),
                    );
                    changed = true;
                }
            }
            for item in entries.values_mut() {
                changed |= rebind_artifact_digest_ref(item, artifact_path, artifact_sha256);
            }
            changed
        }
        _ => false,
    }
}

fn rebind_enterprise_risk_report_digest_refs(
    out: &Path,
    risk_report_sha256: &str,
) -> Result<(), CliError> {
    for artifact in ["telemetry-projection.json", "evidence-export-bundle.json"] {
        let path = out.join(artifact);
        if !path.is_file() {
            continue;
        }
        let mut value = read_json_value(&path)?;
        if rebind_risk_report_digest_ref(&mut value, risk_report_sha256) {
            write_json_line_file(&path, &value)?;
        }
    }
    Ok(())
}

fn rebind_risk_report_digest_ref(value: &mut serde_json::Value, risk_report_sha256: &str) -> bool {
    match value {
        serde_json::Value::Array(items) => {
            let mut changed = false;
            for item in items {
                changed |= rebind_risk_report_digest_ref(item, risk_report_sha256);
            }
            changed
        }
        serde_json::Value::Object(entries) => {
            let mut changed = false;
            let references_risk_report = entries
                .get("artifact_ref")
                .or_else(|| entries.get("path"))
                .and_then(serde_json::Value::as_str)
                == Some("risk-comptroller-report.json");
            if references_risk_report {
                if entries.contains_key("artifact_sha256") {
                    entries.insert(
                        "artifact_sha256".to_string(),
                        serde_json::Value::String(risk_report_sha256.to_string()),
                    );
                    changed = true;
                }
                if entries.contains_key("sha256") {
                    entries.insert(
                        "sha256".to_string(),
                        serde_json::Value::String(risk_report_sha256.to_string()),
                    );
                    changed = true;
                }
            }
            for item in entries.values_mut() {
                changed |= rebind_risk_report_digest_ref(item, risk_report_sha256);
            }
            changed
        }
        _ => false,
    }
}

fn enterprise_risk_lifecycle_for_state(state: &str) -> Vec<serde_json::Value> {
    let transitions = [
        serde_json::json!({
            "transition_id": "facility-transition-underwriting-ready",
            "from_state": "evidence_cold",
            "to_state": "underwriting_ready",
            "authority_receipt_ref": "approval-case",
            "evidence_ref": "data-governance-report"
        }),
        serde_json::json!({
            "transition_id": "facility-transition-facility-granted",
            "from_state": "underwriting_ready",
            "to_state": "facility_granted",
            "authority_receipt_ref": "approval-case",
            "evidence_ref": "data-governance-report"
        }),
        serde_json::json!({
            "transition_id": "facility-transition-reserve-held",
            "from_state": "facility_granted",
            "to_state": "reserve_held",
            "authority_receipt_ref": "approval-case",
            "evidence_ref": "data-governance-report"
        }),
        serde_json::json!({
            "transition_id": "facility-transition-coverage-bound",
            "from_state": "reserve_held",
            "to_state": "coverage_bound",
            "authority_receipt_ref": "approval-case",
            "evidence_ref": "data-governance-report"
        }),
        serde_json::json!({
            "transition_id": "facility-transition-settlement-matched",
            "from_state": "coverage_bound",
            "to_state": "settlement_matched",
            "authority_receipt_ref": "approval-case",
            "evidence_ref": "evidence-export-bundle"
        }),
    ];
    let take = match state {
        "underwriting_ready" => 1,
        "facility_granted" => 2,
        "reserve_held" => 3,
        "coverage_bound" => 4,
        "settlement_matched" => 5,
        _ => 0,
    };
    transitions.into_iter().take(take).collect()
}

fn refresh_signed_lineage_subgraph_digest(bundle: &Path) -> Result<(), CliError> {
    let path = bundle.join("signed-lineage-subgraph.json");
    let mut value = read_json_value(&path)?;
    normalize_signed_lineage_subgraph_metadata(bundle, &path, &mut value)?;
    let mut lineage: chio_selective_disclosure::SignedLineageSubgraph =
        serde_json::from_value(value).map_err(|error| {
            CliError::cli_other_error(format!("signed lineage subgraph parse failed: {error}"))
        })?;
    lineage.subgraph_sha256 =
        chio_selective_disclosure::compute_signed_lineage_subgraph_digest(&lineage)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    lineage.signature = chio_selective_disclosure::sign_lineage_subgraph(
        &lineage,
        &Keypair::from_seed(&DISCLOSURE_LINEAGE_SIGNATURE_SEED),
    )
    .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    write_json_line_file(&path, &lineage)?;
    Ok(())
}

fn normalize_signed_lineage_subgraph_metadata(
    bundle: &Path,
    path: &Path,
    lineage: &mut serde_json::Value,
) -> Result<(), CliError> {
    if !lineage.is_object() {
        return Err(CliError::cli_other_error(format!(
            "signed lineage subgraph must be a JSON object: {}",
            path.display()
        )));
    }
    set_json_string_if_missing(lineage, "policy_profile_id", "privacy-profile-valid");
    set_json_string_if_missing(lineage, "generated_at", "2026-06-10T00:00:00Z");
    set_json_string_if_missing(lineage, "audience", "https://auditor.example/chio");
    set_json_string_if_missing(
        lineage,
        "challenge_nonce",
        "disclosure-lineage-fixture-nonce",
    );
    set_json_string_if_missing(lineage, "checkpoint_ref", "checkpoint-disclosure-valid");
    set_json_string_if_missing(lineage, "required_evidence_class", "observed");
    set_json_string_if_missing(
        lineage,
        "lineage_anchor_ref",
        "lineage-anchor-local-fixture",
    );
    normalize_lineage_nodes(path, lineage)?;
    normalize_lineage_edges(path, lineage)?;
    let computed_frontier_sha256 = lineage_frontier_sha256_from_json(path, lineage)?;
    let max_depth = lineage_max_depth_from_json(path, lineage)?;
    if lineage.get("max_depth").is_none() {
        lineage["max_depth"] = serde_json::Value::Number(serde_json::Number::from(max_depth));
    }
    let redactions = lineage
        .get("redactions")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    set_json_string_if_missing(lineage, "frontier_sha256", &computed_frontier_sha256);
    let checkpoint_ref = lineage
        .get("checkpoint_ref")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("checkpoint-disclosure-valid")
        .to_string();
    let frontier_sha256 = lineage
        .get("frontier_sha256")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    set_json_string_if_missing(
        lineage,
        "checkpoint_inclusion_sha256",
        &chio_core::sha256_hex(format!("{checkpoint_ref}|{frontier_sha256}").as_bytes()),
    );
    set_json_string(
        lineage,
        "redaction_map_sha256",
        sha256_json_value(&redactions)?,
    );
    let leakage_ledger_path = bundle.join("leakage-ledger.json");
    let leakage_ledger_sha256 = if leakage_ledger_path.is_file() {
        sha256_file(&leakage_ledger_path)?
    } else {
        chio_core::sha256_hex(b"missing-leakage-ledger")
    };
    set_json_string(lineage, "leakage_ledger_sha256", leakage_ledger_sha256);
    let projection_manifest_path = bundle.join("bbs-projection-manifest.json");
    let projection_manifest_sha256 = if projection_manifest_path.is_file() {
        sha256_file(&projection_manifest_path)?
    } else {
        chio_core::sha256_hex(chio_selective_disclosure::PROJECTION_VERSION_RECEIPT_V1.as_bytes())
    };
    set_json_string(
        lineage,
        "projection_manifest_sha256",
        projection_manifest_sha256,
    );
    Ok(())
}

fn normalize_lineage_nodes(path: &Path, lineage: &mut serde_json::Value) -> Result<(), CliError> {
    let root_ids = json_string_array(lineage, "root_receipt_ids", path)?;
    let fallback_parent = root_ids
        .first()
        .cloned()
        .unwrap_or_else(|| "receipt-root".to_string());
    let nodes = json_array_mut(lineage, "nodes", path)?;
    for node in nodes {
        let node_id = node
            .get("id")
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "signed lineage node id missing: {}",
                    path.display()
                ))
            })?
            .to_string();
        let receipt_ref = node
            .get("receipt_ref")
            .and_then(serde_json::Value::as_str)
            .filter(|receipt_ref| !receipt_ref.is_empty())
            .unwrap_or(node_id.as_str())
            .to_string();
        let disclosure_state = node
            .get("disclosure_state")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("disclosed")
            .to_string();
        let kind = if disclosure_state == "redacted" {
            "receipt_lineage_statement"
        } else {
            "receipt"
        };
        set_json_string_if_missing(node, "kind", kind);
        set_json_string_if_missing(node, "artifact_schema", lineage_node_schema(kind));
        set_json_string_if_missing(node, "evidence_class", lineage_node_evidence_class(kind));
        set_json_string_if_missing(node, "source_table", lineage_node_source_table(kind));
        set_json_string_if_missing(
            node,
            "artifact_sha256",
            &chio_core::sha256_hex(receipt_ref.as_bytes()),
        );
        set_json_string_if_missing(
            node,
            "tenant_hash",
            &chio_core::sha256_hex(b"tenant-fixture"),
        );
        set_json_string_if_missing(
            node,
            "source_id_hash",
            &chio_core::sha256_hex(receipt_ref.as_bytes()),
        );
        let is_root = root_ids.iter().any(|root_id| root_id == &node_id);
        if node.get("depth").is_none() {
            node["depth"] = serde_json::Value::Number(serde_json::Number::from(if is_root {
                0_u64
            } else {
                1_u64
            }));
        }
        if node.get("parent_ids").is_none() {
            node["parent_ids"] = if is_root {
                serde_json::Value::Array(Vec::new())
            } else {
                serde_json::json!([fallback_parent])
            };
        }
    }
    Ok(())
}

fn normalize_lineage_edges(path: &Path, lineage: &mut serde_json::Value) -> Result<(), CliError> {
    let edges = json_array_mut(lineage, "edges", path)?;
    for edge in edges {
        let from = edge
            .get("from")
            .and_then(serde_json::Value::as_str)
            .filter(|from| !from.is_empty())
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "signed lineage edge source missing: {}",
                    path.display()
                ))
            })?
            .to_string();
        let to = edge
            .get("to")
            .and_then(serde_json::Value::as_str)
            .filter(|to| !to.is_empty())
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "signed lineage edge target missing: {}",
                    path.display()
                ))
            })?
            .to_string();
        let relation = edge
            .get("relation")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("continued")
            .to_string();
        let kind = lineage_edge_kind(&relation);
        let edge_id = format!("edge-{from}-{to}-{kind}");
        set_json_string_if_missing(edge, "edge_id", &edge_id);
        set_json_string_if_missing(edge, "kind", kind);
        set_json_string_if_missing(edge, "evidence_class", "observed");
        set_json_string_if_missing(
            edge,
            "source_artifact_sha256",
            &chio_core::sha256_hex(edge_id.as_bytes()),
        );
        set_json_string_if_missing(
            edge,
            "statement_sha256",
            &chio_core::sha256_hex(format!("{from}|{to}|{kind}").as_bytes()),
        );
        set_json_string_if_missing(edge, "disclosure_state", "disclosed");
    }
    Ok(())
}

fn lineage_node_schema(kind: &str) -> &'static str {
    match kind {
        "receipt_lineage_statement" => "chio.receipt-lineage-statement.v1",
        "continuation_token" => "chio.swarm.continuation-token.v1",
        "bbs_projection" => "chio.bbs-projection.receipt.v1",
        "bbs_proof" => "chio.selective-disclosure.proof.v1",
        "passport_presentation" => "chio.transaction.passport.v1",
        "governed_intent" => "chio.runtime.governed-intent.v1",
        "approval_token" => "chio.enterprise.approval-case.v1",
        "runtime_assurance" => "chio.runtime.terminal-receipt.v1",
        _ => "chio.receipt.v1",
    }
}

fn lineage_node_evidence_class(kind: &str) -> &'static str {
    match kind {
        "receipt_lineage_statement" | "bbs_projection" | "bbs_proof" => "derived",
        _ => "observed",
    }
}

fn lineage_node_source_table(kind: &str) -> &'static str {
    match kind {
        "receipt_lineage_statement" => "receipt_lineage_statements",
        "continuation_token" => "continuation_tokens",
        "bbs_projection" => "bbs_projections",
        "bbs_proof" => "bbs_proofs",
        "passport_presentation" => "passport_presentations",
        "governed_intent" => "governed_intents",
        "approval_token" => "approval_cases",
        "runtime_assurance" => "runtime_assurances",
        _ => "receipts",
    }
}

fn lineage_edge_kind(relation: &str) -> &'static str {
    match relation {
        "delegated" => "issued_under",
        "derived" => "signed_lineage_statement",
        _ => "continued_by",
    }
}

fn lineage_frontier_sha256_from_json(
    path: &Path,
    lineage: &serde_json::Value,
) -> Result<String, CliError> {
    let outgoing = json_array(lineage, "edges", path)?
        .iter()
        .filter_map(|edge| edge.get("from").and_then(serde_json::Value::as_str))
        .collect::<BTreeSet<_>>();
    let mut frontier = Vec::new();
    for node in json_array(lineage, "nodes", path)? {
        let node_id = node
            .get("id")
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "signed lineage node id missing: {}",
                    path.display()
                ))
            })?;
        if outgoing.contains(node_id) {
            continue;
        }
        let artifact_sha256 = node
            .get("artifact_sha256")
            .and_then(serde_json::Value::as_str)
            .filter(|digest| !digest.is_empty())
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "signed lineage node artifact digest missing: {}",
                    path.display()
                ))
            })?;
        let depth = node
            .get("depth")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "signed lineage node depth missing: {}",
                    path.display()
                ))
            })?;
        frontier.push(format!("{node_id}:{artifact_sha256}:{depth}"));
    }
    frontier.sort();
    Ok(chio_core::sha256_hex(frontier.join("|").as_bytes()))
}

fn lineage_max_depth_from_json(path: &Path, lineage: &serde_json::Value) -> Result<u64, CliError> {
    json_array(lineage, "nodes", path)?
        .iter()
        .map(|node| {
            node.get("depth")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| {
                    CliError::cli_other_error(format!(
                        "signed lineage node depth missing: {}",
                        path.display()
                    ))
                })
        })
        .try_fold(0_u64, |max_depth, depth| {
            depth.map(|depth| max_depth.max(depth))
        })
}

fn set_json_string_if_missing(value: &mut serde_json::Value, field: &str, replacement: &str) {
    if value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .is_some_and(|current| !current.is_empty())
    {
        return;
    }
    set_json_string(value, field, replacement.to_string());
}

fn set_json_string(value: &mut serde_json::Value, field: &str, replacement: String) {
    value[field] = serde_json::Value::String(replacement);
}

fn sha256_json_value(value: &serde_json::Value) -> Result<String, CliError> {
    let bytes = serde_json::to_vec(value)?;
    Ok(chio_core::sha256_hex(&bytes))
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
    let source_nodes = json_array(&source_graph, "nodes", &source_graph_path)?.clone();
    let mut id_remaps = BTreeMap::new();
    let mut retained_ids = BTreeSet::new();

    for node in source_nodes {
        let path = required_json_string(&node, "path", &source_graph_path)?;
        let id = required_json_string(&node, "id", &source_graph_path)?;
        let role = required_json_string(&node, "role", &source_graph_path)?;
        if matches!(
            path.as_str(),
            "transaction-passport.json"
                | "evidence-graph.json"
                | "claim-set.json"
                | "verifier-policy.json"
        ) || matches!(id.as_str(), "claim-set" | "verifier-policy")
            || matches!(role.as_str(), "claim-set" | "verifier-policy")
        {
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
        let artifact_sha256 = sha256_file(&destination_path)?;
        id_remaps.insert(id, artifact_sha256.clone());
        node["id"] = serde_json::Value::String(artifact_sha256.clone());
        node["sha256"] = serde_json::Value::String(artifact_sha256);
        retained_ids.insert(required_json_string(&node, "id", &source_graph_path)?);
        json_array_mut(evidence_graph, "nodes", &source_graph_path)?.push(node);
    }

    let source_edges = json_array(&source_graph, "edges", &source_graph_path)?.clone();
    for edge in source_edges {
        let Some(from) = edge.get("from").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(to) = edge.get("to").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let from = id_remaps.get(from).map(String::as_str).unwrap_or(from);
        let to = id_remaps.get(to).map(String::as_str).unwrap_or(to);
        let from = from.to_string();
        let to = to.to_string();
        if retained_ids.contains(&from) && retained_ids.contains(&to) {
            let mut edge = edge;
            edge["from"] = serde_json::Value::String(from);
            edge["to"] = serde_json::Value::String(to);
            json_array_mut(evidence_graph, "edges", &source_graph_path)?.push(edge);
        }
    }
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

fn refresh_graph_node_hashes(
    bundle: &Path,
    evidence_graph: &mut serde_json::Value,
) -> Result<(), CliError> {
    let mut id_rewrites = BTreeMap::new();
    let mut seen_ids = BTreeSet::new();
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
        let old_id = node
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "proof fixture evidence node id missing: {}",
                    bundle.display()
                ))
            })?
            .to_string();
        let old_sha256 = node
            .get("sha256")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let mut artifact_path = resolve_graph_artifact_path(bundle, path)?;
        if path == "policy.json"
            && node.get("role").and_then(serde_json::Value::as_str) == Some("policy")
        {
            if let Ok(verifier_policy_path) =
                resolve_graph_artifact_path(bundle, "verifier-policy.json")
            {
                if sha256_file(&artifact_path)? == sha256_file(&verifier_policy_path)? {
                    node["path"] =
                        serde_json::Value::String("verifier-policy.json".to_string());
                    node["role"] =
                        serde_json::Value::String("verifier-policy".to_string());
                    artifact_path = verifier_policy_path;
                }
            }
        }
        let artifact_sha256 = sha256_file(&artifact_path)?;
        node["id"] = serde_json::Value::String(artifact_sha256.clone());
        node["sha256"] = serde_json::Value::String(artifact_sha256.clone());
        id_rewrites.insert(old_id, artifact_sha256.clone());
        if let Some(old_sha256) = old_sha256 {
            id_rewrites.insert(old_sha256, artifact_sha256);
        }
    }
    json_array_mut(evidence_graph, "nodes", &bundle.join("evidence-graph.json"))?.retain(|node| {
        node.get("id")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|id| seen_ids.insert(id.to_string()))
    });
    for edge in json_array_mut(evidence_graph, "edges", &bundle.join("evidence-graph.json"))? {
        for field in ["from", "to"] {
            let Some(current) = edge.get(field).and_then(serde_json::Value::as_str) else {
                continue;
            };
            if let Some(rewritten) = id_rewrites.get(current) {
                edge[field] = serde_json::Value::String(rewritten.clone());
            }
        }
    }
    Ok(())
}

fn resolve_graph_artifact_path(root: &Path, path: &str) -> Result<PathBuf, CliError> {
    let direct = root.join(path);
    if direct.is_file() {
        return Ok(direct);
    }
    let roots_artifact = root.join("roots").join(path);
    if roots_artifact.is_file() {
        return Ok(roots_artifact);
    }
    Err(CliError::cli_other_error(format!(
        "proof fixture graph artifact missing: {}",
        direct.display()
    )))
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

fn required_json_pointer_string(
    value: &serde_json::Value,
    pointer: &str,
    path: &Path,
) -> Result<String, CliError> {
    value
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "proof fixture JSON pointer missing: {}: {pointer}",
                path.display()
            ))
        })
}

fn required_json_pointer_u64(
    value: &serde_json::Value,
    pointer: &str,
    path: &Path,
) -> Result<u64, CliError> {
    value
        .pointer(pointer)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "proof fixture JSON pointer missing: {}: {pointer}",
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

fn json_string_array(
    value: &serde_json::Value,
    field: &str,
    path: &Path,
) -> Result<Vec<String>, CliError> {
    json_array(value, field, path)?
        .iter()
        .map(|item| {
            item.as_str()
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .ok_or_else(|| {
                    CliError::cli_other_error(format!(
                        "proof fixture JSON string array invalid: {}: {field}",
                        path.display()
                    ))
                })
        })
        .collect()
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
    file_path.strip_prefix(fixture_path)?.strip_prefix('/')
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
