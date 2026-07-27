use super::*;
use std::{collections::BTreeSet, fs, io::Write, path::Path};

const PROOF_ROOM_BUNDLE_SCHEMA: &str = "chio.proof-room.bundle.v1";
const PROOF_ROOM_VERIFIER_REPORT_SCHEMA: &str = "chio.proof-room.verifier-report.v1";
const PROOF_ROOM_DSSE_PAYLOAD_TYPE: &str = "application/vnd.chio.proof-room.bundle.v1+json";
const PROOF_ROOM_BUNDLE_SIGNATURE_PATH: &str = "bundle-signature.dsse.json";
const PROOF_ROOM_PENDING_BUNDLE_SIGNATURE_PATH: &str =
    ".bundle-signature.dsse.json.pending";
const PROOF_ROOM_TRUST_ROOTS_PATH: &str = "artifacts/authority/trust-roots.json";
const PROOF_ROOM_TRUST_ROOTS_SCHEMA: &str = "chio.proof.first-run.trust-roots.v1";
pub(super) const PROOF_COLLECT_BUNDLE_SIGNER_SEED_HEX_ENV: &str =
    "CHIO_PROOF_COLLECT_BUNDLE_SIGNER_SEED_HEX";
const CHIO_RECEIPT_SCHEMA: &str = "chio.receipt.v1";
const RUNTIME_TERMINAL_RECEIPT_SCHEMA: &str = "chio.runtime.terminal-receipt.v1";
const REPORT_HASH_MISMATCH_NEGATIVE_ID: &str = "report-hash-mismatch";
const REPORT_HASH_MISMATCH_NEGATIVE_PATH: &str = "negatives/report-hash-mismatch.json";
const REPORT_HASH_MISMATCH_FAILURE_CODE: &str = "proof-room.report.hash-mismatch";
const TERMINAL_RECEIPT_CATEGORIES: [&str; 3] = [
    "runtime_terminal_allow",
    "runtime_terminal_denial",
    "runtime_terminal_failure",
];

#[derive(serde::Serialize)]
struct ProofCollectReport {
    schema: &'static str,
    kind: &'static str,
    artifact_dir: String,
    out: String,
    passport_path: String,
    verifier_report_path: String,
    verdict: String,
}

#[derive(serde::Deserialize)]
struct CollectedEvidenceGraph {
    #[serde(default)]
    nodes: Vec<CollectedEvidenceNode>,
}

#[derive(serde::Deserialize)]
struct CollectedEvidenceNode {
    path: String,
    schema: String,
    #[serde(default)]
    role: String,
}

pub(super) fn collect_proof_bundle(
    kind: ProofCollectKind,
    artifact_dir: &Path,
    out: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    match kind {
        ProofCollectKind::AgentWebEnvelope
        | ProofCollectKind::BuyerPackage
        | ProofCollectKind::DisclosureAgentWebEnvelope
        | ProofCollectKind::Evidence
        | ProofCollectKind::IoaWeb3
        | ProofCollectKind::Replay
        | ProofCollectKind::TransactionPassport
        | ProofCollectKind::RuntimeSpine => {
            fixture::copy_dir_contents(artifact_dir, out)?;
            if kind == ProofCollectKind::DisclosureAgentWebEnvelope
                && out.join("capsule.json").is_file()
                && out.join("crypto-context-report.json").is_file()
            {
                fixture::add_disclosure_bbs_material_to_bundle(out)?;
            }
            let report = seal_collected_proof_bundle(kind, out)?;
            let passport_path = out.join("transaction-passport.json");
            let verifier_report_path = out.join("verifier/report.json");
            let collect_report = ProofCollectReport {
                schema: "chio.proof.collect-report.v1",
                kind: kind.as_str(),
                artifact_dir: artifact_dir.to_string_lossy().into_owned(),
                out: out.to_string_lossy().into_owned(),
                passport_path: passport_path.to_string_lossy().into_owned(),
                verifier_report_path: verifier_report_path.to_string_lossy().into_owned(),
                verdict: report
                    .get("verdict")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
            };
            write_collect_report(&collect_report, json_output)
        }
    }
}

pub(super) fn seal_collected_proof_bundle(
    kind: ProofCollectKind,
    bundle: &Path,
) -> Result<serde_json::Value, CliError> {
    seal_collected_proof_bundle_with_fixture_id(
        kind,
        bundle,
        None,
        SealVerificationMode::ConsumeReplays,
    )
}

pub(super) fn seal_generated_fixture_bundle(
    kind: ProofCollectKind,
    bundle: &Path,
) -> Result<serde_json::Value, CliError> {
    seal_collected_proof_bundle_with_fixture_id(
        kind,
        bundle,
        None,
        SealVerificationMode::IsolatedFixture,
    )
}

pub(super) fn seal_collected_public_fixture_bundle(
    kind: ProofCollectKind,
    bundle: &Path,
    fixture_id: &str,
) -> Result<serde_json::Value, CliError> {
    seal_collected_proof_bundle_with_fixture_id(
        kind,
        bundle,
        Some(fixture_id),
        SealVerificationMode::IsolatedFixture,
    )
}

#[derive(Clone, Copy)]
enum SealVerificationMode {
    ConsumeReplays,
    IsolatedFixture,
}

fn seal_collected_proof_bundle_with_fixture_id(
    kind: ProofCollectKind,
    bundle: &Path,
    public_fixture_id: Option<&str>,
    verification_mode: SealVerificationMode,
) -> Result<serde_json::Value, CliError> {
    let passport_path = bundle.join("transaction-passport.json");
    let (verification_report, replay_snapshot) = match verification_mode {
        SealVerificationMode::ConsumeReplays => {
            let read_only_report = verify_transaction_passport_file(&passport_path)?;
            enforce_collect_kind_requirements(kind, &read_only_report)?;
            (read_only_report.clone(), Some(read_only_report))
        }
        SealVerificationMode::IsolatedFixture => {
            (
                fixture::verify_fixture_transaction_passport_file(&passport_path)?,
                None,
            )
        }
    };
    enforce_collect_kind_requirements(kind, &verification_report)?;
    let signature_path = match verification_mode {
        SealVerificationMode::ConsumeReplays => {
            invalidate_collected_proof_room_bundle(bundle)?;
            bundle.join(PROOF_ROOM_PENDING_BUNDLE_SIGNATURE_PATH)
        }
        SealVerificationMode::IsolatedFixture => {
            bundle.join(PROOF_ROOM_BUNDLE_SIGNATURE_PATH)
        }
    };
    let report = collected_verifier_report(bundle, verification_report)?;
    let verifier_report_path = bundle.join("verifier/report.json");
    if let Some(parent) = verifier_report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    write_json_line_file(&verifier_report_path, &report)?;
    write_collected_proof_room_bundle(
        bundle,
        &report,
        kind,
        public_fixture_id,
        &signature_path,
    )?;
    sync_collected_proof_room_bundle(bundle)?;
    if let Some(read_only_report) = replay_snapshot {
        let consume_result =
            super::verify_transaction_passport_file_and_consume_agent_web_replays(
                &passport_path,
                &read_only_report,
            )
            .and_then(|consumed_report| {
                enforce_collect_kind_requirements(kind, &consumed_report)
            });
        if let Err(error) = consume_result {
            return match invalidate_collected_proof_room_bundle(bundle) {
                Ok(()) => Err(error),
                Err(invalidation_error) => Err(CliError::cli_other_error(format!(
                    "{error}; failed to invalidate the uncommitted proof bundle: {invalidation_error}"
                ))),
            };
        }
        fs::rename(
            bundle.join(PROOF_ROOM_PENDING_BUNDLE_SIGNATURE_PATH),
            bundle.join(PROOF_ROOM_BUNDLE_SIGNATURE_PATH),
        )?;
        sync_collected_proof_room_bundle(bundle)?;
    }
    Ok(report)
}

fn invalidate_collected_proof_room_bundle(bundle: &Path) -> Result<(), CliError> {
    for relative_path in [
        PROOF_ROOM_BUNDLE_SIGNATURE_PATH,
        PROOF_ROOM_PENDING_BUNDLE_SIGNATURE_PATH,
        "manifest.json",
        "verifier/report.json",
    ] {
        match fs::remove_file(bundle.join(relative_path)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(CliError::from(error)),
        }
    }
    Ok(())
}

fn sync_collected_proof_room_bundle(path: &Path) -> Result<(), CliError> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            sync_collected_proof_room_bundle(&entry.path())?;
        } else if file_type.is_file() {
            fs::File::open(entry.path())?.sync_all()?;
        }
    }
    #[cfg(unix)]
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

fn enforce_collect_kind_requirements(
    kind: ProofCollectKind,
    report: &serde_json::Value,
) -> Result<(), CliError> {
    match kind {
        ProofCollectKind::AgentWebEnvelope => {
            ensure_verified_claim_family(report, "external-envelope", "claim.agent_web.")
        }
        ProofCollectKind::BuyerPackage => {
            ensure_verified_claim_family(report, "delegation", "claim.swarm.")?;
            ensure_runtime_parity_verified(report)
        }
        ProofCollectKind::DisclosureAgentWebEnvelope => {
            ensure_verified_claim_family(report, "disclosure", "claim.disclosure.")?;
            ensure_verified_claim_family(report, "external-envelope", "claim.agent_web.")
        }
        ProofCollectKind::Evidence => Ok(()),
        ProofCollectKind::IoaWeb3 => {
            ensure_verified_claim_family(report, "commerce", "claim.commerce.")?;
            ensure_verified_claim_family(report, "settlement", "claim.public_settlement.")
        }
        ProofCollectKind::Replay => {
            ensure_verified_claim_family(report, "commerce", "claim.commerce.")
        }
        ProofCollectKind::TransactionPassport => Ok(()),
        ProofCollectKind::RuntimeSpine => {
            ensure_verified_claim_family(report, "delegation", "claim.swarm.")?;
            ensure_runtime_parity_verified(report)
        }
    }
}

fn write_collect_report(report: &ProofCollectReport, json_output: bool) -> Result<(), CliError> {
    let mut stdout = std::io::stdout();
    if json_output {
        serde_json::to_writer(&mut stdout, report)?;
        stdout.write_all(b"\n")?;
    } else {
        writeln!(
            stdout,
            "collected {} proof bundle at {}",
            report.kind, report.out
        )?;
        writeln!(stdout, "verdict: {}", report.verdict)?;
    }
    Ok(())
}

fn write_collected_proof_room_bundle(
    bundle: &Path,
    verifier_report: &serde_json::Value,
    kind: ProofCollectKind,
    public_fixture_id: Option<&str>,
    signature_path: &Path,
) -> Result<(), CliError> {
    let keypair = proof_collect_bundle_signer_from_env()?;
    fs::create_dir_all(bundle.join("roots"))?;
    fs::create_dir_all(bundle.join("ui/proof-room-static"))?;
    for artifact in [
        "transaction-passport.json",
        "evidence-graph.json",
        "claim-set.json",
        "verifier-policy.json",
    ] {
        fs::copy(bundle.join(artifact), bundle.join("roots").join(artifact))?;
    }
    if bundle.join("order-passport.json").is_file() {
        fs::copy(
            bundle.join("order-passport.json"),
            bundle.join("roots/order-passport.json"),
        )?;
    }

    let passport_id = required_report_string(verifier_report, "passport_id")?;
    let issued_at = required_report_string(verifier_report, "issued_at")?;
    let verdict = required_report_string(verifier_report, "verdict")?;
    let (bundle_id, fixture_id, source_command) = match public_fixture_id {
        Some(fixture_id) => (
            format!("proof-room-{fixture_id}"),
            fixture_id.to_string(),
            format!("chio proof fixture generate {fixture_id}"),
        ),
        None => (
            format!("proof-room-collected-{passport_id}"),
            format!("collected-{passport_id}"),
            format!("chio proof collect --kind {}", kind.as_str()),
        ),
    };
    let verifier_report_ref = artifact_ref(
        bundle,
        "verifier/report.json",
        "chio.transaction.verifier-report.v1",
    )?;
    let evidence_graph = read_collected_evidence_graph(bundle)?;
    let receipt_coverage = collected_receipt_coverage(bundle, &evidence_graph)?;
    let claims = collected_manifest_claims(verifier_report, verdict, &receipt_coverage);
    let rendered_claims = collected_rendered_claims(&claims, verdict)?;
    let ui_report = serde_json::json!({
        "schema": PROOF_ROOM_VERIFIER_REPORT_SCHEMA,
        "id": format!("proof-room-verifier-report-{passport_id}"),
        "issued_at": issued_at,
        "verdict": verdict,
        "bundle_id": bundle_id.clone(),
        "fixture_id": fixture_id.clone(),
        "source_verifier_report_ref": verifier_report_ref,
        "ui_verdict_source": "verifier_report_ref",
        "rendered_claims": rendered_claims
    });
    write_json_line_file(
        &bundle.join("ui/proof-room-static/load-report.json"),
        &ui_report,
    )?;
    write_collected_trust_roots(bundle, passport_id, &keypair)?;
    write_collected_bundle_readme(bundle, &fixture_id, &source_command, verdict)?;

    let artifacts = collected_manifest_artifacts(bundle, &evidence_graph, &receipt_coverage)?;
    let negative_cases = write_collected_negative_cases(bundle, verifier_report)?;
    let manifest = serde_json::json!({
        "schema": PROOF_ROOM_BUNDLE_SCHEMA,
        "bundle_id": bundle_id,
        "fixture_id": fixture_id,
        "stage": "collected",
        "created_at": issued_at,
        "source_commit": "collected-artifacts",
        "source_branch": "local",
        "source_command": source_command,
        "chio_version": env!("CARGO_PKG_VERSION"),
        "schema_versions": {
            "proof_room_bundle": PROOF_ROOM_BUNDLE_SCHEMA,
            "proof_room_verifier_report": PROOF_ROOM_VERIFIER_REPORT_SCHEMA,
            "transaction_passport": "chio.transaction-passport.v1",
            "transaction_evidence_graph": "chio.transaction.evidence-graph.v1",
            "transaction_claim_set": "chio.transaction.claim-set.v1",
            "transaction_verifier_policy": "chio.transaction.verifier-policy.v1",
            "transaction_verifier_report": "chio.transaction.verifier-report.v1"
        },
        "hash_algorithm": "sha256",
        "transaction_passport_ref": artifact_ref(bundle, "roots/transaction-passport.json", "chio.transaction-passport.v1")?,
        "evidence_graph_ref": artifact_ref(bundle, "roots/evidence-graph.json", "chio.transaction.evidence-graph.v1")?,
        "verifier_report_ref": artifact_ref(bundle, "verifier/report.json", "chio.transaction.verifier-report.v1")?,
        "proof_room_verifier_report_ref": artifact_ref(bundle, "ui/proof-room-static/load-report.json", PROOF_ROOM_VERIFIER_REPORT_SCHEMA)?,
        "artifacts": artifacts,
        "claims": claims,
        "receipt_coverage": receipt_coverage,
        "negative_cases": negative_cases,
        "advisory_artifacts": [],
        "excluded_artifacts": [],
        "signature": {
            "kind": "detached-dsse",
            "signature_ref": PROOF_ROOM_BUNDLE_SIGNATURE_PATH
        }
    });
    write_json_line_file(&bundle.join("manifest.json"), &manifest)?;
    write_bundle_signature_to_path(bundle, &keypair, signature_path)
}

fn write_collected_bundle_readme(
    bundle: &Path,
    fixture_id: &str,
    source_command: &str,
    verdict: &str,
) -> Result<(), CliError> {
    fs::write(
        bundle.join("README.md"),
        format!(
            "# Chio Proof Room bundle\n\nFixture: `{fixture_id}`\n\nVerifier verdict: `{verdict}`\n\nGenerated by `{source_command}`.\n\nThe proof verdict is read from `verifier/report.json`; this file is only a human-readable bundle index.\n"
        ),
    )?;
    Ok(())
}

fn write_collected_negative_cases(
    bundle: &Path,
    verifier_report: &serde_json::Value,
) -> Result<Vec<serde_json::Value>, CliError> {
    let negative_path = bundle.join(REPORT_HASH_MISMATCH_NEGATIVE_PATH);
    if let Some(parent) = negative_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let descriptor = serde_json::json!({
        "schema": "chio.proof-room.negative-fixture.v1",
        "id": REPORT_HASH_MISMATCH_NEGATIVE_ID,
        "base_manifest": "manifest.json",
        "mutation": {
            "path": ["verifier_report_ref", "sha256"],
            "value": "0000000000000000000000000000000000000000000000000000000000000000"
        },
        "expected_failure_code": REPORT_HASH_MISMATCH_FAILURE_CODE
    });
    write_json_line_file(&negative_path, &descriptor)?;
    let mut negative_cases = vec![serde_json::json!({
        "id": REPORT_HASH_MISMATCH_NEGATIVE_ID,
        "path": REPORT_HASH_MISMATCH_NEGATIVE_PATH,
        "expected_failure_code": REPORT_HASH_MISMATCH_FAILURE_CODE,
        "observed_failure_code": REPORT_HASH_MISMATCH_FAILURE_CODE
    })];
    negative_cases.extend(write_catalog_negative_cases(bundle, verifier_report)?);
    Ok(negative_cases)
}

fn collected_verifier_report(
    bundle: &Path,
    report: serde_json::Value,
) -> Result<serde_json::Value, CliError> {
    if report.get("schema").and_then(serde_json::Value::as_str)
        == Some("chio.transaction.verifier-report.v1")
        && report
            .get("passport_id")
            .and_then(serde_json::Value::as_str)
            .is_some()
        && should_preserve_collected_transaction_report(&report)
    {
        let mut report = report;
        attach_checker_provenance(&mut report);
        return Ok(report);
    }

    let passport = read_collected_transaction_passport(bundle)?;
    let evidence_graph_bytes = fs::read(bundle.join(&passport.evidence_graph_path))?;
    let transparency_state =
        chio_control_plane::transaction_passport::transaction_evidence_graph_transparency_state(
            &evidence_graph_bytes,
        )
        .map_err(map_proof_error)?;
    let mut collected_report = merge_family_verifier_reports(
        &passport,
        "transaction-passport.json".to_string(),
        vec![report],
        &transparency_state,
    );
    if let Some(parity_report) = collected_report["family_reports"][0]
        .get("runtime_proof_parity_report")
        .cloned()
    {
        collected_report["runtime_proof_parity_report"] = parity_report;
    }
    Ok(collected_report)
}

fn should_preserve_collected_transaction_report(report: &serde_json::Value) -> bool {
    if report
        .get("family_reports")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|reports| !reports.is_empty())
    {
        return true;
    }
    report_verified_claims(report)
        .iter()
        .all(|claim| claim.starts_with("claim.transaction."))
}

fn attach_checker_provenance(report: &mut serde_json::Value) {
    if report
        .get("family_reports")
        .and_then(serde_json::Value::as_array)
        .is_none_or(|reports| reports.is_empty())
    {
        return;
    }
    report["checker_provenance"] = claim_checker_provenance(report).into();
}

fn read_collected_transaction_passport(
    bundle: &Path,
) -> Result<chio_control_plane::transaction_passport::TransactionPassport, CliError> {
    let bytes = fs::read(bundle.join("transaction-passport.json"))?;
    serde_json::from_slice(&bytes).map_err(CliError::from)
}

fn report_verified_claims(report: &serde_json::Value) -> Vec<String> {
    let mut claims = BTreeSet::new();
    push_report_verified_claims(report, &mut claims);
    if let Some(family_reports) = report
        .get("family_reports")
        .and_then(serde_json::Value::as_array)
    {
        for family_report in family_reports {
            push_report_verified_claims(family_report, &mut claims);
        }
    }
    claims.into_iter().collect()
}

fn claim_checker_provenance(report: &serde_json::Value) -> Vec<serde_json::Value> {
    report_top_level_verified_claims(report)
        .unwrap_or_else(|| report_verified_claims(report))
        .into_iter()
        .map(|claim_id| {
            serde_json::json!({
                "claim_id": claim_id,
                "checker": checker_for_claim(&claim_id)
            })
        })
        .collect()
}

fn report_top_level_verified_claims(report: &serde_json::Value) -> Option<Vec<String>> {
    report
        .get("verified_claims")
        .and_then(serde_json::Value::as_array)
        .map(|claims| {
            claims
                .iter()
                .filter_map(serde_json::Value::as_str)
                .filter(|claim| !claim.is_empty())
                .map(str::to_string)
                .collect()
        })
}

fn checker_for_claim(claim_id: &str) -> &'static str {
    if claim_id.starts_with("claim.agent_web.") {
        "chio proof verify --require external-envelope"
    } else if claim_id.starts_with("claim.commerce.") {
        "chio proof verify --require commerce"
    } else if claim_id.starts_with("claim.disclosure.") {
        "chio proof verify --require disclosure"
    } else if claim_id.starts_with("claim.enterprise.") {
        "chio proof verify --require enterprise"
    } else if claim_id.starts_with("claim.public_settlement.") {
        "chio proof verify --require settlement"
    } else if claim_id.starts_with("claim.risk.") {
        "chio proof verify --require risk"
    } else if claim_id.starts_with("claim.runtime.") {
        "chio proof verify --require runtime"
    } else if claim_id.starts_with("claim.swarm.") {
        "chio proof verify --require delegation"
    } else if claim_id.starts_with("claim.trust_market.") {
        "chio proof verify --require trust-market"
    } else {
        "chio proof verify"
    }
}

fn push_report_verified_claims(report: &serde_json::Value, claims: &mut BTreeSet<String>) {
    if let Some(report_claims) = report
        .get("verified_claims")
        .or_else(|| report.get("verifiedClaims"))
        .and_then(serde_json::Value::as_array)
    {
        for claim in report_claims {
            if let Some(claim) = claim.as_str().filter(|claim| !claim.is_empty()) {
                claims.insert(claim.to_string());
            }
        }
    }
}

fn write_catalog_negative_cases(
    bundle: &Path,
    verifier_report: &serde_json::Value,
) -> Result<Vec<serde_json::Value>, CliError> {
    let prefixes = catalog_negative_prefixes(verifier_report);
    let verified_claims = report_verified_claims(verifier_report);
    if prefixes.is_empty() && verified_claims.is_empty() {
        return Ok(Vec::new());
    }

    let mut cases = Vec::new();
    for descriptor in fixture::proof_fixtures()? {
        if descriptor.kind != "negative-transaction-passport" {
            continue;
        }
        let prefix_matches = prefixes
            .iter()
            .any(|prefix| descriptor.id.starts_with(prefix));
        let claim_matches = if prefix_matches {
            false
        } else {
            catalog_negative_claim_matches(&descriptor, &verified_claims)?
        };
        if !prefix_matches && !claim_matches {
            continue;
        }
        let destination = bundle.join("negatives/catalog").join(&descriptor.id);
        if destination.exists() {
            fs::remove_dir_all(&destination)?;
        }
        fixture::copy_proof_fixture(&descriptor.id, &destination)?;
        if descriptor.id.starts_with("disclosure-lineage-")
            && !fixture::is_generated_disclosure_negative_fixture_id(&descriptor.id)
        {
            fixture::add_disclosure_bbs_material_to_bundle(&destination)?;
        }
        let passport_path = destination.join("transaction-passport.json");
        let expected_failure = fixture::proof_fixture_negative_expected_failure(&descriptor)?;
        let observed_failure =
            fixture::with_proof_fixture_negative_verifier_context(&descriptor, || {
                match fixture::verify_fixture_transaction_passport_file(&passport_path) {
                    Ok(_) => Err(CliError::cli_other_error(format!(
                        "catalog negative proof fixture unexpectedly verified: {}",
                        descriptor.id
                    ))),
                    Err(error) => Ok(semantic_negative_failure_code(&error.to_string())),
                }
            })?;
        if !negative_failure_code_matches(&observed_failure, &expected_failure) {
            return Err(CliError::cli_other_error(format!(
                "catalog negative proof fixture failed for the wrong reason: {}: expected {}, got {}",
                descriptor.id, expected_failure, observed_failure
            )));
        }
        let mut case = serde_json::json!({
            "id": descriptor.id,
            "path": format!("negatives/catalog/{}/transaction-passport.json", descriptor.id),
            "expected_failure_code": expected_failure,
            "observed_failure_code": observed_failure
        });
        if let Some(verifier_context) =
            fixture::proof_fixture_negative_verifier_context(&descriptor)?
        {
            case["verifier_context"] = verifier_context;
        }
        cases.push(case);
    }
    Ok(cases)
}

fn catalog_negative_claim_matches(
    descriptor: &fixture::ProofFixtureDescriptor,
    verified_claims: &[String],
) -> Result<bool, CliError> {
    let Some(claim_ref) = fixture::proof_fixture_negative_claim_ref(descriptor)? else {
        return Ok(false);
    };
    Ok(verified_claims.iter().any(|claim| claim == &claim_ref))
}

fn catalog_negative_prefixes(verifier_report: &serde_json::Value) -> Vec<&'static str> {
    let claims = report_verified_claims(verifier_report);
    let mut prefixes = BTreeSet::new();
    if claims
        .iter()
        .any(|claim| claim.starts_with("claim.commerce."))
    {
        prefixes.insert("commerce-");
    }
    if claims
        .iter()
        .any(|claim| claim.starts_with("claim.runtime."))
    {
        prefixes.insert("runtime-");
    }
    if claims.iter().any(|claim| claim.starts_with("claim.swarm.")) {
        prefixes.insert("recursive-runtime-swarm-");
    }
    if claims
        .iter()
        .any(|claim| claim.starts_with("claim.disclosure."))
    {
        prefixes.insert("disclosure-lineage-");
    }
    if claims
        .iter()
        .any(|claim| claim.starts_with("claim.public_settlement."))
    {
        prefixes.insert("public-settlement-");
    }
    if claims
        .iter()
        .any(|claim| claim.starts_with("claim.agent_web."))
    {
        prefixes.insert("agent-web-");
    }
    if claims
        .iter()
        .any(|claim| claim.starts_with("claim.enterprise."))
    {
        prefixes.insert("enterprise-");
    }
    if claims
        .iter()
        .any(|claim| claim.starts_with("claim.trust_market."))
    {
        prefixes.insert("trust-market-");
    }
    prefixes.into_iter().collect()
}

fn read_collected_evidence_graph(bundle: &Path) -> Result<CollectedEvidenceGraph, CliError> {
    let bytes = fs::read(bundle.join("evidence-graph.json"))?;
    serde_json::from_slice(&bytes).map_err(CliError::from)
}

fn collected_manifest_claims(
    verifier_report: &serde_json::Value,
    verdict: &str,
    receipt_coverage: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    let mut claims = vec![
        serde_json::json!({
            "claim_id": "claim.transaction.passport_root_verified",
            "required_artifacts": [
                "roots/transaction-passport.json",
                "roots/evidence-graph.json",
                "roots/claim-set.json",
                "roots/verifier-policy.json",
                "verifier/report.json"
            ],
            "checker": "chio proof verify roots/transaction-passport.json",
            "result": verdict,
            "proof_level": "deterministic-verifier-report",
            "caveat": "",
            "source_refs": ["verifier/report.json"]
        }),
        serde_json::json!({
            "claim_id": "claim.proof_room.verifier_report_bound",
            "required_artifacts": [
                "verifier/report.json",
                "ui/proof-room-static/load-report.json"
            ],
            "checker": "chio proof serve --dry-run",
            "result": verdict,
            "proof_level": "hash-bound-display-report",
            "caveat": "The UI report consumes verifier output and is not a separate proof source.",
            "source_refs": ["ui/proof-room-static/load-report.json"]
        }),
    ];

    let allow_receipt = covered_receipt_artifact(receipt_coverage, "runtime_terminal_allow");
    let denial_receipt = covered_receipt_artifact(receipt_coverage, "runtime_terminal_denial");
    if let (Some(allow_receipt), Some(denial_receipt)) = (&allow_receipt, &denial_receipt) {
        claims.push(serde_json::json!({
            "claim_id": "claim.proof_room.allow_and_deny_visible",
            "required_artifacts": [allow_receipt, denial_receipt],
            "checker": "chio proof verify --require denials",
            "result": verdict,
            "proof_level": "receipt-coverage",
            "caveat": "",
            "source_refs": [allow_receipt, denial_receipt]
        }));
    }

    if allow_receipt.is_some()
        && denial_receipt.is_some()
        && receipt_coverage_has_category(receipt_coverage, "runtime_terminal_failure")
    {
        let required_artifacts = receipt_coverage
            .iter()
            .filter_map(|entry| {
                entry
                    .get("artifact_path")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            })
            .collect::<Vec<_>>();
        if !required_artifacts.is_empty() {
            claims.push(serde_json::json!({
                "claim_id": "claim.proof_room.receipt_coverage_matrix_bound",
                "required_artifacts": required_artifacts,
                "checker": "chio proof serve --dry-run",
                "result": verdict,
                "proof_level": "receipt-coverage-matrix",
                "caveat": "",
                "source_refs": required_artifacts
            }));
        }
    }

    let existing_claims = claims
        .iter()
        .filter_map(|claim| claim.get("claim_id").and_then(serde_json::Value::as_str))
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    for claim_id in report_verified_claims(verifier_report) {
        if existing_claims.contains(&claim_id) || claim_id.starts_with("claim.proof_room.") {
            continue;
        }
        claims.push(serde_json::json!({
            "claim_id": claim_id,
            "required_artifacts": ["verifier/report.json"],
            "checker": checker_for_claim(&claim_id),
            "result": verdict,
            "proof_level": "deterministic-verifier-report",
            "caveat": "This claim is emitted by the verifier report; Proof Room renders it but does not independently prove it.",
            "source_refs": ["verifier/report.json"]
        }));
    }

    claims
}

fn collected_rendered_claims(
    claims: &[serde_json::Value],
    verdict: &str,
) -> Result<Vec<serde_json::Value>, CliError> {
    claims
        .iter()
        .map(|claim| {
            let claim_id = claim
                .get("claim_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    CliError::cli_other_error("proof collect claim missing id".to_string())
                })?;
            let source = claim
                .get("required_artifacts")
                .and_then(serde_json::Value::as_array)
                .and_then(|artifacts| artifacts.first())
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    CliError::cli_other_error(format!(
                        "proof collect claim missing required artifact: {claim_id}"
                    ))
                })?;
            Ok(serde_json::json!({
                "claim_id": claim_id,
                "source": source,
                "verdict": verdict,
                "checker": claim
                    .get("checker")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("chio proof verify")
            }))
        })
        .collect()
}

fn covered_receipt_artifact(
    receipt_coverage: &[serde_json::Value],
    category: &str,
) -> Option<String> {
    receipt_coverage
        .iter()
        .find(|entry| {
            entry.get("category").and_then(serde_json::Value::as_str) == Some(category)
                && entry.get("status").and_then(serde_json::Value::as_str) == Some("covered")
        })
        .and_then(|entry| {
            entry
                .get("artifact_path")
                .and_then(serde_json::Value::as_str)
        })
        .map(str::to_string)
}

fn receipt_coverage_has_category(receipt_coverage: &[serde_json::Value], category: &str) -> bool {
    receipt_coverage
        .iter()
        .any(|entry| entry.get("category").and_then(serde_json::Value::as_str) == Some(category))
}

fn collected_manifest_artifacts(
    bundle: &Path,
    evidence_graph: &CollectedEvidenceGraph,
    receipt_coverage: &[serde_json::Value],
) -> Result<Vec<serde_json::Value>, CliError> {
    let mut paths = BTreeSet::new();
    let mut artifacts = Vec::new();
    for (path, schema, artifact_class, renderer_hint) in [
        (
            "roots/transaction-passport.json",
            "chio.transaction-passport.v1",
            "transaction-root",
            "transaction-passport",
        ),
        (
            "roots/evidence-graph.json",
            "chio.transaction.evidence-graph.v1",
            "transaction-root",
            "evidence-graph",
        ),
        (
            "roots/claim-set.json",
            "chio.transaction.claim-set.v1",
            "transaction-root",
            "claim-set",
        ),
        (
            "roots/verifier-policy.json",
            "chio.transaction.verifier-policy.v1",
            "transaction-policy",
            "verifier-policy",
        ),
        (
            "verifier/report.json",
            "chio.transaction.verifier-report.v1",
            "verifier-output",
            "verifier-report",
        ),
        (
            "ui/proof-room-static/load-report.json",
            PROOF_ROOM_VERIFIER_REPORT_SCHEMA,
            "proof-room-display",
            "proof-room-report",
        ),
        (
            PROOF_ROOM_TRUST_ROOTS_PATH,
            PROOF_ROOM_TRUST_ROOTS_SCHEMA,
            "authority",
            "trust-roots",
        ),
    ] {
        artifacts.push(artifact(
            bundle,
            path,
            schema,
            artifact_class,
            renderer_hint,
        )?);
        paths.insert(path.to_string());
    }

    for node in &evidence_graph.nodes {
        if paths.contains(&node.path) || node.path.starts_with("roots/") {
            continue;
        }
        let artifact_path = bundle.join(&node.path);
        if !artifact_path.is_file() {
            continue;
        }
        if !artifact_declares_schema(&artifact_path, &node.schema)? {
            continue;
        }
        let artifact_class = artifact_class_for_node(node);
        let renderer_hint = renderer_hint_for_path(&node.path);
        artifacts.push(artifact(
            bundle,
            &node.path,
            &node.schema,
            artifact_class,
            &renderer_hint,
        )?);
        paths.insert(node.path.clone());
    }

    for receipt_path in receipt_coverage.iter().filter_map(|entry| {
        entry
            .get("artifact_path")
            .and_then(serde_json::Value::as_str)
    }) {
        if paths.contains(receipt_path) || !bundle.join(receipt_path).is_file() {
            continue;
        }
        artifacts.push(artifact(
            bundle,
            receipt_path,
            &artifact_schema_from_file(&bundle.join(receipt_path))?,
            "receipt",
            "receipt",
        )?);
        paths.insert(receipt_path.to_string());
    }

    Ok(artifacts)
}

fn artifact_declares_schema(path: &Path, expected_schema: &str) -> Result<bool, CliError> {
    Ok(artifact_schema_from_file(path).is_ok_and(|schema| schema == expected_schema))
}

fn artifact_schema_from_file(path: &Path) -> Result<String, CliError> {
    let bytes = fs::read(path)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    Ok(value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string())
}

fn artifact(
    bundle: &Path,
    path: &str,
    schema: &str,
    artifact_class: &str,
    renderer_hint: &str,
) -> Result<serde_json::Value, CliError> {
    let mut reference = artifact_ref(bundle, path, schema)?;
    let reference_object = reference
        .as_object_mut()
        .ok_or_else(|| CliError::cli_other_error("proof artifact ref invalid".to_string()))?;
    reference_object.insert(
        "media_type".to_string(),
        serde_json::Value::String("application/json".to_string()),
    );
    reference_object.insert(
        "artifact_class".to_string(),
        serde_json::Value::String(artifact_class.to_string()),
    );
    reference_object.insert(
        "sensitivity_class".to_string(),
        serde_json::Value::String("public".to_string()),
    );
    reference_object.insert(
        "producer".to_string(),
        serde_json::Value::String("chio proof collect".to_string()),
    );
    reference_object.insert(
        "participates_in_primary_verdict".to_string(),
        serde_json::Value::Bool(true),
    );
    reference_object.insert(
        "renderer_hint".to_string(),
        serde_json::Value::String(renderer_hint.to_string()),
    );
    Ok(reference)
}

fn artifact_ref(bundle: &Path, path: &str, schema: &str) -> Result<serde_json::Value, CliError> {
    let bytes = fs::read(bundle.join(path))?;
    Ok(serde_json::json!({
        "path": path,
        "sha256": chio_core::sha256_hex(&bytes),
        "schema": schema
    }))
}

fn collected_receipt_coverage(
    bundle: &Path,
    evidence_graph: &CollectedEvidenceGraph,
) -> Result<Vec<serde_json::Value>, CliError> {
    let mut categories = BTreeSet::new();
    let mut coverage = Vec::new();
    for node in &evidence_graph.nodes {
        if !is_terminal_receipt_schema(&node.schema) {
            continue;
        }
        chio_proof_room::validate_proof_room_bundle_relative_path(&node.path)
            .map_err(CliError::cli_other_error)?;
        let source_path = bundle.join(&node.path);
        if !source_path.is_file() {
            continue;
        }
        let bytes = fs::read(&source_path)?;
        let receipt: serde_json::Value = serde_json::from_slice(&bytes)?;
        let Some(status) = receipt
            .get("terminal_status")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let Some(category) = receipt_category(status) else {
            continue;
        };
        if !categories.insert(category) {
            continue;
        }
        let missing_fields = missing_receipt_coverage_fields(&receipt);
        if !missing_fields.is_empty() {
            coverage.push(serde_json::json!({
                "category": category,
                "status": "excluded",
                "exclusion_reason": format!(
                    "{category} receipt is present but missing signed coverage fields: {}",
                    missing_fields.join(", ")
                )
            }));
            continue;
        }
        let artifact_path = normalized_receipt_artifact_path(category);
        let destination_path = bundle.join(artifact_path);
        if source_path != destination_path {
            if let Some(parent) = destination_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&source_path, &destination_path)?;
        }
        coverage.push(serde_json::json!({
            "category": category,
            "status": "covered",
            "artifact_path": artifact_path,
            "terminal_status": status
        }));
    }

    for category in TERMINAL_RECEIPT_CATEGORIES {
        if categories.contains(category) {
            continue;
        }
        coverage.push(serde_json::json!({
            "category": category,
            "status": "excluded",
            "exclusion_reason": format!("{category} is not present in collected transaction passport evidence")
        }));
    }

    coverage.sort_by_key(|entry| {
        entry
            .get("category")
            .and_then(serde_json::Value::as_str)
            .map(receipt_category_rank)
            .unwrap_or(usize::MAX)
    });
    Ok(coverage)
}

fn missing_receipt_coverage_fields(receipt: &serde_json::Value) -> Vec<&'static str> {
    ["policy_digest", "kernel_key", "signature"]
        .into_iter()
        .filter(|field| {
            receipt
                .get(field)
                .and_then(serde_json::Value::as_str)
                .is_none_or(str::is_empty)
        })
        .collect()
}

fn is_terminal_receipt_schema(schema: &str) -> bool {
    schema == CHIO_RECEIPT_SCHEMA || schema == RUNTIME_TERMINAL_RECEIPT_SCHEMA
}

fn receipt_category(status: &str) -> Option<&'static str> {
    if status.starts_with("allowed_") {
        Some("runtime_terminal_allow")
    } else if status.starts_with("denied_") {
        Some("runtime_terminal_denial")
    } else if status.starts_with("failed_") {
        Some("runtime_terminal_failure")
    } else {
        None
    }
}

fn normalized_receipt_artifact_path(category: &str) -> &'static str {
    match category {
        "runtime_terminal_allow" => "artifacts/receipts/allow-receipt.json",
        "runtime_terminal_denial" => "artifacts/receipts/denial-receipt.json",
        "runtime_terminal_failure" => "artifacts/receipts/failure-receipt.json",
        _ => "artifacts/receipts/receipt.json",
    }
}

fn receipt_category_rank(category: &str) -> usize {
    match category {
        "runtime_terminal_allow" => 0,
        "runtime_terminal_denial" => 1,
        "runtime_terminal_failure" => 2,
        _ => usize::MAX,
    }
}

fn artifact_class_for_node(node: &CollectedEvidenceNode) -> &'static str {
    if is_terminal_receipt_schema(&node.schema) {
        "receipt"
    } else if node.role == "verifier-policy" || node.role == "policy" {
        "transaction-policy"
    } else {
        "transaction-root"
    }
}

fn renderer_hint_for_path(path: &str) -> String {
    path.strip_suffix(".json").unwrap_or(path).to_string()
}

fn required_report_string<'a>(
    report: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, CliError> {
    report
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::cli_other_error(format!("proof collect report missing {field}")))
}

pub(super) fn write_bundle_signature(
    bundle: &Path,
    keypair: &chio_core::Keypair,
) -> Result<(), CliError> {
    write_bundle_signature_to_path(
        bundle,
        keypair,
        &bundle.join(PROOF_ROOM_BUNDLE_SIGNATURE_PATH),
    )
}

fn write_bundle_signature_to_path(
    bundle: &Path,
    keypair: &chio_core::Keypair,
    signature_path: &Path,
) -> Result<(), CliError> {
    let manifest_bytes = fs::read(bundle.join("manifest.json"))?;
    let signed_payload = dsse_pre_auth_encoding(PROOF_ROOM_DSSE_PAYLOAD_TYPE, &manifest_bytes);
    let signature = serde_json::json!({
        "payloadType": PROOF_ROOM_DSSE_PAYLOAD_TYPE,
        "payloadRef": {
            "path": "manifest.json",
            "sha256": chio_core::sha256_hex(&manifest_bytes),
            "schema": PROOF_ROOM_BUNDLE_SCHEMA
        },
        "signatures": [
            {
                "keyid": keypair.public_key().to_hex(),
                "sig": keypair.sign(&signed_payload).to_hex()
            }
        ]
    });
    write_json_line_file(signature_path, &signature)
}

pub(super) fn proof_collect_bundle_signer_from_env() -> Result<chio_core::Keypair, CliError> {
    match std::env::var(PROOF_COLLECT_BUNDLE_SIGNER_SEED_HEX_ENV) {
        Ok(seed_hex) => {
            let seed_hex = seed_hex.trim();
            if seed_hex.is_empty() {
                return Err(CliError::cli_other_error(format!(
                    "{PROOF_COLLECT_BUNDLE_SIGNER_SEED_HEX_ENV} must contain a 32-byte hex seed"
                )));
            }
            chio_core::Keypair::from_seed_hex(seed_hex).map_err(|error| {
                CliError::cli_other_error(format!(
                    "{PROOF_COLLECT_BUNDLE_SIGNER_SEED_HEX_ENV} is invalid: {error}"
                ))
            })
        }
        Err(std::env::VarError::NotPresent) => Err(CliError::cli_other_error(format!(
            "proof collect requires {PROOF_COLLECT_BUNDLE_SIGNER_SEED_HEX_ENV} to sign the collected bundle manifest"
        ))),
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::cli_other_error(format!(
            "{PROOF_COLLECT_BUNDLE_SIGNER_SEED_HEX_ENV} must be valid UTF-8"
        ))),
    }
}

fn write_collected_trust_roots(
    bundle: &Path,
    passport_id: &str,
    keypair: &chio_core::Keypair,
) -> Result<(), CliError> {
    let public_key = keypair.public_key().to_hex();
    let mut trust_roots = serde_json::json!({
        "schema": PROOF_ROOM_TRUST_ROOTS_SCHEMA,
        "id": format!("trust-roots-collected-{passport_id}"),
        "trust_domain": format!("did:chio:proof-room-collected:{passport_id}"),
        "roots": [
            {
                "subject": "did:chio:proof-room-collector",
                "key_id": public_key,
                "key_digest": chio_core::sha256_hex(public_key.as_bytes())
            }
        ]
    });
    sign_collected_json_artifact(&mut trust_roots, keypair)?;
    let path = bundle.join(PROOF_ROOM_TRUST_ROOTS_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    write_json_line_file(&path, &trust_roots)
}

fn sign_collected_json_artifact(
    value: &mut serde_json::Value,
    keypair: &chio_core::Keypair,
) -> Result<(), CliError> {
    let object = value.as_object_mut().ok_or_else(|| {
        CliError::cli_other_error("collected proof artifact must be a JSON object")
    })?;
    object.remove("signature");
    let (signature, _) = keypair.sign_canonical(value).map_err(|error| {
        CliError::cli_other_error(format!("failed to sign collected proof artifact: {error}"))
    })?;
    value["signature"] = serde_json::Value::String(signature.to_hex());
    Ok(())
}

fn dsse_pre_auth_encoding(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let payload_type = payload_type.as_bytes();
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"DSSEv1 ");
    encoded.extend_from_slice(payload_type.len().to_string().as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload_type);
    encoded.push(b' ');
    encoded.extend_from_slice(payload.len().to_string().as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload);
    encoded
}
