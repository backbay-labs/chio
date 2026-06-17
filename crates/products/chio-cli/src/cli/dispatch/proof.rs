use super::*;
use std::collections::{BTreeMap, BTreeSet};

const REQUIRED_RUNTIME_AUTHORITY_CLAIMS: [&str; 6] = [
    "claim.runtime.execution_lease_valid",
    "claim.runtime.nonce_fresh",
    "claim.runtime.revocation_fresh_at_dispatch",
    "claim.runtime.sandbox_attestation_matched",
    "claim.runtime.tool_server_ack_bound",
    "claim.runtime.receipt_totality_complete",
];
const CLAIM_PREFIX_RUNTIME: &str = "claim.runtime.";
const CLAIM_PREFIX_RISK: &str = "claim.risk.";
const CLAIM_PREFIX_ENTERPRISE: &str = "claim.enterprise.";
const CLAIM_PREFIX_AGENT_WEB: &str = "claim.agent_web.";
const CLAIM_PREFIX_TRUST_MARKET: &str = "claim.trust_market.";
const CLAIM_PREFIX_PUBLIC_SETTLEMENT: &str = "claim.public_settlement.";
const CLAIM_PREFIX_SWARM: &str = "claim.swarm.";
const CLAIM_PREFIX_DISCLOSURE: &str = "claim.disclosure.";
const CLAIM_PREFIX_COMMERCE: &str = "claim.commerce.";
const CLAIM_PREFIX_TRANSACTION: &str = "claim.transaction.";
const CLAIM_PREFIX_MARKET: &str = "claim.market.";
const STANDALONE_TRANSACTION_VERIFIED_CLAIMS: [&str; 3] = [
    "claim.transaction.passport_root_verified",
    "claim.transaction.evidence_graph_digest_bound",
    "claim.transaction.policy_digest_bound",
];
const AGENT_WEB_STANDARD_WEBHOOKS_SECRET_ENV: &str = "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_SECRET";
const AGENT_WEB_TRUSTED_KERNEL_KEYS_ENV: &str = "CHIO_AGENT_WEB_TRUSTED_KERNEL_KEYS";
const VERIFIER_CLAIM_PREFIXES: [&str; 11] = [
    CLAIM_PREFIX_RUNTIME,
    CLAIM_PREFIX_RISK,
    CLAIM_PREFIX_ENTERPRISE,
    CLAIM_PREFIX_AGENT_WEB,
    CLAIM_PREFIX_TRUST_MARKET,
    CLAIM_PREFIX_PUBLIC_SETTLEMENT,
    CLAIM_PREFIX_SWARM,
    CLAIM_PREFIX_DISCLOSURE,
    CLAIM_PREFIX_COMMERCE,
    CLAIM_PREFIX_TRANSACTION,
    CLAIM_PREFIX_MARKET,
];

fn agent_web_verifier_trust_from_env(
) -> Result<chio_control_plane::agent_web::AgentWebVerifierTrust, CliError> {
    let mut trust = match std::env::var(AGENT_WEB_STANDARD_WEBHOOKS_SECRET_ENV) {
        Ok(secret) => chio_control_plane::agent_web::AgentWebVerifierTrust::new()
            .with_standard_webhooks_secret(secret.into_bytes()),
        Err(std::env::VarError::NotPresent) => {
            chio_control_plane::agent_web::AgentWebVerifierTrust::new()
        }
        Err(std::env::VarError::NotUnicode(_)) => return Err(CliError::cli_other_error(format!(
            "{AGENT_WEB_STANDARD_WEBHOOKS_SECRET_ENV} must be valid UTF-8"
        ))),
    };
    match std::env::var(AGENT_WEB_TRUSTED_KERNEL_KEYS_ENV) {
        Ok(keys) => {
            trust =
                trust.with_trusted_receipt_kernel_keys(parse_agent_web_trusted_kernel_keys(&keys)?);
        }
        Err(std::env::VarError::NotPresent) => {}
        Err(std::env::VarError::NotUnicode(_)) => return Err(CliError::cli_other_error(format!(
            "{AGENT_WEB_TRUSTED_KERNEL_KEYS_ENV} must be valid UTF-8"
        ))),
    }
    Ok(trust)
}

fn parse_agent_web_trusted_kernel_keys(
    keys: &str,
) -> Result<Vec<chio_core_types::PublicKey>, CliError> {
    if keys.trim().is_empty() {
        return Err(CliError::cli_other_error(format!(
            "{AGENT_WEB_TRUSTED_KERNEL_KEYS_ENV} must contain comma-separated public keys"
        )));
    }

    keys.split(',')
        .map(|key| {
            let key = key.trim();
            if key.is_empty() {
                return Err(CliError::cli_other_error(format!(
                    "{AGENT_WEB_TRUSTED_KERNEL_KEYS_ENV} must not contain empty public keys"
                )));
            }
            chio_core_types::PublicKey::from_hex(key).map_err(|error| {
                CliError::cli_other_error(format!(
                    "{AGENT_WEB_TRUSTED_KERNEL_KEYS_ENV} contains invalid public key: {error}"
                ))
            })
        })
        .collect()
}

#[derive(Clone, Copy)]
enum LocalProofFamilyRoute {
    Commerce,
    DisclosureLineage,
    Swarm,
    PublicSettlement,
}

struct LocalProofFamilySpec {
    prefix: &'static str,
    label: &'static str,
    route: LocalProofFamilyRoute,
}

const LOCAL_PROOF_FAMILY_SPECS: &[LocalProofFamilySpec] = &[
    LocalProofFamilySpec {
        prefix: CLAIM_PREFIX_COMMERCE,
        label: "commerce",
        route: LocalProofFamilyRoute::Commerce,
    },
    LocalProofFamilySpec {
        prefix: CLAIM_PREFIX_DISCLOSURE,
        label: "disclosure lineage",
        route: LocalProofFamilyRoute::DisclosureLineage,
    },
    LocalProofFamilySpec {
        prefix: CLAIM_PREFIX_SWARM,
        label: "swarm",
        route: LocalProofFamilyRoute::Swarm,
    },
    LocalProofFamilySpec {
        prefix: CLAIM_PREFIX_PUBLIC_SETTLEMENT,
        label: "public settlement",
        route: LocalProofFamilyRoute::PublicSettlement,
    },
];

fn negative_failure_code_matches(error: &str, expected_code: &str) -> bool {
    error.match_indices(expected_code).any(|(index, _)| {
        let before = error[..index].chars().next_back();
        let after = error[index + expected_code.len()..].chars().next();
        negative_failure_code_start_boundary(before) && negative_failure_code_end_boundary(after)
    })
}

fn negative_failure_code_start_boundary(boundary: Option<char>) -> bool {
    boundary.is_none_or(|character| character == ':' || character.is_ascii_whitespace())
}

fn negative_failure_code_end_boundary(boundary: Option<char>) -> bool {
    boundary.is_none_or(|character| character == ':')
}

fn semantic_negative_failure_code(error: &str) -> String {
    let code = error
        .split("proof verify: ")
        .nth(1)
        .unwrap_or(error)
        .split(" (")
        .next()
        .unwrap_or(error)
        .trim();
    if code.is_empty() {
        error.to_string()
    } else {
        code.to_string()
    }
}

#[path = "proof/archive.rs"]
mod archive;
#[path = "proof/assemble.rs"]
mod assemble;
#[path = "proof/collect.rs"]
mod collect;
#[path = "proof/doctor.rs"]
mod doctor;
#[path = "proof/export.rs"]
mod export;
#[path = "proof/explain.rs"]
mod explain;
#[path = "proof/fixture.rs"]
mod fixture;
#[path = "proof/risk.rs"]
mod risk;
#[path = "proof/serve.rs"]
mod serve;

pub(crate) fn dispatch_proof(command: ProofCommands, _json_output: bool) -> Result<(), CliError> {
    match command {
        ProofCommands::Assemble {
            artifact_dir,
            verifier_policy,
            passport_id,
            issued_at,
            out,
        } => assemble::assemble_transaction_passport(
            &artifact_dir,
            &verifier_policy,
            &passport_id,
            &issued_at,
            &out,
            _json_output,
        ),
        ProofCommands::Collect {
            kind,
            artifact_dir,
            out,
        } => collect::collect_proof_bundle(kind, &artifact_dir, &out, _json_output),
        ProofCommands::Verify { path, out, require } => {
            verify_transaction_passport(&path, out.as_deref(), &require)
        }
        ProofCommands::Explain { bundle, claim } => {
            explain::explain_proof_claim(&bundle, &claim, _json_output)
        }
        ProofCommands::Fixture { command } => fixture::dispatch_proof_fixture(command, _json_output),
        ProofCommands::Serve {
            bundle,
            listen,
            dry_run,
        } => serve::serve_proof_bundle(&bundle, &listen, dry_run, _json_output),
        ProofCommands::Export {
            bundle,
            out,
            redact,
        } => export::export_proof_bundle(&bundle, &out, redact, _json_output),
        ProofCommands::Doctor { scenario, root } => {
            let scenario = scenario.unwrap_or(ProofDoctorScenario::SingleCallAuthority);
            doctor::run_proof_doctor(scenario, root.as_deref(), _json_output)
        }
    }
}

#[derive(serde::Deserialize)]
struct ProofBundleManifestClaims {
    #[serde(default)]
    claims: Vec<ProofBundleManifestClaim>,
}

#[derive(serde::Deserialize)]
struct ProofBundleManifestClaim {
    claim_id: String,
    #[serde(default)]
    required_artifacts: Vec<String>,
    #[serde(default)]
    source_refs: Vec<String>,
    #[serde(default)]
    result: String,
    #[serde(default)]
    checker: Option<String>,
    #[serde(default)]
    proof_level: Option<String>,
    #[serde(default)]
    caveat: Option<String>,
}

fn write_json_line_file<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), CliError> {
    let mut file = std::fs::File::create(path)?;
    serde_json::to_writer(&mut file, value)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn resolve_proof_passport_path(bundle: &Path) -> Result<PathBuf, CliError> {
    if bundle.is_file() {
        return Ok(bundle.to_path_buf());
    }
    let direct = bundle.join("transaction-passport.json");
    if direct.is_file() {
        return Ok(direct);
    }
    let proof_room_root = bundle.join("roots/transaction-passport.json");
    if proof_room_root.is_file() {
        return Ok(proof_room_root);
    }
    Err(CliError::cli_io_error(format!(
        "proof bundle has no transaction passport: {}",
        bundle.display()
    )))
}

fn proof_room_bundle_manifest_path_for_input(input_path: &Path) -> Option<PathBuf> {
    if input_path.is_dir() {
        let manifest_path = input_path.join("manifest.json");
        return manifest_path.is_file().then_some(manifest_path);
    }

    let parent = input_path.parent()?;
    let sibling_manifest = parent.join("manifest.json");
    if sibling_manifest.is_file() {
        return Some(sibling_manifest);
    }

    if parent.file_name().and_then(|name| name.to_str()) == Some("roots") {
        let bundle_manifest = parent.parent()?.join("manifest.json");
        if bundle_manifest.is_file() {
            return Some(bundle_manifest);
        }
    }

    None
}

fn load_manifest_claim(
    bundle: &Path,
    claim_id: &str,
) -> Result<Option<ProofBundleManifestClaim>, CliError> {
    let Some(manifest_path) = proof_room_bundle_manifest_path_for_input(bundle) else {
        return Ok(None);
    };
    let manifest_bytes = fs::read(&manifest_path)?;
    let manifest: ProofBundleManifestClaims = serde_json::from_slice(&manifest_bytes)?;
    Ok(manifest
        .claims
        .into_iter()
        .find(|claim| claim.claim_id == claim_id))
}

pub(super) fn verify_static_proof_bundle(bundle: &Path) -> Result<(), CliError> {
    let manifest_path = bundle.join("manifest.json");
    if !manifest_path.is_file() {
        return Err(CliError::cli_other_error(format!(
            "proof room bundle manifest missing: {}",
            manifest_path.display()
        )));
    }
    chio_proof_room::verify_proof_room_bundle(&manifest_path)
        .map_err(|error| CliError::cli_other_error(format!("proof room bundle: {error}")))
}

fn verify_transaction_passport(
    path: &Path,
    out: Option<&Path>,
    requirements: &[ProofVerifyRequirement],
) -> Result<(), CliError> {
    let archive_root = archive::extract_proof_archive(path)?;
    let input_path = match archive_root.as_ref() {
        Some(archive_root) => archive_root.path(),
        None => path,
    };
    verify_proof_room_bundle_if_present(input_path)?;
    let passport_path = resolve_proof_passport_path(input_path)?;
    let report = verify_transaction_passport_file(&passport_path)?;
    enforce_proof_verify_requirements(input_path, &report, requirements)?;

    if let Some(out) = out {
        if path_exists_or_is_symlink(out)? {
            return Err(CliError::cli_other_error(format!(
                "proof verify output already exists: {}",
                out.display()
            )));
        }
        if let Some(parent) = out.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        write_json_line_file(out, &report)?;
    }

    let mut stdout = std::io::stdout();
    serde_json::to_writer(&mut stdout, &report)?;
    stdout.write_all(b"\n")?;
    Ok(())
}

fn path_exists_or_is_symlink(path: &Path) -> Result<bool, CliError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(CliError::from(error)),
    }
}

fn enforce_proof_verify_requirements(
    input_path: &Path,
    report: &serde_json::Value,
    requirements: &[ProofVerifyRequirement],
) -> Result<(), CliError> {
    for requirement in requirements {
        match requirement {
            ProofVerifyRequirement::Commerce => {
                ensure_verified_claim_family(report, requirement.as_str(), CLAIM_PREFIX_COMMERCE)?;
            }
            ProofVerifyRequirement::Delegation => {
                ensure_verified_claim_family(report, requirement.as_str(), CLAIM_PREFIX_SWARM)?;
            }
            ProofVerifyRequirement::Denials => ensure_manifest_claim_verified(
                input_path,
                requirement.as_str(),
                "claim.proof_room.allow_and_deny_visible",
            )?,
            ProofVerifyRequirement::Disclosure => {
                ensure_verified_claim_family(report, requirement.as_str(), CLAIM_PREFIX_DISCLOSURE)?;
            }
            ProofVerifyRequirement::Enterprise => {
                ensure_verified_claim_family(report, requirement.as_str(), CLAIM_PREFIX_ENTERPRISE)?;
            }
            ProofVerifyRequirement::ExternalEnvelope => {
                ensure_verified_claim_family(report, requirement.as_str(), CLAIM_PREFIX_AGENT_WEB)?;
            }
            ProofVerifyRequirement::Risk => {
                ensure_verified_claim_family(report, requirement.as_str(), CLAIM_PREFIX_RISK)?;
            }
            ProofVerifyRequirement::Runtime => {
                ensure_runtime_authority_claims_verified(report)?;
            }
            ProofVerifyRequirement::RuntimeParity => {
                ensure_runtime_parity_verified(report)?;
            }
            ProofVerifyRequirement::Settlement => {
                ensure_verified_claim_family(
                    report,
                    requirement.as_str(),
                    CLAIM_PREFIX_PUBLIC_SETTLEMENT,
                )?;
            }
            ProofVerifyRequirement::TrustMarket => {
                ensure_verified_claim_family(report, requirement.as_str(), CLAIM_PREFIX_TRUST_MARKET)?;
            }
        }
    }
    Ok(())
}

fn ensure_manifest_claim_verified(
    input_path: &Path,
    label: &str,
    claim_id: &str,
) -> Result<(), CliError> {
    match load_manifest_claim(input_path, claim_id)? {
        Some(claim) if claim.result == "verified" => Ok(()),
        _ => Err(CliError::cli_other_error(format!(
            "required proof claim family missing: {label}"
        ))),
    }
}

fn ensure_verified_claim_family(
    report: &serde_json::Value,
    label: &str,
    claim_prefix: &str,
) -> Result<(), CliError> {
    let verified = verified_claims_array(report)
        .map(|claims| {
            claims.iter().any(|claim| {
                claim
                    .as_str()
                    .is_some_and(|claim| claim.starts_with(claim_prefix))
            })
        })
        .unwrap_or(false);
    if verified {
        Ok(())
    } else {
        Err(CliError::cli_other_error(format!(
            "required proof claim family missing: {label}"
        )))
    }
}

fn ensure_runtime_authority_claims_verified(report: &serde_json::Value) -> Result<(), CliError> {
    let verified_claims = verified_claims_array(report).ok_or_else(|| {
        CliError::cli_other_error("required proof claim family missing: runtime".to_string())
    })?;
    for required_claim in REQUIRED_RUNTIME_AUTHORITY_CLAIMS {
        if !verified_claims
            .iter()
            .any(|claim| claim.as_str() == Some(required_claim))
        {
            return Err(CliError::cli_other_error(format!(
                "required proof runtime authority missing: {required_claim}"
            )));
        }
    }
    Ok(())
}

fn ensure_runtime_parity_verified(report: &serde_json::Value) -> Result<(), CliError> {
    if runtime_parity_report_is_accepted(report) {
        return Ok(());
    }
    if report
        .get("runtime_proof_parity_report")
        .is_some_and(runtime_parity_report_is_accepted)
    {
        return Ok(());
    }

    Err(CliError::cli_other_error(
        "required proof runtime parity missing",
    ))
}

fn runtime_parity_report_is_accepted(report: &serde_json::Value) -> bool {
    let schema_matches = report
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|schema| schema == chio_runtime_core::CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA);
    let accepted = report
        .get("accepted")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let mismatches_empty = report
        .get("mismatches")
        .and_then(serde_json::Value::as_array)
        .is_some_and(Vec::is_empty);

    schema_matches && accepted && mismatches_empty
}

fn verified_claims_array(report: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
    report
        .get("verified_claims")
        .or_else(|| report.get("verifiedClaims"))
        .and_then(serde_json::Value::as_array)
}

fn verify_proof_room_bundle_if_present(input_path: &Path) -> Result<(), CliError> {
    let Some(manifest_path) = proof_room_bundle_manifest_path_for_input(input_path) else {
        return Ok(());
    };
    chio_proof_room::verify_proof_room_bundle(&manifest_path)
        .map_err(|error| CliError::cli_other_error(format!("proof room bundle: {error}")))
}

pub(super) fn verify_transaction_passport_file(
    path: &Path,
) -> Result<serde_json::Value, CliError> {
    let passport_bytes = fs::read(path)?;
    let passport: chio_control_plane::transaction_passport::TransactionPassport =
        serde_json::from_slice(&passport_bytes)?;

    chio_control_plane::transaction_passport::verify_minimal_passport_schema(&passport)
        .map_err(map_proof_error)?;

    let bundle_dir = path.parent().ok_or_else(|| {
        CliError::cli_io_error(format!(
            "transaction passport path has no parent directory: {}",
            path.display()
        ))
    })?;

    let evidence_graph_path =
        resolve_bundle_artifact_path(bundle_dir, &passport.evidence_graph_path)?;
    let verifier_policy_path =
        resolve_bundle_artifact_path(bundle_dir, &passport.verifier_policy_path)?;
    let evidence_graph_bytes = fs::read(&evidence_graph_path)?;
    let verifier_policy_bytes = fs::read(&verifier_policy_path)?;
    let passport_report_path = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned());

    verify_transaction_passport_artifact_digests(
        &passport,
        &evidence_graph_bytes,
        &verifier_policy_bytes,
    )?;
    chio_control_plane::transaction_passport::validate_verifier_policy_artifact(
        &verifier_policy_bytes,
    )
    .map_err(map_proof_error)?;

    let claim_requirements = verifier_policy_claim_requirements(&verifier_policy_bytes)?;
    let risk_route = risk::risk_route(
        &evidence_graph_bytes,
        claim_requirements.requires(CLAIM_PREFIX_RISK),
    )?;
    let mut family_reports = Vec::new();
    for spec in LOCAL_PROOF_FAMILY_SPECS {
        if claim_requirements.requires(spec.prefix) {
            push_local_proof_family_report(
                &mut family_reports,
                &claim_requirements,
                &passport,
                bundle_dir,
                &evidence_graph_bytes,
                spec,
            )?;
        }
    }
    if risk_route.standalone {
        family_reports.push(risk::verify_standalone_risk_claim(
            &passport,
            bundle_dir,
            &evidence_graph_bytes,
            &claim_requirements,
            &passport_report_path,
        )?);
    }
    if claim_requirements.requires(CLAIM_PREFIX_TRUST_MARKET) || risk_route.through_trust_market {
        let trust_market_evidence_graph_bytes =
            scoped_evidence_graph_bytes(&evidence_graph_bytes, is_trust_market_evidence_graph_node)?;
        let artifacts =
            load_trust_market_artifacts_from_graph(bundle_dir, &trust_market_evidence_graph_bytes)?;
        let trust_market_passport =
            passport_for_evidence_graph(&passport, &trust_market_evidence_graph_bytes);
        let report = chio_control_plane::trust_market::verify_trust_market_context(
            &chio_control_plane::trust_market::TrustMarketBundle {
                passport: trust_market_passport,
                evidence_graph_bytes: trust_market_evidence_graph_bytes,
                verifier_policy_bytes: verifier_policy_bytes.clone(),
                artifacts,
            },
        )
        .map_err(map_proof_error)?;
        push_family_report(&mut family_reports, report)?;
    }
    if claim_requirements.requires(CLAIM_PREFIX_AGENT_WEB) {
        let agent_web_trust = agent_web_verifier_trust_from_env()?;
        let artifacts = load_agent_web_artifacts_from_graph(bundle_dir, &evidence_graph_bytes)?;
        let agent_web_evidence_graph_bytes = scoped_evidence_graph_bytes(
            &evidence_graph_bytes,
            is_agent_web_evidence_graph_node,
        )?;
        let agent_web_passport =
            passport_for_evidence_graph(&passport, &agent_web_evidence_graph_bytes);
        let report = chio_control_plane::agent_web::verify_agent_web_interop_with_trust(
            &chio_control_plane::agent_web::AgentWebInteropBundle {
                passport: agent_web_passport,
                evidence_graph_bytes: agent_web_evidence_graph_bytes,
                verifier_policy_bytes: verifier_policy_bytes.clone(),
                artifacts,
            },
            &agent_web_trust,
        )
        .map_err(map_proof_error)?;
        push_family_report(&mut family_reports, report)?;
    }
    if claim_requirements.requires(CLAIM_PREFIX_ENTERPRISE) || risk_route.through_enterprise {
        let enterprise_evidence_graph_bytes =
            scoped_evidence_graph_bytes(&evidence_graph_bytes, is_enterprise_evidence_graph_node)?;
        let artifacts =
            load_enterprise_artifacts_from_graph(bundle_dir, &enterprise_evidence_graph_bytes)?;
        let enterprise_passport =
            passport_for_evidence_graph(&passport, &enterprise_evidence_graph_bytes);
        let report = chio_control_plane::enterprise_export::verify_enterprise_export(
            &chio_control_plane::enterprise_export::EnterpriseExportBundle {
                passport: enterprise_passport,
                evidence_graph_bytes: enterprise_evidence_graph_bytes,
                verifier_policy_bytes: verifier_policy_bytes.clone(),
                artifacts,
            },
        )
        .map_err(map_proof_error)?;
        push_family_report(&mut family_reports, report)?;
    }
    if claim_requirements.requires(CLAIM_PREFIX_RUNTIME) {
        let runtime_evidence_graph_bytes =
            scoped_evidence_graph_bytes(&evidence_graph_bytes, is_runtime_evidence_graph_node)?;
        let artifacts = load_runtime_artifacts_from_graph(bundle_dir, &runtime_evidence_graph_bytes)?;
        let runtime_passport =
            passport_for_evidence_graph(&passport, &runtime_evidence_graph_bytes);
        let report = chio_control_plane::transaction_passport::verify_runtime_security_claims(
            &chio_control_plane::transaction_passport::RuntimeSecurityBundle {
                passport: runtime_passport,
                evidence_graph_bytes: runtime_evidence_graph_bytes,
                verifier_policy_bytes: verifier_policy_bytes.clone(),
                artifacts,
            },
        )
        .map_err(map_proof_error)?;
        push_family_report(&mut family_reports, report)?;
    }
    let mut report = if family_reports.is_empty() {
        let artifact_base_dir = standalone_evidence_artifact_base_dir(bundle_dir);
        let artifacts =
            load_standalone_evidence_graph_artifacts(&artifact_base_dir, &evidence_graph_bytes)?;
        let report =
            chio_control_plane::transaction_passport::verify_standalone_minimal_passport_artifacts(
                &passport,
                passport_report_path,
                &evidence_graph_bytes,
                &verifier_policy_bytes,
                &artifacts,
            )
            .map_err(map_proof_error)?;
        serde_json::to_value(report).map_err(CliError::from)
    } else if family_reports.len() == 1 {
        Ok(family_reports.remove(0))
    } else {
        Ok(merge_family_verifier_reports(
            &passport,
            passport_report_path,
            family_reports,
        ))
    }?;
    attach_runtime_proof_parity_report(bundle_dir, &evidence_graph_bytes, &mut report)?;
    ensure_policy_required_claims_verified(&claim_requirements, &report)?;
    Ok(report)
}

fn push_local_proof_family_report(
    family_reports: &mut Vec<serde_json::Value>,
    claim_requirements: &VerifierPolicyClaimRequirements,
    passport: &chio_control_plane::transaction_passport::TransactionPassport,
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
    spec: &LocalProofFamilySpec,
) -> Result<(), CliError> {
    match spec.route {
        LocalProofFamilyRoute::Commerce => {
            let bundle = load_commerce_order_bundle_from_graph(bundle_dir, evidence_graph_bytes)?;
            let report = chio_commerce_order::verify_commerce_order(&bundle)
                .map_err(|error| CliError::cli_other_error(format!("proof verify: {error}")))?;
            push_checked_local_family_report(family_reports, claim_requirements, spec, report)
        }
        LocalProofFamilyRoute::DisclosureLineage => {
            let bundle =
                load_disclosure_lineage_bundle_from_graph(bundle_dir, evidence_graph_bytes)?;
            let report = chio_selective_disclosure::verify_disclosure_lineage_bundle(&bundle)
                .map_err(|error| CliError::cli_other_error(format!("proof verify: {error}")))?;
            push_checked_local_family_report(family_reports, claim_requirements, spec, report)
        }
        LocalProofFamilyRoute::Swarm => {
            let bundle = load_swarm_authority_bundle_from_graph(bundle_dir, evidence_graph_bytes)?;
            let report = chio_swarm_authority::verify_swarm_authority_bundle(&bundle)
                .map_err(|error| CliError::cli_other_error(format!("proof verify: {error}")))?;
            push_checked_local_family_report(family_reports, claim_requirements, spec, report)
        }
        LocalProofFamilyRoute::PublicSettlement => {
            let proof_bundle =
                load_public_settlement_proof_bundle_from_graph(bundle_dir, evidence_graph_bytes)?;
            if proof_bundle.transaction_passport_id != passport.id {
                return Err(CliError::cli_other_error(format!(
                    "proof verify: public settlement proof bundle passport mismatch: expected {}, got {}",
                    passport.id, proof_bundle.transaction_passport_id
                )));
            }
            let report = chio_web3::settlement_proof::verify_public_settlement_proof(&proof_bundle)
                .map_err(|error| CliError::cli_other_error(format!("proof verify: {error}")))?;
            push_checked_local_family_report(family_reports, claim_requirements, spec, report)
        }
    }
}

fn push_checked_local_family_report<T: serde::Serialize>(
    family_reports: &mut Vec<serde_json::Value>,
    claim_requirements: &VerifierPolicyClaimRequirements,
    spec: &LocalProofFamilySpec,
    report: T,
) -> Result<(), CliError>
{
    let report = serde_json::to_value(report).map_err(CliError::from)?;
    ensure_required_claims_verified(
        claim_requirements,
        &report,
        spec.prefix,
        spec.label,
    )?;
    family_reports.push(report);
    Ok(())
}

fn push_family_report<T: serde::Serialize>(
    family_reports: &mut Vec<serde_json::Value>,
    report: T,
) -> Result<(), CliError> {
    family_reports.push(serde_json::to_value(report).map_err(CliError::from)?);
    Ok(())
}

fn merge_family_verifier_reports(
    passport: &chio_control_plane::transaction_passport::TransactionPassport,
    passport_report_path: String,
    family_reports: Vec<serde_json::Value>,
) -> serde_json::Value {
    let mut seen_claims = BTreeSet::new();
    let mut verified_claims = Vec::new();
    for report in &family_reports {
        if let Some(claims) = verified_claims_array(report) {
            for claim in claims {
                let Some(claim) = claim.as_str() else {
                    continue;
                };
                if seen_claims.insert(claim.to_string()) {
                    verified_claims.push(serde_json::Value::String(claim.to_string()));
                }
            }
        }
    }

    serde_json::json!({
        "schema": "chio.transaction.verifier-report.v1",
        "id": format!("verifier-report-{}", passport.id),
        "issued_at": passport.issued_at.clone(),
        "verdict": "verified",
        "passport_id": passport.id.clone(),
        "passport_path": passport_report_path,
        "evidence_graph_sha256": passport.evidence_graph_sha256.clone(),
        "evidence_graph_path": passport.evidence_graph_path.clone(),
        "verifier_policy_sha256": passport.verifier_policy_sha256.clone(),
        "verifier_policy_path": passport.verifier_policy_path.clone(),
        "verified_claims": verified_claims,
        "family_reports": family_reports,
    })
}

fn standalone_evidence_artifact_base_dir(bundle_dir: &Path) -> PathBuf {
    if bundle_dir.file_name().and_then(|name| name.to_str()) == Some("roots") {
        if let Some(parent) = bundle_dir.parent() {
            if parent.join("manifest.json").is_file() {
                return parent.to_path_buf();
            }
        }
    }
    bundle_dir.to_path_buf()
}

#[derive(serde::Deserialize)]
struct StandaloneEvidenceGraphArtifactIndex {
    nodes: Vec<StandaloneEvidenceGraphArtifactNode>,
}

#[derive(serde::Deserialize)]
struct StandaloneEvidenceGraphArtifactNode {
    path: String,
}

#[derive(serde::Deserialize)]
struct RuntimeParityEvidenceGraph {
    nodes: Vec<RuntimeParityEvidenceNode>,
}

#[derive(serde::Deserialize)]
struct RuntimeParityEvidenceNode {
    path: String,
    schema: String,
    sha256: String,
    #[serde(default)]
    role: String,
}

fn attach_runtime_proof_parity_report(
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
    report: &mut serde_json::Value,
) -> Result<(), CliError> {
    let Some(parity_report) =
        load_runtime_proof_parity_report_from_graph(bundle_dir, evidence_graph_bytes)?
    else {
        return Ok(());
    };
    if !runtime_parity_report_is_accepted(&parity_report) {
        return Err(CliError::cli_other_error(
            "proof verify: runtime proof parity report is not accepted".to_string(),
        ));
    }
    validate_runtime_proof_regeneration_artifacts_from_graph(bundle_dir, evidence_graph_bytes)?;
    let report_object = report.as_object_mut().ok_or_else(|| {
        CliError::cli_other_error("proof verify: verifier report is not a JSON object".to_string())
    })?;
    report_object.insert("runtime_proof_parity_report".to_string(), parity_report);
    Ok(())
}

fn load_runtime_proof_parity_report_from_graph(
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
) -> Result<Option<serde_json::Value>, CliError> {
    let graph: RuntimeParityEvidenceGraph = serde_json::from_slice(evidence_graph_bytes)?;
    let parity_nodes = graph
        .nodes
        .into_iter()
        .filter(|node| {
            node.role == "runtime-proof-parity-report"
                || node.schema == chio_runtime_core::CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA
        })
        .collect::<Vec<_>>();
    let node = match parity_nodes.as_slice() {
        [] => return Ok(None),
        [node] => node,
        _ => {
            return Err(CliError::cli_other_error(
                "proof verify: multiple runtime proof parity reports".to_string(),
            ));
        }
    };
    if node.schema != chio_runtime_core::CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA {
        return Err(CliError::cli_other_error(format!(
            "proof verify: unsupported runtime proof parity schema: {}",
            node.schema
        )));
    }
    let parity_path = resolve_bundle_artifact_path(bundle_dir, &node.path)?;
    let parity_bytes = fs::read(&parity_path)?;
    let actual_sha256 = chio_core::sha256_hex(&parity_bytes);
    if actual_sha256 != node.sha256 {
        return Err(CliError::cli_other_error(format!(
            "proof verify: runtime proof parity report digest mismatch: expected {}, got {}",
            node.sha256, actual_sha256
        )));
    }
    let parity_report: chio_runtime_core::RuntimeProofParityReport =
        serde_json::from_slice(&parity_bytes)?;
    chio_runtime_core::validate_runtime_proof_parity_report(&parity_report)
        .map_err(|error| CliError::cli_other_error(format!("proof verify: {error}")))?;
    serde_json::to_value(parity_report)
        .map(Some)
        .map_err(CliError::from)
}

fn validate_runtime_proof_regeneration_artifacts_from_graph(
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
) -> Result<(), CliError> {
    let graph: RuntimeParityEvidenceGraph = serde_json::from_slice(evidence_graph_bytes)?;
    if !graph
        .nodes
        .iter()
        .any(runtime_proof_regeneration_node_is_present)
    {
        return Ok(());
    }
    let proof_regeneration_report = runtime_graph_artifact_bytes(
        bundle_dir,
        &graph.nodes,
        "runtime-proof-regeneration-report",
        Some(chio_runtime_core::CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA),
    )?;
    let proof_regeneration_input = runtime_graph_artifact_bytes(
        bundle_dir,
        &graph.nodes,
        "runtime-proof-regeneration-input",
        Some(chio_runtime_core::CHIO_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA),
    )?;
    let evidence_manifest = runtime_graph_artifact_bytes(
        bundle_dir,
        &graph.nodes,
        "runtime-evidence-manifest",
        Some(chio_runtime_core::CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA),
    )?;
    let workflow_run_report = runtime_graph_artifact_bytes(
        bundle_dir,
        &graph.nodes,
        "runtime-workflow-run-report",
        Some(chio_runtime_core::CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA),
    )?;
    let proof_package =
        runtime_graph_artifact_bytes(bundle_dir, &graph.nodes, "runtime-proof-package", None)?;
    let verifier_report =
        runtime_graph_artifact_bytes(bundle_dir, &graph.nodes, "runtime-verifier-report", None)?;
    let workflow_receipt =
        runtime_graph_artifact_bytes(bundle_dir, &graph.nodes, "runtime-workflow-receipt", None)?;

    chio_runtime_core::validate_runtime_proof_regeneration_artifacts(
        chio_runtime_core::RuntimeProofRegenerationArtifacts {
            proof_regeneration_report: &proof_regeneration_report,
            proof_regeneration_input: &proof_regeneration_input,
            evidence_manifest: &evidence_manifest,
            workflow_run_report: &workflow_run_report,
            proof_package: &proof_package,
            verifier_report: &verifier_report,
            workflow_receipt: &workflow_receipt,
        },
    )
    .map_err(|error| CliError::cli_other_error(format!("proof verify: {error}")))
}

fn runtime_proof_regeneration_node_is_present(node: &RuntimeParityEvidenceNode) -> bool {
    matches!(
        node.role.as_str(),
        "runtime-proof-regeneration-report"
            | "runtime-proof-regeneration-input"
            | "runtime-evidence-manifest"
            | "runtime-workflow-run-report"
    ) || matches!(
        node.schema.as_str(),
        chio_runtime_core::CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA
            | chio_runtime_core::CHIO_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA
            | chio_runtime_core::CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA
            | chio_runtime_core::CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA
    )
}

fn runtime_graph_artifact_bytes(
    bundle_dir: &Path,
    nodes: &[RuntimeParityEvidenceNode],
    role: &str,
    schema: Option<&str>,
) -> Result<Vec<u8>, CliError> {
    let matching_nodes = nodes
        .iter()
        .filter(|node| {
            node.role == role || schema.is_some_and(|expected_schema| node.schema == expected_schema)
        })
        .collect::<Vec<_>>();
    let node = match matching_nodes.as_slice() {
        [node] => *node,
        [] => {
            return Err(CliError::cli_other_error(format!(
                "proof verify: runtime proof regeneration evidence missing: {role}"
            )));
        }
        _ => {
            return Err(CliError::cli_other_error(format!(
                "proof verify: multiple runtime proof regeneration artifacts: {role}"
            )));
        }
    };
    if let Some(expected_schema) = schema {
        if node.schema != expected_schema {
            return Err(CliError::cli_other_error(format!(
                "proof verify: unsupported runtime proof regeneration schema for {role}: {}",
                node.schema
            )));
        }
    }
    let artifact_path = resolve_bundle_artifact_path(bundle_dir, &node.path)?;
    let bytes = fs::read(&artifact_path)?;
    let actual_sha256 = chio_core::sha256_hex(&bytes);
    if actual_sha256 != node.sha256 {
        return Err(CliError::cli_other_error(format!(
            "proof verify: runtime proof regeneration artifact digest mismatch for {role}: expected {}, got {}",
            node.sha256, actual_sha256
        )));
    }
    Ok(bytes)
}

fn load_standalone_evidence_graph_artifacts(
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
) -> Result<BTreeMap<String, Vec<u8>>, CliError> {
    let graph: StandaloneEvidenceGraphArtifactIndex = serde_json::from_slice(evidence_graph_bytes)?;
    let mut artifacts = BTreeMap::new();
    for node in graph.nodes {
        let Some(artifact_path) = try_resolve_bundle_artifact_path(bundle_dir, &node.path)? else {
            continue;
        };
        let bytes = fs::read(&artifact_path)?;
        artifacts.insert(node.path.clone(), bytes);
    }
    Ok(artifacts)
}

fn resolve_bundle_artifact_path(bundle_dir: &Path, relative_path: &str) -> Result<PathBuf, CliError> {
    try_resolve_bundle_artifact_path(bundle_dir, relative_path)?.ok_or_else(|| {
        CliError::cli_io_error(format!("proof artifact not found: {relative_path}"))
    })
}

fn try_resolve_bundle_artifact_path(
    bundle_dir: &Path,
    relative_path: &str,
) -> Result<Option<PathBuf>, CliError> {
    let relative_path = crate::archive::safe_archive_member_path(relative_path, "proof artifact")?;
    for bundle_root in bundle_artifact_roots(bundle_dir)? {
        let joined_path = bundle_root.join(&relative_path);
        match fs::canonicalize(&joined_path) {
            Ok(resolved_path) if resolved_path.starts_with(&bundle_root) => {
                return Ok(Some(resolved_path));
            }
            Ok(_) => {
                return Err(CliError::cli_io_error(format!(
                    "artifact path escapes proof bundle: {relative_path}"
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(CliError::from(error)),
        }
    }
    Ok(None)
}

fn bundle_artifact_roots(bundle_dir: &Path) -> Result<Vec<PathBuf>, CliError> {
    let bundle_root = fs::canonicalize(bundle_dir)?;
    let mut roots = vec![bundle_root.clone()];
    if bundle_root.file_name().and_then(|name| name.to_str()) == Some("roots") {
        if let Some(parent) = bundle_root.parent() {
            if parent.join("manifest.json").is_file() {
                roots.push(parent.to_path_buf());
            }
        }
    }
    Ok(roots)
}

fn verify_transaction_passport_artifact_digests(
    passport: &chio_control_plane::transaction_passport::TransactionPassport,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
) -> Result<(), CliError> {
    let evidence_graph_sha256 = chio_core::sha256_hex(evidence_graph_bytes);
    if evidence_graph_sha256 != passport.evidence_graph_sha256 {
        return Err(map_proof_error(
            chio_control_plane::transaction_passport::TransactionPassportError::EvidenceGraphDigestMismatch {
                expected: passport.evidence_graph_sha256.clone(),
                actual: evidence_graph_sha256,
            },
        ));
    }

    let verifier_policy_sha256 = chio_core::sha256_hex(verifier_policy_bytes);
    if verifier_policy_sha256 != passport.verifier_policy_sha256 {
        return Err(map_proof_error(
            chio_control_plane::transaction_passport::TransactionPassportError::VerifierPolicyDigestMismatch {
                expected: passport.verifier_policy_sha256.clone(),
                actual: verifier_policy_sha256,
            },
        ));
    }

    Ok(())
}

#[derive(Default)]
struct VerifierPolicyClaimRequirements {
    required_claims: Vec<serde_json::Value>,
    prefixes: BTreeSet<&'static str>,
}

impl VerifierPolicyClaimRequirements {
    fn requires(&self, prefix: &'static str) -> bool {
        self.prefixes.contains(prefix)
    }
}

fn verifier_policy_claim_requirements(
    policy_bytes: &[u8],
) -> Result<VerifierPolicyClaimRequirements, CliError> {
    let policy: serde_json::Value = serde_json::from_slice(policy_bytes)?;
    let mut requirements = VerifierPolicyClaimRequirements::default();
    if let Some(claims) = policy
        .get("required_claims")
        .and_then(serde_json::Value::as_array)
    {
        requirements.required_claims = claims.clone();
        for claim in claims {
            let Some(claim) = claim.as_str() else {
                return Err(CliError::cli_other_error(
                    "proof verify: required claims must be strings".to_string(),
                ));
            };
            let mut supported = false;
            for prefix in VERIFIER_CLAIM_PREFIXES {
                if claim.starts_with(prefix) {
                    requirements.prefixes.insert(prefix);
                    supported = true;
                }
            }
            if !supported {
                return Err(CliError::cli_other_error(format!(
                    "proof verify: unsupported required proof claim: {claim}",
                )));
            }
        }
    }
    Ok(requirements)
}

#[derive(serde::Deserialize)]
struct GraphArtifactPaths {
    nodes: Vec<GraphArtifactNode>,
}

#[derive(serde::Deserialize)]
struct GraphArtifactNode {
    #[serde(default)]
    id: Option<String>,
    path: String,
    role: String,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    schema: Option<String>,
}

fn parse_graph_artifact_paths(evidence_graph_bytes: &[u8]) -> Result<GraphArtifactPaths, CliError> {
    serde_json::from_slice(evidence_graph_bytes).map_err(CliError::from)
}

fn select_required_graph_node<'a>(
    nodes: &'a [GraphArtifactNode],
    role: &str,
    label: &str,
) -> Result<&'a GraphArtifactNode, CliError> {
    let matches = graph_nodes_by_role(nodes, role);
    match matches.as_slice() {
        [node] => Ok(node),
        [] => Err(CliError::cli_other_error(format!(
            "proof verify: missing {label} artifact role: {role}",
        ))),
        _ => Err(CliError::cli_other_error(format!(
            "proof verify: multiple {label} artifact roles: {role}",
        ))),
    }
}

fn graph_nodes_by_role<'a>(
    nodes: &'a [GraphArtifactNode],
    role: &str,
) -> Vec<&'a GraphArtifactNode> {
    nodes.iter().filter(|node| node.role == role).collect()
}

fn load_required_graph_json_artifact<T: for<'de> serde::Deserialize<'de>>(
    bundle_dir: &Path,
    nodes: &[GraphArtifactNode],
    role: &str,
    expected_schema: &str,
    label: &str,
) -> Result<T, CliError> {
    let bytes = load_required_graph_bytes_artifact(
        bundle_dir,
        nodes,
        role,
        expected_schema,
        label,
    )?;
    serde_json::from_slice(&bytes).map_err(CliError::from)
}

fn load_required_graph_bytes_artifact(
    bundle_dir: &Path,
    nodes: &[GraphArtifactNode],
    role: &str,
    expected_schema: &str,
    label: &str,
) -> Result<Vec<u8>, CliError> {
    let node = select_required_graph_node(nodes, role, label)?;
    load_graph_bytes_artifact(bundle_dir, node, expected_schema, label)
}

fn load_optional_graph_json_artifact<T: for<'de> serde::Deserialize<'de>>(
    bundle_dir: &Path,
    nodes: &[GraphArtifactNode],
    role: &str,
    expected_schema: &str,
    label: &str,
) -> Result<Option<T>, CliError> {
    let matches = graph_nodes_by_role(nodes, role);
    match matches.as_slice() {
        [node] => load_graph_json_artifact(bundle_dir, node, expected_schema, label).map(Some),
        [] => Ok(None),
        _ => Err(CliError::cli_other_error(format!(
            "proof verify: multiple {label} artifact roles: {role}",
        ))),
    }
}

fn load_required_graph_json_artifacts<T: for<'de> serde::Deserialize<'de>>(
    bundle_dir: &Path,
    nodes: &[GraphArtifactNode],
    role: &str,
    expected_schema: &str,
    label: &str,
) -> Result<Vec<T>, CliError> {
    let mut artifacts = Vec::new();
    for node in graph_nodes_by_role(nodes, role) {
        artifacts.push(load_graph_json_artifact(
            bundle_dir,
            node,
            expected_schema,
            label,
        )?);
    }
    if artifacts.is_empty() {
        return Err(CliError::cli_other_error(format!(
            "proof verify: missing {label} artifact role: {role}",
        )));
    }
    Ok(artifacts)
}

fn load_graph_json_artifact<T: for<'de> serde::Deserialize<'de>>(
    bundle_dir: &Path,
    node: &GraphArtifactNode,
    expected_schema: &str,
    label: &str,
) -> Result<T, CliError> {
    let bytes = load_graph_bytes_artifact(bundle_dir, node, expected_schema, label)?;
    serde_json::from_slice(&bytes).map_err(CliError::from)
}

fn load_graph_bytes_artifact(
    bundle_dir: &Path,
    node: &GraphArtifactNode,
    expected_schema: &str,
    label: &str,
) -> Result<Vec<u8>, CliError> {
    let schema = graph_node_schema(node, label)?;
    if schema != expected_schema {
        return Err(CliError::cli_other_error(format!(
            "proof verify: unsupported {label} artifact schema for {}: {schema}",
            node.path,
        )));
    }
    let bytes = read_graph_artifact(bundle_dir, node)?;
    let actual_digest = chio_core::sha256_hex(&bytes);
    let expected_digest = graph_node_sha256(node, label)?;
    if actual_digest != expected_digest {
        return Err(CliError::cli_other_error(format!(
            "proof verify: {label} artifact digest mismatch for {}: expected {}, got {}",
            node.path, expected_digest, actual_digest,
        )));
    }
    Ok(bytes)
}

fn graph_node_schema<'a>(node: &'a GraphArtifactNode, label: &str) -> Result<&'a str, CliError> {
    node.schema.as_deref().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "proof verify: missing {label} artifact schema for {}",
            node.path,
        ))
    })
}

fn graph_node_sha256<'a>(node: &'a GraphArtifactNode, label: &str) -> Result<&'a str, CliError> {
    node.sha256.as_deref().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "proof verify: missing {label} artifact digest for {}",
            node.path,
        ))
    })
}

fn load_graph_artifacts_matching(
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
    include_node: impl Fn(&GraphArtifactNode) -> bool,
) -> Result<BTreeMap<String, Vec<u8>>, CliError> {
    let graph = parse_graph_artifact_paths(evidence_graph_bytes)?;
    let mut artifacts = BTreeMap::new();
    for node in graph.nodes.iter().filter(|node| include_node(node)) {
        artifacts.insert(node.path.clone(), read_graph_artifact(bundle_dir, node)?);
    }
    Ok(artifacts)
}

fn read_graph_artifact(
    bundle_dir: &Path,
    node: &GraphArtifactNode,
) -> Result<Vec<u8>, CliError> {
    let artifact_path = resolve_bundle_artifact_path(bundle_dir, &node.path)?;
    fs::read(artifact_path).map_err(CliError::from)
}

fn load_commerce_order_bundle_from_graph(
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
) -> Result<chio_commerce_order::CommerceOrderVerificationBundle, CliError> {
    let graph = parse_graph_artifact_paths(evidence_graph_bytes)?;
    let order_context: chio_commerce_order::CommerceOrderContext =
        load_required_graph_json_artifact(
            bundle_dir,
            &graph.nodes,
            "commerce-order-context",
            chio_commerce_order::COMMERCE_ORDER_CONTEXT_SCHEMA_ID,
            "commerce",
        )?;
    let event_log_bytes = load_required_graph_bytes_artifact(
        bundle_dir,
        &graph.nodes,
        "commerce-event-log",
        chio_commerce_order::COMMERCE_EVENT_LOG_SCHEMA_ID,
        "commerce",
    )?;
    let payment_lifecycle_bytes = load_required_graph_bytes_artifact(
        bundle_dir,
        &graph.nodes,
        "commerce-payment-lifecycle",
        chio_commerce_order::COMMERCE_PAYMENT_LIFECYCLE_SCHEMA_ID,
        "commerce",
    )?;
    let mandate_ledger_bytes = load_required_graph_bytes_artifact(
        bundle_dir,
        &graph.nodes,
        "commerce-mandate-allowance-ledger",
        chio_commerce_order::COMMERCE_MANDATE_ALLOWANCE_LEDGER_SCHEMA_ID,
        "commerce",
    )?;

    Ok(
        chio_commerce_order::CommerceOrderVerificationBundle {
            order_context,
            event_log_bytes,
            payment_lifecycle_bytes,
            mandate_ledger_bytes,
        },
    )
}

fn ensure_required_claims_verified(
    policy: &VerifierPolicyClaimRequirements,
    report: &serde_json::Value,
    prefix: &str,
    label: &str,
) -> Result<(), CliError> {
    let verified_claims = verified_claims_array(report).ok_or_else(|| {
        CliError::cli_other_error(format!(
            "proof verify: {label} verifier report missing verified_claims"
        ))
    })?;
    for required_claim in &policy.required_claims {
        let Some(required_claim) = required_claim.as_str() else {
            return Err(CliError::cli_other_error(
                "proof verify: required claims must be strings".to_string(),
            ));
        };
        if !required_claim.starts_with(prefix) {
            continue;
        }
        if !verified_claims
            .iter()
            .any(|verified_claim| verified_claim.as_str() == Some(required_claim))
        {
            return Err(CliError::cli_other_error(format!(
                "proof verify: required {label} claim not verified: {required_claim}",
            )));
        }
    }
    Ok(())
}

fn ensure_policy_required_claims_verified(
    policy: &VerifierPolicyClaimRequirements,
    report: &serde_json::Value,
) -> Result<(), CliError> {
    for required_claim in &policy.required_claims {
        let Some(required_claim) = required_claim.as_str() else {
            return Err(CliError::cli_other_error(
                "proof verify: required claims must be strings".to_string(),
            ));
        };
        if !report_verifies_required_claim(report, required_claim) {
            return Err(CliError::cli_other_error(format!(
                "proof verify: required proof claim not verified: {required_claim}",
            )));
        }
    }
    Ok(())
}

fn report_verifies_required_claim(report: &serde_json::Value, required_claim: &str) -> bool {
    verified_claims_array(report)
        .is_some_and(|claims| {
            claims
                .iter()
                .any(|verified_claim| verified_claim.as_str() == Some(required_claim))
        })
        || transaction_report_verifies_claim(report, required_claim)
}

fn transaction_report_verifies_claim(report: &serde_json::Value, required_claim: &str) -> bool {
    STANDALONE_TRANSACTION_VERIFIED_CLAIMS.contains(&required_claim)
        && report
            .get("schema")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|schema| schema == "chio.transaction.verifier-report.v1")
        && report
            .get("verdict")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|verdict| verdict == "verified")
}

fn load_disclosure_lineage_bundle_from_graph(
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
) -> Result<chio_selective_disclosure::DisclosureLineageBundle, CliError> {
    let graph = parse_graph_artifact_paths(evidence_graph_bytes)?;
    let capsule: chio_selective_disclosure::DisclosureCapsule =
        load_required_graph_json_artifact(
            bundle_dir,
            &graph.nodes,
            "disclosure-capsule",
            chio_selective_disclosure::DISCLOSURE_CAPSULE_SCHEMA_V1,
            "disclosure lineage",
        )?;
    let lineage: chio_selective_disclosure::SignedLineageSubgraph =
        load_required_graph_json_artifact(
            bundle_dir,
            &graph.nodes,
            "signed-lineage-subgraph",
            chio_selective_disclosure::LINEAGE_SIGNED_SUBGRAPH_SCHEMA_V1,
            "disclosure lineage",
        )?;
    let leakage_ledger: chio_selective_disclosure::DisclosureLeakageLedger =
        load_required_graph_json_artifact(
            bundle_dir,
            &graph.nodes,
            "disclosure-leakage-ledger",
            chio_selective_disclosure::DISCLOSURE_LEAKAGE_LEDGER_SCHEMA_V1,
            "disclosure lineage",
        )?;
    let crypto_context_report: Option<chio_selective_disclosure::DisclosureCryptoContextReport> =
        load_optional_graph_json_artifact(
            bundle_dir,
            &graph.nodes,
            "disclosure-crypto-context-report",
            chio_selective_disclosure::DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1,
            "disclosure lineage",
        )?;

    Ok(chio_selective_disclosure::DisclosureLineageBundle {
        capsule,
        lineage,
        leakage_ledger,
        crypto_context_report,
    })
}

fn load_swarm_authority_bundle_from_graph(
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
) -> Result<chio_swarm_authority::SwarmAuthorityBundle, CliError> {
    let graph = parse_graph_artifact_paths(evidence_graph_bytes)?;
    let task_graph: chio_swarm_authority::SwarmTaskGraph =
        load_required_graph_json_artifact(
            bundle_dir,
            &graph.nodes,
            "swarm-task-graph",
            chio_swarm_authority::CHIO_SWARM_TASK_GRAPH_SCHEMA,
            "swarm",
        )?;
    let budget_pool: chio_swarm_authority::SwarmBudgetPool =
        load_required_graph_json_artifact(
            bundle_dir,
            &graph.nodes,
            "swarm-budget-pool",
            chio_swarm_authority::CHIO_SWARM_BUDGET_POOL_SCHEMA,
            "swarm",
        )?;
    let revocation_epoch: chio_swarm_authority::SwarmRevocationEpoch =
        load_required_graph_json_artifact(
            bundle_dir,
            &graph.nodes,
            "swarm-revocation-epoch",
            chio_swarm_authority::CHIO_SWARM_REVOCATION_EPOCH_SCHEMA,
            "swarm",
        )?;
    let continuation_tokens: Vec<chio_swarm_authority::SwarmContinuationToken> =
        load_required_graph_json_artifacts(
            bundle_dir,
            &graph.nodes,
            "swarm-continuation-token",
            chio_swarm_authority::CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA,
            "swarm",
        )?;
    let witness_chains: Vec<chio_swarm_authority::SwarmDelegationWitnessChain> =
        load_required_graph_json_artifacts(
            bundle_dir,
            &graph.nodes,
            "swarm-delegation-witness-chain",
            chio_swarm_authority::CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA,
            "swarm",
        )?;
    let join_receipts: Vec<chio_swarm_authority::SwarmJoinReceipt> =
        load_required_graph_json_artifacts(
            bundle_dir,
            &graph.nodes,
            "swarm-join-receipt",
            chio_swarm_authority::CHIO_SWARM_JOIN_RECEIPT_SCHEMA,
            "swarm",
        )?;
    let route_plan_receipts: Vec<chio_swarm_authority::SwarmRoutePlanReceipt> =
        load_required_graph_json_artifacts(
            bundle_dir,
            &graph.nodes,
            "swarm-route-plan-receipt",
            chio_swarm_authority::CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA,
            "swarm",
        )?;
    let now_unix_ms = swarm_authority_verification_time(
        &task_graph,
        &continuation_tokens,
        &revocation_epoch,
    );

    Ok(chio_swarm_authority::SwarmAuthorityBundle {
        now_unix_ms,
        task_graph,
        continuation_tokens,
        witness_chains,
        join_receipts,
        route_plan_receipts,
        budget_pool,
        revocation_epoch,
    })
}

fn swarm_authority_verification_time(
    task_graph: &chio_swarm_authority::SwarmTaskGraph,
    continuation_tokens: &[chio_swarm_authority::SwarmContinuationToken],
    revocation_epoch: &chio_swarm_authority::SwarmRevocationEpoch,
) -> u64 {
    continuation_tokens
        .iter()
        .map(|token| token.issued_at_unix_ms)
        .chain([
            task_graph.created_at_unix_ms,
            revocation_epoch.issued_at_unix_ms,
        ])
        .max()
        .unwrap_or(task_graph.created_at_unix_ms)
}

fn load_public_settlement_proof_bundle_from_graph(
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
) -> Result<chio_web3::settlement_proof::PublicSettlementProofBundle, CliError> {
    let graph = parse_graph_artifact_paths(evidence_graph_bytes)?;
    load_required_graph_json_artifact(
        bundle_dir,
        &graph.nodes,
        "public-settlement-proof-bundle",
        chio_web3::settlement_proof::CHIO_WEB3_SETTLEMENT_PROOF_BUNDLE_SCHEMA,
        "public settlement proof bundle",
    )
}

fn load_runtime_artifacts_from_graph(
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
) -> Result<BTreeMap<String, Vec<u8>>, CliError> {
    load_graph_artifacts_matching(bundle_dir, evidence_graph_bytes, |node| {
        is_runtime_artifact_node(&node.role, node.schema.as_deref())
    })
}

fn is_runtime_artifact_node(role: &str, schema: Option<&str>) -> bool {
    if role == "receipt" {
        return schema == Some("chio.runtime.terminal-receipt.v1");
    }
    is_runtime_artifact_role(role)
}

fn is_runtime_evidence_graph_node(node: &serde_json::Value) -> bool {
    let Some(role) = node.get("role").and_then(serde_json::Value::as_str) else {
        return false;
    };
    if node.get("path").and_then(serde_json::Value::as_str).is_none() {
        return false;
    }
    let Some(id) = node.get("id").and_then(serde_json::Value::as_str) else {
        return false;
    };
    let schema = node.get("schema").and_then(serde_json::Value::as_str);
    is_runtime_evidence_graph_node_parts(role, id, schema)
}

fn is_runtime_evidence_graph_node_parts(role: &str, _id: &str, schema: Option<&str>) -> bool {
    if role == "receipt" {
        return schema == Some("chio.runtime.terminal-receipt.v1");
    }
    matches!(role, "advisory-observation" | "verifier-policy") || is_runtime_artifact_role(role)
}

fn is_runtime_artifact_role(role: &str) -> bool {
    matches!(
        role,
        "execution-lease"
            | "tool-server-ack"
            | "revocation-freshness-proof"
            | "sandbox-attestation"
    )
}

fn load_enterprise_artifacts_from_graph(
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
) -> Result<BTreeMap<String, Vec<u8>>, CliError> {
    let graph = parse_graph_artifact_paths(evidence_graph_bytes)?;
    let mut artifacts = BTreeMap::new();
    let mut export_bundle_paths = Vec::new();
    for node in graph
        .nodes
        .iter()
        .filter(|node| is_enterprise_artifact_role(&node.role))
    {
        let bytes = read_graph_artifact(bundle_dir, node)?;
        if node.role == "evidence-export-bundle" {
            export_bundle_paths.push(node.path.clone());
        }
        artifacts.insert(node.path.clone(), bytes);
    }

    for export_bundle_path in export_bundle_paths {
        let Some(export_bundle_bytes) = artifacts.get(&export_bundle_path) else {
            continue;
        };
        let sidecar_paths = enterprise_export_sidecar_paths(export_bundle_bytes)?;
        for sidecar_path in sidecar_paths {
            if artifacts.contains_key(&sidecar_path) {
                continue;
            }
            let artifact_path = resolve_bundle_artifact_path(bundle_dir, &sidecar_path)?;
            artifacts.insert(sidecar_path, fs::read(artifact_path)?);
        }
    }
    Ok(artifacts)
}

fn enterprise_export_sidecar_paths(export_bundle_bytes: &[u8]) -> Result<Vec<String>, CliError> {
    #[derive(serde::Deserialize)]
    struct ExportBundlePaths {
        artifacts: Vec<ExportArtifactPath>,
    }

    #[derive(serde::Deserialize)]
    struct ExportArtifactPath {
        path: String,
    }

    let export_bundle: ExportBundlePaths = serde_json::from_slice(export_bundle_bytes)?;
    Ok(export_bundle
        .artifacts
        .into_iter()
        .map(|artifact| artifact.path)
        .collect())
}

fn is_enterprise_artifact_role(role: &str) -> bool {
    matches!(
        role,
        "risk-comptroller-report"
            | "data-governance-report"
            | "evidence-export-bundle"
            | "telemetry-projection"
            | "approval-case"
            | "control-evidence-map"
    )
}

fn is_enterprise_evidence_graph_node(node: &serde_json::Value) -> bool {
    let Some(role) = node.get("role").and_then(serde_json::Value::as_str) else {
        return false;
    };
    is_enterprise_evidence_graph_role(role)
}

fn is_enterprise_evidence_graph_role(role: &str) -> bool {
    matches!(
        role,
        "adjudication-jurisdiction-receipt" | "verifier-policy" | "report"
    ) || is_enterprise_artifact_role(role)
}

fn load_agent_web_artifacts_from_graph(
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
) -> Result<BTreeMap<String, Vec<u8>>, CliError> {
    load_graph_artifacts_matching(bundle_dir, evidence_graph_bytes, |node| {
        is_agent_web_evidence_graph_node_parts(
            &node.role,
            node.id.as_deref().unwrap_or_default(),
            node.schema.as_deref(),
        )
    })
}

fn is_agent_web_artifact_role(role: &str) -> bool {
    matches!(
        role,
        "agent-web-proof-envelope"
            | "external-projection-manifest"
            | "external-subject"
            | "verifier-policy"
            | "report"
    )
}

fn is_agent_web_evidence_graph_node(node: &serde_json::Value) -> bool {
    let Some(role) = node.get("role").and_then(serde_json::Value::as_str) else {
        return false;
    };
    if node.get("path").and_then(serde_json::Value::as_str).is_none() {
        return false;
    }
    let Some(id) = node.get("id").and_then(serde_json::Value::as_str) else {
        return false;
    };
    let schema = node.get("schema").and_then(serde_json::Value::as_str);
    is_agent_web_evidence_graph_node_parts(role, id, schema)
}

fn is_agent_web_evidence_graph_node_parts(role: &str, id: &str, schema: Option<&str>) -> bool {
    if role == "receipt" {
        return schema == Some("chio.receipt.v1") && is_agent_web_receipt_node(id);
    }
    is_agent_web_artifact_role(role)
}

fn is_agent_web_receipt_node(id: &str) -> bool {
    id.starts_with("receipt-agent-web-")
}

fn scoped_evidence_graph_bytes(
    evidence_graph_bytes: &[u8],
    include_node: fn(&serde_json::Value) -> bool,
) -> Result<Vec<u8>, CliError> {
    let mut graph: serde_json::Value = serde_json::from_slice(evidence_graph_bytes)?;
    let Some(nodes) = graph.get_mut("nodes").and_then(serde_json::Value::as_array_mut) else {
        return Err(CliError::cli_other_error(
            "proof verify: evidence graph nodes must be an array",
        ));
    };

    let mut retained_ids = BTreeSet::new();
    nodes.retain(|node| {
        if !include_node(node) {
            return false;
        }
        let Some(id) = node.get("id").and_then(serde_json::Value::as_str) else {
            return false;
        };
        retained_ids.insert(id.to_string());
        true
    });

    if let Some(edges) = graph.get_mut("edges").and_then(serde_json::Value::as_array_mut) {
        edges.retain(|edge| {
            let Some(from) = edge.get("from").and_then(serde_json::Value::as_str) else {
                return false;
            };
            let Some(to) = edge.get("to").and_then(serde_json::Value::as_str) else {
                return false;
            };
            retained_ids.contains(from) && retained_ids.contains(to)
        });
    }

    serde_json::to_vec(&graph).map_err(CliError::from)
}

fn passport_for_evidence_graph(
    passport: &chio_control_plane::transaction_passport::TransactionPassport,
    evidence_graph_bytes: &[u8],
) -> chio_control_plane::transaction_passport::TransactionPassport {
    let mut scoped_passport = passport.clone();
    scoped_passport.evidence_graph_sha256 = chio_core::sha256_hex(evidence_graph_bytes);
    scoped_passport
}

fn load_trust_market_artifacts_from_graph(
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
) -> Result<BTreeMap<String, Vec<u8>>, CliError> {
    load_graph_artifacts_matching(bundle_dir, evidence_graph_bytes, |node| {
        is_trust_market_artifact_role(&node.role)
    })
}

fn is_trust_market_artifact_role(role: &str) -> bool {
    matches!(
        role,
        "provider-discovery-snapshot"
            | "provider-selection-report"
            | "trust-scorecard-snapshot"
            | "reputation-import-report"
            | "sla-commitment"
            | "sla-performance-report"
            | "risk-comptroller-report"
            | "collateral-position-report"
            | "guarantee-decision"
            | "adjudication-jurisdiction-receipt"
    )
}

fn is_trust_market_evidence_graph_node(node: &serde_json::Value) -> bool {
    let Some(role) = node.get("role").and_then(serde_json::Value::as_str) else {
        return false;
    };
    is_trust_market_evidence_graph_role(role)
}

fn is_trust_market_evidence_graph_role(role: &str) -> bool {
    matches!(role, "receipt" | "verifier-policy" | "report") || is_trust_market_artifact_role(role)
}

fn map_proof_error(
    error: chio_control_plane::transaction_passport::TransactionPassportError,
) -> CliError {
    CliError::cli_other_error(format!("proof verify: {error}"))
}
