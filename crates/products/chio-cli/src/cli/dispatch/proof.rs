use super::*;
use chio_errors::_generated::error_codes::{
    TRANSACTION_ARTIFACT_HASH_MISMATCH, TRANSACTION_AUTHORIZATION_NOT_BOUND,
    TRANSACTION_DISPUTE_UNBOUND, TRANSACTION_GRAPH_CYCLE, TRANSACTION_GRAPH_NOT_CLOSED,
    TRANSACTION_IDENTITY_NOT_BOUND, TRANSACTION_PASSPORT_HASH_MISMATCH,
    TRANSACTION_PASSPORT_SCHEMA_UNSUPPORTED, TRANSACTION_REQUIRED_CLAIM_MISSING,
    TRANSACTION_RUNTIME_PROOF_REJECTED, TRANSACTION_SETTLEMENT_UNVERIFIED,
    TRANSACTION_TRANSPARENCY_PREVIEW_NOT_ALLOWED,
};
use std::collections::{BTreeMap, BTreeSet};

#[path = "proof/env.rs"]
mod proof_env;
use proof_env::{
    agent_web_replay_store_from_env_if_configured, agent_web_verifier_trust_from_env,
    cognition_market_proof_trust_from_env,
    commerce_trusted_event_authority_receipt_kernel_keys_from_env,
    commerce_trusted_payment_signer_keys_from_env, commerce_trusted_provider_keys_from_env,
    disclosure_lineage_verifier_trust_from_env, enterprise_trusted_approval_signer_keys_from_env,
    enterprise_trusted_receipt_kernel_keys_from_env,
    enterprise_trusted_risk_comptroller_signer_keys_from_env,
    public_settlement_verifier_trust_from_env, runtime_trust_from_env,
    swarm_trusted_witness_keys_for_bundle, transaction_trusted_checkpoint_keys_from_env,
    transaction_trusted_root_keys_from_env,
    trust_market_trusted_authority_keys_from_env, AgentWebReplayMode,
};

const REQUIRED_RUNTIME_AUTHORITY_CLAIMS: [&str; 6] = [
    "claim.runtime.execution_lease_valid",
    "claim.runtime.nonce_fresh",
    "claim.runtime.revocation_fresh_at_dispatch",
    "claim.runtime.sandbox_attestation_matched",
    "claim.runtime.tool_server_ack_bound",
    "claim.runtime.receipt_totality_complete",
];
const REQUIRED_DELEGATION_CLAIMS: [&str; 3] = [
    "claim.swarm.continuation_fresh",
    "claim.swarm.attenuation_witness_chain_bound",
    "claim.swarm.route_plan_bound",
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
const CLAIM_PREFIX_FINDING: &str = "claim.finding.";
const CLAIM_DISCLOSURE_CRYPTO_CONTEXT_BOUND: &str = "claim.disclosure.crypto_context_bound";
const STANDALONE_TRANSACTION_VERIFIED_CLAIMS: [&str; 6] = [
    "claim.transaction.passport_root_verified",
    "claim.transaction.evidence_graph_digest_bound",
    "claim.transaction.evidence_graph_structure_verified",
    "claim.transaction.claim_set_digest_bound",
    "claim.transaction.policy_digest_bound",
    "claim.transaction.omission_policy_bound",
];
const VERIFIER_CLAIM_PREFIXES: [&str; 12] = [
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
    CLAIM_PREFIX_FINDING,
];
const PROOF_VERIFY_EXIT_REQUIRED_CLAIM_FAILED: i32 = 10;
const PROOF_VERIFY_EXIT_INTEGRITY_FAILURE: i32 = 20;
const PROOF_VERIFY_EXIT_PARSE_OR_SCHEMA_FAILURE: i32 = 30;
const PROOF_VERIFY_EXIT_NEGATIVE_DID_NOT_FAIL: i32 = 40;
const PROOF_VERIFY_EXIT_UNSUPPORTED_FEATURE: i32 = 50;
const PROOF_VERIFY_EXIT_RELEASE_TRUTH_FAILURE: i32 = 60;

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
        stable_negative_failure_code(code)
    }
}

fn stable_negative_failure_code(code: &str) -> String {
    let normalized = strip_negative_failure_context(code);
    if is_dotted_negative_failure_code(normalized) {
        return normalized.to_string();
    }
    let slug = slug_negative_failure_code(normalized);
    if slug.is_empty() {
        "proof-room.negative.unknown".to_string()
    } else {
        format!("proof-room.negative.{slug}")
    }
}

fn strip_negative_failure_context(mut code: &str) -> &str {
    code = code.trim();
    for prefix in [
        "invalid disclosure lineage artifact: ",
        "proof-room.source-verifier.failed: ",
        "proof-room.passport.invalid: ",
        "invalid agent web interop artifact: ",
        "invalid Agent Web interop artifact: ",
        "invalid public settlement artifact: ",
        "invalid enterprise export artifact: ",
        "invalid trust market artifact: ",
        "invalid runtime security artifact: ",
        "runtime security claim failed: ",
        "invalid evidence graph artifact: ",
        "minimal governed action evidence invalid: ",
        "commerce payment failed: ",
        "commerce mandate failed: ",
        "commerce event log failed: ",
        "commerce replay failed: ",
        "commerce recovery failed: ",
        "commerce fraud failed: ",
        "swarm authority invalid: ",
        "public settlement proof invalid: ",
        "invalid settlement: ",
        "invalid proof: ",
        "agent web interop invalid: ",
        "agent web claim failed: ",
        "Agent Web claim failed: ",
        "enterprise export invalid: ",
        "enterprise export claim failed: ",
        "risk comptroller claim failed: ",
        "trust market context invalid: ",
        "trust market claim failed: ",
        "trust-market claim failed: ",
        "Trust market claim failed: ",
        "Trust Market claim failed: ",
    ] {
        if let Some(stripped) = code.strip_prefix(prefix) {
            code = stripped.trim();
        }
    }
    if !is_dotted_negative_failure_code(code) {
        if let Some((base, _detail)) = code.split_once(": ") {
            code = base.trim();
        }
    }
    code
}

fn is_dotted_negative_failure_code(code: &str) -> bool {
    let base = code.split(':').next().unwrap_or(code);
    !base.is_empty()
        && base.contains('.')
        && !base.chars().any(char::is_whitespace)
        && base.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '.' | '-' | '_')
        })
}

fn slug_negative_failure_code(code: &str) -> String {
    let mut slug = String::new();
    let mut last_was_separator = false;
    for character in code.chars().flat_map(char::to_lowercase) {
        if character.is_ascii_alphanumeric() {
            slug.push(character);
            last_was_separator = false;
        } else if !last_was_separator {
            slug.push('-');
            last_was_separator = true;
        }
    }
    slug.trim_matches('-').to_string()
}

#[path = "proof/archive.rs"]
mod archive;
#[path = "proof/assemble.rs"]
mod assemble;
#[path = "proof/collect.rs"]
mod collect;
#[path = "proof/doctor.rs"]
mod doctor;
#[path = "proof/explain.rs"]
mod explain;
#[path = "proof/export.rs"]
mod export;
#[path = "proof/fixture.rs"]
mod fixture;
#[path = "proof/risk.rs"]
mod risk;
#[path = "proof/serve.rs"]
mod serve;

pub(crate) fn dispatch_proof(command: ProofCommands, json_output: bool) -> Result<(), CliError> {
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
            json_output,
        ),
        ProofCommands::Collect {
            kind,
            artifact_dir,
            out,
        } => collect::collect_proof_bundle(kind, &artifact_dir, &out, json_output),
        ProofCommands::Verify { path, out, require } => {
            match verify_transaction_passport(&path, out.as_deref(), &require) {
                Ok(()) => Ok(()),
                Err(error) => exit_proof_verify_error(error, json_output),
            }
        }
        ProofCommands::Explain { bundle, claim } => {
            explain::explain_proof_claim(&bundle, &claim, json_output)
        }
        ProofCommands::Fixture { command } => fixture::dispatch_proof_fixture(command, json_output),
        ProofCommands::Serve {
            bundle,
            listen,
            dry_run,
        } => serve::serve_proof_bundle(&bundle, &listen, dry_run, json_output),
        ProofCommands::Export {
            bundle,
            out,
            redact,
        } => export::export_proof_bundle(&bundle, &out, redact, json_output),
        ProofCommands::Doctor { scenario, root } => {
            let scenario = scenario.unwrap_or(ProofDoctorScenario::SingleCallAuthority);
            doctor::run_proof_doctor(scenario, root.as_deref(), json_output)
        }
    }
}

pub(crate) fn dispatch_commerce(
    command: CommerceCommands,
    json_output: bool,
) -> Result<(), CliError> {
    match command {
        CommerceCommands::Verify { path, out } => {
            match verify_transaction_passport_with_label(
                &path,
                out.as_deref(),
                &[ProofVerifyRequirement::Commerce],
                Some(("claim.commerce.", "chio commerce verify")),
            ) {
                Ok(()) => Ok(()),
                Err(error) => exit_proof_verify_error(error, json_output),
            }
        }
    }
}

fn exit_proof_verify_error(error: CliError, json_output: bool) -> ! {
    let exit_code = proof_verify_exit_code(&error);
    let mut stderr = std::io::stderr();
    let _ = write_cli_error(&mut stderr, &error, json_output);
    std::process::exit(exit_code);
}

fn proof_verify_exit_code(error: &CliError) -> i32 {
    let report = error.report();
    let code = report.code.as_str();
    let message = report.message.as_str();
    if code == TRANSACTION_REQUIRED_CLAIM_MISSING.urn
        || code == TRANSACTION_REQUIRED_CLAIM_MISSING.string_code
        || proof_verify_required_claim_failed(message)
    {
        return PROOF_VERIFY_EXIT_REQUIRED_CLAIM_FAILED;
    }
    if proof_verify_integrity_failed(code, message) {
        return PROOF_VERIFY_EXIT_INTEGRITY_FAILURE;
    }
    if proof_verify_parse_or_schema_failed(code, message) {
        return PROOF_VERIFY_EXIT_PARSE_OR_SCHEMA_FAILURE;
    }
    if proof_verify_negative_did_not_fail(message) {
        return PROOF_VERIFY_EXIT_NEGATIVE_DID_NOT_FAIL;
    }
    if proof_verify_release_truth_failed(message) {
        return PROOF_VERIFY_EXIT_RELEASE_TRUTH_FAILURE;
    }
    if proof_verify_unsupported_feature(message) {
        return PROOF_VERIFY_EXIT_UNSUPPORTED_FEATURE;
    }
    1
}

fn proof_verify_required_claim_failed(message: &str) -> bool {
    message.contains("required proof claim not verified")
        || message.contains("required proof claim family missing")
        || message.contains("required proof runtime authority missing")
        || message.contains("required delegation claim not verified")
        || message.contains("required commerce claim not verified")
        || message.contains("required disclosure lineage claim not verified")
        || message.contains("required swarm claim not verified")
        || message.contains("required public settlement claim not verified")
}

fn proof_verify_integrity_failed(code: &str, message: &str) -> bool {
    code == TRANSACTION_ARTIFACT_HASH_MISMATCH.urn
        || code == TRANSACTION_ARTIFACT_HASH_MISMATCH.string_code
        || code == TRANSACTION_GRAPH_NOT_CLOSED.urn
        || code == TRANSACTION_GRAPH_NOT_CLOSED.string_code
        || code == TRANSACTION_PASSPORT_HASH_MISMATCH.urn
        || code == TRANSACTION_PASSPORT_HASH_MISMATCH.string_code
        || message.contains("digest mismatch")
        || message.contains("hash mismatch")
        || message.contains("proof-room.signature.")
        || message.contains("signature invalid")
        || message.contains("signature verification failed")
        || message.contains("manifest integrity")
}

fn proof_verify_parse_or_schema_failed(code: &str, message: &str) -> bool {
    code == TRANSACTION_PASSPORT_SCHEMA_UNSUPPORTED.urn
        || code == TRANSACTION_PASSPORT_SCHEMA_UNSUPPORTED.string_code
        || code == "CHIO-CLI-JSON"
        || message.contains("unsupported transaction passport schema")
        || message.contains("unsupported verifier policy schema")
        || message.contains("unsupported evidence graph schema")
        || message.contains("unsupported required proof claim")
        || message.contains("proof-room.schema-violation")
        || message.contains("json error")
        || message.contains("missing field")
}

fn proof_verify_negative_did_not_fail(message: &str) -> bool {
    message.contains("proof-room.negative-case.unexpected-success")
        || message.contains("proof-room.negative-case.failure-mismatch")
        || (message.contains("negative fixture") && message.contains("verified unexpectedly"))
}

fn proof_verify_release_truth_failed(message: &str) -> bool {
    message.contains("release truth")
        || message.contains("package truth")
        || message.contains("release-truth")
        || message.contains("package-truth")
        || message.contains("chio.proof.release-truth.v1")
}

fn proof_verify_unsupported_feature(message: &str) -> bool {
    message.contains("unsupported proof feature")
        || message.contains("must pin trusted")
        || message.contains("missing disclosure crypto verification context")
        || message.contains("missing disclosure selective disclosure proof")
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
    verify_transaction_passport_with_label(path, out, requirements, None)
}

fn verify_transaction_passport_with_label(
    path: &Path,
    out: Option<&Path>,
    requirements: &[ProofVerifyRequirement],
    report_label: Option<(&str, &str)>,
) -> Result<(), CliError> {
    let archive_root = archive::extract_proof_archive(path)?;
    let input_path = match archive_root.as_ref() {
        Some(archive_root) => archive_root.path(),
        None => path,
    };
    verify_proof_room_bundle_if_present(input_path)?;
    let passport_path = resolve_proof_passport_path(input_path)?;
    let mut report = match verify_transaction_passport_file(&passport_path) {
        Ok(report) => report,
        Err(error) => {
            if let Some(out) = out {
                write_failed_transaction_report_output(&passport_path, out, &error)?;
            }
            return Err(error);
        }
    };
    enforce_proof_verify_requirements(input_path, &report, requirements)?;
    if let Some((claim_prefix, verifier_label)) = report_label {
        relabel_report_claim_verifier(&mut report, claim_prefix, verifier_label);
    }

    if let Some(out) = out {
        write_proof_verify_report_output(out, &report)?;
    }

    let mut stdout = std::io::stdout();
    serde_json::to_writer(&mut stdout, &report)?;
    stdout.write_all(b"\n")?;
    Ok(())
}

fn relabel_report_claim_verifier(
    report: &mut serde_json::Value,
    claim_prefix: &str,
    verifier_label: &str,
) {
    if let Some(claim_results) = report
        .get_mut("claimResults")
        .and_then(serde_json::Value::as_array_mut)
    {
        for claim_result in claim_results {
            if claim_result
                .get("claim_id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|claim_id| claim_id.starts_with(claim_prefix))
            {
                claim_result["verifier_module"] =
                    serde_json::Value::String(verifier_label.to_string());
            }
        }
    }

    if let Some(checker_provenance) = report
        .get_mut("checker_provenance")
        .and_then(serde_json::Value::as_array_mut)
    {
        for checker in checker_provenance {
            if checker
                .get("claim_id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|claim_id| claim_id.starts_with(claim_prefix))
            {
                checker["checker"] = serde_json::Value::String(verifier_label.to_string());
            }
        }
    }
}

fn write_failed_transaction_report_output(
    passport_path: &Path,
    out: &Path,
    error: &CliError,
) -> Result<(), CliError> {
    let Some(report) = failed_transaction_report(passport_path, error)? else {
        return Ok(());
    };
    write_proof_verify_report_output(out, &report)
}

fn failed_transaction_report(
    passport_path: &Path,
    error: &CliError,
) -> Result<Option<serde_json::Value>, CliError> {
    let passport_bytes = match fs::read(passport_path) {
        Ok(passport_bytes) => passport_bytes,
        Err(_) => return Ok(None),
    };
    let passport = match serde_json::from_slice::<
        chio_control_plane::transaction_passport::TransactionPassport,
    >(&passport_bytes)
    {
        Ok(passport) => passport,
        Err(_) => return Ok(None),
    };
    let passport_report_path = path_file_name_or_display(passport_path);
    let report = chio_control_plane::transaction_passport::TransactionVerifierReport::failed(
        &passport,
        passport_report_path,
        proof_error_failure_code(error),
        error.to_string(),
    );
    serde_json::to_value(report)
        .map(Some)
        .map_err(CliError::from)
}

fn path_file_name_or_display(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned())
}

fn proof_error_failure_code(error: &CliError) -> String {
    error.report().code
}

fn write_proof_verify_report_output(
    out: &Path,
    report: &serde_json::Value,
) -> Result<(), CliError> {
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
    write_json_line_file(out, report)
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
                ensure_delegation_claims_verified(report)?;
            }
            ProofVerifyRequirement::Denials => ensure_manifest_claim_verified(
                input_path,
                requirement.as_str(),
                "claim.proof_room.allow_and_deny_visible",
            )?,
            ProofVerifyRequirement::Disclosure => {
                ensure_verified_claim_family(
                    report,
                    requirement.as_str(),
                    CLAIM_PREFIX_DISCLOSURE,
                )?;
            }
            ProofVerifyRequirement::Enterprise => {
                ensure_verified_claim_family(
                    report,
                    requirement.as_str(),
                    CLAIM_PREFIX_ENTERPRISE,
                )?;
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
                ensure_verified_claim_family(
                    report,
                    requirement.as_str(),
                    CLAIM_PREFIX_TRUST_MARKET,
                )?;
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

fn ensure_delegation_claims_verified(report: &serde_json::Value) -> Result<(), CliError> {
    let verified_claims = verified_claims_array(report).ok_or_else(|| {
        CliError::cli_other_error("required proof claim family missing: delegation".to_string())
    })?;
    for required_claim in REQUIRED_DELEGATION_CLAIMS {
        if !verified_claims
            .iter()
            .any(|claim| claim.as_str() == Some(required_claim))
        {
            return Err(CliError::cli_other_error(format!(
                "required delegation claim not verified: {required_claim}"
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

pub(super) fn verify_transaction_passport_file(path: &Path) -> Result<serde_json::Value, CliError> {
    verify_transaction_passport_file_with_mode(path, TransactionPassportVerificationMode::ReadOnly)
}

#[cfg(test)]
pub(super) fn verify_transaction_passport_file_and_consume_agent_web_replays(
    path: &Path,
    expected_read_only_report: &serde_json::Value,
) -> Result<serde_json::Value, CliError> {
    verify_transaction_passport_file_with_mode(
        path,
        TransactionPassportVerificationMode::ConsumeAgentWebReplays {
            expected_read_only_report,
            replay_reservation_id: None,
        },
    )
}

pub(super) fn verify_transaction_passport_file_and_reserve_agent_web_replays(
    path: &Path,
    expected_read_only_report: &serde_json::Value,
    replay_reservation_id: &str,
) -> Result<serde_json::Value, CliError> {
    verify_transaction_passport_file_with_mode(
        path,
        TransactionPassportVerificationMode::ConsumeAgentWebReplays {
            expected_read_only_report,
            replay_reservation_id: Some(replay_reservation_id),
        },
    )
}

#[derive(Clone, Copy)]
enum TransactionPassportVerificationMode<'a> {
    ReadOnly,
    ConsumeAgentWebReplays {
        expected_read_only_report: &'a serde_json::Value,
        replay_reservation_id: Option<&'a str>,
    },
}

impl TransactionPassportVerificationMode<'_> {
    fn agent_web_replay_mode(self) -> AgentWebReplayMode {
        match self {
            Self::ReadOnly => AgentWebReplayMode::ReadOnly,
            Self::ConsumeAgentWebReplays { .. } => AgentWebReplayMode::Consume,
        }
    }
}

struct DeferredAgentWebReplayReservation {
    bundle: chio_control_plane::agent_web::AgentWebInteropBundle,
    trust: chio_control_plane::agent_web::AgentWebVerifierTrust,
    read_only_report: chio_control_plane::agent_web::AgentWebInteropReport,
}

#[cfg(test)]
static FAIL_BEFORE_ROOT_CLAIM_SET_VERIFICATION_ONCE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
fn fail_before_root_claim_set_verification_once() {
    FAIL_BEFORE_ROOT_CLAIM_SET_VERIFICATION_ONCE
        .store(true, std::sync::atomic::Ordering::SeqCst);
}

fn enforce_pre_root_claim_set_test_hook() -> Result<(), CliError> {
    #[cfg(test)]
    if FAIL_BEFORE_ROOT_CLAIM_SET_VERIFICATION_ONCE
        .swap(false, std::sync::atomic::Ordering::SeqCst)
    {
        return Err(CliError::cli_other_error(
            "injected failure before root claim set verification",
        ));
    }
    Ok(())
}

fn verify_transaction_passport_file_with_mode(
    path: &Path,
    verification_mode: TransactionPassportVerificationMode<'_>,
) -> Result<serde_json::Value, CliError> {
    let passport_bytes = fs::read(path)?;
    let passport: chio_control_plane::transaction_passport::TransactionPassport =
        serde_json::from_slice(&passport_bytes)?;

    chio_control_plane::transaction_passport::verify_minimal_passport_schema(&passport)
        .map_err(map_proof_error)?;
    let trusted_transaction_root_keys = transaction_trusted_root_keys_from_env()?;
    let trusted_transaction_checkpoint_keys = transaction_trusted_checkpoint_keys_from_env()?;
    chio_control_plane::transaction_passport::verify_transaction_passport_signature(
        &passport,
        &trusted_transaction_root_keys,
    )
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
    let transparency_artifacts =
        load_standalone_evidence_graph_artifacts(bundle_dir, &evidence_graph_bytes)?;
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
    if let Err(error) =
        chio_control_plane::transaction_passport::validate_transaction_evidence_graph(
            &evidence_graph_bytes,
        )
    {
        if claim_requirements.requires(CLAIM_PREFIX_RUNTIME)
            && is_advisory_authority_edge_proof_error(&error)
        {
            match verify_runtime_security_family_report(
                &passport,
                bundle_dir,
                &evidence_graph_bytes,
                &verifier_policy_bytes,
            ) {
                Ok(_) => return Err(map_proof_error(error)),
                Err(runtime_error) => return Err(runtime_error),
            }
        }
        return Err(map_proof_error(error));
    }
    let risk_route = risk::risk_route(
        &evidence_graph_bytes,
        claim_requirements.requires(CLAIM_PREFIX_RISK),
    )?;
    let settlement_requires_trust_market_context = if claim_requirements.requires_claim(
        chio_web3::settlement_proof::CLAIM_PUBLIC_SETTLEMENT_TRUST_MARKET_REFS_BOUND,
    ) {
        load_public_settlement_proof_bundle_from_graph(bundle_dir, &evidence_graph_bytes)?
            .has_trust_market_refs()
    } else {
        false
    };
    let disclosure_evidence_present =
        evidence_graph_contains_disclosure_artifacts(&evidence_graph_bytes)?;
    let mut family_reports = Vec::new();
    let mut deferred_agent_web_replay_reservation = None;
    let mut expected_public_settlement_trust_market_context = None;
    let mut expected_commerce_trust_market_context = None;
    let finding_claim_set_path = resolve_bundle_artifact_path(bundle_dir, &passport.claim_set_path)?;
    let finding_claim_set = fs::read(finding_claim_set_path)?;
    let finding_claims_advertised =
        claim_set_bytes_advertise_verified_prefix(&finding_claim_set, CLAIM_PREFIX_FINDING)?;
    if claim_requirements.requires(CLAIM_PREFIX_FINDING) || finding_claims_advertised {
        let trust = cognition_market_proof_trust_from_env(&trusted_transaction_root_keys)?;
        let report = chio_control_plane::transaction_passport::
            verify_cognition_market_passport_artifacts(
                &passport,
                passport_report_path.clone(),
                &evidence_graph_bytes,
                &verifier_policy_bytes,
                &transparency_artifacts,
                &trust,
            )
            .map_err(map_proof_error)?;
        push_family_report(&mut family_reports, report)?;
    }
    if claim_requirements.requires(CLAIM_PREFIX_TRUST_MARKET)
        || risk_route.through_trust_market
        || settlement_requires_trust_market_context
    {
        let trust_market_evidence_graph_bytes = scoped_evidence_graph_bytes(
            &evidence_graph_bytes,
            is_trust_market_evidence_graph_node,
        )?;
        let artifacts =
            load_trust_market_artifacts_from_graph(bundle_dir, &trust_market_evidence_graph_bytes)?;
        let trust_market_passport =
            passport_for_evidence_graph(&passport, &trust_market_evidence_graph_bytes);
        let trusted_market_authority_keys = trust_market_trusted_authority_keys_from_env()?;
        let report = chio_control_plane::trust_market::verify_trust_market_context(
            &chio_control_plane::trust_market::TrustMarketBundle {
                passport: trust_market_passport,
                evidence_graph_bytes: trust_market_evidence_graph_bytes,
                root_evidence_graph_bytes: Some(evidence_graph_bytes.clone()),
                verifier_policy_bytes: verifier_policy_bytes.clone(),
                artifacts,
                trusted_passport_signer_keys: trusted_transaction_root_keys.clone(),
                trusted_market_authority_keys,
            },
        )
        .map_err(map_proof_error)?;
        expected_public_settlement_trust_market_context =
            Some(public_settlement_trust_market_context_from_trust_market_report(&report));
        expected_commerce_trust_market_context = Some(
            commerce_trust_market_context_from_trust_market_report(&report),
        );
        push_family_report(&mut family_reports, report)?;
    }
    for spec in LOCAL_PROOF_FAMILY_SPECS {
        let evidence_presence_required =
            matches!(spec.route, LocalProofFamilyRoute::DisclosureLineage)
                && disclosure_evidence_present;
        if claim_requirements.requires(spec.prefix) || evidence_presence_required {
            push_local_proof_family_report(
                &mut family_reports,
                &claim_requirements,
                &passport,
                bundle_dir,
                &evidence_graph_bytes,
                spec,
                expected_public_settlement_trust_market_context.as_ref(),
                expected_commerce_trust_market_context.as_ref(),
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
    if claim_requirements.requires(CLAIM_PREFIX_AGENT_WEB) {
        let replay_reservation_id = match verification_mode {
            TransactionPassportVerificationMode::ConsumeAgentWebReplays {
                replay_reservation_id,
                ..
            } => replay_reservation_id,
            TransactionPassportVerificationMode::ReadOnly => None,
        };
        let agent_web_trust = agent_web_verifier_trust_from_env(
            verification_mode.agent_web_replay_mode(),
            replay_reservation_id,
        )?
        .with_trusted_passport_signer_keys(trusted_transaction_root_keys.clone());
        let artifacts = load_agent_web_artifacts_from_graph(bundle_dir, &evidence_graph_bytes)?;
        let agent_web_evidence_graph_bytes =
            scoped_evidence_graph_bytes(&evidence_graph_bytes, is_agent_web_evidence_graph_node)?;
        let agent_web_passport =
            passport_for_evidence_graph(&passport, &agent_web_evidence_graph_bytes);
        let agent_web_bundle = chio_control_plane::agent_web::AgentWebInteropBundle {
            passport: agent_web_passport,
            evidence_graph_bytes: agent_web_evidence_graph_bytes,
            root_evidence_graph_bytes: Some(evidence_graph_bytes.clone()),
            verifier_policy_bytes: verifier_policy_bytes.clone(),
            artifacts,
        };
        let report = chio_control_plane::agent_web::verify_agent_web_interop_with_trust(
            &agent_web_bundle,
            &agent_web_trust,
        )
        .map_err(map_proof_error)?;
        push_family_report(&mut family_reports, &report)?;
        if matches!(
            verification_mode,
            TransactionPassportVerificationMode::ConsumeAgentWebReplays { .. }
        ) {
            deferred_agent_web_replay_reservation = Some(DeferredAgentWebReplayReservation {
                bundle: agent_web_bundle,
                trust: agent_web_trust,
                read_only_report: report,
            });
        }
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
                root_evidence_graph_bytes: Some(evidence_graph_bytes.clone()),
                verifier_policy_bytes: verifier_policy_bytes.clone(),
                artifacts,
                trusted_passport_signer_keys: trusted_transaction_root_keys.clone(),
                trusted_receipt_kernel_keys: enterprise_trusted_receipt_kernel_keys_from_env()?,
                trusted_approval_signer_keys: enterprise_trusted_approval_signer_keys_from_env()?,
                trusted_risk_comptroller_signer_keys:
                    enterprise_trusted_risk_comptroller_signer_keys_from_env()?,
            },
        )
        .map_err(map_proof_error)?;
        push_family_report(&mut family_reports, report)?;
    }
    if claim_requirements.requires(CLAIM_PREFIX_RUNTIME) {
        let report = verify_runtime_security_family_report(
            &passport,
            bundle_dir,
            &evidence_graph_bytes,
            &verifier_policy_bytes,
        )?;
        push_family_report(&mut family_reports, report)?;
    }
    if !family_reports.is_empty() {
        enforce_pre_root_claim_set_test_hook()?;
        let trust_anchors =
            chio_control_plane::transaction_passport::TransactionTrustAnchors {
                passport_root_signers: &trusted_transaction_root_keys,
                checkpoint_signers: &trusted_transaction_checkpoint_keys,
            };
        let externally_verified_claims = verified_claims_from_family_reports(&family_reports);
        chio_control_plane::transaction_passport::verify_passport_root_and_claim_set_artifacts_with_transparency_anchors(
            &passport,
            passport_report_path.clone(),
            &evidence_graph_bytes,
            &verifier_policy_bytes,
            &transparency_artifacts,
            trust_anchors,
            &externally_verified_claims,
        )
        .map_err(map_proof_error)?;
    }
    ensure_integrated_commerce_settlement_order_binding(&family_reports)?;
    let transparency_state = chio_control_plane::transaction_passport::
        transaction_evidence_graph_transparency_state_with_anchors(
            &evidence_graph_bytes,
            &transparency_artifacts,
            chio_control_plane::transaction_passport::TransactionTrustAnchors {
                passport_root_signers: &trusted_transaction_root_keys,
                checkpoint_signers: &trusted_transaction_checkpoint_keys,
            },
        )
        .map_err(map_proof_error)?;
    let mut report = if family_reports.is_empty() {
        let report = chio_control_plane::transaction_passport::
            verify_standalone_minimal_passport_artifacts_with_transparency_anchors(
                &passport,
                passport_report_path,
                &evidence_graph_bytes,
                &verifier_policy_bytes,
                &transparency_artifacts,
                chio_control_plane::transaction_passport::TransactionTrustAnchors {
                    passport_root_signers: &trusted_transaction_root_keys,
                    checkpoint_signers: &trusted_transaction_checkpoint_keys,
                },
            )
            .map_err(map_proof_error)?;
        serde_json::to_value(report).map_err(CliError::from)
    } else {
        Ok(merge_family_verifier_reports(
            &passport,
            passport_report_path,
            family_reports,
            &transparency_state,
        ))
    }?;
    attach_runtime_proof_parity_report(bundle_dir, &evidence_graph_bytes, &mut report)?;
    ensure_policy_required_claims_verified(&claim_requirements, &report)?;

    if let TransactionPassportVerificationMode::ConsumeAgentWebReplays {
        expected_read_only_report,
        ..
    } = verification_mode
    {
        if &report != expected_read_only_report {
            return Err(CliError::cli_other_error(
                "proof collect: consuming verification snapshot does not match the read-only verifier report",
            ));
        }
        if let Some(reservation) = deferred_agent_web_replay_reservation {
            chio_control_plane::agent_web::verify_agent_web_interop_with_trust_and_consume_replays_if_report_matches(
                &reservation.bundle,
                &reservation.trust,
                &reservation.read_only_report,
            )
            .map_err(map_proof_error)?;
        }
    }
    Ok(report)
}

fn evidence_graph_contains_disclosure_artifacts(
    evidence_graph_bytes: &[u8],
) -> Result<bool, CliError> {
    let graph = parse_graph_artifact_paths(evidence_graph_bytes)?;
    Ok(graph
        .nodes
        .iter()
        .any(|node| is_disclosure_artifact_role(&node.role)))
}

fn is_disclosure_artifact_role(role: &str) -> bool {
    matches!(
        role,
        "disclosure-capsule"
            | "signed-lineage-subgraph"
            | "disclosure-leakage-ledger"
            | "disclosure-verifier-privacy-profile"
            | "disclosure-crypto-context-report"
            | "crypto-verification-context"
            | "selective-disclosure-proof"
            | "bbs-projection-manifest"
            | "transparency-inclusion-proof"
    )
}

fn push_local_proof_family_report(
    family_reports: &mut Vec<serde_json::Value>,
    claim_requirements: &VerifierPolicyClaimRequirements,
    passport: &chio_control_plane::transaction_passport::TransactionPassport,
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
    spec: &LocalProofFamilySpec,
    expected_public_settlement_trust_market_context: Option<
        &chio_web3::settlement_proof::PublicSettlementTrustMarketContext,
    >,
    expected_commerce_trust_market_context: Option<
        &chio_commerce_order::CommerceVerifiedTrustMarketContext,
    >,
) -> Result<(), CliError> {
    match spec.route {
        LocalProofFamilyRoute::Commerce => {
            let bundle = load_commerce_order_bundle_from_graph(
                bundle_dir,
                evidence_graph_bytes,
                &commerce_trusted_event_authority_receipt_kernel_keys_from_env()?,
                &commerce_trusted_payment_signer_keys_from_env()?,
                &commerce_trusted_provider_keys_from_env()?,
                expected_commerce_trust_market_context,
            )?;
            let report = chio_commerce_order::verify_commerce_order(&bundle)
                .map_err(map_commerce_proof_error)?;
            ensure_graph_bound_commerce_order_passport(bundle_dir, evidence_graph_bytes, &report)?;
            push_checked_local_family_report(family_reports, claim_requirements, spec, report)
        }
        LocalProofFamilyRoute::DisclosureLineage => {
            let bundle = load_disclosure_lineage_bundle_from_graph(
                bundle_dir,
                evidence_graph_bytes,
                claim_requirements.requires_claim(CLAIM_DISCLOSURE_CRYPTO_CONTEXT_BOUND),
            )?;
            let trust = disclosure_lineage_verifier_trust_from_env()?;
            let report = chio_selective_disclosure::verify_disclosure_lineage_bundle_with_trust(
                &bundle, &trust,
            )
            .map_err(|error| CliError::cli_other_error(format!("proof verify: {error}")))?;
            push_checked_local_family_report(family_reports, claim_requirements, spec, report)
        }
        LocalProofFamilyRoute::Swarm => {
            let bundle = load_swarm_authority_bundle_from_graph(bundle_dir, evidence_graph_bytes)?;
            let trusted_witness_keys = swarm_trusted_witness_keys_for_bundle(&bundle)?;
            let report =
                chio_swarm_authority::verify_swarm_authority_bundle(&bundle, &trusted_witness_keys)
                    .map_err(|error| CliError::cli_other_error(format!("proof verify: {error}")))?;
            push_checked_local_family_report(family_reports, claim_requirements, spec, report)
        }
        LocalProofFamilyRoute::PublicSettlement => {
            let proof_bundle =
                load_public_settlement_proof_bundle_from_graph(bundle_dir, evidence_graph_bytes)?;
            let mut trust = public_settlement_verifier_trust_from_env(&proof_bundle)?;
            trust.expected_trust_market_context =
                expected_public_settlement_trust_market_context.cloned();
            if proof_bundle.transaction_passport_id != passport.id {
                return Err(CliError::cli_other_error(format!(
                    "proof verify: public settlement proof bundle passport mismatch: expected {}, got {}",
                    passport.id, proof_bundle.transaction_passport_id
                )));
            }
            let report =
                chio_web3::settlement_proof::verify_public_settlement_proof(&proof_bundle, &trust)
                    .map_err(map_public_settlement_proof_error)?;
            push_checked_local_family_report(family_reports, claim_requirements, spec, report)
        }
    }
}

fn ensure_graph_bound_commerce_order_passport(
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
    report: &chio_commerce_order::CommerceOrderPassportReport,
) -> Result<(), CliError> {
    let graph = parse_graph_artifact_paths(evidence_graph_bytes)?;
    let order_passport_bytes = load_required_graph_bytes_artifact(
        bundle_dir,
        &graph.nodes,
        "commerce-order-passport",
        chio_commerce_order::COMMERCE_ORDER_PASSPORT_SCHEMA_ID,
        "commerce order passport",
    )?;
    let graph_bound_passport: chio_commerce_order::CommerceOrderPassportReport =
        serde_json::from_slice(&order_passport_bytes).map_err(CliError::from)?;
    if &graph_bound_passport != report {
        return Err(CliError::cli_other_error(
            "proof verify: commerce order passport artifact mismatch".to_string(),
        ));
    }
    Ok(())
}

fn public_settlement_trust_market_context_from_trust_market_report(
    report: &chio_control_plane::trust_market::TrustMarketVerifierReport,
) -> chio_web3::settlement_proof::PublicSettlementTrustMarketContext {
    chio_web3::settlement_proof::PublicSettlementTrustMarketContext {
        collateral_position_ref: report.trust_market_sections.collateral_position_ref.clone(),
        guarantee_decision_ref: report.trust_market_sections.guarantee_decision_ref.clone(),
        sla_remedy_ref: report.trust_market_sections.sla_remedy_ref.clone(),
        slash_authority_ref: report.trust_market_sections.slash_authority_ref.clone(),
    }
}

fn commerce_trust_market_context_from_trust_market_report(
    report: &chio_control_plane::trust_market::TrustMarketVerifierReport,
) -> chio_commerce_order::CommerceVerifiedTrustMarketContext {
    chio_commerce_order::CommerceVerifiedTrustMarketContext {
        provider_discovery_snapshot_ref: report
            .trust_market_sections
            .provider_discovery_snapshot_ref
            .clone(),
        provider_selection_report_ref: report
            .trust_market_sections
            .provider_selection_report_ref
            .clone(),
        trust_scorecard_ref: report.trust_market_sections.trust_scorecard_ref.clone(),
        reputation_import_ref: report.trust_market_sections.reputation_import_ref.clone(),
        sla_commitment_ref: report.trust_market_sections.sla_commitment_ref.clone(),
        risk_comptroller_report_ref: report
            .trust_market_sections
            .risk_comptroller_report_ref
            .clone(),
        collateral_position_ref: report.trust_market_sections.collateral_position_ref.clone(),
        guarantee_decision_ref: report.trust_market_sections.guarantee_decision_ref.clone(),
        adjudication_jurisdiction_ref: report
            .trust_market_sections
            .adjudication_jurisdiction_ref
            .clone(),
        selected_provider_subject: report
            .trust_market_sections
            .selected_provider_subject
            .clone(),
    }
}

fn ensure_integrated_commerce_settlement_order_binding(
    family_reports: &[serde_json::Value],
) -> Result<(), CliError> {
    let commerce_order_ids = family_report_field_values(
        family_reports,
        chio_commerce_order::COMMERCE_ORDER_PASSPORT_SCHEMA_ID,
        "order_id",
    );
    let settlement_order_ids = family_report_field_values(
        family_reports,
        chio_web3::settlement_proof::CHIO_PUBLIC_SETTLEMENT_VERIFIER_REPORT_SCHEMA,
        "commerce_order_id",
    );
    for commerce_order_id in &commerce_order_ids {
        for settlement_order_id in &settlement_order_ids {
            if commerce_order_id != settlement_order_id {
                return Err(CliError::cli_other_error(format!(
                    "proof verify: public settlement commerce order mismatch: commerce report order_id {}, settlement report commerce_order_id {}",
                    commerce_order_id, settlement_order_id
                )));
            }
        }
    }
    Ok(())
}

fn family_report_field_values(
    family_reports: &[serde_json::Value],
    schema: &str,
    field: &str,
) -> BTreeSet<String> {
    family_reports
        .iter()
        .filter(|report| report.get("schema").and_then(serde_json::Value::as_str) == Some(schema))
        .filter_map(|report| report.get(field).and_then(serde_json::Value::as_str))
        .map(ToOwned::to_owned)
        .collect()
}

fn push_checked_local_family_report<T: serde::Serialize>(
    family_reports: &mut Vec<serde_json::Value>,
    claim_requirements: &VerifierPolicyClaimRequirements,
    spec: &LocalProofFamilySpec,
    report: T,
) -> Result<(), CliError> {
    let report = serde_json::to_value(report).map_err(CliError::from)?;
    ensure_required_claims_verified(claim_requirements, &report, spec.prefix, spec.label)?;
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

fn verified_claims_from_family_reports(family_reports: &[serde_json::Value]) -> Vec<String> {
    let mut seen_claims = BTreeSet::new();
    let mut verified_claims = Vec::new();
    for report in family_reports {
        if let Some(claims) = verified_claims_array(report) {
            for claim in claims {
                let Some(claim) = claim.as_str() else {
                    continue;
                };
                if seen_claims.insert(claim.to_string()) {
                    verified_claims.push(claim.to_string());
                }
            }
        }
    }
    verified_claims
}

fn merge_family_verifier_reports(
    passport: &chio_control_plane::transaction_passport::TransactionPassport,
    passport_report_path: String,
    family_reports: Vec<serde_json::Value>,
    transparency_state: &str,
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
                    verified_claims.push(claim.to_string());
                }
            }
        }
    }
    let claim_results = verified_claim_results(&verified_claims);
    let checker_provenance = verified_claim_checker_provenance(&verified_claims);
    let all_families_verified = family_reports.iter().all(family_report_is_verified);
    let (verdict, accepted, state) = if all_families_verified {
        ("verified", true, "verified")
    } else {
        ("rejected", false, "rejected")
    };

    serde_json::json!({
        "schema": "chio.transaction.verifier-report.v1",
        "id": format!("verifier-report-{}", passport.id),
        "issued_at": passport.issued_at.clone(),
        "verdict": verdict,
        "accepted": accepted,
        "state": state,
        "passport_id": passport.id.clone(),
        "passport_path": passport_report_path,
        "evidence_graph_sha256": passport.evidence_graph_sha256.clone(),
        "evidence_graph_path": passport.evidence_graph_path.clone(),
        "claim_set_sha256": passport.claim_set_sha256.clone(),
        "claim_set_path": passport.claim_set_path.clone(),
        "verifier_policy_sha256": passport.verifier_policy_sha256.clone(),
        "verifier_policy_path": passport.verifier_policy_path.clone(),
        "transparencyState": transparency_state,
        "verified_claims": verified_claims,
        "claimResults": claim_results,
        "family_reports": family_reports,
        "checker_provenance": checker_provenance,
    })
}

fn family_report_is_verified(report: &serde_json::Value) -> bool {
    let verdict_verified =
        report.get("verdict").and_then(serde_json::Value::as_str) == Some("verified");
    let accepted_ok = match report.get("accepted") {
        Some(value) => value.as_bool() == Some(true),
        None => true,
    };
    let state_ok = match report.get("state") {
        Some(value) => value.as_str() == Some("verified"),
        None => true,
    };
    verdict_verified && accepted_ok && state_ok
}

fn verified_claim_results(verified_claims: &[String]) -> Vec<serde_json::Value> {
    verified_claims
        .iter()
        .map(|claim_id| {
            serde_json::json!({
                "claim_id": claim_id,
                "status": "verified",
                "verifier_module": proof_verify_checker_for_claim(claim_id),
            })
        })
        .collect()
}

fn verified_claim_checker_provenance(verified_claims: &[String]) -> Vec<serde_json::Value> {
    verified_claims
        .iter()
        .map(|claim_id| {
            serde_json::json!({
                "claim_id": claim_id,
                "checker": proof_verify_checker_for_claim(claim_id),
            })
        })
        .collect()
}

fn proof_verify_checker_for_claim(claim_id: &str) -> &'static str {
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
    } else if claim_id.starts_with("claim.finding.") {
        "chio proof verify (cognition-market)"
    } else {
        "chio proof verify"
    }
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
    let regeneration_hashes =
        validate_runtime_proof_regeneration_artifacts_from_graph(bundle_dir, evidence_graph_bytes)?;
    ensure_runtime_parity_report_binds_regenerated_artifacts(&parity_report, &regeneration_hashes)?;
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
) -> Result<RuntimeProofRegenerationHashes, CliError> {
    let graph: RuntimeParityEvidenceGraph = serde_json::from_slice(evidence_graph_bytes)?;
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
    .map_err(|error| CliError::cli_other_error(format!("proof verify: {error}")))?;
    Ok(RuntimeProofRegenerationHashes {
        proof_package_sha256: chio_core_types::canonical_json_bytes(&serde_json::from_slice::<
            serde_json::Value,
        >(&proof_package)?)
        .map(|bytes| chio_core::sha256_hex(&bytes))
        .map_err(CliError::from)?,
        verifier_report_sha256: chio_core_types::canonical_json_bytes(&serde_json::from_slice::<
            serde_json::Value,
        >(&verifier_report)?)
        .map(|bytes| chio_core::sha256_hex(&bytes))
        .map_err(CliError::from)?,
    })
}

struct RuntimeProofRegenerationHashes {
    proof_package_sha256: String,
    verifier_report_sha256: String,
}

fn ensure_runtime_parity_report_binds_regenerated_artifacts(
    parity_report: &serde_json::Value,
    regeneration_hashes: &RuntimeProofRegenerationHashes,
) -> Result<(), CliError> {
    ensure_runtime_parity_hash_matches(
        parity_report,
        "runtimeProofPackageSha256",
        &regeneration_hashes.proof_package_sha256,
        "runtime proof parity package hash mismatch",
    )?;
    ensure_runtime_parity_hash_matches(
        parity_report,
        "runtimeVerifierReportSha256",
        &regeneration_hashes.verifier_report_sha256,
        "runtime proof parity verifier report hash mismatch",
    )
}

fn ensure_runtime_parity_hash_matches(
    parity_report: &serde_json::Value,
    field: &str,
    expected: &str,
    label: &'static str,
) -> Result<(), CliError> {
    let Some(actual) = parity_report.get(field).and_then(serde_json::Value::as_str) else {
        return Err(CliError::cli_other_error(format!(
            "proof verify: runtime proof parity report missing {field}"
        )));
    };
    if actual == expected {
        Ok(())
    } else {
        Err(CliError::cli_other_error(format!(
            "proof verify: {label}: expected {expected}, got {actual}"
        )))
    }
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
            node.role == role
                || schema.is_some_and(|expected_schema| node.schema == expected_schema)
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

fn claim_set_bytes_advertise_verified_prefix(
    bytes: &[u8],
    prefix: &str,
) -> Result<bool, CliError> {
    let claim_set: serde_json::Value = serde_json::from_slice(bytes)?;
    let claims = claim_set
        .get("claims")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| CliError::cli_other_error("proof verify: claim set missing claims array"))?;
    for claim in claims {
        let claim_id = claim
            .get("claim_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                CliError::cli_other_error("proof verify: claim set claim_id must be a string")
            })?;
        let status = claim
            .get("status")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                CliError::cli_other_error("proof verify: claim set status must be a string")
            })?;
        if claim_id.starts_with(prefix) && status == "verified" {
            return Ok(true);
        }
    }
    Ok(false)
}

fn resolve_bundle_artifact_path(
    bundle_dir: &Path,
    relative_path: &str,
) -> Result<PathBuf, CliError> {
    try_resolve_bundle_artifact_path(bundle_dir, relative_path)?
        .ok_or_else(|| CliError::cli_io_error(format!("proof artifact not found: {relative_path}")))
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

    fn requires_claim(&self, claim_ref: &str) -> bool {
        self.required_claims
            .iter()
            .any(|claim| claim.as_str() == Some(claim_ref))
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

fn select_required_graph_node_by_path<'a>(
    nodes: &'a [GraphArtifactNode],
    path: &str,
    label: &str,
) -> Result<&'a GraphArtifactNode, CliError> {
    let matches: Vec<&GraphArtifactNode> = nodes.iter().filter(|node| node.path == path).collect();
    match matches.as_slice() {
        [node] => Ok(node),
        [] => Err(CliError::cli_other_error(format!(
            "proof verify: missing {label} artifact path: {path}",
        ))),
        _ => Err(CliError::cli_other_error(format!(
            "proof verify: multiple {label} artifact paths: {path}",
        ))),
    }
}

fn load_required_graph_json_artifact<T: for<'de> serde::Deserialize<'de>>(
    bundle_dir: &Path,
    nodes: &[GraphArtifactNode],
    role: &str,
    expected_schema: &str,
    label: &str,
) -> Result<T, CliError> {
    let bytes =
        load_required_graph_bytes_artifact(bundle_dir, nodes, role, expected_schema, label)?;
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

fn load_required_graph_bytes_artifact_by_path(
    bundle_dir: &Path,
    nodes: &[GraphArtifactNode],
    path: &str,
    expected_schema: &str,
    label: &str,
) -> Result<Vec<u8>, CliError> {
    let node = select_required_graph_node_by_path(nodes, path, label)?;
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

fn load_optional_graph_json_artifacts<T: for<'de> serde::Deserialize<'de>>(
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

fn read_graph_artifact(bundle_dir: &Path, node: &GraphArtifactNode) -> Result<Vec<u8>, CliError> {
    let artifact_path = resolve_bundle_artifact_path(bundle_dir, &node.path)?;
    fs::read(artifact_path).map_err(CliError::from)
}

#[derive(serde::Deserialize)]
struct CommerceMandateProtocolPayloadRefs {
    protocol_projections: Vec<CommerceMandateProtocolPayloadRef>,
}

#[derive(serde::Deserialize)]
struct CommerceMandateProtocolPayloadRef {
    protocol: String,
    purpose: String,
    payload_path: String,
}

fn load_commerce_mandate_protocol_payloads(
    bundle_dir: &Path,
    nodes: &[GraphArtifactNode],
    mandate_ledger_bytes: &[u8],
) -> Result<Vec<chio_commerce_order::CommerceMandateProtocolPayload>, CliError> {
    let refs: CommerceMandateProtocolPayloadRefs =
        serde_json::from_slice(mandate_ledger_bytes).map_err(CliError::from)?;
    let mut payloads = Vec::with_capacity(refs.protocol_projections.len());
    for projection in refs.protocol_projections {
        let payload_bytes = load_required_graph_bytes_artifact_by_path(
            bundle_dir,
            nodes,
            &projection.payload_path,
            chio_commerce_order::COMMERCE_PROTOCOL_PAYLOAD_SCHEMA_ID,
            "commerce mandate protocol payload",
        )?;
        payloads.push(chio_commerce_order::CommerceMandateProtocolPayload {
            protocol: projection.protocol,
            purpose: projection.purpose,
            payload_bytes,
        });
    }
    Ok(payloads)
}

fn load_commerce_order_bundle_from_graph(
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
    trusted_event_authority_receipt_kernel_keys: &[chio_core_types::PublicKey],
    trusted_payment_signer_keys: &[chio_core_types::PublicKey],
    trusted_provider_trust_signer_keys: &[chio_core_types::PublicKey],
    verified_trust_market_context: Option<&chio_commerce_order::CommerceVerifiedTrustMarketContext>,
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
    let event_log_bytes = load_required_graph_bytes_artifact_by_path(
        bundle_dir,
        &graph.nodes,
        &order_context.event_log_path,
        chio_commerce_order::COMMERCE_EVENT_LOG_SCHEMA_ID,
        "commerce",
    )?;
    let event_authority_receipts =
        load_commerce_event_authority_receipts(bundle_dir, &graph.nodes, &event_log_bytes)?;
    let payment_lifecycle_bytes = load_required_graph_bytes_artifact_by_path(
        bundle_dir,
        &graph.nodes,
        &order_context.payment_lifecycle_path,
        chio_commerce_order::COMMERCE_PAYMENT_LIFECYCLE_SCHEMA_ID,
        "commerce",
    )?;
    let mandate_ledger_bytes = load_required_graph_bytes_artifact_by_path(
        bundle_dir,
        &graph.nodes,
        &order_context.mandate_ledger_path,
        chio_commerce_order::COMMERCE_MANDATE_ALLOWANCE_LEDGER_SCHEMA_ID,
        "commerce",
    )?;
    let mandate_protocol_payloads =
        load_commerce_mandate_protocol_payloads(bundle_dir, &graph.nodes, &mandate_ledger_bytes)?;
    let provider_passport_bytes = load_required_graph_bytes_artifact_by_path(
        bundle_dir,
        &graph.nodes,
        &order_context.provider_passport_path,
        chio_commerce_order::COMMERCE_PROVIDER_PASSPORT_SCHEMA_ID,
        "commerce",
    )?;
    let reputation_snapshot_bytes = load_required_graph_bytes_artifact_by_path(
        bundle_dir,
        &graph.nodes,
        &order_context.reputation_snapshot_path,
        chio_commerce_order::COMMERCE_REPUTATION_SNAPSHOT_SCHEMA_ID,
        "commerce",
    )?;
    let federation_trust_bundle_bytes = load_required_graph_bytes_artifact_by_path(
        bundle_dir,
        &graph.nodes,
        &order_context.federation_trust_bundle_path,
        chio_commerce_order::COMMERCE_FEDERATION_TRUST_BUNDLE_SCHEMA_ID,
        "commerce",
    )?;
    let settlement_packet_bytes = load_required_graph_bytes_artifact_by_path(
        bundle_dir,
        &graph.nodes,
        &order_context.settlement_packet_path,
        chio_commerce_order::COMMERCE_SETTLEMENT_PACKET_SCHEMA_ID,
        "commerce",
    )?;
    let risk_comptroller_report_bytes = if let Some(requirement) = order_context
        .coverage_requirement
        .as_ref()
        .filter(|requirement| requirement.required)
    {
        Some(load_required_graph_bytes_artifact_by_path(
            bundle_dir,
            &graph.nodes,
            &requirement.risk_comptroller_report_path,
            "chio.risk.comptroller-report.v1",
            "commerce",
        )?)
    } else {
        None
    };

    Ok(chio_commerce_order::CommerceOrderVerificationBundle {
        order_context,
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
        verified_trust_market_context: verified_trust_market_context.cloned(),
        trusted_event_authority_receipt_kernel_keys: trusted_event_authority_receipt_kernel_keys
            .to_vec(),
        trusted_payment_signer_keys: trusted_payment_signer_keys.to_vec(),
        trusted_provider_trust_signer_keys: trusted_provider_trust_signer_keys.to_vec(),
        trusted_risk_comptroller_signer_keys:
            enterprise_trusted_risk_comptroller_signer_keys_from_env()?,
    })
}

fn load_commerce_event_authority_receipts(
    bundle_dir: &Path,
    nodes: &[GraphArtifactNode],
    event_log_bytes: &[u8],
) -> Result<Vec<chio_commerce_order::CommerceEventAuthorityReceiptArtifact>, CliError> {
    commerce_event_authority_receipt_refs(event_log_bytes)?
        .into_iter()
        .map(|receipt_ref| {
            let node = select_required_graph_receipt_node(bundle_dir, nodes, &receipt_ref)?;
            let receipt_bytes = load_graph_bytes_artifact(
                bundle_dir,
                node,
                chio_core_types::receipt::body::CHIO_RECEIPT_SCHEMA,
                "commerce authority receipt",
            )?;
            Ok(chio_commerce_order::CommerceEventAuthorityReceiptArtifact {
                receipt_ref,
                receipt_bytes,
            })
        })
        .collect()
}

fn commerce_event_authority_receipt_refs(event_log_bytes: &[u8]) -> Result<Vec<String>, CliError> {
    let event_log: serde_json::Value = serde_json::from_slice(event_log_bytes)?;
    let events = event_log
        .get("events")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            CliError::cli_other_error(
                "proof verify: commerce event log events must be an array".to_string(),
            )
        })?;
    events
        .iter()
        .map(|event| {
            event
                .get("authority_receipt_ref")
                .and_then(serde_json::Value::as_str)
                .filter(|receipt_ref| !receipt_ref.is_empty())
                .map(str::to_string)
                .ok_or_else(|| {
                    CliError::cli_other_error(
                        "proof verify: commerce event missing authority receipt ref".to_string(),
                    )
                })
        })
        .collect()
}

fn select_required_graph_receipt_node<'a>(
    bundle_dir: &Path,
    nodes: &'a [GraphArtifactNode],
    receipt_ref: &str,
) -> Result<&'a GraphArtifactNode, CliError> {
    let receipt_path = format!("authority-receipts/{receipt_ref}.json");
    let matches: Vec<&GraphArtifactNode> = nodes
        .iter()
        .filter(|node| {
            node.schema.as_deref() == Some(chio_core_types::receipt::body::CHIO_RECEIPT_SCHEMA)
                && (node.path == receipt_path
                    || graph_receipt_artifact_id_matches(bundle_dir, node, receipt_ref)
                        .unwrap_or(false))
        })
        .collect();
    match matches.as_slice() {
        [node] => Ok(node),
        [] => Err(CliError::cli_other_error(format!(
            "proof verify: missing commerce authority receipt artifact: {receipt_ref}",
        ))),
        _ => Err(CliError::cli_other_error(format!(
            "proof verify: multiple commerce authority receipt artifacts: {receipt_ref}",
        ))),
    }
}

fn graph_receipt_artifact_id_matches(
    bundle_dir: &Path,
    node: &GraphArtifactNode,
    receipt_ref: &str,
) -> Result<bool, CliError> {
    let bytes = read_graph_artifact(bundle_dir, node)?;
    let receipt: serde_json::Value = serde_json::from_slice(&bytes).map_err(CliError::from)?;
    Ok(receipt
        .get("id")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|id| id == receipt_ref))
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
    verified_claims_array(report).is_some_and(|claims| {
        claims
            .iter()
            .any(|verified_claim| verified_claim.as_str() == Some(required_claim))
    }) || transaction_report_verifies_claim(report, required_claim)
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
    require_crypto_context_material: bool,
) -> Result<chio_selective_disclosure::DisclosureLineageBundle, CliError> {
    let graph = parse_graph_artifact_paths(evidence_graph_bytes)?;
    let capsule: chio_selective_disclosure::DisclosureCapsule = load_required_graph_json_artifact(
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
    let privacy_profile: chio_selective_disclosure::DisclosureVerifierPrivacyProfile =
        load_required_graph_json_artifact(
            bundle_dir,
            &graph.nodes,
            "disclosure-verifier-privacy-profile",
            chio_selective_disclosure::DISCLOSURE_VERIFIER_PRIVACY_PROFILE_SCHEMA_V1,
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
    let report_claims_crypto_context = crypto_context_report.as_ref().is_some_and(|report| {
        report
            .verified_claims
            .iter()
            .any(|claim| claim == CLAIM_DISCLOSURE_CRYPTO_CONTEXT_BOUND)
    });
    if require_crypto_context_material || report_claims_crypto_context {
        if let Some(report) = &crypto_context_report {
            let context =
                load_required_disclosure_crypto_verification_context(bundle_dir, &graph.nodes)?;
            ensure_disclosure_crypto_context_matches_report(&context, report)?;
            let proof =
                load_required_disclosure_selective_disclosure_proof(bundle_dir, &graph.nodes)?;
            let projection_manifest =
                load_required_disclosure_bbs_projection_manifest(bundle_dir, &graph.nodes)?;
            let transparency_inclusion =
                load_required_disclosure_transparency_inclusion_proof_for_anchored_context(
                    bundle_dir,
                    &graph.nodes,
                    &context,
                    &privacy_profile,
                )?;
            ensure_disclosure_selective_disclosure_proof_matches_context(
                &capsule,
                &proof,
                &projection_manifest,
                transparency_inclusion.as_ref(),
                &context,
                &privacy_profile,
                report,
            )?;
        }
    }

    Ok(chio_selective_disclosure::DisclosureLineageBundle {
        capsule,
        privacy_profile,
        lineage,
        leakage_ledger,
        crypto_context_report,
    })
}

fn load_required_disclosure_crypto_verification_context(
    bundle_dir: &Path,
    nodes: &[GraphArtifactNode],
) -> Result<chio_selective_disclosure::CryptoVerificationContext, CliError> {
    let matches = graph_nodes_by_role(nodes, "crypto-verification-context");
    match matches.as_slice() {
        [node] => load_graph_json_artifact(
            bundle_dir,
            node,
            chio_selective_disclosure::CRYPTO_VERIFICATION_CONTEXT_SCHEMA_V1,
            "disclosure lineage",
        ),
        [] => Err(CliError::cli_other_error(
            "proof verify: missing disclosure crypto verification context".to_string(),
        )),
        _ => Err(CliError::cli_other_error(
            "proof verify: multiple disclosure crypto verification contexts".to_string(),
        )),
    }
}

fn ensure_disclosure_crypto_context_matches_report(
    context: &chio_selective_disclosure::CryptoVerificationContext,
    report: &chio_selective_disclosure::DisclosureCryptoContextReport,
) -> Result<(), CliError> {
    if context.context_id != report.context_id {
        return Err(CliError::cli_other_error(
            "proof verify: disclosure crypto verification context id mismatch".to_string(),
        ));
    }
    if context.artifact_ref != report.artifact_ref {
        return Err(CliError::cli_other_error(
            "proof verify: disclosure crypto verification context artifact mismatch".to_string(),
        ));
    }
    if context.proof_mechanism != "bbs" {
        return Err(CliError::cli_other_error(
            "proof verify: disclosure crypto verification context must use bbs".to_string(),
        ));
    }
    Ok(())
}

fn load_required_disclosure_selective_disclosure_proof(
    bundle_dir: &Path,
    nodes: &[GraphArtifactNode],
) -> Result<chio_selective_disclosure::SelectiveDisclosureProof, CliError> {
    let matches = graph_nodes_by_role(nodes, "selective-disclosure-proof");
    match matches.as_slice() {
        [node] => load_graph_json_artifact(
            bundle_dir,
            node,
            chio_selective_disclosure::SELECTIVE_DISCLOSURE_PROOF_SCHEMA_V1,
            "disclosure lineage",
        ),
        [] => Err(CliError::cli_other_error(
            "proof verify: missing disclosure selective disclosure proof".to_string(),
        )),
        _ => Err(CliError::cli_other_error(
            "proof verify: multiple disclosure selective disclosure proofs".to_string(),
        )),
    }
}

fn load_required_disclosure_bbs_projection_manifest(
    bundle_dir: &Path,
    nodes: &[GraphArtifactNode],
) -> Result<chio_selective_disclosure::BbsProjectionManifest, CliError> {
    let matches = graph_nodes_by_role(nodes, "bbs-projection-manifest");
    match matches.as_slice() {
        [node] => load_graph_json_artifact(
            bundle_dir,
            node,
            chio_selective_disclosure::BBS_PROJECTION_MANIFEST_SCHEMA_V2,
            "disclosure lineage",
        ),
        [] => Err(CliError::cli_other_error(
            "proof verify: missing disclosure BBS projection manifest".to_string(),
        )),
        _ => Err(CliError::cli_other_error(
            "proof verify: multiple disclosure BBS projection manifests".to_string(),
        )),
    }
}

fn load_required_disclosure_transparency_inclusion_proof_for_anchored_context(
    bundle_dir: &Path,
    nodes: &[GraphArtifactNode],
    context: &chio_selective_disclosure::CryptoVerificationContext,
    profile: &chio_selective_disclosure::DisclosureVerifierPrivacyProfile,
) -> Result<Option<chio_selective_disclosure::TransparencyInclusionProof>, CliError> {
    if context.transparency_state < chio_selective_disclosure::TransparencyState::Anchored
        && profile.required_transparency_state
            < chio_selective_disclosure::TransparencyState::Anchored
    {
        return Ok(None);
    }
    let matches = graph_nodes_by_role(nodes, "transparency-inclusion-proof");
    match matches.as_slice() {
        [node] => load_graph_json_artifact(
            bundle_dir,
            node,
            chio_selective_disclosure::TRANSPARENCY_INCLUSION_PROOF_SCHEMA_V1,
            "disclosure lineage",
        )
        .map(Some),
        [] => Err(CliError::cli_other_error(
            "proof verify: missing disclosure transparency inclusion proof".to_string(),
        )),
        _ => Err(CliError::cli_other_error(
            "proof verify: multiple disclosure transparency inclusion proofs".to_string(),
        )),
    }
}

fn ensure_disclosure_selective_disclosure_proof_matches_context(
    capsule: &chio_selective_disclosure::DisclosureCapsule,
    proof: &chio_selective_disclosure::SelectiveDisclosureProof,
    projection_manifest: &chio_selective_disclosure::BbsProjectionManifest,
    transparency_inclusion: Option<&chio_selective_disclosure::TransparencyInclusionProof>,
    context: &chio_selective_disclosure::CryptoVerificationContext,
    profile: &chio_selective_disclosure::DisclosureVerifierPrivacyProfile,
    report: &chio_selective_disclosure::DisclosureCryptoContextReport,
) -> Result<(), CliError> {
    ensure_projection_manifest_declares_capsule_hidden_predicates(capsule, projection_manifest)?;
    chio_selective_disclosure::verify_bbs_projection_manifest(proof, projection_manifest)
        .map_err(|error| CliError::cli_other_error(format!("proof verify: {error}")))?;
    if let Some(inclusion) = transparency_inclusion {
        chio_selective_disclosure::verify_transparency_inclusion_proof(proof, inclusion)
            .map_err(|error| CliError::cli_other_error(format!("proof verify: {error}")))?;
    }
    if report.projection_manifest_ref != projection_manifest.manifest_id {
        return Err(CliError::cli_other_error(
            "proof verify: disclosure crypto report projection manifest ref mismatch".to_string(),
        ));
    }

    let public_key_bytes = hex::decode(&proof.issuer_public_key_hex).map_err(|error| {
        CliError::cli_other_error(format!(
            "proof verify: malformed disclosure proof issuer public key: {error}"
        ))
    })?;
    let issuer_fingerprint = chio_core::sha256_hex(&public_key_bytes);
    if issuer_fingerprint != proof.issuer_fingerprint {
        return Err(CliError::cli_other_error(
            "proof verify: disclosure proof issuer public key fingerprint mismatch".to_string(),
        ));
    }

    let mut registry = chio_selective_disclosure::InMemoryIssuerRegistry::default();
    registry.insert(
        proof.issuer_fingerprint.clone(),
        proof.issuer_public_key_hex.clone(),
    );

    let mut proof_context = context.clone();
    proof_context.artifact_ref = proof.subject_sha256_hex.clone();
    let recomputed = chio_selective_disclosure::verify_selective_disclosure_with_context(
        proof,
        &registry,
        &proof_context,
        profile,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "proof verify: disclosure selective disclosure proof rejected: {error}"
        ))
    })?;

    if recomputed.verdict != chio_selective_disclosure::DisclosureContextVerdict::Verified {
        let rejected_codes = recomputed
            .rejected_checks
            .iter()
            .map(|check| check.code.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let message = format!("proof verify: {rejected_codes}: disclosure crypto context rejected");
        return if is_transparency_preview_not_allowed_error(&rejected_codes) {
            Err(CliError::registry_error(
                &TRANSACTION_TRANSPARENCY_PREVIEW_NOT_ALLOWED,
                message,
            ))
        } else {
            Err(CliError::cli_other_error(message))
        };
    }
    if !recomputed.cryptographic_proof_verified {
        return Err(CliError::cli_other_error(
            "proof verify: disclosure cryptographic proof was not verified".to_string(),
        ));
    }
    if report.projection_manifest_ref != recomputed.projection_manifest_ref {
        return Err(CliError::cli_other_error(
            "proof verify: disclosure crypto report projection manifest ref mismatch".to_string(),
        ));
    }

    ensure_same_string_set(
        "disclosure crypto report verified claims",
        &report.verified_claims,
        &recomputed.verified_claims,
    )?;
    ensure_same_string_set(
        "disclosure crypto report disclosed fields",
        &report.disclosed_fields,
        &recomputed.disclosed_fields,
    )?;
    Ok(())
}

fn ensure_projection_manifest_declares_capsule_hidden_predicates(
    capsule: &chio_selective_disclosure::DisclosureCapsule,
    projection_manifest: &chio_selective_disclosure::BbsProjectionManifest,
) -> Result<(), CliError> {
    let declared = projection_manifest
        .hidden_predicates
        .iter()
        .map(|predicate| (predicate.predicate_id.as_str(), predicate))
        .collect::<BTreeMap<_, _>>();
    if declared.len() != projection_manifest.hidden_predicates.len() {
        return Err(CliError::cli_other_error(
            "proof verify: disclosure projection manifest has duplicate hidden predicates"
                .to_string(),
        ));
    }
    for predicate in &capsule.hidden_predicates {
        let Some(declared_predicate) = declared.get(predicate.predicate_id.as_str()) else {
            return Err(CliError::cli_other_error(format!(
                "proof verify: disclosure hidden predicate missing from projection manifest: {}",
                predicate.predicate_id
            )));
        };
        if declared_predicate.field != predicate.field {
            return Err(CliError::cli_other_error(format!(
                "proof verify: disclosure hidden predicate field mismatch with projection manifest: {}",
                predicate.predicate_id
            )));
        }
        if declared_predicate.operator != predicate.operator {
            return Err(CliError::cli_other_error(format!(
                "proof verify: disclosure hidden predicate operator mismatch with projection manifest: {}",
                predicate.predicate_id
            )));
        }
        let projection_slot = u16::try_from(predicate.projection_slot).map_err(|_| {
            CliError::cli_other_error(format!(
                "proof verify: disclosure hidden predicate projection slot out of range: {}",
                predicate.predicate_id
            ))
        })?;
        let Some(slot) = projection_manifest
            .message_slots
            .iter()
            .find(|slot| slot.slot == projection_slot)
        else {
            return Err(CliError::cli_other_error(format!(
                "proof verify: disclosure hidden predicate projection slot missing from projection manifest: {}",
                predicate.predicate_id
            )));
        };
        if slot.field != predicate.field {
            return Err(CliError::cli_other_error(format!(
                "proof verify: disclosure hidden predicate projection slot field mismatch with projection manifest: {}",
                predicate.predicate_id
            )));
        }
        if slot.disclosure != chio_selective_disclosure::BbsProjectionDisclosure::Hidden {
            return Err(CliError::cli_other_error(format!(
                "proof verify: disclosure hidden predicate projection slot is not hidden in projection manifest: {}",
                predicate.predicate_id
            )));
        }
        if let Some(expected_value_sha256) = declared_predicate.value_sha256.as_deref() {
            let actual_value_sha256 = chio_core::sha256_hex(predicate.operand.as_bytes());
            if expected_value_sha256 != actual_value_sha256 {
                return Err(CliError::cli_other_error(format!(
                    "proof verify: disclosure hidden predicate value hash mismatch with projection manifest: {}",
                    predicate.predicate_id
                )));
            }
        }
    }
    Ok(())
}

fn ensure_same_string_set(
    label: &str,
    actual: &[String],
    expected: &[String],
) -> Result<(), CliError> {
    let actual = actual.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(CliError::cli_other_error(format!(
            "proof verify: {label} did not match recomputed BBS verification"
        )));
    }
    Ok(())
}

fn load_swarm_authority_bundle_from_graph(
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
) -> Result<chio_swarm_authority::SwarmAuthorityBundle, CliError> {
    let graph = parse_graph_artifact_paths(evidence_graph_bytes)?;
    let task_graph: chio_swarm_authority::SwarmTaskGraph = load_required_graph_json_artifact(
        bundle_dir,
        &graph.nodes,
        "swarm-task-graph",
        chio_swarm_authority::CHIO_SWARM_TASK_GRAPH_SCHEMA,
        "swarm",
    )?;
    let budget_pool: chio_swarm_authority::SwarmBudgetPool = load_required_graph_json_artifact(
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
        load_optional_graph_json_artifacts(
            bundle_dir,
            &graph.nodes,
            "swarm-continuation-token",
            chio_swarm_authority::CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA,
            "swarm",
        )?;
    let witness_chains: Vec<chio_swarm_authority::SwarmDelegationWitnessChain> =
        load_optional_graph_json_artifacts(
            bundle_dir,
            &graph.nodes,
            "swarm-delegation-witness-chain",
            chio_swarm_authority::CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA,
            "swarm",
        )?;
    let join_receipts: Vec<chio_swarm_authority::SwarmJoinReceipt> =
        load_optional_graph_json_artifacts(
            bundle_dir,
            &graph.nodes,
            "swarm-join-receipt",
            chio_swarm_authority::CHIO_SWARM_JOIN_RECEIPT_SCHEMA,
            "swarm",
        )?;
    let route_plan_receipts: Vec<chio_swarm_authority::SwarmRoutePlanReceipt> =
        load_optional_graph_json_artifacts(
            bundle_dir,
            &graph.nodes,
            "swarm-route-plan-receipt",
            chio_swarm_authority::CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA,
            "swarm",
        )?;
    let terminal_receipts: Vec<chio_swarm_authority::SwarmTerminalGraphReceipt> =
        load_optional_graph_json_artifacts(
            bundle_dir,
            &graph.nodes,
            "swarm-terminal-graph-receipt",
            chio_swarm_authority::CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_SCHEMA,
            "swarm",
        )?;
    let now_unix_ms = swarm_authority_verification_time()?;

    Ok(chio_swarm_authority::SwarmAuthorityBundle {
        now_unix_ms,
        task_graph,
        continuation_tokens,
        witness_chains,
        join_receipts,
        route_plan_receipts,
        budget_pool,
        revocation_epoch,
        terminal_receipts,
    })
}

fn swarm_authority_verification_time() -> Result<u64, CliError> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "proof verify: system clock before Unix epoch: {error}"
            ))
        })?;
    u64::try_from(duration.as_millis()).map_err(|_| {
        CliError::cli_other_error("proof verify: system clock milliseconds overflow".to_string())
    })
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
    if role == "trust-root" {
        return schema == Some("chio.trust.root.v1");
    }
    if role == "request" {
        return schema == Some("chio.request.digest.v1");
    }
    if role == "claim-set" {
        return schema == Some("chio.transaction.claim-set.v1");
    }
    is_runtime_artifact_role(role)
}

fn verify_runtime_security_family_report(
    passport: &chio_control_plane::transaction_passport::TransactionPassport,
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
) -> Result<chio_control_plane::transaction_passport::RuntimeSecurityReport, CliError> {
    let runtime_evidence_graph_bytes =
        scoped_evidence_graph_bytes(evidence_graph_bytes, is_runtime_evidence_graph_node)?;
    let artifacts = load_runtime_artifacts_from_graph(bundle_dir, &runtime_evidence_graph_bytes)?;
    let runtime_trust = runtime_trust_from_env()?;
    chio_control_plane::transaction_passport::verify_runtime_security_claims_with_trust(
        &chio_control_plane::transaction_passport::RuntimeSecurityBundle {
            passport: passport.clone(),
            evidence_graph_bytes: runtime_evidence_graph_bytes,
            root_evidence_graph_bytes: Some(evidence_graph_bytes.to_vec()),
            verifier_policy_bytes: verifier_policy_bytes.to_vec(),
            artifacts,
        },
        &runtime_trust,
    )
    .map_err(map_proof_error)
}

fn is_runtime_evidence_graph_node(node: &serde_json::Value) -> bool {
    let Some(role) = node.get("role").and_then(serde_json::Value::as_str) else {
        return false;
    };
    if node
        .get("path")
        .and_then(serde_json::Value::as_str)
        .is_none()
    {
        return false;
    }
    let schema = node.get("schema").and_then(serde_json::Value::as_str);
    if role == "receipt" {
        return schema == Some("chio.runtime.terminal-receipt.v1");
    }
    matches!(
        role,
        "advisory-observation" | "claim-set" | "request" | "trust-root" | "verifier-policy"
    ) || is_runtime_artifact_role(role)
}

fn is_runtime_artifact_role(role: &str) -> bool {
    matches!(
        role,
        "execution-lease"
            | "policy-activation-receipt"
            | "tool-server-ack"
            | "trusted-time-proof"
            | "revocation-freshness-proof"
            | "sandbox-attestation"
            | "swarm-task-graph"
            | "swarm-budget-pool"
            | "swarm-join-receipt"
            | "swarm-route-plan-receipt"
            | "runtime-attack-simulation-report"
            | "runtime-chaos-run-report"
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
            | "adjudication-jurisdiction-receipt"
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
        "adjudication-jurisdiction-receipt" | "claim-set" | "verifier-policy" | "report"
    ) || is_enterprise_artifact_role(role)
}

fn load_agent_web_artifacts_from_graph(
    bundle_dir: &Path,
    evidence_graph_bytes: &[u8],
) -> Result<BTreeMap<String, Vec<u8>>, CliError> {
    load_graph_artifacts_matching(bundle_dir, evidence_graph_bytes, |node| {
        is_agent_web_evidence_graph_node_parts(&node.role, &node.path, node.schema.as_deref())
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
    if node
        .get("path")
        .and_then(serde_json::Value::as_str)
        .is_none()
    {
        return false;
    }
    let Some(path) = node.get("path").and_then(serde_json::Value::as_str) else {
        return false;
    };
    let schema = node.get("schema").and_then(serde_json::Value::as_str);
    is_agent_web_evidence_graph_node_parts(role, path, schema)
}

fn is_agent_web_evidence_graph_node_parts(role: &str, _path: &str, schema: Option<&str>) -> bool {
    if role == "receipt" {
        return schema == Some("chio.receipt.v1");
    }
    role == "claim-set" || is_agent_web_artifact_role(role)
}

fn scoped_evidence_graph_bytes(
    evidence_graph_bytes: &[u8],
    include_node: fn(&serde_json::Value) -> bool,
) -> Result<Vec<u8>, CliError> {
    let mut graph: serde_json::Value = serde_json::from_slice(evidence_graph_bytes)?;
    let Some(nodes) = graph
        .get_mut("nodes")
        .and_then(serde_json::Value::as_array_mut)
    else {
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

    if let Some(edges) = graph
        .get_mut("edges")
        .and_then(serde_json::Value::as_array_mut)
    {
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
            | "receipt"
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
    matches!(role, "claim-set" | "receipt" | "verifier-policy" | "report")
        || is_trust_market_artifact_role(role)
}

fn map_proof_error(
    error: chio_control_plane::transaction_passport::TransactionPassportError,
) -> CliError {
    use chio_control_plane::transaction_passport::TransactionPassportError;

    match error {
        TransactionPassportError::UnsupportedSchema(_) => CliError::registry_error(
            &TRANSACTION_PASSPORT_SCHEMA_UNSUPPORTED,
            format!("proof verify: {error}"),
        ),
        TransactionPassportError::EvidenceGraphDigestMismatch { .. }
        | TransactionPassportError::VerifierPolicyDigestMismatch { .. } => {
            CliError::registry_error(
                &TRANSACTION_PASSPORT_HASH_MISMATCH,
                format!("proof verify: {error}"),
            )
        }
        TransactionPassportError::EvidenceGraphArtifactDigestMismatch { .. } => {
            CliError::registry_error(
                &TRANSACTION_ARTIFACT_HASH_MISMATCH,
                format!("proof verify: {error}"),
            )
        }
        TransactionPassportError::MissingExecutionLease
        | TransactionPassportError::MissingRuntimeArtifact(_)
        | TransactionPassportError::InvalidRuntimeArtifact { .. }
        | TransactionPassportError::RuntimeSecurityClaimFailed(_)
        | TransactionPassportError::AdvisoryEvidenceCannotAuthorize => CliError::registry_error(
            &TRANSACTION_RUNTIME_PROOF_REJECTED,
            format!("proof verify: {error}"),
        ),
        TransactionPassportError::InvalidEvidenceGraphArtifact(ref message)
            if is_required_claim_missing_error(message) =>
        {
            CliError::registry_error(
                &TRANSACTION_REQUIRED_CLAIM_MISSING,
                format!("proof verify: {error}"),
            )
        }
        TransactionPassportError::InvalidEvidenceGraphArtifact(ref message)
            if is_graph_cycle_error(message) =>
        {
            CliError::registry_error(&TRANSACTION_GRAPH_CYCLE, format!("proof verify: {error}"))
        }
        TransactionPassportError::MissingEvidenceGraphArtifact(_) => CliError::registry_error(
            &TRANSACTION_GRAPH_NOT_CLOSED,
            format!("proof verify: {error}"),
        ),
        TransactionPassportError::InvalidEvidenceGraphArtifact(ref message)
            if is_graph_not_closed_error(message) =>
        {
            CliError::registry_error(
                &TRANSACTION_GRAPH_NOT_CLOSED,
                format!("proof verify: {error}"),
            )
        }
        TransactionPassportError::InvalidEvidenceGraphArtifact(ref message)
            if is_authorization_not_bound_error(message) =>
        {
            CliError::registry_error(
                &TRANSACTION_AUTHORIZATION_NOT_BOUND,
                format!("proof verify: {error}"),
            )
        }
        other => CliError::cli_other_error(format!("proof verify: {other}")),
    }
}

fn map_commerce_proof_error(error: chio_commerce_order::CommerceOrderError) -> CliError {
    match error {
        chio_commerce_order::CommerceOrderError::ReplayFailed(ref message)
        | chio_commerce_order::CommerceOrderError::SettlementFailed(ref message)
            if is_settlement_unverified_error(message) =>
        {
            CliError::registry_error(
                &TRANSACTION_SETTLEMENT_UNVERIFIED,
                format!("proof verify: {error}"),
            )
        }
        other => CliError::cli_other_error(format!("proof verify: {other}")),
    }
}

fn map_public_settlement_proof_error(error: chio_web3::error::Web3ContractError) -> CliError {
    match error {
        chio_web3::error::Web3ContractError::InvalidProof(ref message)
            if is_public_settlement_identity_not_bound_error(message) =>
        {
            CliError::registry_error(
                &TRANSACTION_IDENTITY_NOT_BOUND,
                format!("proof verify: {error}"),
            )
        }
        chio_web3::error::Web3ContractError::InvalidProof(ref message)
            if is_public_settlement_dispute_unbound_error(message) =>
        {
            CliError::registry_error(
                &TRANSACTION_DISPUTE_UNBOUND,
                format!("proof verify: {error}"),
            )
        }
        chio_web3::error::Web3ContractError::InvalidSettlement(ref message)
            if is_settlement_unverified_error(message) =>
        {
            CliError::registry_error(
                &TRANSACTION_SETTLEMENT_UNVERIFIED,
                format!("proof verify: {error}"),
            )
        }
        other => CliError::cli_other_error(format!("proof verify: {other}")),
    }
}

fn is_public_settlement_identity_not_bound_error(message: &str) -> bool {
    message.starts_with("public settlement beneficiary identity binding ")
}

fn is_public_settlement_dispute_unbound_error(message: &str) -> bool {
    message.starts_with("public settlement dispute ")
}

fn is_advisory_authority_edge_proof_error(
    error: &chio_control_plane::transaction_passport::TransactionPassportError,
) -> bool {
    matches!(
        error,
        chio_control_plane::transaction_passport::TransactionPassportError::InvalidEvidenceGraphArtifact(message)
            if message == "advisory evidence cannot satisfy authority edge"
    )
}

fn is_settlement_unverified_error(message: &str) -> bool {
    message.contains("settlement event missing settlement packet evidence")
        || message == "public settlement finality requires successful settlement state"
}

fn is_transparency_preview_not_allowed_error(message: &str) -> bool {
    message.contains("disclosure_context_transparency_state_insufficient")
        || message.contains("context transparency state was weaker than the profile requirement")
}

fn is_authorization_not_bound_error(message: &str) -> bool {
    matches!(
        message.strip_prefix("minimal governed action evidence invalid: "),
        Some(
            "capability proof not valid at evidence graph issuance"
                | "capability proof expired before evidence graph issuance"
                | "capability proof does not match receipt capability"
                | "guard decision does not match capability proof"
                | "guard-to-receipt binding missing"
        )
    )
}

fn is_graph_not_closed_error(message: &str) -> bool {
    message.starts_with("unknown evidence graph edge source: ")
        || message.starts_with("unknown evidence graph edge target: ")
}

fn is_graph_cycle_error(message: &str) -> bool {
    message.starts_with("cyclic evidence graph: ")
}

fn is_required_claim_missing_error(message: &str) -> bool {
    message.starts_with("claim set missing required claim: ")
        || message.starts_with("claim set required claim was not verified: ")
}

#[cfg(test)]
mod unit_tests;
