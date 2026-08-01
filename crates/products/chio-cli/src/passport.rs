use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::{Keypair, PublicKey};
use chio_credentials::{
    build_agent_passport, create_passport_presentation_challenge_with_reference,
    create_signed_passport_verifier_policy,
    default_oid4vci_passport_issuer_metadata_with_signing_key,
    default_oid4vci_passport_issuer_metadata_with_status_distribution,
    ensure_signed_passport_verifier_policy_active, evaluate_agent_passport,
    issue_reputation_credential_with_enterprise_identity, passport_artifact_id,
    present_agent_passport, respond_to_oid4vp_request, respond_to_passport_presentation_challenge,
    verify_agent_passport, verify_passport_presentation_response_with_policy,
    verify_signed_oid4vp_request_object_with_any_key, verify_signed_passport_verifier_policy,
    AgentPassport, AttestationWindow, ChioCredentialEvidence, CredentialError,
    EnterpriseIdentityProvenance, Oid4vciCredentialOffer, Oid4vciCredentialRequest,
    Oid4vciTokenRequest, Oid4vciTokenResponse, Oid4vpPresentationVerification, Oid4vpRequestObject,
    Oid4vpVerifierMetadata, PassportLifecycleResolution, PassportLifecycleState,
    PassportPresentationChallenge, PassportPresentationOptions, PassportPresentationResponse,
    PassportStatusDistribution, PassportVerifierPolicy, PassportVerifierPolicyReference,
    PortableJwkSet, SignedPassportVerifierPolicy, OID4VP_VERIFIER_METADATA_PATH,
};
use chio_credentials::{synthesize_trust_tier, TrustTier};
use chio_did::DidChio;
use chio_errors::_generated::error_codes::TRANSACTION_RECEIPT_UNCHECKPOINTED;
use chio_kernel::{
    behavioral_anomaly_score, compliance_score, ComplianceReport, ComplianceScoreConfig,
    ComplianceScoreInputs, EmaBaselineState, EvidenceChildReceiptScope, EvidenceExportQuery,
};
use chio_reputation::{compute_local_scorecard, ReputationConfig};
use chio_store_sqlite::SqliteReceiptStore;
use url::Url;

use crate::issuance::build_local_reputation_corpus;
use crate::passport_verifier::{
    PassportIssuanceOfferRegistry, PassportStatusListResponse, PassportStatusRegistry,
    PassportStatusRevocationRequest, PassportVerifierChallengeStore, PublishPassportStatusRequest,
    VerifierPolicyRegistry,
};
use crate::trust_control::{
    CreateIdentityAssertionRequest, CreateOid4vpRequest, CreatePassportChallengeRequest,
    CreatePassportChallengeResponse, VerifierPolicyListResponse, VerifyPassportChallengeRequest,
};
use crate::{load_or_create_authority_keypair, CliError};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn ensure_parent_dir(path: &Path) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn require_verifier_policy_registry_path(path: Option<&Path>) -> Result<&Path, CliError> {
    path.ok_or_else(|| {
        CliError::cli_other_error(
            "verifier policy commands require --verifier-policies-file <path> when not using --control-url"
                .to_string(),
        )
    })
}

fn require_passport_status_registry_path(path: Option<&Path>) -> Result<&Path, CliError> {
    path.ok_or_else(|| {
        CliError::cli_other_error(
            "passport lifecycle commands require --passport-statuses-file <path> when not using --control-url"
                .to_string(),
        )
    })
}

fn require_passport_issuance_registry_path(path: Option<&Path>) -> Result<&Path, CliError> {
    path.ok_or_else(|| {
        CliError::cli_other_error(
            "passport issuance commands require --passport-issuance-offers-file <path> when not using --control-url"
                .to_string(),
        )
    })
}

fn require_credential_issuer_url(value: Option<&str>) -> Result<&str, CliError> {
    value.ok_or_else(|| {
        CliError::cli_other_error(
            "passport issuance commands require --issuer-url <url> when not using --control-url"
                .to_string(),
        )
    })
}

fn load_verifier_policy_registry_for_admin(
    path: &Path,
) -> Result<VerifierPolicyRegistry, CliError> {
    if path.exists() {
        VerifierPolicyRegistry::load(path)
    } else {
        Ok(VerifierPolicyRegistry::default())
    }
}

fn load_passport_status_registry_for_admin(
    path: &Path,
) -> Result<PassportStatusRegistry, CliError> {
    if path.exists() {
        PassportStatusRegistry::load(path)
    } else {
        Ok(PassportStatusRegistry::default())
    }
}

fn load_passport_issuance_registry_for_admin(
    path: &Path,
) -> Result<PassportIssuanceOfferRegistry, CliError> {
    if path.exists() {
        PassportIssuanceOfferRegistry::load(path)
    } else {
        Ok(PassportIssuanceOfferRegistry::default())
    }
}

fn load_signed_passport_verifier_policy(
    path: &Path,
) -> Result<SignedPassportVerifierPolicy, CliError> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn load_oid4vci_offer(path: &Path) -> Result<Oid4vciCredentialOffer, CliError> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn load_oid4vci_token(path: &Path) -> Result<Oid4vciTokenResponse, CliError> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn fetch_json_url<T: for<'de> serde::Deserialize<'de>>(url: &str) -> Result<T, CliError> {
    match ureq::get(url).call() {
        Ok(response) => Ok(serde_json::from_reader(response.into_reader())?),
        Err(ureq::Error::Status(status, response)) => {
            let message = response
                .into_string()
                .ok()
                .filter(|body| !body.trim().is_empty())
                .unwrap_or_else(|| format!("request failed with status {status}"));
            Err(CliError::transport_error(message))
        }
        Err(ureq::Error::Transport(error)) => Err(CliError::transport_error(format!(
            "transport request failed: {error}"
        ))),
    }
}

fn fetch_text_url(url: &str) -> Result<String, CliError> {
    match ureq::get(url).call() {
        Ok(response) => response.into_string().map_err(|error| {
            CliError::transport_error(format!("failed to read response body: {error}"))
        }),
        Err(ureq::Error::Status(status, response)) => {
            let message = response
                .into_string()
                .ok()
                .filter(|body| !body.trim().is_empty())
                .unwrap_or_else(|| format!("request failed with status {status}"));
            Err(CliError::transport_error(message))
        }
        Err(ureq::Error::Transport(error)) => Err(CliError::transport_error(format!(
            "transport request failed: {error}"
        ))),
    }
}

fn post_json_url<B: serde::Serialize, T: for<'de> serde::Deserialize<'de>>(
    url: &str,
    body: &B,
) -> Result<T, CliError> {
    match ureq::post(url).send_json(serde_json::to_value(body)?) {
        Ok(response) => Ok(serde_json::from_reader(response.into_reader())?),
        Err(ureq::Error::Status(status, response)) => {
            let message = response
                .into_string()
                .ok()
                .filter(|body| !body.trim().is_empty())
                .unwrap_or_else(|| format!("request failed with status {status}"));
            Err(CliError::transport_error(message))
        }
        Err(ureq::Error::Transport(error)) => Err(CliError::transport_error(format!(
            "transport request failed: {error}"
        ))),
    }
}

fn post_form_url<T: for<'de> serde::Deserialize<'de>>(
    url: &str,
    fields: &[(&str, &str)],
) -> Result<T, CliError> {
    let body = serde_urlencoded::to_string(fields).map_err(|error| {
        CliError::transport_shape_error(format!("failed to encode form body: {error}"))
    })?;
    match ureq::post(url)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&body)
    {
        Ok(response) => Ok(serde_json::from_reader(response.into_reader())?),
        Err(ureq::Error::Status(status, response)) => {
            let message = response
                .into_string()
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| format!("request failed with status {status}"));
            Err(CliError::transport_error(message))
        }
        Err(ureq::Error::Transport(error)) => Err(CliError::transport_error(format!(
            "transport request failed: {error}"
        ))),
    }
}

fn load_text_file(path: &Path) -> Result<String, CliError> {
    let bytes = fs::read(path)?;
    let value = String::from_utf8(bytes).map_err(|error| {
        CliError::cli_other_error(format!("{} is not valid UTF-8: {error}", path.display()))
    })?;
    Ok(value.trim().to_string())
}

fn oid4vp_request_url_from_launch_url(url: &str) -> Result<String, CliError> {
    let parsed = Url::parse(url).map_err(|error| {
        CliError::transport_shape_error(format!("invalid OID4VP launch URL `{url}`: {error}"))
    })?;
    parsed
        .query_pairs()
        .find_map(|(key, value)| (key == "request_uri").then(|| value.into_owned()))
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            CliError::transport_shape_error(
                "OID4VP launch URL must include a non-empty request_uri query parameter"
                    .to_string(),
            )
        })
}

fn oid4vp_verifier_metadata_url(request_url: &str) -> Result<String, CliError> {
    let parsed = Url::parse(request_url).map_err(|error| {
        CliError::transport_shape_error(format!(
            "invalid OID4VP request URL `{request_url}`: {error}"
        ))
    })?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(CliError::transport_shape_error(
            "OID4VP request URL must use http or https".to_string(),
        ));
    }
    let host = parsed.host_str().ok_or_else(|| {
        CliError::transport_shape_error("OID4VP request URL must include a host".to_string())
    })?;
    let mut metadata = Url::parse(&format!("{scheme}://{host}")).map_err(|error| {
        CliError::transport_shape_error(format!(
            "failed to construct verifier metadata URL: {error}"
        ))
    })?;
    if let Some(port) = parsed.port() {
        metadata.set_port(Some(port)).map_err(|_| {
            CliError::transport_shape_error("failed to preserve verifier port".to_string())
        })?;
    }
    metadata.set_path(OID4VP_VERIFIER_METADATA_PATH);
    metadata.set_query(None);
    metadata.set_fragment(None);
    Ok(metadata.to_string())
}

fn verifier_public_keys_from_jwks(jwks: &PortableJwkSet) -> Result<Vec<PublicKey>, CliError> {
    let mut keys = Vec::new();
    for entry in &jwks.keys {
        keys.push(entry.jwk.to_public_key().map_err(|error| {
            CliError::transport_shape_error(format!(
                "portable verifier JWKS entry is invalid: {error}"
            ))
        })?);
    }
    if keys.is_empty() {
        return Err(CliError::transport_shape_error(
            "portable verifier JWKS did not publish any signing keys".to_string(),
        ));
    }
    Ok(keys)
}

fn load_existing_keypair(path: &Path) -> Result<Keypair, CliError> {
    let seed_hex = fs::read_to_string(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CliError::cli_other_error(format!("required seed file not found: {}", path.display()))
        } else {
            CliError::Io(error)
        }
    })?;
    Keypair::from_seed_hex(seed_hex.trim()).map_err(CliError::from)
}

pub(crate) struct PassportPolicyCreateArgs<'a> {
    pub output: &'a Path,
    pub policy_id: &'a str,
    pub verifier: &'a str,
    pub signing_seed_file: &'a Path,
    pub policy_path: &'a Path,
    pub expires_at: u64,
    pub verifier_policies_file: Option<&'a Path>,
    pub json_output: bool,
    pub control_url: Option<&'a str>,
    pub control_token: Option<&'a str>,
}

pub(crate) struct PassportChallengeCreateArgs<'a> {
    pub output: &'a Path,
    pub verifier: &'a str,
    pub ttl_secs: u64,
    pub issuers: &'a [String],
    pub max_credentials: Option<usize>,
    pub policy_path: Option<&'a Path>,
    pub policy_id: Option<&'a str>,
    pub verifier_policies_file: Option<&'a Path>,
    pub verifier_challenge_db: Option<&'a Path>,
    pub json_output: bool,
    pub control_url: Option<&'a str>,
    pub control_token: Option<&'a str>,
}

pub(crate) struct PassportOid4vpRequestCreateArgs<'a> {
    pub output: Option<&'a Path>,
    pub disclosure_claims: &'a [String],
    pub issuer_allowlist: &'a [String],
    pub ttl_secs: Option<u64>,
    pub identity_subject: Option<&'a str>,
    pub identity_continuity_id: Option<&'a str>,
    pub identity_provider: Option<&'a str>,
    pub identity_session_hint: Option<&'a str>,
    pub identity_ttl_secs: Option<u64>,
    pub json_output: bool,
    pub control_url: Option<&'a str>,
    pub control_token: Option<&'a str>,
}

pub(crate) struct PassportOid4vpRespondArgs<'a> {
    pub input: &'a Path,
    pub request_url: Option<&'a str>,
    pub same_device_url: Option<&'a str>,
    pub cross_device_url: Option<&'a str>,
    pub holder_seed_file: &'a Path,
    pub output: Option<&'a Path>,
    pub submit: bool,
    pub submit_url: Option<&'a str>,
    pub at: Option<u64>,
    pub json_output: bool,
}

fn validity_seconds(validity_days: u32) -> u64 {
    u64::from(validity_days) * 86_400
}

fn load_enterprise_identity_provenance(
    path: Option<&Path>,
) -> Result<Option<EnterpriseIdentityProvenance>, CliError> {
    path.map(|path| {
        let context: chio_core::EnterpriseIdentityContext =
            serde_json::from_slice(&fs::read(path)?)?;
        Ok(EnterpriseIdentityProvenance::from(&context))
    })
    .transpose()
}

fn summarize_enterprise_provenance(
    provenance: &[EnterpriseIdentityProvenance],
) -> (usize, Vec<String>) {
    (
        provenance.len(),
        provenance
            .iter()
            .map(|entry| entry.provider_id.clone())
            .collect(),
    )
}

fn passport_status_distribution(
    resolve_urls: &[String],
    cache_ttl_secs: Option<u64>,
) -> PassportStatusDistribution {
    PassportStatusDistribution {
        resolve_urls: resolve_urls.to_vec(),
        cache_ttl_secs,
    }
}

fn local_passport_issuer_metadata(
    issuer_url: &str,
    signing_seed_file: Option<&Path>,
    passport_status_url: Option<&str>,
    passport_status_cache_ttl_secs: Option<u64>,
) -> Result<chio_credentials::Oid4vciCredentialIssuerMetadata, CliError> {
    let distribution = passport_status_url
        .map(|resolve_url| {
            passport_status_distribution(&[resolve_url.to_string()], passport_status_cache_ttl_secs)
        })
        .unwrap_or_default();
    let portable_signing_public_key = signing_seed_file
        .map(load_or_create_authority_keypair)
        .transpose()?
        .map(|keypair| keypair.public_key());
    default_oid4vci_passport_issuer_metadata_with_signing_key(
        issuer_url,
        distribution,
        portable_signing_public_key.as_ref(),
    )
    .map_err(CliError::from)
}

fn passport_lifecycle_reason(lifecycle: &PassportLifecycleResolution) -> String {
    match lifecycle.state {
        PassportLifecycleState::Active => "passport lifecycle state is active".to_string(),
        PassportLifecycleState::Stale => lifecycle
            .updated_at
            .map(|updated_at| {
                format!("passport lifecycle state is stale: last updated at {updated_at}")
            })
            .unwrap_or_else(|| "passport lifecycle state is stale".to_string()),
        PassportLifecycleState::Superseded => lifecycle
            .superseded_by
            .as_deref()
            .map(|passport_id| format!("passport lifecycle state is superseded by {passport_id}"))
            .unwrap_or_else(|| "passport lifecycle state is superseded".to_string()),
        PassportLifecycleState::Revoked => lifecycle
            .revoked_reason
            .as_deref()
            .map(|reason| format!("passport lifecycle state is revoked: {reason}"))
            .unwrap_or_else(|| "passport lifecycle state is revoked".to_string()),
        PassportLifecycleState::NotFound => "passport lifecycle record was not found".to_string(),
    }
}

fn resolve_passport_lifecycle(
    passport: &AgentPassport,
    at: u64,
    passport_statuses_file: Option<&Path>,
    control_url: Option<&str>,
    _control_token: Option<&str>,
    required: bool,
) -> Result<Option<PassportLifecycleResolution>, CliError> {
    if let Some(url) = control_url {
        let client = crate::trust_control::service_runtime::client::build_public_client(url)?;
        let passport_id = passport_artifact_id(passport).map_err(|error| {
            CliError::policy_error(format!("failed to derive passport artifact id: {error}"))
        })?;
        let mut lifecycle = match client.public_resolve_passport_status(&passport_id) {
            Ok(lifecycle) => lifecycle,
            Err(error)
                if !required
                    && error
                        .to_string()
                        .contains("passport lifecycle administration requires") =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        lifecycle
            .validate()
            .map_err(|error| CliError::policy_error(error.to_string()))?;
        lifecycle
            .source
            .get_or_insert_with(|| format!("remote:{url}"));
        return Ok(Some(lifecycle));
    }

    let Some(path) = passport_statuses_file else {
        return Ok(None);
    };
    let registry = load_passport_status_registry_for_admin(path)?;
    let mut lifecycle = registry.resolve_for_passport(passport, at)?;
    lifecycle.source = Some(format!("registry:{}", path.display()));
    Ok(Some(lifecycle))
}

fn portable_passport_status_reference(
    passport: &AgentPassport,
    at: u64,
    passport_statuses_file: Option<&Path>,
) -> Result<Option<chio_credentials::Oid4vciChioPassportStatusReference>, CliError> {
    let Some(path) = passport_statuses_file else {
        return Ok(None);
    };
    let registry = load_passport_status_registry_for_admin(path)?;
    registry
        .portable_status_reference_for_passport(passport, at)
        .map(Some)
}

fn require_passport_lifecycle_source(
    require_active_lifecycle: bool,
    passport_statuses_file: Option<&Path>,
    control_url: Option<&str>,
) -> Result<(), CliError> {
    if require_active_lifecycle && passport_statuses_file.is_none() && control_url.is_none() {
        return Err(CliError::policy_error(
            "passport verifier policy requires active lifecycle enforcement, but no --passport-statuses-file or --control-url was provided"
                .to_string(),
        ));
    }
    Ok(())
}

fn apply_passport_lifecycle_to_evaluation(
    evaluation: &mut chio_credentials::PassportPolicyEvaluation,
    lifecycle: Option<PassportLifecycleResolution>,
) {
    evaluation.verification.passport_lifecycle = lifecycle.clone();
    if !evaluation.policy.require_active_lifecycle {
        return;
    }
    let Some(lifecycle) = lifecycle else {
        return;
    };
    if lifecycle.state == PassportLifecycleState::Active {
        return;
    }

    let reason = passport_lifecycle_reason(&lifecycle);
    evaluation.accepted = false;
    evaluation.matched_credential_indexes.clear();
    evaluation.matched_issuers.clear();
    if !evaluation
        .passport_reasons
        .iter()
        .any(|existing| existing == &reason)
    {
        evaluation.passport_reasons.push(reason);
    }
}

fn apply_passport_lifecycle_to_presentation(
    verification: &mut chio_credentials::PassportPresentationVerification,
    lifecycle: Option<PassportLifecycleResolution>,
) {
    verification.passport_lifecycle = lifecycle.clone();
    let Some(policy_evaluation) = verification.policy_evaluation.as_mut() else {
        return;
    };
    if !policy_evaluation.policy.require_active_lifecycle {
        return;
    }
    let Some(lifecycle) = lifecycle else {
        return;
    };
    if lifecycle.state == PassportLifecycleState::Active {
        return;
    }

    let reason = passport_lifecycle_reason(&lifecycle);
    policy_evaluation.accepted = false;
    policy_evaluation.matched_credential_indexes.clear();
    policy_evaluation.matched_issuers.clear();
    if !policy_evaluation
        .passport_reasons
        .iter()
        .any(|existing| existing == &reason)
    {
        policy_evaluation.passport_reasons.push(reason);
    }
    verification.accepted = false;
}

fn require_receipt_db(receipt_db_path: Option<&Path>) -> Result<&Path, CliError> {
    receipt_db_path.ok_or_else(|| {
        CliError::policy_error(
            "passport creation requires --receipt-db so the local attestation corpus can be assembled"
                .to_string(),
        )
    })
}

fn build_attestation_evidence(
    store: &SqliteReceiptStore,
    subject_key: &str,
    since: Option<u64>,
    until: Option<u64>,
    receipt_log_urls: &[String],
    require_checkpoints: bool,
) -> Result<ChioCredentialEvidence, CliError> {
    let bundle = store.build_evidence_export_bundle(&EvidenceExportQuery {
        capability_id: None,
        agent_subject: Some(subject_key.to_string()),
        since,
        until,
        tenant: None,
        read_boundary: Some(chio_kernel::ReceiptReadBoundary::AdminAll),
    })?;

    if bundle.tool_receipts.is_empty() {
        return Err(CliError::policy_error(format!(
            "no receipts found for subject {subject_key} in the selected window"
        )));
    }
    if require_checkpoints && !bundle.uncheckpointed_receipts.is_empty() {
        return Err(CliError::registry_error(
            &TRANSACTION_RECEIPT_UNCHECKPOINTED,
            format!(
            "passport creation requires checkpoint coverage, but {} selected receipt(s) are uncheckpointed",
            bundle.uncheckpointed_receipts.len()
            ),
        ));
    }

    Ok(ChioCredentialEvidence {
        query: AttestationWindow {
            since,
            until: until.unwrap_or_else(unix_now),
        },
        receipt_count: bundle.tool_receipts.len(),
        receipt_ids: bundle
            .tool_receipts
            .into_iter()
            .map(|record| record.receipt.id)
            .collect(),
        checkpoint_roots: bundle
            .checkpoints
            .into_iter()
            .map(|checkpoint| checkpoint.body.merkle_root.to_string())
            .collect(),
        receipt_log_urls: receipt_log_urls.to_vec(),
        lineage_records: bundle.capability_lineage.len(),
        uncheckpointed_receipts: bundle.uncheckpointed_receipts.len(),
        runtime_attestation: None,
    })
}

/// Build a deterministic snapshot of the inputs the kernel's
/// `compliance_score` function expects. When a caller provides a
/// `compliance_score_override`, we skip the full factor math and echo
/// the override verbatim so CI and ops harnesses can pin a specific
/// tier. When no override is supplied we materialize a clean-agent
/// report and feed it through `compliance_score` so the emitted score
/// is the kernel's own output, not a shortcut.
fn compute_generate_trust_tier(
    agent: &str,
    compliance_score_override: Option<u32>,
    behavioral_anomaly: bool,
    now: u64,
) -> (u32, bool, TrustTier) {
    let effective_score = if let Some(score) = compliance_score_override {
        score.min(chio_kernel::COMPLIANCE_SCORE_MAX)
    } else {
        // Clean-agent baseline: no denies, no revocations, no velocity
        // anomalies, no stale attestation. The kernel's scoring math
        // returns 1000 for this shape, which matches the default
        // "Premier" tier for a freshly provisioned agent.
        let report = ComplianceReport {
            matching_receipts: 0,
            evidence_ready_receipts: 0,
            uncheckpointed_receipts: 0,
            checkpoint_coverage_rate: None,
            lineage_covered_receipts: 0,
            lineage_gap_receipts: 0,
            lineage_coverage_rate: None,
            pending_settlement_receipts: 0,
            failed_settlement_receipts: 0,
            direct_evidence_export_supported: true,
            child_receipt_scope: EvidenceChildReceiptScope::FullQueryWindow,
            proofs_complete: true,
            export_query: EvidenceExportQuery::default(),
            export_scope_note: None,
        };
        let inputs = ComplianceScoreInputs::new(0, 0, 0, 0, 0, 0, Some(0));
        let config = ComplianceScoreConfig::default();
        compliance_score(&report, &inputs, &config, agent, now).score
    };

    // Drive the kernel's behavioral anomaly scorer so the boolean tier
    // input is not fabricated locally. An all-zero baseline with
    // sample_count < 2 yields `z_score == None`, so we seed a tiny
    // two-sample baseline and feed either the mean (anomaly=false) or
    // a far-tail sample (anomaly=true) to drive the desired output.
    let baseline = EmaBaselineState {
        sample_count: 2,
        ema_mean: 1.0,
        ema_variance: 1.0,
        last_update: now,
    };
    let sample = if behavioral_anomaly { 100.0 } else { 1.0 };
    let anomaly = behavioral_anomaly_score(agent, &baseline, sample, 3.0, now).anomaly;

    let tier = synthesize_trust_tier(effective_score, anomaly);
    (effective_score, anomaly, tier)
}

pub(crate) fn cmd_passport_generate(
    agent: &str,
    output: Option<&Path>,
    compliance_score_override: Option<u32>,
    behavioral_anomaly: bool,
    validity_days: u32,
    json_output: bool,
) -> Result<(), CliError> {
    if agent.trim().is_empty() {
        return Err(CliError::policy_error(
            "`chio passport generate` requires a non-empty --agent".to_string(),
        ));
    }
    let now = unix_now();
    let valid_until = now.saturating_add(validity_seconds(validity_days));

    let (score, anomaly, tier) =
        compute_generate_trust_tier(agent, compliance_score_override, behavioral_anomaly, now);

    // Keep the emitted document structurally compatible with the
    // extended `AgentPassport` wire form (camelCase, `trustTier` as an
    // optional string field) while remaining lightweight: the real
    // passport builder needs receipts and a signing authority, which
    // the `generate` command deliberately does not require.
    let passport_json = serde_json::json!({
        "schema": "chio.agent-passport.v1",
        "subject": agent,
        "credentials": [],
        "merkleRoots": [],
        "issuedAt": now,
        "validUntil": valid_until,
        "trustTier": tier,
    });

    if let Some(path) = output {
        ensure_parent_dir(path)?;
        fs::write(path, serde_json::to_vec_pretty(&passport_json)?)?;
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "output": output.map(|path| path.display().to_string()),
                "subject": agent,
                "complianceScore": score,
                "behavioralAnomaly": anomaly,
                "trustTier": tier,
                "validUntil": valid_until,
                "passport": passport_json,
            }))?
        );
    } else {
        println!("passport generated");
        println!("subject:          {agent}");
        println!("compliance_score: {score}");
        println!("behavioral_anomaly: {anomaly}");
        println!("trust_tier:       {}", tier.label());
        println!("valid_until:      {valid_until}");
        if let Some(path) = output {
            println!("output:           {}", path.display());
        } else {
            println!("{}", serde_json::to_string_pretty(&passport_json)?);
        }
    }
    Ok(())
}

pub(crate) fn cmd_passport_create(
    subject_public_key: &str,
    output: &Path,
    signing_seed_file: &Path,
    validity_days: u32,
    since: Option<u64>,
    until: Option<u64>,
    receipt_log_urls: &[String],
    require_checkpoints: bool,
    enterprise_identity_path: Option<&Path>,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    json_output: bool,
) -> Result<(), CliError> {
    let subject_public_key = PublicKey::from_hex(subject_public_key)?;
    let subject_key = subject_public_key.to_hex();
    let now = unix_now();
    let attestation_until = until.unwrap_or(now);
    let corpus = build_local_reputation_corpus(
        &subject_key,
        receipt_db_path,
        budget_db_path,
        since,
        Some(attestation_until),
    )?;
    if corpus.receipts.is_empty() {
        return Err(CliError::policy_error(format!(
            "no receipts found for subject {subject_key} in the selected window"
        )));
    }

    // Load the authority key first so its public key can anchor the
    // reputation config's trusted kernel set. Without trusted kernel keys,
    // `compute_local_scorecard` filters every receipt as unsigned and the
    // resulting score is silently unknown / zero (see chio-reputation P2).
    let signing_key = load_or_create_authority_keypair(signing_seed_file)?;
    let scoring_config =
        ReputationConfig::default().with_trusted_kernel_keys([signing_key.public_key().to_hex()]);
    let scorecard =
        compute_local_scorecard(&subject_key, attestation_until, &corpus, &scoring_config);
    let store = SqliteReceiptStore::open(require_receipt_db(receipt_db_path)?)?;
    let evidence = build_attestation_evidence(
        &store,
        &subject_key,
        since,
        Some(attestation_until),
        receipt_log_urls,
        require_checkpoints,
    )?;
    let credential = issue_reputation_credential_with_enterprise_identity(
        &signing_key,
        scorecard,
        evidence,
        load_enterprise_identity_provenance(enterprise_identity_path)?,
        now,
        now + validity_seconds(validity_days),
    )?;
    let subject_did = DidChio::from_public_key(subject_public_key).map_err(CredentialError::Did)?;
    let passport = build_agent_passport(&subject_did.to_string(), vec![credential])?;
    let (enterprise_provenance_count, enterprise_provider_ids) =
        summarize_enterprise_provenance(&passport.enterprise_identity_provenance);

    ensure_parent_dir(output)?;
    fs::write(output, serde_json::to_vec_pretty(&passport)?)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "output": output.display().to_string(),
                "subject": passport.subject,
                "credentialCount": passport.credentials.len(),
                "merkleRootCount": passport.merkle_roots.len(),
                "enterpriseIdentityProvenanceCount": enterprise_provenance_count,
                "enterpriseProviderIds": enterprise_provider_ids,
                "validUntil": passport.valid_until,
            }))?
        );
    } else {
        println!("wrote passport to {}", output.display());
        println!("subject:          {}", passport.subject);
        println!("credential_count: {}", passport.credentials.len());
        println!("merkle_roots:     {}", passport.merkle_roots.len());
        println!("enterprise_provenance: {}", enterprise_provenance_count);
        if !enterprise_provider_ids.is_empty() {
            println!(
                "enterprise_providers: {}",
                enterprise_provider_ids.join(", ")
            );
        }
        println!("valid_until:      {}", passport.valid_until);
    }
    Ok(())
}

pub(crate) fn cmd_passport_verify(
    input: &Path,
    at: Option<u64>,
    passport_statuses_file: Option<&Path>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let passport: AgentPassport = serde_json::from_slice(&fs::read(input)?)?;
    let now = at.unwrap_or_else(unix_now);
    let mut verification = verify_agent_passport(&passport, now)
        .map_err(|error| CliError::policy_error(error.to_string()))?;
    verification.passport_lifecycle = resolve_passport_lifecycle(
        &passport,
        now,
        passport_statuses_file,
        control_url,
        control_token,
        false,
    )?;
    let (enterprise_provenance_count, enterprise_provider_ids) =
        summarize_enterprise_provenance(&verification.enterprise_identity_provenance);

    if json_output {
        println!("{}", serde_json::to_string_pretty(&verification)?);
    } else {
        println!("passport verified");
        println!("subject:          {}", verification.subject);
        println!("passport_id:      {}", verification.passport_id);
        if let Some(issuer) = verification.issuer.as_deref() {
            println!("issuer:           {issuer}");
        } else {
            println!("issuers:          {}", verification.issuers.join(", "));
        }
        println!("issuer_count:     {}", verification.issuer_count);
        println!("credential_count: {}", verification.credential_count);
        println!("merkle_roots:     {}", verification.merkle_root_count);
        println!("enterprise_provenance: {}", enterprise_provenance_count);
        if !enterprise_provider_ids.is_empty() {
            println!(
                "enterprise_providers: {}",
                enterprise_provider_ids.join(", ")
            );
        }
        if let Some(lifecycle) = verification.passport_lifecycle.as_ref() {
            println!("lifecycle_state:  {}", lifecycle.state.label());
            if let Some(source) = lifecycle.source.as_deref() {
                println!("lifecycle_source: {source}");
            }
            if let Some(superseded_by) = lifecycle.superseded_by.as_deref() {
                println!("superseded_by:    {superseded_by}");
            }
            if let Some(revoked_at) = lifecycle.revoked_at {
                println!("revoked_at:       {revoked_at}");
            }
            if let Some(reason) = lifecycle.revoked_reason.as_deref() {
                println!("revoked_reason:   {reason}");
            }
        }
        println!("valid_until:      {}", verification.valid_until);
    }
    Ok(())
}

pub(crate) fn cmd_passport_evaluate(
    input: &Path,
    policy_path: &Path,
    at: Option<u64>,
    passport_statuses_file: Option<&Path>,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let passport: AgentPassport = serde_json::from_slice(&fs::read(input)?)?;
    let policy = load_passport_verifier_policy(policy_path)?;
    let now = at.unwrap_or_else(unix_now);
    require_passport_lifecycle_source(
        policy.require_active_lifecycle,
        passport_statuses_file,
        control_url,
    )?;
    let mut evaluation = evaluate_agent_passport(&passport, now, &policy)
        .map_err(|error| CliError::policy_error(error.to_string()))?;
    let lifecycle = resolve_passport_lifecycle(
        &passport,
        now,
        passport_statuses_file,
        control_url,
        control_token,
        policy.require_active_lifecycle,
    )?;
    apply_passport_lifecycle_to_evaluation(&mut evaluation, lifecycle);

    if json_output {
        println!("{}", serde_json::to_string_pretty(&evaluation)?);
    } else {
        let (enterprise_provenance_count, enterprise_provider_ids) =
            summarize_enterprise_provenance(
                &evaluation.verification.enterprise_identity_provenance,
            );
        println!("passport evaluated");
        println!("subject:             {}", evaluation.verification.subject);
        println!(
            "passport_id:         {}",
            evaluation.verification.passport_id
        );
        if let Some(issuer) = evaluation.verification.issuer.as_deref() {
            println!("issuer:              {issuer}");
        } else {
            println!(
                "issuers:             {}",
                evaluation.verification.issuers.join(", ")
            );
        }
        println!(
            "issuer_count:        {}",
            evaluation.verification.issuer_count
        );
        println!("accepted:            {}", evaluation.accepted);
        println!(
            "matched_credentials: {}",
            evaluation.matched_credential_indexes.len()
        );
        if !evaluation.matched_issuers.is_empty() {
            println!(
                "matched_issuers:     {}",
                evaluation.matched_issuers.join(", ")
            );
        }
        println!(
            "credential_count:    {}",
            evaluation.verification.credential_count
        );
        println!("enterprise_provenance: {}", enterprise_provenance_count);
        if !enterprise_provider_ids.is_empty() {
            println!(
                "enterprise_providers: {}",
                enterprise_provider_ids.join(", ")
            );
        }
        if let Some(lifecycle) = evaluation.verification.passport_lifecycle.as_ref() {
            println!("lifecycle_state:     {}", lifecycle.state.label());
            if let Some(source) = lifecycle.source.as_deref() {
                println!("lifecycle_source:    {source}");
            }
        }
        println!(
            "valid_until:         {}",
            evaluation.verification.valid_until
        );
        if !evaluation.passport_reasons.is_empty() {
            println!("passport_reasons:");
            for reason in &evaluation.passport_reasons {
                println!("  - {reason}");
            }
        }
        if !evaluation.accepted {
            println!("rejections:");
            for result in &evaluation.credential_results {
                if result.accepted {
                    continue;
                }
                println!("  credential {} ({}):", result.index, result.issuer);
                for reason in &result.reasons {
                    println!("    - {}", reason);
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn cmd_passport_present(
    input: &Path,
    output: &Path,
    issuers: &[String],
    max_credentials: Option<usize>,
    json_output: bool,
) -> Result<(), CliError> {
    let passport: AgentPassport = serde_json::from_slice(&fs::read(input)?)?;
    verify_agent_passport(&passport, unix_now())?;

    let presented = present_agent_passport(
        &passport,
        &PassportPresentationOptions {
            issuer_allowlist: issuers.iter().cloned().collect::<BTreeSet<_>>(),
            max_credentials,
        },
    )?;

    ensure_parent_dir(output)?;
    fs::write(output, serde_json::to_vec_pretty(&presented)?)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "output": output.display().to_string(),
                "subject": presented.subject,
                "credentialCount": presented.credentials.len(),
                "merkleRootCount": presented.merkle_roots.len(),
            }))?
        );
    } else {
        println!("wrote presented passport to {}", output.display());
        println!("subject:          {}", presented.subject);
        println!("credential_count: {}", presented.credentials.len());
        println!("merkle_roots:     {}", presented.merkle_roots.len());
    }
    Ok(())
}

pub(crate) fn cmd_passport_issuance_metadata(
    issuer_url: Option<&str>,
    signing_seed_file: Option<&Path>,
    passport_status_url: Option<&str>,
    passport_status_cache_ttl_secs: Option<u64>,
    json_output: bool,
    control_url: Option<&str>,
    _control_token: Option<&str>,
) -> Result<(), CliError> {
    let metadata = if let Some(url) = control_url {
        crate::trust_control::service_runtime::client::build_public_client(url)?
            .passport_issuer_metadata()?
    } else {
        local_passport_issuer_metadata(
            require_credential_issuer_url(issuer_url)?,
            signing_seed_file,
            passport_status_url,
            passport_status_cache_ttl_secs,
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&metadata)?);
    } else {
        println!("credential_issuer: {}", metadata.credential_issuer);
        println!("token_endpoint:    {}", metadata.token_endpoint);
        println!("credential_endpoint: {}", metadata.credential_endpoint);
        println!(
            "configurations:    {}",
            metadata
                .credential_configurations_supported
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

pub(crate) fn cmd_passport_issuance_offer_create(
    input: &Path,
    output: Option<&Path>,
    issuer_url: Option<&str>,
    passport_issuance_offers_file: Option<&Path>,
    passport_statuses_file: Option<&Path>,
    signing_seed_file: Option<&Path>,
    credential_configuration_id: Option<&str>,
    ttl_secs: u64,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let passport: AgentPassport = serde_json::from_slice(&fs::read(input)?)?;
    let record = if let Some(url) = control_url {
        let token = crate::require_control_token(control_token)?;
        crate::trust_control::service_runtime::client::build_client(url, token)?
            .create_passport_issuance_offer(
                &crate::trust_control::CreatePassportIssuanceOfferRequest {
                    passport,
                    ttl_seconds: ttl_secs,
                    credential_configuration_id: credential_configuration_id.map(str::to_string),
                },
            )?
    } else {
        let path = require_passport_issuance_registry_path(passport_issuance_offers_file)?;
        let mut registry = load_passport_issuance_registry_for_admin(path)?;
        let metadata = local_passport_issuer_metadata(
            require_credential_issuer_url(issuer_url)?,
            signing_seed_file,
            None,
            None,
        )?;
        if passport_statuses_file.is_some() {
            portable_passport_status_reference(&passport, unix_now(), passport_statuses_file)?;
        }
        let record = registry.issue_offer(
            &metadata,
            passport,
            credential_configuration_id,
            ttl_secs,
            unix_now(),
        )?;
        registry.save(path)?;
        record
    };

    if let Some(output) = output {
        ensure_parent_dir(output)?;
        fs::write(output, serde_json::to_vec_pretty(&record.offer)?)?;
    }

    if json_output {
        println!("{}", serde_json::to_string_pretty(&record)?);
    } else {
        println!("passport issuance offer created");
        println!("offer_id:          {}", record.offer_id);
        println!("credential_issuer: {}", record.offer.credential_issuer);
        println!(
            "configuration_id:  {}",
            record.offer.primary_configuration_id()?
        );
        println!("state:             {:?}", record.state);
        println!("expires_at:        {}", record.expires_at);
        if let Some(output) = output {
            println!("offer_output:      {}", output.display());
        }
    }
    Ok(())
}

pub(crate) fn cmd_passport_issuance_token_redeem(
    offer_path: &Path,
    output: Option<&Path>,
    passport_issuance_offers_file: Option<&Path>,
    json_output: bool,
    control_url: Option<&str>,
    _control_token: Option<&str>,
) -> Result<(), CliError> {
    let offer = load_oid4vci_offer(offer_path)?;
    let request = Oid4vciTokenRequest {
        grant_type: chio_credentials::OID4VCI_PRE_AUTHORIZED_GRANT_TYPE.to_string(),
        pre_authorized_code: offer.pre_authorized_code()?.to_string(),
    };
    let token = if let Some(url) = control_url {
        crate::trust_control::service_runtime::client::build_public_client(url)?
            .redeem_passport_issuance_token(&request)?
    } else {
        let metadata = default_oid4vci_passport_issuer_metadata_with_status_distribution(
            &offer.credential_issuer,
            PassportStatusDistribution::default(),
        )?;
        let path = require_passport_issuance_registry_path(passport_issuance_offers_file)?;
        let mut registry = load_passport_issuance_registry_for_admin(path)?;
        let token = registry.redeem_pre_authorized_code(&metadata, &request, unix_now(), 300)?;
        registry.save(path)?;
        token
    };

    if let Some(output) = output {
        ensure_parent_dir(output)?;
        fs::write(output, serde_json::to_vec_pretty(&token)?)?;
    }

    if json_output {
        println!("{}", serde_json::to_string_pretty(&token)?);
    } else {
        println!("passport issuance token redeemed");
        println!("token_type: {}", token.token_type);
        println!("expires_in: {}", token.expires_in);
        if let Some(output) = output {
            println!("token_output: {}", output.display());
        }
    }
    Ok(())
}

pub(crate) fn cmd_passport_issuance_credential_redeem(
    offer_path: &Path,
    token_path: &Path,
    output: Option<&Path>,
    passport_issuance_offers_file: Option<&Path>,
    passport_statuses_file: Option<&Path>,
    signing_seed_file: Option<&Path>,
    credential_configuration_id: Option<&str>,
    format: Option<&str>,
    json_output: bool,
    control_url: Option<&str>,
    _control_token: Option<&str>,
) -> Result<(), CliError> {
    let offer = load_oid4vci_offer(offer_path)?;
    let token = load_oid4vci_token(token_path)?;
    let metadata = if let Some(url) = control_url {
        crate::trust_control::service_runtime::client::build_public_client(url)?
            .passport_issuer_metadata()?
    } else {
        local_passport_issuer_metadata(&offer.credential_issuer, signing_seed_file, None, None)?
    };
    let resolved_credential_configuration_id = credential_configuration_id
        .map(str::to_string)
        .or_else(|| offer.primary_configuration_id().ok().map(str::to_string));
    let resolved_format = format.map(str::to_string).or_else(|| {
        resolved_credential_configuration_id
            .as_deref()
            .and_then(|configuration_id| {
                metadata
                    .credential_configuration(configuration_id)
                    .ok()
                    .map(|configuration| configuration.format.clone())
            })
    });
    let request = Oid4vciCredentialRequest {
        credential_configuration_id: resolved_credential_configuration_id,
        format: resolved_format,
        subject: offer
            .chio_offer_context
            .as_ref()
            .map(|context| context.subject.clone())
            .unwrap_or_default(),
    };
    let response = if let Some(url) = control_url {
        crate::trust_control::service_runtime::client::build_public_client(url)?
            .redeem_passport_issuance_credential(&token.access_token, &request)?
    } else {
        let path = require_passport_issuance_registry_path(passport_issuance_offers_file)?;
        let mut registry = load_passport_issuance_registry_for_admin(path)?;
        let portable_signing_keypair = signing_seed_file
            .map(load_or_create_authority_keypair)
            .transpose()?;
        let portable_status_registry = passport_statuses_file
            .map(load_passport_status_registry_for_admin)
            .transpose()?;
        let response = registry.redeem_credential(
            &metadata,
            &token.access_token,
            &request,
            unix_now(),
            portable_signing_keypair.as_ref(),
            portable_status_registry.as_ref(),
        )?;
        registry.save(path)?;
        response
    };

    if let Some(output) = output {
        ensure_parent_dir(output)?;
        fs::write(output, response.credential.write_output_bytes()?)?;
    }

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!("passport credential redeemed");
        if let Some(subject) = response.subject_hint() {
            println!("subject: {}", subject);
        }
        println!("format:  {}", response.format);
        if let Some(passport_id) = response.passport_id_hint() {
            println!("passport_id: {}", passport_id);
        }
        if let Some(output) = output {
            println!("credential_output: {}", output.display());
        }
    }
    Ok(())
}

#[path = "passport/verifier.rs"]
pub(crate) mod verifier;

fn load_passport_verifier_policy(path: &Path) -> Result<PassportVerifierPolicy, CliError> {
    let contents = fs::read_to_string(path)?;
    let policy = if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "yaml" | "yml"))
    {
        serde_yml::from_str(&contents)?
    } else if let Ok(document) = serde_json::from_str::<SignedPassportVerifierPolicy>(&contents) {
        verify_signed_passport_verifier_policy(&document)
            .map_err(|error| CliError::policy_error(error.to_string()))?;
        document.body.policy
    } else {
        serde_json::from_str(&contents).or_else(|_| serde_yml::from_str(&contents))?
    };
    Ok(policy)
}

fn resolve_challenge_policy_local(
    challenge: &PassportPresentationChallenge,
    verifier_policies_file: Option<&Path>,
    now: u64,
) -> Result<(Option<PassportVerifierPolicy>, Option<String>), CliError> {
    if let Some(policy) = challenge.policy.as_ref() {
        return Ok((Some(policy.clone()), Some("embedded".to_string())));
    }
    let Some(reference) = challenge.policy_ref.as_ref() else {
        return Ok((None, None));
    };
    let path = require_verifier_policy_registry_path(verifier_policies_file)?;
    let registry = load_verifier_policy_registry_for_admin(path)?;
    let document = registry.active_policy(&reference.policy_id, now)?;
    if document.body.verifier != challenge.verifier {
        return Err(CliError::policy_error(format!(
            "verifier policy `{}` is bound to verifier `{}` but challenge expects `{}`",
            document.body.policy_id, document.body.verifier, challenge.verifier
        )));
    }
    Ok((
        Some(document.body.policy.clone()),
        Some(format!("registry:{}", document.body.policy_id)),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod passport_error_classification_tests {
    use super::*;

    const CLI_CREDENTIAL_CODE: &str = "CHIO-CLI-CREDENTIAL";
    const CLI_OTHER_CODE: &str = "urn:chio:error:cli:other";

    fn assert_credential(error: &CliError) {
        assert_eq!(error.report().code, CLI_CREDENTIAL_CODE);
    }

    fn assert_cli_other(error: &CliError) {
        match error {
            CliError::Chio(chio) => {
                assert_eq!(chio.code().as_str(), CLI_OTHER_CODE);
                assert_eq!(chio.domain().as_str(), "cli");
            }
            other => panic!("expected registry-backed CliError::Chio, got: {other:?}"),
        }
    }

    #[test]
    fn credential_and_did_errors_keep_credential_domain() {
        let credential: CliError =
            CredentialError::InvalidOid4vciCredentialResponse("bad credential".to_string()).into();
        assert_credential(&credential);

        let did: CliError = CredentialError::Did(chio_did::DidError::InvalidPrefix).into();
        assert_credential(&did);
    }

    #[test]
    fn local_passport_registry_prerequisites_are_cli_errors() {
        let verifier = require_verifier_policy_registry_path(None).unwrap_err();
        assert_cli_other(&verifier);

        let statuses = require_passport_status_registry_path(None).unwrap_err();
        assert_cli_other(&statuses);

        let issuance = require_passport_issuance_registry_path(None).unwrap_err();
        assert_cli_other(&issuance);

        let issuer_url = require_credential_issuer_url(None).unwrap_err();
        assert_cli_other(&issuer_url);
    }

    #[test]
    fn challenge_policy_path_and_id_conflict_is_cli_error() {
        let issuers: Vec<String> = Vec::new();
        let err = verifier::cmd_passport_challenge_create(PassportChallengeCreateArgs {
            output: Path::new("unused.challenge.json"),
            verifier: "did:chio:verifier",
            ttl_secs: 60,
            issuers: &issuers,
            max_credentials: None,
            policy_path: Some(Path::new("policy.json")),
            policy_id: Some("policy-1"),
            verifier_policies_file: None,
            verifier_challenge_db: None,
            json_output: false,
            control_url: None,
            control_token: None,
        })
        .unwrap_err();

        assert_cli_other(&err);
    }
}
