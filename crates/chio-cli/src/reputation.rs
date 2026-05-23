use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::PublicKey;
use chio_credentials::{
    evaluate_agent_passport, verify_agent_passport, verify_signed_passport_verifier_policy,
    AgentPassport, PassportPolicyEvaluation, PassportVerification, PassportVerifierPolicy,
    ReputationCredential, SignedPassportVerifierPolicy,
};
use chio_did::DidChio;
use chio_kernel::{
    BehavioralFeedReputationSummary, CapabilitySnapshot, SharedEvidenceQuery,
    SharedEvidenceReferenceReport,
};
use chio_reputation::{
    build_imported_reputation_signal, CapabilityLineageRecord, CapabilityLineageScopeJsonInput,
    ImportedReputationProvenance, ImportedTrustPolicy, LocalReputationCorpus, MetricValue,
};
use chio_store_sqlite::SqliteReceiptStore;
use serde::{Deserialize, Serialize};

use crate::issuance::{self, LocalReputationInspection, ReputationScoringSource};
use crate::{load_or_create_authority_keypair, policy::load_policy, trust_control, CliError};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Load the local authority public key from a seed file and return it as the
/// single-element trusted-kernel-key set, or an empty vec when no seed file is
/// configured. Plumbing this into reputation scoring keeps locally signed
/// receipts from being silently filtered out as unsigned. See
/// `chio_reputation::receipt_integrity_valid`.
fn load_trusted_kernel_keys_from_authority(
    authority_seed_file: Option<&Path>,
) -> Result<Vec<String>, CliError> {
    let Some(path) = authority_seed_file else {
        return Ok(Vec::new());
    };
    let keypair = load_or_create_authority_keypair(path)?;
    Ok(vec![keypair.public_key().to_hex()])
}

pub struct ReputationLocalCommand<'a> {
    pub subject_public_key: &'a str,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub policy_path: Option<&'a Path>,
    pub json_output: bool,
    pub receipt_db_path: Option<&'a Path>,
    pub budget_db_path: Option<&'a Path>,
    pub control_url: Option<&'a str>,
    pub control_token: Option<&'a str>,
    /// Optional authority seed file used to derive the trusted kernel
    /// public key. When provided, the loaded keypair's public key is added
    /// to the scoring config's `trusted_kernel_keys` so receipts signed by
    /// this kernel pass integrity validation. Without it, an empty trust
    /// set silently filters every receipt as unsigned and scores collapse
    /// to zero / unknown.
    pub authority_seed_file: Option<&'a Path>,
}

pub fn cmd_reputation_local(command: ReputationLocalCommand<'_>) -> Result<(), CliError> {
    let ReputationLocalCommand {
        subject_public_key,
        since,
        until,
        policy_path,
        json_output,
        receipt_db_path,
        budget_db_path,
        control_url,
        control_token,
        authority_seed_file,
    } = command;

    let mut inspection = if let Some(url) = control_url {
        if policy_path.is_some() {
            return Err(CliError::cli_other_error(
                "reputation queries against --control-url use the trust service's configured policy; omit --policy"
                    .to_string(),
            ));
        }
        let token = super::require_control_token(control_token)?;
        trust_control::build_client(url, token)?.local_reputation(
            subject_public_key,
            &trust_control::LocalReputationQuery { since, until },
        )?
    } else {
        let receipt_db_path = require_receipt_db_path(receipt_db_path)?;
        let issuance_policy = policy_path
            .map(load_policy)
            .transpose()?
            .and_then(|loaded| loaded.issuance_policy);
        let trusted_kernel_keys = load_trusted_kernel_keys_from_authority(authority_seed_file)?;
        issuance::inspect_local_reputation(
            subject_public_key,
            Some(receipt_db_path),
            budget_db_path,
            since,
            until,
            issuance_policy.as_ref(),
            &trusted_kernel_keys,
        )?
    };

    if control_url.is_none() {
        let receipt_db_path = require_receipt_db_path(receipt_db_path)?;
        inspection.imported_trust = Some(build_imported_trust_report(
            receipt_db_path,
            &inspection.subject_key,
            inspection.since,
            inspection.until,
            unix_now(),
            &inspection.scoring,
        )?);
    }

    if json_output {
        println!("{}", serde_json::to_string_pretty(&inspection)?);
    } else {
        print_local_reputation(&inspection);
    }

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReputationMetricComparison {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portable: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_minus_portable: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReputationMetricDriftSet {
    pub composite_score: ReputationMetricComparison,
    pub boundary_pressure: ReputationMetricComparison,
    pub resource_stewardship: ReputationMetricComparison,
    pub least_privilege: ReputationMetricComparison,
    pub history_depth: ReputationMetricComparison,
    pub specialization: ReputationMetricComparison,
    pub delegation_hygiene: ReputationMetricComparison,
    pub reliability: ReputationMetricComparison,
    pub incident_correlation: ReputationMetricComparison,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PortableCredentialDrift {
    pub index: usize,
    pub issuer: String,
    pub issuance_date: String,
    pub expiration_date: String,
    pub attestation_until: u64,
    pub receipt_count: usize,
    pub lineage_records: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_accepted: Option<bool>,
    pub metrics: ReputationMetricDriftSet,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PortableReputationComparison {
    pub subject_key: String,
    pub passport_subject: String,
    pub subject_matches: bool,
    pub compared_at: u64,
    pub local: LocalReputationInspection,
    pub passport_verification: PassportVerification,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passport_evaluation: Option<PassportPolicyEvaluation>,
    pub credential_drifts: Vec<PortableCredentialDrift>,
    pub shared_evidence: SharedEvidenceReferenceReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported_trust: Option<issuance::ImportedTrustReport>,
}

pub struct ReputationCompareCommand<'a> {
    pub subject_public_key: &'a str,
    pub passport_path: &'a Path,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub local_policy_path: Option<&'a Path>,
    pub verifier_policy_path: Option<&'a Path>,
    pub json_output: bool,
    pub receipt_db_path: Option<&'a Path>,
    pub budget_db_path: Option<&'a Path>,
    pub control_url: Option<&'a str>,
    pub control_token: Option<&'a str>,
    /// Optional authority seed file used to derive the trusted kernel
    /// public key. See `ReputationLocalCommand::authority_seed_file`.
    pub authority_seed_file: Option<&'a Path>,
}

pub fn cmd_reputation_compare(command: ReputationCompareCommand<'_>) -> Result<(), CliError> {
    let ReputationCompareCommand {
        subject_public_key,
        passport_path,
        since,
        until,
        local_policy_path,
        verifier_policy_path,
        json_output,
        receipt_db_path,
        budget_db_path,
        control_url,
        control_token,
        authority_seed_file,
    } = command;

    let passport: AgentPassport = serde_json::from_slice(&fs::read(passport_path)?)?;
    let verifier_policy = verifier_policy_path
        .map(load_passport_verifier_policy)
        .transpose()?;
    let comparison = if let Some(url) = control_url {
        if local_policy_path.is_some() {
            return Err(CliError::cli_other_error(
                "reputation compare against --control-url uses the trust service's configured local scoring; omit --local-policy"
                    .to_string(),
            ));
        }
        let token = super::require_control_token(control_token)?;
        trust_control::build_client(url, token)?.reputation_compare(
            subject_public_key,
            &trust_control::ReputationCompareRequest {
                passport: passport.clone(),
                verifier_policy: verifier_policy.clone(),
                since,
                until,
            },
        )?
    } else {
        let local = {
            let receipt_db_path = require_receipt_db_path(receipt_db_path)?;
            let issuance_policy = local_policy_path
                .map(load_policy)
                .transpose()?
                .and_then(|loaded| loaded.issuance_policy);
            let trusted_kernel_keys = load_trusted_kernel_keys_from_authority(authority_seed_file)?;
            issuance::inspect_local_reputation(
                subject_public_key,
                Some(receipt_db_path),
                budget_db_path,
                since,
                until,
                issuance_policy.as_ref(),
                &trusted_kernel_keys,
            )?
        };
        let imported_trust = {
            let receipt_db_path = require_receipt_db_path(receipt_db_path)?;
            build_imported_trust_report(
                receipt_db_path,
                &local.subject_key,
                local.since,
                local.until,
                unix_now(),
                &local.scoring,
            )?
        };
        let shared_evidence = {
            let receipt_db_path = require_receipt_db_path(receipt_db_path)?;
            let store = SqliteReceiptStore::open(receipt_db_path)?;
            store.query_shared_evidence_report(&SharedEvidenceQuery {
                agent_subject: Some(local.subject_key.clone()),
                since: local.since,
                until: local.until,
                read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
                ..SharedEvidenceQuery::default()
            })?
        };
        build_reputation_comparison(
            local,
            &passport,
            verifier_policy.as_ref(),
            unix_now(),
            shared_evidence,
            Some(imported_trust),
        )?
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&comparison)?);
    } else {
        print_reputation_comparison(&comparison);
    }

    Ok(())
}

fn require_receipt_db_path(receipt_db_path: Option<&Path>) -> Result<&Path, CliError> {
    receipt_db_path.ok_or_else(|| {
        CliError::cli_other_error(
            "reputation commands require --receipt-db <path> when not using --control-url"
                .to_string(),
        )
    })
}

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
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        document.body.policy
    } else {
        serde_json::from_str(&contents).or_else(|_| serde_yml::from_str(&contents))?
    };
    Ok(policy)
}

pub(crate) fn build_reputation_comparison(
    local: LocalReputationInspection,
    passport: &AgentPassport,
    verifier_policy: Option<&PassportVerifierPolicy>,
    now: u64,
    shared_evidence: SharedEvidenceReferenceReport,
    imported_trust: Option<issuance::ImportedTrustReport>,
) -> Result<PortableReputationComparison, CliError> {
    let passport_verification = verify_agent_passport(passport, now)?;
    let passport_evaluation = verifier_policy
        .map(|policy| evaluate_agent_passport(passport, now, policy))
        .transpose()?;
    let local_did = DidChio::from_public_key(PublicKey::from_hex(&local.subject_key)?)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?
        .to_string();
    let subject_matches = local_did == passport.subject;
    let credential_drifts = passport
        .credentials
        .iter()
        .enumerate()
        .map(|(index, credential)| {
            build_credential_drift(index, credential, &passport_evaluation, &local)
        })
        .collect();

    Ok(PortableReputationComparison {
        subject_key: local.subject_key.clone(),
        passport_subject: passport.subject.clone(),
        subject_matches,
        compared_at: now,
        local,
        passport_verification,
        credential_drifts,
        passport_evaluation,
        shared_evidence,
        imported_trust,
    })
}

pub(crate) fn build_imported_trust_report(
    receipt_db_path: &Path,
    subject_key: &str,
    since: Option<u64>,
    until: Option<u64>,
    now: u64,
    scoring: &chio_reputation::ReputationConfig,
) -> Result<issuance::ImportedTrustReport, CliError> {
    let policy = ImportedTrustPolicy::default();
    let store = SqliteReceiptStore::open(receipt_db_path)?;
    let signals = store
        .list_federated_share_subject_corpora(subject_key, since, until)?
        .into_iter()
        .map(|(share, receipts, capabilities)| {
            let provenance = ImportedReputationProvenance {
                share_id: share.share_id,
                issuer: share.issuer,
                partner: share.partner,
                signer_public_key: share.signer_public_key,
                imported_at: share.imported_at,
                exported_at: share.exported_at,
                require_proofs: share.require_proofs,
                tool_receipts: share.tool_receipts,
                capability_lineage: share.capability_lineage,
            };
            let corpus = LocalReputationCorpus {
                receipts: receipts.into_iter().map(|record| record.receipt).collect(),
                capabilities: capabilities
                    .into_iter()
                    .map(capability_snapshot_to_lineage)
                    .collect::<Result<Vec<_>, _>>()?,
                budget_usage: Vec::new(),
                incident_reports: None,
            };
            Ok(build_imported_reputation_signal(
                subject_key,
                provenance,
                &corpus,
                now,
                scoring,
                &policy,
            ))
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    let accepted_count = signals.iter().filter(|signal| signal.accepted).count();
    Ok(issuance::ImportedTrustReport {
        policy,
        signal_count: signals.len(),
        accepted_count,
        signals,
    })
}

pub(crate) fn build_behavioral_feed_reputation_summary(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    subject_key: &str,
    since: Option<u64>,
    until: Option<u64>,
    now: u64,
    trusted_kernel_keys: &[String],
) -> Result<BehavioralFeedReputationSummary, CliError> {
    let inspection = issuance::inspect_local_reputation(
        subject_key,
        Some(receipt_db_path),
        budget_db_path,
        since,
        until,
        None,
        trusted_kernel_keys,
    )?;
    let imported_trust = build_imported_trust_report(
        receipt_db_path,
        &inspection.subject_key,
        inspection.since,
        inspection.until,
        now,
        &inspection.scoring,
    )?;

    Ok(BehavioralFeedReputationSummary {
        subject_key: inspection.subject_key,
        effective_score: inspection.effective_score,
        probationary: inspection.probationary,
        resolved_tier: inspection.resolved_tier.map(|tier| tier.name),
        imported_signal_count: imported_trust.signal_count,
        accepted_imported_signal_count: imported_trust.accepted_count,
    })
}

fn capability_snapshot_to_lineage(
    snapshot: CapabilitySnapshot,
) -> Result<CapabilityLineageRecord, CliError> {
    CapabilityLineageRecord::from_scope_json(CapabilityLineageScopeJsonInput {
        capability_id: snapshot.capability_id,
        subject_key: snapshot.subject_key,
        issuer_key: snapshot.issuer_key,
        issued_at: snapshot.issued_at,
        expires_at: snapshot.expires_at,
        scope_json: &snapshot.grants_json,
        delegation_depth: snapshot.delegation_depth,
        parent_capability_id: snapshot.parent_capability_id,
    })
    .map_err(|error| CliError::cli_other_error(error.to_string()))
}

fn build_credential_drift(
    index: usize,
    credential: &ReputationCredential,
    passport_evaluation: &Option<PassportPolicyEvaluation>,
    local: &LocalReputationInspection,
) -> PortableCredentialDrift {
    let portable = &credential.unsigned.credential_subject.metrics;
    let evaluation = passport_evaluation.as_ref().and_then(|evaluation| {
        evaluation
            .credential_results
            .iter()
            .find(|result| result.index == index)
    });
    PortableCredentialDrift {
        index,
        issuer: credential.unsigned.issuer.clone(),
        issuance_date: credential.unsigned.issuance_date.clone(),
        expiration_date: credential.unsigned.expiration_date.clone(),
        attestation_until: credential.unsigned.evidence.query.until,
        receipt_count: credential.unsigned.evidence.receipt_count,
        lineage_records: credential.unsigned.evidence.lineage_records,
        policy_accepted: evaluation.map(|result| result.accepted),
        metrics: ReputationMetricDriftSet {
            composite_score: compare_metric_values(
                portable.composite_score,
                local.scorecard.composite_score,
            ),
            boundary_pressure: compare_metric_values(
                portable.boundary_pressure.deny_ratio,
                local.scorecard.boundary_pressure.deny_ratio,
            ),
            resource_stewardship: compare_metric_values(
                portable.resource_stewardship.fit_score,
                local.scorecard.resource_stewardship.fit_score,
            ),
            least_privilege: compare_metric_values(
                portable.least_privilege.score,
                local.scorecard.least_privilege.score,
            ),
            history_depth: compare_metric_values(
                portable.history_depth.score,
                local.scorecard.history_depth.score,
            ),
            specialization: compare_metric_values(
                portable.specialization.score,
                local.scorecard.specialization.score,
            ),
            delegation_hygiene: compare_metric_values(
                portable.delegation_hygiene.score,
                local.scorecard.delegation_hygiene.score,
            ),
            reliability: compare_metric_values(
                portable.reliability.score,
                local.scorecard.reliability.score,
            ),
            incident_correlation: compare_metric_values(
                portable.incident_correlation.score,
                local.scorecard.incident_correlation.score,
            ),
        },
    }
}

fn compare_metric_values(portable: MetricValue, local: MetricValue) -> ReputationMetricComparison {
    let portable = portable.as_option();
    let local = local.as_option();
    ReputationMetricComparison {
        portable,
        local,
        local_minus_portable: match (portable, local) {
            (Some(portable), Some(local)) => Some(local - portable),
            _ => None,
        },
    }
}

fn print_local_reputation(inspection: &LocalReputationInspection) {
    println!("subject_key:             {}", inspection.subject_key);
    println!("window:                  {}", describe_window(inspection));
    println!(
        "scoring_source:          {}",
        match inspection.scoring_source {
            ReputationScoringSource::Default => "default",
            ReputationScoringSource::IssuancePolicy => "issuance_policy",
        }
    );
    println!(
        "composite_score:         {}",
        format_metric(inspection.scorecard.composite_score)
    );
    println!("effective_score:         {:.3}", inspection.effective_score);
    println!("probationary:            {}", inspection.probationary);
    println!(
        "probationary_receipts:   {} / {}",
        inspection.scorecard.history_depth.receipt_count, inspection.probationary_receipt_count
    );
    println!(
        "probationary_span_days:  {} / {}",
        inspection.scorecard.history_depth.span_days, inspection.probationary_min_days
    );
    if let Some(limit) = inspection.probationary_score_ceiling {
        println!("probationary_ceiling:    {:.3}", limit);
    }
    println!(
        "resolved_tier:           {}",
        inspection
            .resolved_tier
            .as_ref()
            .map(|tier| tier.name.as_str())
            .unwrap_or("n/a")
    );
    println!(
        "boundary_pressure:       {}",
        format_metric(inspection.boundary_pressure_score())
    );
    println!(
        "resource_stewardship:    {}",
        format_metric(inspection.resource_stewardship_score())
    );
    println!(
        "least_privilege:         {}",
        format_metric(inspection.least_privilege_score())
    );
    println!(
        "history_depth:           {}",
        format_metric(inspection.history_depth_score())
    );
    println!(
        "specialization:          {}",
        format_metric(inspection.specialization_score())
    );
    println!(
        "delegation_hygiene:      {}",
        format_metric(inspection.delegation_hygiene_score())
    );
    println!(
        "reliability:             {}",
        format_metric(inspection.reliability_score())
    );
    println!(
        "incident_correlation:    {}",
        format_metric(inspection.incident_correlation_score())
    );
    if let Some(imported_trust) = inspection.imported_trust.as_ref() {
        println!("imported_signals:        {}", imported_trust.signal_count);
        println!("imported_accepted:       {}", imported_trust.accepted_count);
    }
}

fn print_reputation_comparison(comparison: &PortableReputationComparison) {
    println!("subject_key:             {}", comparison.subject_key);
    println!("passport_subject:        {}", comparison.passport_subject);
    println!("subject_matches:         {}", comparison.subject_matches);
    println!(
        "local_effective_score:   {:.3}",
        comparison.local.effective_score
    );
    println!(
        "portable_issuers:        {}",
        comparison.passport_verification.issuers.join(", ")
    );
    println!(
        "portable_issuer_count:   {}",
        comparison.passport_verification.issuer_count
    );
    println!(
        "portable_credentials:    {}",
        comparison.passport_verification.credential_count
    );
    println!(
        "portable_valid_until:    {}",
        comparison.passport_verification.valid_until
    );
    if let Some(evaluation) = &comparison.passport_evaluation {
        println!("verifier_policy_accepts: {}", evaluation.accepted);
        println!(
            "matched_credentials:     {}",
            evaluation.matched_credential_indexes.len()
        );
    }
    println!(
        "shared_evidence_shares:  {}",
        comparison.shared_evidence.summary.matching_shares
    );
    println!(
        "shared_evidence_refs:    {}",
        comparison.shared_evidence.summary.matching_references
    );
    println!(
        "shared_evidence_receipts:{}",
        comparison.shared_evidence.summary.matching_local_receipts
    );
    if let Some(imported_trust) = comparison.imported_trust.as_ref() {
        println!("imported_signals:        {}", imported_trust.signal_count);
        println!("imported_accepted:       {}", imported_trust.accepted_count);
    }
    for drift in &comparison.credential_drifts {
        println!("credential {}:", drift.index);
        println!("  issuer:                {}", drift.issuer);
        println!(
            "  policy_accepted:       {}",
            drift
                .policy_accepted
                .map(|accepted| accepted.to_string())
                .unwrap_or_else(|| "n/a".to_string())
        );
        println!(
            "  composite_score:       {}",
            format_comparison(&drift.metrics.composite_score)
        );
        println!(
            "  reliability:           {}",
            format_comparison(&drift.metrics.reliability)
        );
        println!(
            "  least_privilege:       {}",
            format_comparison(&drift.metrics.least_privilege)
        );
        println!(
            "  delegation_hygiene:    {}",
            format_comparison(&drift.metrics.delegation_hygiene)
        );
        println!(
            "  boundary_pressure:     {}",
            format_comparison(&drift.metrics.boundary_pressure)
        );
    }
    for reference in &comparison.shared_evidence.references {
        println!("shared_reference {}:", reference.share.share_id);
        println!("  partner:               {}", reference.share.partner);
        println!("  remote_capability:     {}", reference.capability_id);
        println!(
            "  local_anchor:          {}",
            reference
                .local_anchor_capability_id
                .as_deref()
                .unwrap_or("n/a")
        );
        println!(
            "  matched_receipts:      {}",
            reference.matched_local_receipts
        );
    }
}

fn describe_window(inspection: &LocalReputationInspection) -> String {
    match (inspection.since, inspection.until) {
        (Some(since), Some(until)) => format!("{since}..{until}"),
        (Some(since), None) => format!("{since}..now"),
        (None, Some(until)) => format!("origin..{until}"),
        (None, None) => "full_history".to_string(),
    }
}

fn format_metric(value: MetricValue) -> String {
    match value {
        MetricValue::Known(value) => format!("{value:.3}"),
        MetricValue::Unknown => "unknown".to_string(),
    }
}

fn format_comparison(value: &ReputationMetricComparison) -> String {
    let portable = value
        .portable
        .map(|value| format!("{value:.3}"))
        .unwrap_or_else(|| "unknown".to_string());
    let local = value
        .local
        .map(|value| format!("{value:.3}"))
        .unwrap_or_else(|| "unknown".to_string());
    let delta = value
        .local_minus_portable
        .map(|value| format!("{value:+.3}"))
        .unwrap_or_else(|| "n/a".to_string());
    format!("portable={portable}, local={local}, local_minus_portable={delta}")
}

trait InspectionMetricExt {
    fn boundary_pressure_score(&self) -> MetricValue;
    fn resource_stewardship_score(&self) -> MetricValue;
    fn least_privilege_score(&self) -> MetricValue;
    fn history_depth_score(&self) -> MetricValue;
    fn specialization_score(&self) -> MetricValue;
    fn delegation_hygiene_score(&self) -> MetricValue;
    fn reliability_score(&self) -> MetricValue;
    fn incident_correlation_score(&self) -> MetricValue;
}

impl InspectionMetricExt for LocalReputationInspection {
    fn boundary_pressure_score(&self) -> MetricValue {
        self.scorecard.boundary_pressure.deny_ratio
    }

    fn resource_stewardship_score(&self) -> MetricValue {
        self.scorecard.resource_stewardship.fit_score
    }

    fn least_privilege_score(&self) -> MetricValue {
        self.scorecard.least_privilege.score
    }

    fn history_depth_score(&self) -> MetricValue {
        self.scorecard.history_depth.score
    }

    fn specialization_score(&self) -> MetricValue {
        self.scorecard.specialization.score
    }

    fn delegation_hygiene_score(&self) -> MetricValue {
        self.scorecard.delegation_hygiene.score
    }

    fn reliability_score(&self) -> MetricValue {
        self.scorecard.reliability.score
    }

    fn incident_correlation_score(&self) -> MetricValue {
        self.scorecard.incident_correlation.score
    }
}
