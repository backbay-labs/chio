use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_appraisal::{verify_runtime_attestation_record, VerifiedRuntimeAttestationRecord};
use chio_core::capability::{
    ChioScope, Constraint, Operation, PromptGrant, ResourceGrant, RuntimeAssuranceTier,
    RuntimeAttestationEvidence, ToolGrant,
};
use chio_core::crypto::PublicKey;
use chio_kernel::{BudgetStore, CapabilityAuthority, KernelError};
use chio_reputation::{
    compute_local_scorecard, BudgetUsageRecord as ReputationBudgetUsageRecord,
    CapabilityLineageRecord, CapabilityLineageScopeJsonInput, ImportedReputationSignal,
    ImportedTrustPolicy, LocalReputationCorpus, LocalReputationScorecard, ReputationConfig,
};
use chio_store_sqlite::{SqliteBudgetStore, SqliteReceiptStore};
use serde::{Deserialize, Serialize};

use crate::policy::{
    ReputationIssuancePolicy, ReputationTierPolicy, RuntimeAssuranceIssuancePolicy,
    RuntimeAssuranceTierPolicy, TierScopeCeiling,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReputationScoringSource {
    Default,
    IssuancePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProbationaryStatus {
    pub below_receipt_target: bool,
    pub below_day_target: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LocalReputationTierView {
    pub name: String,
    pub score_range: [f64; 2],
    pub max_scope: TierScopeCeiling,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LocalReputationInspection {
    pub subject_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    pub scoring_source: ReputationScoringSource,
    pub scoring: ReputationConfig,
    pub probationary_receipt_count: u64,
    pub probationary_min_days: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probationary_score_ceiling: Option<f64>,
    pub probationary: bool,
    pub probationary_status: ProbationaryStatus,
    pub effective_score: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_tier: Option<LocalReputationTierView>,
    pub scorecard: LocalReputationScorecard,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported_trust: Option<ImportedTrustReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ImportedTrustReport {
    pub policy: ImportedTrustPolicy,
    pub signal_count: usize,
    pub accepted_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<ImportedReputationSignal>,
}

pub fn wrap_capability_authority(
    inner: Box<dyn CapabilityAuthority>,
    issuance_policy: Option<ReputationIssuancePolicy>,
    runtime_assurance_policy: Option<RuntimeAssuranceIssuancePolicy>,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
) -> Box<dyn CapabilityAuthority> {
    Box::new(PolicyBackedCapabilityAuthority {
        inner,
        issuance_policy,
        runtime_assurance_policy,
        receipt_db_path: receipt_db_path.map(Path::to_path_buf),
        budget_db_path: budget_db_path.map(Path::to_path_buf),
    })
}

struct PolicyBackedCapabilityAuthority {
    inner: Box<dyn CapabilityAuthority>,
    issuance_policy: Option<ReputationIssuancePolicy>,
    runtime_assurance_policy: Option<RuntimeAssuranceIssuancePolicy>,
    receipt_db_path: Option<PathBuf>,
    budget_db_path: Option<PathBuf>,
}

impl CapabilityAuthority for PolicyBackedCapabilityAuthority {
    fn authority_public_key(&self) -> PublicKey {
        self.inner.authority_public_key()
    }

    fn trusted_public_keys(&self) -> Vec<PublicKey> {
        self.inner.trusted_public_keys()
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<chio_core::capability::CapabilityToken, KernelError> {
        self.issue_capability_with_attestation(subject, scope, ttl_seconds, None)
    }

    fn issue_capability_with_attestation(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        runtime_attestation: Option<RuntimeAttestationEvidence>,
    ) -> Result<chio_core::capability::CapabilityToken, KernelError> {
        let mut scope = scope;
        let now = unix_now();
        let verified_runtime_attestation = verify_runtime_attestation_for_issuance(
            runtime_attestation.as_ref(),
            self.runtime_assurance_policy.as_ref(),
            now,
        )?;

        if let Some(policy) = &self.issuance_policy {
            enforce_reputation_policy(
                subject,
                &scope,
                ttl_seconds,
                policy,
                self.receipt_db_path.as_deref(),
                self.budget_db_path.as_deref(),
            )?;
        }

        if let Some(policy) = &self.runtime_assurance_policy {
            scope = enforce_runtime_assurance_policy(
                &scope,
                ttl_seconds,
                policy,
                verified_runtime_attestation.as_ref(),
            )?;
        }

        let capability = self.inner.issue_capability(subject, scope, ttl_seconds)?;

        if let Some(path) = self.receipt_db_path.as_deref() {
            let store = SqliteReceiptStore::open(path)
                .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
            store
                .record_capability_snapshot(&capability, None)
                .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
        }

        Ok(capability)
    }
}

fn validate_runtime_attestation_binding(
    runtime_attestation: Option<&RuntimeAttestationEvidence>,
) -> Result<(), KernelError> {
    if let Some(attestation) = runtime_attestation {
        attestation
            .validate_workload_identity_binding()
            .map_err(|error| {
                KernelError::CapabilityIssuanceDenied(format!(
                    "runtime attestation workload identity is invalid: {error}"
                ))
            })?;
    }
    Ok(())
}

fn verify_runtime_attestation_for_issuance(
    runtime_attestation: Option<&RuntimeAttestationEvidence>,
    policy: Option<&RuntimeAssuranceIssuancePolicy>,
    now: u64,
) -> Result<Option<VerifiedRuntimeAttestationRecord>, KernelError> {
    let Some(runtime_attestation) = runtime_attestation else {
        return Ok(None);
    };
    let Some(policy) = policy else {
        validate_runtime_attestation_binding(Some(runtime_attestation))?;
        return verify_runtime_attestation_record(runtime_attestation, None, now)
            .map(Some)
            .map_err(|error| {
                KernelError::CapabilityIssuanceDenied(format!(
                    "runtime attestation evidence rejected by local verification boundary: {error}"
                ))
            });
    };

    verify_runtime_attestation_record(
        runtime_attestation,
        policy.attestation_trust_policy.as_ref(),
        now,
    )
    .map(Some)
    .map_err(|error| {
        KernelError::CapabilityIssuanceDenied(format!(
            "runtime attestation evidence rejected by local verification boundary: {error}"
        ))
    })
}

fn enforce_reputation_policy(
    subject: &PublicKey,
    scope: &ChioScope,
    ttl_seconds: u64,
    policy: &ReputationIssuancePolicy,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
) -> Result<(), KernelError> {
    let subject_key = subject.to_hex();
    let inspection = inspect_local_reputation(
        &subject_key,
        receipt_db_path,
        budget_db_path,
        None,
        None,
        Some(policy),
    )?;
    let tier = inspection.resolved_tier.ok_or_else(|| {
        KernelError::CapabilityIssuanceFailed(
            "reputation issuance policy did not resolve a matching tier".to_string(),
        )
    })?;

    let tier_policy = ReputationTierPolicy {
        name: tier.name,
        score_range: tier.score_range,
        max_scope: tier.max_scope,
    };
    enforce_tier_scope(scope, ttl_seconds, &tier_policy)
}

pub(crate) fn inspect_local_reputation(
    subject_key: &str,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    since: Option<u64>,
    until: Option<u64>,
    issuance_policy: Option<&ReputationIssuancePolicy>,
) -> Result<LocalReputationInspection, KernelError> {
    let corpus =
        build_local_reputation_corpus(subject_key, receipt_db_path, budget_db_path, since, until)?;
    let (scoring_source, scoring, probationary_receipt_count, probationary_min_days, ceiling) =
        scoring_context(issuance_policy);
    let now = unix_now();
    let scorecard = compute_local_scorecard(subject_key, now, &corpus, &scoring);
    let probationary_status = ProbationaryStatus {
        below_receipt_target: scorecard.history_depth.receipt_count
            < probationary_receipt_count as usize,
        below_day_target: scorecard.history_depth.span_days < probationary_min_days,
    };
    let probationary =
        probationary_status.below_receipt_target || probationary_status.below_day_target;
    let effective_score = scorecard.composite_score.as_option().unwrap_or(0.0);
    let effective_score = ceiling
        .filter(|_| probationary)
        .map_or(effective_score, |limit| effective_score.min(limit));
    let resolved_tier = issuance_policy
        .and_then(|policy| resolve_tier(policy, effective_score))
        .map(|tier| LocalReputationTierView {
            name: tier.name.clone(),
            score_range: tier.score_range,
            max_scope: tier.max_scope.clone(),
        });

    Ok(LocalReputationInspection {
        subject_key: subject_key.to_string(),
        since,
        until,
        scoring_source,
        scoring,
        probationary_receipt_count,
        probationary_min_days,
        probationary_score_ceiling: ceiling,
        probationary,
        probationary_status,
        effective_score,
        resolved_tier,
        scorecard,
        imported_trust: None,
    })
}

pub fn build_local_reputation_corpus(
    subject_key: &str,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    since: Option<u64>,
    until: Option<u64>,
) -> Result<LocalReputationCorpus, KernelError> {
    let mut receipts = Vec::new();
    let mut capabilities = BTreeMap::new();

    if let Some(path) = receipt_db_path {
        let store = SqliteReceiptStore::open(path)
            .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
        receipts = store
            .list_tool_receipts_for_subject(subject_key)
            .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?
            .into_iter()
            .filter(|receipt| {
                since.is_none_or(|since| receipt.body().timestamp >= since)
                    && until.is_none_or(|until| receipt.body().timestamp <= until)
            })
            .collect();

        for snapshot in store
            .list_capability_snapshots(Some(subject_key), None)
            .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?
            .into_iter()
            .chain(
                store
                    .list_capability_snapshots(None, Some(subject_key))
                    .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?,
            )
        {
            capabilities
                .entry(snapshot.capability_id.clone())
                .or_insert(
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
                    .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?,
                );
        }
    }

    let mut budget_usage = Vec::new();
    if let Some(path) = budget_db_path {
        let store = SqliteBudgetStore::open(path)
            .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
        for capability in capabilities.values() {
            for grant_index in 0..capability.scope.grants.len() {
                if let Some(record) = store
                    .get_usage(&capability.capability_id, grant_index)
                    .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?
                {
                    let committed_cost_units = record.committed_cost_units().map_err(|error| {
                        KernelError::CapabilityIssuanceFailed(error.to_string())
                    })?;
                    budget_usage.push(ReputationBudgetUsageRecord {
                        capability_id: record.capability_id,
                        grant_index: record.grant_index,
                        invocation_count: record.invocation_count,
                        updated_at: record.updated_at,
                        total_cost_charged: committed_cost_units,
                    });
                }
            }
        }
    }

    Ok(LocalReputationCorpus {
        receipts,
        capabilities: capabilities.into_values().collect(),
        budget_usage,
        incident_reports: None,
    })
}

fn resolve_tier(
    policy: &ReputationIssuancePolicy,
    effective_score: f64,
) -> Option<&ReputationTierPolicy> {
    policy
        .tiers
        .iter()
        .rfind(|tier| score_in_range(effective_score, tier.score_range))
        .or_else(|| policy.tiers.first())
}

fn score_in_range(score: f64, score_range: [f64; 2]) -> bool {
    score >= score_range[0] && score <= score_range[1]
}

fn enforce_tier_scope(
    scope: &ChioScope,
    ttl_seconds: u64,
    tier: &ReputationTierPolicy,
) -> Result<(), KernelError> {
    enforce_scope_ceiling(scope, ttl_seconds, &tier.name, &tier.max_scope)
}

fn enforce_scope_ceiling(
    scope: &ChioScope,
    ttl_seconds: u64,
    ceiling_name: &str,
    max_scope: &TierScopeCeiling,
) -> Result<(), KernelError> {
    if ttl_seconds > max_scope.ttl_seconds {
        return Err(KernelError::CapabilityIssuanceDenied(format!(
            "requested ttl_seconds {ttl_seconds} exceeds policy tier '{}' ceiling {}",
            ceiling_name, max_scope.ttl_seconds
        )));
    }

    for grant in &scope.grants {
        enforce_tool_grant(grant, ceiling_name, max_scope)?;
    }
    for grant in &scope.resource_grants {
        enforce_resource_grant(grant, ceiling_name, max_scope)?;
    }
    for grant in &scope.prompt_grants {
        enforce_prompt_grant(grant, ceiling_name, max_scope)?;
    }

    Ok(())
}

fn enforce_runtime_assurance_policy(
    scope: &ChioScope,
    ttl_seconds: u64,
    policy: &RuntimeAssuranceIssuancePolicy,
    runtime_attestation: Option<&VerifiedRuntimeAttestationRecord>,
) -> Result<ChioScope, KernelError> {
    let actual_tier = runtime_attestation
        .map(VerifiedRuntimeAttestationRecord::effective_tier)
        .unwrap_or(RuntimeAssuranceTier::None);
    let tier = resolve_runtime_assurance_tier(policy, actual_tier).ok_or_else(|| {
        KernelError::CapabilityIssuanceDenied(format!(
            "runtime assurance tier '{actual_tier:?}' does not satisfy any configured assurance tier"
        ))
    })?;

    enforce_scope_ceiling(scope, ttl_seconds, &tier.name, &tier.max_scope)?;

    let mut constrained = scope.clone();
    if tier.minimum_attestation_tier > RuntimeAssuranceTier::None {
        for grant in &mut constrained.grants {
            if grant_is_economically_sensitive(grant)
                && !grant
                    .constraints
                    .contains(&Constraint::MinimumRuntimeAssurance(
                        tier.minimum_attestation_tier,
                    ))
            {
                grant.constraints.push(Constraint::MinimumRuntimeAssurance(
                    tier.minimum_attestation_tier,
                ));
            }
        }
    }

    Ok(constrained)
}

fn resolve_runtime_assurance_tier(
    policy: &RuntimeAssuranceIssuancePolicy,
    actual_tier: RuntimeAssuranceTier,
) -> Option<&RuntimeAssuranceTierPolicy> {
    policy
        .tiers
        .iter()
        .rfind(|tier| actual_tier >= tier.minimum_attestation_tier)
}

fn grant_is_economically_sensitive(grant: &ToolGrant) -> bool {
    grant.max_cost_per_invocation.is_some()
        || grant.max_total_cost.is_some()
        || grant.constraints.iter().any(|constraint| {
            matches!(
                constraint,
                Constraint::GovernedIntentRequired
                    | Constraint::RequireApprovalAbove { .. }
                    | Constraint::SellerExact(_)
                    | Constraint::MinimumAutonomyTier(_)
            )
        })
}

fn enforce_tool_grant(
    grant: &ToolGrant,
    ceiling_name: &str,
    max_scope: &TierScopeCeiling,
) -> Result<(), KernelError> {
    if max_scope.constraints_required && grant.constraints.is_empty() {
        return Err(KernelError::CapabilityIssuanceDenied(format!(
            "policy tier '{}' requires constrained tool grants",
            ceiling_name
        )));
    }

    if max_scope.max_delegation_depth == Some(0) && grant.operations.contains(&Operation::Delegate)
    {
        return Err(KernelError::CapabilityIssuanceDenied(format!(
            "policy tier '{}' does not allow delegated capability issuance",
            ceiling_name
        )));
    }

    let ceiling = ToolGrant {
        server_id: grant.server_id.clone(),
        tool_name: grant.tool_name.clone(),
        operations: max_scope.operations.clone(),
        constraints: if max_scope.constraints_required {
            required_constraints(grant)
        } else {
            Vec::new()
        },
        max_invocations: max_scope.max_invocations,
        max_cost_per_invocation: max_scope.max_cost_per_invocation.clone(),
        max_total_cost: max_scope.max_total_cost.clone(),
        dpop_required: None,
    };
    if grant.is_subset_of(&ceiling) {
        Ok(())
    } else {
        Err(KernelError::CapabilityIssuanceDenied(format!(
            "requested tool grant '{}'/'{}' exceeds policy tier '{}' scope ceiling",
            grant.server_id, grant.tool_name, ceiling_name
        )))
    }
}

fn enforce_resource_grant(
    grant: &ResourceGrant,
    ceiling_name: &str,
    max_scope: &TierScopeCeiling,
) -> Result<(), KernelError> {
    let ceiling = ResourceGrant {
        uri_pattern: grant.uri_pattern.clone(),
        operations: max_scope.operations.clone(),
    };
    if grant.is_subset_of(&ceiling) {
        Ok(())
    } else {
        Err(KernelError::CapabilityIssuanceDenied(format!(
            "requested resource grant '{}' exceeds policy tier '{}' scope ceiling",
            grant.uri_pattern, ceiling_name
        )))
    }
}

fn enforce_prompt_grant(
    grant: &PromptGrant,
    ceiling_name: &str,
    max_scope: &TierScopeCeiling,
) -> Result<(), KernelError> {
    let ceiling = PromptGrant {
        prompt_name: grant.prompt_name.clone(),
        operations: max_scope.operations.clone(),
    };
    if grant.is_subset_of(&ceiling) {
        Ok(())
    } else {
        Err(KernelError::CapabilityIssuanceDenied(format!(
            "requested prompt grant '{}' exceeds policy tier '{}' scope ceiling",
            grant.prompt_name, ceiling_name
        )))
    }
}

fn required_constraints(grant: &ToolGrant) -> Vec<Constraint> {
    grant.constraints.clone()
}

fn scoring_context(
    issuance_policy: Option<&ReputationIssuancePolicy>,
) -> (
    ReputationScoringSource,
    ReputationConfig,
    u64,
    u64,
    Option<f64>,
) {
    if let Some(policy) = issuance_policy {
        (
            ReputationScoringSource::IssuancePolicy,
            policy.scoring.clone(),
            policy.probationary_receipt_count,
            policy.probationary_min_days,
            Some(policy.probationary_score_ceiling),
        )
    } else {
        let scoring = ReputationConfig::default();
        (
            ReputationScoringSource::Default,
            scoring.clone(),
            scoring.history_receipt_target,
            scoring.history_day_target,
            None,
        )
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;

    use chio_core::capability::{CapabilityToken, MonetaryAmount, Operation, ToolGrant};
    use chio_core::crypto::Keypair;
    use chio_core::receipt::{
        ChioReceipt, ChioReceiptBody, Decision, ReceiptAttributionMetadata, ToolCallAction,
    };
    use chio_kernel::ReceiptStore;
    use chio_store_sqlite::SqliteReceiptStore;

    use crate::policy::{
        RuntimeAssuranceIssuancePolicy, RuntimeAssuranceTierPolicy, TierScopeCeiling,
    };

    fn unique_path(prefix: &str, extension: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}{extension}"))
    }

    fn test_policy() -> ReputationIssuancePolicy {
        ReputationIssuancePolicy {
            scoring: chio_reputation::ReputationConfig {
                history_receipt_target: 10,
                history_day_target: 10,
                ..Default::default()
            },
            probationary_receipt_count: 10,
            probationary_min_days: 10,
            probationary_score_ceiling: 0.60,
            tiers: vec![
                ReputationTierPolicy {
                    name: "probationary".to_string(),
                    score_range: [0.0, 0.50],
                    max_scope: TierScopeCeiling {
                        operations: vec![Operation::Read, Operation::Get],
                        max_invocations: Some(50),
                        max_cost_per_invocation: Some(MonetaryAmount {
                            units: 100,
                            currency: "USD".to_string(),
                        }),
                        max_total_cost: Some(MonetaryAmount {
                            units: 1_000,
                            currency: "USD".to_string(),
                        }),
                        max_delegation_depth: Some(0),
                        ttl_seconds: 60,
                        constraints_required: true,
                    },
                },
                ReputationTierPolicy {
                    name: "trusted".to_string(),
                    score_range: [0.50, 1.0],
                    max_scope: TierScopeCeiling {
                        operations: vec![
                            Operation::Read,
                            Operation::Get,
                            Operation::Invoke,
                            Operation::ReadResult,
                            Operation::Delegate,
                        ],
                        max_invocations: Some(500),
                        max_cost_per_invocation: Some(MonetaryAmount {
                            units: 1_000,
                            currency: "USD".to_string(),
                        }),
                        max_total_cost: Some(MonetaryAmount {
                            units: 10_000,
                            currency: "USD".to_string(),
                        }),
                        max_delegation_depth: Some(3),
                        ttl_seconds: 300,
                        constraints_required: false,
                    },
                },
            ],
        }
    }

    fn test_runtime_assurance_policy() -> RuntimeAssuranceIssuancePolicy {
        RuntimeAssuranceIssuancePolicy {
            tiers: vec![
                RuntimeAssuranceTierPolicy {
                    name: "baseline".to_string(),
                    minimum_attestation_tier: RuntimeAssuranceTier::None,
                    max_scope: TierScopeCeiling {
                        operations: vec![Operation::Invoke],
                        max_invocations: Some(5),
                        max_cost_per_invocation: Some(MonetaryAmount {
                            units: 50,
                            currency: "USD".to_string(),
                        }),
                        max_total_cost: Some(MonetaryAmount {
                            units: 100,
                            currency: "USD".to_string(),
                        }),
                        max_delegation_depth: Some(0),
                        ttl_seconds: 30,
                        constraints_required: false,
                    },
                },
                RuntimeAssuranceTierPolicy {
                    name: "attested".to_string(),
                    minimum_attestation_tier: RuntimeAssuranceTier::Attested,
                    max_scope: TierScopeCeiling {
                        operations: vec![Operation::Invoke],
                        max_invocations: Some(20),
                        max_cost_per_invocation: Some(MonetaryAmount {
                            units: 250,
                            currency: "USD".to_string(),
                        }),
                        max_total_cost: Some(MonetaryAmount {
                            units: 1_000,
                            currency: "USD".to_string(),
                        }),
                        max_delegation_depth: Some(0),
                        ttl_seconds: 300,
                        constraints_required: false,
                    },
                },
            ],
            attestation_trust_policy: None,
        }
    }

    fn test_trusted_runtime_assurance_policy() -> RuntimeAssuranceIssuancePolicy {
        let mut policy = test_runtime_assurance_policy();
        policy.attestation_trust_policy = Some(chio_core::capability::AttestationTrustPolicy {
            rules: vec![
                chio_core::capability::AttestationTrustRule {
                    name: "azure-contoso".to_string(),
                    schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
                    verifier: "https://maa.contoso.test".to_string(),
                    effective_tier: RuntimeAssuranceTier::Verified,
                    verifier_family: Some(
                        chio_core::appraisal::AttestationVerifierFamily::AzureMaa,
                    ),
                    max_evidence_age_seconds: Some(120),
                    allowed_attestation_types: vec!["sgx".to_string()],
                    required_assertions: std::collections::BTreeMap::new(),
                },
                chio_core::capability::AttestationTrustRule {
                    name: "google-confidential".to_string(),
                    schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
                    verifier: "https://confidentialcomputing.googleapis.com".to_string(),
                    effective_tier: RuntimeAssuranceTier::Verified,
                    verifier_family: Some(
                        chio_core::appraisal::AttestationVerifierFamily::GoogleAttestation,
                    ),
                    max_evidence_age_seconds: Some(120),
                    allowed_attestation_types: vec!["confidential_vm".to_string()],
                    required_assertions: std::collections::BTreeMap::from([
                        ("hardwareModel".to_string(), "GCP_AMD_SEV".to_string()),
                        ("secureBoot".to_string(), "enabled".to_string()),
                    ]),
                },
            ],
        });
        policy.tiers.push(RuntimeAssuranceTierPolicy {
            name: "verified".to_string(),
            minimum_attestation_tier: RuntimeAssuranceTier::Verified,
            max_scope: TierScopeCeiling {
                operations: vec![Operation::Invoke],
                max_invocations: Some(50),
                max_cost_per_invocation: Some(MonetaryAmount {
                    units: 500,
                    currency: "USD".to_string(),
                }),
                max_total_cost: Some(MonetaryAmount {
                    units: 5_000,
                    currency: "USD".to_string(),
                }),
                max_delegation_depth: Some(0),
                ttl_seconds: 600,
                constraints_required: false,
            },
        });
        policy
    }

    fn test_azure_runtime_attestation() -> RuntimeAttestationEvidence {
        let now = unix_now();
        RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test/".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: now.saturating_sub(5),
            expires_at: now + 300,
            evidence_sha256: "attestation-digest-azure".to_string(),
            runtime_identity: Some("spiffe://chio/runtime/test".to_string()),
            workload_identity: None,
            claims: Some(serde_json::json!({
                "azureMaa": {
                    "attestationType": "sgx"
                }
            })),
        }
    }

    fn test_google_runtime_attestation() -> RuntimeAttestationEvidence {
        let now = unix_now();
        RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
            verifier: "https://confidentialcomputing.googleapis.com".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: now.saturating_sub(5),
            expires_at: now + 300,
            evidence_sha256: "attestation-digest-google".to_string(),
            runtime_identity: Some(
                "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/vm-1"
                    .to_string(),
            ),
            workload_identity: None,
            claims: Some(serde_json::json!({
                "googleAttestation": {
                    "attestationType": "confidential_vm",
                    "hardwareModel": "GCP_AMD_SEV",
                    "secureBoot": "enabled"
                }
            })),
        }
    }

    fn make_receipt(
        id: &str,
        capability_id: &str,
        subject_key: &str,
        issuer_key: &str,
        timestamp: u64,
    ) -> ChioReceipt {
        let kernel_kp = Keypair::generate();
        ChioReceipt::sign(
            ChioReceiptBody {
                id: id.to_string(),
                timestamp,
                capability_id: capability_id.to_string(),
                tool_server: "filesystem".to_string(),
                tool_name: "read_file".to_string(),
                action: ToolCallAction::from_parameters(serde_json::json!({
                    "path": "/workspace/safe/data.txt"
                }))
                .expect("action"),
                decision: Decision::Allow,
                content_hash: format!("content-{id}"),
                policy_hash: "policy-hash".to_string(),
                evidence: Vec::new(),
                metadata: Some(serde_json::json!({
                    "attribution": ReceiptAttributionMetadata {
                        subject_key: subject_key.to_string(),
                        issuer_key: issuer_key.to_string(),
                        delegation_depth: 0,
                        grant_index: Some(0),
                    }
                })),
                trust_level: chio_core::TrustLevel::default(),
                tenant_id: None,
                kernel_key: kernel_kp.public_key(),
            },
            &kernel_kp,
        )
        .expect("sign receipt")
    }

    fn make_subject_capability(
        capability_id: &str,
        subject_kp: &Keypair,
        issuer_kp: &Keypair,
        issued_at: u64,
        max_invocations: Option<u32>,
    ) -> CapabilityToken {
        let body = chio_core::capability::CapabilityTokenBody {
            id: capability_id.to_string(),
            issuer: issuer_kp.public_key(),
            subject: subject_kp.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "filesystem".to_string(),
                    tool_name: "read_file".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![Constraint::PathPrefix("/workspace/safe".to_string())],
                    max_invocations,
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 250,
                        currency: "USD".to_string(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units: 2_500,
                        currency: "USD".to_string(),
                    }),
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            issued_at,
            expires_at: issued_at + 3_600,
            delegation_chain: Vec::new(),
        };
        CapabilityToken::sign(body, issuer_kp).expect("sign capability")
    }

    #[test]
    fn probationary_subject_requires_constrained_read_scope_and_persists_snapshot() {
        let receipt_db_path = unique_path("issuance-policy-receipts", ".sqlite3");
        let authority = wrap_capability_authority(
            Box::new(chio_kernel::LocalCapabilityAuthority::new(
                Keypair::generate(),
            )),
            Some(test_policy()),
            None,
            Some(&receipt_db_path),
            None,
        );
        let subject_kp = Keypair::generate();
        let scope = ChioScope {
            grants: vec![ToolGrant {
                server_id: "filesystem".to_string(),
                tool_name: "read_file".to_string(),
                operations: vec![Operation::Read],
                constraints: vec![Constraint::PathPrefix("/workspace/safe".to_string())],
                max_invocations: Some(10),
                max_cost_per_invocation: Some(MonetaryAmount {
                    units: 50,
                    currency: "USD".to_string(),
                }),
                max_total_cost: Some(MonetaryAmount {
                    units: 500,
                    currency: "USD".to_string(),
                }),
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        };

        let capability = authority
            .issue_capability(&subject_kp.public_key(), scope, 30)
            .expect("probationary read capability should issue");

        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        let stored = store
            .get_lineage(&capability.id)
            .expect("lineage query")
            .expect("snapshot present");
        assert_eq!(stored.subject_key, subject_kp.public_key().to_hex());

        let _ = fs::remove_file(receipt_db_path);
    }

    #[test]
    fn probationary_subject_denied_broad_issue_request() {
        let receipt_db_path = unique_path("issuance-policy-deny", ".sqlite3");
        let authority = wrap_capability_authority(
            Box::new(chio_kernel::LocalCapabilityAuthority::new(
                Keypair::generate(),
            )),
            Some(test_policy()),
            None,
            Some(&receipt_db_path),
            None,
        );
        let subject_kp = Keypair::generate();
        let scope = ChioScope {
            grants: vec![ToolGrant {
                server_id: "filesystem".to_string(),
                tool_name: "read_file".to_string(),
                operations: vec![Operation::Invoke, Operation::Delegate],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        };

        let error = authority
            .issue_capability(&subject_kp.public_key(), scope, 300)
            .expect_err("broad probationary issuance should be denied");
        assert!(
            matches!(error, KernelError::CapabilityIssuanceDenied(_)),
            "expected denial, got {error:?}"
        );

        let _ = fs::remove_file(receipt_db_path);
    }

    #[test]
    fn strong_local_history_allows_trusted_invoke_scope() {
        let receipt_db_path = unique_path("issuance-policy-history", ".sqlite3");
        let receipt_store = SqliteReceiptStore::open(&receipt_db_path).expect("receipt store");
        let subject_kp = Keypair::generate();
        let issuer_kp = Keypair::generate();
        let subject_hex = subject_kp.public_key().to_hex();
        let issuer_hex = issuer_kp.public_key().to_hex();
        let now = unix_now();
        let subject_capability = make_subject_capability(
            "cap-history-001",
            &subject_kp,
            &issuer_kp,
            now - 20 * 86_400,
            Some(200),
        );
        receipt_store
            .record_capability_snapshot(&subject_capability, None)
            .expect("record subject capability");
        for day in 0..12 {
            let receipt = make_receipt(
                &format!("rcpt-{day}"),
                &subject_capability.id,
                &subject_hex,
                &issuer_hex,
                now - (11 - day) * 86_400,
            );
            receipt_store
                .append_chio_receipt(&receipt)
                .expect("append receipt");
        }
        drop(receipt_store);

        let authority = wrap_capability_authority(
            Box::new(chio_kernel::LocalCapabilityAuthority::new(
                Keypair::generate(),
            )),
            Some(test_policy()),
            None,
            Some(&receipt_db_path),
            None,
        );
        let requested_scope = ChioScope {
            grants: vec![ToolGrant {
                server_id: "filesystem".to_string(),
                tool_name: "read_file".to_string(),
                operations: vec![Operation::Invoke, Operation::Delegate],
                constraints: Vec::new(),
                max_invocations: Some(250),
                max_cost_per_invocation: Some(MonetaryAmount {
                    units: 500,
                    currency: "USD".to_string(),
                }),
                max_total_cost: Some(MonetaryAmount {
                    units: 5_000,
                    currency: "USD".to_string(),
                }),
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        };

        let capability = authority
            .issue_capability(&subject_kp.public_key(), requested_scope, 300)
            .expect("trusted issuance should succeed");
        assert_eq!(capability.subject, subject_kp.public_key());

        let _ = fs::remove_file(receipt_db_path);
    }

    #[test]
    fn runtime_assurance_policy_denies_high_budget_without_attestation() {
        let authority = wrap_capability_authority(
            Box::new(chio_kernel::LocalCapabilityAuthority::new(
                Keypair::generate(),
            )),
            None,
            Some(test_runtime_assurance_policy()),
            None,
            None,
        );
        let subject_kp = Keypair::generate();
        let requested_scope = ChioScope {
            grants: vec![ToolGrant {
                server_id: "payments".to_string(),
                tool_name: "charge".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![Constraint::GovernedIntentRequired],
                max_invocations: Some(10),
                max_cost_per_invocation: Some(MonetaryAmount {
                    units: 250,
                    currency: "USD".to_string(),
                }),
                max_total_cost: Some(MonetaryAmount {
                    units: 1_000,
                    currency: "USD".to_string(),
                }),
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        };

        let error = authority
            .issue_capability(&subject_kp.public_key(), requested_scope, 120)
            .expect_err("baseline runtime tier should not allow the higher monetary ceiling");
        assert!(
            matches!(error, KernelError::CapabilityIssuanceDenied(_)),
            "expected runtime-assurance issuance denial, got {error:?}"
        );
    }

    #[test]
    fn runtime_assurance_policy_denies_raw_attestation_without_local_trust_boundary() {
        let authority = wrap_capability_authority(
            Box::new(chio_kernel::LocalCapabilityAuthority::new(
                Keypair::generate(),
            )),
            None,
            Some(test_runtime_assurance_policy()),
            None,
            None,
        );
        let subject_kp = Keypair::generate();
        let requested_scope = ChioScope {
            grants: vec![ToolGrant {
                server_id: "payments".to_string(),
                tool_name: "charge".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![Constraint::GovernedIntentRequired],
                max_invocations: Some(10),
                max_cost_per_invocation: Some(MonetaryAmount {
                    units: 250,
                    currency: "USD".to_string(),
                }),
                max_total_cost: Some(MonetaryAmount {
                    units: 1_000,
                    currency: "USD".to_string(),
                }),
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        };

        let error = authority
            .issue_capability_with_attestation(
                &subject_kp.public_key(),
                requested_scope,
                120,
                Some(test_azure_runtime_attestation()),
            )
            .expect_err("raw attestation must not unlock attested scope without local trust");

        assert!(
            error
                .to_string()
                .contains("policy tier 'baseline'"),
            "expected local verification boundary to keep raw attestation on the baseline tier, got {error}"
        );
    }

    #[test]
    fn issuance_verification_returns_canonical_subject_and_provenance() {
        let policy = test_trusted_runtime_assurance_policy();
        let verified = verify_runtime_attestation_for_issuance(
            Some(&test_azure_runtime_attestation()),
            Some(&policy),
            unix_now(),
        )
        .expect("trusted attestation should verify")
        .expect("verified record should be returned when runtime policy is present");

        assert!(verified.is_locally_accepted());
        assert_eq!(verified.effective_tier(), RuntimeAssuranceTier::Verified);
        assert_eq!(
            verified.provenance.canonical_verifier,
            "https://maa.contoso.test"
        );
        assert_eq!(verified.matched_trust_rule(), Some("azure-contoso"));
        assert_eq!(
            verified
                .workload_identity()
                .expect("trusted attestation should bind a workload identity")
                .trust_domain,
            "chio"
        );
    }

    #[test]
    fn issuance_verification_returns_verified_record_without_runtime_policy() {
        let evidence = test_azure_runtime_attestation();
        let verified = verify_runtime_attestation_for_issuance(Some(&evidence), None, unix_now())
            .expect("attestation should pass local binding validation")
            .expect("verified record should still be returned without runtime policy");

        assert!(!verified.policy_outcome.trust_policy_configured);
        assert!(!verified.is_locally_accepted());
        assert_eq!(verified.effective_tier(), RuntimeAssuranceTier::None);
        assert_eq!(
            verified.evidence_schema(),
            "chio.runtime-attestation.azure-maa.jwt.v1"
        );
        assert_eq!(verified.evidence_sha256(), "attestation-digest-azure");
        assert_eq!(verified.canonical_verifier(), "https://maa.contoso.test");
        assert_eq!(
            verified.verifier_family(),
            chio_core::appraisal::AttestationVerifierFamily::AzureMaa
        );
        assert!(verified.matches_evidence(&evidence));
    }

    #[test]
    fn workload_identity_validation_denies_conflicting_attestation_without_policy() {
        let authority = wrap_capability_authority(
            Box::new(chio_kernel::LocalCapabilityAuthority::new(
                Keypair::generate(),
            )),
            None,
            None,
            None,
            None,
        );
        let subject_kp = Keypair::generate();
        let now = unix_now();
        let requested_scope = ChioScope {
            grants: vec![ToolGrant {
                server_id: "payments".to_string(),
                tool_name: "charge".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![Constraint::GovernedIntentRequired],
                max_invocations: Some(1),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        };
        let runtime_attestation = RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.v1".to_string(),
            verifier: "verifier.chio".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: now.saturating_sub(5),
            expires_at: now + 300,
            evidence_sha256: "attestation-digest".to_string(),
            runtime_identity: Some("spiffe://prod.chio/payments/worker".to_string()),
            workload_identity: Some(chio_core::capability::WorkloadIdentity {
                scheme: chio_core::capability::WorkloadIdentityScheme::Spiffe,
                credential_kind: chio_core::capability::WorkloadCredentialKind::X509Svid,
                uri: "spiffe://dev.chio/payments/worker".to_string(),
                trust_domain: "dev.chio".to_string(),
                path: "/payments/worker".to_string(),
            }),
            claims: None,
        };

        let error = authority
            .issue_capability_with_attestation(
                &subject_kp.public_key(),
                requested_scope,
                120,
                Some(runtime_attestation),
            )
            .expect_err("conflicting workload identity should fail closed");
        assert!(
            matches!(error, KernelError::CapabilityIssuanceDenied(_)),
            "expected issuance denial, got {error:?}"
        );
        assert!(
            error.to_string().contains("workload identity"),
            "expected workload-identity denial, got {error}"
        );
    }

    #[test]
    fn runtime_assurance_policy_rebinds_trusted_attestation_to_verified_tier() {
        let authority = wrap_capability_authority(
            Box::new(chio_kernel::LocalCapabilityAuthority::new(
                Keypair::generate(),
            )),
            None,
            Some(test_trusted_runtime_assurance_policy()),
            None,
            None,
        );
        let subject_kp = Keypair::generate();
        let requested_scope = ChioScope {
            grants: vec![ToolGrant {
                server_id: "payments".to_string(),
                tool_name: "charge".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![Constraint::GovernedIntentRequired],
                max_invocations: Some(10),
                max_cost_per_invocation: Some(MonetaryAmount {
                    units: 500,
                    currency: "USD".to_string(),
                }),
                max_total_cost: Some(MonetaryAmount {
                    units: 5_000,
                    currency: "USD".to_string(),
                }),
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        };

        let capability = authority
            .issue_capability_with_attestation(
                &subject_kp.public_key(),
                requested_scope,
                120,
                Some(test_azure_runtime_attestation()),
            )
            .expect("trusted attestation should unlock verified tier");

        assert!(
            capability.scope.grants[0]
                .constraints
                .contains(&Constraint::MinimumRuntimeAssurance(
                    RuntimeAssuranceTier::Verified
                )),
            "issued capability should bind the verified runtime assurance tier"
        );
    }

    #[test]
    fn runtime_assurance_policy_denies_untrusted_attestation_when_verifier_rules_exist() {
        let authority = wrap_capability_authority(
            Box::new(chio_kernel::LocalCapabilityAuthority::new(
                Keypair::generate(),
            )),
            None,
            Some(test_trusted_runtime_assurance_policy()),
            None,
            None,
        );
        let subject_kp = Keypair::generate();
        let requested_scope = ChioScope {
            grants: vec![ToolGrant {
                server_id: "payments".to_string(),
                tool_name: "charge".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![Constraint::GovernedIntentRequired],
                max_invocations: Some(10),
                max_cost_per_invocation: Some(MonetaryAmount {
                    units: 250,
                    currency: "USD".to_string(),
                }),
                max_total_cost: Some(MonetaryAmount {
                    units: 1_000,
                    currency: "USD".to_string(),
                }),
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        };
        let mut untrusted = test_azure_runtime_attestation();
        untrusted.verifier = "https://maa.untrusted.test".to_string();

        let error = authority
            .issue_capability_with_attestation(
                &subject_kp.public_key(),
                requested_scope,
                120,
                Some(untrusted),
            )
            .expect_err("untrusted verifier should fail closed");
        assert!(
            error.to_string().contains("trust policy"),
            "expected trust policy denial, got {error}"
        );
    }

    #[test]
    fn runtime_assurance_policy_rebinds_google_attestation_to_verified_tier() {
        let authority = wrap_capability_authority(
            Box::new(chio_kernel::LocalCapabilityAuthority::new(
                Keypair::generate(),
            )),
            None,
            Some(test_trusted_runtime_assurance_policy()),
            None,
            None,
        );
        let subject_kp = Keypair::generate();
        let requested_scope = ChioScope {
            grants: vec![ToolGrant {
                server_id: "payments".to_string(),
                tool_name: "charge".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![Constraint::GovernedIntentRequired],
                max_invocations: Some(10),
                max_cost_per_invocation: Some(MonetaryAmount {
                    units: 250,
                    currency: "USD".to_string(),
                }),
                max_total_cost: Some(MonetaryAmount {
                    units: 1_000,
                    currency: "USD".to_string(),
                }),
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        };

        let capability = authority
            .issue_capability_with_attestation(
                &subject_kp.public_key(),
                requested_scope,
                120,
                Some(test_google_runtime_attestation()),
            )
            .expect("trusted google appraisal should unlock verified tier");

        assert!(
            capability.scope.grants[0]
                .constraints
                .contains(&Constraint::MinimumRuntimeAssurance(
                    RuntimeAssuranceTier::Verified
                )),
            "issued capability should bind the verified runtime assurance tier"
        );
    }
}
