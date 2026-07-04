use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use chio_core::capability::scope::ChioScope;
use chio_core::crypto::PublicKey;
use chio_kernel::{BudgetStore, KernelError, ReceiptReadContext};
use chio_reputation::{
    compute_local_scorecard, BudgetUsageRecord as ReputationBudgetUsageRecord,
    CapabilityLineageRecord, CapabilityLineageScopeJsonInput, LocalReputationCorpus,
    ReputationConfig,
};
use chio_store_sqlite::{SqliteBudgetStore, SqliteReceiptStore};

use crate::policy::{ReputationIssuancePolicy, ReputationTierPolicy};

use super::scope::enforce_tier_scope;
use super::types::{
    LocalReputationInspection, LocalReputationTierView, ProbationaryStatus, ReputationScoringSource,
};
use super::util::unix_now;

pub(in crate::issuance) fn enforce_reputation_policy(
    subject: &PublicKey,
    scope: &ChioScope,
    ttl_seconds: u64,
    policy: &ReputationIssuancePolicy,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    trusted_kernel_keys: &[String],
) -> Result<(), KernelError> {
    let subject_key = subject.to_hex();
    let inspection = inspect_local_reputation(
        &subject_key,
        receipt_db_path,
        budget_db_path,
        None,
        None,
        Some(policy),
        trusted_kernel_keys,
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
    trusted_kernel_keys: &[String],
) -> Result<LocalReputationInspection, KernelError> {
    inspect_local_reputation_with_read_context(
        subject_key,
        receipt_db_path,
        budget_db_path,
        since,
        until,
        issuance_policy,
        trusted_kernel_keys,
        &ReceiptReadContext::local_operator_admin_all(),
    )
}

pub(crate) fn inspect_local_reputation_with_read_context(
    subject_key: &str,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    since: Option<u64>,
    until: Option<u64>,
    issuance_policy: Option<&ReputationIssuancePolicy>,
    trusted_kernel_keys: &[String],
    read_context: &ReceiptReadContext,
) -> Result<LocalReputationInspection, KernelError> {
    let corpus = build_local_reputation_corpus_with_read_context(
        subject_key,
        receipt_db_path,
        budget_db_path,
        since,
        until,
        read_context,
    )?;
    let (scoring_source, scoring, probationary_receipt_count, probationary_min_days, ceiling) =
        scoring_context(issuance_policy, trusted_kernel_keys);
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
    build_local_reputation_corpus_with_read_context(
        subject_key,
        receipt_db_path,
        budget_db_path,
        since,
        until,
        &ReceiptReadContext::local_operator_admin_all(),
    )
}

pub fn build_local_reputation_corpus_with_read_context(
    subject_key: &str,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    since: Option<u64>,
    until: Option<u64>,
    read_context: &ReceiptReadContext,
) -> Result<LocalReputationCorpus, KernelError> {
    let mut receipts = Vec::new();
    let mut capabilities = BTreeMap::new();

    if let Some(path) = receipt_db_path {
        let store = SqliteReceiptStore::open(path)
            .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
        receipts = store
            .list_tool_receipts_for_subject_with_context(read_context, subject_key)
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

fn scoring_context(
    issuance_policy: Option<&ReputationIssuancePolicy>,
    trusted_kernel_keys: &[String],
) -> (
    ReputationScoringSource,
    ReputationConfig,
    u64,
    u64,
    Option<f64>,
) {
    if let Some(policy) = issuance_policy {
        let mut scoring = policy.scoring.clone();
        merge_trusted_kernel_keys(&mut scoring, trusted_kernel_keys);
        (
            ReputationScoringSource::IssuancePolicy,
            scoring,
            policy.probationary_receipt_count,
            policy.probationary_min_days,
            Some(policy.probationary_score_ceiling),
        )
    } else {
        let mut scoring = ReputationConfig::default();
        merge_trusted_kernel_keys(&mut scoring, trusted_kernel_keys);
        (
            ReputationScoringSource::Default,
            scoring.clone(),
            scoring.history_receipt_target,
            scoring.history_day_target,
            None,
        )
    }
}

/// Merge caller-supplied trusted kernel keys into the scoring config. Existing
/// keys from a policy-derived config are preserved; additional caller keys are
/// added so reputation scoring can verify receipts signed by either source.
fn merge_trusted_kernel_keys(config: &mut ReputationConfig, trusted_kernel_keys: &[String]) {
    if trusted_kernel_keys.is_empty() {
        return;
    }
    let merged: BTreeSet<String> = config
        .trusted_kernel_keys
        .iter()
        .cloned()
        .chain(trusted_kernel_keys.iter().cloned())
        .collect();
    config.trusted_kernel_keys = merged;
}
