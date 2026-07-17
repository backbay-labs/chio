use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::{PublicKey, Signature};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::substrate::{PairBucketKey, PassportCapKey, ScarcityBucketKey};
use crate::{
    agent_passport_jwk_thumbprint, agent_passport_key_hash, scarcity_admissions_for_deposit,
    scarcity_policy_sha256, CostCommitmentPolicy, ObservationCostVerificationMode,
    PassportAdmission, PheromoneCostCommitment, PheromoneDeposit, PheromoneDepositBody,
    PheromoneError, PheromoneObservationCostLeaf, PheromoneObservationCostStatement,
    PheromoneObservationCostVerifierRoot, PheromoneScarcityAdmission, PheromoneScarcityPolicy,
    PheromoneValidationContext, PheromoneWorkflowContext, SubjectClassPolicy,
    DEFAULT_NEWCOMER_DISCOUNT_HORIZON_EPOCHS, OBSERVATION_COST_TELEMETRY_ALGORITHM,
    OBSERVATION_COST_UNIT, PHEROMONE_COST_COMMITMENT_SCHEMA, PHEROMONE_DEPOSIT_SCHEMA,
    PHEROMONE_OBSERVATION_COST_LEAF_SCHEMA, PHEROMONE_OBSERVATION_COST_STATEMENT_SCHEMA,
    PHEROMONE_OBSERVATION_COST_TELEMETRY_ROOT_SCHEMA,
    PHEROMONE_OBSERVATION_COST_VERIFIER_ROOT_SCHEMA, PHEROMONE_SCARCITY_POLICY_SCHEMA,
    PHEROMONE_WORKFLOW_CONTEXT_SCHEMA,
};

pub(crate) fn validate_deposit_static(
    deposit: &PheromoneDeposit,
    context: &PheromoneValidationContext,
) -> Result<(), PheromoneError> {
    let body = &deposit.body;
    if body.schema != PHEROMONE_DEPOSIT_SCHEMA {
        return Err(PheromoneError::UnsupportedSchema(body.schema.clone()));
    }
    validate_non_empty(&body.kernel_id, "kernel_id")?;
    validate_non_empty(&body.agent_passport_key_hash, "agent_passport_key_hash")?;
    validate_non_empty(
        &body.agent_passport_jwk_thumbprint,
        "agent_passport_jwk_thumbprint",
    )?;
    validate_non_empty(&body.subject_class, "subject_class")?;
    validate_non_empty(&body.subject_class_namespace, "subject_class_namespace")?;
    validate_non_empty(&body.nonce, "nonce")?;
    validate_unique_non_empty_strings(&body.treaty_scope, "treaty_scope")?;
    if !body.confidence.is_finite() || !(0.0..=1.0).contains(&body.confidence) {
        return Err(PheromoneError::ConfidenceOutOfRange(body.confidence));
    }
    if !body.decay_half_life_secs.is_finite() || body.decay_half_life_secs <= 0.0 {
        return Err(PheromoneError::HalfLifeInvalid(body.decay_half_life_secs));
    }
    if let Some(floor) = body.evaporation_floor {
        if !floor.is_finite() || !(0.0..=1.0).contains(&floor) {
            return Err(PheromoneError::EvaporationFloorInvalid(floor));
        }
    }
    if let Some(commitment) = &body.cost_commitment {
        if commitment.schema != PHEROMONE_COST_COMMITMENT_SCHEMA {
            return Err(PheromoneError::UnsupportedSchema(commitment.schema.clone()));
        }
        validate_cost_commitment_static(commitment)?;
    }
    if let Some(workflow) = &body.workflow_context {
        validate_workflow_context(workflow)?;
    }
    let policy = subject_policy(body, context)?;
    if policy
        .allowed_treaties
        .iter()
        .all(|treaty| !body.treaty_scope.contains(treaty))
    {
        return Err(PheromoneError::TreatyScopeViolation(format!(
            "deposit has no treaty accepted for {}",
            body.subject_class
        )));
    }
    if (policy.destructive || policy.cost_commitment == CostCommitmentPolicy::Required)
        && body.cost_commitment.is_none()
    {
        return Err(PheromoneError::ObservationCostCommitmentMissing(
            body.subject_class.clone(),
        ));
    }
    let _admissions = scarcity_admissions_for_deposit(deposit, context)?;
    if body
        .timestamp_unix_ms
        .saturating_add(context.replay_window_ms)
        <= context.now_unix_ms
    {
        return Err(PheromoneError::ReplayWindowExceeded(body.nonce.clone()));
    }
    if body.timestamp_unix_ms > context.now_unix_ms {
        return Err(PheromoneError::DepositFromFuture(body.nonce.clone()));
    }
    Ok(())
}

fn validate_workflow_context(workflow: &PheromoneWorkflowContext) -> Result<(), PheromoneError> {
    if workflow.schema != PHEROMONE_WORKFLOW_CONTEXT_SCHEMA {
        return Err(PheromoneError::UnsupportedSchema(workflow.schema.clone()));
    }
    validate_non_empty(&workflow.workflow_id, "workflow_id")?;
    validate_non_empty(&workflow.workflow_receipt_id, "workflow_receipt_id")?;
    validate_hex64(&workflow.workflow_receipt_sha256, "workflow_receipt_sha256")?;
    validate_non_empty(
        &workflow.workflow_intersection_id,
        "workflow_intersection_id",
    )?;
    validate_hex64(
        &workflow.workflow_intersection_sha256,
        "workflow_intersection_sha256",
    )?;
    validate_non_empty(&workflow.tool_receipt_id, "tool_receipt_id")?;
    validate_hex64(&workflow.bilateral_dsse_sha256, "bilateral_dsse_sha256")?;
    validate_non_empty(&workflow.consistency_anchor, "consistency_anchor")?;
    Ok(())
}

pub(crate) fn resolve_passport<'a>(
    deposit: &PheromoneDeposit,
    context: &'a PheromoneValidationContext,
) -> Result<&'a PassportAdmission, PheromoneError> {
    for kernel_key in &context.kernel_public_keys {
        if agent_passport_key_hash(kernel_key) == deposit.body.agent_passport_key_hash
            && verify_deposit_signature(deposit, kernel_key).is_ok()
        {
            return Err(PheromoneError::KernelKeyUsedForDeposit);
        }
    }
    let passport = context
        .passports
        .iter()
        .find(|passport| {
            passport.kernel_id == deposit.body.kernel_id
                && agent_passport_key_hash(&passport.public_key)
                    == deposit.body.agent_passport_key_hash
        })
        .ok_or_else(|| PheromoneError::UnknownOriginAgent(deposit.body.kernel_id.clone()))?;
    if passport.revoked
        || passport.valid_from_unix_ms > deposit.body.timestamp_unix_ms
        || passport.valid_until_unix_ms <= deposit.body.timestamp_unix_ms
    {
        return Err(PheromoneError::UnknownOriginAgent(
            deposit.body.kernel_id.clone(),
        ));
    }
    if agent_passport_jwk_thumbprint(&passport.public_key)
        != deposit.body.agent_passport_jwk_thumbprint
    {
        return Err(PheromoneError::SignatureKeyMismatch(
            "JWK thumbprint mismatch".to_string(),
        ));
    }
    Ok(passport)
}

pub(crate) fn verify_deposit_signature(
    deposit: &PheromoneDeposit,
    public_key: &PublicKey,
) -> Result<(), PheromoneError> {
    let canonical = canonical_json_bytes(&deposit_signature_body(&deposit.body))
        .map_err(|error| PheromoneError::CanonicalJson(error.to_string()))?;
    if public_key.verify(&canonical, &deposit.signature) {
        Ok(())
    } else {
        Err(PheromoneError::SignatureInvalid)
    }
}

pub(crate) fn deposit_signature_body(body: &PheromoneDepositBody) -> PheromoneDepositBody {
    let mut signed = body.clone();
    signed.cost_commitment = None;
    signed
}

pub(crate) fn commit_admission_state(
    deposit: &PheromoneDeposit,
    seen_nonces: &Mutex<BTreeSet<(String, String, String)>>,
    context: &PheromoneValidationContext,
    scarcity_buckets: &Mutex<BTreeMap<ScarcityBucketKey, u64>>,
    pair_counts: &Mutex<BTreeMap<PairBucketKey, u64>>,
    passports_by_kernel_class: &Mutex<BTreeMap<PassportCapKey, BTreeSet<String>>>,
) -> Result<(), PheromoneError> {
    let admissions = scarcity_admissions_for_deposit(deposit, context)?;
    let nonce_key = (
        deposit.body.kernel_id.clone(),
        deposit.body.agent_passport_key_hash.clone(),
        deposit.body.nonce.clone(),
    );

    let mut seen = seen_nonces.lock()?;
    if seen.contains(&nonce_key) {
        return Err(PheromoneError::ReplayWindowExceeded(
            deposit.body.nonce.clone(),
        ));
    }
    let mut buckets = scarcity_buckets.lock()?;
    let mut counts = pair_counts.lock()?;
    let mut by_kernel = passports_by_kernel_class.lock()?;

    for admission in &admissions {
        let scarcity_key = scarcity_bucket_key(admission);
        let bucket_count = buckets.get(&scarcity_key).copied().unwrap_or(0);
        if bucket_count >= admission.token_capacity {
            return Err(PheromoneError::RateLimitExhausted(format!(
                "{}:{}:{}:{}",
                admission.reputation_epoch,
                admission.window_id,
                admission.treaty_id,
                admission.subject_class
            )));
        }
        let pair_key = pair_bucket_key(deposit, admission);
        let count = counts.get(&pair_key).copied().unwrap_or(0);
        if count >= context.max_deposits_per_pair {
            return Err(PheromoneError::DiversityCapExceeded(
                deposit.body.agent_passport_key_hash.clone(),
            ));
        }

        let passport_key = passport_cap_key(deposit, admission);
        let cap = sqrt_passport_cap(context.active_peers_in_treaty);
        let passport_seen = by_kernel
            .get(&passport_key)
            .map(|passports| passports.contains(&deposit.body.agent_passport_key_hash))
            .unwrap_or(false);
        let projected_passport_count = by_kernel
            .get(&passport_key)
            .map(BTreeSet::len)
            .unwrap_or(0)
            .saturating_add(usize::from(!passport_seen));
        if projected_passport_count as u64 > cap {
            return Err(PheromoneError::SqrtNPassportCapExceeded(
                deposit.body.kernel_id.clone(),
            ));
        }
    }

    seen.insert(nonce_key);
    for admission in &admissions {
        let scarcity_key = scarcity_bucket_key(admission);
        let count = buckets.get(&scarcity_key).copied().unwrap_or(0);
        buckets.insert(scarcity_key, count.saturating_add(1));
        let pair_key = pair_bucket_key(deposit, admission);
        let pair_count = counts.get(&pair_key).copied().unwrap_or(0);
        counts.insert(pair_key, pair_count.saturating_add(1));
        by_kernel
            .entry(passport_cap_key(deposit, admission))
            .or_default()
            .insert(deposit.body.agent_passport_key_hash.clone());
    }
    Ok(())
}

fn scarcity_bucket_key(admission: &PheromoneScarcityAdmission) -> ScarcityBucketKey {
    (
        admission.reputation_epoch,
        admission.window_id.clone(),
        admission.treaty_id.clone(),
        admission.subject_class_namespace.clone(),
        admission.subject_class.clone(),
    )
}

fn pair_bucket_key(
    deposit: &PheromoneDeposit,
    admission: &PheromoneScarcityAdmission,
) -> PairBucketKey {
    (
        admission.reputation_epoch,
        admission.window_id.clone(),
        admission.treaty_id.clone(),
        admission.subject_class_namespace.clone(),
        admission.subject_class.clone(),
        deposit.body.kernel_id.clone(),
        deposit.body.agent_passport_key_hash.clone(),
    )
}

fn passport_cap_key(
    deposit: &PheromoneDeposit,
    admission: &PheromoneScarcityAdmission,
) -> PassportCapKey {
    (
        admission.active_peers_epoch,
        admission.window_id.clone(),
        admission.treaty_id.clone(),
        admission.subject_class_namespace.clone(),
        admission.subject_class.clone(),
        deposit.body.kernel_id.clone(),
    )
}

pub(crate) fn subject_policy<'a>(
    body: &PheromoneDepositBody,
    context: &'a PheromoneValidationContext,
) -> Result<&'a SubjectClassPolicy, PheromoneError> {
    context
        .subject_classes
        .iter()
        .find(|policy| {
            policy.subject_class == body.subject_class
                && policy.subject_class_namespace == body.subject_class_namespace
        })
        .ok_or_else(|| PheromoneError::SubjectClassUnknown(body.subject_class.clone()))
}

pub(crate) fn accepted_deposit_treaties(
    body: &PheromoneDepositBody,
    policy: &SubjectClassPolicy,
) -> Vec<String> {
    body.treaty_scope
        .iter()
        .filter(|treaty| {
            policy
                .allowed_treaties
                .iter()
                .any(|allowed| allowed == *treaty)
        })
        .cloned()
        .collect()
}

pub fn validate_scarcity_policy_material(
    policy: &PheromoneScarcityPolicy,
    context: &PheromoneValidationContext,
) -> Result<(), PheromoneError> {
    if policy.schema != PHEROMONE_SCARCITY_POLICY_SCHEMA {
        return Err(PheromoneError::UnsupportedSchema(policy.schema.clone()));
    }
    validate_non_empty(&policy.policy_id, "scarcity policy id")?;
    validate_non_empty(&policy.window_id, "scarcity window id")?;
    validate_hex64(&policy.runtime_policy_sha256, "runtime_policy_sha256")?;
    validate_hex64(&policy.policy_sha256, "policy_sha256")?;
    validate_non_empty(
        &policy.subject_class_namespace,
        "scarcity subject class namespace",
    )?;
    validate_non_empty(&policy.subject_class, "scarcity subject class")?;
    if policy.treaty_scope.is_empty() {
        return Err(PheromoneError::ScarcityPolicyInvalid(format!(
            "{} treaty scope must not be empty",
            policy.policy_id
        )));
    }
    validate_unique_non_empty_strings(&policy.treaty_scope, "scarcity treaty scope")?;
    if !context
        .known_reputation_epochs
        .contains(&policy.reputation_epoch)
    {
        return Err(PheromoneError::UnknownReputationEpoch(
            policy.reputation_epoch,
        ));
    }
    if !context
        .known_reputation_epochs
        .contains(&context.active_reputation_epoch)
    {
        return Err(PheromoneError::UnknownReputationEpoch(
            context.active_reputation_epoch,
        ));
    }
    if !context
        .known_reputation_epochs
        .contains(&policy.active_peers_epoch)
    {
        return Err(PheromoneError::UnknownReputationEpoch(
            policy.active_peers_epoch,
        ));
    }
    let runtime_policy_sha256 = context.runtime_policy_sha256.as_deref().ok_or_else(|| {
        PheromoneError::ScarcityPolicyInvalid(format!(
            "{} runtime policy hash is absent from receiver context",
            policy.policy_id
        ))
    })?;
    if policy.runtime_policy_sha256 != runtime_policy_sha256 {
        return Err(PheromoneError::ScarcityPolicyInvalid(format!(
            "{} runtime policy hash {} does not match receiver policy hash {}",
            policy.policy_id, policy.runtime_policy_sha256, runtime_policy_sha256
        )));
    }
    let expected_policy_sha256 = scarcity_policy_sha256(policy)?;
    if policy.policy_sha256 != expected_policy_sha256 {
        return Err(PheromoneError::ScarcityPolicyInvalid(format!(
            "{} policy hash {} does not match canonical hash {}",
            policy.policy_id, policy.policy_sha256, expected_policy_sha256
        )));
    }
    if policy.window_start_unix_ms >= policy.window_end_unix_ms {
        return Err(PheromoneError::ScarcityPolicyInvalid(format!(
            "{} window start must be before end",
            policy.policy_id
        )));
    }
    if policy.token_capacity == 0 {
        return Err(PheromoneError::ScarcityPolicyInvalid(format!(
            "{} token capacity must be positive",
            policy.policy_id
        )));
    }
    if policy.newcomer_horizon_epochs == 0 {
        return Err(PheromoneError::InvalidNewcomerHorizon(
            policy.newcomer_horizon_epochs,
        ));
    }
    if policy.observation_cost_verification == ObservationCostVerificationMode::Required {
        validate_non_empty(&policy.verifier_id, "scarcity verifier id")?;
    }
    let Some(subject) = context.subject_classes.iter().find(|subject| {
        subject.subject_class == policy.subject_class
            && subject.subject_class_namespace == policy.subject_class_namespace
    }) else {
        return Err(PheromoneError::SubjectClassUnknown(
            policy.subject_class.clone(),
        ));
    };
    for treaty in &policy.treaty_scope {
        if !subject
            .allowed_treaties
            .iter()
            .any(|allowed| allowed == treaty)
        {
            return Err(PheromoneError::ScarcityPolicyInvalid(format!(
                "{} treaty {} is not allowed for subject class",
                policy.policy_id, treaty
            )));
        }
    }
    Ok(())
}

pub(crate) fn scarcity_policy_is_active(
    policy: &PheromoneScarcityPolicy,
    context: &PheromoneValidationContext,
) -> bool {
    policy.reputation_epoch == context.active_reputation_epoch
        && policy.window_start_unix_ms <= context.now_unix_ms
        && context.now_unix_ms < policy.window_end_unix_ms
}

pub(crate) fn scarcity_windows_overlap(
    left: &PheromoneScarcityPolicy,
    right: &PheromoneScarcityPolicy,
) -> bool {
    left.window_start_unix_ms < right.window_end_unix_ms
        && right.window_start_unix_ms < left.window_end_unix_ms
}

pub(crate) fn verify_observation_cost_commitment(
    deposit: &PheromoneDeposit,
    policy: &PheromoneScarcityPolicy,
    context: &PheromoneValidationContext,
    treaty_id: &str,
) -> Result<(), PheromoneError> {
    let body = &deposit.body;
    let Some(commitment) = body.cost_commitment.as_ref() else {
        return Err(PheromoneError::ObservationCostCommitmentMissing(
            body.subject_class.clone(),
        ));
    };
    validate_cost_commitment_static(commitment)?;
    let statement = &commitment.statement;
    let runtime_policy_sha256 = context.runtime_policy_sha256.as_deref().ok_or_else(|| {
        PheromoneError::ObservationCostRuntimePolicyMismatch(
            "runtime policy hash is absent from receiver context".to_string(),
        )
    })?;
    let scarcity_policy_sha256 = scarcity_policy_sha256(policy)?;
    if statement.runtime_policy_sha256 != runtime_policy_sha256 {
        return Err(PheromoneError::ObservationCostRuntimePolicyMismatch(
            statement.commitment_id.clone(),
        ));
    }
    if statement.scarcity_policy_sha256 != scarcity_policy_sha256 {
        return Err(PheromoneError::ObservationCostPolicyMismatch(
            statement.commitment_id.clone(),
        ));
    }
    verify_observation_cost_policy_binding(deposit, policy, statement, treaty_id)?;

    let root = resolve_observation_cost_verifier_root(context, statement, treaty_id)?;
    if observation_cost_root_is_revoked(context, root) {
        return Err(PheromoneError::ObservationCostRevoked(
            root.body.verifier_key_id.clone(),
        ));
    }
    verify_observation_cost_signature(commitment, root)?;
    verify_observation_cost_leaf_and_inclusion(deposit, statement)?;
    Ok(())
}

fn validate_cost_commitment_static(
    commitment: &PheromoneCostCommitment,
) -> Result<(), PheromoneError> {
    if commitment.schema != PHEROMONE_COST_COMMITMENT_SCHEMA {
        return Err(PheromoneError::ObservationCostCommitmentSchemaInvalid(
            commitment.schema.clone(),
        ));
    }
    let statement = &commitment.statement;
    if statement.schema != PHEROMONE_OBSERVATION_COST_STATEMENT_SCHEMA {
        return Err(PheromoneError::ObservationCostCommitmentSchemaInvalid(
            statement.schema.clone(),
        ));
    }
    validate_non_empty(&statement.commitment_id, "cost commitment id")?;
    validate_non_empty(&statement.verifier_id, "cost verifier id")?;
    validate_non_empty(&statement.verifier_key_id, "cost verifier key id")?;
    validate_hex64(&statement.runtime_policy_sha256, "runtime_policy_sha256")?;
    validate_hex64(&statement.scarcity_policy_sha256, "scarcity_policy_sha256")?;
    validate_hex64(&statement.deposit_body_sha256, "deposit_body_sha256")?;
    validate_hex64(
        &statement.deposit_signature_sha256,
        "deposit_signature_sha256",
    )?;
    validate_non_empty(&statement.kernel_id, "cost kernel id")?;
    validate_non_empty(
        &statement.agent_passport_key_hash,
        "cost agent passport key hash",
    )?;
    validate_non_empty(&statement.treaty_id, "cost treaty id")?;
    validate_non_empty(
        &statement.subject_class_namespace,
        "cost subject class namespace",
    )?;
    validate_non_empty(&statement.subject_class, "cost subject class")?;
    validate_hex64(&statement.event_digest_sha256, "event_digest_sha256")?;
    validate_hex64(&statement.leaf_preimage_sha256, "leaf_preimage_sha256")?;
    if statement.observation_window_start_unix_ms >= statement.observation_window_end_unix_ms {
        return Err(PheromoneError::ObservationCostWindowMismatch(
            statement.commitment_id.clone(),
        ));
    }
    if statement.cost.unit != OBSERVATION_COST_UNIT || statement.cost.amount == 0 {
        return Err(PheromoneError::ObservationCostUnitInvalid(
            statement.commitment_id.clone(),
        ));
    }
    let telemetry = &statement.telemetry;
    if telemetry.schema != PHEROMONE_OBSERVATION_COST_TELEMETRY_ROOT_SCHEMA
        || telemetry.algorithm != OBSERVATION_COST_TELEMETRY_ALGORITHM
        || telemetry.tree_size == 0
        || telemetry.verifier_id != statement.verifier_id
        || telemetry.verifier_key_id != statement.verifier_key_id
    {
        return Err(PheromoneError::ObservationCostTelemetryRootMismatch(
            statement.commitment_id.clone(),
        ));
    }
    Ok(())
}

fn verify_observation_cost_policy_binding(
    deposit: &PheromoneDeposit,
    policy: &PheromoneScarcityPolicy,
    statement: &PheromoneObservationCostStatement,
    treaty_id: &str,
) -> Result<(), PheromoneError> {
    let body = &deposit.body;
    if statement.deposit_body_sha256 != deposit_signature_body_sha256(body)?
        || statement.deposit_signature_sha256 != deposit_signature_sha256(&deposit.signature)
        || statement.kernel_id != body.kernel_id
        || statement.agent_passport_key_hash != body.agent_passport_key_hash
        || statement.treaty_id != treaty_id
        || statement.subject_class_namespace != body.subject_class_namespace
        || statement.subject_class != body.subject_class
        || statement.verifier_id != policy.verifier_id
    {
        return Err(PheromoneError::ObservationCostPolicyMismatch(
            statement.commitment_id.clone(),
        ));
    }
    if statement.observation_window_start_unix_ms < policy.window_start_unix_ms
        || statement.observation_window_end_unix_ms > policy.window_end_unix_ms
        || statement.observed_at_unix_ms < statement.observation_window_start_unix_ms
        || statement.observed_at_unix_ms >= statement.observation_window_end_unix_ms
        || statement.telemetry.closed_at_unix_ms < statement.observation_window_start_unix_ms
        || statement.telemetry.closed_at_unix_ms >= statement.observation_window_end_unix_ms
    {
        return Err(PheromoneError::ObservationCostWindowMismatch(
            statement.commitment_id.clone(),
        ));
    }
    Ok(())
}

fn resolve_observation_cost_verifier_root<'a>(
    context: &'a PheromoneValidationContext,
    statement: &PheromoneObservationCostStatement,
    treaty_id: &str,
) -> Result<&'a PheromoneObservationCostVerifierRoot, PheromoneError> {
    let runtime_policy_sha256 = context.runtime_policy_sha256.as_deref().ok_or_else(|| {
        PheromoneError::ObservationCostRuntimePolicyMismatch(
            "runtime policy hash is absent from receiver context".to_string(),
        )
    })?;
    let matches = context
        .observation_cost_verifier_roots
        .iter()
        .filter(|root| {
            root.body.schema == PHEROMONE_OBSERVATION_COST_VERIFIER_ROOT_SCHEMA
                && root.body.verifier_id == statement.verifier_id
                && root.body.verifier_key_id == statement.verifier_key_id
                && root.body.runtime_policy_sha256 == runtime_policy_sha256
                && root.body.valid_from_unix_ms <= context.now_unix_ms
                && context.now_unix_ms < root.body.valid_until_unix_ms
                && root
                    .body
                    .allowed_treaties
                    .iter()
                    .any(|allowed| allowed == treaty_id)
                && root
                    .body
                    .allowed_subject_class_namespaces
                    .iter()
                    .any(|allowed| allowed == &statement.subject_class_namespace)
                && root
                    .body
                    .allowed_subject_classes
                    .iter()
                    .any(|allowed| allowed == &statement.subject_class)
                && root.body.signature_algorithm == root.body.public_key.algorithm()
                && verifier_root_issuer_signature_is_valid(context, root)
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [root] => Ok(*root),
        _ => Err(PheromoneError::ObservationCostVerifierUntrusted(
            statement.verifier_key_id.clone(),
        )),
    }
}

fn verifier_root_issuer_signature_is_valid(
    context: &PheromoneValidationContext,
    root: &PheromoneObservationCostVerifierRoot,
) -> bool {
    let Ok(canonical) = canonical_json_bytes(&root.body) else {
        return false;
    };
    context
        .runtime_policy_issuer_public_keys
        .iter()
        .any(|public_key| public_key.verify(&canonical, &root.issuer_signature))
}

fn observation_cost_root_is_revoked(
    context: &PheromoneValidationContext,
    root: &PheromoneObservationCostVerifierRoot,
) -> bool {
    context
        .runtime_trust_floor_state
        .entries
        .iter()
        .all(|entry| {
            entry.verifier_id != root.body.verifier_id
                || entry.key_id != root.body.verifier_key_id
                || entry.highest_version == 0
                || validate_hex64(&entry.latest_bundle_sha256, "latest_bundle_sha256").is_err()
                || validate_hex64(
                    &entry.latest_revocation_checkpoint_sha256,
                    "latest_revocation_checkpoint_sha256",
                )
                .is_err()
        })
}

fn verify_observation_cost_signature(
    commitment: &PheromoneCostCommitment,
    root: &PheromoneObservationCostVerifierRoot,
) -> Result<(), PheromoneError> {
    if commitment.signature.algorithm() != root.body.signature_algorithm {
        return Err(PheromoneError::ObservationCostSignatureInvalid(
            commitment.statement.commitment_id.clone(),
        ));
    }
    let canonical = canonical_json_bytes(&commitment.statement)
        .map_err(|error| PheromoneError::CanonicalJson(error.to_string()))?;
    if root
        .body
        .public_key
        .verify(&canonical, &commitment.signature)
    {
        Ok(())
    } else {
        Err(PheromoneError::ObservationCostSignatureInvalid(
            commitment.statement.commitment_id.clone(),
        ))
    }
}

fn verify_observation_cost_leaf_and_inclusion(
    deposit: &PheromoneDeposit,
    statement: &PheromoneObservationCostStatement,
) -> Result<(), PheromoneError> {
    if statement.telemetry.tree_size != statement.inclusion_proof.tree_size {
        return Err(PheromoneError::ObservationCostTelemetryRootMismatch(
            statement.commitment_id.clone(),
        ));
    }
    let leaf = PheromoneObservationCostLeaf {
        schema: PHEROMONE_OBSERVATION_COST_LEAF_SCHEMA.to_string(),
        deposit_body_sha256: deposit_signature_body_sha256(&deposit.body)?,
        deposit_signature_sha256: deposit_signature_sha256(&deposit.signature),
        kernel_id: statement.kernel_id.clone(),
        agent_passport_key_hash: statement.agent_passport_key_hash.clone(),
        treaty_id: statement.treaty_id.clone(),
        subject_class_namespace: statement.subject_class_namespace.clone(),
        subject_class: statement.subject_class.clone(),
        observed_at_unix_ms: statement.observed_at_unix_ms,
        event_digest_sha256: statement.event_digest_sha256.clone(),
        cost: statement.cost.clone(),
        scarcity_policy_sha256: statement.scarcity_policy_sha256.clone(),
        runtime_policy_sha256: statement.runtime_policy_sha256.clone(),
    };
    let leaf_bytes = canonical_json_bytes(&leaf)
        .map_err(|error| PheromoneError::CanonicalJson(error.to_string()))?;
    if sha256_hex_bytes(&leaf_bytes) != statement.leaf_preimage_sha256 {
        return Err(PheromoneError::ObservationCostLeafMismatch(
            statement.commitment_id.clone(),
        ));
    }
    if statement
        .inclusion_proof
        .verify(&leaf_bytes, &statement.telemetry.root_hash)
    {
        Ok(())
    } else {
        Err(PheromoneError::ObservationCostInclusionInvalid(
            statement.commitment_id.clone(),
        ))
    }
}

pub(crate) fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, PheromoneError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| PheromoneError::CanonicalJson(error.to_string()))?;
    Ok(sha256_hex_bytes(&canonical))
}

fn deposit_signature_body_sha256(body: &PheromoneDepositBody) -> Result<String, PheromoneError> {
    canonical_sha256(&deposit_signature_body(body))
}

fn deposit_signature_sha256(signature: &Signature) -> String {
    sha256_hex_bytes(signature.to_hex().as_bytes())
}

fn sha256_hex_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub(crate) fn newcomer_horizon_for_subject(
    context: &PheromoneValidationContext,
    reputation_epoch: u64,
    subject_class_namespace: &str,
    subject_class: &str,
) -> Result<u64, PheromoneError> {
    let mut horizon = None;
    for policy in context.scarcity_policies.iter().filter(|policy| {
        policy.reputation_epoch == reputation_epoch
            && policy.subject_class == subject_class
            && policy.subject_class_namespace == subject_class_namespace
    }) {
        validate_scarcity_policy_material(policy, context)?;
        if !scarcity_policy_is_active(policy, context) {
            continue;
        }
        match horizon {
            None => horizon = Some(policy.newcomer_horizon_epochs),
            Some(existing) if existing == policy.newcomer_horizon_epochs => {}
            Some(_) => {
                return Err(PheromoneError::ScarcityPolicyAmbiguous(format!(
                    "conflicting newcomer horizons for {subject_class_namespace}:{subject_class}"
                )))
            }
        }
    }
    Ok(horizon.unwrap_or(DEFAULT_NEWCOMER_DISCOUNT_HORIZON_EPOCHS))
}

pub(crate) fn strength_at(deposit: &PheromoneDeposit, now_unix_ms: u64) -> f64 {
    if now_unix_ms <= deposit.body.timestamp_unix_ms {
        return deposit.body.confidence;
    }
    let elapsed_secs = now_unix_ms.saturating_sub(deposit.body.timestamp_unix_ms) as f64 / 1000.0;
    deposit.body.confidence * 2_f64.powf(-(elapsed_secs / deposit.body.decay_half_life_secs))
}

fn sqrt_passport_cap(active_peers: u64) -> u64 {
    (active_peers.max(1) as f64).sqrt().ceil() as u64
}

fn validate_non_empty(value: &str, field: &str) -> Result<(), PheromoneError> {
    if value.trim().is_empty() || value.trim() != value {
        return Err(PheromoneError::InvalidField(format!(
            "{field} must be non-empty and unpadded"
        )));
    }
    Ok(())
}

fn validate_unique_non_empty_strings(values: &[String], field: &str) -> Result<(), PheromoneError> {
    if values.is_empty() {
        return Err(PheromoneError::InvalidField(format!(
            "{field} must not be empty"
        )));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_non_empty(value, field)?;
        if !seen.insert(value.as_str()) {
            return Err(PheromoneError::InvalidField(format!(
                "{field} contains duplicate value {value}"
            )));
        }
    }
    Ok(())
}

fn validate_hex64(value: &str, field: &str) -> Result<(), PheromoneError> {
    if !is_hex64_shape(value) {
        return Err(PheromoneError::InvalidField(format!(
            "{field} must be 64 lowercase hex characters"
        )));
    }
    if value.chars().any(|ch| ch.is_ascii_uppercase()) {
        return Err(PheromoneError::InvalidField(format!(
            "{field} must be lowercase hex"
        )));
    }
    Ok(())
}

fn is_hex64_shape(value: &str) -> bool {
    value.len() == 64 && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

#[cfg(test)]
mod tests {
    #[test]
    fn hex64_shape_helper_accepts_exact_ascii_hex_before_lowercase_validation() {
        assert!(super::is_hex64_shape(&"a".repeat(64)));
        assert!(super::is_hex64_shape(&"A".repeat(64)));
        assert!(!super::is_hex64_shape(&"a".repeat(63)));
        assert!(!super::is_hex64_shape(&format!("{}g", "a".repeat(63))));
    }
}
