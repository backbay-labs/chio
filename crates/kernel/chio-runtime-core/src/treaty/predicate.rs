use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::types::{
    BilateralInvocation, CrossBoundaryAdmissionReport, CrossKernelContinuation, TreatyScope,
};
use crate::{canonical_sha256, rejected, ChioRuntimeError};

use super::{
    bilateral_dsse_consistency_model, bilateral_invocation_binding_sha256, ladder_mode_rank,
    treaty_scope_sha256, validate_bilateral_invocation, validate_cross_boundary_admission_report,
    validate_cross_kernel_continuation, validate_treaty_scope,
};

pub const CHIO_BOUNDED_TREATY_PREDICATE_SCHEMA: &str =
    "chio.federation.bounded-treaty-predicate.v1";

const MAX_PREDICATE_DEPTH: usize = 32;
const MAX_PREDICATE_NODES: usize = 1_024;
const MAX_PREDICATE_JSON_BYTES: usize = 64 * 1_024;
const MAX_PREDICATE_ATOM_STRING_BYTES: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundedAdmissionDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoundedEvidenceDigest {
    pub evidence_class: String,
    pub digest: String,
}

/// Finite admission surface interpreted by the bounded treaty predicate.
///
/// Construction from production artifacts is restricted to
/// `bounded_treaty_receipt_view_from_verified_artifacts`. The type remains
/// public so the independent differential oracle can generate model inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoundedTreatyReceiptView {
    pub receipt_id: String,
    pub receipt_hash: String,
    pub action_class: String,
    pub participant_kernel_ids: Vec<String>,
    pub ladder_mode_rank: u64,
    pub live_continuation_ids: Vec<String>,
    pub decision: BoundedAdmissionDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub evidence_digests: Vec<BoundedEvidenceDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "tag",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum BoundedTreatyPredicateAtom {
    ScopeContains {
        target: String,
    },
    ParticipantKernelIdEquals {
        kernel_id: String,
    },
    ActionClassIn {
        class: String,
    },
    LadderModeAtLeastRank {
        rank: u64,
    },
    ReceiptHashEquals {
        hash: String,
    },
    ContinuationLive {
        continuation_id: String,
    },
    DecisionEquals {
        decision: BoundedAdmissionDecision,
    },
    FailureCodeEquals {
        code: String,
    },
    EvidenceDigestEquals {
        evidence_class: String,
        digest: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "op",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum BoundedTreatyPredicate {
    Atom {
        atom: BoundedTreatyPredicateAtom,
    },
    Top,
    Bot,
    Conj {
        left: Box<BoundedTreatyPredicate>,
        right: Box<BoundedTreatyPredicate>,
    },
    Disj {
        left: Box<BoundedTreatyPredicate>,
        right: Box<BoundedTreatyPredicate>,
    },
    Neg {
        predicate: Box<BoundedTreatyPredicate>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoundedTreatyPredicateDocument {
    pub schema: String,
    pub predicate: BoundedTreatyPredicate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoundedTreatyConstitution {
    pub predicates: Vec<BoundedTreatyPredicate>,
}

/// Parse and evaluate a serialized predicate. Malformed JSON, unknown fields,
/// unknown tags, unsupported versions, and complexity-limit violations deny.
#[must_use]
pub fn evaluate_bounded_treaty_predicate_json(
    json: &str,
    receipt: &BoundedTreatyReceiptView,
) -> bool {
    if json.len() > MAX_PREDICATE_JSON_BYTES {
        return false;
    }
    let Ok(canonical) = chio_core_types::canonical_json_bytes_from_str(json) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&canonical) else {
        return false;
    };
    if !document_json_shape_is_strict(&value) {
        return false;
    }
    serde_json::from_value::<BoundedTreatyPredicateDocument>(value)
        .ok()
        .is_some_and(|document| evaluate_bounded_treaty_predicate_document(&document, receipt))
}

/// Evaluate a versioned predicate document. Unsupported versions deny.
#[must_use]
pub fn evaluate_bounded_treaty_predicate_document(
    document: &BoundedTreatyPredicateDocument,
    receipt: &BoundedTreatyReceiptView,
) -> bool {
    document.schema == CHIO_BOUNDED_TREATY_PREDICATE_SCHEMA
        && evaluate_bounded_treaty_predicate(&document.predicate, receipt)
}

/// Executable counterpart to `ReceiptPredicate.evaluate` on the bounded Rust domain.
#[must_use]
pub fn evaluate_bounded_treaty_predicate(
    predicate: &BoundedTreatyPredicate,
    receipt: &BoundedTreatyReceiptView,
) -> bool {
    let mut nodes = 0;
    evaluate_predicate_checked(predicate, receipt, 0, &mut nodes).unwrap_or(false)
}

/// Executable counterpart to `ReceiptPredicate.admits`.
#[must_use]
pub fn evaluate_bounded_treaty_constitution(
    constitution: &BoundedTreatyConstitution,
    receipt: &BoundedTreatyReceiptView,
) -> bool {
    evaluate_constitution_checked(constitution, receipt).unwrap_or(false)
}

/// Executable counterpart to `ReceiptPredicate.refinesOn`.
///
/// The result is restricted to `domain`. An empty domain returns true, as in
/// Lean. A constitution outside the evaluator's complexity bound returns
/// false even when the domain is empty.
#[must_use]
pub fn bounded_treaty_constitution_refines_on(
    new: &BoundedTreatyConstitution,
    old: &BoundedTreatyConstitution,
    domain: &[BoundedTreatyReceiptView],
) -> bool {
    if !constitution_within_limits(new) || !constitution_within_limits(old) {
        return false;
    }
    domain.iter().all(|receipt| {
        let Some(new_admits) = evaluate_constitution_checked(new, receipt) else {
            return false;
        };
        let Some(old_admits) = evaluate_constitution_checked(old, receipt) else {
            return false;
        };
        !new_admits || old_admits
    })
}

/// Construct the bounded view from artifacts that pass the production
/// validators and cross-artifact bindings. No request-supplied policy field is
/// accepted by this constructor. `expected_admission_report_sha256` must come
/// from an independently authenticated binding to the canonical admission
/// report, such as a verified bilateral DSSE treaty binding.
pub fn bounded_treaty_receipt_view_from_verified_artifacts(
    treaty_scope: &TreatyScope,
    report: &CrossBoundaryAdmissionReport,
    expected_admission_report_sha256: &str,
    invocation: &BilateralInvocation,
    continuation: &CrossKernelContinuation,
    now_unix_ms: u64,
) -> Result<BoundedTreatyReceiptView, ChioRuntimeError> {
    validate_treaty_scope(treaty_scope)?;
    validate_cross_boundary_admission_report(report)?;
    validate_bilateral_invocation(invocation)?;
    validate_cross_kernel_continuation(continuation)?;

    if now_unix_ms < treaty_scope.issued_at_unix_ms
        || now_unix_ms >= treaty_scope.expires_at_unix_ms
    {
        return rejected("chio_treaty_stale", "bounded treaty view scope is not live");
    }

    if canonical_sha256(report)? != expected_admission_report_sha256 {
        return rejected(
            "chio_treaty_admission_report_hash_mismatch",
            "bounded treaty view admission report does not match its authenticated binding",
        );
    }

    let invocation_sha256 = bilateral_invocation_binding_sha256(invocation)?;
    let mut invocation_evidence = report
        .verified_evidence
        .iter()
        .filter(|evidence| evidence.evidence_class == "bilateral_invocation");
    let Some(bound_invocation) = invocation_evidence.next() else {
        return rejected(
            "chio_treaty_bilateral_hash_mismatch",
            "bounded treaty view admission report is missing bilateral invocation evidence",
        );
    };
    if invocation_evidence.next().is_some()
        || !bound_invocation.verified
        || bound_invocation.artifact_sha256 != invocation_sha256
    {
        return rejected(
            "chio_treaty_bilateral_hash_mismatch",
            "bounded treaty view invocation does not match the admission report evidence",
        );
    }

    let expected_scope_sha256 = treaty_scope_sha256(treaty_scope)?;
    if report.treaty_scope_sha256 != expected_scope_sha256
        || report.treaty_id != treaty_scope.treaty_id
        || invocation.treaty_id != treaty_scope.treaty_id
    {
        return rejected(
            "chio_treaty_scope_hash_mismatch",
            "bounded treaty view artifacts do not bind the same treaty scope",
        );
    }
    if report.ladder_intersection_sha256 != invocation.ladder_intersection_sha256
        || report.action_class_id != invocation.action_class_id
        || bilateral_dsse_consistency_model(&report.consistency_model)?
            != bilateral_dsse_consistency_model(&invocation.consistency_model)?
    {
        return rejected(
            "chio_treaty_intersection_mismatch",
            "bounded treaty view artifacts do not bind the same admission decision",
        );
    }
    if !treaty_scope
        .allowed_action_classes
        .iter()
        .any(|allowed| allowed == &report.action_class_id)
    {
        return rejected(
            "chio_treaty_action_class_not_allowed",
            "bounded treaty view action class is outside the treaty scope",
        );
    }

    let participant_kernels: BTreeSet<_> = treaty_scope.participant_kernel_ids.iter().collect();
    let signer_kernels: BTreeSet<_> = invocation.signer_kernel_ids.iter().collect();
    if participant_kernels != signer_kernels {
        return rejected(
            "bilateral_invocation_signer_count_mismatch",
            "bounded treaty view signers do not equal the treaty participants",
        );
    }

    let continuation_sha256 = canonical_sha256(continuation)?;
    if invocation.continuation_sha256 != continuation_sha256
        || invocation.capability_id != continuation.capability_id
        || continuation.action_class_id != report.action_class_id
        || now_unix_ms < continuation.issued_at_unix_ms
        || now_unix_ms >= continuation.expires_at_unix_ms
    {
        return rejected(
            "chio_treaty_continuation_hash_mismatch",
            "bounded treaty view continuation is unbound or not live",
        );
    }
    let continuation_kernels = BTreeSet::from([
        &continuation.source_kernel_id,
        &continuation.target_kernel_id,
    ]);
    if continuation_kernels != participant_kernels {
        return rejected(
            "chio_treaty_continuation_origin_mismatch",
            "bounded treaty view continuation kernels do not equal the treaty participants",
        );
    }

    Ok(BoundedTreatyReceiptView {
        // The production bilateral surface exposes content-addressed receipt
        // hashes, so the local receipt hash is also the bounded receipt ID.
        receipt_id: invocation.local_receipt_sha256.clone(),
        receipt_hash: invocation.local_receipt_sha256.clone(),
        action_class: report.action_class_id.clone(),
        participant_kernel_ids: treaty_scope.participant_kernel_ids.clone(),
        ladder_mode_rank: u64::from(ladder_mode_rank(&report.mode)?),
        live_continuation_ids: vec![continuation.continuation_id.clone()],
        decision: if report.accepted {
            BoundedAdmissionDecision::Allow
        } else {
            BoundedAdmissionDecision::Deny
        },
        failure_code: report.failure_code.clone(),
        evidence_digests: report
            .verified_evidence
            .iter()
            .filter(|evidence| evidence.verified)
            .map(|evidence| BoundedEvidenceDigest {
                evidence_class: evidence.evidence_class.clone(),
                digest: evidence.artifact_sha256.clone(),
            })
            .collect(),
    })
}

fn evaluate_atom(atom: &BoundedTreatyPredicateAtom, receipt: &BoundedTreatyReceiptView) -> bool {
    match atom {
        BoundedTreatyPredicateAtom::ScopeContains { target } => receipt.receipt_id == *target,
        BoundedTreatyPredicateAtom::ParticipantKernelIdEquals { kernel_id } => {
            receipt.participant_kernel_ids.contains(kernel_id)
        }
        BoundedTreatyPredicateAtom::ActionClassIn { class } => receipt.action_class == *class,
        BoundedTreatyPredicateAtom::LadderModeAtLeastRank { rank } => {
            *rank <= receipt.ladder_mode_rank
        }
        BoundedTreatyPredicateAtom::ReceiptHashEquals { hash } => receipt.receipt_hash == *hash,
        BoundedTreatyPredicateAtom::ContinuationLive { continuation_id } => {
            receipt.live_continuation_ids.contains(continuation_id)
        }
        BoundedTreatyPredicateAtom::DecisionEquals { decision } => receipt.decision == *decision,
        BoundedTreatyPredicateAtom::FailureCodeEquals { code } => {
            receipt.failure_code.as_ref() == Some(code)
        }
        BoundedTreatyPredicateAtom::EvidenceDigestEquals {
            evidence_class,
            digest,
        } => receipt.evidence_digests.iter().any(|evidence| {
            evidence.evidence_class == *evidence_class && evidence.digest == *digest
        }),
    }
}

fn evaluate_predicate_checked(
    predicate: &BoundedTreatyPredicate,
    receipt: &BoundedTreatyReceiptView,
    depth: usize,
    nodes: &mut usize,
) -> Option<bool> {
    if depth > MAX_PREDICATE_DEPTH || *nodes >= MAX_PREDICATE_NODES {
        return None;
    }
    *nodes += 1;
    match predicate {
        BoundedTreatyPredicate::Atom { atom } => {
            atom_within_limits(atom).then(|| evaluate_atom(atom, receipt))
        }
        BoundedTreatyPredicate::Top => Some(true),
        BoundedTreatyPredicate::Bot => Some(false),
        BoundedTreatyPredicate::Conj { left, right } => {
            let left_value = evaluate_predicate_checked(left, receipt, depth + 1, nodes)?;
            let right_value = evaluate_predicate_checked(right, receipt, depth + 1, nodes)?;
            Some(left_value && right_value)
        }
        BoundedTreatyPredicate::Disj { left, right } => {
            let left_value = evaluate_predicate_checked(left, receipt, depth + 1, nodes)?;
            let right_value = evaluate_predicate_checked(right, receipt, depth + 1, nodes)?;
            Some(left_value || right_value)
        }
        BoundedTreatyPredicate::Neg { predicate } => {
            evaluate_predicate_checked(predicate, receipt, depth + 1, nodes).map(|value| !value)
        }
    }
}

fn evaluate_constitution_checked(
    constitution: &BoundedTreatyConstitution,
    receipt: &BoundedTreatyReceiptView,
) -> Option<bool> {
    let mut nodes = 0;
    let mut result = true;
    for predicate in &constitution.predicates {
        let value = evaluate_predicate_checked(predicate, receipt, 0, &mut nodes)?;
        result = result && value;
    }
    Some(result)
}

fn constitution_within_limits(constitution: &BoundedTreatyConstitution) -> bool {
    let mut nodes = 0;
    constitution
        .predicates
        .iter()
        .all(|predicate| count_predicate_nodes(predicate, 0, &mut nodes))
}

fn count_predicate_nodes(
    predicate: &BoundedTreatyPredicate,
    depth: usize,
    nodes: &mut usize,
) -> bool {
    if depth > MAX_PREDICATE_DEPTH || *nodes >= MAX_PREDICATE_NODES {
        return false;
    }
    *nodes += 1;
    match predicate {
        BoundedTreatyPredicate::Atom { atom } => atom_within_limits(atom),
        BoundedTreatyPredicate::Top | BoundedTreatyPredicate::Bot => true,
        BoundedTreatyPredicate::Conj { left, right }
        | BoundedTreatyPredicate::Disj { left, right } => {
            count_predicate_nodes(left, depth + 1, nodes)
                && count_predicate_nodes(right, depth + 1, nodes)
        }
        BoundedTreatyPredicate::Neg { predicate } => {
            count_predicate_nodes(predicate, depth + 1, nodes)
        }
    }
}

fn document_json_shape_is_strict(value: &serde_json::Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.len() != 2 || !object.contains_key("schema") || !object.contains_key("predicate") {
        return false;
    }
    let mut nodes = 0;
    object
        .get("predicate")
        .is_some_and(|predicate| predicate_json_shape_is_strict(predicate, 0, &mut nodes))
}

fn predicate_json_shape_is_strict(
    value: &serde_json::Value,
    depth: usize,
    nodes: &mut usize,
) -> bool {
    if depth > MAX_PREDICATE_DEPTH || *nodes >= MAX_PREDICATE_NODES {
        return false;
    }
    *nodes += 1;
    let Some(object) = value.as_object() else {
        return false;
    };
    let Some(operation) = object.get("op").and_then(serde_json::Value::as_str) else {
        return false;
    };
    match operation {
        "top" | "bot" => object.len() == 1,
        "atom" => object.len() == 2 && object.get("atom").is_some_and(atom_json_shape_is_strict),
        "conj" | "disj" => {
            object.len() == 3
                && object.contains_key("left")
                && object.contains_key("right")
                && object
                    .get("left")
                    .is_some_and(|left| predicate_json_shape_is_strict(left, depth + 1, nodes))
                && object
                    .get("right")
                    .is_some_and(|right| predicate_json_shape_is_strict(right, depth + 1, nodes))
        }
        "neg" => {
            object.len() == 2
                && object.get("predicate").is_some_and(|predicate| {
                    predicate_json_shape_is_strict(predicate, depth + 1, nodes)
                })
        }
        _ => false,
    }
}

fn atom_json_shape_is_strict(value: &serde_json::Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let Some(tag) = object.get("tag").and_then(serde_json::Value::as_str) else {
        return false;
    };
    match tag {
        "scope_contains" => object.len() == 2 && bounded_string_field(object, "target"),
        "participant_kernel_id_equals" => {
            object.len() == 2 && bounded_string_field(object, "kernelId")
        }
        "action_class_in" => object.len() == 2 && bounded_string_field(object, "class"),
        "ladder_mode_at_least_rank" => {
            object.len() == 2 && object.get("rank").is_some_and(serde_json::Value::is_u64)
        }
        "receipt_hash_equals" => object.len() == 2 && bounded_string_field(object, "hash"),
        "continuation_live" => object.len() == 2 && bounded_string_field(object, "continuationId"),
        "decision_equals" => object.len() == 2 && bounded_string_field(object, "decision"),
        "failure_code_equals" => object.len() == 2 && bounded_string_field(object, "code"),
        "evidence_digest_equals" => {
            object.len() == 3
                && bounded_string_field(object, "evidenceClass")
                && bounded_string_field(object, "digest")
        }
        _ => false,
    }
}

fn bounded_string_field(object: &serde_json::Map<String, serde_json::Value>, key: &str) -> bool {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value.len() <= MAX_PREDICATE_ATOM_STRING_BYTES)
}

fn atom_within_limits(atom: &BoundedTreatyPredicateAtom) -> bool {
    let bounded = |value: &str| value.len() <= MAX_PREDICATE_ATOM_STRING_BYTES;
    match atom {
        BoundedTreatyPredicateAtom::ScopeContains { target } => bounded(target),
        BoundedTreatyPredicateAtom::ParticipantKernelIdEquals { kernel_id } => bounded(kernel_id),
        BoundedTreatyPredicateAtom::ActionClassIn { class } => bounded(class),
        BoundedTreatyPredicateAtom::LadderModeAtLeastRank { .. }
        | BoundedTreatyPredicateAtom::DecisionEquals { .. } => true,
        BoundedTreatyPredicateAtom::ReceiptHashEquals { hash } => bounded(hash),
        BoundedTreatyPredicateAtom::ContinuationLive { continuation_id } => {
            bounded(continuation_id)
        }
        BoundedTreatyPredicateAtom::FailureCodeEquals { code } => bounded(code),
        BoundedTreatyPredicateAtom::EvidenceDigestEquals {
            evidence_class,
            digest,
        } => bounded(evidence_class) && bounded(digest),
    }
}
