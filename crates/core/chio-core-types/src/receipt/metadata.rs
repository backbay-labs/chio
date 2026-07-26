use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::capability::{
    governance::ProvenanceEvidenceClass,
    scope::{ModelMetadata, ModelSafetyTier},
};
use crate::error::{Error, Result};

use super::decision::Decision;
use super::kinds::{BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin};

/// Actor reference carried by signed receipt semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ActorRef {
    pub actor_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_kind: Option<String>,
}

/// Signed v1 semantic fields used by UI, SIEM, and bridge admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReceiptSemanticFields {
    pub receipt_kind: ReceiptKind,
    pub boundary_class: BoundaryClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_outcome: Option<ObservationOutcome>,
    pub tool_origin: ToolOrigin,
    pub redaction_mode: RedactionMode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actor_chain: Vec<ActorRef>,
}

impl ReceiptSemanticFields {
    #[must_use]
    pub fn mediated_prevent() -> Self {
        Self {
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
        }
    }

    #[must_use]
    pub fn trace_detect_only() -> Self {
        Self {
            receipt_kind: ReceiptKind::TraceObservation,
            boundary_class: BoundaryClass::DetectOnly,
            observation_outcome: Some(ObservationOutcome::Observed),
            tool_origin: ToolOrigin::HostExecutedProviderReported,
            redaction_mode: RedactionMode::Summary,
            actor_chain: Vec::new(),
        }
    }

    #[must_use]
    pub fn advisory_only() -> Self {
        Self {
            receipt_kind: ReceiptKind::AdvisoryEvaluation,
            boundary_class: BoundaryClass::AdvisoryOnly,
            observation_outcome: Some(ObservationOutcome::Evaluated),
            tool_origin: ToolOrigin::HostExecutedUnmediated,
            redaction_mode: RedactionMode::Redacted,
            actor_chain: Vec::new(),
        }
    }

    /// Strict decision compatibility check for v1 signed semantics.
    pub fn validate_decision(&self, decision: Option<&Decision>) -> Result<()> {
        if self.boundary_class == BoundaryClass::CannotSee {
            return Err(Error::CanonicalJson(format!(
                "{} receipts cannot use cannot_see as a signed runtime boundary",
                self.receipt_kind.as_str()
            )));
        }
        match (
            self.receipt_kind,
            self.boundary_class,
            self.observation_outcome,
            decision,
        ) {
            (ReceiptKind::MediatedDecision, BoundaryClass::Prevent, None, Some(_)) => Ok(()),
            (ReceiptKind::MediatedDecision, _, _, _) => Err(Error::CanonicalJson(
                "mediated_decision receipts require a prevent boundary, no observation outcome, and a decision"
                    .to_string(),
            )),
            (
                ReceiptKind::TraceObservation,
                BoundaryClass::DetectOnly,
                Some(_),
                None,
            ) => Ok(()),
            (ReceiptKind::TraceObservation, _, _, Some(decision)) => {
                Err(Error::CanonicalJson(format!(
                    "trace_observation receipts must not carry {:?} as an authorization decision",
                    decision
                )))
            }
            (ReceiptKind::TraceObservation, _, _, None) => Err(Error::CanonicalJson(
                "trace_observation receipts require detect_only boundary and observation outcome"
                    .to_string(),
            )),
            (
                ReceiptKind::AdvisoryEvaluation,
                BoundaryClass::AdvisoryOnly,
                Some(_),
                None,
            ) => Ok(()),
            (ReceiptKind::AdvisoryEvaluation, _, _, Some(decision)) => {
                Err(Error::CanonicalJson(format!(
                    "advisory_evaluation receipts must not carry {:?} as an authorization decision",
                    decision
                )))
            }
            (ReceiptKind::AdvisoryEvaluation, _, _, None) => Err(Error::CanonicalJson(
                "advisory_evaluation receipts require advisory_only boundary and observation outcome"
                    .to_string(),
            )),
        }
    }

    #[must_use]
    pub fn is_authorized(&self, decision: Option<&Decision>) -> bool {
        self.receipt_kind == ReceiptKind::MediatedDecision
            && self.boundary_class == BoundaryClass::Prevent
            && self.observation_outcome.is_none()
            && matches!(decision, Some(Decision::Allow))
    }

    #[must_use]
    pub fn result_label(&self, decision: Option<&Decision>) -> &'static str {
        if self.is_authorized(decision) {
            return "Authorized";
        }
        match self.receipt_kind {
            ReceiptKind::TraceObservation => "Observed",
            ReceiptKind::AdvisoryEvaluation => "Advisory",
            ReceiptKind::MediatedDecision => match decision {
                Some(Decision::Allow) => "Allowed",
                Some(Decision::Deny { .. }) => "Denied",
                Some(Decision::Cancelled { .. }) => "Cancelled",
                Some(Decision::Incomplete { .. }) => "Incomplete",
                None => "Invalid",
            },
        }
    }
}

/// Explicit model-routing context attached to a receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ModelMetadataReceiptMetadata {
    pub model_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safety_tier: Option<ModelSafetyTier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    pub provenance_class: ProvenanceEvidenceClass,
}

impl From<&ModelMetadata> for ModelMetadataReceiptMetadata {
    fn from(value: &ModelMetadata) -> Self {
        Self {
            model_id: value.model_id.clone(),
            safety_tier: value.safety_tier,
            provider: value.provider.clone(),
            provenance_class: value.provenance_class,
        }
    }
}

/// Evidence from a single guard's evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardEvidence {
    /// Name of the guard (e.g. "ForbiddenPathGuard").
    pub guard_name: String,
    /// Whether the guard passed (true) or denied (false).
    pub verdict: bool,
    /// Optional details about the guard's decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Universal receipt-side attribution for capability context.
///
/// This metadata gives downstream analytics a deterministic local join path
/// from a receipt to the capability subject and, when available, the matched
/// grant within the capability scope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptAttributionMetadata {
    /// Hex-encoded subject public key of the capability holder.
    pub subject_key: String,
    /// Hex-encoded issuer public key of the capability issuer.
    pub issuer_key: String,
    /// Delegation depth of the capability used for this receipt.
    pub delegation_depth: u32,
    /// Index of the matched grant when the request resolved to a specific grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_index: Option<u32>,
}
