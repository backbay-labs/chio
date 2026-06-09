//! Decision receipts for HushSpec evaluation.
//!
//! Ported from the HushSpec reference implementation. Wraps `evaluate()` with
//! timing, policy hashing, and a structured receipt.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;
use uuid::Uuid;

use crate::evaluate::{evaluate, Decision, EvaluationAction, PostureResult};
use crate::models::HushSpec;
use crate::version::HUSHSPEC_VERSION;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionReceipt {
    pub receipt_id: String,
    pub timestamp: String,
    pub hushspec_version: String,
    pub action: ActionSummary,
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub policy: PolicySummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<PostureResult>,
    pub evaluation_duration_us: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSummary {
    #[serde(rename = "type")]
    pub action_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub content_redacted: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub version: String,
    /// SHA-256 hex digest of the canonical JSON serialization.
    pub content_hash: String,
}

#[derive(Clone, Debug)]
pub struct AuditConfig {
    pub enabled: bool,
    pub redact_content: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            redact_content: true,
        }
    }
}

/// Wrap `evaluate()` with timing and policy hashing.
pub fn evaluate_audited(
    spec: &HushSpec,
    action: &EvaluationAction,
    config: &AuditConfig,
) -> DecisionReceipt {
    let start = if config.enabled {
        Some(Instant::now())
    } else {
        None
    };

    let result = evaluate(spec, action);

    let duration_us = start.map(|s| s.elapsed().as_micros() as u64).unwrap_or(0);

    let policy = if config.enabled {
        build_policy_summary(spec)
    } else {
        PolicySummary {
            name: spec.name.clone(),
            version: spec.hushspec.clone(),
            content_hash: String::new(),
        }
    };

    let action_summary = ActionSummary {
        action_type: action.action_type.clone(),
        target: action.target.clone(),
        content_redacted: config.redact_content && action.content.is_some(),
    };

    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    DecisionReceipt {
        receipt_id: Uuid::new_v4().to_string(),
        timestamp,
        hushspec_version: HUSHSPEC_VERSION.to_string(),
        action: action_summary,
        decision: result.decision,
        matched_rule: result.matched_rule,
        reason: result.reason,
        policy,
        origin_profile: result.origin_profile,
        posture: result.posture,
        evaluation_duration_us: duration_us,
    }
}

fn build_policy_summary(spec: &HushSpec) -> PolicySummary {
    let content_hash = compute_policy_hash(spec);
    PolicySummary {
        name: spec.name.clone(),
        version: spec.hushspec.clone(),
        content_hash,
    }
}

/// SHA-256 hex digest of the canonical JSON serialization.
pub fn compute_policy_hash(spec: &HushSpec) -> String {
    let json = serde_json::to_string(spec).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DefaultAction, HushSpec, Rules, ToolAccessRule};

    fn allow_spec() -> HushSpec {
        HushSpec {
            hushspec: "1.0".to_string(),
            name: Some("receipt-tests".to_string()),
            description: None,
            extends: None,
            merge_strategy: None,
            rules: Some(Rules {
                tool_access: Some(ToolAccessRule {
                    enabled: true,
                    allow: vec!["mail.send".to_string()],
                    block: Vec::new(),
                    require_confirmation: Vec::new(),
                    default: DefaultAction::Block,
                    max_args_size: None,
                    require_runtime_assurance_tier: None,
                    prefer_runtime_assurance_tier: None,
                    require_workload_identity: None,
                    prefer_workload_identity: None,
                }),
                ..Rules::default()
            }),
            extensions: None,
            metadata: None,
        }
    }

    #[test]
    fn audited_receipts_hash_policies_and_redact_content() {
        let spec = allow_spec();
        let receipt = evaluate_audited(
            &spec,
            &EvaluationAction {
                action_type: "tool_call".to_string(),
                target: Some("mail.send".to_string()),
                content: Some("secret payload".to_string()),
                origin: None,
                posture: None,
                args_size: None,
                runtime_attestation: None,
            },
            &AuditConfig::default(),
        );

        assert_eq!(receipt.decision, Decision::Allow);
        assert!(receipt.action.content_redacted);
        assert_eq!(receipt.policy.content_hash, compute_policy_hash(&spec));
        assert!(!receipt.receipt_id.is_empty());
        assert!(receipt.timestamp.ends_with('Z'));
    }

    #[test]
    fn disabled_audit_skips_timing_and_policy_hashes() {
        let receipt = evaluate_audited(
            &allow_spec(),
            &EvaluationAction {
                action_type: "tool_call".to_string(),
                target: Some("mail.send".to_string()),
                content: Some("visible payload".to_string()),
                origin: None,
                posture: None,
                args_size: None,
                runtime_attestation: None,
            },
            &AuditConfig {
                enabled: false,
                redact_content: false,
            },
        );

        assert_eq!(receipt.evaluation_duration_us, 0);
        assert!(receipt.policy.content_hash.is_empty());
        assert!(!receipt.action.content_redacted);
    }

    #[test]
    fn policy_summary_helpers_are_stable_and_defaults_are_enabled() {
        let spec = allow_spec();
        let summary = build_policy_summary(&spec);

        assert!(AuditConfig::default().enabled);
        assert!(AuditConfig::default().redact_content);
        assert_eq!(summary.name.as_deref(), Some("receipt-tests"));
        assert_eq!(summary.version, "1.0");
        assert_eq!(summary.content_hash, compute_policy_hash(&spec));
        assert_eq!(compute_policy_hash(&spec), compute_policy_hash(&spec));
    }

    #[test]
    fn disabled_audit_still_preserves_policy_metadata_and_targets() {
        let receipt = evaluate_audited(
            &allow_spec(),
            &EvaluationAction {
                action_type: "tool_call".to_string(),
                target: Some("mail.send".to_string()),
                content: None,
                origin: None,
                posture: None,
                args_size: None,
                runtime_attestation: None,
            },
            &AuditConfig {
                enabled: false,
                redact_content: true,
            },
        );

        assert_eq!(receipt.action.target.as_deref(), Some("mail.send"));
        assert!(!receipt.action.content_redacted);
        assert_eq!(receipt.policy.name.as_deref(), Some("receipt-tests"));
        assert_eq!(receipt.policy.version, "1.0");
        assert!(receipt.policy.content_hash.is_empty());
    }

    #[test]
    fn audited_receipts_preserve_policy_denials() {
        let spec = HushSpec {
            hushspec: "1.0".to_string(),
            name: Some("deny-tests".to_string()),
            description: None,
            extends: None,
            merge_strategy: None,
            rules: Some(Rules {
                tool_access: Some(ToolAccessRule {
                    enabled: true,
                    allow: Vec::new(),
                    block: Vec::new(),
                    require_confirmation: Vec::new(),
                    default: DefaultAction::Block,
                    max_args_size: None,
                    require_runtime_assurance_tier: None,
                    prefer_runtime_assurance_tier: None,
                    require_workload_identity: None,
                    prefer_workload_identity: None,
                }),
                ..Rules::default()
            }),
            extensions: None,
            metadata: None,
        };

        let receipt = evaluate_audited(
            &spec,
            &EvaluationAction {
                action_type: "tool_call".to_string(),
                target: Some("mail.send".to_string()),
                content: None,
                origin: None,
                posture: None,
                args_size: None,
                runtime_attestation: None,
            },
            &AuditConfig::default(),
        );

        assert_eq!(receipt.decision, Decision::Deny);
        assert_eq!(
            receipt.matched_rule.as_deref(),
            Some("rules.tool_access.default")
        );
        assert!(receipt
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("default block")));
    }
}
