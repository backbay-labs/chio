use chio_core::{chio_receipt_id, ChioReceipt, Decision, PublicKey};
use serde::{Deserialize, Serialize};

use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptDecisionKind {
    Allow,
    Deny,
    Cancelled,
    Incomplete,
    None,
}

impl From<Option<&Decision>> for ReceiptDecisionKind {
    fn from(value: Option<&Decision>) -> Self {
        match value {
            Some(Decision::Allow) => Self::Allow,
            Some(Decision::Deny { .. }) => Self::Deny,
            Some(Decision::Cancelled { .. }) => Self::Cancelled,
            Some(Decision::Incomplete { .. }) => Self::Incomplete,
            None => Self::None,
        }
    }
}

fn binding_result_label(
    receipt_kind: &str,
    boundary_class: &str,
    decision: ReceiptDecisionKind,
) -> &'static str {
    if receipt_kind == "mediated_decision"
        && boundary_class == "prevent"
        && decision == ReceiptDecisionKind::Allow
    {
        return "Authorized";
    }
    match receipt_kind {
        "trace_observation" => "Observed",
        "advisory_evaluation" => "Advisory",
        _ => match decision {
            ReceiptDecisionKind::Allow => "Allowed",
            ReceiptDecisionKind::Deny => "Denied",
            ReceiptDecisionKind::Cancelled => "Cancelled",
            ReceiptDecisionKind::Incomplete => "Incomplete",
            ReceiptDecisionKind::None => "Invalid",
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptVerification {
    pub signature_valid: bool,
    pub parameter_hash_valid: bool,
    pub receipt_id_valid: bool,
    pub decision: ReceiptDecisionKind,
    pub receipt_kind: String,
    pub boundary_class: String,
    pub trust_level: String,
    pub result: String,
    pub authorized: bool,
    pub signer_key_hex: String,
    pub signer_trusted: bool,
    pub ok: bool,
}

pub fn parse_receipt_json(input: &str) -> Result<ChioReceipt> {
    Ok(serde_json::from_str(input)?)
}

pub fn receipt_body_canonical_json(receipt: &ChioReceipt) -> Result<String> {
    Ok(chio_core::canonical_json_string(&receipt.body())?)
}

pub fn verify_receipt(receipt: &ChioReceipt) -> Result<ReceiptVerification> {
    verify_receipt_with_trusted_signers(receipt, &[])
}

pub fn verify_receipt_with_trusted_signers(
    receipt: &ChioReceipt,
    trusted_signers: &[PublicKey],
) -> Result<ReceiptVerification> {
    let receipt_id_valid = chio_receipt_id(&receipt.body())? == receipt.id;
    let semantics = receipt.semantic_fields();
    let semantic_authorized = semantics.is_authorized(receipt.decision.as_ref());
    let decision = ReceiptDecisionKind::from(receipt.decision.as_ref());
    let receipt_kind = semantics.receipt_kind.as_str().to_string();
    let boundary_class = semantics.boundary_class.as_str().to_string();
    let signature_valid = receipt.verify_signature()?;
    let parameter_hash_valid = receipt.action.verify_hash()?;
    let signer_trusted = !trusted_signers.is_empty()
        && trusted_signers
            .iter()
            .any(|signer| signer == &receipt.kernel_key);
    let authorized = semantic_authorized
        && signature_valid
        && parameter_hash_valid
        && receipt_id_valid
        && signer_trusted;
    Ok(ReceiptVerification {
        signature_valid,
        parameter_hash_valid,
        receipt_id_valid,
        decision,
        receipt_kind: receipt_kind.clone(),
        boundary_class: boundary_class.clone(),
        trust_level: receipt.trust_level.as_str().to_string(),
        result: binding_result_label(&receipt_kind, &boundary_class, decision).to_string(),
        authorized,
        signer_key_hex: receipt.kernel_key.to_hex(),
        signer_trusted,
        ok: signature_valid && parameter_hash_valid && receipt_id_valid && signer_trusted,
    })
}

pub fn verify_receipt_with_trusted_signer_hex<S: AsRef<str>>(
    receipt: &ChioReceipt,
    trusted_signer_hex: &[S],
) -> Result<ReceiptVerification> {
    let trusted_signers = parse_trusted_signer_hex(trusted_signer_hex)?;
    verify_receipt_with_trusted_signers(receipt, &trusted_signers)
}

pub fn verify_receipt_json(input: &str) -> Result<ReceiptVerification> {
    let receipt = parse_receipt_json(input)?;
    verify_receipt(&receipt)
}

pub fn verify_receipt_json_with_trusted_signer_hex<S: AsRef<str>>(
    input: &str,
    trusted_signer_hex: &[S],
) -> Result<ReceiptVerification> {
    let receipt = parse_receipt_json(input)?;
    verify_receipt_with_trusted_signer_hex(&receipt, trusted_signer_hex)
}

fn parse_trusted_signer_hex<S: AsRef<str>>(trusted_signer_hex: &[S]) -> Result<Vec<PublicKey>> {
    trusted_signer_hex
        .iter()
        .map(|value| PublicKey::from_hex(value.as_ref()).map_err(Into::into))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        verify_receipt, verify_receipt_json_with_trusted_signer_hex,
        verify_receipt_with_trusted_signer_hex, ReceiptDecisionKind,
    };
    use chio_core::{
        sha256_hex, ChioReceipt, ChioReceiptBody, Decision, GuardEvidence, Keypair, ToolCallAction,
    };

    fn sample_receipt() -> crate::Result<ChioReceipt> {
        let seed = [7u8; 32];
        let keypair = Keypair::from_seed(&seed);
        let action = ToolCallAction::from_parameters(serde_json::json!({
            "path": "/workspace/docs/roadmap.md",
            "mode": "read"
        }))?;
        let body = ChioReceiptBody {
            id: "rcpt-bindings-allow".to_string(),
            timestamp: 1710000100,
            capability_id: "cap-bindings-001".to_string(),
            tool_server: "srv-files".to_string(),
            tool_name: "file_read".to_string(),
            action,
            decision: Some(Decision::Allow),
            receipt_kind: chio_core::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: sha256_hex(br#"{"ok":true}"#),
            policy_hash: "policy-bindings-v1".to_string(),
            evidence: vec![GuardEvidence {
                guard_name: "ForbiddenPathGuard".to_string(),
                verdict: true,
                details: Some("path allowed".to_string()),
            }],
            metadata: Some(serde_json::json!({
                "surface": "bindings-test"
            })),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        };
        Ok(ChioReceipt::sign(body, &keypair)?)
    }

    #[test]
    fn verify_valid_receipt() -> crate::Result<()> {
        let receipt = sample_receipt()?;
        let verification = verify_receipt(&receipt)?;
        assert!(verification.signature_valid);
        assert!(verification.parameter_hash_valid);
        assert!(verification.receipt_id_valid);
        assert_eq!(verification.decision, ReceiptDecisionKind::Allow);
        assert_eq!(verification.receipt_kind, "mediated_decision");
        assert_eq!(verification.boundary_class, "prevent");
        assert_eq!(verification.trust_level, "mediated");
        assert_eq!(verification.result, "Authorized");
        assert!(!verification.authorized);
        assert!(!verification.signer_trusted);
        assert!(!verification.ok);
        assert_eq!(verification.signer_key_hex, receipt.kernel_key.to_hex());
        Ok(())
    }

    #[test]
    fn verify_valid_receipt_with_trusted_signer_is_ok() -> crate::Result<()> {
        let receipt = sample_receipt()?;
        let verification = super::verify_receipt_with_trusted_signers(
            &receipt,
            std::slice::from_ref(&receipt.kernel_key),
        )?;
        assert!(verification.signer_trusted);
        assert!(verification.ok);
        assert!(verification.authorized);
        Ok(())
    }

    #[test]
    fn verify_valid_receipt_with_trusted_signer_hex_is_ok() -> crate::Result<()> {
        let receipt = sample_receipt()?;
        let trusted = vec![receipt.kernel_key.to_hex()];
        let verification = verify_receipt_with_trusted_signer_hex(&receipt, &trusted)?;

        assert!(verification.signer_trusted);
        assert!(verification.ok);
        assert!(verification.authorized);
        Ok(())
    }

    #[test]
    fn verify_receipt_json_with_trusted_signer_hex_is_ok() -> crate::Result<()> {
        let receipt = sample_receipt()?;
        let input = serde_json::to_string(&receipt)?;
        let trusted = vec![receipt.kernel_key.to_hex()];
        let verification = verify_receipt_json_with_trusted_signer_hex(&input, &trusted)?;

        assert!(verification.signer_trusted);
        assert!(verification.ok);
        assert!(verification.authorized);
        Ok(())
    }

    #[test]
    fn invalid_trusted_signer_hex_fails_closed() -> crate::Result<()> {
        let receipt = sample_receipt()?;
        let error =
            verify_receipt_with_trusted_signer_hex(&receipt, &["not-a-public-key"]).unwrap_err();

        assert_eq!(error.code(), crate::ErrorCode::InvalidHex);
        Ok(())
    }

    #[test]
    fn verify_receipt_reports_mismatched_content_addressed_id() -> crate::Result<()> {
        let mut receipt = sample_receipt()?;
        receipt.id = "rcpt-symbolic-invalid".to_string();
        let verification = super::verify_receipt_with_trusted_signers(
            &receipt,
            std::slice::from_ref(&receipt.kernel_key),
        )?;
        assert!(!verification.receipt_id_valid);
        assert!(!verification.signature_valid);
        assert!(!verification.ok);
        Ok(())
    }
}
