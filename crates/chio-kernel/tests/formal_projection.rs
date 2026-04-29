use std::time::Duration;

use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::receipt::{
    ChioReceipt, ChioReceiptBody, Decision, GuardEvidence, ToolCallAction, TrustLevel,
};
use chio_kernel::dpop::DpopNonceStore;
use chio_kernel::{BudgetStore, InMemoryBudgetStore, InMemoryRevocationStore, RevocationStore};
use serde_json::json;

struct RevocationProjection {
    token_revoked: bool,
    ancestor_revoked: bool,
}

impl RevocationProjection {
    fn denies(&self) -> bool {
        self.token_revoked || self.ancestor_revoked
    }
}

struct BudgetProjection {
    invocation_count: u32,
    committed_cost_units: u64,
}

impl BudgetProjection {
    fn within(&self, max_invocations: u32, max_total_cost_units: u64) -> bool {
        self.invocation_count <= max_invocations
            && self.committed_cost_units <= max_total_cost_units
    }
}

struct ReceiptProjection {
    capability_id: String,
    tool_server: String,
    tool_name: String,
    parameter_hash: String,
    decision: Decision,
    policy_hash: String,
    has_guard_evidence: bool,
}

impl ReceiptProjection {
    fn from_receipt(receipt: &ChioReceipt) -> Self {
        Self {
            capability_id: receipt.capability_id.clone(),
            tool_server: receipt.tool_server.clone(),
            tool_name: receipt.tool_name.clone(),
            parameter_hash: receipt.action.parameter_hash.clone(),
            decision: receipt.decision.clone(),
            policy_hash: receipt.policy_hash.clone(),
            has_guard_evidence: !receipt.evidence.is_empty(),
        }
    }

    fn couples(
        &self,
        capability_id: &str,
        tool_server: &str,
        tool_name: &str,
        parameter_hash: &str,
        decision: &Decision,
        policy_hash: &str,
    ) -> bool {
        self.capability_id == capability_id
            && self.tool_server == tool_server
            && self.tool_name == tool_name
            && self.parameter_hash == parameter_hash
            && &self.decision == decision
            && self.policy_hash == policy_hash
            && self.has_guard_evidence
    }
}

#[test]
fn dpop_nonce_projection_rejects_replay() {
    let store = DpopNonceStore::new(8, Duration::from_secs(60));

    assert!(store.check_and_insert("nonce-1", "cap-1").unwrap());
    assert!(!store.check_and_insert("nonce-1", "cap-1").unwrap());
}

#[test]
fn revocation_snapshot_projection_denies_token_and_ancestor() {
    let store = InMemoryRevocationStore::new();
    store.revoke("cap-child").unwrap();
    store.revoke("cap-parent").unwrap();

    let child_projection = RevocationProjection {
        token_revoked: store.is_revoked("cap-child").unwrap(),
        ancestor_revoked: false,
    };
    assert!(child_projection.denies());

    let ancestor_projection = RevocationProjection {
        token_revoked: false,
        ancestor_revoked: store.is_revoked("cap-parent").unwrap(),
    };
    assert!(ancestor_projection.denies());
}

#[test]
fn budget_snapshot_projection_preserves_single_node_bounds() {
    let store = InMemoryBudgetStore::new();

    assert!(store
        .try_charge_cost("cap-budget", 0, Some(2), 40, Some(50), Some(100))
        .unwrap());
    assert!(store
        .try_charge_cost("cap-budget", 0, Some(2), 50, Some(50), Some(100))
        .unwrap());
    assert!(!store
        .try_charge_cost("cap-budget", 0, Some(2), 1, Some(50), Some(100))
        .unwrap());

    let usage = store.get_usage("cap-budget", 0).unwrap().unwrap();
    let projection = BudgetProjection {
        invocation_count: usage.invocation_count,
        committed_cost_units: usage.committed_cost_units().unwrap(),
    };

    assert!(projection.within(2, 100));
}

#[test]
fn receipt_projection_couples_decision_to_evidence_body() {
    let keypair = Keypair::from_seed(&[42; 32]);
    let action = ToolCallAction::from_parameters(json!({"path": "/workspace/safe.txt"})).unwrap();
    let parameter_hash = action.parameter_hash.clone();
    let decision = Decision::Deny {
        reason: "blocked by path guard".to_string(),
        guard: "path-guard".to_string(),
    };
    let policy_hash = sha256_hex(b"policy-v1");
    let body = ChioReceiptBody {
        id: "rcpt-formal-1".to_string(),
        timestamp: 1_700_000_000,
        capability_id: "cap-formal-1".to_string(),
        tool_server: "srv-files".to_string(),
        tool_name: "read_file".to_string(),
        action,
        decision: decision.clone(),
        content_hash: sha256_hex(b"content"),
        policy_hash: policy_hash.clone(),
        evidence: vec![GuardEvidence {
            guard_name: "path-guard".to_string(),
            verdict: false,
            details: Some("deny".to_string()),
        }],
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: keypair.public_key(),
    };

    let receipt = ChioReceipt::sign(body, &keypair).unwrap();
    assert!(receipt.verify_signature().unwrap());

    let projection = ReceiptProjection::from_receipt(&receipt);
    assert!(projection.couples(
        "cap-formal-1",
        "srv-files",
        "read_file",
        &parameter_hash,
        &decision,
        &policy_hash,
    ));
}
