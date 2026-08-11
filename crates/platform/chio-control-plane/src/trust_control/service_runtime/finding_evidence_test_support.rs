use chio_core::canonical_json_bytes;
use chio_core::crypto::Keypair;
use chio_core::message::{ExecutionNonce, NonceBinding, SignedExecutionNonce};
use chio_core::receipt::authoritative_spend::{BudgetAuthorityReceiptRef, PresentedNonceView};
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::metadata::{
    DeliveryContract, DeliveryResult, DELIVERY_CONTRACT_METADATA_KEY, DELIVERY_CONTRACT_SCHEMA,
};
use chio_finding_verifier::{FindingNonceResolver, ResolvedReceiptEvidence};

fn add_mediated_spend_metadata(
    metadata: &mut serde_json::Map<String, serde_json::Value>,
    index: u32,
) {
    metadata.insert(
        "budget_authority".to_owned(),
        serde_json::json!({
            "guarantee_level": "single_node_atomic",
            "authority_profile": "authoritative_hold_event",
            "metering_profile": "max_cost_preauthorize_then_reconcile_actual",
            "hold_id": format!("hold-evidence-{index}"),
            "execution_nonce_id": format!("nonce-evidence-{index}"),
            "mediated_spend": { "profile": "chio.mediated_spend.v1" },
            "authorize": {
                "event_id": format!("hold-evidence-{index}:authorize"),
                "exposure_units": 5,
                "committed_cost_units_after": 5
            },
            "terminal": {
                "disposition": "reconciled",
                "event_id": format!("hold-evidence-{index}:reconcile"),
                "exposure_units": 5,
                "realized_spend_units": 5,
                "committed_cost_units_after": 5
            }
        }),
    );
    metadata.insert(
        "financial".to_owned(),
        serde_json::json!({
            "grant_index": 0,
            "cost_charged": 5,
            "currency": "USD",
            "budget_remaining": 95,
            "budget_total": 100,
            "delegation_depth": 0,
            "root_budget_holder": "finding-producer",
            "settlement_status": "settled"
        }),
    );
}

pub(super) fn matched_delivery_metadata(
    content_hash: &str,
    index: u32,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut metadata = serde_json::Map::new();
    add_mediated_spend_metadata(&mut metadata, index);
    metadata.insert(
        DELIVERY_CONTRACT_METADATA_KEY.to_owned(),
        serde_json::to_value(DeliveryContract {
            schema: DELIVERY_CONTRACT_SCHEMA.to_owned(),
            expected_digest: content_hash.to_owned(),
            observed_digest: content_hash.to_owned(),
            result: DeliveryResult::Matched,
        })?,
    );
    Ok(serde_json::Value::Object(metadata))
}

pub(super) struct TestFindingNonceResolver {
    nonces: Vec<SignedExecutionNonce>,
}

impl FindingNonceResolver for TestFindingNonceResolver {
    fn nonce_for(&self, receipt: &ChioReceipt) -> Option<&dyn PresentedNonceView> {
        let nonce_id = BudgetAuthorityReceiptRef::from_receipt(receipt)?.execution_nonce_id?;
        self.nonces
            .iter()
            .find(|nonce| nonce.nonce.nonce_id == nonce_id)
            .map(|nonce| nonce as &dyn PresentedNonceView)
    }
}

pub(super) fn signed_nonce_resolver(
    receipts: &[ResolvedReceiptEvidence],
    kernel: &Keypair,
) -> Result<TestFindingNonceResolver, Box<dyn std::error::Error>> {
    let nonces = receipts
        .iter()
        .map(|evidence| signed_nonce(&evidence.receipt, kernel))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(TestFindingNonceResolver { nonces })
}

fn signed_nonce(
    receipt: &ChioReceipt,
    kernel: &Keypair,
) -> Result<SignedExecutionNonce, Box<dyn std::error::Error>> {
    let budget = BudgetAuthorityReceiptRef::from_receipt(receipt)
        .ok_or("receipt budget authority missing")?;
    let nonce = ExecutionNonce {
        schema: "chio.execution_nonce.v1".to_owned(),
        nonce_id: budget
            .execution_nonce_id
            .ok_or("receipt execution nonce id missing")?,
        issued_at: i64::try_from(receipt.timestamp.saturating_sub(1))?,
        expires_at: i64::try_from(receipt.timestamp.saturating_add(60))?,
        bound_to: NonceBinding {
            subject_id: "finding-producer".to_owned(),
            request_id: format!("request-{}", receipt.id),
            capability_id: receipt.capability_id.clone(),
            tool_server: receipt.tool_server.clone(),
            tool_name: receipt.tool_name.clone(),
            parameter_hash: receipt.action.parameter_hash.clone(),
        },
        reserved_hold_id: Some(budget.hold_id),
        reserving_request_id: None,
    };
    let signature = kernel.sign(&canonical_json_bytes(&nonce)?);
    Ok(SignedExecutionNonce { nonce, signature })
}
