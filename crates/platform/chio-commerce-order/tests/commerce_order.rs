use std::path::{Path, PathBuf};

use chio_core_types::crypto::{Keypair, PublicKey};
use chio_core_types::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::{Decision, ToolCallAction},
    kinds::{BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel},
    metadata::ActorRef,
};
use chio_test_support::prelude::*;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|crates_dir| crates_dir.parent())
        .and_then(|workspace| workspace.parent())
        .test_expect("workspace root is parent of crates/platform/chio-commerce-order")
        .to_path_buf()
}

fn fixture_dir(case_name: &str) -> PathBuf {
    workspace_root().join(format!("fixtures/proof-room/commerce-payments/{case_name}"))
}

fn read_fixture(dir: &Path, name: &str) -> Vec<u8> {
    let case_path = dir.join(name);
    let path = if case_path.is_file() {
        case_path
    } else {
        fixture_dir("offline-psp-valid").join(name)
    };
    std::fs::read(path).test_expect("fixture file reads")
}

fn enterprise_risk_report_bytes() -> Vec<u8> {
    std::fs::read(
        workspace_root()
            .join("fixtures/proof-room/enterprise-export/open-appeal-claim-payout")
            .join("risk-comptroller-report.json"),
    )
    .test_expect("enterprise risk comptroller report reads")
}

fn commerce_payment_signer_key() -> PublicKey {
    Keypair::from_seed(&[7u8; 32]).public_key()
}

fn commerce_payment_signer() -> Keypair {
    Keypair::from_seed(&[7u8; 32])
}

fn commerce_provider_trust_signer_key() -> PublicKey {
    Keypair::from_seed(&[8u8; 32]).public_key()
}

fn commerce_provider_trust_signer() -> Keypair {
    Keypair::from_seed(&[8u8; 32])
}

fn commerce_event_authority_receipt_key() -> PublicKey {
    Keypair::from_seed(&[9u8; 32]).public_key()
}

fn commerce_event_authority_receipt_signer() -> Keypair {
    Keypair::from_seed(&[9u8; 32])
}

fn risk_comptroller_signer_key() -> PublicKey {
    PublicKey::from_hex("3f0dda81e6abbcc5f17c359df8517177769d2dfff3d4ce942e7ce9a82dfb0db2")
        .test_expect("enterprise risk comptroller signer key parses")
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    hex::encode(Sha256::digest(bytes))
}

fn mandate_protocol_payloads() -> Vec<chio_commerce_order::CommerceMandateProtocolPayload> {
    [
        ("ap2", "checkout_mandate"),
        ("ap2", "payment_mandate"),
        ("acp-commerce", "delegated_payment_token"),
        ("x402", "payment_requirements"),
        ("chio", "authority_projection"),
    ]
    .into_iter()
    .map(
        |(protocol, purpose)| chio_commerce_order::CommerceMandateProtocolPayload {
            protocol: protocol.to_string(),
            purpose: purpose.to_string(),
            payload_bytes: mandate_protocol_payload_bytes(protocol, purpose),
        },
    )
    .collect()
}

fn mandate_protocol_payload_bytes(protocol: &str, purpose: &str) -> Vec<u8> {
    let payload = serde_json::json!({
        "schema": chio_commerce_order::COMMERCE_PROTOCOL_PAYLOAD_SCHEMA_ID,
        "protocol": protocol,
        "purpose": purpose,
        "order_id": "order-commerce-001",
        "amount_minor": 4200,
        "currency": "USD",
        "merchant_subject": "merchant:stripe:coffee-shop",
    });
    chio_core_types::canonical_json_bytes(&payload).test_expect("payload canonicalizes")
}

fn mandate_protocol_payload_bytes_with_amount(
    protocol: &str,
    purpose: &str,
    amount_minor: u64,
) -> Vec<u8> {
    let payload = serde_json::json!({
        "schema": chio_commerce_order::COMMERCE_PROTOCOL_PAYLOAD_SCHEMA_ID,
        "protocol": protocol,
        "purpose": purpose,
        "order_id": "order-commerce-001",
        "amount_minor": amount_minor,
        "currency": "USD",
        "merchant_subject": "merchant:stripe:coffee-shop",
    });
    chio_core_types::canonical_json_bytes(&payload).test_expect("payload canonicalizes")
}

fn canonical_context_sha256(context: &chio_commerce_order::CommerceOrderContext) -> String {
    let canonical =
        chio_core_types::canonical_json_bytes(context).test_expect("order context canonicalizes");
    sha256_hex(&canonical)
}

fn load_bundle(case_name: &str) -> chio_commerce_order::CommerceOrderVerificationBundle {
    let dir = fixture_dir(case_name);
    let context_bytes = read_fixture(&dir, "order-context.json");
    let mut order_context: chio_commerce_order::CommerceOrderContext =
        serde_json::from_slice(&context_bytes).test_expect("order context parses");
    let event_log_bytes = read_fixture(&dir, "event-log.json");
    let provider_passport_bytes =
        signed_provider_trust_artifact_bytes(read_fixture(&dir, "provider-passport.json"));
    let reputation_snapshot_bytes =
        signed_provider_trust_artifact_bytes(read_fixture(&dir, "reputation-snapshot.json"));
    let federation_trust_bundle_bytes =
        signed_provider_trust_artifact_bytes(read_fixture(&dir, "federation-trust-bundle.json"));
    order_context.provider_passport_sha256 = sha256_hex(&provider_passport_bytes);
    order_context.reputation_snapshot_sha256 = sha256_hex(&reputation_snapshot_bytes);
    order_context.federation_trust_bundle_sha256 = sha256_hex(&federation_trust_bundle_bytes);

    chio_commerce_order::CommerceOrderVerificationBundle {
        order_context,
        event_log_bytes: event_log_bytes.clone(),
        event_authority_receipts: event_authority_receipt_artifacts(&event_log_bytes),
        payment_lifecycle_bytes: read_fixture(&dir, "payment-lifecycle.json"),
        mandate_ledger_bytes: read_fixture(&dir, "mandate-allowance-ledger.json"),
        provider_passport_bytes,
        reputation_snapshot_bytes,
        federation_trust_bundle_bytes,
        settlement_packet_bytes: read_fixture(&dir, "settlement-packet.json"),
        mandate_protocol_payloads: mandate_protocol_payloads(),
        risk_comptroller_report_bytes: None,
        verified_trust_market_context: None,
        trusted_event_authority_receipt_kernel_keys: vec![commerce_event_authority_receipt_key()],
        trusted_payment_signer_keys: vec![commerce_payment_signer_key()],
        trusted_provider_trust_signer_keys: vec![commerce_provider_trust_signer_key()],
        trusted_risk_comptroller_signer_keys: vec![risk_comptroller_signer_key()],
    }
}

fn event_authority_receipt_artifacts(
    event_log_bytes: &[u8],
) -> Vec<chio_commerce_order::CommerceEventAuthorityReceiptArtifact> {
    let event_log: serde_json::Value =
        serde_json::from_slice(event_log_bytes).test_expect("event log parses");
    let events = event_log["events"]
        .as_array()
        .test_expect("event log events array");
    events
        .iter()
        .map(event_authority_receipt_artifact)
        .collect()
}

fn event_authority_receipt_artifact(
    event: &serde_json::Value,
) -> chio_commerce_order::CommerceEventAuthorityReceiptArtifact {
    let receipt_ref = event["authority_receipt_ref"]
        .as_str()
        .test_expect("event authority receipt ref")
        .to_string();
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: receipt_ref.clone(),
            timestamp: 1_781_072_000,
            capability_id: format!("cap-{receipt_ref}"),
            tool_server: "chio-commerce-order-authority".to_string(),
            tool_name: event["transition"]
                .as_str()
                .test_expect("event transition")
                .to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({
                "authority_receipt_ref": receipt_ref,
                "event_id": event["event_id"],
                "order_id": event["order_id"],
                "transition": event["transition"],
            }))
            .test_expect("authority receipt action hashes"),
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: vec![ActorRef {
                actor_id: event["actor"]
                    .as_str()
                    .test_expect("event actor")
                    .to_string(),
                actor_kind: Some("agent".to_string()),
            }],
            content_hash: event["event_sha256"]
                .as_str()
                .test_expect("event digest")
                .to_string(),
            policy_hash: sha256_hex(b"chio.commerce.event-authority.v1"),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: commerce_event_authority_receipt_key(),
            bbs_projection_version: None,
        },
        &commerce_event_authority_receipt_signer(),
    )
    .test_expect("authority receipt signs");
    let mut receipt_value = serde_json::to_value(receipt).test_expect("receipt serializes");
    receipt_value["schema"] = serde_json::Value::String("chio.receipt.v1".to_string());
    chio_commerce_order::CommerceEventAuthorityReceiptArtifact {
        receipt_ref,
        receipt_bytes: serde_json::to_vec(&receipt_value).test_expect("receipt JSON serializes"),
    }
}

fn signed_provider_trust_artifact_bytes(bytes: Vec<u8>) -> Vec<u8> {
    let mut value: serde_json::Value =
        serde_json::from_slice(&bytes).test_expect("provider trust artifact parses");
    sign_provider_trust_value(&mut value);
    serde_json::to_vec(&value).test_expect("provider trust artifact serializes")
}

fn sign_provider_trust_value(value: &mut serde_json::Value) {
    value
        .as_object_mut()
        .test_expect("provider trust artifact object")
        .remove("signature");
    let (signature, _) = commerce_provider_trust_signer()
        .sign_canonical(value)
        .test_expect("provider trust artifact signs");
    value["signature"] = serde_json::Value::String(signature.to_hex());
}

fn sign_payment_lifecycle_value(payment_lifecycle: &mut serde_json::Value) {
    let payment_object = payment_lifecycle
        .as_object_mut()
        .test_expect("payment lifecycle object");
    payment_object.entry("issuer").or_insert_with(|| {
        serde_json::Value::String(format!(
            "did:chio:{}",
            commerce_payment_signer_key().to_hex()
        ))
    });
    payment_object
        .entry("authorization_ref")
        .or_insert_with(|| serde_json::Value::String("auth_commerce_001".to_string()));
    payment_object
        .entry("capture_ref")
        .or_insert_with(|| serde_json::Value::String("cap_commerce_001".to_string()));
    payment_object
        .entry("charge_ref")
        .or_insert_with(|| serde_json::Value::String("ch_commerce_001".to_string()));
    payment_object
        .entry("balance_transaction_ref")
        .or_insert_with(|| serde_json::Value::String("txn_commerce_001".to_string()));
    payment_lifecycle
        .as_object_mut()
        .test_expect("payment lifecycle object")
        .remove("signature");
    let (signature, _) = commerce_payment_signer()
        .sign_canonical(payment_lifecycle)
        .test_expect("payment lifecycle signs");
    payment_lifecycle["signature"] = serde_json::Value::String(signature.to_hex());
}

fn mutate_event_log(
    bundle: &mut chio_commerce_order::CommerceOrderVerificationBundle,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    mutate_event_log_with_sealing(bundle, mutate, true);
}

fn mutate_event_log_with_sealing(
    bundle: &mut chio_commerce_order::CommerceOrderVerificationBundle,
    mutate: impl FnOnce(&mut serde_json::Value),
    seal_events: bool,
) {
    let mut event_log: serde_json::Value =
        serde_json::from_slice(&bundle.event_log_bytes).test_expect("event log parses");
    mutate(&mut event_log);
    if seal_events {
        seal_event_log(&mut event_log, &bundle.order_context.agent_subject);
    }
    bundle.event_log_bytes = serde_json::to_vec(&event_log).test_expect("event log serializes");
    bundle.order_context.event_log_sha256 = sha256_hex(&bundle.event_log_bytes);
    if seal_events {
        bundle.event_authority_receipts =
            event_authority_receipt_artifacts(&bundle.event_log_bytes);
    }
}

fn seal_event_log(event_log: &mut serde_json::Value, default_actor: &str) {
    let events = event_log["events"]
        .as_array_mut()
        .test_expect("event log events array");
    for event in events {
        if event.get("actor").is_none() {
            event["actor"] = serde_json::Value::String(default_actor.to_string());
        }
        event
            .as_object_mut()
            .test_expect("event object")
            .remove("event_sha256");
        let canonical =
            chio_core_types::canonical_json_bytes(event).test_expect("event canonicalizes");
        event["event_sha256"] = serde_json::Value::String(sha256_hex(&canonical));
    }
}

fn mutate_payment_lifecycle(
    bundle: &mut chio_commerce_order::CommerceOrderVerificationBundle,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let mut payment_lifecycle: serde_json::Value =
        serde_json::from_slice(&bundle.payment_lifecycle_bytes)
            .test_expect("payment lifecycle parses");
    mutate(&mut payment_lifecycle);
    sign_payment_lifecycle_value(&mut payment_lifecycle);
    bundle.payment_lifecycle_bytes =
        serde_json::to_vec(&payment_lifecycle).test_expect("payment lifecycle serializes");
    bundle.order_context.payment_lifecycle_sha256 = sha256_hex(&bundle.payment_lifecycle_bytes);
}

fn mutate_payment_lifecycle_without_resign(
    bundle: &mut chio_commerce_order::CommerceOrderVerificationBundle,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let mut payment_lifecycle: serde_json::Value =
        serde_json::from_slice(&bundle.payment_lifecycle_bytes)
            .test_expect("payment lifecycle parses");
    mutate(&mut payment_lifecycle);
    bundle.payment_lifecycle_bytes =
        serde_json::to_vec(&payment_lifecycle).test_expect("payment lifecycle serializes");
    bundle.order_context.payment_lifecycle_sha256 = sha256_hex(&bundle.payment_lifecycle_bytes);
}

fn mutate_mandate_ledger(
    bundle: &mut chio_commerce_order::CommerceOrderVerificationBundle,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let mut mandate_ledger: serde_json::Value =
        serde_json::from_slice(&bundle.mandate_ledger_bytes).test_expect("mandate ledger parses");
    mutate(&mut mandate_ledger);
    bundle.mandate_ledger_bytes =
        serde_json::to_vec(&mandate_ledger).test_expect("mandate ledger serializes");
    bundle.order_context.mandate_ledger_sha256 = sha256_hex(&bundle.mandate_ledger_bytes);
}

fn mutate_settlement_packet(
    bundle: &mut chio_commerce_order::CommerceOrderVerificationBundle,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let mut settlement_packet: serde_json::Value =
        serde_json::from_slice(&bundle.settlement_packet_bytes)
            .test_expect("settlement packet parses");
    mutate(&mut settlement_packet);
    bundle.settlement_packet_bytes =
        serde_json::to_vec(&settlement_packet).test_expect("settlement packet serializes");
    bundle.order_context.settlement_packet_sha256 = sha256_hex(&bundle.settlement_packet_bytes);
}

fn mutate_provider_passport(
    bundle: &mut chio_commerce_order::CommerceOrderVerificationBundle,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let mut provider_passport: serde_json::Value =
        serde_json::from_slice(&bundle.provider_passport_bytes)
            .test_expect("provider passport parses");
    mutate(&mut provider_passport);
    bundle.provider_passport_bytes =
        serde_json::to_vec(&provider_passport).test_expect("provider passport serializes");
    bundle.order_context.provider_passport_sha256 = sha256_hex(&bundle.provider_passport_bytes);
}

fn mutate_provider_passport_and_resign(
    bundle: &mut chio_commerce_order::CommerceOrderVerificationBundle,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    mutate_provider_passport(bundle, |provider_passport| {
        mutate(provider_passport);
        sign_provider_trust_value(provider_passport);
    });
}

fn mutate_reputation_snapshot(
    bundle: &mut chio_commerce_order::CommerceOrderVerificationBundle,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let mut reputation_snapshot: serde_json::Value =
        serde_json::from_slice(&bundle.reputation_snapshot_bytes)
            .test_expect("reputation snapshot parses");
    mutate(&mut reputation_snapshot);
    bundle.reputation_snapshot_bytes =
        serde_json::to_vec(&reputation_snapshot).test_expect("reputation snapshot serializes");
    bundle.order_context.reputation_snapshot_sha256 = sha256_hex(&bundle.reputation_snapshot_bytes);
}

fn mutate_reputation_snapshot_and_resign(
    bundle: &mut chio_commerce_order::CommerceOrderVerificationBundle,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    mutate_reputation_snapshot(bundle, |reputation_snapshot| {
        mutate(reputation_snapshot);
        sign_provider_trust_value(reputation_snapshot);
    });
}

fn truncate_to_payment_verified(bundle: &mut chio_commerce_order::CommerceOrderVerificationBundle) {
    mutate_event_log(bundle, |event_log| {
        let events = event_log["events"]
            .as_array_mut()
            .test_expect("event log events array");
        let payment_event_index = events
            .iter()
            .position(|event| event["next_state"] == "payment_verified")
            .test_expect("payment verification event exists");
        events.truncate(payment_event_index + 1);
    });
    bundle.order_context.current_state = "payment_verified".to_string();
}

fn require_enterprise_coverage(bundle: &mut chio_commerce_order::CommerceOrderVerificationBundle) {
    let risk_report_bytes = enterprise_risk_report_bytes();
    bundle.order_context.coverage_requirement =
        Some(chio_commerce_order::CommerceCoverageRequirement {
            required: true,
            coverage_id: "coverage-enterprise-valid".to_string(),
            risk_comptroller_report_ref: "risk-comptroller-enterprise-valid".to_string(),
            risk_comptroller_report_sha256: sha256_hex(&risk_report_bytes),
            risk_comptroller_report_path: "risk-comptroller-report.json".to_string(),
        });
    bundle.risk_comptroller_report_bytes = Some(risk_report_bytes);
}

fn require_trust_market_context(bundle: &mut chio_commerce_order::CommerceOrderVerificationBundle) {
    bundle.order_context.trust_market_requirement =
        Some(chio_commerce_order::CommerceTrustMarketRequirement {
            required: true,
            provider_discovery_snapshot_ref: "discovery-trust-market-valid".to_string(),
            provider_selection_report_ref: "selection-trust-market-valid".to_string(),
            trust_scorecard_ref: "scorecard-trust-market-valid".to_string(),
            reputation_import_ref: "reputation-import-trust-market-valid".to_string(),
            sla_commitment_ref: "sla-commitment-trust-market-valid".to_string(),
            collateral_position_ref: "collateral-trust-market-valid".to_string(),
            guarantee_decision_ref: "guarantee-trust-market-valid".to_string(),
            adjudication_jurisdiction_ref: "jurisdiction-trust-market-valid".to_string(),
        });
    bundle.verified_trust_market_context =
        Some(chio_commerce_order::CommerceVerifiedTrustMarketContext {
            provider_discovery_snapshot_ref: "discovery-trust-market-valid".to_string(),
            provider_selection_report_ref: "selection-trust-market-valid".to_string(),
            trust_scorecard_ref: "scorecard-trust-market-valid".to_string(),
            reputation_import_ref: "reputation-import-trust-market-valid".to_string(),
            sla_commitment_ref: "sla-commitment-trust-market-valid".to_string(),
            risk_comptroller_report_ref: "risk-comptroller-market-valid".to_string(),
            collateral_position_ref: "collateral-trust-market-valid".to_string(),
            guarantee_decision_ref: "guarantee-trust-market-valid".to_string(),
            adjudication_jurisdiction_ref: "jurisdiction-trust-market-valid".to_string(),
            selected_provider_subject: "merchant:stripe:coffee-shop".to_string(),
        });
}

fn add_all_trust_market_context_refs(
    bundle: &mut chio_commerce_order::CommerceOrderVerificationBundle,
) {
    mutate_event_log(bundle, |event_log| {
        let events = event_log["events"]
            .as_array_mut()
            .test_expect("event log has events");
        for event in events {
            let next_state = event["next_state"]
                .as_str()
                .test_expect("event next_state string")
                .to_string();
            let evidence_refs = event["evidence_refs"]
                .as_array_mut()
                .test_expect("event has evidence refs");
            if next_state == "provider_admitted" {
                for evidence_ref in [
                    "discovery-trust-market-valid",
                    "selection-trust-market-valid",
                    "scorecard-trust-market-valid",
                    "reputation-import-trust-market-valid",
                ] {
                    evidence_refs.push(serde_json::Value::String(evidence_ref.to_string()));
                }
            }
            if [
                "settlement_packet_assembled",
                "settlement_dispatched",
                "settlement_observed",
                "settlement_reconciled",
            ]
            .contains(&next_state.as_str())
            {
                for evidence_ref in [
                    "sla-commitment-trust-market-valid",
                    "collateral-trust-market-valid",
                    "guarantee-trust-market-valid",
                    "jurisdiction-trust-market-valid",
                ] {
                    evidence_refs.push(serde_json::Value::String(evidence_ref.to_string()));
                }
            }
        }
    });
}

#[test]
fn commerce_order_replay_rejects_marketplace_provider_admission_without_trust_market_refs() {
    let mut bundle = load_bundle("offline-psp-valid");
    require_trust_market_context(&mut bundle);

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("marketplace-mode provider admission must bind trust-market evidence");

    assert!(error
        .to_string()
        .contains("provider event missing trust-market evidence"));
}

#[test]
fn commerce_order_replay_rejects_marketplace_settlement_without_trust_market_refs() {
    let mut bundle = load_bundle("offline-psp-valid");
    require_trust_market_context(&mut bundle);
    mutate_event_log(&mut bundle, |event_log| {
        let events = event_log["events"]
            .as_array_mut()
            .test_expect("event log has events");
        for event in events {
            if event["next_state"] == "provider_admitted" {
                let evidence_refs = event["evidence_refs"]
                    .as_array_mut()
                    .test_expect("provider event has evidence refs");
                for evidence_ref in [
                    "discovery-trust-market-valid",
                    "selection-trust-market-valid",
                    "scorecard-trust-market-valid",
                    "reputation-import-trust-market-valid",
                ] {
                    evidence_refs.push(serde_json::Value::String(evidence_ref.to_string()));
                }
            }
        }
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("marketplace-mode settlement must bind trust-market evidence");

    assert!(error
        .to_string()
        .contains("settlement event missing trust-market evidence"));
}

#[test]
fn commerce_order_replay_rejects_marketplace_refs_without_verified_trust_market_context() {
    let mut bundle = load_bundle("offline-psp-valid");
    require_trust_market_context(&mut bundle);
    add_all_trust_market_context_refs(&mut bundle);
    bundle.verified_trust_market_context = None;

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("marketplace-mode orders must bind verified trust-market context");

    assert!(error
        .to_string()
        .contains("trust-market verifier context missing"));
}

#[test]
fn commerce_order_replay_rejects_trust_market_refs_with_required_false() {
    let mut bundle = load_bundle("offline-psp-valid");
    require_trust_market_context(&mut bundle);
    add_all_trust_market_context_refs(&mut bundle);
    bundle
        .order_context
        .trust_market_requirement
        .as_mut()
        .test_expect("trust-market requirement")
        .required = false;
    bundle.verified_trust_market_context = None;

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("marketplace refs must not self-disable trust-market verification");

    assert!(error
        .to_string()
        .contains("trust-market refs cannot disable verifier"));
}

#[test]
fn commerce_order_replay_rejects_marketplace_selected_provider_subject_mismatch() {
    let mut bundle = load_bundle("offline-psp-valid");
    require_trust_market_context(&mut bundle);
    add_all_trust_market_context_refs(&mut bundle);
    bundle
        .verified_trust_market_context
        .as_mut()
        .test_expect("verified trust-market context")
        .selected_provider_subject = "did:chio:provider-other".to_string();

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("selected trust-market provider must match the order provider");

    assert!(error
        .to_string()
        .contains("trust-market selected provider subject mismatch"));
}

#[test]
fn commerce_order_replay_rejects_marketplace_risk_ref_mismatch() {
    let mut bundle = load_bundle("offline-psp-valid");
    require_enterprise_coverage(&mut bundle);
    require_trust_market_context(&mut bundle);
    add_all_trust_market_context_refs(&mut bundle);

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("marketplace-mode orders must bind coverage and trust-market risk refs");

    assert!(error
        .to_string()
        .contains("trust-market risk report ref mismatch"));
}

#[test]
fn commerce_order_replay_accepts_marketplace_refs_with_verified_trust_market_context() {
    let mut bundle = load_bundle("offline-psp-valid");
    require_trust_market_context(&mut bundle);
    add_all_trust_market_context_refs(&mut bundle);

    let report = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect("verified trust-market context should bind marketplace refs");

    assert!(report
        .verified_claims
        .contains(&"claim.commerce.trust_market_context_bound".to_string()));
}

#[test]
fn commerce_order_replay_rejects_provider_passport_subject_mismatch() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_provider_passport_and_resign(&mut bundle, |provider_passport| {
        provider_passport["provider_subject"] = serde_json::json!("merchant:stripe:other-shop");
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("provider passport subject must match merchant");

    assert!(error
        .to_string()
        .contains("provider passport subject mismatch"));
}

#[test]
fn commerce_order_replay_rejects_forged_provider_passport_signature() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_provider_passport(&mut bundle, |provider_passport| {
        provider_passport["signature"] = serde_json::json!(
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        );
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("forged provider passport signature must fail");

    assert!(error
        .to_string()
        .contains("provider passport signature invalid"));
}

#[test]
fn commerce_order_replay_rejects_stale_reputation_snapshot() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_reputation_snapshot_and_resign(&mut bundle, |reputation_snapshot| {
        reputation_snapshot["issued_at"] = serde_json::json!("2026-06-08T00:07:59Z");
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("stale signed reputation snapshots must fail");

    assert!(
        error
            .to_string()
            .contains("reputation snapshot stale for order context"),
        "{error}"
    );
}

#[test]
fn commerce_order_replay_rejects_zero_reputation_score() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_reputation_snapshot_and_resign(&mut bundle, |reputation_snapshot| {
        reputation_snapshot["score_bps"] = serde_json::json!(0);
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("accepted reputation snapshots must clear the floor");

    assert!(
        error
            .to_string()
            .contains("reputation score below minimum accepted floor"),
        "{error}"
    );
}

#[test]
fn commerce_order_replay_accepts_offline_psp_fixture() {
    let bundle = load_bundle("offline-psp-valid");

    let report = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect("valid offline PSP commerce fixture should verify");

    assert_eq!(report.schema, "chio.commerce.order-passport.v1");
    assert_eq!(report.verdict, "verified");
    assert_eq!(report.order_id, "order-commerce-001");
    assert_eq!(report.current_state, "completed");
    assert!(report
        .verified_claims
        .contains(&"claim.commerce.order_replay_consistent".to_string()));
    assert!(report
        .verified_claims
        .contains(&"claim.commerce.payment_lifecycle_bound".to_string()));
    assert!(report
        .verified_claims
        .contains(&"claim.commerce.mandate_allowance_bound".to_string()));
    assert!(report
        .verified_claims
        .contains(&"claim.commerce.admission_gates_bound".to_string()));
    assert!(report
        .verified_claims
        .contains(&"claim.commerce.settlement_lifecycle_bound".to_string()));
    assert!(report
        .verified_claims
        .contains(&"claim.commerce.order_passport_summary_bound".to_string()));
}

#[test]
fn commerce_order_replay_rejects_event_authority_receipt_without_signed_artifact() {
    let mut bundle = load_bundle("offline-psp-valid");
    bundle.event_authority_receipts.clear();

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("event authority receipt refs must resolve to trusted signed receipts");

    assert!(error.to_string().contains("authority receipt missing"));
}

#[test]
fn commerce_order_replay_rejects_event_without_actor() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_event_log_with_sealing(
        &mut bundle,
        |event_log| {
            let events = event_log["events"]
                .as_array_mut()
                .test_expect("event log events array");
            events[0]
                .as_object_mut()
                .test_expect("event object")
                .remove("actor");
        },
        false,
    );

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("commerce event actor must be present");

    assert!(error.to_string().contains("actor"));
}

#[test]
fn commerce_order_replay_rejects_event_without_digest() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_event_log_with_sealing(
        &mut bundle,
        |event_log| {
            let events = event_log["events"]
                .as_array_mut()
                .test_expect("event log events array");
            events[0]
                .as_object_mut()
                .test_expect("event object")
                .remove("event_sha256");
        },
        false,
    );

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("commerce event digest must be present");

    assert!(error.to_string().contains("event_sha256"));
}

#[test]
fn commerce_order_replay_rejects_coverage_required_without_risk_report() {
    let mut bundle = load_bundle("offline-psp-valid");
    bundle.order_context.coverage_requirement =
        Some(chio_commerce_order::CommerceCoverageRequirement {
            required: true,
            coverage_id: "coverage-enterprise-valid".to_string(),
            risk_comptroller_report_ref: "risk-comptroller-enterprise-valid".to_string(),
            risk_comptroller_report_sha256:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            risk_comptroller_report_path: "risk-comptroller-report.json".to_string(),
        });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("coverage-required orders must bind a risk comptroller report");

    assert!(error.to_string().contains("coverage report missing"));
}

#[test]
fn commerce_order_replay_accepts_coverage_required_with_bound_risk_report() {
    let mut bundle = load_bundle("offline-psp-valid");
    require_enterprise_coverage(&mut bundle);

    let report = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect("coverage-required order with bound risk report should verify");

    assert!(report
        .verified_claims
        .contains(&"claim.commerce.coverage_decision_bound".to_string()));
    assert_eq!(
        report.artifact_digests.risk_comptroller_report_sha256,
        bundle
            .order_context
            .coverage_requirement
            .as_ref()
            .map(|requirement| requirement.risk_comptroller_report_sha256.clone())
    );
}

#[test]
fn commerce_order_replay_rejects_forged_risk_comptroller_signature() {
    let mut bundle = load_bundle("offline-psp-valid");
    require_enterprise_coverage(&mut bundle);
    let mut report: serde_json::Value = serde_json::from_slice(
        bundle
            .risk_comptroller_report_bytes
            .as_ref()
            .test_expect("risk report present"),
    )
    .test_expect("risk report parses");
    let original_signature = report["signature"]
        .as_str()
        .test_expect("risk report signature")
        .to_string();
    let signature_hex = original_signature
        .rsplit(':')
        .next()
        .test_expect("risk report signature hex");
    report["signature"] = serde_json::Value::String(format!(
        "sig-ed25519:{}:{}",
        Keypair::from_seed(&[61u8; 32]).public_key().to_hex(),
        signature_hex
    ));
    let forged_report_bytes =
        serde_json::to_vec(&report).test_expect("forged risk report serializes");
    bundle
        .order_context
        .coverage_requirement
        .as_mut()
        .test_expect("coverage requirement present")
        .risk_comptroller_report_sha256 = sha256_hex(&forged_report_bytes);
    bundle.risk_comptroller_report_bytes = Some(forged_report_bytes);

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("forged risk comptroller report signature must fail");

    assert!(
        error
            .to_string()
            .contains("risk comptroller report signer untrusted"),
        "{error}"
    );
}

#[test]
fn commerce_order_passport_binds_verified_digests_and_redaction_policy() {
    let bundle = load_bundle("offline-psp-valid");

    let report = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect("valid offline PSP commerce fixture should verify");

    assert_eq!(
        report.artifact_digests.order_context_sha256,
        canonical_context_sha256(&bundle.order_context)
    );
    assert_eq!(
        report.artifact_digests.event_log_sha256,
        bundle.order_context.event_log_sha256
    );
    assert_eq!(
        report.artifact_digests.payment_lifecycle_sha256,
        bundle.order_context.payment_lifecycle_sha256
    );
    assert_eq!(
        report.artifact_digests.mandate_ledger_sha256,
        bundle.order_context.mandate_ledger_sha256
    );
    assert_eq!(
        report.artifact_digests.provider_passport_sha256,
        bundle.order_context.provider_passport_sha256
    );
    assert_eq!(
        report.artifact_digests.reputation_snapshot_sha256,
        bundle.order_context.reputation_snapshot_sha256
    );
    assert_eq!(
        report.artifact_digests.federation_trust_bundle_sha256,
        bundle.order_context.federation_trust_bundle_sha256
    );
    assert_eq!(
        report.artifact_digests.settlement_packet_sha256,
        bundle.order_context.settlement_packet_sha256
    );
    assert_eq!(
        report.selective_disclosure_policy.policy_id,
        "chio.commerce.order-passport.public-summary.v1"
    );
    assert!(report
        .selective_disclosure_policy
        .disclosed_fields
        .contains(&"order_id".to_string()));
    assert!(report
        .selective_disclosure_policy
        .redacted_fields
        .contains(&"payment_intent_id".to_string()));
    assert!(report
        .selective_disclosure_policy
        .redacted_fields
        .contains(&"buyer_subject".to_string()));
}

#[test]
fn commerce_order_replay_rejects_payment_wrong_merchant() {
    let bundle = load_bundle("payment-wrong-merchant");

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("payment bound to wrong merchant must fail");

    assert!(error.to_string().contains("payment merchant mismatch"));
}

#[test]
fn commerce_order_replay_rejects_payment_wrong_transfer_group() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_payment_lifecycle(&mut bundle, |payment_lifecycle| {
        payment_lifecycle["transfer_group"] = serde_json::json!("order-commerce-other");
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("payment transfer group must bind the same order");

    assert!(error
        .to_string()
        .contains("payment transfer group mismatch"));
}

#[test]
fn commerce_order_replay_rejects_unsigned_payment_lifecycle() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_payment_lifecycle_without_resign(&mut bundle, |payment_lifecycle| {
        payment_lifecycle
            .as_object_mut()
            .test_expect("payment lifecycle object")
            .remove("signature");
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("unsigned payment lifecycle must fail");

    assert!(error.to_string().contains("payment signature missing"));
}

#[test]
fn commerce_order_replay_rejects_forged_payment_lifecycle_signature() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_payment_lifecycle_without_resign(&mut bundle, |payment_lifecycle| {
        payment_lifecycle["signature"] = serde_json::json!(
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        );
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("forged payment lifecycle signature must fail");

    assert!(error.to_string().contains("payment signature invalid"));
}

#[test]
fn commerce_order_replay_rejects_payment_lifecycle_bad_psp_object_ref() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_payment_lifecycle(&mut bundle, |payment_lifecycle| {
        payment_lifecycle["capture_ref"] = serde_json::json!("charge_without_capture_ref");
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("unsupported PSP object refs must fail");

    assert!(error
        .to_string()
        .contains("payment capture_ref is not a supported PSP object ref"));
}

#[test]
fn commerce_order_replay_rejects_payment_quote_digest_mismatch() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_payment_lifecycle(&mut bundle, |payment_lifecycle| {
        payment_lifecycle["quote_sha256"] =
            serde_json::json!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("payment quote digest mismatch must fail");

    assert!(error.to_string().contains("payment quote digest mismatch"));
}

#[test]
fn commerce_order_replay_rejects_mandate_missing_x402_projection() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_mandate_ledger(&mut bundle, |mandate_ledger| {
        let projections = mandate_ledger["protocol_projections"]
            .as_array_mut()
            .test_expect("mandate projections array");
        projections.retain(|projection| projection["protocol"] != "x402");
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("missing x402 mandate projection must fail");

    assert!(error
        .to_string()
        .contains("mandate projection missing: x402/payment_requirements"));
}

#[test]
fn commerce_order_replay_rejects_mandate_missing_chio_projection() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_mandate_ledger(&mut bundle, |mandate_ledger| {
        let projections = mandate_ledger["protocol_projections"]
            .as_array_mut()
            .test_expect("mandate projections array");
        projections.retain(|projection| {
            projection["protocol"] != "chio" || projection["purpose"] != "authority_projection"
        });
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("missing Chio-native mandate projection must fail");

    assert!(error
        .to_string()
        .contains("mandate projection missing: chio/authority_projection"));
}

#[test]
fn commerce_order_replay_rejects_mandate_protocol_digest_mismatch() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_mandate_ledger(&mut bundle, |mandate_ledger| {
        let projections = mandate_ledger["protocol_projections"]
            .as_array_mut()
            .test_expect("mandate projections array");
        let projection = projections
            .iter_mut()
            .find(|projection| {
                projection["protocol"] == "ap2" && projection["purpose"] == "checkout_mandate"
            })
            .test_expect("ap2 checkout projection exists");
        projection["digest"] =
            serde_json::json!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("AP2 mandate digest mismatch must fail");

    assert!(error
        .to_string()
        .contains("mandate projection digest mismatch: ap2/checkout_mandate"));
}

#[test]
fn commerce_order_replay_rejects_mandate_protocol_payload_digest_mismatch() {
    let mut bundle = load_bundle("offline-psp-valid");
    bundle.mandate_protocol_payloads[0].payload_bytes = b"{\"tampered\":true}".to_vec();

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("AP2 payload digest mismatch must fail");

    assert!(error
        .to_string()
        .contains("mandate projection payload digest mismatch: ap2/checkout_mandate"));
}

#[test]
fn commerce_order_replay_rejects_mandate_protocol_payload_semantic_mismatch() {
    let mut bundle = load_bundle("offline-psp-valid");
    let payload_bytes = mandate_protocol_payload_bytes_with_amount("ap2", "checkout_mandate", 4300);
    let payload_digest = sha256_hex(&payload_bytes);
    bundle.mandate_protocol_payloads[0].payload_bytes = payload_bytes;
    mutate_mandate_ledger(&mut bundle, |mandate_ledger| {
        mandate_ledger["ap2_checkout_mandate_hash"] = serde_json::json!(payload_digest);
        let projections = mandate_ledger["protocol_projections"]
            .as_array_mut()
            .test_expect("mandate projections array");
        let projection = projections
            .iter_mut()
            .find(|projection| {
                projection["protocol"] == "ap2" && projection["purpose"] == "checkout_mandate"
            })
            .test_expect("ap2 checkout projection exists");
        projection["digest"] = serde_json::json!(payload_digest);
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("AP2 payload semantic mismatch must fail");

    assert!(error
        .to_string()
        .contains("mandate projection payload amount mismatch: ap2/checkout_mandate"));
}

#[test]
fn commerce_order_replay_rejects_mandate_unsupported_protocol_name() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_mandate_ledger(&mut bundle, |mandate_ledger| {
        let projections = mandate_ledger["protocol_projections"]
            .as_array_mut()
            .test_expect("mandate projections array");
        projections[0]["protocol"] = serde_json::json!("ACP");
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("unsupported mandate protocol names must fail");

    assert!(error
        .to_string()
        .contains("unsupported mandate protocol: ACP"));
}

#[test]
fn commerce_order_replay_rejects_payment_before_budget_reservation() {
    let bundle = load_bundle("payment-before-budget");

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("payment before budget reservation must fail");

    assert!(error.to_string().contains("unknown commerce transition"));
}

#[test]
fn commerce_order_replay_accepts_full_normative_success_path() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_event_log(&mut bundle, |event_log| {
        let events = event_log["events"]
            .as_array_mut()
            .test_expect("event log events array");
        let payment_index = events
            .iter()
            .position(|event| event["next_state"] == "payment_verified")
            .test_expect("payment event exists");
        events[payment_index]["prior_state"] = serde_json::json!("payment_challenged");
        events.insert(
            payment_index,
            serde_json::json!({
                "event_id": "event-commerce-001-payment-challenge",
                "order_id": "order-commerce-001",
                "prior_state": "budget_reserved",
                "next_state": "payment_challenged",
                "transition": "challenge_payment",
                "occurred_at": "2026-06-10T00:03:30Z",
                "authority_receipt_ref": "receipt-payment-challenge-commerce-001",
                "evidence_refs": ["payment-lifecycle-commerce-001"],
                "idempotency_key": "idem-event-commerce-001-payment-challenge"
            }),
        );

        let fulfillment_index = events
            .iter()
            .position(|event| event["next_state"] == "fulfillment_attested")
            .test_expect("fulfillment event exists");
        events[fulfillment_index]["prior_state"] = serde_json::json!("fulfillment_requested");
        events.insert(
            fulfillment_index,
            serde_json::json!({
                "event_id": "event-commerce-001-fulfillment-request",
                "order_id": "order-commerce-001",
                "prior_state": "payment_verified",
                "next_state": "fulfillment_requested",
                "transition": "request_fulfillment",
                "occurred_at": "2026-06-10T00:04:30Z",
                "authority_receipt_ref": "receipt-fulfillment-request-commerce-001",
                "evidence_refs": ["fulfillment-commerce-001"],
                "idempotency_key": "idem-event-commerce-001-fulfillment-request"
            }),
        );

        let dispatch_index = events
            .iter()
            .position(|event| event["next_state"] == "settlement_dispatched")
            .test_expect("settlement dispatch event exists");
        events[dispatch_index]["prior_state"] = serde_json::json!("settlement_packet_assembled");
        events.insert(
            dispatch_index,
            serde_json::json!({
                "event_id": "event-commerce-001-settlement-assemble",
                "order_id": "order-commerce-001",
                "prior_state": "fulfillment_attested",
                "next_state": "settlement_packet_assembled",
                "transition": "assemble_settlement_packet",
                "occurred_at": "2026-06-10T00:05:30Z",
                "authority_receipt_ref": "receipt-settlement-assemble-commerce-001",
                "evidence_refs": ["settlement-packet-commerce-001"],
                "idempotency_key": "idem-event-commerce-001-settlement-assemble"
            }),
        );

        let reconcile_index = events
            .iter()
            .position(|event| event["next_state"] == "settlement_reconciled")
            .test_expect("settlement reconcile event exists");
        events[reconcile_index]["prior_state"] = serde_json::json!("settlement_observed");
        events.insert(
            reconcile_index,
            serde_json::json!({
                "event_id": "event-commerce-001-settlement-observed",
                "order_id": "order-commerce-001",
                "prior_state": "settlement_dispatched",
                "next_state": "settlement_observed",
                "transition": "observe_settlement",
                "occurred_at": "2026-06-10T00:06:30Z",
                "authority_receipt_ref": "receipt-settlement-observed-commerce-001",
                "evidence_refs": ["settlement-packet-commerce-001"],
                "idempotency_key": "idem-event-commerce-001-settlement-observed"
            }),
        );
    });

    let report = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect("normative state path should verify");

    assert_eq!(report.current_state, "completed");
}

#[test]
fn commerce_order_replay_accepts_disputed_refunded_recovery_path() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_event_log(&mut bundle, |event_log| {
        let events = event_log["events"]
            .as_array_mut()
            .test_expect("event log events array");
        events.push(serde_json::json!({
            "event_id": "event-commerce-001-dispute",
            "order_id": "order-commerce-001",
            "prior_state": "completed",
            "next_state": "disputed",
            "transition": "open_dispute",
            "occurred_at": "2026-06-10T00:09:00Z",
            "authority_receipt_ref": "receipt-dispute-commerce-001",
            "evidence_refs": ["payment-lifecycle-commerce-001"],
            "idempotency_key": "idem-event-commerce-001-dispute"
        }));
        events.push(serde_json::json!({
            "event_id": "event-commerce-001-refund",
            "order_id": "order-commerce-001",
            "prior_state": "disputed",
            "next_state": "refunded",
            "transition": "refund_payment",
            "occurred_at": "2026-06-10T00:10:00Z",
            "authority_receipt_ref": "receipt-refund-commerce-001",
            "evidence_refs": ["payment-lifecycle-commerce-001"],
            "idempotency_key": "idem-event-commerce-001-refund"
        }));
    });
    mutate_payment_lifecycle(&mut bundle, |payment_lifecycle| {
        payment_lifecycle["dispute_status"] = serde_json::json!("resolved");
        payment_lifecycle["refund_status"] = serde_json::json!("succeeded");
    });
    bundle.order_context.current_state = "refunded".to_string();

    let report = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect("disputed refund path should verify");

    assert_eq!(report.current_state, "refunded");
}

#[test]
fn commerce_order_replay_rejects_refund_without_dispute_transition() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_event_log(&mut bundle, |event_log| {
        let events = event_log["events"]
            .as_array_mut()
            .test_expect("event log events array");
        events.push(serde_json::json!({
            "event_id": "event-commerce-001-refund",
            "order_id": "order-commerce-001",
            "prior_state": "completed",
            "next_state": "refunded",
            "transition": "refund_payment",
            "occurred_at": "2026-06-10T00:09:00Z",
            "authority_receipt_ref": "receipt-refund-commerce-001",
            "evidence_refs": ["payment-lifecycle-commerce-001"],
            "idempotency_key": "idem-event-commerce-001-refund"
        }));
    });
    mutate_payment_lifecycle(&mut bundle, |payment_lifecycle| {
        payment_lifecycle["refund_status"] = serde_json::json!("succeeded");
    });
    bundle.order_context.current_state = "refunded".to_string();

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("refund without dispute transition must fail");

    assert!(error
        .to_string()
        .contains("unknown commerce transition: completed -> refunded via refund_payment"));
}

#[test]
fn commerce_order_replay_rejects_payment_capture_after_replay_event() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_payment_lifecycle(&mut bundle, |payment_lifecycle| {
        payment_lifecycle["captured_at"] = serde_json::json!("2026-06-10T00:09:00Z");
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("payment replay event must not predate capture");

    assert!(error
        .to_string()
        .contains("payment captured after replay event"));
}

#[test]
fn commerce_order_replay_rejects_payment_capture_before_authorization_events() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_payment_lifecycle(&mut bundle, |payment_lifecycle| {
        payment_lifecycle["captured_at"] = serde_json::json!("2026-06-10T00:01:30Z");
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("payment capture must follow mandate and budget authorization");

    assert!(error
        .to_string()
        .contains("payment captured before commerce authorization event"));
}

#[test]
fn commerce_order_replay_rejects_double_budget_reservation() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_event_log(&mut bundle, |event_log| {
        let events = event_log["events"]
            .as_array_mut()
            .test_expect("event log events array");
        let budget_event_index = events
            .iter()
            .position(|event| event["next_state"] == "budget_reserved")
            .test_expect("budget reservation event exists");
        let mut duplicate_budget_event = events[budget_event_index].clone();
        duplicate_budget_event["event_id"] =
            serde_json::json!("event-commerce-001-budget-replayed");
        duplicate_budget_event["authority_receipt_ref"] =
            serde_json::json!("receipt-budget-replayed-commerce-001");
        duplicate_budget_event["idempotency_key"] =
            serde_json::json!("idem-event-commerce-001-budget-replayed");
        duplicate_budget_event["prior_state"] = serde_json::json!("budget_reserved");
        duplicate_budget_event["occurred_at"] = serde_json::json!("2026-06-10T00:04:30Z");
        events.insert(budget_event_index + 1, duplicate_budget_event);
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("double budget reservation must fail");

    assert!(error
        .to_string()
        .contains("commerce budget reserved more than once"));
}

#[test]
fn commerce_order_replay_rejects_duplicate_idempotency_key() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_event_log(&mut bundle, |event_log| {
        let events = event_log["events"]
            .as_array_mut()
            .test_expect("event log events array");
        let idempotency_key = events[0]["idempotency_key"].clone();
        events[1]["idempotency_key"] = idempotency_key;
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("duplicate event idempotency key must fail");

    assert!(error
        .to_string()
        .contains("duplicate commerce idempotency key"));
}

#[test]
fn commerce_order_replay_rejects_wrong_intent_evidence_ref() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_event_log(&mut bundle, |event_log| {
        let events = event_log["events"]
            .as_array_mut()
            .test_expect("event log events array");
        for event in events {
            if event["next_state"] == "intent_recorded" {
                event["evidence_refs"] = serde_json::json!(["intent-commerce-other"]);
            }
        }
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("intent event bound to wrong evidence must fail");

    assert!(error
        .to_string()
        .contains("intent event missing intent evidence"));
}

#[test]
fn commerce_order_replay_rejects_wrong_provider_admission_ref() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_event_log(&mut bundle, |event_log| {
        let events = event_log["events"]
            .as_array_mut()
            .test_expect("event log events array");
        for event in events {
            if event["next_state"] == "provider_admitted" {
                event["evidence_refs"] = serde_json::json!(["provider-admission-other"]);
            }
        }
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("provider event bound to wrong admission must fail");

    assert!(error
        .to_string()
        .contains("provider event missing provider admission evidence"));
}

#[test]
fn commerce_order_replay_rejects_wrong_settlement_packet_ref() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_event_log(&mut bundle, |event_log| {
        let events = event_log["events"]
            .as_array_mut()
            .test_expect("event log events array");
        for event in events {
            if event["next_state"] == "settlement_dispatched" {
                event["evidence_refs"] = serde_json::json!(["settlement-packet-other"]);
            }
        }
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("settlement dispatch event bound to wrong packet must fail");

    assert!(error
        .to_string()
        .contains("settlement event missing settlement packet evidence"));
}

#[test]
fn commerce_order_replay_rejects_settlement_packet_digest_mismatch() {
    let mut bundle = load_bundle("offline-psp-valid");
    bundle.settlement_packet_bytes = br#"{"schema":"chio.commerce.settlement-packet.v1"}"#.to_vec();

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("settlement packet digest must be bound");

    assert!(error
        .to_string()
        .contains("settlement packet digest mismatch"));
}

#[test]
fn commerce_order_replay_rejects_unverified_settlement_dispatch_receipt_ref() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_settlement_packet(&mut bundle, |settlement_packet| {
        settlement_packet["dispatch_receipt_ref"] =
            serde_json::json!("receipt-settlement-dispatch-missing");
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("settlement dispatch receipt ref must resolve to signed receipt");

    assert!(error
        .to_string()
        .contains("settlement dispatch receipt missing"));
}

#[test]
fn commerce_order_replay_rejects_unused_settlement_dispatch_receipt_ref() {
    let mut bundle = load_bundle("offline-psp-valid");
    let event_log: serde_json::Value =
        serde_json::from_slice(&bundle.event_log_bytes).test_expect("event log parses");
    let dispatch_event = event_log["events"]
        .as_array()
        .test_expect("event log has events")
        .iter()
        .find(|event| event["next_state"] == "settlement_dispatched")
        .test_expect("settlement dispatch event exists");
    let mut unused_dispatch_event = dispatch_event.clone();
    unused_dispatch_event["event_id"] =
        serde_json::json!("event-commerce-001-unused-settlement-dispatch");
    unused_dispatch_event["authority_receipt_ref"] =
        serde_json::json!("receipt-settlement-dispatch-unused");
    unused_dispatch_event["idempotency_key"] =
        serde_json::json!("idem-event-commerce-001-unused-settlement-dispatch");
    unused_dispatch_event
        .as_object_mut()
        .test_expect("unused dispatch event object")
        .remove("event_sha256");
    let canonical = chio_core_types::canonical_json_bytes(&unused_dispatch_event)
        .test_expect("unused dispatch event canonicalizes");
    unused_dispatch_event["event_sha256"] = serde_json::json!(sha256_hex(&canonical));
    bundle
        .event_authority_receipts
        .push(event_authority_receipt_artifact(&unused_dispatch_event));
    mutate_settlement_packet(&mut bundle, |settlement_packet| {
        settlement_packet["dispatch_receipt_ref"] =
            serde_json::json!("receipt-settlement-dispatch-unused");
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("settlement packet must bind the replayed dispatch receipt");

    assert!(error
        .to_string()
        .contains("settlement dispatch receipt does not match replayed dispatch event"));
}

#[test]
fn commerce_order_replay_rejects_settlement_packet_order_mismatch() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_settlement_packet(&mut bundle, |settlement_packet| {
        settlement_packet["order_id"] = serde_json::json!("order-commerce-other");
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("settlement packet must bind the order");

    assert!(error
        .to_string()
        .contains("settlement packet order mismatch"));
}

#[test]
fn commerce_order_replay_rejects_settlement_packet_psp_mismatch() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_settlement_packet(&mut bundle, |settlement_packet| {
        settlement_packet["psp"] = serde_json::json!("offline-psp-other");
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("settlement packet must bind the payment PSP");

    assert!(error.to_string().contains("settlement packet PSP mismatch"));
}

#[test]
fn commerce_order_replay_rejects_wrong_reconciliation_ref() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_event_log(&mut bundle, |event_log| {
        let events = event_log["events"]
            .as_array_mut()
            .test_expect("event log events array");
        for event in events {
            if event["next_state"] == "settlement_reconciled" {
                event["evidence_refs"] = serde_json::json!(["reconciliation-other"]);
            }
        }
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("reconciliation event bound to wrong evidence must fail");

    assert!(error
        .to_string()
        .contains("reconciliation event missing reconciliation evidence"));
}

#[test]
fn commerce_order_replay_rejects_expired_mandate() {
    let bundle = load_bundle("expired-mandate");

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("expired mandate must fail");

    assert!(error
        .to_string()
        .contains("mandate expired before payment capture"));
}

#[test]
fn commerce_order_replay_rejects_completed_order_with_open_dispute() {
    let bundle = load_bundle("open-dispute-completed");

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("completed order with open dispute must fail");

    assert!(error
        .to_string()
        .contains("unresolved payment recovery state"));
}

#[test]
fn commerce_order_replay_rejects_quote_evidence_mismatch() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_event_log(&mut bundle, |event_log| {
        if let Some(events) = event_log["events"].as_array_mut() {
            for event in events {
                if event["transition"] == "bind_quote" {
                    event["evidence_refs"] = serde_json::json!(["quote-commerce-replayed-other"]);
                }
            }
        }
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("quote event bound to wrong quote must fail");

    assert!(error
        .to_string()
        .contains("quote event missing quote evidence"));
}

#[test]
fn commerce_order_replay_rejects_unknown_recovery_status_before_completion() {
    let mut bundle = load_bundle("offline-psp-valid");
    truncate_to_payment_verified(&mut bundle);
    mutate_payment_lifecycle(&mut bundle, |payment_lifecycle| {
        payment_lifecycle["refund_status"] = serde_json::json!("merchant_claimed");
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("unknown payment recovery status must fail closed");

    assert!(error.to_string().contains("unsupported refund_status"));
}

#[test]
fn commerce_order_replay_rejects_refund_before_completion() {
    let mut bundle = load_bundle("offline-psp-valid");
    truncate_to_payment_verified(&mut bundle);
    mutate_payment_lifecycle(&mut bundle, |payment_lifecycle| {
        payment_lifecycle["refund_status"] = serde_json::json!("succeeded");
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("refunded payment must not verify before completion");

    assert!(error
        .to_string()
        .contains("unresolved payment recovery state"));
}
