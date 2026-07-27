use super::support::*;
use std::sync::{Arc, Mutex};

use chio_agent_web_interop::{
    verify_agent_web_interop_with_trust_and_consume_replays,
    verify_agent_web_interop_with_trust_and_consume_replays_if_report_matches, AgentWebReplayEntry,
    AgentWebReplayScope, AgentWebReplayStore, AgentWebReplayStoreError, AgentWebVerifierTrust,
    InMemoryAgentWebReplayStore,
};
use chio_core_types::{Keypair, PublicKey};
use chio_test_support::prelude::*;
use serde_json::json;
use sha2::Sha256;

#[derive(Debug, Default)]
struct CapturingReplayStore {
    entries: Mutex<Vec<AgentWebReplayEntry>>,
}

impl AgentWebReplayStore for CapturingReplayStore {
    fn check_and_insert(
        &self,
        _now_unix_seconds: u64,
        entries: &[AgentWebReplayEntry],
    ) -> Result<(), AgentWebReplayStoreError> {
        let mut captured = self.entries.lock().map_err(|_| {
            AgentWebReplayStoreError::Unavailable("capture store lock poisoned".to_string())
        })?;
        captured.extend_from_slice(entries);
        Ok(())
    }
}

fn agent_web_trust_with_role_keys(
    passport_keys: Vec<PublicKey>,
    kernel_keys: Vec<PublicKey>,
    sidecar_keys: Vec<PublicKey>,
    replay_store: Option<Arc<dyn AgentWebReplayStore>>,
    now_unix_seconds: u64,
) -> AgentWebVerifierTrust {
    let mut trust = AgentWebVerifierTrust::new()
        .with_trusted_passport_signer_keys(passport_keys)
        .with_standard_webhooks_secret_for(
            STANDARD_WEBHOOKS_WEBHOOK_ID,
            STANDARD_WEBHOOKS_VERIFIER_SECRET.to_vec(),
        )
        .with_standard_webhooks_replay_window(now_unix_seconds, STANDARD_WEBHOOKS_MAX_AGE_SECONDS)
        .with_trusted_receipt_kernel_keys(kernel_keys)
        .with_trusted_envelope_sidecar_keys(sidecar_keys);
    if let Some(store) = replay_store {
        trust = trust.with_standard_webhooks_replay_store(store);
    }
    trust
}

fn default_role_keys() -> (PublicKey, PublicKey, PublicKey) {
    (
        transaction_passport_keypair().public_key(),
        agent_web_fixture_kernel_keypair().public_key(),
        agent_web_fixture_sidecar_keypair().public_key(),
    )
}

fn replay_entry(webhook_id: &str, expires_at_unix_seconds: u64) -> AgentWebReplayEntry {
    replay_entry_in_scope(1, webhook_id, expires_at_unix_seconds)
}

fn replay_entry_in_scope(
    scope_seed: u8,
    webhook_id: &str,
    expires_at_unix_seconds: u64,
) -> AgentWebReplayEntry {
    let replay_scope = AgentWebReplayScope::parse(format!("{scope_seed:064x}"))
        .test_expect("fixture replay scope parses");
    AgentWebReplayEntry::new(replay_scope, webhook_id, expires_at_unix_seconds)
        .test_expect("fixture replay entry validates")
}

#[test]
fn published_agent_web_schemas_accept_supported_projection_fixtures() {
    let envelope_schema =
        read_workspace_json("spec/schemas/chio-agent-web/v2/proof-envelope.schema.json");
    let manifest_schema = read_workspace_json(
        "spec/schemas/chio-agent-web/v1/external-projection-manifest.schema.json",
    );

    for relative_path in agent_web_envelope_or_manifest_paths(
        "fixtures/proof-room/agent-web/valid-webhook-cloudevents",
    ) {
        if relative_path.ends_with("-envelope.json") {
            assert_schema_accepts_fixture(&envelope_schema, &relative_path);
        } else {
            assert_schema_accepts_fixture(&manifest_schema, &relative_path);
        }
    }
}

#[test]
fn published_v1_proof_envelope_schema_accepts_legacy_shape() {
    let envelope_schema =
        read_workspace_json("spec/schemas/chio-agent-web/v1/proof-envelope.schema.json");
    let envelope_path = agent_web_envelope_or_manifest_paths(
        "fixtures/proof-room/agent-web/valid-webhook-cloudevents",
    )
    .into_iter()
    .find(|path| path.ends_with("-envelope.json"))
    .test_expect("Agent Web fixture contains a proof envelope");
    let mut legacy_envelope = read_workspace_json(&envelope_path);
    legacy_envelope["schema"] = json!("chio.agent-web-proof-envelope.v1");
    legacy_envelope
        .as_object_mut()
        .test_expect("proof envelope is an object")
        .remove("agent_web_passport_scope_sha256");
    let receipt_ref = legacy_envelope["receipt_refs"][0]
        .as_str()
        .test_expect("proof envelope has a receipt ref")
        .to_string();
    legacy_envelope["receipt_refs"] = json!([receipt_ref, receipt_ref]);

    assert_schema_accepts_value(
        &envelope_schema,
        &legacy_envelope,
        "legacy unscoped v1 proof envelope",
    );

    legacy_envelope["agent_web_passport_scope_sha256"] = json!(format!("{:064x}", 1));
    assert_schema_rejects_value(
        &envelope_schema,
        &legacy_envelope,
        "v1 proof envelope with a v2-only passport scope digest",
    );
}

#[test]
fn published_v2_proof_envelope_schema_requires_scope_and_unique_receipts() {
    let envelope_schema =
        read_workspace_json("spec/schemas/chio-agent-web/v2/proof-envelope.schema.json");
    let envelope_path = agent_web_envelope_or_manifest_paths(
        "fixtures/proof-room/agent-web/valid-webhook-cloudevents",
    )
    .into_iter()
    .find(|path| path.ends_with("-envelope.json"))
    .test_expect("Agent Web fixture contains a proof envelope");
    let envelope = read_workspace_json(&envelope_path);

    assert_schema_accepts_value(&envelope_schema, &envelope, "scope-bound v2 proof envelope");

    let mut missing_scope = envelope.clone();
    missing_scope
        .as_object_mut()
        .test_expect("proof envelope is an object")
        .remove("agent_web_passport_scope_sha256");
    assert_schema_rejects_value(
        &envelope_schema,
        &missing_scope,
        "v2 proof envelope without a passport scope digest",
    );

    for (label, invalid_ref) in [
        ("receipt node id", "receipt-node-agent-web-webhook-allow"),
        (
            "receipt digest",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        (
            "receipt artifact path",
            "receipts/receipt-agent-web-webhook-allow.json",
        ),
        ("uppercase receipt ref", "receipt-agent-web-Webhook-allow"),
    ] {
        let mut invalid_receipt_ref = envelope.clone();
        invalid_receipt_ref["receipt_refs"] = json!([invalid_ref]);
        assert_schema_rejects_value(
            &envelope_schema,
            &invalid_receipt_ref,
            &format!("v2 proof envelope with {label}"),
        );
    }

    let mut duplicate_receipts = envelope;
    let receipt_ref = duplicate_receipts["receipt_refs"][0]
        .as_str()
        .test_expect("proof envelope has a receipt ref")
        .to_string();
    duplicate_receipts["receipt_refs"] = json!([receipt_ref, receipt_ref]);
    assert_schema_rejects_value(
        &envelope_schema,
        &duplicate_receipts,
        "v2 proof envelope with duplicate receipt references",
    );

    for invalid_receipt_ref in [
        "receipt-agent-web-UPPERCASE",
        "receipt-agent-web-valid/../../artifact",
        "receipt-node-id",
    ] {
        let mut noncanonical_receipt = read_workspace_json(&envelope_path);
        noncanonical_receipt["receipt_refs"] = json!([invalid_receipt_ref]);
        assert_schema_rejects_value(
            &envelope_schema,
            &noncanonical_receipt,
            "v2 proof envelope with a noncanonical receipt reference",
        );
    }
}

#[test]
fn verifier_accepts_signed_legacy_v1_envelope() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    downgrade_agent_web_bundle_to_signed_v1(&mut bundle);

    let receipt: chio_core_types::receipt::body::ChioReceipt = serde_json::from_slice(
        bundle
            .artifacts
            .get("receipts/receipt-agent-web-webhook-allow.json")
            .test_expect("legacy Agent Web receipt exists"),
    )
    .test_expect("legacy Agent Web receipt parses");
    assert!(receipt
        .action
        .parameters
        .get("agent_web_receipt_ref")
        .is_none());
    assert!(receipt.action.parameters.get("content_hash").is_none());
    assert_eq!(
        receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("agent_web_receipt_ref"))
            .and_then(serde_json::Value::as_str),
        Some("receipt-agent-web-webhook-allow")
    );
    assert!(receipt
        .verify_signature()
        .test_expect("legacy Agent Web receipt signature verifies"));
    let envelope: serde_json::Value = serde_json::from_slice(
        bundle
            .artifacts
            .get("standard-webhooks-envelope.json")
            .test_expect("legacy Agent Web envelope exists"),
    )
    .test_expect("legacy Agent Web envelope parses");
    assert_eq!(
        Some(receipt.content_hash.as_str()),
        envelope
            .get("external_subject_digest")
            .and_then(serde_json::Value::as_str)
    );

    verify_agent_web_interop(&bundle)
        .test_expect("new verifier accepts signed main-shape v1 envelopes and receipts");
}

#[test]
fn verifier_accepts_legacy_v1_receipt_node_aliases() {
    for alias_field in ["id", "sha256", "path"] {
        let mut bundle = agent_web_bundle(AgentWebCase::Valid);
        downgrade_agent_web_bundle_to_signed_v1(&mut bundle);
        let graph: serde_json::Value = serde_json::from_slice(&bundle.evidence_graph_bytes)
            .test_expect("legacy Agent Web evidence graph parses");
        let receipt_node = graph["nodes"]
            .as_array()
            .test_expect("legacy Agent Web evidence graph has nodes")
            .iter()
            .find(|node| {
                node["path"].as_str() == Some("receipts/receipt-agent-web-webhook-allow.json")
            })
            .test_expect("legacy Agent Web receipt node exists");
        let alias = receipt_node[alias_field]
            .as_str()
            .test_expect("legacy Agent Web receipt alias exists")
            .to_string();

        replace_agent_web_envelope_artifact(
            &mut bundle,
            "standard-webhooks-envelope.json",
            |envelope| envelope["receipt_refs"] = json!([alias]),
        );

        verify_agent_web_interop(&bundle).test_expect(
            "v1 receipt references retain node id, digest, and artifact path compatibility",
        );
    }
}

#[test]
fn published_agent_web_report_schema_accepts_verifier_output() {
    let report_schema =
        read_workspace_json("spec/schemas/chio-agent-web/v1/interop-verifier-report.schema.json");

    for case in [
        AgentWebCase::Valid,
        AgentWebCase::VcProjection,
        AgentWebCase::DsseProjection,
    ] {
        let bundle = agent_web_bundle(case);
        let report = verify_agent_web_interop(&bundle)
            .test_expect("valid Agent Web interop bundle should verify");
        let report_value =
            serde_json::to_value(report).test_expect("Agent Web verifier report serializes");

        assert_schema_accepts_value(&report_schema, &report_value, "Agent Web verifier report");
    }
}

#[test]
fn agent_web_interop_accepts_webhook_and_cloudevents_fixture() {
    let bundle = agent_web_bundle(AgentWebCase::Valid);

    let report = verify_agent_web_interop(&bundle)
        .test_expect("valid Agent Web interop bundle should verify");

    assert_eq!(report.schema, "chio.agent-web.interop-verifier-report.v1");
    assert_eq!(report.verdict, "verified");
    assert_eq!(report.passport_id, "passport-agent-web-valid");
    assert_eq!(report.projections.len(), 5);
    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "graphql-http"));
    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "mcp"));
    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "a2a"));
    let graphql_projection = report
        .projections
        .iter()
        .find(|projection| projection.source_protocol == "graphql-http")
        .test_expect("GraphQL projection report is present");
    assert!(graphql_projection.claim_evidence.iter().any(|entry| {
        entry.claim_ref == CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND
            && entry.evidence_class == "digest-bound-reference"
    }));
    assert!(graphql_projection.claim_evidence.iter().any(|entry| {
        entry.claim_ref == CLAIM_PROJECTION_MANIFEST_BOUND
            && entry.evidence_class == "chio-sidecar-proof"
    }));
    assert!(report
        .verified_claims
        .contains(&CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_PROJECTION_MANIFEST_BOUND.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_UNSUPPORTED_CLAIMS_LIMITED.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY.to_string()));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_WEBHOOK_AUTHORITY_CLAIM.to_string()));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_GRAPHQL_SUBSCRIPTION_CLAIM.to_string()));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_GRAPHQL_AUTHORITY_CLAIM.to_string()));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_MCP_AUTHORITY_CLAIM.to_string()));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_A2A_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_tampered_transaction_passport_signature() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    bundle.passport.signature = "00".repeat(64);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Agent Web verifier must reject a forged passport root");

    assert!(error
        .to_string()
        .contains("transaction passport signature invalid"));
}

#[test]
fn agent_web_interop_rejects_valid_passport_signature_from_untrusted_signer() {
    let bundle = agent_web_bundle(AgentWebCase::Valid);
    let (_, kernel_key, sidecar_key) = default_role_keys();
    let trust = agent_web_trust_with_role_keys(
        vec![Keypair::from_seed(&[19; 32]).public_key()],
        vec![kernel_key],
        vec![sidecar_key],
        Some(Arc::new(InMemoryAgentWebReplayStore::new())),
        STANDARD_WEBHOOKS_VERIFIER_NOW,
    );

    let error = chio_agent_web_interop::verify_agent_web_interop_with_trust(&bundle, &trust)
        .test_expect_err("a cryptographically valid passport still requires a trusted signer");

    assert!(error
        .to_string()
        .contains("transaction passport signer is not trusted"));
}

#[test]
fn agent_web_interop_rejects_valid_envelope_signature_from_untrusted_sidecar() {
    let bundle = agent_web_bundle(AgentWebCase::Valid);
    let (passport_key, kernel_key, _) = default_role_keys();
    let trust = agent_web_trust_with_role_keys(
        vec![passport_key],
        vec![kernel_key],
        vec![Keypair::from_seed(&[19; 32]).public_key()],
        Some(Arc::new(InMemoryAgentWebReplayStore::new())),
        STANDARD_WEBHOOKS_VERIFIER_NOW,
    );

    let error = chio_agent_web_interop::verify_agent_web_interop_with_trust(&bundle, &trust)
        .test_expect_err("a cryptographically valid envelope still requires a trusted sidecar");

    assert!(error
        .to_string()
        .contains("Agent Web envelope signer untrusted"));
}

#[test]
fn agent_web_interop_rejects_passport_and_kernel_role_overlap() {
    let bundle = agent_web_bundle(AgentWebCase::Valid);
    let (passport_key, _, sidecar_key) = default_role_keys();
    let trust = agent_web_trust_with_role_keys(
        vec![passport_key.clone()],
        vec![passport_key],
        vec![sidecar_key],
        Some(Arc::new(InMemoryAgentWebReplayStore::new())),
        STANDARD_WEBHOOKS_VERIFIER_NOW,
    );

    let error = chio_agent_web_interop::verify_agent_web_interop_with_trust(&bundle, &trust)
        .test_expect_err("passport and kernel signer authority must be separated");

    assert!(error
        .to_string()
        .contains("Agent Web passport and kernel signer roles overlap"));
}

#[test]
fn agent_web_interop_rejects_passport_and_sidecar_role_overlap() {
    let bundle = agent_web_bundle(AgentWebCase::Valid);
    let (passport_key, kernel_key, _) = default_role_keys();
    let trust = agent_web_trust_with_role_keys(
        vec![passport_key.clone()],
        vec![kernel_key],
        vec![passport_key],
        Some(Arc::new(InMemoryAgentWebReplayStore::new())),
        STANDARD_WEBHOOKS_VERIFIER_NOW,
    );

    let error = chio_agent_web_interop::verify_agent_web_interop_with_trust(&bundle, &trust)
        .test_expect_err("passport and sidecar signer authority must be separated");

    assert!(error
        .to_string()
        .contains("Agent Web passport and sidecar signer roles overlap"));
}

#[test]
fn agent_web_interop_rejects_kernel_and_sidecar_role_overlap() {
    let bundle = agent_web_bundle(AgentWebCase::Valid);
    let (passport_key, kernel_key, _) = default_role_keys();
    let trust = agent_web_trust_with_role_keys(
        vec![passport_key],
        vec![kernel_key.clone()],
        vec![kernel_key],
        Some(Arc::new(InMemoryAgentWebReplayStore::new())),
        STANDARD_WEBHOOKS_VERIFIER_NOW,
    );

    let error = chio_agent_web_interop::verify_agent_web_interop_with_trust(&bundle, &trust)
        .test_expect_err("kernel and sidecar signer authority must be separated");

    assert!(error
        .to_string()
        .contains("Agent Web kernel and sidecar signer roles overlap"));
}

#[test]
fn agent_web_interop_rejects_standard_webhooks_without_configured_secret() {
    let bundle = agent_web_bundle(AgentWebCase::Valid);
    let trust = chio_agent_web_interop::AgentWebVerifierTrust::new()
        .with_trusted_passport_signer_keys([transaction_passport_keypair().public_key()])
        .with_standard_webhooks_replay_window(
            STANDARD_WEBHOOKS_VERIFIER_NOW,
            STANDARD_WEBHOOKS_MAX_AGE_SECONDS,
        )
        .with_trusted_envelope_sidecar_keys([agent_web_fixture_sidecar_keypair().public_key()]);

    let error = chio_agent_web_interop::verify_agent_web_interop_with_trust(&bundle, &trust)
        .test_expect_err("Standard Webhooks verification requires verifier-owned secret config");

    assert!(error
        .to_string()
        .contains("missing Standard Webhooks verifier secret"));
}

#[test]
fn agent_web_interop_rejects_receipts_without_trusted_kernel_key() {
    let bundle = agent_web_bundle(AgentWebCase::Valid);
    let trust = chio_agent_web_interop::AgentWebVerifierTrust::new()
        .with_trusted_passport_signer_keys([transaction_passport_keypair().public_key()])
        .with_standard_webhooks_secret_for(
            STANDARD_WEBHOOKS_WEBHOOK_ID,
            STANDARD_WEBHOOKS_VERIFIER_SECRET.to_vec(),
        )
        .with_standard_webhooks_replay_window(
            STANDARD_WEBHOOKS_VERIFIER_NOW,
            STANDARD_WEBHOOKS_MAX_AGE_SECONDS,
        )
        .with_trusted_envelope_sidecar_keys([agent_web_fixture_sidecar_keypair().public_key()]);

    let error = chio_agent_web_interop::verify_agent_web_interop_with_trust(&bundle, &trust)
        .test_expect_err("Agent Web receipt signer must be verifier-trusted");

    assert!(error
        .to_string()
        .contains("Agent Web receipt kernel key untrusted"));
}

#[test]
fn agent_web_interop_rejects_tampered_sidecar_envelope_signature() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    replace_agent_web_json_artifact(&mut bundle, "standard-webhooks-envelope.json", |envelope| {
        envelope["signature"] = json!("sig-agent-web-standard-webhooks-envelope-tampered");
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Agent Web sidecar envelope signature must verify");

    assert!(error
        .to_string()
        .contains("Agent Web envelope signature invalid"));
}

#[test]
fn agent_web_interop_rejects_non_content_addressed_envelope_id() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    replace_agent_web_json_artifact(&mut bundle, "standard-webhooks-envelope.json", |envelope| {
        envelope["envelope_id"] = json!("agent-web-envelope-standard-webhooks-valid");
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Agent Web envelope id must be content-addressed");

    assert!(error
        .to_string()
        .contains("Agent Web envelope id is not content-addressed"));
}

#[test]
fn agent_web_interop_rejects_passport_issuance_transplant() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    bundle.passport.issued_at = "2026-06-10T00:00:01Z".to_string();
    sign_transaction_passport(&mut bundle.passport);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("sidecar envelopes must bind the passport issuance fields");

    assert!(error
        .to_string()
        .contains("Agent Web envelope passport scope mismatch"));
}

#[test]
fn agent_web_interop_rejects_claim_set_transplant() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    replace_agent_web_json_artifact(&mut bundle, "claim-set.json", |claim_set| {
        claim_set["issued_at"] = json!("2026-06-10T00:00:01Z");
    });
    bundle.passport.claim_set_sha256 = chio_core_types::sha256_hex(
        bundle
            .artifacts
            .get("claim-set.json")
            .test_expect("Agent Web claim set exists"),
    );
    sign_transaction_passport(&mut bundle.passport);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("sidecar envelopes must bind the passport claim-set digest");

    assert!(error
        .to_string()
        .contains("Agent Web envelope passport scope mismatch"));
}

#[test]
fn agent_web_interop_rejects_receipt_from_previous_passport_scope() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    bundle.passport.issued_at = "2026-06-10T00:00:01Z".to_string();
    sign_transaction_passport(&mut bundle.passport);
    let updated_scope = chio_agent_web_interop::agent_web_passport_scope_sha256(&bundle.passport)
        .test_expect("updated passport scope hashes");
    replace_agent_web_envelope_artifact(
        &mut bundle,
        "standard-webhooks-envelope.json",
        |envelope| {
            envelope["agent_web_passport_scope_sha256"] = json!(updated_scope);
        },
    );

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("kernel receipts must bind the same passport scope as the envelope");

    assert!(error
        .to_string()
        .contains("Agent Web receipt action passport scope mismatch"));
}

#[test]
fn agent_web_interop_rejects_duplicate_projection_id() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    let mut duplicate_manifest: serde_json::Value = serde_json::from_slice(
        bundle
            .artifacts
            .get("standard-webhooks-manifest.json")
            .test_expect("standard webhooks manifest exists"),
    )
    .test_expect("standard webhooks manifest parses");
    duplicate_manifest["copy_limitations"] =
        json!(["A second artifact cannot reuse an existing projection identifier."]);
    append_agent_web_json_artifact(
        &mut bundle,
        "duplicate-standard-webhooks-manifest.json",
        "external-projection-manifest",
        "chio.agent-web.external-projection-manifest.v1",
        duplicate_manifest,
    );

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("projection identifiers must resolve to exactly one manifest");

    assert!(error
        .to_string()
        .contains("duplicate Agent Web projection id: projection-standard-webhooks-valid"));
}

#[test]
fn agent_web_interop_rejects_ambiguous_same_role_receipt_alias() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    append_agent_web_json_artifact(
        &mut bundle,
        "alternate/receipt-agent-web-webhook-allow.json",
        "receipt",
        "chio.receipt.v1",
        json!({
            "schema": "chio.receipt.v1",
            "id": "alternate-receipt-agent-web-webhook-allow"
        }),
    );

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("same-role graph aliases must resolve unambiguously");

    assert!(error
        .to_string()
        .contains("ambiguous evidence graph alias for role Receipt"));
}

#[test]
fn agent_web_interop_rejects_duplicate_envelope_id() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    let mut duplicate_envelope: serde_json::Value = serde_json::from_slice(
        bundle
            .artifacts
            .get("standard-webhooks-envelope.json")
            .test_expect("standard webhooks envelope exists"),
    )
    .test_expect("standard webhooks envelope parses");
    let second_sidecar = Keypair::from_seed(&[19; 32]);
    sign_agent_web_envelope_with_key(&mut duplicate_envelope, &second_sidecar);
    append_agent_web_json_artifact(
        &mut bundle,
        "duplicate-standard-webhooks-envelope.json",
        "agent-web-proof-envelope",
        "chio.agent-web-proof-envelope.v2",
        duplicate_envelope,
    );
    let (passport_key, kernel_key, sidecar_key) = default_role_keys();
    let trust = agent_web_trust_with_role_keys(
        vec![passport_key],
        vec![kernel_key],
        vec![sidecar_key, second_sidecar.public_key()],
        Some(Arc::new(InMemoryAgentWebReplayStore::new())),
        STANDARD_WEBHOOKS_VERIFIER_NOW,
    );

    let error = chio_agent_web_interop::verify_agent_web_interop_with_trust(&bundle, &trust)
        .test_expect_err("envelope identifiers must resolve to exactly one signed artifact");

    assert!(error
        .to_string()
        .contains("duplicate Agent Web envelope id"));
}

#[test]
fn agent_web_interop_rejects_projection_manifest_changed_after_sidecar_signature() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    replace_agent_web_json_artifact(&mut bundle, "standard-webhooks-manifest.json", |manifest| {
        let mappings = manifest["claim_mapping"]
            .as_array_mut()
            .test_expect("Agent Web manifest has claim mappings");
        let mapping = mappings
            .iter_mut()
            .find(|mapping| mapping["claim_ref"].as_str() == Some(CLAIM_PROJECTION_MANIFEST_BOUND))
            .test_expect("projection manifest claim mapping exists");
        mapping["evidence_class"] = json!("digest-bound-reference");
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("sidecar envelope signature must bind projection manifest digest");

    assert!(error
        .to_string()
        .contains("projection manifest digest mismatch"));
}

#[test]
fn agent_web_interop_rejects_external_digest_mismatch() {
    let bundle = agent_web_bundle(AgentWebCase::ExternalDigestMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("external subject digest mismatch must fail");

    assert!(error
        .to_string()
        .contains("external subject digest mismatch"));
}

#[test]
fn agent_web_interop_rejects_unresolved_receipt_ref() {
    let bundle = agent_web_bundle(AgentWebCase::MissingReceiptRef);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Agent Web receipt refs must resolve to evidence artifacts");

    assert!(error
        .to_string()
        .contains("missing Agent Web receipt ref: receipt-agent-web-webhook-allow"));
}

#[test]
fn agent_web_interop_rejects_bound_receipt_that_did_not_execute() {
    let bundle = agent_web_bundle(AgentWebCase::BoundReceiptDenied);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("external projection must bind an executed Chio receipt");

    assert!(error
        .to_string()
        .contains("Agent Web receipt did not execute"));
}

#[test]
fn agent_web_interop_rejects_unsigned_bound_receipt() {
    let bundle = agent_web_bundle(AgentWebCase::BoundReceiptUnsigned);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("external projection must bind a signed Chio receipt");

    assert!(error
        .to_string()
        .contains("Agent Web receipt signature invalid"));
}

#[test]
fn agent_web_interop_rejects_bound_receipt_for_different_policy() {
    let bundle = agent_web_bundle(AgentWebCase::BoundReceiptPolicyHashMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("external projection receipt must bind the verifier policy");

    assert!(error
        .to_string()
        .contains("Agent Web receipt policy digest mismatch"));
}

#[test]
fn agent_web_interop_rejects_bound_receipt_from_different_tool_server() {
    let bundle = agent_web_bundle(AgentWebCase::BoundReceiptProducerServerMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Agent Web receipt must come from the established tool server");

    assert!(error
        .to_string()
        .contains("Agent Web receipt producer mismatch"));
}

#[test]
fn agent_web_interop_rejects_bound_receipt_from_different_tool() {
    let bundle = agent_web_bundle(AgentWebCase::BoundReceiptProducerToolMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Agent Web receipt must come from the established projection tool");

    assert!(error
        .to_string()
        .contains("Agent Web receipt producer mismatch"));
}

#[test]
fn agent_web_interop_rejects_action_receipt_ref_mismatch() {
    let bundle = agent_web_bundle(AgentWebCase::BoundReceiptActionRefMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Agent Web receipt action must bind the envelope receipt ref");

    assert!(error
        .to_string()
        .contains("Agent Web receipt action ref mismatch"));
}

#[test]
fn agent_web_interop_rejects_action_content_digest_mismatch() {
    let bundle = agent_web_bundle(AgentWebCase::BoundReceiptActionContentHashMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Agent Web receipt action must bind the external subject digest");

    assert!(error
        .to_string()
        .contains("Agent Web receipt action content digest mismatch"));
}

#[test]
fn agent_web_interop_rejects_action_for_different_passport() {
    let bundle = agent_web_bundle(AgentWebCase::BoundReceiptActionPassportIdMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Agent Web receipt action must bind the transaction passport id");

    assert!(error
        .to_string()
        .contains("Agent Web receipt action passport id mismatch"));
}

#[test]
fn agent_web_interop_rejects_action_for_different_passport_issuer() {
    let bundle = agent_web_bundle(AgentWebCase::BoundReceiptActionPassportIssuerMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Agent Web receipt action must bind the transaction passport issuer");

    assert!(error
        .to_string()
        .contains("Agent Web receipt action passport issuer mismatch"));
}

#[test]
fn agent_web_interop_rejects_action_for_different_envelope() {
    let bundle = agent_web_bundle(AgentWebCase::BoundReceiptActionEnvelopeIdMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Agent Web receipt action must bind the proof envelope id");

    assert!(error
        .to_string()
        .contains("Agent Web receipt action envelope id mismatch"));
}

#[test]
fn agent_web_interop_rejects_action_for_different_projection_manifest() {
    let bundle = agent_web_bundle(AgentWebCase::BoundReceiptActionProjectionManifestMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Agent Web receipt action must bind the projection manifest digest");

    assert!(error
        .to_string()
        .contains("Agent Web receipt action projection manifest digest mismatch"));
}

#[test]
fn agent_web_interop_rejects_action_for_different_source_protocol() {
    let bundle = agent_web_bundle(AgentWebCase::BoundReceiptActionSourceProtocolMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Agent Web receipt action must bind the source protocol");

    assert!(error
        .to_string()
        .contains("Agent Web receipt action source protocol mismatch"));
}

#[test]
fn agent_web_interop_rejects_action_for_different_source_protocol_version() {
    let bundle = agent_web_bundle(AgentWebCase::BoundReceiptActionSourceProtocolVersionMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Agent Web receipt action must bind the source protocol version");

    assert!(error
        .to_string()
        .contains("Agent Web receipt action source protocol version mismatch"));
}

#[test]
fn agent_web_interop_rejects_envelope_missing_required_sidecar_claim() {
    let bundle = agent_web_bundle(AgentWebCase::MissingRequiredSidecarClaim);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("required sidecar claims must be present in the envelope");

    assert!(error.to_string().contains(
        "Agent Web envelope missing required claim: claim.agent_web.sidecar_not_native_authority"
    ));
}

#[test]
fn agent_web_interop_rejects_missing_manifest_binding_edge() {
    let bundle = agent_web_bundle(AgentWebCase::MissingManifestEdge);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("projection manifest must be bound by the evidence graph");

    assert!(error
        .to_string()
        .contains("missing Agent Web manifest binding edge"));
}

#[test]
fn agent_web_interop_rejects_missing_external_subject_binding_edge() {
    let bundle = agent_web_bundle(AgentWebCase::MissingExternalSubjectEdge);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("external subject must be bound by the evidence graph");

    assert!(error
        .to_string()
        .contains("missing Agent Web external subject binding edge"));
}

#[test]
fn agent_web_interop_rejects_missing_receipt_binding_edge() {
    let bundle = agent_web_bundle(AgentWebCase::MissingReceiptEdge);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("receipt refs must be bound by the evidence graph");

    assert!(error
        .to_string()
        .contains("missing Agent Web receipt binding edge"));
}

#[test]
fn agent_web_interop_rejects_unbound_risk_refs() {
    let bundle = agent_web_bundle(AgentWebCase::UnboundRiskRef);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("risk refs must not pass unless verifier loads them");

    assert!(error
        .to_string()
        .contains("Agent Web risk refs are not verifier-bound"));
}

#[test]
fn agent_web_interop_rejects_required_signature_with_none_algorithm() {
    let bundle = agent_web_bundle(AgentWebCase::RequiredSignatureAlgorithmNone);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("required external signature must name a signature algorithm");

    assert!(error
        .to_string()
        .contains("Agent Web required signature cannot use none algorithm"));
}

#[test]
fn agent_web_interop_rejects_unused_signature_algorithm() {
    let bundle = agent_web_bundle(AgentWebCase::UnusedSignatureAlgorithmPresent);

    let error = verify_agent_web_interop(&bundle).test_expect_err(
        "signature algorithm must not be present when no external signature is required",
    );

    assert!(error
        .to_string()
        .contains("Agent Web signature algorithm present without external signature requirement"));
}

#[test]
fn agent_web_interop_rejects_unsupported_claim_without_limitation() {
    let bundle = agent_web_bundle(AgentWebCase::UnsupportedClaimNotLimited);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("unsupported external claim must be explicitly limited");

    assert!(error.to_string().contains(
        "missing Agent Web unsupported authority limitation: claim.external.webhook_signature_is_chio_authority"
    ));
}

#[test]
fn agent_web_interop_rejects_policy_required_external_authority_claim() {
    let bundle = agent_web_bundle(AgentWebCase::RequiredExternalAuthorityClaim);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("external authority claims cannot be required by policy");

    assert!(error.to_string().contains(
        "Agent Web policy requires unsupported external claim: claim.external.webhook_signature_is_chio_authority"
    ));
}

#[test]
fn agent_web_interop_rejects_sidecar_claim_marked_native() {
    let bundle = agent_web_bundle(AgentWebCase::SidecarClaimMarkedNative);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("sidecar Chio proof cannot be native external authority");

    assert!(error
        .to_string()
        .contains("sidecar claim presented as native external proof"));
}

#[test]
fn agent_web_interop_rejects_missing_required_signature() {
    let bundle = agent_web_bundle(AgentWebCase::MissingRequiredSignature);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("manifest-required external signature must be present");

    assert!(error.to_string().contains("missing external signature"));
}

#[test]
fn agent_web_interop_rejects_malformed_webhook_signature() {
    let bundle = agent_web_bundle(AgentWebCase::MalformedWebhookSignature);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Standard Webhooks signature must use the v1 signature format");

    assert!(error
        .to_string()
        .contains("invalid Standard Webhooks signature"));
}

#[test]
fn agent_web_interop_rejects_forged_webhook_signature() {
    let bundle = agent_web_bundle(AgentWebCase::ForgedWebhookSignature);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Standard Webhooks signature must verify against the delivery fields");

    assert!(error
        .to_string()
        .contains("invalid Standard Webhooks signature"));
}

#[test]
fn agent_web_interop_rejects_missing_webhook_timestamp() {
    let bundle = agent_web_bundle(AgentWebCase::MissingWebhookTimestamp);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Standard Webhooks timestamp is required");

    assert!(error
        .to_string()
        .contains("missing Standard Webhooks timestamp"));
}

#[test]
fn agent_web_interop_rejects_stale_webhook_timestamp() {
    let bundle = agent_web_bundle(AgentWebCase::StaleWebhookTimestamp);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Standard Webhooks timestamp must be inside verifier replay window");

    assert!(error
        .to_string()
        .contains("stale Standard Webhooks timestamp"));
}

#[test]
fn in_memory_replay_store_closes_forward_prune_clock_rollback_window() {
    let store = InMemoryAgentWebReplayStore::new();
    store
        .check_and_insert(10, &[replay_entry("used", 20)])
        .test_expect("initial replay marker reserves");
    store
        .check_and_insert(21, &[replay_entry("forward", 30)])
        .test_expect("forward observation prunes the expired marker");

    let error = store
        .check_and_insert(20, &[replay_entry("used", 40)])
        .test_expect_err("clock rollback rejects reuse of the pruned id");
    assert!(matches!(
        error,
        AgentWebReplayStoreError::Unavailable(message)
            if message.contains("clock rollback detected")
    ));

    store
        .check_and_insert(21, &[replay_entry("used", 40)])
        .test_expect("a clock caught up to the high-water may reserve the reclaimed id");
}

#[test]
fn in_memory_replay_store_advances_clock_on_replay_and_preserves_batch_atomicity() {
    let store = InMemoryAgentWebReplayStore::new();
    store
        .check_and_insert(10, &[replay_entry("conflict", 100)])
        .test_expect("conflict marker seeds");

    let error = store
        .check_and_insert(
            50,
            &[replay_entry("fresh", 100), replay_entry("conflict", 100)],
        )
        .test_expect_err("later replay conflict rejects the batch");
    assert_eq!(
        error,
        AgentWebReplayStoreError::Replayed("conflict".to_string())
    );
    let rollback_error = store
        .check_and_insert(49, &[])
        .test_expect_err("even an empty operation fails closed during rollback");
    assert!(matches!(
        rollback_error,
        AgentWebReplayStoreError::Unavailable(message)
            if message.contains("clock rollback detected")
    ));
    store
        .check_and_insert(50, &[replay_entry("fresh", 100)])
        .test_expect("failed batch did not partially reserve its fresh id");
}

#[test]
fn in_memory_replay_store_rejects_expired_input_and_preserves_exact_boundary() {
    let store = InMemoryAgentWebReplayStore::new();
    let error = store
        .check_and_insert(10, &[replay_entry("fresh", 20), replay_entry("expired", 9)])
        .test_expect_err("an already expired marker rejects the whole batch");
    assert!(matches!(
        error,
        AgentWebReplayStoreError::Unavailable(message)
            if message.contains("replay expiry")
    ));
    store
        .check_and_insert(10, &[replay_entry("fresh", 20)])
        .test_expect("invalid batch did not reserve its valid prefix");
    store
        .check_and_insert(10, &[replay_entry("boundary", 10)])
        .test_expect("expiry equality is accepted");
    let error = store
        .check_and_insert(10, &[replay_entry("boundary", 20)])
        .test_expect_err("expiry equality remains reserved through the current second");
    assert_eq!(
        error,
        AgentWebReplayStoreError::Replayed("boundary".to_string())
    );
    store
        .check_and_insert(11, &[replay_entry("boundary", 20)])
        .test_expect("the marker becomes reclaimable after its exact expiry boundary");
}

#[test]
fn replay_scope_and_webhook_id_inputs_are_strictly_validated() {
    for invalid_scope in [
        "a".repeat(63),
        "A".repeat(64),
        "g".repeat(64),
        "a".repeat(65),
    ] {
        let error = AgentWebReplayScope::parse(invalid_scope)
            .test_expect_err("invalid replay scope rejects");
        assert!(matches!(
            error,
            AgentWebReplayStoreError::Unavailable(message)
                if message.contains("64 lowercase hexadecimal")
        ));
    }

    let replay_scope =
        AgentWebReplayScope::parse("a".repeat(64)).test_expect("valid replay scope parses");
    for invalid_id in [String::new(), "contains space".to_string(), "x".repeat(513)] {
        let error = AgentWebReplayEntry::new(replay_scope.clone(), invalid_id, 20)
            .test_expect_err("invalid webhook id rejects");
        assert!(matches!(error, AgentWebReplayStoreError::Unavailable(_)));
    }
}

#[test]
fn in_memory_replay_store_scopes_ids_to_authenticated_sender_and_endpoint() {
    let store = InMemoryAgentWebReplayStore::new_with_capacity(4, 2)
        .test_expect("positive capacities construct");
    store
        .check_and_insert(10, &[replay_entry_in_scope(1, "shared", 20)])
        .test_expect("first scope reserves id");
    store
        .check_and_insert(10, &[replay_entry_in_scope(2, "shared", 20)])
        .test_expect("second authenticated scope may reuse id");

    let error = store
        .check_and_insert(10, &[replay_entry_in_scope(1, "shared", 20)])
        .test_expect_err("same scope still rejects replay");
    assert_eq!(
        error,
        AgentWebReplayStoreError::Replayed("shared".to_string())
    );
}

#[test]
fn in_memory_replay_capacity_is_atomic_and_never_evicts_live_markers() {
    let store = InMemoryAgentWebReplayStore::new_with_capacity(2, 1)
        .test_expect("positive capacities construct");
    store
        .check_and_insert(10, &[replay_entry_in_scope(1, "one", 20)])
        .test_expect("first marker reserves");
    let per_scope_error = store
        .check_and_insert(10, &[replay_entry_in_scope(1, "two", 20)])
        .test_expect_err("per-scope capacity rejects");
    assert!(matches!(
        per_scope_error,
        AgentWebReplayStoreError::Unavailable(message)
            if message.contains("per-scope live-entry capacity")
    ));
    let replay_error = store
        .check_and_insert(10, &[replay_entry_in_scope(1, "one", 20)])
        .test_expect_err("capacity denial did not evict existing marker");
    assert_eq!(
        replay_error,
        AgentWebReplayStoreError::Replayed("one".to_string())
    );
    store
        .check_and_insert(10, &[replay_entry_in_scope(2, "two", 20)])
        .test_expect("second scope fills global capacity");
    let global_error = store
        .check_and_insert(10, &[replay_entry_in_scope(3, "three", 20)])
        .test_expect_err("global capacity rejects");
    assert!(matches!(
        global_error,
        AgentWebReplayStoreError::Unavailable(message)
            if message.contains("global live-entry capacity")
    ));

    store
        .check_and_insert(21, &[replay_entry_in_scope(3, "three", 30)])
        .test_expect("expired markers free capacity");

    let atomic_store = InMemoryAgentWebReplayStore::new_with_capacity(1, 1)
        .test_expect("positive capacities construct");
    atomic_store
        .check_and_insert(
            10,
            &[
                replay_entry_in_scope(1, "batch-one", 20),
                replay_entry_in_scope(2, "batch-two", 20),
            ],
        )
        .test_expect_err("oversized batch rejects atomically");
    atomic_store
        .check_and_insert(10, &[replay_entry_in_scope(1, "batch-one", 20)])
        .test_expect("failed oversized batch reserved no prefix");
}

#[test]
fn in_memory_replay_capacity_rejects_zero_or_inverted_limits() {
    for (global_capacity, per_scope_capacity) in [(0, 1), (1, 0), (1, 2)] {
        let error =
            InMemoryAgentWebReplayStore::new_with_capacity(global_capacity, per_scope_capacity)
                .test_expect_err("invalid capacities reject");
        assert!(matches!(error, AgentWebReplayStoreError::Unavailable(_)));
    }
}

#[test]
fn agent_web_interop_rejects_replayed_webhook_id() {
    let bundle = agent_web_bundle(AgentWebCase::Valid);
    let trust =
        agent_web_fixture_trust().with_seen_standard_webhooks_id(STANDARD_WEBHOOKS_WEBHOOK_ID);

    let error = verify_agent_web_interop_with_trust_and_consume_replays(&bundle, &trust)
        .test_expect_err("Standard Webhooks ids must be unique inside the replay window");

    assert!(error.to_string().contains("replayed Standard Webhooks id"));
}

#[test]
fn agent_web_interop_rejects_webhook_when_durable_replay_store_is_missing() {
    let bundle = agent_web_bundle(AgentWebCase::Valid);
    let (passport_key, kernel_key, sidecar_key) = default_role_keys();
    let trust = agent_web_trust_with_role_keys(
        vec![passport_key],
        vec![kernel_key],
        vec![sidecar_key],
        None,
        STANDARD_WEBHOOKS_VERIFIER_NOW,
    );

    let error = verify_agent_web_interop_with_trust_and_consume_replays(&bundle, &trust)
        .test_expect_err("webhook verification must fail closed without a replay store");

    assert!(error
        .to_string()
        .contains("missing durable Standard Webhooks replay store"));
}

#[test]
fn agent_web_interop_read_only_verification_is_idempotent_without_replay_store() {
    let bundle = agent_web_bundle(AgentWebCase::Valid);
    let (passport_key, kernel_key, sidecar_key) = default_role_keys();
    let trust = agent_web_trust_with_role_keys(
        vec![passport_key],
        vec![kernel_key],
        vec![sidecar_key],
        None,
        STANDARD_WEBHOOKS_VERIFIER_NOW,
    );

    chio_agent_web_interop::verify_agent_web_interop_with_trust(&bundle, &trust)
        .test_expect("first read-only verification succeeds without a replay store");
    chio_agent_web_interop::verify_agent_web_interop_with_trust(&bundle, &trust)
        .test_expect("repeated read-only verification remains idempotent");
}

#[test]
fn agent_web_interop_persists_webhook_replay_after_successful_verification() {
    let bundle = agent_web_bundle(AgentWebCase::Valid);
    let (passport_key, kernel_key, sidecar_key) = default_role_keys();
    let replay_store: Arc<dyn AgentWebReplayStore> = Arc::new(InMemoryAgentWebReplayStore::new());
    let trust = agent_web_trust_with_role_keys(
        vec![passport_key],
        vec![kernel_key],
        vec![sidecar_key],
        Some(replay_store),
        STANDARD_WEBHOOKS_VERIFIER_NOW,
    );

    verify_agent_web_interop_with_trust_and_consume_replays(&bundle, &trust)
        .test_expect("first webhook delivery verifies and reserves its id");
    chio_agent_web_interop::verify_agent_web_interop_with_trust(&bundle, &trust)
        .test_expect("offline verification succeeds after admission");
    chio_agent_web_interop::verify_agent_web_interop_with_trust(&bundle, &trust)
        .test_expect("repeated offline verification remains idempotent");
    let error = verify_agent_web_interop_with_trust_and_consume_replays(&bundle, &trust)
        .test_expect_err("second verification must observe the stored replay marker");

    assert!(error.to_string().contains("replayed Standard Webhooks id"));
}

#[test]
fn consuming_verifier_deduplicates_one_webhook_subject_across_envelopes() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    let graph: serde_json::Value = serde_json::from_slice(&bundle.evidence_graph_bytes)
        .test_expect("Agent Web evidence graph parses");
    let nodes = graph["nodes"]
        .as_array()
        .test_expect("Agent Web evidence graph has nodes");
    let original_envelope_node_id = nodes
        .iter()
        .find(|node| node["path"].as_str() == Some("standard-webhooks-envelope.json"))
        .and_then(|node| node["id"].as_str())
        .test_expect("standard webhooks envelope node exists")
        .to_string();
    let original_receipt_node_id = nodes
        .iter()
        .find(|node| node["path"].as_str() == Some("receipts/receipt-agent-web-webhook-allow.json"))
        .and_then(|node| node["id"].as_str())
        .test_expect("standard webhooks receipt node exists")
        .to_string();
    let mut duplicate_edges = graph["edges"]
        .as_array()
        .test_expect("Agent Web evidence graph has edges")
        .iter()
        .filter(|edge| edge["from"].as_str() == Some(original_envelope_node_id.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(duplicate_edges.len(), 3);

    let mut duplicate_envelope: serde_json::Value = serde_json::from_slice(
        bundle
            .artifacts
            .get("standard-webhooks-envelope.json")
            .test_expect("standard webhooks envelope exists"),
    )
    .test_expect("standard webhooks envelope parses");
    let duplicate_receipt_ref = "receipt-agent-web-webhook-allow-duplicate";
    duplicate_envelope["receipt_refs"] = json!([duplicate_receipt_ref]);
    duplicate_envelope["limitations"]
        .as_array_mut()
        .test_expect("standard webhooks envelope limitations are an array")
        .push(json!(
            "One authenticated delivery is projected through a second envelope."
        ));
    sign_agent_web_envelope_with_key(
        &mut duplicate_envelope,
        &agent_web_fixture_sidecar_keypair(),
    );
    let duplicate_envelope_id = duplicate_envelope["envelope_id"]
        .as_str()
        .test_expect("duplicate envelope has a content-addressed id")
        .to_string();
    let projection_manifest_sha256 = duplicate_envelope["projection_manifest_sha256"]
        .as_str()
        .test_expect("duplicate envelope binds its manifest digest")
        .to_string();
    let source_protocol = duplicate_envelope["source_protocol"]
        .as_str()
        .test_expect("duplicate envelope names its source protocol")
        .to_string();
    let source_protocol_version = duplicate_envelope["source_protocol_version"]
        .as_str()
        .test_expect("duplicate envelope names its source protocol version")
        .to_string();
    let external_subject_digest = duplicate_envelope["external_subject_digest"]
        .as_str()
        .test_expect("duplicate envelope binds its external subject")
        .to_string();
    let duplicate_envelope_node_id = append_agent_web_json_artifact(
        &mut bundle,
        "duplicate-standard-webhooks-envelope.json",
        "agent-web-proof-envelope",
        "chio.agent-web-proof-envelope.v2",
        duplicate_envelope,
    );

    let passport_scope_sha256 =
        chio_agent_web_interop::agent_web_passport_scope_sha256(&bundle.passport)
            .test_expect("Agent Web passport scope hashes");
    let receipt_intent = AgentWebReceiptIntent {
        passport_id: bundle.passport.id.clone(),
        passport_issuer: bundle.passport.issuer.clone(),
        passport_scope_sha256,
        envelope_id: duplicate_envelope_id,
        projection_manifest_sha256,
        source_protocol,
        source_protocol_version,
    };
    let duplicate_receipt: serde_json::Value =
        serde_json::from_slice(&signed_agent_web_receipt_bytes(
            AgentWebCase::Valid,
            duplicate_receipt_ref,
            &external_subject_digest,
            &bundle.passport.verifier_policy_sha256,
            true,
            &receipt_intent,
        ))
        .test_expect("duplicate Agent Web receipt parses");
    let duplicate_receipt_node_id = append_agent_web_json_artifact(
        &mut bundle,
        "receipts/receipt-agent-web-webhook-allow-duplicate.json",
        "receipt",
        "chio.receipt.v1",
        duplicate_receipt,
    );

    for edge in &mut duplicate_edges {
        edge["from"] = json!(duplicate_envelope_node_id.clone());
        if edge["to"].as_str() == Some(original_receipt_node_id.as_str()) {
            edge["to"] = json!(duplicate_receipt_node_id.clone());
        }
    }
    let mut extended_graph: serde_json::Value =
        serde_json::from_slice(&bundle.evidence_graph_bytes)
            .test_expect("extended Agent Web evidence graph parses");
    extended_graph["edges"]
        .as_array_mut()
        .test_expect("extended Agent Web evidence graph has edges")
        .extend(duplicate_edges);
    bundle.evidence_graph_bytes = json_bytes(extended_graph);
    bundle.passport.evidence_graph_sha256 =
        chio_core_types::sha256_hex(&bundle.evidence_graph_bytes);
    sign_transaction_passport(&mut bundle.passport);

    let (passport_key, kernel_key, sidecar_key) = default_role_keys();
    let capture = Arc::new(CapturingReplayStore::default());
    let replay_store: Arc<dyn AgentWebReplayStore> = capture.clone();
    let trust = agent_web_trust_with_role_keys(
        vec![passport_key],
        vec![kernel_key],
        vec![sidecar_key],
        Some(replay_store),
        STANDARD_WEBHOOKS_VERIFIER_NOW,
    );
    let report = verify_agent_web_interop_with_trust_and_consume_replays(&bundle, &trust)
        .test_expect("both envelopes for one authenticated delivery verify");

    assert_eq!(
        report
            .projections
            .iter()
            .filter(|projection| projection.source_protocol == "standard-webhooks")
            .count(),
        2
    );
    assert_eq!(
        capture
            .entries
            .lock()
            .test_expect("capture store lock remains available")
            .len(),
        1,
        "one authenticated subject reserves one replay marker"
    );
}

#[test]
fn consuming_verifier_derives_opaque_scope_only_for_authenticated_delivery() {
    let bundle = agent_web_bundle(AgentWebCase::Valid);
    let (passport_key, kernel_key, sidecar_key) = default_role_keys();
    let capture = Arc::new(CapturingReplayStore::default());
    let replay_store: Arc<dyn AgentWebReplayStore> = capture.clone();
    let trust = agent_web_trust_with_role_keys(
        vec![passport_key],
        vec![kernel_key],
        vec![sidecar_key],
        Some(replay_store),
        STANDARD_WEBHOOKS_VERIFIER_NOW,
    );

    verify_agent_web_interop_with_trust_and_consume_replays(&bundle, &trust)
        .test_expect("authenticated delivery reaches replay store");
    let captured = capture
        .entries
        .lock()
        .test_expect("capture store lock remains available");
    assert_eq!(captured.len(), 1);
    let mut scope_hasher = <Sha256 as sha2::Digest>::new();
    sha2::Digest::update(&mut scope_hasher, b"chio.agent-web.replay-scope.v2\0");
    sha2::Digest::update(
        &mut scope_hasher,
        STANDARD_WEBHOOKS_ENDPOINT_URL_DIGEST.as_bytes(),
    );
    let expected_scope = hex::encode(sha2::Digest::finalize(scope_hasher));
    assert_eq!(captured[0].replay_scope().as_str(), expected_scope);
    drop(captured);

    let forged_bundle = agent_web_bundle(AgentWebCase::ForgedWebhookSignature);
    let error = verify_agent_web_interop_with_trust_and_consume_replays(&forged_bundle, &trust)
        .test_expect_err("forged delivery rejects before replay insertion");
    assert!(error
        .to_string()
        .contains("invalid Standard Webhooks signature"));
    assert_eq!(
        capture
            .entries
            .lock()
            .test_expect("capture store lock remains available")
            .len(),
        1,
        "failed HMAC verification must not derive or insert another replay scope"
    );
}

#[test]
fn agent_web_interop_report_mismatch_does_not_consume_replay_id() {
    let bundle = agent_web_bundle(AgentWebCase::Valid);
    let (passport_key, kernel_key, sidecar_key) = default_role_keys();
    let replay_store: Arc<dyn AgentWebReplayStore> = Arc::new(InMemoryAgentWebReplayStore::new());
    let trust = agent_web_trust_with_role_keys(
        vec![passport_key],
        vec![kernel_key],
        vec![sidecar_key],
        Some(replay_store),
        STANDARD_WEBHOOKS_VERIFIER_NOW,
    );
    let expected = chio_agent_web_interop::verify_agent_web_interop_with_trust(&bundle, &trust)
        .test_expect("read-only verification succeeds");
    let mut mismatched = expected.clone();
    mismatched.id.push_str("-changed-snapshot");

    let error = verify_agent_web_interop_with_trust_and_consume_replays_if_report_matches(
        &bundle,
        &trust,
        &mismatched,
    )
    .test_expect_err("mismatched read-only report must reject before replay reservation");
    assert!(error
        .to_string()
        .contains("consuming Agent Web report does not match its read-only verification"));

    verify_agent_web_interop_with_trust_and_consume_replays_if_report_matches(
        &bundle, &trust, &expected,
    )
    .test_expect("matching retry succeeds because mismatch did not reserve replay id");
}

#[test]
fn agent_web_interop_does_not_consume_replay_id_before_whole_bundle_succeeds() {
    let valid_bundle = agent_web_bundle(AgentWebCase::Valid);
    let mut invalid_bundle = valid_bundle.clone();
    replace_agent_web_json_artifact(
        &mut invalid_bundle,
        "cloudevents-envelope.json",
        |envelope| {
            envelope["signature"] = json!("sig-ed25519:invalid");
        },
    );
    let (passport_key, kernel_key, sidecar_key) = default_role_keys();
    let replay_store: Arc<dyn AgentWebReplayStore> = Arc::new(InMemoryAgentWebReplayStore::new());
    let trust = agent_web_trust_with_role_keys(
        vec![passport_key],
        vec![kernel_key],
        vec![sidecar_key],
        Some(replay_store),
        STANDARD_WEBHOOKS_VERIFIER_NOW,
    );

    let error = verify_agent_web_interop_with_trust_and_consume_replays(&invalid_bundle, &trust)
        .test_expect_err("a later invalid envelope rejects the whole bundle");
    assert!(error
        .to_string()
        .contains("Agent Web envelope signature invalid"));
    verify_agent_web_interop_with_trust_and_consume_replays(&valid_bundle, &trust).test_expect(
        "corrected retry succeeds because the failed bundle did not consume replay id",
    );
}

#[test]
fn agent_web_interop_keeps_replay_marker_at_max_age_boundary() {
    let bundle = agent_web_bundle(AgentWebCase::Valid);
    let (passport_key, kernel_key, sidecar_key) = default_role_keys();
    let timestamp = STANDARD_WEBHOOKS_TIMESTAMP
        .parse::<u64>()
        .test_expect("fixture webhook timestamp is an integer");
    let boundary_now = timestamp + STANDARD_WEBHOOKS_MAX_AGE_SECONDS;
    let replay_store: Arc<dyn AgentWebReplayStore> = Arc::new(InMemoryAgentWebReplayStore::new());
    let trust = agent_web_trust_with_role_keys(
        vec![passport_key],
        vec![kernel_key],
        vec![sidecar_key],
        Some(replay_store),
        boundary_now,
    );

    verify_agent_web_interop_with_trust_and_consume_replays(&bundle, &trust)
        .test_expect("a webhook exactly max_age seconds old is accepted");
    let error = verify_agent_web_interop_with_trust_and_consume_replays(&bundle, &trust)
        .test_expect_err("the replay marker remains active when expires_at equals now");

    assert!(error.to_string().contains("replayed Standard Webhooks id"));
}

#[test]
fn agent_web_interop_rejects_cloudevents_specversion_mismatch() {
    let bundle = agent_web_bundle(AgentWebCase::CloudEventsSpecVersionMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("CloudEvents specversion must match the projection version");

    assert!(error
        .to_string()
        .contains("CloudEvents specversion mismatch"));
}

#[test]
fn agent_web_interop_rejects_cloudevents_authority_claim_without_limitation() {
    let bundle = agent_web_bundle(AgentWebCase::CloudEventsAuthorityClaimNotLimited);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("CloudEvents authority claim must be explicitly limited");

    assert!(error.to_string().contains(
        "missing Agent Web unsupported authority limitation: claim.external.cloudevents_event_is_chio_authority"
    ));
}

#[test]
fn agent_web_interop_rejects_graphql_http_draft_version_missing() {
    let bundle = agent_web_bundle(AgentWebCase::GraphqlHttpDraftVersionMissing);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("GraphQL over HTTP projection must keep draft status visible");

    assert!(error
        .to_string()
        .contains("GraphQL over HTTP version must be draft-labeled"));
}

#[test]
fn agent_web_interop_rejects_graphql_errors_projected_as_success() {
    let bundle = agent_web_bundle(AgentWebCase::GraphqlErrorsProjectedAsSuccess);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("GraphQL response errors must not verify as success");

    assert!(error
        .to_string()
        .contains("GraphQL response contains errors"));
}

#[test]
fn agent_web_interop_rejects_graphql_http_failed_status() {
    let bundle = agent_web_bundle(AgentWebCase::GraphqlHttpFailedStatus);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("GraphQL failed HTTP status must not verify as success");

    assert!(
        error
            .to_string()
            .contains("GraphQL HTTP status was not successful"),
        "{error}"
    );
}

#[test]
fn agent_web_interop_rejects_external_subject_schema_mismatch() {
    let bundle = agent_web_bundle(AgentWebCase::ExternalSubjectSchemaMismatch);

    let error =
        verify_agent_web_interop(&bundle).test_expect_err("external subject schema must match");

    assert!(error
        .to_string()
        .contains("external subject schema mismatch"));
}

#[test]
fn agent_web_interop_rejects_mcp_authority_claim_without_limitation() {
    let bundle = agent_web_bundle(AgentWebCase::McpAuthorityClaimNotLimited);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("MCP authority claim must be explicitly limited");

    assert!(error.to_string().contains(
        "missing Agent Web unsupported authority limitation: claim.external.mcp_tool_call_is_chio_authority"
    ));
}

#[test]
fn agent_web_interop_rejects_a2a_authority_claim_without_limitation() {
    let bundle = agent_web_bundle(AgentWebCase::A2aAuthorityClaimNotLimited);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("A2A authority claim must be explicitly limited");

    assert!(error.to_string().contains(
        "missing Agent Web unsupported authority limitation: claim.external.a2a_task_is_chio_authority"
    ));
}

#[test]
fn agent_web_interop_rejects_a2a_failed_task_state() {
    let bundle = agent_web_bundle(AgentWebCase::A2aFailedTaskState);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("A2A failed task state must not verify as success");

    assert!(
        error
            .to_string()
            .contains("A2A task state was not successful"),
        "{error}"
    );
}

#[test]
fn agent_web_interop_accepts_openapi_projection() {
    let bundle = agent_web_bundle(AgentWebCase::OpenApiProjection);

    let report = verify_agent_web_interop(&bundle).test_expect("OpenAPI projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "openapi"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_OPENAPI_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_accepts_openapi_30_projection() {
    let mut bundle = agent_web_bundle(AgentWebCase::OpenApiProjection);
    replace_agent_web_json_artifact(&mut bundle, "openapi-manifest.json", |manifest| {
        manifest["source_version"] = json!("3.0.3");
    });
    let manifest_digest = chio_core_types::sha256_hex(
        bundle
            .artifacts
            .get("openapi-manifest.json")
            .test_expect("OpenAPI manifest exists"),
    );
    replace_agent_web_envelope_artifact(&mut bundle, "openapi-envelope.json", |envelope| {
        envelope["source_protocol_version"] = json!("3.0.3");
        envelope["projection_manifest_sha256"] = json!(manifest_digest);
    });
    let subject_digest = bundle
        .artifacts
        .get("external/openapi-operation.json")
        .map(|subject| chio_core_types::sha256_hex(subject))
        .test_expect("OpenAPI subject exists");
    replace_agent_web_receipt_for_subject(
        &mut bundle,
        "receipts/receipt-agent-web-openapi-operation-allow.json",
        "receipt-agent-web-openapi-operation-allow",
        &subject_digest,
    );

    let report =
        verify_agent_web_interop(&bundle).test_expect("OpenAPI 3.0 projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "openapi"));
}

#[test]
fn agent_web_interop_rejects_openapi_without_proof_envelope_profile() {
    let mut bundle = agent_web_bundle(AgentWebCase::OpenApiProjection);
    mutate_openapi_subject_and_bound_receipt(&mut bundle, |subject| {
        subject
            .as_object_mut()
            .test_expect("OpenAPI subject is an object")
            .remove("x_chio_proof_envelope_profile");
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("OpenAPI projection must bind x-chio proof-envelope profile");

    assert!(
        error
            .to_string()
            .contains("missing OpenAPI proof-envelope profile"),
        "{error}"
    );
}

#[test]
fn agent_web_interop_rejects_openapi_profile_from_another_envelope_version() {
    let mut bundle = agent_web_bundle(AgentWebCase::OpenApiProjection);
    mutate_openapi_subject_and_bound_receipt(&mut bundle, |subject| {
        subject["x_chio_proof_envelope_profile"] = json!("chio.agent-web-proof-envelope.v1");
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("OpenAPI profile must match its proof-envelope version");

    assert!(
        error
            .to_string()
            .contains("OpenAPI proof-envelope profile mismatch"),
        "{error}"
    );
}

#[test]
fn agent_web_interop_rejects_openapi_redirect_followed() {
    let mut bundle = agent_web_bundle(AgentWebCase::OpenApiProjection);
    mutate_openapi_subject_and_bound_receipt(&mut bundle, |subject| {
        subject["redirect_followed"] = json!(true);
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("OpenAPI projection must reject followed redirects");

    assert!(
        error.to_string().contains("OpenAPI redirect was followed"),
        "{error}"
    );
}

#[test]
fn agent_web_interop_rejects_openapi_response_size_exceeded() {
    let mut bundle = agent_web_bundle(AgentWebCase::OpenApiProjection);
    mutate_openapi_subject_and_bound_receipt(&mut bundle, |subject| {
        subject["response_size_bytes"] = json!(2_000_000_u64);
        subject["max_response_size_bytes"] = json!(1_000_000_u64);
    });

    let error =
        verify_agent_web_interop(&bundle).test_expect_err("OpenAPI response size must be bounded");

    assert!(
        error
            .to_string()
            .contains("OpenAPI response exceeded size bound"),
        "{error}"
    );
}

#[test]
fn agent_web_interop_rejects_unsupported_openapi_version() {
    let bundle = agent_web_bundle(AgentWebCase::OpenApiUnsupportedVersion);

    let error =
        verify_agent_web_interop(&bundle).test_expect_err("OpenAPI projection version is bounded");

    assert!(
        error
            .to_string()
            .contains("unsupported OpenAPI source version"),
        "{error}"
    );
}

#[test]
fn agent_web_interop_rejects_openapi_unbound_operation_receipt() {
    let bundle = agent_web_bundle(AgentWebCase::OpenApiReceiptRefMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("OpenAPI operation receipt ref must be bound");

    assert!(
        error
            .to_string()
            .contains("OpenAPI operation receipt ref is not bound"),
        "{error}"
    );
}

#[test]
fn agent_web_interop_rejects_openapi_failed_status() {
    let bundle = agent_web_bundle(AgentWebCase::OpenApiFailedStatus);

    let error =
        verify_agent_web_interop(&bundle).test_expect_err("OpenAPI failed status must not verify");

    assert!(
        error
            .to_string()
            .contains("OpenAPI response status was not successful"),
        "{error}"
    );
}

fn mutate_openapi_subject_and_bound_receipt(
    bundle: &mut chio_agent_web_interop::AgentWebInteropBundle,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    replace_agent_web_json_artifact(bundle, "external/openapi-operation.json", mutate);
    let subject_digest = chio_core_types::sha256_hex(
        bundle
            .artifacts
            .get("external/openapi-operation.json")
            .test_expect("OpenAPI subject exists"),
    );
    replace_agent_web_envelope_artifact(bundle, "openapi-envelope.json", |envelope| {
        envelope["external_subject_digest"] = json!(subject_digest);
    });
    replace_agent_web_receipt_for_subject(
        bundle,
        "receipts/receipt-agent-web-openapi-operation-allow.json",
        "receipt-agent-web-openapi-operation-allow",
        &subject_digest,
    );
}

#[test]
fn agent_web_interop_accepts_acp_client_projection() {
    let bundle = agent_web_bundle(AgentWebCase::AcpClientProjection);

    let report =
        verify_agent_web_interop(&bundle).test_expect("ACP-Client projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "acp-client"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_ACP_CLIENT_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_denied_acp_client_permission() {
    let bundle = agent_web_bundle(AgentWebCase::AcpClientDenied);

    let error =
        verify_agent_web_interop(&bundle).test_expect_err("denied ACP-Client permission must fail");

    assert!(error
        .to_string()
        .contains("ACP-Client permission was denied"));
}

#[test]
fn agent_web_interop_accepts_acp_commerce_projection() {
    let bundle = agent_web_bundle(AgentWebCase::AcpCommerceProjection);

    let report =
        verify_agent_web_interop(&bundle).test_expect("ACP-Commerce projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "acp-commerce"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_ACP_COMMERCE_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_acp_commerce_order_context_digest_mismatch() {
    let bundle = agent_web_bundle(AgentWebCase::AcpCommerceOrderContextDigestMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("ACP-Commerce checkout must bind the order context digest");

    assert!(error
        .to_string()
        .contains("acp-commerce order context digest mismatch"));
}

#[test]
fn agent_web_interop_rejects_acp_commerce_unbound_checkout_receipt() {
    let bundle = agent_web_bundle(AgentWebCase::AcpCommerceReceiptRefMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("ACP-Commerce checkout receipt ref must be bound");

    assert!(
        error
            .to_string()
            .contains("ACP-Commerce checkout receipt ref is not bound"),
        "{error}"
    );
}

#[test]
fn agent_web_interop_rejects_refunded_acp_commerce_payment() {
    let bundle = agent_web_bundle(AgentWebCase::AcpCommerceRefunded);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("refunded ACP-Commerce payments must not verify");

    assert!(error
        .to_string()
        .contains("ACP-Commerce payment was refunded"));
}

#[test]
fn agent_web_interop_accepts_ag_ui_projection() {
    let bundle = agent_web_bundle(AgentWebCase::AgUiProjection);

    let report = verify_agent_web_interop(&bundle).test_expect("AG-UI projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "ag-ui"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_AG_UI_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_denied_ag_ui_event() {
    let bundle = agent_web_bundle(AgentWebCase::AgUiDenied);

    let error =
        verify_agent_web_interop(&bundle).test_expect_err("denied AG-UI events must not verify");

    assert!(error.to_string().contains("AG-UI event was not allowed"));
}

#[test]
fn agent_web_interop_accepts_browser_automation_projection() {
    let bundle = agent_web_bundle(AgentWebCase::BrowserAutomationProjection);

    let report = verify_agent_web_interop(&bundle)
        .test_expect("browser automation projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "browser-automation"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_BROWSER_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_browser_automation_unbound_command_receipt() {
    let bundle = agent_web_bundle(AgentWebCase::BrowserAutomationReceiptRefMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("browser automation command receipt must be bound to the envelope");

    assert!(
        error
            .to_string()
            .contains("browser command receipt ref is not bound"),
        "{error}"
    );
}

#[test]
fn agent_web_interop_accepts_rpa_projection() {
    let bundle = agent_web_bundle(AgentWebCase::RpaProjection);

    let report = verify_agent_web_interop(&bundle).test_expect("RPA projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "rpa"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_RPA_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_accepts_email_projection() {
    let bundle = agent_web_bundle(AgentWebCase::EmailProjection);

    let report = verify_agent_web_interop(&bundle).test_expect("Email projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "gmail-api"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_EMAIL_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_email_send_without_message_digest() {
    let bundle = agent_web_bundle(AgentWebCase::EmailMissingMessageDigest);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Gmail send projection must bind the RFC 5322 message digest");

    assert!(error.to_string().contains("missing email message digest"));
}

#[test]
fn agent_web_interop_accepts_calendar_projection() {
    let bundle = agent_web_bundle(AgentWebCase::CalendarProjection);

    let report = verify_agent_web_interop(&bundle).test_expect("Calendar projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "google-calendar-api"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_CALENDAR_AUTHORITY_CLAIM.to_string()));
}
