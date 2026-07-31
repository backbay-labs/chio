#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};

use chio_core_types::capability::governance::{
    CallChainContinuationToken, CallChainContinuationTokenBody, CHIO_CALL_CHAIN_CONTINUATION_SCHEMA,
};
use chio_core_types::receipt::lineage::{
    ReceiptLineageEndpoints, ReceiptLineageRelationKind, ReceiptLineageStatement,
    ReceiptLineageStatementBody,
};
use chio_core_types::session::{
    RequestLineageMode, RequestLineageRecord, SessionAnchor, SessionAnchorBody,
    SessionAnchorContext, SessionAnchorReference,
};
use chio_core_types::{
    sha256_hex, Keypair, OperationKind, RequestId, SessionAuthContext, SessionId, Signature,
};

const UNSUPPORTED_SCHEMA: &str = "chio.unsupported_future_schema.v999";
const BBS_PROJECTION_MANIFEST_V2_SCHEMA: &str = "chio.bbs-projection.manifest.v2";
const PROOF_ROOM_FIXTURE_CATALOG_SCHEMA: &str = "chio.proof-room.fixture-catalog.v1";
const PROOF_ROOM_FIXTURE_ROOT_CATALOG_SCHEMA: &str = "chio.proof-room.fixture-root-catalog.v1";

#[test]
fn known_signed_artifact_schemas_are_supported() {
    for schema in chio_core_types::KNOWN_SIGNED_ARTIFACT_SCHEMAS {
        assert!(
            chio_core_types::is_supported_signed_artifact_schema(schema),
            "schema should be supported: {schema}"
        );
    }
}

#[test]
fn economic_continuity_schemas_are_registered() {
    for (schema, artifact_kind) in [
        ("chio.economy.resource-head.v1", "economic_resource_head"),
        ("chio.economy.state-batch.v1", "economic_state_batch"),
        ("chio.economy.effect-slot.v1", "economic_effect_slot"),
        ("chio.economy.anchor-view.v1", "economic_state_anchor_view"),
        (
            "chio.economy.effect-dispatch-commit.v1",
            "economic_effect_dispatch_commit",
        ),
    ] {
        assert!(chio_core_types::is_supported_signed_artifact_schema(schema));
        assert!(chio_core_types::built_in_signed_artifact_registry()
            .iter()
            .any(|entry| entry.schema == schema
                && entry.artifact_kind == artifact_kind
                && entry.introduced_by == "economic-state-continuity-v1"));
    }
}

#[test]
fn clearing_signed_artifact_schemas_are_registered() {
    for (schema, artifact_kind) in [
        (
            "chio.clearing.participant-snapshot.v1",
            "clearing_participant_snapshot",
        ),
        (
            "chio.clearing.participant-snapshot-acknowledgement.v1",
            "clearing_participant_snapshot_acknowledgement",
        ),
        ("chio.clearing.input-manifest.v1", "clearing_input_manifest"),
        (
            "chio.clearing.netting-round-core.v1",
            "clearing_netting_round_core",
        ),
        (
            "chio.clearing.participant-statement.v1",
            "clearing_participant_statement",
        ),
        (
            "chio.clearing.settlement-intent.v1",
            "clearing_settlement_intent",
        ),
        (
            "chio.clearing.settlement-reconciliation.v1",
            "clearing_settlement_reconciliation",
        ),
        (
            "chio.clearing.round-satisfaction.v1",
            "clearing_round_satisfaction",
        ),
        (
            "chio.clearing.zero-intent-reconciliation.v1",
            "clearing_zero_intent_reconciliation",
        ),
        (
            "chio.clearing.atom-transformation.v1",
            "clearing_atom_transformation",
        ),
        (
            "chio.clearing.output-manifest.v1",
            "clearing_output_manifest",
        ),
        (
            "chio.clearing.participant-acceptance.v1",
            "clearing_participant_acceptance",
        ),
        (
            "chio.clearing.round-finalization.v1",
            "clearing_round_finalization",
        ),
        (
            "chio.clearing.zero-dispatch-proof.v1",
            "clearing_zero_dispatch_proof",
        ),
        ("chio.clearing.round-abort.v1", "clearing_round_abort"),
    ] {
        assert!(chio_core_types::is_supported_signed_artifact_schema(schema));
        assert!(chio_core_types::built_in_signed_artifact_registry()
            .iter()
            .any(|entry| entry.schema == schema
                && entry.artifact_kind == artifact_kind
                && entry.introduced_by == "ws4-clearing-v1"));
    }
    assert!(!chio_core_types::is_supported_signed_artifact_schema(
        "chio.clearing.round-finalization.v9"
    ));
}

#[test]
fn channel_signed_artifact_schemas_are_registered() {
    for (schema, artifact_kind) in [
        (
            "chio.channel.funding-evidence.v1",
            "channel_funding_evidence",
        ),
        ("chio.channel.open-intent.v1", "channel_open_intent"),
        (
            "chio.channel.funding-acknowledgement.v1",
            "channel_funding_acknowledgement",
        ),
        ("chio.channel.open.v1", "channel_open"),
        ("chio.channel.reservation.v1", "channel_reservation"),
        ("chio.channel.state.v1", "channel_state"),
        ("chio.channel.close.v1", "channel_close"),
        ("chio.channel.dispute.v1", "channel_dispute"),
        (
            "chio.channel.release-authorization.v1",
            "channel_release_authorization",
        ),
        (
            "chio.channel.terminal-outcome-commitment.v1",
            "channel_terminal_outcome_commitment",
        ),
    ] {
        assert!(chio_core_types::is_supported_signed_artifact_schema(schema));
        assert!(chio_core_types::built_in_signed_artifact_registry()
            .iter()
            .any(|entry| entry.schema == schema
                && entry.artifact_kind == artifact_kind
                && entry.introduced_by == "micro-escrow-channels-v1"));
    }
    assert!(!chio_core_types::is_supported_signed_artifact_schema(
        "chio.channel.open.v9"
    ));
}

#[test]
fn financial_credential_signed_artifact_schemas_are_registered() {
    for (schema, artifact_kind) in [
        (
            "chio.fincred.credit-scorecard.v1",
            "financial_credit_scorecard",
        ),
        (
            "chio.fincred.exposure-history.v1",
            "financial_exposure_history",
        ),
        (
            "chio.fincred.settlement-reliability.v1",
            "financial_settlement_reliability",
        ),
        (
            "chio.fincred.premium-history.v1",
            "financial_premium_history",
        ),
        ("chio.fincred.loss-history.v1", "financial_loss_history"),
        ("chio.fincred.source-member.v1", "financial_source_member"),
        (
            "chio.fincred.source-checkpoint.v1",
            "financial_source_checkpoint",
        ),
        (
            "chio.fincred.source-completeness-attestation.v1",
            "financial_source_completeness_attestation",
        ),
        (
            "chio.financial-agent-passport.source-manifest.v1",
            "agent_passport_source_manifest",
        ),
        (
            "chio.financial-agent-passport-presentation-challenge.v1",
            "agent_passport_presentation_challenge",
        ),
    ] {
        assert!(chio_core_types::is_supported_signed_artifact_schema(schema));
        assert!(chio_core_types::built_in_signed_artifact_registry()
            .iter()
            .any(|entry| entry.schema == schema
                && entry.artifact_kind == artifact_kind
                && entry.introduced_by == "financial-credentials-v1"));
    }
    assert!(!chio_core_types::is_supported_signed_artifact_schema(
        "chio.fincred.credit-scorecard.v9"
    ));
}

#[test]
fn fiscal_signed_artifact_schemas_are_registered() {
    for (schema, artifact_kind) in [
        ("chio.fiscal.charter.v1", "fiscal_charter"),
        ("chio.fiscal.schedule.v1", "fiscal_schedule"),
        ("chio.fiscal.proposal.v1", "fiscal_proposal"),
        (
            "chio.fiscal.proposal-admission.v1",
            "fiscal_proposal_admission",
        ),
        ("chio.fiscal.approval.v1", "fiscal_approval"),
        ("chio.fiscal.activation.v1", "fiscal_activation"),
        (
            "chio.fiscal.consumer-readiness.v1",
            "fiscal_consumer_readiness",
        ),
        (
            "chio.fiscal.continuity-checkpoint.v1",
            "fiscal_continuity_checkpoint",
        ),
    ] {
        assert!(chio_core_types::is_supported_signed_artifact_schema(schema));
        assert!(chio_core_types::built_in_signed_artifact_registry()
            .iter()
            .any(|entry| entry.schema == schema
                && entry.artifact_kind == artifact_kind
                && entry.introduced_by == "fiscal-constitutions-v1"));
    }
    assert!(!chio_core_types::is_supported_signed_artifact_schema(
        "chio.fiscal.charter.v9"
    ));
}

#[test]
fn fiscal_genesis_policy_remains_outside_the_signed_artifact_registry() {
    let schema = "chio.fiscal.genesis-policy.v1";
    assert!(!chio_core_types::is_supported_signed_artifact_schema(
        schema
    ));
    assert!(chio_core_types::built_in_signed_artifact_registry()
        .iter()
        .all(|entry| entry.schema != schema));

    let registry: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../spec/schemas/registry.json"
    )))
    .expect("schema registry parses");
    assert!(registry
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .expect("registry artifacts are present")
        .iter()
        .all(|entry| entry.get("schema").and_then(serde_json::Value::as_str) != Some(schema)));
}

#[test]
fn econsim_qualification_matrix_is_registered_and_unknown_versions_fail_closed() {
    let schema = "chio.econsim.qualification-matrix.v1";
    assert!(chio_core_types::is_supported_signed_artifact_schema(schema));
    assert!(chio_core_types::built_in_signed_artifact_registry()
        .iter()
        .any(|entry| entry.schema == schema
            && entry.artifact_kind == "economic_simulation_qualification_matrix"
            && entry.introduced_by == "economic-wind-tunnel-v1"));
    assert!(chio_core_types::validate_signed_artifact_schema(schema).is_ok());
    assert!(chio_core_types::validate_signed_artifact_schema(
        "chio.econsim.qualification-matrix.v9"
    )
    .is_err());

    let body: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../spec/schemas/chio-econsim/v1/fixtures/qualification-matrix.positive.json"
    )))
    .expect("econsim qualification fixture parses");
    assert_eq!(body["schema"], schema);
    let signed = chio_core_types::receipt::lineage::SignedExportEnvelope::sign(
        body,
        &chio_core_types::Keypair::from_seed(&[91; 32]),
    )
    .expect("econsim qualification fixture signs");
    assert!(signed
        .verify_signature()
        .expect("econsim signature verifies"));
}

#[test]
fn fiscal_signed_artifact_registry_names_exact_schema_files() {
    let registry: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../spec/schemas/registry.json"
    )))
    .expect("schema registry parses");
    let rows: BTreeMap<&str, &str> = registry
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .expect("registry artifacts are present")
        .iter()
        .filter_map(|entry| {
            let schema = entry.get("schema")?.as_str()?;
            schema.starts_with("chio.fiscal.").then(|| {
                (
                    schema,
                    entry
                        .get("schemaFile")
                        .and_then(serde_json::Value::as_str)
                        .expect("fiscal registry entry has schemaFile"),
                )
            })
        })
        .collect();
    assert_eq!(
        rows,
        BTreeMap::from([
            (
                "chio.fiscal.activation.v1",
                "spec/schemas/chio-fiscal/v1/activation.schema.json",
            ),
            (
                "chio.fiscal.approval.v1",
                "spec/schemas/chio-fiscal/v1/approval.schema.json",
            ),
            (
                "chio.fiscal.charter.v1",
                "spec/schemas/chio-fiscal/v1/charter.schema.json",
            ),
            (
                "chio.fiscal.consumer-readiness.v1",
                "spec/schemas/chio-fiscal/v1/consumer-readiness.schema.json",
            ),
            (
                "chio.fiscal.continuity-checkpoint.v1",
                "spec/schemas/chio-fiscal/v1/continuity-checkpoint.schema.json",
            ),
            (
                "chio.fiscal.proposal-admission.v1",
                "spec/schemas/chio-fiscal/v1/proposal-admission.schema.json",
            ),
            (
                "chio.fiscal.proposal.v1",
                "spec/schemas/chio-fiscal/v1/proposal.schema.json",
            ),
            (
                "chio.fiscal.schedule.v1",
                "spec/schemas/chio-fiscal/v1/schedule.schema.json",
            ),
        ])
    );
}

#[test]
fn new_economy_artifact_families_are_registered_exactly() {
    let registry: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../spec/schemas/registry.json"
    )))
    .expect("schema registry parses");
    let rows: Vec<(&str, &str, &str, &str)> = registry
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .expect("registry artifacts are present")
        .iter()
        .filter_map(|entry| {
            let schema = entry.get("schema")?.as_str()?;
            matches!(
                schema,
                "chio.obligation.status-proof.v1"
                    | "chio.credit.facility-bind.v1"
                    | "chio.credit.receivable-iou-envelope.v1"
                    | "chio.factor.normalized-assignment-request.v1"
                    | "chio.factor.receivable-claim.v1"
                    | "chio.factor.assignment-offer.v1"
                    | "chio.factor.discount-quote.v1"
                    | "chio.factor.assignment-bind-authorization.v1"
                    | "chio.factor.assignment-agreement.v1"
                    | "chio.factor.assignment-acknowledgement.v1"
                    | "chio.factor.assignment-not-applied.v1"
                    | "chio.parametric.policy.v1"
            )
            .then(|| {
                (
                    schema,
                    entry
                        .get("artifactKind")
                        .and_then(serde_json::Value::as_str)
                        .expect("economy registry entry has artifactKind"),
                    entry
                        .get("introducedBy")
                        .and_then(serde_json::Value::as_str)
                        .expect("economy registry entry has introducedBy"),
                    entry
                        .get("schemaFile")
                        .and_then(serde_json::Value::as_str)
                        .expect("economy registry entry has schemaFile"),
                )
            })
        })
        .collect();

    assert_eq!(
        rows,
        [
            (
                "chio.obligation.status-proof.v1",
                "obligation_status_proof",
                "receivables-factoring-v1",
                "spec/schemas/chio-economy/obligation-status-proof.v1.json",
            ),
            (
                "chio.credit.facility-bind.v1",
                "credit_facility_bind",
                "credit-admission-v1",
                "spec/schemas/chio-economy/credit-facility-bind.v1.json",
            ),
            (
                "chio.credit.receivable-iou-envelope.v1",
                "credit_iou_envelope",
                "receivables-factoring-v1",
                "spec/schemas/chio-economy/receivable-iou-envelope.v1.json",
            ),
            (
                "chio.factor.normalized-assignment-request.v1",
                "factor_normalized_assignment_request",
                "receivables-factoring-v1",
                "spec/schemas/chio-economy/factor-normalized-assignment-request.v1.json",
            ),
            (
                "chio.factor.receivable-claim.v1",
                "factor_receivable_claim",
                "receivables-factoring-v1",
                "spec/schemas/chio-economy/factor-receivable-claim.v1.json",
            ),
            (
                "chio.factor.assignment-offer.v1",
                "factor_assignment_offer",
                "receivables-factoring-v1",
                "spec/schemas/chio-economy/factor-assignment-offer.v1.json",
            ),
            (
                "chio.factor.discount-quote.v1",
                "factor_discount_quote",
                "receivables-factoring-v1",
                "spec/schemas/chio-economy/factor-discount-quote.v1.json",
            ),
            (
                "chio.factor.assignment-bind-authorization.v1",
                "factor_assignment_bind_authorization",
                "receivables-factoring-v1",
                "spec/schemas/chio-economy/factor-assignment-bind-authorization.v1.json",
            ),
            (
                "chio.factor.assignment-agreement.v1",
                "factor_assignment_agreement",
                "receivables-factoring-v1",
                "spec/schemas/chio-economy/factor-assignment-agreement.v1.json",
            ),
            (
                "chio.factor.assignment-acknowledgement.v1",
                "factor_assignment_acknowledgement",
                "receivables-factoring-v1",
                "spec/schemas/chio-economy/factor-assignment-acknowledgement.v1.json",
            ),
            (
                "chio.factor.assignment-not-applied.v1",
                "factor_assignment_not_applied",
                "receivables-factoring-v1",
                "spec/schemas/chio-economy/factor-assignment-not-applied.v1.json",
            ),
            (
                "chio.parametric.policy.v1",
                "parametric_policy",
                "parametric-insurance-v1",
                "spec/schemas/chio-parametric/v1/policy.schema.json",
            ),
        ]
    );
    assert!(chio_core_types::is_supported_signed_artifact_schema(
        "chio.obligation.status-proof.v1"
    ));
    assert!(!chio_core_types::is_supported_signed_artifact_schema(
        "chio.obligation.status-proof.v9"
    ));
    assert!(chio_core_types::is_supported_signed_artifact_schema(
        "chio.credit.facility-bind.v1"
    ));
    assert!(!chio_core_types::is_supported_signed_artifact_schema(
        "chio.credit.facility-bind.v9"
    ));
    assert!(chio_core_types::is_supported_signed_artifact_schema(
        "chio.credit.receivable-iou-envelope.v1"
    ));
    assert!(!chio_core_types::is_supported_signed_artifact_schema(
        "chio.credit.iou-envelope.v9"
    ));
    for schema in [
        "chio.factor.normalized-assignment-request.v1",
        "chio.factor.receivable-claim.v1",
        "chio.factor.assignment-offer.v1",
        "chio.factor.discount-quote.v1",
    ] {
        assert!(!chio_core_types::is_supported_signed_artifact_schema(
            schema
        ));
    }
    assert!(chio_core_types::is_supported_signed_artifact_schema(
        "chio.factor.assignment-bind-authorization.v1"
    ));
    assert!(!chio_core_types::is_supported_signed_artifact_schema(
        "chio.factor.assignment-bind-authorization.v9"
    ));
    assert!(chio_core_types::is_supported_signed_artifact_schema(
        "chio.factor.assignment-agreement.v1"
    ));
    assert!(!chio_core_types::is_supported_signed_artifact_schema(
        "chio.factor.assignment-agreement.v9"
    ));
    assert!(chio_core_types::is_supported_signed_artifact_schema(
        "chio.factor.assignment-acknowledgement.v1"
    ));
    assert!(!chio_core_types::is_supported_signed_artifact_schema(
        "chio.factor.assignment-acknowledgement.v9"
    ));
    assert!(chio_core_types::is_supported_signed_artifact_schema(
        "chio.factor.assignment-not-applied.v1"
    ));
    assert!(!chio_core_types::is_supported_signed_artifact_schema(
        "chio.factor.assignment-not-applied.v9"
    ));
    assert!(chio_core_types::is_supported_signed_artifact_schema(
        "chio.parametric.policy.v1"
    ));
    assert!(!chio_core_types::is_supported_signed_artifact_schema(
        "chio.parametric.policy.v9"
    ));
}

#[test]
fn outcome_signed_artifact_schemas_are_registered_exactly() {
    let registry: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../spec/schemas/registry.json"
    )))
    .expect("schema registry parses");
    let rows: Vec<(&str, &str, &str, &str)> = registry
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .expect("registry artifacts are present")
        .iter()
        .filter_map(|entry| {
            let schema = entry.get("schema")?.as_str()?;
            schema.starts_with("chio.outcome.").then(|| {
                (
                    schema,
                    entry
                        .get("artifactKind")
                        .and_then(serde_json::Value::as_str)
                        .expect("outcome registry entry has artifactKind"),
                    entry
                        .get("introducedBy")
                        .and_then(serde_json::Value::as_str)
                        .expect("outcome registry entry has introducedBy"),
                    entry
                        .get("schemaFile")
                        .and_then(serde_json::Value::as_str)
                        .expect("outcome registry entry has schemaFile"),
                )
            })
        })
        .collect();
    let expected = [
        (
            chio_core_types::CHIO_OUTCOME_PREDICATE_V1_SCHEMA,
            "outcome_predicate",
            "verified-outcome-pricing-v1",
            "spec/schemas/chio-outcome/v1/predicate.schema.json",
        ),
        (
            chio_core_types::CHIO_OUTCOME_PRICING_V1_SCHEMA,
            "outcome_pricing",
            "verified-outcome-pricing-v1",
            "spec/schemas/chio-outcome/v1/pricing.schema.json",
        ),
        (
            chio_core_types::CHIO_OUTCOME_SLA_V1_SCHEMA,
            "outcome_sla",
            "verified-outcome-pricing-v1",
            "spec/schemas/chio-outcome/v1/sla.schema.json",
        ),
        (
            chio_core_types::CHIO_OUTCOME_ELIGIBILITY_V1_SCHEMA,
            "outcome_eligibility",
            "verified-outcome-pricing-v1",
            "spec/schemas/chio-outcome/v1/eligibility.schema.json",
        ),
        (
            chio_core_types::CHIO_OUTCOME_DELIVERY_CHECKPOINT_V1_SCHEMA,
            "outcome_delivery_checkpoint",
            "verified-outcome-pricing-v1",
            "spec/schemas/chio-outcome/v1/delivery-checkpoint.schema.json",
        ),
        (
            chio_core_types::CHIO_OUTCOME_DELIVERY_ACKNOWLEDGEMENT_V1_SCHEMA,
            "outcome_delivery_acknowledgement",
            "verified-outcome-pricing-v1",
            "spec/schemas/chio-outcome/v1/delivery-acknowledgement.schema.json",
        ),
        (
            chio_core_types::CHIO_OUTCOME_DELIVERY_NONACCEPTANCE_V1_SCHEMA,
            "outcome_delivery_nonacceptance",
            "verified-outcome-pricing-v1",
            "spec/schemas/chio-outcome/v1/delivery-nonacceptance.schema.json",
        ),
        (
            chio_core_types::CHIO_OUTCOME_OUTPUT_PROVENANCE_V1_SCHEMA,
            "outcome_output_provenance",
            "verified-outcome-pricing-v1",
            "spec/schemas/chio-outcome/v1/output-provenance.schema.json",
        ),
        (
            chio_core_types::CHIO_OUTCOME_CONTRACTUAL_ZERO_V1_SCHEMA,
            "outcome_contractual_zero",
            "verified-outcome-pricing-v1",
            "spec/schemas/chio-outcome/v1/contractual-zero.schema.json",
        ),
    ];

    assert_eq!(rows, expected);
    for (schema, ..) in expected {
        assert!(chio_core_types::is_supported_signed_artifact_schema(schema));
        let unsupported = format!(
            "{}.v9",
            schema.strip_suffix(".v1").expect("v1 schema suffix")
        );
        assert!(!chio_core_types::is_supported_signed_artifact_schema(
            &unsupported
        ));
    }
    for schema in ["chio.outcome.request.v1", "chio.outcome.verdict.v1"] {
        assert!(!chio_core_types::is_supported_signed_artifact_schema(
            schema
        ));
    }
}

#[test]
fn known_signed_artifact_schemas_match_public_registry_or_internal_exemption() {
    let registry: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../spec/schemas/registry.json"
    )))
    .expect("schema registry parses");
    let registered_schemas: BTreeSet<&str> = registry
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .expect("registry artifacts are present")
        .iter()
        .filter_map(|entry| entry.get("schema").and_then(serde_json::Value::as_str))
        .collect();
    let internal_only_schemas: BTreeSet<&str> = [
        "chio.session_anchor.v1",
        "chio.request_lineage_record.v1",
        "chio.runtime-attestation.azure-maa.jwt.v1",
        "chio.runtime-attestation.aws-nitro-attestation.v1",
        "chio.runtime-attestation.google-confidential-vm.jwt.v1",
        "chio.runtime-attestation.enterprise-verifier.json.v1",
    ]
    .into_iter()
    .collect();
    let missing_schemas: Vec<&str> = chio_core_types::KNOWN_SIGNED_ARTIFACT_SCHEMAS
        .iter()
        .copied()
        .filter(|schema| {
            !registered_schemas.contains(schema) && !internal_only_schemas.contains(schema)
        })
        .collect();

    assert!(
        missing_schemas.is_empty(),
        "known signed-artifact schemas missing from registry.json or internal exemption list: {missing_schemas:?}"
    );
}

#[test]
fn built_in_signed_artifact_registry_matches_public_metadata() {
    let registry: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../spec/schemas/registry.json"
    )))
    .expect("schema registry parses");
    let registered_metadata: BTreeMap<&str, (&str, &str)> = registry
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .expect("registry artifacts are present")
        .iter()
        .map(|entry| {
            let schema = entry
                .get("schema")
                .and_then(serde_json::Value::as_str)
                .expect("registry artifact has schema");
            let artifact_kind = entry
                .get("artifactKind")
                .and_then(serde_json::Value::as_str)
                .expect("registry artifact has artifactKind");
            let introduced_by = entry
                .get("introducedBy")
                .and_then(serde_json::Value::as_str)
                .expect("registry artifact has introducedBy");
            (schema, (artifact_kind, introduced_by))
        })
        .collect();
    let internal_only_schemas: BTreeSet<&str> = [
        "chio.session_anchor.v1",
        "chio.request_lineage_record.v1",
        "chio.runtime-attestation.azure-maa.jwt.v1",
        "chio.runtime-attestation.aws-nitro-attestation.v1",
        "chio.runtime-attestation.google-confidential-vm.jwt.v1",
        "chio.runtime-attestation.enterprise-verifier.json.v1",
    ]
    .into_iter()
    .collect();

    for entry in chio_core_types::built_in_signed_artifact_registry() {
        let Some((artifact_kind, introduced_by)) = registered_metadata.get(entry.schema.as_str())
        else {
            assert!(
                internal_only_schemas.contains(entry.schema.as_str()),
                "built-in signed-artifact registry row missing from registry.json or internal exemption list: {}",
                entry.schema
            );
            continue;
        };
        assert_eq!(
            entry.artifact_kind, *artifact_kind,
            "built-in artifact kind must match registry.json for {}",
            entry.schema
        );
        assert_eq!(
            entry.introduced_by, *introduced_by,
            "built-in introducedBy must match registry.json for {}",
            entry.schema
        );
    }
}

/// Bidirectional schema-registry parity for the cognition-market finding
/// family and for the open-market penalty artifact its challenge lane
/// registers. The generic test above proves allowlist-to-registry
/// correspondence only; a row added to registry.json without a matching
/// allowlist registration (or vice versa) would pass it. This table is the
/// lane's explicit row list: standalone signed schemas carry their exact
/// registration metadata, and registry-only unsigned schemas are enumerated
/// separately. Each milestone that registers a schema in this lane extends
/// the matching table.
#[test]
fn finding_family_schema_registry_parity_is_bidirectional() {
    /// The open-market penalty body is frozen and lives outside the
    /// `chio.finding.` namespace, but the finding challenge lane owns its
    /// public registration, so it belongs to this table.
    const MARKET_PENALTY_SCHEMA: &str = "chio.registry.market-penalty.v1";

    fn in_finding_lane(schema: &str) -> bool {
        schema.starts_with("chio.finding.") || schema == MARKET_PENALTY_SCHEMA
    }

    const EXPECTED_SIGNED: &[(&str, &str, &str, &str)] = &[
        (
            "chio.finding.v1",
            "finding",
            "finding-market-v1",
            "spec/schemas/chio-finding/v1/finding.schema.json",
        ),
        (
            "chio.finding.admission.v1",
            "finding_admission",
            "finding-market-v1",
            "spec/schemas/chio-finding/v1/admission.schema.json",
        ),
        (
            "chio.finding.audit-epoch.v1",
            "finding_audit_epoch",
            "finding-market-v1",
            "spec/schemas/chio-finding/v1/audit-epoch.schema.json",
        ),
        (
            "chio.finding.audit-report.v1",
            "finding_audit_report",
            "finding-market-v1",
            "spec/schemas/chio-finding/v1/audit-report.schema.json",
        ),
        (
            "chio.finding.bond-backing.v1",
            "finding_bond_backing",
            "finding-market-v1",
            "spec/schemas/chio-finding/v1/bond-backing.schema.json",
        ),
        (
            "chio.finding.challenge-enforcement.v1",
            "finding_challenge_enforcement",
            "finding-market-v1",
            "spec/schemas/chio-finding/v1/challenge-enforcement.schema.json",
        ),
        (
            "chio.finding.challenge-outcome.v1",
            "finding_challenge_outcome",
            "finding-market-v1",
            "spec/schemas/chio-finding/v1/challenge-outcome.schema.json",
        ),
        (
            "chio.finding.challenge-verifier-profile.v1",
            "finding_challenge_verifier_profile",
            "finding-market-v1",
            "spec/schemas/chio-finding/v1/challenge-verifier-profile.schema.json",
        ),
        (
            "chio.finding.challenge.v1",
            "finding_challenge",
            "finding-market-v1",
            "spec/schemas/chio-finding/v1/challenge.schema.json",
        ),
        (
            "chio.finding.failed-delivery.v1",
            "finding_failed_delivery",
            "finding-market-v1",
            "spec/schemas/chio-finding/v1/failed-delivery.schema.json",
        ),
        (
            "chio.finding.finalized-bond-snapshot.v1",
            "finding_finalized_bond_snapshot",
            "finding-market-v1",
            "spec/schemas/chio-finding/v1/finalized-bond-snapshot.schema.json",
        ),
        (
            "chio.finding.key-revocation.v1",
            "finding_key_revocation",
            "finding-market-v1",
            "spec/schemas/chio-finding/v1/key-revocation.schema.json",
        ),
        (
            "chio.finding.market-terms.v1",
            "finding_market_terms",
            "finding-market-v1",
            "spec/schemas/chio-finding/v1/market-terms.schema.json",
        ),
        (
            "chio.finding.purchase-record.v1",
            "finding_purchase_record",
            "finding-market-v1",
            "spec/schemas/chio-finding/v1/purchase-record.schema.json",
        ),
        (
            "chio.finding.seller-authorization.v1",
            "finding_seller_authorization",
            "finding-market-v1",
            "spec/schemas/chio-finding/v1/seller-authorization.schema.json",
        ),
        (
            "chio.finding.verifier-report.v1",
            "finding_verifier_report",
            "finding-market-v1",
            "spec/schemas/chio-finding/v1/verifier-report.schema.json",
        ),
        (
            MARKET_PENALTY_SCHEMA,
            "open_market_penalty",
            "finding-market-v1",
            "spec/schemas/chio-finding/v1/market-penalty.schema.json",
        ),
    ];
    const EXPECTED_REGISTRY_ONLY: &[&str] = &[
        "chio.finding.delivery.v1",
        "chio.finding.purchase-context.v1",
        "chio.finding.replay-observation.v1",
        "chio.finding.replay-recipe-input.v1",
    ];

    let registry: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../spec/schemas/registry.json"
    )))
    .expect("schema registry parses");
    let registry_rows: BTreeMap<&str, (&str, &str, &str)> = registry
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .expect("registry artifacts are present")
        .iter()
        .filter_map(|entry| {
            let schema = entry
                .get("schema")
                .and_then(serde_json::Value::as_str)
                .expect("registry artifact has schema");
            if !in_finding_lane(schema) {
                return None;
            }
            let artifact_kind = entry
                .get("artifactKind")
                .and_then(serde_json::Value::as_str)
                .expect("registry artifact has artifactKind");
            let introduced_by = entry
                .get("introducedBy")
                .and_then(serde_json::Value::as_str)
                .expect("registry artifact has introducedBy");
            let schema_file = entry
                .get("schemaFile")
                .and_then(serde_json::Value::as_str)
                .expect("registry artifact has schemaFile");
            Some((schema, (artifact_kind, introduced_by, schema_file)))
        })
        .collect();
    let built_in_rows: BTreeMap<String, (String, String)> =
        chio_core_types::built_in_signed_artifact_registry()
            .into_iter()
            .filter(|entry| in_finding_lane(&entry.schema))
            .map(|entry| (entry.schema, (entry.artifact_kind, entry.introduced_by)))
            .collect();

    for (schema, artifact_kind, introduced_by, schema_file) in EXPECTED_SIGNED {
        assert!(
            chio_core_types::is_supported_signed_artifact_schema(schema),
            "expected signed finding-family schema must be supported: {schema}"
        );
        let (built_kind, built_introduced_by) = built_in_rows
            .get(*schema)
            .unwrap_or_else(|| panic!("expected signed row missing from allowlist: {schema}"));
        assert_eq!(built_kind, artifact_kind, "allowlist kind for {schema}");
        assert_eq!(
            built_introduced_by, introduced_by,
            "allowlist introducedBy for {schema}"
        );
        let (reg_kind, reg_introduced_by, reg_schema_file) = registry_rows
            .get(*schema)
            .unwrap_or_else(|| panic!("expected signed row missing from registry.json: {schema}"));
        assert_eq!(reg_kind, artifact_kind, "registry.json kind for {schema}");
        assert_eq!(
            reg_introduced_by, introduced_by,
            "registry.json introducedBy for {schema}"
        );
        assert_eq!(
            reg_schema_file, schema_file,
            "registry.json schemaFile for {schema}"
        );
    }
    for schema in EXPECTED_REGISTRY_ONLY {
        assert!(
            registry_rows.contains_key(schema),
            "expected registry-only row missing from registry.json: {schema}"
        );
        assert!(
            !built_in_rows.contains_key(*schema),
            "registry-only finding-family schema must stay out of the signed allowlist: {schema}"
        );
    }

    let expected: BTreeSet<&str> = EXPECTED_SIGNED
        .iter()
        .map(|(schema, _, _, _)| *schema)
        .chain(EXPECTED_REGISTRY_ONLY.iter().copied())
        .collect();
    for schema in built_in_rows.keys() {
        assert!(
            expected.contains(schema.as_str()),
            "finding-family allowlist row has no explicit parity entry: {schema}"
        );
    }
    for schema in registry_rows.keys() {
        assert!(
            expected.contains(schema),
            "finding-family registry.json row has no explicit parity entry: {schema}"
        );
    }
}

#[test]
fn public_settlement_dispatch_and_receipt_schemas_are_supported() {
    let registry: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../spec/schemas/registry.json"
    )))
    .expect("schema registry parses");
    let settlement_schemas: Vec<&str> = registry
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .expect("registry artifacts are present")
        .iter()
        .filter(|entry| {
            matches!(
                entry
                    .get("artifactKind")
                    .and_then(serde_json::Value::as_str),
                Some("web3_settlement_dispatch" | "web3_settlement_execution_receipt")
            )
        })
        .map(|entry| {
            entry
                .get("schema")
                .and_then(serde_json::Value::as_str)
                .expect("registry artifact has schema")
        })
        .collect();

    assert_eq!(settlement_schemas.len(), 4);
    for schema in settlement_schemas {
        assert!(
            chio_core_types::is_supported_signed_artifact_schema(schema),
            "public settlement schema should be supported by the core signed-artifact gate: {schema}"
        );
    }
}

#[test]
fn governed_action_evidence_schemas_are_registered() {
    for (schema, artifact_kind) in [
        ("chio.capability.proof.v1", "capability_proof"),
        ("chio.guard.decision.v1", "guard_decision"),
        ("chio.policy.bundle.v1", "policy_bundle"),
        ("chio.trust.root.v1", "trust_root"),
    ] {
        assert!(
            chio_core_types::is_supported_signed_artifact_schema(schema),
            "governed-action evidence schema should be supported: {schema}"
        );
        assert!(
            chio_core_types::built_in_signed_artifact_registry()
                .iter()
                .any(|entry| entry.schema == schema
                    && entry.artifact_kind == artifact_kind
                    && entry.introduced_by == "transaction-passport-v1"),
            "governed-action evidence schema should have a built-in registry row: {schema}"
        );
    }
}

#[test]
fn proof_room_fixture_catalog_schema_is_registered() {
    assert!(chio_core_types::is_supported_signed_artifact_schema(
        PROOF_ROOM_FIXTURE_CATALOG_SCHEMA
    ));
    assert!(chio_core_types::built_in_signed_artifact_registry()
        .iter()
        .any(|entry| entry.schema == PROOF_ROOM_FIXTURE_CATALOG_SCHEMA
            && entry.artifact_kind == "proof_room_fixture_catalog"
            && entry.introduced_by == "proof-room-v1"));
    assert!(chio_core_types::is_supported_signed_artifact_schema(
        PROOF_ROOM_FIXTURE_ROOT_CATALOG_SCHEMA
    ));
    assert!(chio_core_types::built_in_signed_artifact_registry()
        .iter()
        .any(
            |entry| entry.schema == PROOF_ROOM_FIXTURE_ROOT_CATALOG_SCHEMA
                && entry.artifact_kind == "proof_room_fixture_root_catalog"
                && entry.introduced_by == "proof-room-v1"
        ));
}

#[test]
fn public_settlement_anchor_evidence_schemas_are_registered() {
    for (schema, artifact_kind, introduced_by) in [
        (
            "chio.anchor-inclusion-proof.v1",
            "anchor_inclusion_proof",
            "public-settlement-v1",
        ),
        (
            "chio.anchor-inclusion-proof.v2",
            "anchor_inclusion_proof",
            "checkpoint-transparency-v2",
        ),
        (
            "chio.anchor-proof-bundle.v1",
            "anchor_proof_bundle",
            "public-settlement-v1",
        ),
        (
            "chio.anchor-proof-bundle.v2",
            "anchor_proof_bundle",
            "checkpoint-transparency-v2",
        ),
    ] {
        assert!(
            chio_core_types::is_supported_signed_artifact_schema(schema),
            "anchor evidence schema should be supported: {schema}"
        );
        assert!(
            chio_core_types::built_in_signed_artifact_registry()
                .iter()
                .any(|entry| entry.schema == schema
                    && entry.artifact_kind == artifact_kind
                    && entry.introduced_by == introduced_by),
            "anchor evidence schema should have a built-in registry row: {schema}"
        );
    }
}

#[test]
fn bbs_projection_manifest_v2_schema_is_registered() {
    assert!(chio_core_types::is_supported_signed_artifact_schema(
        BBS_PROJECTION_MANIFEST_V2_SCHEMA
    ));
    assert!(chio_core_types::built_in_signed_artifact_registry()
        .iter()
        .any(|entry| entry.schema == BBS_PROJECTION_MANIFEST_V2_SCHEMA
            && entry.artifact_kind == "bbs_projection_manifest"
            && entry.introduced_by == "crypto-context-v1"));
}

fn session_anchor_body(kernel: &Keypair) -> SessionAnchorBody {
    let auth = SessionAuthContext::streamable_http_static_bearer(
        "static-bearer:abcd1234",
        "cafebabe",
        Some("https://app.example".to_string()),
    );
    SessionAnchorBody::new(
        "anchor-schema",
        SessionAnchorContext::new(
            SessionId::new("sess-schema"),
            "agent-schema".to_string(),
            auth,
            None,
        ),
        1,
        1_710_000_000,
        kernel.public_key(),
    )
    .expect("session anchor body builds")
}

fn receipt_lineage_body(kernel: &Keypair) -> ReceiptLineageStatementBody {
    let endpoints = ReceiptLineageEndpoints::new(
        "parent-receipt-schema",
        "child-receipt-schema",
        RequestId::new("parent-req-schema"),
        RequestId::new("child-req-schema"),
        SessionAnchorReference::new("parent-anchor", sha256_hex(b"parent-anchor")),
        SessionAnchorReference::new("child-anchor", sha256_hex(b"child-anchor")),
    );
    ReceiptLineageStatementBody::new(
        "lineage-schema",
        endpoints,
        ReceiptLineageRelationKind::LocalChild,
        1_710_000_000,
        kernel.public_key(),
    )
}

fn continuation_body(signer: &Keypair) -> CallChainContinuationTokenBody {
    CallChainContinuationTokenBody {
        schema: CHIO_CALL_CHAIN_CONTINUATION_SCHEMA.to_string(),
        token_id: "continuation-schema".to_string(),
        signer: signer.public_key(),
        subject: Keypair::generate().public_key(),
        chain_id: "chain-schema".to_string(),
        parent_request_id: "parent-req-schema".to_string(),
        parent_receipt_id: Some("parent-receipt-schema".to_string()),
        parent_receipt_hash: Some(sha256_hex(b"parent-receipt")),
        parent_session_anchor: None,
        current_subject: "current-subject".to_string(),
        delegator_subject: "delegator-subject".to_string(),
        origin_subject: "origin-subject".to_string(),
        parent_capability_id: Some("cap-parent".to_string()),
        delegation_link_hash: Some(sha256_hex(b"delegation-link")),
        governed_intent_hash: Some(sha256_hex(b"governed-intent")),
        audience: None,
        nonce: Some("nonce-schema".to_string()),
        issued_at: 1_710_000_000,
        expires_at: 1_710_003_600,
    }
}

fn request_lineage_record() -> RequestLineageRecord {
    RequestLineageRecord::new(
        RequestId::new("request-lineage-schema"),
        SessionAnchorReference::new("anchor-schema", sha256_hex(b"anchor-schema")),
        OperationKind::ToolCall,
        RequestLineageMode::LocalChild,
        1_710_000_000,
    )
}

fn sign_body<T: serde::Serialize>(body: &T, keypair: &Keypair) -> Signature {
    keypair.sign_canonical(body).expect("body signs").0
}

fn session_anchor_from_body(body: SessionAnchorBody, signature: Signature) -> SessionAnchor {
    SessionAnchor {
        schema: body.schema,
        id: body.id,
        session_id: body.session_id,
        agent_id: body.agent_id,
        auth_context: body.auth_context,
        auth_context_hash: body.auth_context_hash,
        auth_method_hash: body.auth_method_hash,
        proof_binding: body.proof_binding,
        auth_epoch: body.auth_epoch,
        issued_at: body.issued_at,
        kernel_key: body.kernel_key,
        signature,
    }
}

fn receipt_lineage_from_body(
    body: ReceiptLineageStatementBody,
    signature: Signature,
) -> ReceiptLineageStatement {
    ReceiptLineageStatement {
        schema: body.schema,
        id: body.id,
        parent_receipt_id: body.parent_receipt_id,
        child_receipt_id: body.child_receipt_id,
        parent_request_id: body.parent_request_id,
        child_request_id: body.child_request_id,
        parent_session_anchor: body.parent_session_anchor,
        child_session_anchor: body.child_session_anchor,
        relation_kind: body.relation_kind,
        evidence_class: body.evidence_class,
        continuation_token_id: body.continuation_token_id,
        issued_at: body.issued_at,
        kernel_key: body.kernel_key,
        signature,
    }
}

fn continuation_from_body(
    body: CallChainContinuationTokenBody,
    signature: Signature,
) -> CallChainContinuationToken {
    CallChainContinuationToken {
        schema: body.schema,
        token_id: body.token_id,
        signer: body.signer,
        subject: body.subject,
        chain_id: body.chain_id,
        parent_request_id: body.parent_request_id,
        parent_receipt_id: body.parent_receipt_id,
        parent_receipt_hash: body.parent_receipt_hash,
        parent_session_anchor: body.parent_session_anchor,
        current_subject: body.current_subject,
        delegator_subject: body.delegator_subject,
        origin_subject: body.origin_subject,
        parent_capability_id: body.parent_capability_id,
        delegation_link_hash: body.delegation_link_hash,
        governed_intent_hash: body.governed_intent_hash,
        audience: body.audience,
        nonce: body.nonce,
        issued_at: body.issued_at,
        expires_at: body.expires_at,
        signature,
    }
}

#[test]
fn schema_tagged_signers_reject_unsupported_schema_ids() {
    let keypair = Keypair::generate();

    let mut anchor_body = session_anchor_body(&keypair);
    anchor_body.schema = UNSUPPORTED_SCHEMA.to_string();
    assert!(SessionAnchor::sign(anchor_body, &keypair).is_err());

    let mut lineage_body = receipt_lineage_body(&keypair);
    lineage_body.schema = UNSUPPORTED_SCHEMA.to_string();
    assert!(ReceiptLineageStatement::sign(lineage_body, &keypair).is_err());

    let mut continuation_body = continuation_body(&keypair);
    continuation_body.schema = UNSUPPORTED_SCHEMA.to_string();
    assert!(CallChainContinuationToken::sign(continuation_body, &keypair).is_err());
}

#[test]
fn schema_tagged_verifiers_reject_supported_key_with_unsupported_schema() {
    let keypair = Keypair::generate();

    let mut anchor_body = session_anchor_body(&keypair);
    anchor_body.schema = UNSUPPORTED_SCHEMA.to_string();
    let anchor_signature = sign_body(&anchor_body, &keypair);
    let anchor = session_anchor_from_body(anchor_body, anchor_signature);
    assert!(anchor.verify_signature().is_err());

    let mut lineage_body = receipt_lineage_body(&keypair);
    lineage_body.schema = UNSUPPORTED_SCHEMA.to_string();
    let lineage_signature = sign_body(&lineage_body, &keypair);
    let lineage = receipt_lineage_from_body(lineage_body, lineage_signature);
    assert!(lineage.verify_signature().is_err());

    let mut continuation_body = continuation_body(&keypair);
    continuation_body.schema = UNSUPPORTED_SCHEMA.to_string();
    let continuation_signature = sign_body(&continuation_body, &keypair);
    let continuation = continuation_from_body(continuation_body, continuation_signature);
    assert!(continuation.verify_signature().is_err());
}

#[test]
fn schema_tagged_request_lineage_record_rejects_unsupported_schema_id() {
    let mut record = request_lineage_record();
    assert!(record.validate_schema().is_ok());

    record.schema = UNSUPPORTED_SCHEMA.to_string();
    assert!(record.validate_schema().is_err());
}
