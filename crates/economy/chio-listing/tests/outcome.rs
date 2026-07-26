use chio_core_types::capability::governance::{
    VerifiedOutcomeRequestV1, VERIFIED_OUTCOME_REQUEST_SCHEMA,
};
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_listing::outcome::*;
use serde::Serialize;
use serde_json::{json, Value};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const DELIVERED_OUTPUT: &[u8] = br#"{"items":[5],"a/b":{"~key":{"y":2,"x":1}}}"#;
const FAILED_OUTPUT: &[u8] = br#"{"items":[4],"a/b":{"~key":{"y":2,"x":1}}}"#;

fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

fn money(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        currency: "USD".to_owned(),
        units,
    }
}

fn schema_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-outcome/v1")
        .join(name)
}

fn validate_schema(name: &str, artifact: &impl Serialize) -> TestResult {
    let path = schema_path(name);
    let schema = chio_spec_validate::load_json(&path)?;
    chio_spec_validate::validate_value(
        &path,
        &schema,
        &std::path::PathBuf::from("<outcome-artifact>"),
        &serde_json::to_value(artifact)?,
    )?;
    Ok(())
}

fn assert_unknown_schema_rejected(name: &str, artifact: &impl Serialize) -> TestResult {
    let path = schema_path(name);
    let schema = chio_spec_validate::load_json(&path)?;
    let mut value = serde_json::to_value(artifact)?;
    let schema_value = if value.get("body").is_some() {
        &mut value["body"]["schema"]
    } else {
        &mut value["schema"]
    };
    *schema_value = json!("chio.outcome.unknown.v9");
    assert!(chio_spec_validate::validate_value(
        &path,
        &schema,
        &std::path::PathBuf::from("<unknown-outcome-artifact>"),
        &value,
    )
    .is_err());
    Ok(())
}

fn assert_schema_rejected(name: &str, artifact: &impl Serialize) -> TestResult {
    let path = schema_path(name);
    let schema = chio_spec_validate::load_json(&path)?;
    assert!(chio_spec_validate::validate_value(
        &path,
        &schema,
        &std::path::PathBuf::from("<invalid-outcome-artifact>"),
        &serde_json::to_value(artifact)?,
    )
    .is_err());
    Ok(())
}

fn require_error<T>(result: Result<T, OutcomeError>) -> OutcomeError {
    match result {
        Ok(_) => panic!("outcome operation unexpectedly succeeded"),
        Err(error) => error,
    }
}

struct Fixture {
    provider: Keypair,
    kernel: Keypair,
    anchor: Keypair,
    receiver: Keypair,
    predicate: VerifiedOutcomePredicateV1,
    pricing: VerifiedOutcomePricingV1,
    sla: VerifiedOutcomeSlaV1,
    eligibility: AuthenticatedOutcomeEligibilityV1,
    signed_predicate: SignedOutcomePredicateV1,
    signed_pricing: SignedOutcomePricingV1,
    signed_sla: SignedOutcomeSlaV1,
    signed_eligibility: SignedOutcomeEligibilityV1,
}

fn provider_trust(fixture: &Fixture) -> Result<OutcomeSignerTrustV1, OutcomeError> {
    OutcomeSignerTrustV1::new(
        "provider-1".to_owned(),
        fixture.provider.public_key(),
        4,
        400_000,
    )
}

fn anchor_trust(fixture: &Fixture) -> Result<OutcomeSignerTrustV1, OutcomeError> {
    OutcomeSignerTrustV1::new(
        "delivery-anchor-1".to_owned(),
        fixture.anchor.public_key(),
        8,
        1,
    )
}

fn receiver_trust(fixture: &Fixture) -> Result<OutcomeSignerTrustV1, OutcomeError> {
    OutcomeSignerTrustV1::new(
        "receiver-key-1".to_owned(),
        fixture.receiver.public_key(),
        9,
        1,
    )
}

fn receiver_binding(fixture: &Fixture) -> Result<OutcomeReceiverBindingV1, OutcomeError> {
    OutcomeReceiverBindingV1::new(
        "receiver-1".to_owned(),
        "receiver-production".to_owned(),
        &anchor_trust(fixture)?,
        &receiver_trust(fixture)?,
    )
}

fn kernel_trust(fixture: &Fixture) -> Result<OutcomeSignerTrustV1, OutcomeError> {
    OutcomeSignerTrustV1::new("kernel-1".to_owned(), fixture.kernel.public_key(), 6, 1_000)
}

fn output_provenance(
    fixture: &Fixture,
    provider_output: &[u8],
    final_output: &[u8],
    redaction_proof_digest: Option<String>,
) -> Result<
    (
        SignedOutcomeOutputProvenanceV1,
        AuthenticatedOutcomeOutputProvenanceV1,
    ),
    OutcomeError,
> {
    let signed = SignedOutcomeOutputProvenanceV1::sign(
        OutcomeOutputProvenanceBodyV1::from_kernel_assertion(
            &fixture.eligibility,
            OutcomeOutputProvenanceInputV1 {
                provider_acceptance_digest: digest("provider-acceptance"),
                provider_output_digest: sha256_hex(provider_output),
                final_output_digest: sha256_hex(final_output),
                post_guard_evidence_digest: digest("post-guard-evidence"),
                redaction_proof_digest,
                authority_id: "kernel-1".to_owned(),
                authority_key_epoch: 6,
                issued_at_unix_ms: 1_300,
                expires_at_unix_ms: 1_800,
            },
        )?,
        &fixture.kernel,
    )?;
    let verified = authenticate_outcome_output_provenance(
        &canonical_outcome_bytes(&signed)?,
        &fixture.eligibility,
        &kernel_trust(fixture)?,
        1_400,
    )?;
    Ok((signed, verified))
}

fn contractual_zero(
    fixture: &Fixture,
) -> Result<
    (
        SignedOutcomeContractualZeroV1,
        AuthenticatedOutcomeContractualZeroV1,
    ),
    OutcomeError,
> {
    let signed = SignedOutcomeContractualZeroV1::sign(
        OutcomeContractualZeroBodyV1::from_kernel_assertion(
            &fixture.eligibility,
            OutcomeContractualZeroInputV1 {
                provider_acceptance_digest: digest("provider-acceptance"),
                reason: OutcomePreDeliveryZeroReasonV1::OutputBlocked,
                terminal_tool_outcome_digest: digest("terminal-tool-outcome"),
                no_delivery_slot_proof_digest: digest("no-delivery-slot"),
                post_guard_evidence_digest: digest("post-guard-evidence"),
                authority_id: "kernel-1".to_owned(),
                authority_key_epoch: 6,
                issued_at_unix_ms: 1_300,
                expires_at_unix_ms: 1_800,
            },
        )?,
        &fixture.kernel,
    )?;
    let verified = authenticate_outcome_contractual_zero(
        &canonical_outcome_bytes(&signed)?,
        &fixture.eligibility,
        &kernel_trust(fixture)?,
        1_400,
    )?;
    Ok((signed, verified))
}

fn predicate_body() -> Result<OutcomePredicateBodyV1, OutcomeError> {
    OutcomePredicateBodyV1::new(OutcomePredicateInputV1 {
        assertions: vec![
            OutcomeAssertionV1 {
                pointer: "/a~1b/~0key".to_owned(),
                comparator: OutcomeComparatorV1::Eq {
                    value: json!({"x": 1, "y": 2}),
                },
            },
            OutcomeAssertionV1 {
                pointer: "/items/0".to_owned(),
                comparator: OutcomeComparatorV1::Gte { value: json!(5) },
            },
        ],
        provider_id: "provider-1".to_owned(),
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
    })
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let provider = Keypair::from_seed(&[91; 32]);
    let kernel = Keypair::from_seed(&[92; 32]);
    let anchor = Keypair::from_seed(&[93; 32]);
    let receiver = Keypair::from_seed(&[94; 32]);
    let trusted_provider =
        OutcomeSignerTrustV1::new("provider-1".to_owned(), provider.public_key(), 4, 400_000)?;
    let trusted_anchor =
        OutcomeSignerTrustV1::new("delivery-anchor-1".to_owned(), anchor.public_key(), 8, 1)?;
    let trusted_receiver =
        OutcomeSignerTrustV1::new("receiver-key-1".to_owned(), receiver.public_key(), 9, 1)?;
    let trusted_receiver_binding = OutcomeReceiverBindingV1::new(
        "receiver-1".to_owned(),
        "receiver-production".to_owned(),
        &trusted_anchor,
        &trusted_receiver,
    )?;

    let signed_predicate = SignedOutcomePredicateV1::sign(predicate_body()?, &provider)?;
    let predicate = verify_outcome_predicate(
        &canonical_outcome_bytes(&signed_predicate)?,
        &OutcomePredicateVerificationV1 {
            provider_id: "provider-1",
            trust: &trusted_provider,
            trusted_now_unix_ms: 1_200,
        },
    )?;
    let signed_sla = SignedOutcomeSlaV1::sign(
        OutcomeSlaBodyV1::new(OutcomeSlaInputV1 {
            provider_id: "provider-1".to_owned(),
            listing_digest: digest("listing"),
            max_failure_bps: 3_333,
            minimum_sample_count: 3,
            window_seconds: 60,
            window_anchor_unix_ms: 500,
            effective_at_unix_ms: 1_000,
            expires_at_unix_ms: 300_000,
        })?,
        &provider,
    )?;
    let sla = verify_outcome_sla(
        &canonical_outcome_bytes(&signed_sla)?,
        &trusted_provider,
        1_200,
    )?;
    let signed_pricing = SignedOutcomePricingV1::sign(
        OutcomePricingBodyV1::new(OutcomePricingInputV1 {
            provider_id: "provider-1".to_owned(),
            predicate_id: predicate.body().predicate_id().to_owned(),
            predicate_digest: predicate.envelope_digest().to_owned(),
            outcome_price: money(250),
            sla_digest: Some(sla.envelope_digest().to_owned()),
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: 2_000,
        })?,
        &provider,
    )?;
    let pricing = verify_outcome_pricing(
        &canonical_outcome_bytes(&signed_pricing)?,
        &OutcomePricingVerificationV1 {
            predicate: &predicate,
            sla: Some(&sla),
            trust: &trusted_provider,
            trusted_now_unix_ms: 1_200,
        },
    )?;

    let eligibility_body =
        OutcomeEligibilityBodyV1::from_kernel_assertion(OutcomeEligibilityInputV1 {
            request_id: "req-outcome-1".to_owned(),
            capability_id: "cap-outcome-1".to_owned(),
            tool_server: "tool-server-1".to_owned(),
            tool_name: "produce".to_owned(),
            provider_id: "provider-1".to_owned(),
            listing_id: "listing-1".to_owned(),
            listing_digest: digest("listing"),
            provider_binding_digest: digest("provider-binding"),
            pricing_id: pricing.body().pricing_id().to_owned(),
            pricing_digest: pricing.envelope_digest().to_owned(),
            predicate_id: predicate.body().predicate_id().to_owned(),
            predicate_digest: predicate.envelope_digest().to_owned(),
            quote_digest: digest("quote"),
            sla_digest: Some(sla.envelope_digest().to_owned()),
            outcome_price: money(250),
            request_extension_digest: digest("request-extension"),
            pre_action_authority_digest: digest("pre-action-authority"),
            post_guard_policy_digest: digest("post-guard-policy"),
            receiver_binding_digest: trusted_receiver_binding.digest().to_owned(),
            delivery_ack_deadline_unix_ms: 1_700,
            qualified_rail_id: "qualified-rail-1".to_owned(),
            qualified_rail_capability_digest: digest("rail-capability"),
            rail_capture_deadline_unix_ms: 1_800,
            issued_at_unix_ms: 1_100,
            expires_at_unix_ms: 1_900,
            artifact_valid_until_unix_ms: 2_000,
            kernel_authority_id: "kernel-1".to_owned(),
            kernel_key_epoch: 6,
        })?;
    let signed_eligibility = SignedOutcomeEligibilityV1::sign(eligibility_body.clone(), &kernel)?;
    let kernel_trust =
        OutcomeSignerTrustV1::new("kernel-1".to_owned(), kernel.public_key(), 6, 1_000)?;
    let eligibility = authenticate_outcome_eligibility(
        &canonical_outcome_bytes(&signed_eligibility)?,
        &OutcomeEligibilityAuthenticationV1 {
            expected: &eligibility_body,
            trust: &kernel_trust,
            referenced_artifacts_valid_until_unix_ms: 2_000,
        },
        1_200,
    )?;
    Ok(Fixture {
        provider,
        kernel,
        anchor,
        receiver,
        predicate,
        pricing,
        sla,
        eligibility,
        signed_predicate,
        signed_pricing,
        signed_sla,
        signed_eligibility,
    })
}

fn signed_pending_checkpoint(
    fixture: &Fixture,
    output: &[u8],
) -> Result<SignedOutcomeDeliveryCheckpointV1, OutcomeError> {
    signed_pending_checkpoint_at(fixture, output, 1_400)
}

fn signed_pending_checkpoint_at(
    fixture: &Fixture,
    output: &[u8],
    trusted_clock_high_water_unix_ms: u64,
) -> Result<SignedOutcomeDeliveryCheckpointV1, OutcomeError> {
    SignedOutcomeDeliveryCheckpointV1::sign(
        OutcomeDeliveryCheckpointBodyV1::pending_from_anchor_assertion(
            OutcomeDeliveryCheckpointInputV1 {
                anchor_id: "delivery-anchor-1".to_owned(),
                anchor_key_epoch: 8,
                receiver_binding_digest: receiver_binding(fixture)?.digest().to_owned(),
                receiver_id: "receiver-1".to_owned(),
                receiver_namespace: "receiver-production".to_owned(),
                receiver_key_epoch: 9,
                delivery_id: "delivery-1".to_owned(),
                idempotency_key: "delivery-idempotency-1".to_owned(),
                receiver_queue_id: "receiver-queue-1".to_owned(),
                request_id: "req-outcome-1".to_owned(),
                eligibility_digest: fixture.eligibility.envelope_digest().to_owned(),
                provider_acceptance_digest: digest("provider-acceptance"),
                output_digest: sha256_hex(output),
                trusted_clock_high_water_unix_ms,
            },
        )?,
        &fixture.anchor,
    )
}

fn pending_checkpoint(
    fixture: &Fixture,
    output: &[u8],
) -> Result<AuthenticatedOutcomeDeliveryCheckpointV1, OutcomeError> {
    let signed = signed_pending_checkpoint(fixture, output)?;
    authenticate_outcome_delivery_checkpoint(
        &canonical_outcome_bytes(&signed)?,
        &anchor_trust(fixture)?,
        &receiver_binding(fixture)?,
        None,
    )
}

fn acknowledged_delivery(
    fixture: &Fixture,
    output: &[u8],
) -> Result<
    (
        SignedOutcomeDeliveryCheckpointV1,
        AuthenticatedOutcomeDeliveryCheckpointV1,
        SignedOutcomeDeliveryAcknowledgementV1,
        AuthenticatedOutcomeDeliveryAcknowledgementV1,
    ),
    OutcomeError,
> {
    acknowledged_delivery_at(fixture, output, 1_600)
}

fn acknowledged_delivery_at(
    fixture: &Fixture,
    output: &[u8],
    accepted_at_unix_ms: u64,
) -> Result<
    (
        SignedOutcomeDeliveryCheckpointV1,
        AuthenticatedOutcomeDeliveryCheckpointV1,
        SignedOutcomeDeliveryAcknowledgementV1,
        AuthenticatedOutcomeDeliveryAcknowledgementV1,
    ),
    OutcomeError,
> {
    let signed_pending =
        signed_pending_checkpoint_at(fixture, output, accepted_at_unix_ms.min(1_400))?;
    let pending = authenticate_outcome_delivery_checkpoint(
        &canonical_outcome_bytes(&signed_pending)?,
        &anchor_trust(fixture)?,
        &receiver_binding(fixture)?,
        None,
    )?;
    let signed_checkpoint = SignedOutcomeDeliveryCheckpointV1::sign(
        pending.acknowledgement_assertion(
            "blob:sha256:output".to_owned(),
            sha256_hex(output),
            accepted_at_unix_ms,
        )?,
        &fixture.anchor,
    )?;
    let checkpoint = authenticate_outcome_delivery_checkpoint(
        &canonical_outcome_bytes(&signed_checkpoint)?,
        &anchor_trust(fixture)?,
        &receiver_binding(fixture)?,
        Some(&pending),
    )?;
    let signed_ack = SignedOutcomeDeliveryAcknowledgementV1::sign(
        OutcomeDeliveryAcknowledgementBodyV1::from_receiver_assertion(
            &fixture.eligibility,
            &checkpoint,
            OutcomeDeliveryAcknowledgementInputV1 {
                receiver_key_id: "receiver-key-1".to_owned(),
            },
        )?,
        &fixture.receiver,
    )?;
    let ack = authenticate_outcome_delivery_acknowledgement(
        &canonical_outcome_bytes(&signed_ack)?,
        &fixture.eligibility,
        &checkpoint,
        &receiver_trust(fixture)?,
    )?;
    Ok((signed_checkpoint, checkpoint, signed_ack, ack))
}

fn cancelled_delivery(
    fixture: &Fixture,
    output: &[u8],
) -> Result<
    (
        SignedOutcomeDeliveryNonacceptanceV1,
        AuthenticatedOutcomeDeliveryNonacceptanceV1,
    ),
    OutcomeError,
> {
    let pending = pending_checkpoint(fixture, output)?;
    let signed_checkpoint = SignedOutcomeDeliveryCheckpointV1::sign(
        pending.cancellation_assertion(
            digest("blob-absence"),
            digest("cancellation-fence"),
            1_550,
        )?,
        &fixture.anchor,
    )?;
    let checkpoint = authenticate_outcome_delivery_checkpoint(
        &canonical_outcome_bytes(&signed_checkpoint)?,
        &anchor_trust(fixture)?,
        &receiver_binding(fixture)?,
        Some(&pending),
    )?;
    let signed = SignedOutcomeDeliveryNonacceptanceV1::sign(
        OutcomeDeliveryNonacceptanceBodyV1::from_receiver_assertion(
            &fixture.eligibility,
            &checkpoint,
            OutcomeDeliveryNonacceptanceInputV1 {
                receiver_key_id: "receiver-key-1".to_owned(),
            },
        )?,
        &fixture.receiver,
    )?;
    let verified = authenticate_outcome_delivery_nonacceptance(
        &canonical_outcome_bytes(&signed)?,
        &fixture.eligibility,
        &checkpoint,
        &receiver_trust(fixture)?,
    )?;
    Ok((signed, verified))
}

fn signed_nonacceptance_at(
    fixture: &Fixture,
    cancelled_at_unix_ms: u64,
) -> Result<
    (
        AuthenticatedOutcomeDeliveryCheckpointV1,
        SignedOutcomeDeliveryNonacceptanceV1,
    ),
    OutcomeError,
> {
    let signed_pending =
        signed_pending_checkpoint_at(fixture, DELIVERED_OUTPUT, cancelled_at_unix_ms)?;
    let pending = authenticate_outcome_delivery_checkpoint(
        &canonical_outcome_bytes(&signed_pending)?,
        &anchor_trust(fixture)?,
        &receiver_binding(fixture)?,
        None,
    )?;
    let signed_checkpoint = SignedOutcomeDeliveryCheckpointV1::sign(
        pending.cancellation_assertion(
            digest("blob-absence"),
            digest("cancellation-fence"),
            cancelled_at_unix_ms,
        )?,
        &fixture.anchor,
    )?;
    let checkpoint = authenticate_outcome_delivery_checkpoint(
        &canonical_outcome_bytes(&signed_checkpoint)?,
        &anchor_trust(fixture)?,
        &receiver_binding(fixture)?,
        Some(&pending),
    )?;
    let signed = SignedOutcomeDeliveryNonacceptanceV1::sign(
        OutcomeDeliveryNonacceptanceBodyV1::from_receiver_assertion(
            &fixture.eligibility,
            &checkpoint,
            OutcomeDeliveryNonacceptanceInputV1 {
                receiver_key_id: "receiver-key-1".to_owned(),
            },
        )?,
        &fixture.receiver,
    )?;
    Ok((checkpoint, signed))
}

fn alternate_pricing(fixture: &Fixture) -> Result<VerifiedOutcomePricingV1, OutcomeError> {
    let signed = SignedOutcomePricingV1::sign(
        OutcomePricingBodyV1::new(OutcomePricingInputV1 {
            provider_id: "provider-1".to_owned(),
            predicate_id: fixture.predicate.body().predicate_id().to_owned(),
            predicate_digest: fixture.predicate.envelope_digest().to_owned(),
            outcome_price: money(999),
            sla_digest: Some(fixture.sla.envelope_digest().to_owned()),
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: 2_000,
        })?,
        &fixture.provider,
    )?;
    verify_outcome_pricing(
        &canonical_outcome_bytes(&signed)?,
        &OutcomePricingVerificationV1 {
            predicate: &fixture.predicate,
            sla: Some(&fixture.sla),
            trust: &provider_trust(fixture)?,
            trusted_now_unix_ms: 1_200,
        },
    )
}

fn alternate_eligibility(
    fixture: &Fixture,
) -> Result<AuthenticatedOutcomeEligibilityV1, OutcomeError> {
    let body = OutcomeEligibilityBodyV1::from_kernel_assertion(OutcomeEligibilityInputV1 {
        request_id: "req-outcome-other".to_owned(),
        capability_id: "cap-outcome-1".to_owned(),
        tool_server: "tool-server-1".to_owned(),
        tool_name: "produce".to_owned(),
        provider_id: "provider-1".to_owned(),
        listing_id: "listing-other".to_owned(),
        listing_digest: digest("listing-other"),
        provider_binding_digest: digest("provider-binding"),
        pricing_id: fixture.pricing.body().pricing_id().to_owned(),
        pricing_digest: fixture.pricing.envelope_digest().to_owned(),
        predicate_id: fixture.predicate.body().predicate_id().to_owned(),
        predicate_digest: fixture.predicate.envelope_digest().to_owned(),
        quote_digest: digest("quote-other"),
        sla_digest: Some(fixture.sla.envelope_digest().to_owned()),
        outcome_price: money(250),
        request_extension_digest: digest("request-extension-other"),
        pre_action_authority_digest: digest("pre-action-authority"),
        post_guard_policy_digest: digest("post-guard-policy"),
        receiver_binding_digest: receiver_binding(fixture)?.digest().to_owned(),
        delivery_ack_deadline_unix_ms: 1_700,
        qualified_rail_id: "qualified-rail-1".to_owned(),
        qualified_rail_capability_digest: digest("rail-capability"),
        rail_capture_deadline_unix_ms: 1_800,
        issued_at_unix_ms: 1_100,
        expires_at_unix_ms: 1_900,
        artifact_valid_until_unix_ms: 2_000,
        kernel_authority_id: "kernel-1".to_owned(),
        kernel_key_epoch: 6,
    })?;
    let signed = SignedOutcomeEligibilityV1::sign(body.clone(), &fixture.kernel)?;
    authenticate_outcome_eligibility(
        &canonical_outcome_bytes(&signed)?,
        &OutcomeEligibilityAuthenticationV1 {
            expected: &body,
            trust: &kernel_trust(fixture)?,
            referenced_artifacts_valid_until_unix_ms: 2_000,
        },
        1_200,
    )
}

fn verdict_fixture(fixture: &Fixture) -> Value {
    json!({
        "schema": OUTCOME_VERDICT_SCHEMA,
        "requestId": fixture.eligibility.body().request_id(),
        "listingId": fixture.eligibility.body().listing_id(),
        "listingDigest": fixture.eligibility.body().listing_digest(),
        "providerId": fixture.eligibility.body().provider_id(),
        "providerBindingDigest": fixture.eligibility.body().provider_binding_digest(),
        "pricingId": fixture.eligibility.body().pricing_id(),
        "pricingDigest": fixture.eligibility.body().pricing_digest(),
        "predicateId": fixture.eligibility.body().predicate_id(),
        "predicateDigest": fixture.eligibility.body().predicate_digest(),
        "quoteDigest": fixture.eligibility.body().quote_digest(),
        "eligibilityDigest": fixture.eligibility.envelope_digest(),
        "providerAcceptanceDigest": digest("provider-acceptance"),
        "deliveryDisposition": "acknowledged",
        "deliveryAcknowledgementDigest": digest("delivery-acknowledgement"),
        "deliveredOutputDigest": sha256_hex(DELIVERED_OUTPUT),
        "verdict": "passed",
        "slaAttribution": "provider",
        "attributionEvidenceDigest": digest("output-provenance"),
        "chargedAmount": money(250),
        "railAuthorizationRef": "rail-auth-1"
    })
}

fn validated_verdict(value: Value, fixture: &Fixture) -> Result<OutcomeVerdictV1, OutcomeError> {
    let verdict: OutcomeVerdictV1 = load_canonical_outcome_json(&canonical_outcome_bytes(&value)?)?;
    verdict.validate_against_eligibility(&fixture.eligibility)?;
    Ok(verdict)
}

fn remove_fields(value: &mut Value, fields: &[&str]) {
    let Value::Object(object) = value else {
        panic!("verdict fixture is not an object");
    };
    for field in fields {
        let _ = object.remove(*field);
    }
}

#[test]
fn predicate_uses_rfc6901_canonical_ijson_and_exact_output_bytes() -> TestResult {
    let fixture = fixture()?;
    let passed = evaluate_outcome_predicate(&fixture.predicate, DELIVERED_OUTPUT);
    assert_eq!(passed.evaluation(), &OutcomeEvaluationV1::Passed);
    assert_eq!(passed.output_digest(), sha256_hex(DELIVERED_OUTPUT));
    assert!(matches!(
        evaluate_outcome_predicate(&fixture.predicate, br#"{"items":[],"a/b":{}}"#).evaluation(),
        OutcomeEvaluationV1::Failed {
            reason: OutcomeEvaluationReasonV1::MissingTarget,
            ..
        }
    ));
    assert_eq!(
        evaluate_outcome_predicate(&fixture.predicate, b"not-json").evaluation(),
        &OutcomeEvaluationV1::Unevaluable {
            reason: OutcomeEvaluationReasonV1::InvalidOutputJson,
        }
    );
    assert_eq!(
        evaluate_outcome_predicate(
            &fixture.predicate,
            br#"{"items":[9007199254740992],"a/b":{"~key":{"x":1,"y":2}}}"#,
        )
        .evaluation(),
        &OutcomeEvaluationV1::Unevaluable {
            reason: OutcomeEvaluationReasonV1::InvalidOutputJson,
        }
    );
    assert_eq!(
        evaluate_outcome_predicate(
            &fixture.predicate,
            br#"{"items":[5],"items":[4],"a/b":{"~key":{"x":1,"y":2}}}"#,
        )
        .evaluation(),
        &OutcomeEvaluationV1::Unevaluable {
            reason: OutcomeEvaluationReasonV1::InvalidOutputJson,
        }
    );

    let invalid_pointer = OutcomePredicateBodyV1::new(OutcomePredicateInputV1 {
        assertions: vec![OutcomeAssertionV1 {
            pointer: "/bad~2escape".to_owned(),
            comparator: OutcomeComparatorV1::Exists,
        }],
        provider_id: "provider-1".to_owned(),
        issued_at_unix_ms: 1,
        expires_at_unix_ms: 2,
    });
    assert_eq!(
        require_error(invalid_pointer),
        OutcomeError::InvalidField("pointer_escape")
    );
    assert_eq!(
        require_error(OutcomePredicateBodyV1::new(OutcomePredicateInputV1 {
            assertions: vec![OutcomeAssertionV1 {
                pointer: format!("/{}", "x".repeat(2_048)),
                comparator: OutcomeComparatorV1::Exists,
            }],
            provider_id: "provider-1".to_owned(),
            issued_at_unix_ms: 1,
            expires_at_unix_ms: 2,
        })),
        OutcomeError::InvalidField("pointer")
    );
    let duplicate = OutcomeAssertionV1 {
        pointer: "".to_owned(),
        comparator: OutcomeComparatorV1::Exists,
    };
    assert_eq!(
        require_error(OutcomePredicateBodyV1::new(OutcomePredicateInputV1 {
            assertions: vec![duplicate.clone(), duplicate],
            provider_id: "provider-1".to_owned(),
            issued_at_unix_ms: 1,
            expires_at_unix_ms: 2,
        })),
        OutcomeError::InvalidField("duplicate_assertion")
    );
    assert!(OutcomePredicateBodyV1::new(OutcomePredicateInputV1 {
        assertions: vec![OutcomeAssertionV1 {
            pointer: "".to_owned(),
            comparator: OutcomeComparatorV1::Eq {
                value: json!(9_007_199_254_740_992_u64),
            },
        }],
        provider_id: "provider-1".to_owned(),
        issued_at_unix_ms: 1,
        expires_at_unix_ms: 2,
    })
    .is_err());

    let mut malformed_pointer = serde_json::to_value(&fixture.signed_predicate)?;
    malformed_pointer["body"]["assertions"][0]["pointer"] = json!("/bad~2escape");
    assert_schema_rejected("predicate.schema.json", &malformed_pointer)?;
    let mut duplicate_assertions = serde_json::to_value(&fixture.signed_predicate)?;
    let repeated_assertion = duplicate_assertions["body"]["assertions"][0].clone();
    duplicate_assertions["body"]["assertions"] =
        Value::Array(vec![repeated_assertion.clone(), repeated_assertion]);
    assert_schema_rejected("predicate.schema.json", &duplicate_assertions)?;

    let canonical = canonical_outcome_bytes(&fixture.signed_predicate)?;
    let loaded: SignedOutcomePredicateV1 = load_canonical_outcome_json(&canonical)?;
    assert_eq!(loaded, fixture.signed_predicate);
    assert!(
        load_canonical_outcome_json::<SignedOutcomePredicateV1>(&serde_json::to_vec_pretty(
            &fixture.signed_predicate
        )?)
        .is_err()
    );
    assert!(verify_outcome_predicate(
        &serde_json::to_vec_pretty(&fixture.signed_predicate)?,
        &OutcomePredicateVerificationV1 {
            provider_id: "provider-1",
            trust: &provider_trust(&fixture)?,
            trusted_now_unix_ms: 1_200,
        },
    )
    .is_err());
    let mut unknown_field = serde_json::to_value(&fixture.signed_predicate)?;
    unknown_field["body"]["unexpected"] = json!(true);
    assert!(verify_outcome_predicate(
        &canonical_outcome_bytes(&unknown_field)?,
        &OutcomePredicateVerificationV1 {
            provider_id: "provider-1",
            trust: &provider_trust(&fixture)?,
            trusted_now_unix_ms: 1_200,
        },
    )
    .is_err());
    Ok(())
}

#[test]
fn json_pointer_rejects_signed_array_indices() -> TestResult {
    let fixture = fixture()?;
    let signed = SignedOutcomePredicateV1::sign(
        OutcomePredicateBodyV1::new(OutcomePredicateInputV1 {
            assertions: vec![OutcomeAssertionV1 {
                pointer: "/items/+1".to_owned(),
                comparator: OutcomeComparatorV1::Exists,
            }],
            provider_id: "provider-1".to_owned(),
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: 2_000,
        })?,
        &fixture.provider,
    )?;
    let predicate = verify_outcome_predicate(
        &canonical_outcome_bytes(&signed)?,
        &OutcomePredicateVerificationV1 {
            provider_id: "provider-1",
            trust: &provider_trust(&fixture)?,
            trusted_now_unix_ms: 1_200,
        },
    )?;
    assert_eq!(
        evaluate_outcome_predicate(&predicate, br#"{"items":[0,1]}"#).evaluation(),
        &OutcomeEvaluationV1::Failed {
            assertion_index: 0,
            reason: OutcomeEvaluationReasonV1::MissingTarget,
        }
    );
    Ok(())
}

#[test]
fn signed_contracts_and_eligibility_fail_closed() -> TestResult {
    let fixture = fixture()?;
    let wrong_trust = OutcomeSignerTrustV1::new(
        "provider-1".to_owned(),
        Keypair::from_seed(&[95; 32]).public_key(),
        4,
        400_000,
    )?;
    assert_eq!(
        require_error(verify_outcome_pricing(
            &canonical_outcome_bytes(&fixture.signed_pricing)?,
            &OutcomePricingVerificationV1 {
                predicate: &fixture.predicate,
                sla: Some(&fixture.sla),
                trust: &wrong_trust,
                trusted_now_unix_ms: 1_200,
            },
        )),
        OutcomeError::AuthorityVerification
    );
    assert_eq!(
        require_error(verify_outcome_sla(
            &canonical_outcome_bytes(&fixture.signed_sla)?,
            &provider_trust(&fixture)?,
            300_000,
        )),
        OutcomeError::NotCurrent
    );

    let kernel_trust =
        OutcomeSignerTrustV1::new("kernel-1".to_owned(), fixture.kernel.public_key(), 6, 1_000)?;
    let expected = fixture.signed_eligibility.body().clone();
    let mut tampered = serde_json::to_value(&fixture.signed_eligibility)?;
    tampered["body"]["quoteDigest"] = json!(digest("other-quote"));
    let tampered = canonical_outcome_bytes(&tampered)?;
    assert!(authenticate_outcome_eligibility(
        &tampered,
        &OutcomeEligibilityAuthenticationV1 {
            expected: &expected,
            trust: &kernel_trust,
            referenced_artifacts_valid_until_unix_ms: 2_000,
        },
        1_200,
    )
    .is_err());
    assert_eq!(
        require_error(authenticate_outcome_eligibility(
            &canonical_outcome_bytes(&fixture.signed_eligibility)?,
            &OutcomeEligibilityAuthenticationV1 {
                expected: &expected,
                trust: &kernel_trust,
                referenced_artifacts_valid_until_unix_ms: 1_700,
            },
            1_200,
        )),
        OutcomeError::BindingMismatch
    );
    assert!(
        OutcomeEligibilityBodyV1::from_kernel_assertion(OutcomeEligibilityInputV1 {
            request_id: "req-outcome-1".to_owned(),
            capability_id: "cap-outcome-1".to_owned(),
            tool_server: "tool-server-1".to_owned(),
            tool_name: "produce".to_owned(),
            provider_id: "provider-1".to_owned(),
            listing_id: "listing-1".to_owned(),
            listing_digest: digest("listing"),
            provider_binding_digest: digest("provider-binding"),
            pricing_id: fixture.pricing.body().pricing_id().to_owned(),
            pricing_digest: fixture.pricing.envelope_digest().to_owned(),
            predicate_id: fixture.predicate.body().predicate_id().to_owned(),
            predicate_digest: fixture.predicate.envelope_digest().to_owned(),
            quote_digest: digest("quote"),
            sla_digest: None,
            outcome_price: money(250),
            request_extension_digest: digest("request-extension"),
            pre_action_authority_digest: digest("pre-action-authority"),
            post_guard_policy_digest: digest("post-guard-policy"),
            receiver_binding_digest: receiver_binding(&fixture)?.digest().to_owned(),
            delivery_ack_deadline_unix_ms: 1_000,
            qualified_rail_id: "qualified-rail-1".to_owned(),
            qualified_rail_capability_digest: digest("rail-capability"),
            rail_capture_deadline_unix_ms: 1_800,
            issued_at_unix_ms: 1_100,
            expires_at_unix_ms: 1_900,
            artifact_valid_until_unix_ms: 2_000,
            kernel_authority_id: "kernel-1".to_owned(),
            kernel_key_epoch: 6,
        })
        .is_err()
    );

    let canonical = canonical_outcome_bytes(&fixture.signed_eligibility)?;
    assert!(authenticate_outcome_eligibility(
        &serde_json::to_vec_pretty(&fixture.signed_eligibility)?,
        &OutcomeEligibilityAuthenticationV1 {
            expected: &expected,
            trust: &kernel_trust,
            referenced_artifacts_valid_until_unix_ms: 2_000,
        },
        1_200,
    )
    .is_err());
    let checkpoint = pending_checkpoint(&fixture, DELIVERED_OUTPUT)?;
    assert_eq!(
        require_error(authenticate_outcome_eligibility(
            &canonical,
            &OutcomeEligibilityAuthenticationV1 {
                expected: &expected,
                trust: &kernel_trust,
                referenced_artifacts_valid_until_unix_ms: 2_000,
            },
            1_900,
        )),
        OutcomeError::NotCurrent
    );
    assert!(authenticate_outcome_eligibility_from_checkpoint(
        &canonical,
        &OutcomeEligibilityAuthenticationV1 {
            expected: &expected,
            trust: &kernel_trust,
            referenced_artifacts_valid_until_unix_ms: 2_000,
        },
        &checkpoint,
    )
    .is_ok());
    Ok(())
}

#[test]
fn evidence_authority_is_bound_to_eligibility_kernel() -> TestResult {
    let fixture = fixture()?;
    let foreign_kernel = Keypair::from_seed(&[99; 32]);
    let foreign_trust =
        OutcomeSignerTrustV1::new("kernel-2".to_owned(), foreign_kernel.public_key(), 7, 1_000)?;

    let provenance = SignedOutcomeOutputProvenanceV1::sign(
        OutcomeOutputProvenanceBodyV1::from_kernel_assertion(
            &fixture.eligibility,
            OutcomeOutputProvenanceInputV1 {
                provider_acceptance_digest: digest("provider-acceptance"),
                provider_output_digest: sha256_hex(DELIVERED_OUTPUT),
                final_output_digest: sha256_hex(DELIVERED_OUTPUT),
                post_guard_evidence_digest: digest("post-guard-evidence"),
                redaction_proof_digest: None,
                authority_id: "kernel-2".to_owned(),
                authority_key_epoch: 7,
                issued_at_unix_ms: 1_300,
                expires_at_unix_ms: 1_800,
            },
        )?,
        &foreign_kernel,
    )?;
    assert_eq!(
        require_error(authenticate_outcome_output_provenance(
            &canonical_outcome_bytes(&provenance)?,
            &fixture.eligibility,
            &foreign_trust,
            1_400,
        )),
        OutcomeError::BindingMismatch
    );

    let contractual_zero = SignedOutcomeContractualZeroV1::sign(
        OutcomeContractualZeroBodyV1::from_kernel_assertion(
            &fixture.eligibility,
            OutcomeContractualZeroInputV1 {
                provider_acceptance_digest: digest("provider-acceptance"),
                reason: OutcomePreDeliveryZeroReasonV1::OutputBlocked,
                terminal_tool_outcome_digest: digest("terminal-tool-outcome"),
                no_delivery_slot_proof_digest: digest("no-delivery-slot"),
                post_guard_evidence_digest: digest("post-guard-evidence"),
                authority_id: "kernel-2".to_owned(),
                authority_key_epoch: 7,
                issued_at_unix_ms: 1_300,
                expires_at_unix_ms: 1_800,
            },
        )?,
        &foreign_kernel,
    )?;
    assert_eq!(
        require_error(authenticate_outcome_contractual_zero(
            &canonical_outcome_bytes(&contractual_zero)?,
            &fixture.eligibility,
            &foreign_trust,
            1_400,
        )),
        OutcomeError::BindingMismatch
    );
    Ok(())
}

#[test]
fn delivery_evidence_is_monotonic_exact_and_trust_bound() -> TestResult {
    let fixture = fixture()?;
    let pending = pending_checkpoint(&fixture, DELIVERED_OUTPUT)?;
    assert_eq!(
        pending.body().state(),
        OutcomeDeliveryCheckpointStateV1::Pending
    );
    assert_eq!(
        require_error(pending.acknowledgement_assertion(
            "blob:wrong".to_owned(),
            digest("wrong-output"),
            1_500,
        )),
        OutcomeError::BindingMismatch
    );
    let (_, checkpoint, signed_ack, acknowledgement) =
        acknowledged_delivery(&fixture, DELIVERED_OUTPUT)?;
    assert_eq!(
        checkpoint.body().state(),
        OutcomeDeliveryCheckpointStateV1::Acknowledged
    );
    assert_eq!(
        require_error(checkpoint.acknowledgement_assertion(
            "blob:replacement".to_owned(),
            sha256_hex(DELIVERED_OUTPUT),
            1_650,
        )),
        OutcomeError::IllegalTransition
    );
    assert_eq!(acknowledgement.body().delivery_accepted_at_unix_ms(), 1_600);

    let wrong_receiver = OutcomeSignerTrustV1::new(
        "receiver-key-1".to_owned(),
        Keypair::from_seed(&[96; 32]).public_key(),
        9,
        1,
    )?;
    assert_eq!(
        require_error(authenticate_outcome_delivery_acknowledgement(
            &canonical_outcome_bytes(&signed_ack)?,
            &fixture.eligibility,
            &checkpoint,
            &wrong_receiver,
        )),
        OutcomeError::BindingMismatch
    );

    let signed_pending = signed_pending_checkpoint(&fixture, DELIVERED_OUTPUT)?;
    let wrong_anchor = OutcomeSignerTrustV1::new(
        "delivery-anchor-1".to_owned(),
        Keypair::from_seed(&[97; 32]).public_key(),
        8,
        1,
    )?;
    let wrong_binding = OutcomeReceiverBindingV1::new(
        "receiver-1".to_owned(),
        "receiver-production".to_owned(),
        &wrong_anchor,
        &receiver_trust(&fixture)?,
    )?;
    assert_ne!(wrong_binding.digest(), receiver_binding(&fixture)?.digest());
    assert_eq!(
        require_error(authenticate_outcome_delivery_checkpoint(
            &canonical_outcome_bytes(&signed_pending)?,
            &anchor_trust(&fixture)?,
            &wrong_binding,
            None,
        )),
        OutcomeError::BindingMismatch
    );

    let (_, nonacceptance) = cancelled_delivery(&fixture, DELIVERED_OUTPUT)?;
    assert_eq!(nonacceptance.body().cancelled_at_unix_ms(), 1_550);
    let pending = pending_checkpoint(&fixture, DELIVERED_OUTPUT)?;
    let signed_cancelled = SignedOutcomeDeliveryCheckpointV1::sign(
        pending.cancellation_assertion(
            digest("blob-absence"),
            digest("cancellation-fence"),
            1_550,
        )?,
        &fixture.anchor,
    )?;
    let cancelled = authenticate_outcome_delivery_checkpoint(
        &canonical_outcome_bytes(&signed_cancelled)?,
        &anchor_trust(&fixture)?,
        &receiver_binding(&fixture)?,
        Some(&pending),
    )?;
    assert_eq!(
        cancelled.body().state(),
        OutcomeDeliveryCheckpointStateV1::Cancelled
    );
    assert!(acknowledged_delivery_at(&fixture, DELIVERED_OUTPUT, 1_100).is_ok());
    assert_eq!(
        require_error(acknowledged_delivery_at(&fixture, DELIVERED_OUTPUT, 1_099,)),
        OutcomeError::NotCurrent
    );
    Ok(())
}

#[test]
fn delivery_rejects_inconsistent_blob_and_early_nonacceptance() -> TestResult {
    let fixture = fixture()?;
    let (signed_checkpoint, _, _, _) = acknowledged_delivery(&fixture, DELIVERED_OUTPUT)?;
    let mut body = serde_json::to_value(signed_checkpoint.body())?;
    body["blobDigest"] = json!(digest("wrong-output"));
    let body: OutcomeDeliveryCheckpointBodyV1 = serde_json::from_value(body)?;
    let malformed_checkpoint = SignedExportEnvelope::sign(body, &fixture.anchor)?;
    let pending = pending_checkpoint(&fixture, DELIVERED_OUTPUT)?;
    assert_eq!(
        require_error(authenticate_outcome_delivery_checkpoint(
            &canonical_outcome_bytes(&malformed_checkpoint)?,
            &anchor_trust(&fixture)?,
            &receiver_binding(&fixture)?,
            Some(&pending),
        )),
        OutcomeError::BindingMismatch
    );

    let (early_checkpoint, early_nonacceptance) =
        signed_nonacceptance_at(&fixture, fixture.eligibility.body().issued_at_unix_ms() - 1)?;
    assert_eq!(
        require_error(authenticate_outcome_delivery_nonacceptance(
            &canonical_outcome_bytes(&early_nonacceptance)?,
            &fixture.eligibility,
            &early_checkpoint,
            &receiver_trust(&fixture)?,
        )),
        OutcomeError::NotCurrent
    );

    let (late_checkpoint, late_nonacceptance) = signed_nonacceptance_at(
        &fixture,
        fixture.eligibility.body().expires_at_unix_ms() + 1,
    )?;
    assert!(authenticate_outcome_delivery_nonacceptance(
        &canonical_outcome_bytes(&late_nonacceptance)?,
        &fixture.eligibility,
        &late_checkpoint,
        &receiver_trust(&fixture)?,
    )
    .is_ok());
    Ok(())
}

#[test]
fn pricing_classification_cross_binds_delivery_and_attribution() -> TestResult {
    let fixture = fixture()?;
    let (_, _, _, acknowledgement) = acknowledged_delivery(&fixture, DELIVERED_OUTPUT)?;
    let pass_evaluation = evaluate_outcome_predicate(&fixture.predicate, DELIVERED_OUTPUT);
    let (_, provider_provenance) =
        output_provenance(&fixture, DELIVERED_OUTPUT, DELIVERED_OUTPUT, None)?;
    let pass = assess_outcome_price(
        AuthenticatedOutcomeDeliveryEvidenceV1::Acknowledged {
            acknowledgement: &acknowledgement,
            evaluation: &pass_evaluation,
            provenance: &provider_provenance,
        },
        &fixture.pricing,
        &fixture.eligibility,
    )?;
    assert_eq!(pass.disposition(), &OutcomePriceDispositionV1::FullPrice);
    assert_eq!(
        pass.delivery_disposition(),
        Some(OutcomeDeliveryDispositionV1::Acknowledged)
    );
    assert_eq!(
        pass.sla_attribution(),
        Some(OutcomeSlaAttributionV1::Provider)
    );
    assert_eq!(pass.assessed_amount(), &money(250));

    let (_, _, _, failed_ack) = acknowledged_delivery(&fixture, FAILED_OUTPUT)?;
    let failed_evaluation = evaluate_outcome_predicate(&fixture.predicate, FAILED_OUTPUT);
    let (_, redacted_provenance) = output_provenance(
        &fixture,
        DELIVERED_OUTPUT,
        FAILED_OUTPUT,
        Some(digest("redaction-proof")),
    )?;
    assert_eq!(
        redacted_provenance.body().provenance_class(),
        OutcomeOutputProvenanceClassV1::CallerPolicy
    );
    let failed = assess_outcome_price(
        AuthenticatedOutcomeDeliveryEvidenceV1::Acknowledged {
            acknowledgement: &failed_ack,
            evaluation: &failed_evaluation,
            provenance: &redacted_provenance,
        },
        &fixture.pricing,
        &fixture.eligibility,
    )?;
    assert_eq!(failed.disposition(), &OutcomePriceDispositionV1::ZeroPrice);
    assert_eq!(
        failed.sla_attribution(),
        Some(OutcomeSlaAttributionV1::CallerPolicy)
    );
    assert_eq!(failed.assessed_amount(), &money(0));

    let mut failed_verdict = verdict_fixture(&fixture);
    failed_verdict["deliveryAcknowledgementDigest"] = json!(failed_ack.envelope_digest());
    failed_verdict["deliveredOutputDigest"] = json!(sha256_hex(FAILED_OUTPUT));
    failed_verdict["verdict"] = json!("failed");
    failed_verdict["reasonCode"] = json!("assertion_mismatch");
    failed_verdict["assertionIndex"] = json!(1);
    failed_verdict["slaAttribution"] = json!("caller_policy");
    failed_verdict["attributionEvidenceDigest"] = json!(redacted_provenance.envelope_digest());
    failed_verdict["chargedAmount"] = json!(money(0));
    let failed_verdict = validated_verdict(failed_verdict, &fixture)?;

    let mut unevaluable = verdict_fixture(&fixture);
    unevaluable["verdict"] = json!("unevaluable");
    unevaluable["reasonCode"] = json!("invalid_output_json");
    unevaluable["chargedAmount"] = json!(money(0));
    validated_verdict(unevaluable.clone(), &fixture)?;
    unevaluable["reasonCode"] = json!("delivery_cancelled");
    let impossible: OutcomeVerdictV1 = serde_json::from_value(unevaluable)?;
    assert_eq!(
        require_error(impossible.validate()),
        OutcomeError::BindingMismatch
    );

    assert_eq!(
        require_error(assess_outcome_price(
            AuthenticatedOutcomeDeliveryEvidenceV1::Acknowledged {
                acknowledgement: &acknowledgement,
                evaluation: &failed_evaluation,
                provenance: &provider_provenance,
            },
            &fixture.pricing,
            &fixture.eligibility,
        )),
        OutcomeError::BindingMismatch
    );

    let (_, nonacceptance) = cancelled_delivery(&fixture, DELIVERED_OUTPUT)?;
    let cancelled = assess_outcome_price(
        AuthenticatedOutcomeDeliveryEvidenceV1::Cancelled {
            nonacceptance: &nonacceptance,
            evaluation: &pass_evaluation,
        },
        &fixture.pricing,
        &fixture.eligibility,
    )?;
    assert_eq!(
        cancelled.delivery_disposition(),
        Some(OutcomeDeliveryDispositionV1::Cancelled)
    );
    assert_eq!(
        cancelled.disposition(),
        &OutcomePriceDispositionV1::ZeroPrice
    );
    assert_eq!(
        cancelled.verdict(),
        Some(&OutcomeEvaluationV1::Unevaluable {
            reason: OutcomeEvaluationReasonV1::DeliveryCancelled,
        })
    );

    let mut cancelled_verdict = verdict_fixture(&fixture);
    cancelled_verdict["deliveryDisposition"] = json!("cancelled");
    remove_fields(
        &mut cancelled_verdict,
        &[
            "deliveryAcknowledgementDigest",
            "deliveredOutputDigest",
            "attributionEvidenceDigest",
        ],
    );
    cancelled_verdict["deliveryNonacceptanceDigest"] = json!(nonacceptance.envelope_digest());
    cancelled_verdict["verdict"] = json!("unevaluable");
    cancelled_verdict["reasonCode"] = json!("delivery_cancelled");
    cancelled_verdict["slaAttribution"] = json!("platform");
    cancelled_verdict["chargedAmount"] = json!(money(0));
    validated_verdict(cancelled_verdict, &fixture)?;

    let (signed_zero, authenticated_zero) = contractual_zero(&fixture)?;
    let not_attempted = assess_outcome_price(
        AuthenticatedOutcomeDeliveryEvidenceV1::NotAttempted(&authenticated_zero),
        &fixture.pricing,
        &fixture.eligibility,
    )?;
    assert_eq!(
        not_attempted.delivery_disposition(),
        Some(OutcomeDeliveryDispositionV1::NotAttempted)
    );
    assert_eq!(
        not_attempted.verdict(),
        Some(&OutcomeEvaluationV1::Unevaluable {
            reason: OutcomeEvaluationReasonV1::OutputBlocked,
        })
    );
    assert_eq!(
        not_attempted.sla_attribution(),
        Some(OutcomeSlaAttributionV1::CallerPolicy)
    );

    let mut blocked_verdict = verdict_fixture(&fixture);
    blocked_verdict["deliveryDisposition"] = json!("not_attempted");
    remove_fields(
        &mut blocked_verdict,
        &[
            "deliveryAcknowledgementDigest",
            "deliveredOutputDigest",
            "attributionEvidenceDigest",
        ],
    );
    blocked_verdict["contractualZeroChargeDigest"] = json!(authenticated_zero.envelope_digest());
    blocked_verdict["verdict"] = json!("unevaluable");
    blocked_verdict["reasonCode"] = json!("output_blocked");
    blocked_verdict["slaAttribution"] = json!("caller_policy");
    blocked_verdict["chargedAmount"] = json!(money(0));
    validated_verdict(blocked_verdict, &fixture)?;

    let unknown = assess_outcome_price(
        AuthenticatedOutcomeDeliveryEvidenceV1::Unknown,
        &fixture.pricing,
        &fixture.eligibility,
    )?;
    assert_eq!(
        unknown.disposition(),
        &OutcomePriceDispositionV1::Indeterminate
    );
    assert!(unknown.verdict().is_none());

    assert_eq!(
        require_error(assess_outcome_price(
            AuthenticatedOutcomeDeliveryEvidenceV1::Acknowledged {
                acknowledgement: &acknowledgement,
                evaluation: &pass_evaluation,
                provenance: &provider_provenance,
            },
            &alternate_pricing(&fixture)?,
            &fixture.eligibility,
        )),
        OutcomeError::BindingMismatch
    );
    assert_eq!(
        require_error(assess_outcome_price(
            AuthenticatedOutcomeDeliveryEvidenceV1::Acknowledged {
                acknowledgement: &acknowledgement,
                evaluation: &pass_evaluation,
                provenance: &provider_provenance,
            },
            &fixture.pricing,
            &alternate_eligibility(&fixture)?,
        )),
        OutcomeError::BindingMismatch
    );

    let wrong_signer = Keypair::from_seed(&[98; 32]);
    let zero_body: OutcomeContractualZeroBodyV1 =
        serde_json::from_value(serde_json::to_value(&signed_zero)?["body"].clone())?;
    let fabricated = SignedOutcomeContractualZeroV1::sign(zero_body, &wrong_signer)?;
    assert_eq!(
        require_error(authenticate_outcome_contractual_zero(
            &canonical_outcome_bytes(&fabricated)?,
            &fixture.eligibility,
            &kernel_trust(&fixture)?,
            1_400,
        )),
        OutcomeError::AuthorityVerification
    );

    let mut relabelled = serde_json::to_value(&failed_verdict)?;
    relabelled["listingId"] = json!("listing-other");
    relabelled["providerId"] = json!("provider-other");
    relabelled["quoteDigest"] = json!(digest("quote-other"));
    let relabelled: OutcomeVerdictV1 = serde_json::from_value(relabelled)?;
    assert_eq!(
        require_error(relabelled.validate_against_eligibility(&fixture.eligibility)),
        OutcomeError::BindingMismatch
    );
    for (field, value) in [("units", json!(251)), ("currency", json!("EUR"))] {
        let mut overcharged = serde_json::to_value(&failed_verdict)?;
        overcharged["chargedAmount"][field] = value;
        let overcharged: OutcomeVerdictV1 = serde_json::from_value(overcharged)?;
        assert!(overcharged
            .validate_against_eligibility(&fixture.eligibility)
            .is_err());
    }
    let mut unknown_field = verdict_fixture(&fixture);
    unknown_field["unexpected"] = json!(true);
    assert!(serde_json::from_value::<OutcomeVerdictV1>(unknown_field).is_err());
    Ok(())
}

#[test]
fn sla_arithmetic_and_fixed_interval_boundaries_are_exact() -> TestResult {
    let fixture = fixture()?;
    let third = calculate_outcome_sla_rate(
        fixture.sla.body(),
        OutcomeSlaArithmeticInputV1 {
            accepted_count: 3,
            provider_attributable_count: 3,
            caller_policy_excluded_count: 0,
            platform_excluded_count: 0,
            provider_failure_count: 1,
        },
    )?;
    assert_eq!(third.failure_bps, 3_333);
    assert!(third.exceeds_threshold);
    let quarter_sla = OutcomeSlaBodyV1::new(OutcomeSlaInputV1 {
        provider_id: "provider-1".to_owned(),
        listing_digest: digest("listing"),
        max_failure_bps: 2_500,
        minimum_sample_count: 4,
        window_seconds: 60,
        window_anchor_unix_ms: 500,
        effective_at_unix_ms: 1_000,
        expires_at_unix_ms: 300_000,
    })?;
    assert!(
        !calculate_outcome_sla_rate(
            &quarter_sla,
            OutcomeSlaArithmeticInputV1 {
                accepted_count: 4,
                provider_attributable_count: 4,
                caller_policy_excluded_count: 0,
                platform_excluded_count: 0,
                provider_failure_count: 1,
            },
        )?
        .exceeds_threshold
    );
    let expected = OutcomeSlaWindowV1 {
        start_unix_ms: 120_500,
        end_unix_ms: 180_499,
    };
    assert_eq!(outcome_sla_window(&quarter_sla, 120_500)?, expected);
    assert_eq!(outcome_sla_window(&quarter_sla, 180_499)?, expected);
    assert!(outcome_sla_window(&quarter_sla, 999).is_err());
    assert!(outcome_sla_window(&quarter_sla, 1_000).is_err());
    assert!(outcome_sla_window(&quarter_sla, 299_999).is_err());
    assert!(outcome_sla_window(&quarter_sla, 300_000).is_err());
    Ok(())
}

#[test]
fn representative_artifacts_match_strict_schemas_and_versions() -> TestResult {
    let fixture = fixture()?;
    let (signed_checkpoint, _, signed_ack, acknowledgement) =
        acknowledged_delivery(&fixture, DELIVERED_OUTPUT)?;
    let (signed_nonacceptance, _) = cancelled_delivery(&fixture, DELIVERED_OUTPUT)?;
    let (signed_provenance, _) =
        output_provenance(&fixture, DELIVERED_OUTPUT, DELIVERED_OUTPUT, None)?;
    let (signed_zero, _) = contractual_zero(&fixture)?;
    let mut verdict_value = verdict_fixture(&fixture);
    verdict_value["deliveryAcknowledgementDigest"] = json!(acknowledgement.envelope_digest());
    let verdict = validated_verdict(verdict_value.clone(), &fixture)?;
    verdict.validate_against_price(fixture.pricing.body().outcome_price())?;
    let request = VerifiedOutcomeRequestV1 {
        schema: VERIFIED_OUTCOME_REQUEST_SCHEMA.to_owned(),
        listing_id: "listing-1".to_owned(),
        listing_digest: digest("listing"),
        provider_binding_digest: digest("provider-binding"),
        pricing_id: fixture.pricing.body().pricing_id().to_owned(),
        pricing_digest: fixture.pricing.envelope_digest().to_owned(),
        predicate_id: fixture.predicate.body().predicate_id().to_owned(),
        predicate_digest: fixture.predicate.envelope_digest().to_owned(),
        sla_digest: Some(fixture.sla.envelope_digest().to_owned()),
        receiver_binding_digest: receiver_binding(&fixture)?.digest().to_owned(),
    };
    request.validate()?;

    validate_schema("request.schema.json", &request)?;
    validate_schema("predicate.schema.json", &fixture.signed_predicate)?;
    validate_schema("pricing.schema.json", &fixture.signed_pricing)?;
    validate_schema("sla.schema.json", &fixture.signed_sla)?;
    validate_schema("eligibility.schema.json", &fixture.signed_eligibility)?;
    validate_schema("delivery-checkpoint.schema.json", &signed_checkpoint)?;
    validate_schema("delivery-acknowledgement.schema.json", &signed_ack)?;
    validate_schema("delivery-nonacceptance.schema.json", &signed_nonacceptance)?;
    validate_schema("output-provenance.schema.json", &signed_provenance)?;
    validate_schema("contractual-zero.schema.json", &signed_zero)?;
    validate_schema("verdict.schema.json", &verdict)?;

    let signed_pending = signed_pending_checkpoint(&fixture, DELIVERED_OUTPUT)?;
    validate_schema("delivery-checkpoint.schema.json", &signed_pending)?;
    let pending = authenticate_outcome_delivery_checkpoint(
        &canonical_outcome_bytes(&signed_pending)?,
        &anchor_trust(&fixture)?,
        &receiver_binding(&fixture)?,
        None,
    )?;
    let signed_cancelled = SignedOutcomeDeliveryCheckpointV1::sign(
        pending.cancellation_assertion(
            digest("blob-absence"),
            digest("cancellation-fence"),
            1_550,
        )?,
        &fixture.anchor,
    )?;
    validate_schema("delivery-checkpoint.schema.json", &signed_cancelled)?;

    let mut failed = verdict_value.clone();
    failed["verdict"] = json!("failed");
    failed["reasonCode"] = json!("missing_target");
    failed["assertionIndex"] = json!(0);
    failed["chargedAmount"] = json!(money(0));
    validate_schema("verdict.schema.json", &failed)?;
    let mut unevaluable = verdict_value.clone();
    unevaluable["verdict"] = json!("unevaluable");
    unevaluable["reasonCode"] = json!("target_not_integer");
    unevaluable["chargedAmount"] = json!(money(0));
    validate_schema("verdict.schema.json", &unevaluable)?;
    let mut cancelled = verdict_value.clone();
    cancelled["deliveryDisposition"] = json!("cancelled");
    remove_fields(
        &mut cancelled,
        &[
            "deliveryAcknowledgementDigest",
            "deliveredOutputDigest",
            "attributionEvidenceDigest",
        ],
    );
    cancelled["deliveryNonacceptanceDigest"] = json!(digest("delivery-nonacceptance"));
    cancelled["verdict"] = json!("unevaluable");
    cancelled["reasonCode"] = json!("delivery_cancelled");
    cancelled["slaAttribution"] = json!("platform");
    cancelled["chargedAmount"] = json!(money(0));
    validate_schema("verdict.schema.json", &cancelled)?;
    let mut not_attempted = verdict_value.clone();
    not_attempted["deliveryDisposition"] = json!("not_attempted");
    remove_fields(
        &mut not_attempted,
        &[
            "deliveryAcknowledgementDigest",
            "deliveredOutputDigest",
            "attributionEvidenceDigest",
        ],
    );
    not_attempted["contractualZeroChargeDigest"] = json!(digest("contractual-zero"));
    not_attempted["verdict"] = json!("unevaluable");
    not_attempted["reasonCode"] = json!("output_blocked");
    not_attempted["slaAttribution"] = json!("caller_policy");
    not_attempted["chargedAmount"] = json!(money(0));
    validate_schema("verdict.schema.json", &not_attempted)?;

    let mut impossible_acknowledged = unevaluable;
    impossible_acknowledged["reasonCode"] = json!("delivery_cancelled");
    assert_schema_rejected("verdict.schema.json", &impossible_acknowledged)?;
    let mut unknown_field = verdict_value.clone();
    unknown_field["unexpected"] = json!(true);
    assert_schema_rejected("verdict.schema.json", &unknown_field)?;

    let canonical_verdict = String::from_utf8(canonical_outcome_bytes(&verdict_value)?)?;
    let out_of_ijson = canonical_verdict.replacen("\"units\":250", "\"units\":9007199254740992", 1);
    assert_ne!(out_of_ijson, canonical_verdict);
    assert!(load_canonical_outcome_json::<OutcomeVerdictV1>(out_of_ijson.as_bytes()).is_err());

    assert_unknown_schema_rejected("request.schema.json", &request)?;
    assert_unknown_schema_rejected("predicate.schema.json", &fixture.signed_predicate)?;
    assert_unknown_schema_rejected("pricing.schema.json", &fixture.signed_pricing)?;
    assert_unknown_schema_rejected("sla.schema.json", &fixture.signed_sla)?;
    assert_unknown_schema_rejected("eligibility.schema.json", &fixture.signed_eligibility)?;
    assert_unknown_schema_rejected("delivery-checkpoint.schema.json", &signed_checkpoint)?;
    assert_unknown_schema_rejected("delivery-acknowledgement.schema.json", &signed_ack)?;
    assert_unknown_schema_rejected("delivery-nonacceptance.schema.json", &signed_nonacceptance)?;
    assert_unknown_schema_rejected("output-provenance.schema.json", &signed_provenance)?;
    assert_unknown_schema_rejected("contractual-zero.schema.json", &signed_zero)?;
    assert_unknown_schema_rejected("verdict.schema.json", &verdict)?;

    let verdict_json = serde_json::to_value(&verdict)?;
    assert_eq!(verdict_json["verdict"], "passed");
    assert!(verdict_json.get("reasonCode").is_none());
    assert!(verdict_json.get("assertionIndex").is_none());

    assert_eq!(OUTCOME_ARTIFACT_SCHEMAS.len(), 11);
    for (file, expected_schema) in OUTCOME_ARTIFACT_SCHEMAS {
        let schema: Value = chio_spec_validate::load_json(&schema_path(file))?;
        let actual = schema
            .pointer("/properties/body/properties/schema/const")
            .or_else(|| schema.pointer("/properties/schema/const"));
        assert_eq!(actual, Some(&Value::String((*expected_schema).to_owned())));
    }
    Ok(())
}
