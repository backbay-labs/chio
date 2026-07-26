use std::error::Error;
use std::path::{Path, PathBuf};

use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::Keypair;
use chio_core::economic_continuity::{EconomicContentV1, EconomicTerminalResultV1};
use chio_core::web3::trust_profile::Web3FinalityMode;
use chio_settle::channel::*;
use serde_json::Value;

type TestResult = Result<(), Box<dyn Error>>;

const U128_MAX: &str = "340282366920938463463374607431768211455";
const U128_OVERFLOW: &str = "340282366920938463463374607431768211456";
const U64_MAX_CHAIN_ID: &str = "eip155:18446744073709551615";
const U64_OVERFLOW_CHAIN_ID: &str = "eip155:18446744073709551616";

fn digest(label: &str) -> String {
    chio_core::crypto::sha256_hex(label.as_bytes())
}

fn evm_hash(label: &str) -> String {
    format!("0x{}", digest(label))
}

fn asset_binding() -> ChannelAssetBindingV1 {
    ChannelAssetBindingV1 {
        schema: CHANNEL_ASSET_BINDING_SCHEMA.to_owned(),
        currency: "USD".to_owned(),
        protocol_minor_unit_decimals: 2,
        chain_id: "eip155:31337".to_owned(),
        token_address: "0x1111111111111111111111111111111111111111".to_owned(),
        token_symbol: "USDC".to_owned(),
        token_decimals: 6,
        settlement_policy_digest: digest("settlement-policy"),
    }
}

fn funding_body() -> ChannelFundingEvidenceBodyV1 {
    let depositor = "0x2222222222222222222222222222222222222222".to_owned();
    let beneficiary = "0x3333333333333333333333333333333333333333".to_owned();
    let operator = "0x4444444444444444444444444444444444444444".to_owned();
    let operator_key_hash = evm_hash("operator-key");
    let escrow_id = evm_hash("escrow-id");
    let escrow_contract = "0x5555555555555555555555555555555555555555".to_owned();
    let block_hash = evm_hash("funding-block");
    let terms = ChannelEscrowTermsV1 {
        capability_id: evm_hash("capability"),
        depositor: depositor.clone(),
        beneficiary: beneficiary.clone(),
        token_address: "0x1111111111111111111111111111111111111111".to_owned(),
        max_token_base_units: "1500000".to_owned(),
        deadline_unix_secs: 2_000,
        operator: operator.clone(),
        operator_key_hash: operator_key_hash.clone(),
    };
    ChannelFundingEvidenceBodyV1 {
        schema: CHANNEL_FUNDING_EVIDENCE_SCHEMA.to_owned(),
        escrow_reference: ChannelEscrowReferenceV1 {
            chain_id: "eip155:31337".to_owned(),
            escrow_contract: escrow_contract.clone(),
            escrow_id: escrow_id.clone(),
        },
        escrow_terms: terms.clone(),
        escrow_state: ChannelEscrowStateV1 {
            deposited_token_base_units: "1500000".to_owned(),
            released_token_base_units: "0".to_owned(),
            refunded_token_base_units: "0".to_owned(),
            refunded: false,
        },
        escrow_state_read: ChannelPinnedStateReadV1 {
            contract: escrow_contract.clone(),
            block_number: 100,
            block_hash: block_hash.clone(),
            call_data_digest: evm_hash("get-escrow-call"),
            return_data_digest: evm_hash("get-escrow-result"),
        },
        creation_event: ChannelEscrowCreatedEventV1 {
            transaction_hash: evm_hash("creation-transaction"),
            transaction_to: escrow_contract.clone(),
            transaction_succeeded: true,
            receipt_block_number: 100,
            receipt_block_hash: block_hash.clone(),
            log_emitter: escrow_contract.clone(),
            log_index: 0,
            event_signature: channel_escrow_created_event_signature(),
            escrow_id,
            capability_id: terms.capability_id.clone(),
            depositor,
            beneficiary,
            token_address: terms.token_address.clone(),
            max_token_base_units: terms.max_token_base_units.clone(),
            deadline_unix_secs: terms.deadline_unix_secs,
            operator: operator.clone(),
        },
        identity_observation: ChannelIdentityRegistryObservationV1 {
            registry_contract: "0x6666666666666666666666666666666666666666".to_owned(),
            operator,
            active: true,
            operator_key_hash,
            block_number: 100,
            block_hash: block_hash.clone(),
        },
        token_observation: ChannelTokenObservationV1 {
            token_address: terms.token_address,
            token_symbol: "USDC".to_owned(),
            token_decimals: 6,
            allowed: true,
            escrow_contract,
            block_number: 100,
            block_hash: block_hash.clone(),
        },
        asset_binding: asset_binding(),
        block_pin: ChannelBlockPinV1 {
            block_number: 100,
            block_hash,
            block_timestamp_unix_secs: 1,
            observed_at_unix_ms: 1_100,
            required_confirmations: 12,
            observed_confirmations: 12,
            finalized_head_number: 112,
            finalized_head_hash: evm_hash("finalized-head"),
            finality_mode: Web3FinalityMode::L1Finalized,
            finality_status: ChannelFinalityStatusV1::Finalized,
        },
        evidence_expires_at_unix_ms: 1_900,
    }
}

fn artifacts() -> Result<Vec<(&'static str, Value)>, Box<dyn Error>> {
    let payer_key = Keypair::from_seed(&[1; 32]);
    let payee_key = Keypair::from_seed(&[2; 32]);
    let authority_key = Keypair::from_seed(&[3; 32]);

    let funding_body = funding_body();
    let funding = SignedChannelFundingEvidenceV1 {
        authority_signature: ChannelSignatureV1::sign(
            &funding_body,
            "funding-authority".to_owned(),
            4,
            &authority_key,
        )?,
        body: funding_body,
    };
    let intent_body = ChannelOpenIntentBodyV1 {
        schema: CHANNEL_OPEN_INTENT_SCHEMA.to_owned(),
        open_intent_id: digest("open-intent"),
        payer_id: "payer".to_owned(),
        payer_key: payer_key.public_key(),
        payer_key_epoch: 2,
        payer_refund_address: funding.body.escrow_terms.depositor.clone(),
        payee_id: "payee".to_owned(),
        payee_key: payee_key.public_key(),
        payee_key_epoch: 3,
        payee_beneficiary_address: funding.body.escrow_terms.beneficiary.clone(),
        settlement_authority_scope_id: "channel-settlement".to_owned(),
        currency: "USD".to_owned(),
        bound: MonetaryAmount {
            units: 150,
            currency: "USD".to_owned(),
        },
        asset_binding: funding.body.asset_binding.clone(),
        bound_token_base_units: "1500000".to_owned(),
        channel_expiry_unix_secs: 1_800,
        dispute_tier_upper_bound_units: 1_000,
        dispute_window_secs: 100,
        required_confirmations: 12,
        finality_mode: Web3FinalityMode::L1Finalized,
        fixed_finality_broadcast_margin_secs: 50,
        close_submission_cutoff_unix_secs: 1_950,
        original_web3_dispatch_digest: digest("web3-dispatch"),
        escrow_reference: funding.body.escrow_reference.clone(),
        funding_evidence_digest: funding.digest()?,
        original_operator: funding.body.escrow_terms.operator.clone(),
        original_operator_key_hash: funding.body.escrow_terms.operator_key_hash.clone(),
        participant_snapshot_digest: digest("participant-snapshot"),
    };
    let intent = SignedChannelOpenIntentV1 {
        payer_signature: ChannelSignatureV1::sign(&intent_body, "payer".to_owned(), 2, &payer_key)?,
        payee_signature: ChannelSignatureV1::sign(&intent_body, "payee".to_owned(), 3, &payee_key)?,
        body: intent_body,
    };
    let acknowledgement_body = ChannelFundingAcknowledgementBodyV1 {
        schema: CHANNEL_FUNDING_ACKNOWLEDGEMENT_SCHEMA.to_owned(),
        open_intent_digest: intent.digest()?,
        escrow_reference: intent.body.escrow_reference.clone(),
        prior_state: ChannelEscrowReservationStateV1::Unreserved,
        prior_version: 1,
        prior_head_digest: digest("unreserved-head"),
        new_state: ChannelEscrowReservationStateV1::Opening,
        new_version: 2,
        anchored_head_digest: digest("opening-head"),
        reserved_at_unix_ms: 1_600,
        expires_at_unix_ms: 1_800,
    };
    let acknowledgement = SignedChannelFundingAcknowledgementV1 {
        authority_signature: ChannelSignatureV1::sign(
            &acknowledgement_body,
            "funding-authority".to_owned(),
            4,
            &authority_key,
        )?,
        body: acknowledgement_body,
    };
    let channel_id = derive_channel_id(&intent.digest()?, &acknowledgement.digest()?)?;
    let asset_binding_digest = intent.body.asset_binding.digest()?;
    let initial_state = ChannelStateBodyV1::initial(
        channel_id.clone(),
        "USD".to_owned(),
        asset_binding_digest.clone(),
    )?;
    let open_body = ChannelOpenBodyV1 {
        schema: CHANNEL_OPEN_SCHEMA.to_owned(),
        channel_id: channel_id.clone(),
        open_intent_digest: intent.digest()?,
        funding_acknowledgement_digest: acknowledgement.digest()?,
        initial_state_digest: initial_state.digest()?,
        opened_at_unix_ms: 1_700,
    };
    let open = SignedChannelOpenV1 {
        payer_signature: ChannelSignatureV1::sign(&open_body, "payer".to_owned(), 2, &payer_key)?,
        payee_signature: ChannelSignatureV1::sign(&open_body, "payee".to_owned(), 3, &payee_key)?,
        body: open_body,
    };
    let reservation_body = ChannelReservationBodyV1 {
        schema: CHANNEL_RESERVATION_SCHEMA.to_owned(),
        reservation_id: digest("reservation"),
        channel_id: channel_id.clone(),
        open_digest: open.digest()?,
        request_id: "request-1".to_owned(),
        operation_id: digest("operation-1"),
        next_sequence: 1,
        prior_state_digest: initial_state.digest()?,
        service_binding_digest: digest("service-binding"),
        receipt_authority_digest: digest("receipt-authority"),
        maximum_charge: MonetaryAmount {
            units: 50,
            currency: "USD".to_owned(),
        },
        maximum_token_base_units: "500000".to_owned(),
        expires_at_unix_ms: 1_750,
        disposition_expected_version: 1,
        channel_state_expected_version: 2,
        lifecycle_fence: 2,
    };
    let reservation = SignedChannelReservationV1 {
        payer_signature: ChannelSignatureV1::sign(
            &reservation_body,
            "payer".to_owned(),
            2,
            &payer_key,
        )?,
        authority_signature: ChannelSignatureV1::sign(
            &reservation_body,
            "channel-authority".to_owned(),
            4,
            &authority_key,
        )?,
        body: reservation_body,
    };
    let state_body = ChannelStateBodyV1 {
        schema: CHANNEL_STATE_SCHEMA.to_owned(),
        channel_id: channel_id.clone(),
        seq: 1,
        prev_state_digest: Some(initial_state.digest()?),
        cumulative_owed: MonetaryAmount {
            units: 50,
            currency: "USD".to_owned(),
        },
        receipt_id_root: digest("receipt-root"),
        receipt_count: 1,
        receipt_id: Some("receipt-1".to_owned()),
        receipt_digest: Some(digest("receipt")),
        receipt_authority_digest: Some(digest("receipt-authority")),
        obligation_atom_digest: Some(digest("obligation")),
        reservation_digest: Some(reservation.digest()?),
        actual_charge: Some(MonetaryAmount {
            units: 50,
            currency: "USD".to_owned(),
        }),
        cumulative_token_base_units: "500000".to_owned(),
        asset_binding_digest,
    };
    state_body.validate()?;
    let state = SignedChannelStateV1 {
        payee_signature: ChannelSignatureV1::sign(&state_body, "payee".to_owned(), 3, &payee_key)?,
        body: state_body,
    };
    let close_body = ChannelCloseBodyV1 {
        schema: CHANNEL_CLOSE_SCHEMA.to_owned(),
        channel_id: channel_id.clone(),
        open_digest: open.digest()?,
        close_kind: ChannelCloseKindV1::Cooperative,
        final_state_digest: state.digest()?,
        final_state_sequence: 1,
        final_cumulative_owed: state.body.cumulative_owed.clone(),
        expected_release_token_base_units: "500000".to_owned(),
        expected_refund_after_release_token_base_units: "1000000".to_owned(),
        dispute_window_secs: 100,
        proposed_at_unix_ms: 1_700,
        dispute_deadline_unix_ms: 1_800,
        close_submission_cutoff_unix_secs: 1_950,
        channel_state_version: 3,
        escrow_reservation_version: 3,
        lifecycle_fence: 3,
    };
    let close = SignedChannelCloseV1 {
        payee_signature: ChannelSignatureV1::sign(&close_body, "payee".to_owned(), 3, &payee_key)?,
        payer_signature: Some(ChannelSignatureV1::sign(
            &close_body,
            "payer".to_owned(),
            2,
            &payer_key,
        )?),
        body: close_body,
    };
    let dispute_body = ChannelDisputeBodyV1 {
        schema: CHANNEL_DISPUTE_SCHEMA.to_owned(),
        dispute_id: digest("dispute"),
        channel_id: channel_id.clone(),
        close_digest: close.digest()?,
        close_state_digest: state.digest()?,
        close_state_sequence: 1,
        competing_state_digest: digest("competing-state"),
        competing_state_sequence: 2,
        state_chain_proof_digest: digest("state-chain-proof"),
        reason: "newer signed state".to_owned(),
        submitted_at_unix_ms: 1_750,
    };
    let dispute = SignedChannelDisputeV1 {
        submitter_signature: ChannelSignatureV1::sign(
            &dispute_body,
            "payer".to_owned(),
            2,
            &payer_key,
        )?,
        body: dispute_body,
    };
    let terminal_result_content = EconomicContentV1::Inline {
        value: serde_json::json!({"outcomeId": digest("schema-terminal-outcome")}),
    };
    let terminal_result = EconomicTerminalResultV1 {
        result_id: "schema-terminal-outcome".to_owned(),
        result_digest: terminal_result_content.digest()?,
        result: terminal_result_content,
    };
    let terminal_outcome_body = ChannelTerminalOutcomeCommitmentBodyV1 {
        schema: CHANNEL_TERMINAL_OUTCOME_COMMITMENT_SCHEMA.to_owned(),
        operation_id: reservation.body.operation_id.clone(),
        reservation_id: reservation.body.reservation_id.clone(),
        reservation_digest: reservation.digest()?,
        receipt_id: "schema-terminal-receipt".to_owned(),
        receipt_digest: digest("schema-terminal-receipt"),
        terminal_result,
        outcome_recorded_at_unix_ms: 1_700,
        terminalized_at_unix_ms: 1_750,
    };
    let terminal_outcome = SignedChannelTerminalOutcomeCommitmentV1 {
        kernel_signature: authority_key.sign(&terminal_outcome_body.signing_bytes()?),
        kernel_key: authority_key.public_key(),
        body: terminal_outcome_body,
    };
    Ok(vec![
        ("channel-close.v1.json", serde_json::to_value(close)?),
        ("channel-dispute.v1.json", serde_json::to_value(dispute)?),
        (
            "channel-funding-acknowledgement.v1.json",
            serde_json::to_value(acknowledgement)?,
        ),
        (
            "channel-funding-evidence.v1.json",
            serde_json::to_value(funding)?,
        ),
        ("channel-open-intent.v1.json", serde_json::to_value(intent)?),
        ("channel-open.v1.json", serde_json::to_value(open)?),
        (
            "channel-reservation.v1.json",
            serde_json::to_value(reservation)?,
        ),
        ("channel-state.v1.json", serde_json::to_value(state)?),
        (
            "channel-terminal-outcome-commitment.v1.json",
            serde_json::to_value(terminal_outcome)?,
        ),
    ])
}

fn schema_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-economy")
        .join(name)
}

fn validate_schema(name: &str, artifact: &Value) -> TestResult {
    let path = schema_path(name);
    let schema = chio_spec_validate::load_json(&path)?;
    chio_spec_validate::validate_value(
        &path,
        &schema,
        &PathBuf::from("<channel-artifact>"),
        artifact,
    )?;
    Ok(())
}

fn schema_definition_accepts(name: &str, definition: &str, value: &str) -> TestResult {
    let path = schema_path(name);
    let schema = chio_spec_validate::load_json(&path)?;
    let definition = schema
        .pointer(&format!("/$defs/{definition}"))
        .ok_or_else(|| std::io::Error::other("missing schema definition"))?;
    chio_spec_validate::validate_value(
        &path,
        definition,
        &PathBuf::from("<channel-schema-value>"),
        &Value::String(value.to_owned()),
    )?;
    Ok(())
}

fn mutate_string(
    value: &Value,
    pointer: &str,
    transform: impl FnOnce(&str) -> String,
) -> Result<Value, std::io::Error> {
    let mut mutated = value.clone();
    let field = mutated
        .pointer_mut(pointer)
        .ok_or_else(|| std::io::Error::other("missing artifact field"))?;
    let encoded = field
        .as_str()
        .ok_or_else(|| std::io::Error::other("artifact field is not a string"))?;
    *field = Value::String(transform(encoded));
    Ok(mutated)
}

fn replay_schema_fixture(artifacts: &[(&'static str, Value)]) -> Result<Value, std::io::Error> {
    let artifact = |name: &str| {
        artifacts
            .iter()
            .find(|(schema, _)| *schema == name)
            .map(|(_, value)| value.clone())
            .ok_or_else(|| std::io::Error::other(format!("missing {name} artifact")))
    };
    let funding = artifact("channel-funding-evidence.v1.json")?;
    let acknowledgement = artifact("channel-funding-acknowledgement.v1.json")?;
    let reservation = artifact("channel-reservation.v1.json")?;
    let operation_id = reservation["body"]["operationId"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("missing reservation operation id"))?
        .to_owned();
    let checkpoint_digest = digest("schema-replay-checkpoint");
    let anchor_view = serde_json::json!({
        "schema": "chio.economy.anchor-view.v1",
        "anchorId": "schema-anchor",
        "namespace": "schema-namespace",
        "checkpointSequence": 1,
        "checkpointDigest": checkpoint_digest.clone(),
        "headsRoot": digest("schema-replay-heads-root"),
        "heads": [],
        "absentResourceKeys": [],
        "requestReplaysRoot": digest("schema-replay-requests-root"),
        "requestReplays": [],
        "absentRequestKeys": [],
        "observedAt": 1_700,
        "signerKeyId": "schema-anchor-key",
        "signerKeyEpoch": 1,
        "anchorSignature": "00".repeat(64)
    });
    Ok(serde_json::json!({
        "format": CHANNEL_TRANSITION_REPLAY_FORMAT,
        "version": 1,
        "body": {
            "authorityPins": {
                "openTrust": {},
                "fundingAuthority": {},
                "reservationAuthority": {},
                "trustedKernelKey": "11".repeat(32),
                "anchor": {
                    "anchorId": "schema-anchor",
                    "namespace": "schema-namespace",
                    "signerKeyId": "schema-anchor-key",
                    "signerKeyEpoch": 1,
                    "signerPublicKey": "22".repeat(32)
                }
            },
            "authorityPinsDigest": digest("schema-replay-authorities"),
            "openArtifacts": {
                "fundingEvidence": funding,
                "fundingAcknowledgement": acknowledgement,
                "disputePolicy": {}
            },
            "reservationContext": {
                "prepared": {},
                "signedReservation": reservation,
                "preparedBaseView": anchor_view.clone()
            },
            "currentView": anchor_view,
            "baseCheckpointSequence": 1,
            "baseCheckpointDigest": checkpoint_digest,
            "descriptorKey": format!("reservation:{operation_id}"),
            "operationId": operation_id,
            "request": {
                "requestNamespaceDigest": digest("schema-replay-request-namespace"),
                "requestId": "schema-request",
                "requestBindingDigest": digest("schema-replay-request-binding")
            },
            "sourceBindings": [],
            "issuedAt": 1_700,
            "notAfterUnixMs": 1_800,
            "expectedBatchDigest": digest("schema-replay-batch"),
            "evidence": { "kind": "reservation" }
        },
        "descriptorDigest": digest("schema-replay-descriptor")
    }))
}

#[test]
fn signed_channel_artifacts_match_their_json_schemas() -> TestResult {
    let artifacts = artifacts()?;
    assert_eq!(artifacts.len(), 9);
    for (schema, artifact) in artifacts {
        validate_schema(schema, &artifact)?;
    }
    Ok(())
}

#[test]
fn channel_schemas_reject_unknown_fields_and_unsafe_integers() -> TestResult {
    let artifacts = artifacts()?;
    let mut unknown = artifacts
        .iter()
        .find(|(schema, _)| *schema == "channel-close.v1.json")
        .ok_or_else(|| std::io::Error::other("missing close artifact"))?
        .1
        .clone();
    unknown["unexpected"] = Value::Bool(true);
    assert!(validate_schema("channel-close.v1.json", &unknown).is_err());

    let mut unsafe_integer = artifacts
        .iter()
        .find(|(schema, _)| *schema == "channel-open.v1.json")
        .ok_or_else(|| std::io::Error::other("missing open artifact"))?
        .1
        .clone();
    unsafe_integer["body"]["openedAtUnixMs"] = Value::from(9_007_199_254_740_992_u64);
    assert!(validate_schema("channel-open.v1.json", &unsafe_integer).is_err());
    Ok(())
}

#[test]
fn channel_schema_numeric_strings_match_rust_bounds() -> TestResult {
    let base_unit_schemas = [
        ("channel-close.v1.json", "baseUnits"),
        ("channel-funding-evidence.v1.json", "baseUnits"),
        ("channel-open-intent.v1.json", "baseUnits"),
        ("channel-reservation.v1.json", "positiveBaseUnits"),
        ("channel-state.v1.json", "baseUnits"),
    ];
    for (schema, definition) in base_unit_schemas {
        schema_definition_accepts(schema, definition, U128_MAX)?;
        assert!(schema_definition_accepts(schema, definition, U128_OVERFLOW).is_err());
    }

    let chain_id_schemas = [
        "channel-funding-acknowledgement.v1.json",
        "channel-funding-evidence.v1.json",
        "channel-open-intent.v1.json",
    ];
    for schema in chain_id_schemas {
        schema_definition_accepts(schema, "chainId", U64_MAX_CHAIN_ID)?;
        assert!(schema_definition_accepts(schema, "chainId", U64_OVERFLOW_CHAIN_ID).is_err());
    }

    let mut maximum = funding_body();
    maximum.escrow_terms.max_token_base_units = U128_MAX.to_owned();
    maximum.escrow_state.deposited_token_base_units = U128_MAX.to_owned();
    maximum.creation_event.max_token_base_units = U128_MAX.to_owned();
    maximum.escrow_reference.chain_id = U64_MAX_CHAIN_ID.to_owned();
    maximum.asset_binding.chain_id = U64_MAX_CHAIN_ID.to_owned();
    maximum.validate()?;

    let mut overflow = maximum.clone();
    overflow.escrow_terms.max_token_base_units = U128_OVERFLOW.to_owned();
    overflow.escrow_state.deposited_token_base_units = U128_OVERFLOW.to_owned();
    overflow.creation_event.max_token_base_units = U128_OVERFLOW.to_owned();
    assert!(overflow.validate().is_err());
    overflow = maximum;
    overflow.escrow_reference.chain_id = U64_OVERFLOW_CHAIN_ID.to_owned();
    overflow.asset_binding.chain_id = U64_OVERFLOW_CHAIN_ID.to_owned();
    assert!(overflow.validate().is_err());
    Ok(())
}

#[test]
fn signed_channel_artifacts_require_canonical_crypto_strings() -> TestResult {
    let artifact = artifacts()?
        .into_iter()
        .find(|(schema, _)| *schema == "channel-open-intent.v1.json")
        .ok_or_else(|| std::io::Error::other("missing open intent artifact"))?
        .1;
    let decoded: SignedChannelOpenIntentV1 = serde_json::from_value(artifact.clone())?;
    assert_eq!(serde_json::to_value(decoded)?, artifact);

    let mutations = [
        mutate_string(&artifact, "/body/payerKey", str::to_ascii_uppercase)?,
        mutate_string(&artifact, "/body/payerKey", |value| format!("0x{value}"))?,
        mutate_string(
            &artifact,
            "/payerSignature/signerKey",
            str::to_ascii_uppercase,
        )?,
        mutate_string(&artifact, "/payerSignature/signerKey", |value| {
            format!("0x{value}")
        })?,
        mutate_string(
            &artifact,
            "/payerSignature/signature",
            str::to_ascii_uppercase,
        )?,
        mutate_string(&artifact, "/payerSignature/signature", |value| {
            format!("0x{value}")
        })?,
    ];
    for mutation in mutations {
        assert!(validate_schema("channel-open-intent.v1.json", &mutation).is_err());
        assert!(serde_json::from_value::<SignedChannelOpenIntentV1>(mutation).is_err());
    }
    Ok(())
}

#[test]
fn terminal_outcome_schema_and_wire_reject_noncanonical_or_unknown_fields() -> TestResult {
    let artifact = artifacts()?
        .into_iter()
        .find(|(schema, _)| *schema == "channel-terminal-outcome-commitment.v1.json")
        .ok_or_else(|| std::io::Error::other("missing terminal outcome artifact"))?
        .1;
    let decoded: SignedChannelTerminalOutcomeCommitmentV1 =
        serde_json::from_value(artifact.clone())?;
    assert_eq!(serde_json::to_value(decoded)?, artifact);

    let crypto_mutations = [
        mutate_string(&artifact, "/kernelKey", str::to_ascii_uppercase)?,
        mutate_string(&artifact, "/kernelKey", |value| format!("0x{value}"))?,
        mutate_string(&artifact, "/kernelSignature", str::to_ascii_uppercase)?,
        mutate_string(&artifact, "/kernelSignature", |value| format!("0x{value}"))?,
    ];
    for mutation in crypto_mutations {
        assert!(validate_schema("channel-terminal-outcome-commitment.v1.json", &mutation).is_err());
        assert!(
            serde_json::from_value::<SignedChannelTerminalOutcomeCommitmentV1>(mutation).is_err()
        );
    }

    let mut wrong_schema = artifact.clone();
    wrong_schema["body"]["schema"] = Value::String("chio.channel.terminal-outcome.v9".to_owned());
    assert!(validate_schema("channel-terminal-outcome-commitment.v1.json", &wrong_schema).is_err());
    let mut unknown = artifact.clone();
    unknown["unexpected"] = Value::Bool(true);
    assert!(validate_schema("channel-terminal-outcome-commitment.v1.json", &unknown).is_err());
    assert!(serde_json::from_value::<SignedChannelTerminalOutcomeCommitmentV1>(unknown).is_err());
    let mut unsafe_integer = artifact;
    unsafe_integer["body"]["terminalizedAtUnixMs"] = Value::from(9_007_199_254_740_992_u64);
    assert!(validate_schema(
        "channel-terminal-outcome-commitment.v1.json",
        &unsafe_integer
    )
    .is_err());
    Ok(())
}

#[test]
fn transition_replay_schema_rejects_unknown_format_version_kind_and_fields() -> TestResult {
    let replay = replay_schema_fixture(&artifacts()?)?;
    validate_schema("channel-transition-replay.v1.json", &replay)?;

    for mutation in [
        {
            let mut value = replay.clone();
            value["format"] = Value::String("chio.channel.transition-replay.v9".to_owned());
            value
        },
        {
            let mut value = replay.clone();
            value["version"] = Value::from(2);
            value
        },
        {
            let mut value = replay.clone();
            value["body"]["evidence"]["kind"] = Value::String("unknown".to_owned());
            value
        },
        {
            let mut value = replay.clone();
            value["unexpected"] = Value::Bool(true);
            value
        },
        {
            let mut value = replay;
            value["body"]["issuedAt"] = Value::from(9_007_199_254_740_992_u64);
            value
        },
    ] {
        assert!(validate_schema("channel-transition-replay.v1.json", &mutation).is_err());
    }
    Ok(())
}

#[test]
fn channel_wire_rejects_explicit_null_for_omittable_fields() -> TestResult {
    let artifacts = artifacts()?;
    let mut close = artifacts
        .iter()
        .find(|(schema, _)| *schema == "channel-close.v1.json")
        .ok_or_else(|| std::io::Error::other("missing close artifact"))?
        .1
        .clone();
    close["payerSignature"] = Value::Null;
    assert!(validate_schema("channel-close.v1.json", &close).is_err());
    assert!(serde_json::from_value::<SignedChannelCloseV1>(close).is_err());

    let initial = ChannelStateBodyV1::initial(
        digest("null-state-channel"),
        "USD".to_owned(),
        digest("null-state-asset"),
    )?;
    let mut initial = serde_json::to_value(initial)?;
    initial["prevStateDigest"] = Value::Null;
    assert!(serde_json::from_value::<ChannelStateBodyV1>(initial).is_err());
    Ok(())
}
