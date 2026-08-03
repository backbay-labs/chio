use super::*;

use alloy_primitives::U256;
use alloy_sol_types::SolCall;
use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::Keypair;
use chio_core::receipt::lineage::SignedExportEnvelope;
use chio_core::web3::anchors::AnchorInclusionProof;
use chio_finding::{
    compute_enforcement_id, compute_snapshot_id, signed_envelope_sha256,
    FindingChallengeEnforcement, FindingEffectIntentBinding, FindingEffectIntentKind,
    FindingEnforcementDestination, FindingFinalizedBondSnapshot, FindingObservedFinality,
    FindingVaultReference, SignedFindingChallengeEnforcement, SignedFindingFinalizedBondSnapshot,
    FINDING_CHALLENGE_ENFORCEMENT_SCHEMA_V1, FINDING_FINALIZED_BOND_SNAPSHOT_SCHEMA_V1,
};
use chio_web3_bindings::IChioBondVault;
use serde::Serialize;

use crate::{
    EvmBondSnapshot, EvmTransactionReceipt, PreparedEvmCall, SettlementChainConfig,
    SettlementEvidenceConfig, SettlementFinalityStatus, SettlementOracleConfig,
    SettlementPolicyConfig,
};

use chio_test_support::prelude::*;

const BOND_VAULT_CONTRACT: &str = "0x621c302d6EC93b7186bEF18dF5D6436C6ea30125";
const OPERATOR_KEY_HASH: &str =
    "0x0791868d8f29ea735f26a17a9aea038cd4255baac26eac5a74e58a07ed2f1975";
const BUYER_DESTINATION: &str = "0x1000000000000000000000000000000000000006";
const COMMUNITY_FUND_DESTINATION: &str = "0x1000000000000000000000000000000000000007";
const IDENTITY_REGISTRY_RECORD: &str = "registry/operators/venue-42";
const OBSERVED_AT: u64 = 1_750_090_000;
const TRUSTED_NOW: u64 = OBSERVED_AT + 500;
const MAX_SNAPSHOT_AGE_SECS: u64 = 3_600;

type VaultMutation = Box<dyn Fn(&mut FindingVaultReference)>;
type RecheckMutation = Box<dyn Fn(&mut FindingBondObservationRecheck)>;

fn hex64(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn chain_hash(byte: u8) -> String {
    format!("0x{}", hex64(byte))
}

fn vault_id() -> String {
    chain_hash(0x44)
}

fn finalization_keypair() -> Keypair {
    Keypair::from_seed(&[71; 32])
}

fn observer_keypair() -> Keypair {
    Keypair::from_seed(&[72; 32])
}

fn seller_keypair() -> Keypair {
    Keypair::from_seed(&[73; 32])
}

fn other_seller_keypair() -> Keypair {
    Keypair::from_seed(&[74; 32])
}

fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
}

fn sample_anchor_proof() -> AnchorInclusionProof {
    serde_json::from_str(include_str!(
        "../../../../../docs/standards/CHIO_ANCHOR_INCLUSION_PROOF_EXAMPLE.json"
    ))
    .test_expect("anchor inclusion proof example parses")
}

fn sample_config() -> SettlementChainConfig {
    let proof = sample_anchor_proof();
    let anchor = proof
        .chain_anchor
        .as_ref()
        .test_expect("anchor inclusion proof example carries a chain anchor");
    let rpc_url = "http://127.0.0.1:8545".to_string();
    let mut policy = SettlementPolicyConfig::default();
    policy.finding_impairment_destination_allowlist = [
        BUYER_DESTINATION.to_string(),
        COMMUNITY_FUND_DESTINATION.to_string(),
    ]
    .into_iter()
    .collect();
    SettlementChainConfig {
        chain_id: anchor.chain_id.clone(),
        network_name: "Devnet".to_string(),
        egress_contract: crate::settlement_devnet_rpc_egress_contract(&rpc_url)
            .test_expect("devnet egress contract"),
        rpc_url,
        escrow_contract: "0x69011eD3D9792Ea93595EeBd919EE621764B19e0".to_string(),
        bond_vault_contract: BOND_VAULT_CONTRACT.to_string(),
        identity_registry_contract: "0x0eAFb60DD4F4b3863eb5490752238aC37A625dc6".to_string(),
        root_registry_contract: anchor.contract_address.clone(),
        operator_address: anchor.operator_address.clone(),
        settlement_token_symbol: "mUSDC".to_string(),
        settlement_token_address: "0x735F1Ba389D9D350501dB8FBbB5b52477DcaddA8".to_string(),
        oracle: SettlementOracleConfig::default(),
        evidence_substrate: SettlementEvidenceConfig::default(),
        policy,
    }
}

fn operator_address() -> String {
    sample_config().operator_address
}

fn snapshot_body() -> FindingFinalizedBondSnapshot {
    let mut snapshot = FindingFinalizedBondSnapshot {
        schema: FINDING_FINALIZED_BOND_SNAPSHOT_SCHEMA_V1.to_string(),
        snapshot_id: String::new(),
        chain_id: sample_config().chain_id,
        vault_contract: BOND_VAULT_CONTRACT.to_string(),
        vault_id: vault_id(),
        seller: seller_keypair().public_key(),
        allocation_id: hex64(0xa1),
        locked_amount: 500_000,
        held_amount: 120_000,
        slashed_amount: 0,
        currency: "USD".to_string(),
        block_number: 21_000_000,
        block_hash: chain_hash(0xbb),
        finality_policy: "confirmations>=64".to_string(),
        observed_finality: FindingObservedFinality::Confirmations { depth: 96 },
        identity_registry_record: IDENTITY_REGISTRY_RECORD.to_string(),
        operator_key_hash: OPERATOR_KEY_HASH.to_string(),
        operator_key_epoch: 3,
        observed_at: OBSERVED_AT,
    };
    snapshot.snapshot_id = compute_snapshot_id(&snapshot).test_expect("snapshot id computes");
    snapshot
}

fn sign<T: Serialize + Clone>(body: T, keypair: &Keypair) -> SignedExportEnvelope<T> {
    SignedExportEnvelope::sign(body, keypair).test_expect("envelope signs")
}

fn enforcement_body(bond_snapshot_envelope_sha256: &str) -> FindingChallengeEnforcement {
    FindingChallengeEnforcement {
        schema: FINDING_CHALLENGE_ENFORCEMENT_SCHEMA_V1.to_string(),
        enforcement_id: String::new(),
        liability_key: hex64(0xb1),
        finding_id: hex64(0xb2),
        listing_id: "listing-42".to_string(),
        outcome_id: hex64(0xb3),
        outcome_envelope_sha256: hex64(0xb4),
        penalty_envelope_sha256: hex64(0xb5),
        bond_snapshot_envelope_sha256: bond_snapshot_envelope_sha256.to_string(),
        purchase_snapshot_digest: hex64(0xb6),
        deterministic_allocation_digest: hex64(0xb7),
        seller_allocation_id: hex64(0xa1),
        vault: FindingVaultReference {
            chain_id: sample_config().chain_id,
            vault_contract: BOND_VAULT_CONTRACT.to_string(),
            vault_id: vault_id(),
        },
        amount: usd(250),
        destinations: vec![
            FindingEnforcementDestination {
                destination: BUYER_DESTINATION.to_string(),
                amount: usd(150),
            },
            FindingEnforcementDestination {
                destination: COMMUNITY_FUND_DESTINATION.to_string(),
                amount: usd(100),
            },
        ],
        effect_intents: vec![
            FindingEffectIntentBinding {
                kind: FindingEffectIntentKind::SellerImpair,
                intent_id: hex64(0xc1),
            },
            FindingEffectIntentBinding {
                kind: FindingEffectIntentKind::RootIntent,
                intent_id: hex64(0xc2),
            },
            FindingEffectIntentBinding {
                kind: FindingEffectIntentKind::Retraction,
                intent_id: hex64(0xc3),
            },
        ],
        finalized_at: 1_750_090_100,
    }
}

/// Sign a snapshot, bind an enforcement to that exact envelope, apply the
/// case-specific mutation, then re-derive the content-addressed id so every
/// negative case differs only in the field under test.
fn pair_from(
    snapshot: FindingFinalizedBondSnapshot,
    snapshot_signer: &Keypair,
    enforcement_signer: &Keypair,
    mutate: impl FnOnce(&mut FindingChallengeEnforcement),
) -> (
    SignedFindingChallengeEnforcement,
    SignedFindingFinalizedBondSnapshot,
) {
    let signed_snapshot = sign(snapshot, snapshot_signer);
    let digest = signed_envelope_sha256(&signed_snapshot).test_expect("snapshot envelope digest");
    let mut enforcement = enforcement_body(&digest);
    mutate(&mut enforcement);
    enforcement.enforcement_id =
        compute_enforcement_id(&enforcement).test_expect("enforcement id computes");
    (sign(enforcement, enforcement_signer), signed_snapshot)
}

fn default_pair() -> (
    SignedFindingChallengeEnforcement,
    SignedFindingFinalizedBondSnapshot,
) {
    pair_from(
        snapshot_body(),
        &observer_keypair(),
        &finalization_keypair(),
        |_| {},
    )
}

fn default_pins() -> FindingEnforcementPins {
    FindingEnforcementPins {
        finalization_authority: finalization_keypair().public_key(),
        settlement_observer: observer_keypair().public_key(),
        seller: seller_keypair().public_key(),
        finality_requirement: FindingFinalityRequirement::Confirmations { min_depth: 64 },
        max_snapshot_age_secs: MAX_SNAPSHOT_AGE_SECS,
    }
}

fn verify_default() -> Result<VerifiedFindingEnforcement, SettlementError> {
    let (enforcement, snapshot) = default_pair();
    verify_finding_enforcement(&enforcement, &snapshot, &default_pins(), TRUSTED_NOW)
}

fn verified() -> VerifiedFindingEnforcement {
    verify_default().test_expect("matching enforcement pair verifies")
}

fn vault_snapshot() -> EvmBondSnapshot {
    EvmBondSnapshot {
        vault_id: vault_id(),
        principal_address: "0x1000000000000000000000000000000000000005".to_string(),
        operator_key_hash: OPERATOR_KEY_HASH.to_string(),
        expires_at: 1_800_000_000,
        observed_at: 1_799_999_000,
        locked_minor_units: 5_000_000,
        reserve_requirement_minor_units: 1_000_000,
        reserve_requirement_ratio_bps: 2_000,
        slashed_minor_units: 0,
        released: false,
        expired: false,
    }
}

fn planned() -> PlannedFindingImpairment {
    plan_finding_impairment(
        &sample_config(),
        &verified(),
        &operator_address(),
        &vault_snapshot(),
        &sample_anchor_proof(),
    )
    .test_expect("verified enforcement plans an impairment")
}

fn receipt(tx_hash: &str, to_address: &str, status: bool) -> EvmTransactionReceipt {
    EvmTransactionReceipt {
        tx_hash: tx_hash.to_string(),
        block_number: 21_000_100,
        block_hash: chain_hash(0xcc),
        status,
        from_address: operator_address(),
        to_address: to_address.to_string(),
        gas_used: 120_000,
        observed_at: 1_750_090_500,
        logs: Vec::new(),
    }
}

fn stored_matching(planned: &PlannedFindingImpairment) -> StoredImpairmentTransaction {
    let tx_hash = chain_hash(0xde);
    let to_address = planned.call().to_address.clone();
    StoredImpairmentTransaction {
        chain_id: planned.intent().chain_id.clone(),
        receipt: Some(receipt(&tx_hash, &to_address, true)),
        finality: Some(SettlementFinalityStatus::Finalized),
        input_data: Some(planned.call().data.clone()),
        to_address,
        tx_hash,
    }
}

fn mutated_input(
    planned: &PlannedFindingImpairment,
    mutate: impl FnOnce(&mut IChioBondVault::impairBondDetailedCall),
) -> String {
    let bytes = hex::decode(planned.call().data.trim_start_matches("0x"))
        .test_expect("prepared call data is hex");
    let mut call = IChioBondVault::impairBondDetailedCall::abi_decode(&bytes)
        .test_expect("prepared call data decodes");
    mutate(&mut call);
    format!("0x{}", hex::encode(call.abi_encode()))
}

fn recheck_from_snapshot(verified: &VerifiedFindingEnforcement) -> FindingBondObservationRecheck {
    let snapshot = verified.snapshot();
    FindingBondObservationRecheck {
        block_hash: Some(snapshot.block_hash.clone()),
        observed_finality: snapshot.observed_finality,
        identity_registry_record: snapshot.identity_registry_record.clone(),
        operator_key_hash: snapshot.operator_key_hash.clone(),
        operator_key_epoch: snapshot.operator_key_epoch,
        operator_active: true,
    }
}

fn assert_rejected(result: Result<VerifiedFindingEnforcement, SettlementError>, needle: &str) {
    let error = result.test_expect_err("verification should reject");
    let message = error.to_string();
    assert!(
        message.contains(needle),
        "expected rejection mentioning `{needle}`, got: {message}"
    );
}

#[test]
fn verify_finding_enforcement_accepts_a_matching_pair() {
    let verified = verified();

    assert_eq!(verified.enforcement().amount, usd(250));
    assert_eq!(verified.live_allocated_collateral(), 380_000);
    assert_eq!(verified.seller_impair_intent_id(), hex64(0xc1));
    assert_eq!(
        verified.bond_snapshot_envelope_sha256(),
        verified.enforcement().bond_snapshot_envelope_sha256
    );
    assert_ne!(
        verified.enforcement_envelope_sha256(),
        verified.bond_snapshot_envelope_sha256()
    );
}

#[test]
fn role_substitution_is_rejected_in_both_directions() {
    let pins = default_pins();

    let (enforcement, snapshot) = pair_from(
        snapshot_body(),
        &observer_keypair(),
        &observer_keypair(),
        |_| {},
    );
    assert_rejected(
        verify_finding_enforcement(&enforcement, &snapshot, &pins, TRUSTED_NOW),
        "challenge enforcement rejected",
    );

    let (enforcement, snapshot) = pair_from(
        snapshot_body(),
        &finalization_keypair(),
        &finalization_keypair(),
        |_| {},
    );
    assert_rejected(
        verify_finding_enforcement(&enforcement, &snapshot, &pins, TRUSTED_NOW),
        "finalized bond snapshot rejected",
    );
}

#[test]
fn pins_reject_one_key_reused_across_two_roles() {
    let cases = [
        (
            FindingEnforcementPins {
                settlement_observer: finalization_keypair().public_key(),
                ..default_pins()
            },
            "finalization_authority and settlement_observer",
        ),
        (
            FindingEnforcementPins {
                seller: finalization_keypair().public_key(),
                ..default_pins()
            },
            "finalization_authority and seller",
        ),
        (
            FindingEnforcementPins {
                seller: observer_keypair().public_key(),
                ..default_pins()
            },
            "settlement_observer and seller",
        ),
    ];

    let (enforcement, snapshot) = default_pair();
    for (pins, needle) in cases {
        assert_rejected(
            verify_finding_enforcement(&enforcement, &snapshot, &pins, TRUSTED_NOW),
            needle,
        );
    }
}

#[test]
fn pins_reject_a_zero_observation_age_bound() {
    let pins = FindingEnforcementPins {
        max_snapshot_age_secs: 0,
        ..default_pins()
    };
    let (enforcement, snapshot) = default_pair();

    assert_rejected(
        verify_finding_enforcement(&enforcement, &snapshot, &pins, TRUSTED_NOW),
        "max_snapshot_age_secs must be nonzero",
    );
}

#[test]
fn pins_reject_a_zero_confirmation_requirement() {
    let pins = FindingEnforcementPins {
        finality_requirement: FindingFinalityRequirement::Confirmations { min_depth: 0 },
        ..default_pins()
    };
    let (enforcement, snapshot) = default_pair();

    assert_rejected(
        verify_finding_enforcement(&enforcement, &snapshot, &pins, TRUSTED_NOW),
        "confirmation depth must be nonzero",
    );
}

#[test]
fn a_snapshot_the_enforcement_does_not_bind_is_rejected() {
    let (enforcement, _) = pair_from(
        snapshot_body(),
        &observer_keypair(),
        &finalization_keypair(),
        |enforcement| enforcement.bond_snapshot_envelope_sha256 = hex64(0xee),
    );
    let (_, snapshot) = default_pair();

    assert_rejected(
        verify_finding_enforcement(&enforcement, &snapshot, &default_pins(), TRUSTED_NOW),
        "does not bind the presented snapshot",
    );
}

#[test]
fn a_vault_mismatch_is_rejected() {
    let cases: [VaultMutation; 3] = [
        Box::new(|vault| vault.chain_id = "eip155:1".to_string()),
        Box::new(|vault| {
            vault.vault_contract = "0x00000000000000000000000000000000000000bd".to_string();
        }),
        Box::new(|vault| vault.vault_id = chain_hash(0x45)),
    ];

    for mutate in cases {
        let (enforcement, snapshot) = pair_from(
            snapshot_body(),
            &observer_keypair(),
            &finalization_keypair(),
            |enforcement| mutate(&mut enforcement.vault),
        );
        assert_rejected(
            verify_finding_enforcement(&enforcement, &snapshot, &default_pins(), TRUSTED_NOW),
            "vault does not match the enforcement vault",
        );
    }
}

#[test]
fn an_allocation_mismatch_is_rejected() {
    let (enforcement, snapshot) = pair_from(
        snapshot_body(),
        &observer_keypair(),
        &finalization_keypair(),
        |enforcement| enforcement.seller_allocation_id = hex64(0xa2),
    );

    assert_rejected(
        verify_finding_enforcement(&enforcement, &snapshot, &default_pins(), TRUSTED_NOW),
        "allocation_id does not match",
    );
}

#[test]
fn a_seller_outside_the_pinned_liability_head_is_rejected() {
    let mut body = snapshot_body();
    body.seller = other_seller_keypair().public_key();
    body.snapshot_id = compute_snapshot_id(&body).test_expect("snapshot id computes");
    let (enforcement, snapshot) =
        pair_from(body, &observer_keypair(), &finalization_keypair(), |_| {});

    assert_rejected(
        verify_finding_enforcement(&enforcement, &snapshot, &default_pins(), TRUSTED_NOW),
        "seller does not match the pinned seller",
    );
}

#[test]
fn observed_finality_that_misses_its_policy_is_rejected() {
    let cases = [
        (
            "confirmations>=64".to_string(),
            FindingObservedFinality::Confirmations { depth: 63 },
            FindingFinalityRequirement::Confirmations { min_depth: 64 },
        ),
        (
            "confirmations>=64".to_string(),
            FindingObservedFinality::Finalized,
            FindingFinalityRequirement::Confirmations { min_depth: 64 },
        ),
        (
            "finalized".to_string(),
            FindingObservedFinality::Confirmations { depth: 96 },
            FindingFinalityRequirement::Deterministic,
        ),
    ];

    for (policy, observed, finality_requirement) in cases {
        let mut body = snapshot_body();
        body.finality_policy = policy;
        body.observed_finality = observed;
        body.snapshot_id = compute_snapshot_id(&body).test_expect("snapshot id computes");
        let (enforcement, snapshot) =
            pair_from(body, &observer_keypair(), &finalization_keypair(), |_| {});
        let pins = FindingEnforcementPins {
            finality_requirement,
            ..default_pins()
        };
        assert_rejected(
            verify_finding_enforcement(&enforcement, &snapshot, &pins, TRUSTED_NOW),
            "observed finality does not satisfy",
        );
    }
}

#[test]
fn an_observer_cannot_choose_a_shallower_finality_policy() {
    let mut body = snapshot_body();
    body.finality_policy = "confirmations>=1".to_string();
    body.observed_finality = FindingObservedFinality::Confirmations { depth: 1 };
    body.snapshot_id = compute_snapshot_id(&body).test_expect("snapshot id computes");
    let (enforcement, snapshot) =
        pair_from(body, &observer_keypair(), &finalization_keypair(), |_| {});

    assert_rejected(
        verify_finding_enforcement(&enforcement, &snapshot, &default_pins(), TRUSTED_NOW),
        "does not match the pinned finality requirement",
    );
}

#[test]
fn a_finality_policy_outside_the_closed_vocabulary_is_rejected() {
    for policy in ["probabilistic", "confirmations>=", "confirmations>=064"] {
        let mut body = snapshot_body();
        body.finality_policy = policy.to_string();
        body.snapshot_id = compute_snapshot_id(&body).test_expect("snapshot id computes");
        let (enforcement, snapshot) =
            pair_from(body, &observer_keypair(), &finalization_keypair(), |_| {});
        let error =
            verify_finding_enforcement(&enforcement, &snapshot, &default_pins(), TRUSTED_NOW)
                .test_expect_err("unknown finality policy should reject");
        assert!(
            error.to_string().contains("finality policy"),
            "unexpected rejection for `{policy}`: {error}"
        );
    }
}

#[test]
fn a_deterministic_policy_and_observation_verify() {
    let mut body = snapshot_body();
    body.finality_policy = "finalized".to_string();
    body.observed_finality = FindingObservedFinality::Finalized;
    body.snapshot_id = compute_snapshot_id(&body).test_expect("snapshot id computes");
    let (enforcement, snapshot) =
        pair_from(body, &observer_keypair(), &finalization_keypair(), |_| {});

    let pins = FindingEnforcementPins {
        finality_requirement: FindingFinalityRequirement::Deterministic,
        ..default_pins()
    };
    verify_finding_enforcement(&enforcement, &snapshot, &pins, TRUSTED_NOW)
        .test_expect("deterministic finality verifies");
}

#[test]
fn an_amount_above_the_live_collateral_is_rejected() {
    let (enforcement, snapshot) = pair_from(
        snapshot_body(),
        &observer_keypair(),
        &finalization_keypair(),
        |enforcement| {
            enforcement.amount = usd(400_000);
            enforcement.destinations[0].amount = usd(240_000);
            enforcement.destinations[1].amount = usd(160_000);
        },
    );

    assert_rejected(
        verify_finding_enforcement(&enforcement, &snapshot, &default_pins(), TRUSTED_NOW),
        "exceeds the live allocated collateral",
    );
}

#[test]
fn a_currency_outside_the_snapshot_currency_is_rejected() {
    let (enforcement, snapshot) = pair_from(
        snapshot_body(),
        &observer_keypair(),
        &finalization_keypair(),
        |enforcement| {
            enforcement.amount.currency = "EUR".to_string();
            for destination in &mut enforcement.destinations {
                destination.amount.currency = "EUR".to_string();
            }
        },
    );

    assert_rejected(
        verify_finding_enforcement(&enforcement, &snapshot, &default_pins(), TRUSTED_NOW),
        "currency does not match the bond snapshot currency",
    );
}

#[test]
fn destinations_that_do_not_sum_to_the_amount_are_rejected() {
    let (enforcement, snapshot) = pair_from(
        snapshot_body(),
        &observer_keypair(),
        &finalization_keypair(),
        |enforcement| enforcement.destinations[1].amount = usd(90),
    );

    assert_rejected(
        verify_finding_enforcement(&enforcement, &snapshot, &default_pins(), TRUSTED_NOW),
        "destinations",
    );
}

#[test]
fn a_stale_or_future_dated_snapshot_is_rejected() {
    let (enforcement, snapshot) = default_pair();
    let pins = default_pins();

    assert_rejected(
        verify_finding_enforcement(
            &enforcement,
            &snapshot,
            &pins,
            OBSERVED_AT + MAX_SNAPSHOT_AGE_SECS + 1,
        ),
        "older than the configured maximum observation age",
    );
    assert_rejected(
        verify_finding_enforcement(&enforcement, &snapshot, &pins, OBSERVED_AT - 1),
        "observed after the trusted current time",
    );
    verify_finding_enforcement(
        &enforcement,
        &snapshot,
        &pins,
        OBSERVED_AT + MAX_SNAPSHOT_AGE_SECS,
    )
    .test_expect("a snapshot exactly at the age bound still verifies");
}

#[test]
fn confirmed_reconciliation_authenticates_an_aged_snapshot_without_renewing_dispatch() {
    let (enforcement, snapshot) = default_pair();
    let pins = default_pins();
    let stale_now = OBSERVED_AT + MAX_SNAPSHOT_AGE_SECS + 1;

    verify_finding_enforcement_for_reconciliation(&enforcement, &snapshot, &pins, stale_now)
        .test_expect("confirmed recovery may recheck the originally authenticated block");
    assert_rejected(
        verify_finding_enforcement_for_reconciliation(
            &enforcement,
            &snapshot,
            &pins,
            OBSERVED_AT - 1,
        ),
        "observed after the trusted current time",
    );
}

#[test]
fn plan_finding_impairment_freezes_the_authorized_call() {
    let planned = planned();
    let intent = planned.intent();

    assert_eq!(intent.intent_id, hex64(0xc1));
    assert_eq!(intent.liability_key, hex64(0xb1));
    assert_eq!(intent.amount, usd(250));
    assert_eq!(intent.slash_amount_minor_units, 2_500_000);
    assert_eq!(intent.vault_id, vault_id());
    assert_eq!(intent.chain_id, sample_config().chain_id);
    assert_eq!(
        parse_evm_address(&intent.target_contract, "target").test_expect("target parses"),
        parse_evm_address(BOND_VAULT_CONTRACT, "vault").test_expect("vault parses")
    );
    assert_eq!(
        intent
            .destinations
            .iter()
            .map(|destination| destination.destination.as_str())
            .collect::<Vec<_>>(),
        vec![BUYER_DESTINATION, COMMUNITY_FUND_DESTINATION]
    );
    assert_eq!(intent.destinations[0].share_minor_units, 1_500_000);
    assert_eq!(intent.destinations[1].share_minor_units, 1_000_000);
    assert_eq!(
        intent
            .destinations
            .iter()
            .map(|destination| destination.share_minor_units)
            .sum::<u128>(),
        intent.slash_amount_minor_units
    );
    assert_eq!(planned.prepared().evidence_hash, intent.evidence_hash);
    assert_eq!(planned.prepared().merkle_root, intent.merkle_root);
}

#[test]
fn plan_rejects_a_vault_snapshot_from_another_vault() {
    let mut foreign = vault_snapshot();
    foreign.vault_id = chain_hash(0x45);

    let error = plan_finding_impairment(
        &sample_config(),
        &verified(),
        &operator_address(),
        &foreign,
        &sample_anchor_proof(),
    )
    .test_expect_err("a foreign vault must not be impaired");

    assert!(
        error.to_string().contains("vault_id does not match"),
        "unexpected rejection: {error}"
    );
}

#[test]
fn plan_rejects_operator_key_drift_between_the_snapshot_and_the_chain() {
    let mut drifted = vault_snapshot();
    drifted.operator_key_hash = chain_hash(0x22);

    let error = plan_finding_impairment(
        &sample_config(),
        &verified(),
        &operator_address(),
        &drifted,
        &sample_anchor_proof(),
    )
    .test_expect_err("operator key drift must not be impaired");

    assert!(
        error
            .to_string()
            .contains("operator_key_hash does not match"),
        "unexpected rejection: {error}"
    );
}

#[test]
fn plan_rejects_a_config_that_does_not_match_the_snapshot() {
    let verified = verified();

    let mut wrong_chain = sample_config();
    wrong_chain.chain_id = "eip155:1".to_string();
    let error = plan_finding_impairment(
        &wrong_chain,
        &verified,
        &operator_address(),
        &vault_snapshot(),
        &sample_anchor_proof(),
    )
    .test_expect_err("a foreign chain must not be impaired");
    assert!(
        error.to_string().contains("chain_id does not match"),
        "unexpected rejection: {error}"
    );

    let mut wrong_vault_contract = sample_config();
    wrong_vault_contract.bond_vault_contract =
        "0x00000000000000000000000000000000000000bd".to_string();
    let error = plan_finding_impairment(
        &wrong_vault_contract,
        &verified,
        &operator_address(),
        &vault_snapshot(),
        &sample_anchor_proof(),
    )
    .test_expect_err("a foreign vault contract must not be impaired");
    assert!(
        error
            .to_string()
            .contains("bond_vault_contract does not match"),
        "unexpected rejection: {error}"
    );
}

#[test]
fn plan_refuses_destinations_outside_the_operator_allowlist() {
    let verified = verified();
    let mut config = sample_config();
    config
        .policy
        .finding_impairment_destination_allowlist
        .remove(BUYER_DESTINATION);

    let error = plan_finding_impairment(
        &config,
        &verified,
        &operator_address(),
        &vault_snapshot(),
        &sample_anchor_proof(),
    )
    .test_expect_err("an unallowlisted payout destination must not reach the vault");
    assert!(
        error.to_string().contains("not in the operator allowlist"),
        "unexpected rejection: {error}"
    );
}

#[test]
fn a_matching_finalized_transaction_confirms() {
    let planned = planned();
    let stored = stored_matching(&planned);

    let outcome = reconcile_finding_impairment(
        planned.intent(),
        &FindingImpairmentAttempt::Observed {
            stored: stored.clone(),
        },
    );

    assert_eq!(
        outcome,
        FindingImpairmentOutcome::Confirmed {
            tx_hash: stored.tx_hash
        }
    );
}

#[test]
fn evidence_already_used_with_a_matching_stored_transaction_confirms() {
    let planned = planned();
    let stored = stored_matching(&planned);

    let outcome = reconcile_finding_impairment(
        planned.intent(),
        &FindingImpairmentAttempt::Rejected {
            rejection: FindingVaultRejection::EvidenceAlreadyUsed,
            stored: Some(stored.clone()),
        },
    );

    assert_eq!(
        outcome,
        FindingImpairmentOutcome::Confirmed {
            tx_hash: stored.tx_hash
        }
    );
}

#[test]
fn evidence_already_used_without_a_stored_transaction_quarantines() {
    let planned = planned();

    let outcome = reconcile_finding_impairment(
        planned.intent(),
        &FindingImpairmentAttempt::Rejected {
            rejection: FindingVaultRejection::EvidenceAlreadyUsed,
            stored: None,
        },
    );

    assert_eq!(
        outcome,
        FindingImpairmentOutcome::Quarantined {
            reason: FindingImpairmentQuarantine::StoredTransactionMissing
        }
    );
}

#[test]
fn evidence_already_used_with_an_insufficient_observation_quarantines() {
    let planned = planned();
    let base = stored_matching(&planned);

    let mut missing_receipt = base.clone();
    missing_receipt.receipt = None;
    let mut unassessed = base.clone();
    unassessed.finality = None;
    let mut unfinalized = base.clone();
    unfinalized.finality = Some(SettlementFinalityStatus::AwaitingConfirmations);
    let mut reorged = base.clone();
    reorged.finality = Some(SettlementFinalityStatus::Reorged);
    let mut reverted = base.clone();
    reverted.receipt = Some(receipt(&base.tx_hash, &base.to_address, false));
    let mut foreign_receipt = base.clone();
    foreign_receipt.receipt = Some(receipt(&chain_hash(0xdf), &base.to_address, true));
    let mut foreign_chain = base.clone();
    foreign_chain.chain_id = "eip155:1".to_string();
    let mut foreign_target = base.clone();
    foreign_target.to_address = "0x00000000000000000000000000000000000000bd".to_string();
    let mut no_input = base.clone();
    no_input.input_data = None;
    let mut undecodable = base.clone();
    undecodable.input_data = Some("0xdeadbeef".to_string());

    let cases = [
        (missing_receipt, FindingImpairmentQuarantine::ReceiptMissing),
        (unassessed, FindingImpairmentQuarantine::ReceiptNotFinalized),
        (
            unfinalized,
            FindingImpairmentQuarantine::ReceiptNotFinalized,
        ),
        (reorged, FindingImpairmentQuarantine::ReceiptNotFinalized),
        (reverted, FindingImpairmentQuarantine::ReceiptReverted),
        (
            foreign_receipt,
            FindingImpairmentQuarantine::ReceiptTransactionMismatch,
        ),
        (foreign_chain, FindingImpairmentQuarantine::ChainMismatch),
        (foreign_target, FindingImpairmentQuarantine::TargetMismatch),
        (
            no_input,
            FindingImpairmentQuarantine::EvidenceProvenanceUnavailable,
        ),
        (undecodable, FindingImpairmentQuarantine::UndecodableInput),
    ];

    for (stored, reason) in cases {
        let outcome = reconcile_finding_impairment(
            planned.intent(),
            &FindingImpairmentAttempt::Rejected {
                rejection: FindingVaultRejection::EvidenceAlreadyUsed,
                stored: Some(stored),
            },
        );
        assert_eq!(
            outcome,
            FindingImpairmentOutcome::Quarantined { reason },
            "expected quarantine {reason:?}"
        );
    }
}

#[test]
fn evidence_already_used_with_mismatched_decoded_input_quarantines() {
    let planned = planned();
    let base = stored_matching(&planned);
    let other_beneficiary = Address::from_str("0x1000000000000000000000000000000000000009")
        .test_expect("address parses");

    let inputs = [
        mutated_input(&planned, |call| {
            call.vaultId =
                parse_chain_hash(&chain_hash(0x45), "vault").test_expect("vault id parses")
        }),
        mutated_input(&planned, |call| {
            call.evidenceHash =
                parse_chain_hash(&chain_hash(0x46), "evidence").test_expect("evidence parses");
        }),
        mutated_input(&planned, |call| {
            call.root = parse_chain_hash(&chain_hash(0x47), "root").test_expect("root parses");
        }),
        mutated_input(&planned, |call| {
            call.slashAmount = U256::from(2_400_000_u64)
        }),
        mutated_input(&planned, |call| {
            call.beneficiaries[0] = other_beneficiary;
        }),
        mutated_input(&planned, |call| {
            call.shares[0] = U256::from(1_400_000_u64);
            call.shares[1] = U256::from(1_100_000_u64);
        }),
        mutated_input(&planned, |call| {
            call.beneficiaries.swap(0, 1);
            call.shares.swap(0, 1);
        }),
        mutated_input(&planned, |call| {
            call.beneficiaries.truncate(1);
            call.shares.truncate(1);
        }),
    ];

    for input in inputs {
        let mut stored = base.clone();
        stored.input_data = Some(input);
        let outcome = reconcile_finding_impairment(
            planned.intent(),
            &FindingImpairmentAttempt::Rejected {
                rejection: FindingVaultRejection::EvidenceAlreadyUsed,
                stored: Some(stored),
            },
        );
        assert_eq!(
            outcome,
            FindingImpairmentOutcome::Quarantined {
                reason: FindingImpairmentQuarantine::DecodedInputMismatch
            }
        );
    }
}

#[test]
fn other_vault_rejections_fail_without_claiming_a_slash() {
    let planned = planned();
    let rejections = [
        FindingVaultRejection::BondNotLive,
        FindingVaultRejection::InvalidEvidence,
        FindingVaultRejection::InvalidSlashDistribution,
        FindingVaultRejection::OperatorNotQualified,
        FindingVaultRejection::VaultPaused,
        FindingVaultRejection::TransferFailed,
    ];

    for rejection in rejections {
        let outcome = reconcile_finding_impairment(
            planned.intent(),
            &FindingImpairmentAttempt::Rejected {
                rejection,
                stored: Some(stored_matching(&planned)),
            },
        );
        assert_eq!(
            outcome,
            FindingImpairmentOutcome::Failed { reason: rejection }
        );
    }
}

struct StubPublisher {
    fenced_intent_id: String,
    expected_call_data: String,
    attempt: FindingImpairmentAttempt,
}

impl FindingImpairmentPublisher for StubPublisher {
    fn publish(
        &self,
        intent: &FindingImpairmentIntent,
        call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        if intent.intent_id != self.fenced_intent_id {
            return Err(FindingImpairmentPublishError::IntentNotFenced(
                intent.intent_id.clone(),
            ));
        }
        if call.data != self.expected_call_data {
            return Err(FindingImpairmentPublishError::Permanent(
                "dispatched call does not match the fenced intent".to_string(),
            ));
        }
        Ok(self.attempt.clone())
    }

    fn observe(
        &self,
        intent: &FindingImpairmentIntent,
        call: &PreparedEvmCall,
    ) -> Result<FindingImpairmentAttempt, FindingImpairmentPublishError> {
        if intent.intent_id != self.fenced_intent_id {
            return Err(FindingImpairmentPublishError::IntentNotFenced(
                intent.intent_id.clone(),
            ));
        }
        if call.data != self.expected_call_data {
            return Err(FindingImpairmentPublishError::Permanent(
                "observed call does not match the fenced intent".to_string(),
            ));
        }
        Ok(self.attempt.clone())
    }
}

#[test]
fn the_publisher_seam_dispatches_the_frozen_call_and_reconciles_it() {
    let planned = planned();
    let stored = stored_matching(&planned);
    let publisher = StubPublisher {
        fenced_intent_id: planned.intent().intent_id.clone(),
        expected_call_data: planned.call().data.clone(),
        attempt: FindingImpairmentAttempt::Observed {
            stored: stored.clone(),
        },
    };

    let outcome =
        dispatch_finding_impairment(&planned, &publisher).test_expect("a fenced intent dispatches");

    assert_eq!(
        outcome,
        FindingImpairmentOutcome::Confirmed {
            tx_hash: stored.tx_hash
        }
    );
}

#[test]
fn the_publisher_seam_reobserves_the_frozen_call_without_dispatch() {
    let planned = planned();
    let stored = stored_matching(&planned);
    let publisher = StubPublisher {
        fenced_intent_id: planned.intent().intent_id.clone(),
        expected_call_data: planned.call().data.clone(),
        attempt: FindingImpairmentAttempt::Observed {
            stored: stored.clone(),
        },
    };

    let outcome = reobserve_finding_impairment(&planned, &publisher)
        .test_expect("a stored transaction can be re-observed");

    assert_eq!(
        outcome,
        FindingImpairmentOutcome::Confirmed {
            tx_hash: stored.tx_hash
        }
    );
}

#[test]
fn an_unfenced_intent_never_reaches_reconciliation() {
    let planned = planned();
    let publisher = StubPublisher {
        fenced_intent_id: hex64(0xcf),
        expected_call_data: planned.call().data.clone(),
        attempt: FindingImpairmentAttempt::Observed {
            stored: stored_matching(&planned),
        },
    };

    let error = dispatch_finding_impairment(&planned, &publisher)
        .test_expect_err("an unfenced intent must not dispatch");

    assert!(matches!(
        error,
        FindingImpairmentPublishError::IntentNotFenced(_)
    ));
}

#[test]
fn a_publisher_report_that_does_not_match_the_intent_quarantines() {
    let planned = planned();
    let mut stored = stored_matching(&planned);
    stored.input_data = Some(mutated_input(&planned, |call| {
        call.slashAmount = U256::from(1_u8);
    }));
    let publisher = StubPublisher {
        fenced_intent_id: planned.intent().intent_id.clone(),
        expected_call_data: planned.call().data.clone(),
        attempt: FindingImpairmentAttempt::Observed { stored },
    };

    let outcome = dispatch_finding_impairment(&planned, &publisher)
        .test_expect("the publisher reports an attempt");

    assert_eq!(
        outcome,
        FindingImpairmentOutcome::Quarantined {
            reason: FindingImpairmentQuarantine::DecodedInputMismatch
        }
    );
}

#[test]
fn an_unchanged_observation_stays_qualified() {
    let verified = verified();
    let mut observed = recheck_from_snapshot(&verified);
    // The artifact shape leaves the `0x` prefix and the digit case free, so
    // another rendering of the same hash must still read as unchanged.
    observed.operator_key_hash = OPERATOR_KEY_HASH
        .trim_start_matches("0x")
        .to_ascii_uppercase();

    let verdict = recheck_finding_bond_observation(&verified, &observed);

    assert_eq!(verdict, FindingBondObservationVerdict::Qualified);
    assert!(verdict.is_qualified());
}

#[test]
fn a_reorged_block_hash_returns_to_reconciliation() {
    let verified = verified();

    let mut moved = recheck_from_snapshot(&verified);
    moved.block_hash = Some(chain_hash(0xba));
    let verdict = recheck_finding_bond_observation(&verified, &moved);
    assert_eq!(
        verdict,
        FindingBondObservationVerdict::Reorged {
            expected_block_hash: verified.snapshot().block_hash.clone(),
            observed_block_hash: Some(chain_hash(0xba)),
        }
    );
    assert!(!verdict.is_qualified());

    let mut gone = recheck_from_snapshot(&verified);
    gone.block_hash = None;
    assert_eq!(
        recheck_finding_bond_observation(&verified, &gone),
        FindingBondObservationVerdict::Reorged {
            expected_block_hash: verified.snapshot().block_hash.clone(),
            observed_block_hash: None,
        }
    );
}

#[test]
fn a_regressed_confirmation_depth_returns_to_reconciliation() {
    let verified = verified();
    let mut observed = recheck_from_snapshot(&verified);
    observed.observed_finality = FindingObservedFinality::Confirmations { depth: 63 };

    assert_eq!(
        recheck_finding_bond_observation(&verified, &observed),
        FindingBondObservationVerdict::FinalityRegressed {
            required: FindingFinalityRequirement::Confirmations { min_depth: 64 },
            observed: FindingObservedFinality::Confirmations { depth: 63 },
        }
    );
}

#[test]
fn an_operator_rotation_or_deactivation_returns_to_reconciliation() {
    let verified = verified();

    let mut inactive = recheck_from_snapshot(&verified);
    inactive.operator_active = false;
    assert_eq!(
        recheck_finding_bond_observation(&verified, &inactive),
        FindingBondObservationVerdict::OperatorNotActive
    );

    let cases: [(RecheckMutation, FindingOperatorQualification); 3] = [
        (
            Box::new(|observed: &mut FindingBondObservationRecheck| {
                observed.identity_registry_record = "registry/operators/venue-43".to_string();
            }),
            FindingOperatorQualification::IdentityRegistryRecord,
        ),
        (
            Box::new(|observed: &mut FindingBondObservationRecheck| {
                observed.operator_key_hash = chain_hash(0x22);
            }),
            FindingOperatorQualification::OperatorKeyHash,
        ),
        (
            Box::new(|observed: &mut FindingBondObservationRecheck| {
                observed.operator_key_epoch = 4;
            }),
            FindingOperatorQualification::OperatorKeyEpoch,
        ),
    ];

    for (mutate, field) in cases {
        let mut observed = recheck_from_snapshot(&verified);
        mutate(&mut observed);
        assert_eq!(
            recheck_finding_bond_observation(&verified, &observed),
            FindingBondObservationVerdict::OperatorRotated { field }
        );
    }
}
