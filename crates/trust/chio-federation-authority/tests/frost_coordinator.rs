use std::collections::BTreeMap;

use chio_core_types::Keypair;
use chio_federation::frost::{
    frost_action_registration, FrostActionPreimageV1, FrostAuthorizationBodyV1,
    FrostAuthorizationDomain, FrostParticipantV1, FrostRosterKeyOrigin, FrostRosterV1,
    FrostSettleCommitmentActionV1, CHIO_FROST_AUTHORIZATION_BODY_SCHEMA, CHIO_FROST_ROSTER_SCHEMA,
    CHIO_FROST_SETTLE_COMMITMENT_ACTION_SCHEMA, FROST_ED25519_SHA512_SUITE_ID,
};
use chio_federation_authority::{
    aggregate_frost_authorization, build_frost_signing_package, frost_participant_identifier_bytes,
    validate_frost_signing_commitment, verify_frost_signature_share,
};
use frost_ed25519::keys::{IdentifierList, KeyPackage};
use frost_ed25519::{keys, round1, round2, Identifier, SigningKey, SigningPackage};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

struct Fixture {
    roster: FrostRosterV1,
    body: FrostAuthorizationBodyV1,
    key_packages: BTreeMap<String, KeyPackage>,
}

fn fixture() -> Fixture {
    let registration = frost_action_registration(FrostAuthorizationDomain::SettleCommitment)
        .unwrap_or_else(|| panic!("settlement registration"));
    let participant_ids = (1..=registration.quorum_m)
        .map(|index| format!("operator-{index}"))
        .collect::<Vec<_>>();
    let identifiers = participant_ids
        .iter()
        .map(|participant_id| {
            Identifier::derive(participant_id.as_bytes())
                .unwrap_or_else(|error| panic!("derive identifier: {error}"))
        })
        .collect::<Vec<_>>();
    let mut rng = ChaCha20Rng::from_seed([0x91; 32]);
    let signing_key = SigningKey::new(&mut rng);
    let (shares, public_keys) = keys::split(
        &signing_key,
        registration.quorum_m,
        registration.quorum_n,
        IdentifierList::Custom(&identifiers),
        &mut rng,
    )
    .unwrap_or_else(|error| panic!("split group: {error}"));
    let key_packages = participant_ids
        .iter()
        .zip(identifiers.iter())
        .map(|(participant_id, identifier)| {
            let share = shares
                .get(identifier)
                .cloned()
                .unwrap_or_else(|| panic!("participant share"));
            let package = KeyPackage::try_from(share)
                .unwrap_or_else(|error| panic!("validate key package: {error}"));
            (participant_id.clone(), package)
        })
        .collect::<BTreeMap<_, _>>();
    let roster_authority = Keypair::from_seed(&[0x92; 32]);
    let mut roster = FrostRosterV1 {
        schema: CHIO_FROST_ROSTER_SCHEMA.to_string(),
        roster_id: String::new(),
        roster_digest: String::new(),
        authority_scope: registration.quorum_scope.to_string(),
        scope_id: "settlement.atlantic.v1".to_string(),
        allowed_domains: vec![FrostAuthorizationDomain::SettleCommitment],
        key_epoch: 1,
        threshold: registration.quorum_n,
        participant_count: registration.quorum_m,
        participants: participant_ids
            .iter()
            .map(|participant_id| {
                let package = key_packages
                    .get(participant_id)
                    .unwrap_or_else(|| panic!("key package"));
                FrostParticipantV1 {
                    participant_id: participant_id.clone(),
                    verification_share: hex::encode(
                        package
                            .verifying_share()
                            .serialize()
                            .unwrap_or_else(|error| panic!("serialize share: {error}")),
                    ),
                }
            })
            .collect(),
        group_public_key: hex::encode(
            public_keys
                .verifying_key()
                .serialize()
                .unwrap_or_else(|error| panic!("serialize group key: {error}")),
        ),
        suite_id: FROST_ED25519_SHA512_SUITE_ID.to_string(),
        key_origin: FrostRosterKeyOrigin::DistributedDkg,
        ceremony_transcript_digest: "93".repeat(32),
        predecessor_roster_digest: None,
        valid_from: 100,
        valid_until: 10_000,
        roster_authority_key_id: "roster-authority.v1".to_string(),
        roster_authority_signature: String::new(),
    };
    roster.roster_id = roster
        .recompute_roster_id()
        .unwrap_or_else(|error| panic!("roster id: {error}"));
    roster.roster_authority_signature = roster_authority
        .sign(
            &roster
                .signing_bytes()
                .unwrap_or_else(|error| panic!("roster bytes: {error}")),
        )
        .to_hex();
    roster.roster_digest = roster
        .recompute_roster_digest()
        .unwrap_or_else(|error| panic!("roster digest: {error}"));
    let action = FrostActionPreimageV1::SettleCommitment(FrostSettleCommitmentActionV1 {
        schema: CHIO_FROST_SETTLE_COMMITMENT_ACTION_SCHEMA.to_string(),
        settlement_body_digest: "94".repeat(32),
        payer_id: "payer-1".to_string(),
        payee_id: "payee-1".to_string(),
        amount_base_units: "100".to_string(),
        asset_id: "usd.test".to_string(),
        operation_id: "settlement-operation-1".to_string(),
        rail_idempotency_key: "rail-settlement-operation-1".to_string(),
        resource_version: 1,
        resource_fence: 7,
    });
    let mut body = FrostAuthorizationBodyV1 {
        schema: CHIO_FROST_AUTHORIZATION_BODY_SCHEMA.to_string(),
        authorization_id: String::new(),
        domain: FrostAuthorizationDomain::SettleCommitment,
        ladder_action_class: registration.ladder_action_class.to_string(),
        ladder_contract_digest: registration
            .ladder_contract_digest()
            .unwrap_or_else(|error| panic!("ladder digest: {error}")),
        quorum_n: registration.quorum_n,
        quorum_m: registration.quorum_m,
        quorum_scope: registration.quorum_scope.to_string(),
        scope_id: roster.scope_id.clone(),
        resource_id: "settlement-operation-1".to_string(),
        resource_version: 1,
        resource_fence: 7,
        action_digest: action
            .action_digest()
            .unwrap_or_else(|error| panic!("action digest: {error}")),
        roster_digest: roster.roster_digest.clone(),
        key_epoch: roster.key_epoch,
        issued_at: 100,
        expires_at: 10_000,
    };
    body.authorization_id = body
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("authorization id: {error}"));
    Fixture {
        roster,
        body,
        key_packages,
    }
}

#[test]
fn coordinator_builds_one_sorted_threshold_package_and_verifies_every_share() {
    let fixture = fixture();
    let mut rng = ChaCha20Rng::from_seed([0x95; 32]);
    let mut commitments = BTreeMap::new();
    let mut nonces = BTreeMap::new();
    for (participant_id, key_package) in &fixture.key_packages {
        let (participant_nonces, commitment) =
            round1::commit(key_package.signing_share(), &mut rng);
        let commitment_bytes = commitment
            .serialize()
            .unwrap_or_else(|error| panic!("serialize commitment: {error}"));
        let identifier_bytes = frost_participant_identifier_bytes(participant_id)
            .unwrap_or_else(|error| panic!("participant identifier: {error}"));
        validate_frost_signing_commitment(
            &fixture.roster,
            participant_id,
            &identifier_bytes,
            &commitment_bytes,
        )
        .unwrap_or_else(|error| panic!("validate commitment: {error}"));
        commitments.insert(participant_id.clone(), commitment_bytes);
        nonces.insert(participant_id.clone(), participant_nonces);
    }
    let package = build_frost_signing_package(&fixture.body, &fixture.roster, &commitments)
        .unwrap_or_else(|error| panic!("build package: {error}"));
    let mut oversized_commitments = commitments.clone();
    oversized_commitments.insert(
        "operator-extra".to_string(),
        commitments
            .values()
            .next()
            .cloned()
            .unwrap_or_else(|| panic!("commitment exists")),
    );
    assert!(
        build_frost_signing_package(&fixture.body, &fixture.roster, &oversized_commitments,)
            .is_err()
    );
    assert_eq!(
        package.participant_ids(),
        &fixture
            .key_packages
            .keys()
            .take(usize::from(fixture.roster.threshold))
            .cloned()
            .collect::<Vec<_>>()
    );
    let decoded_package = SigningPackage::deserialize(package.bytes())
        .unwrap_or_else(|error| panic!("decode package: {error}"));
    let mut shares = BTreeMap::new();
    for participant_id in package.participant_ids() {
        let key_package = fixture
            .key_packages
            .get(participant_id)
            .unwrap_or_else(|| panic!("selected key package"));
        let participant_nonces = nonces
            .get(participant_id)
            .unwrap_or_else(|| panic!("selected nonces"));
        let share = round2::sign(&decoded_package, participant_nonces, key_package)
            .unwrap_or_else(|error| panic!("sign share: {error}"));
        let share_bytes = share.serialize();
        verify_frost_signature_share(
            &fixture.body,
            &fixture.roster,
            package.bytes(),
            participant_id,
            &share_bytes,
        )
        .unwrap_or_else(|error| panic!("verify share: {error}"));
        shares.insert(participant_id.clone(), share_bytes);
    }
    let proof =
        aggregate_frost_authorization(&fixture.body, &fixture.roster, package.bytes(), &shares)
            .unwrap_or_else(|error| panic!("aggregate authorization: {error}"));
    assert_eq!(proof.body, fixture.body);

    let mut changed_body = proof.body.clone();
    changed_body.resource_fence += 1;
    assert!(verify_frost_signature_share(
        &changed_body,
        &fixture.roster,
        package.bytes(),
        package
            .participant_ids()
            .first()
            .unwrap_or_else(|| panic!("selected participant")),
        shares
            .values()
            .next()
            .unwrap_or_else(|| panic!("selected share")),
    )
    .is_err());
}
