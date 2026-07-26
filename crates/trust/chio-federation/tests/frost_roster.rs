use std::path::PathBuf;

use chio_core_types::{Keypair, PublicKey};
use chio_federation::frost::{
    registered_frost_actions, FrostArtifactAuthorityRole, FrostArtifactTrustRoot,
    FrostArtifactTrustStore, FrostAuthorizationDomain, FrostParticipantV1, FrostRosterKeyOrigin,
    FrostRosterV1, CHIO_FROST_ROSTER_SCHEMA, FROST_ED25519_SHA512_SUITE_ID,
};
use frost_ed25519::keys::{SigningShare, VerifyingShare};

const OFFICIAL_SHARES: [&str; 3] = [
    "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509",
    "a91e66e012e4364ac9aaa405fcafd370402d9859f7b6685c07eed76bf409e80d",
    "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02",
];
const OFFICIAL_VERIFYING_KEY: &str =
    "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673";

fn decode_hex(value: &str) -> Vec<u8> {
    hex::decode(value).unwrap_or_else(|error| panic!("fixture hex must decode: {error}"))
}

fn verification_share(share: &str) -> String {
    let signing_share = SigningShare::deserialize(&decode_hex(share))
        .unwrap_or_else(|error| panic!("signing share must decode: {error}"));
    hex::encode(
        VerifyingShare::from(signing_share)
            .serialize()
            .unwrap_or_else(|error| panic!("verification share must serialize: {error}")),
    )
}

fn authority() -> Keypair {
    Keypair::from_seed(&[0x42; 32])
}

fn trust_store(public_key: PublicKey) -> FrostArtifactTrustStore {
    FrostArtifactTrustStore::new([FrostArtifactTrustRoot {
        role: FrostArtifactAuthorityRole::Roster,
        key_id: "authority.treaty.v1".to_string(),
        public_key,
    }])
    .unwrap_or_else(|error| panic!("fixture trust store must build: {error}"))
}

fn signed_roster() -> FrostRosterV1 {
    let authority = authority();
    let mut roster = FrostRosterV1 {
        schema: CHIO_FROST_ROSTER_SCHEMA.to_string(),
        roster_id: String::new(),
        roster_digest: String::new(),
        authority_scope: "treaty".to_string(),
        scope_id: "treaty.atlantic.v1".to_string(),
        allowed_domains: vec![FrostAuthorizationDomain::SettleCommitment],
        key_epoch: 4,
        threshold: 2,
        participant_count: 3,
        participants: OFFICIAL_SHARES
            .iter()
            .enumerate()
            .map(|(index, share)| FrostParticipantV1 {
                participant_id: format!("operator-{}", index + 1),
                verification_share: verification_share(share),
            })
            .collect(),
        group_public_key: OFFICIAL_VERIFYING_KEY.to_string(),
        suite_id: FROST_ED25519_SHA512_SUITE_ID.to_string(),
        key_origin: FrostRosterKeyOrigin::DistributedDkg,
        ceremony_transcript_digest: "44".repeat(32),
        predecessor_roster_digest: Some("55".repeat(32)),
        valid_from: 100,
        valid_until: 1_000,
        roster_authority_key_id: "authority.treaty.v1".to_string(),
        roster_authority_signature: String::new(),
    };
    roster.roster_id = roster
        .recompute_roster_id()
        .unwrap_or_else(|error| panic!("roster id must compute: {error}"));
    roster.roster_authority_signature = authority
        .sign(
            &roster
                .signing_bytes()
                .unwrap_or_else(|error| panic!("roster must canonicalize: {error}")),
        )
        .to_hex();
    roster.roster_digest = roster
        .recompute_roster_digest()
        .unwrap_or_else(|error| panic!("roster digest must compute: {error}"));
    roster
}

#[test]
fn dealer_fixture_roster_is_never_active_resolution_material() {
    let mut roster = signed_roster();
    roster.key_origin = FrostRosterKeyOrigin::DealerFixture;
    roster.roster_id = roster
        .recompute_roster_id()
        .unwrap_or_else(|error| panic!("fixture roster id must compute: {error}"));
    roster.roster_authority_signature = authority()
        .sign(
            &roster
                .signing_bytes()
                .unwrap_or_else(|error| panic!("fixture roster must canonicalize: {error}")),
        )
        .to_hex();
    roster.roster_digest = roster
        .recompute_roster_digest()
        .unwrap_or_else(|error| panic!("fixture roster digest must compute: {error}"));

    trust_store(authority().public_key())
        .verify_roster(&roster)
        .unwrap_or_else(|error| panic!("fixture origin remains signed evidence: {error}"));
    assert!(roster.validate_for_active_resolution().is_err());
}

#[test]
fn frost_roster_requires_a_pinned_authority_signature() {
    let roster = signed_roster();
    let trusted = trust_store(authority().public_key());
    trusted
        .verify_roster(&roster)
        .unwrap_or_else(|error| panic!("pinned authority signature must verify: {error}"));

    let untrusted = trust_store(Keypair::from_seed(&[0x24; 32]).public_key());
    assert!(
        untrusted.verify_roster(&roster).is_err(),
        "an artifact cannot authenticate its own signing key"
    );
    let wrong_role = FrostArtifactTrustStore::new([FrostArtifactTrustRoot {
        role: FrostArtifactAuthorityRole::EpochAnchor,
        key_id: "authority.treaty.v1".to_string(),
        public_key: authority().public_key(),
    }])
    .unwrap_or_else(|error| panic!("wrong-role trust store must build: {error}"));
    assert!(
        wrong_role.verify_roster(&roster).is_err(),
        "a key trusted for another role must not authenticate a roster"
    );
    let shared_key = authority().public_key();
    assert!(FrostArtifactTrustStore::new([
        FrostArtifactTrustRoot {
            role: FrostArtifactAuthorityRole::Roster,
            key_id: "authority.treaty.v1".to_string(),
            public_key: shared_key.clone(),
        },
        FrostArtifactTrustRoot {
            role: FrostArtifactAuthorityRole::EpochAnchor,
            key_id: "epoch-anchor-key.v1".to_string(),
            public_key: shared_key,
        },
    ])
    .is_err());

    let mut tampered = roster;
    tampered.valid_until += 1;
    tampered.roster_id = tampered
        .recompute_roster_id()
        .unwrap_or_else(|error| panic!("tampered id must compute: {error}"));
    tampered.roster_digest = tampered
        .recompute_roster_digest()
        .unwrap_or_else(|error| panic!("tampered digest must compute: {error}"));
    assert!(trusted.verify_roster(&tampered).is_err());
}

#[test]
fn frost_roster_rejects_unknown_shape_and_invalid_contract_fields() {
    let roster = signed_roster();
    let mut value = serde_json::to_value(&roster)
        .unwrap_or_else(|error| panic!("roster must serialize: {error}"));
    value["rosterAuthorityPublicKey"] = serde_json::json!(authority().public_key().to_hex());
    assert!(serde_json::from_value::<FrostRosterV1>(value).is_err());

    let mut unknown_schema = roster.clone();
    unknown_schema.schema = "chio.frost.roster.v9".to_string();
    assert!(unknown_schema.validate().is_err());

    let mut unsorted = roster.clone();
    unsorted.participants.swap(0, 1);
    assert!(unsorted.validate().is_err());

    let mut duplicate_share = roster.clone();
    duplicate_share.participants[1].verification_share =
        duplicate_share.participants[0].verification_share.clone();
    assert!(duplicate_share.validate().is_err());

    let mut invalid_threshold = roster.clone();
    invalid_threshold.threshold = 3;
    assert!(invalid_threshold.validate().is_err());

    let mut missing_predecessor = roster.clone();
    missing_predecessor.predecessor_roster_digest = None;
    assert!(missing_predecessor.validate().is_err());

    let mut reserved_domain = roster;
    reserved_domain.allowed_domains = vec![FrostAuthorizationDomain::AdjudicationPanelDecision];
    assert!(reserved_domain.validate().is_err());
}

#[test]
fn frost_roster_registry_has_one_exact_row_for_every_ladder_quorum_action() {
    let ladder = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../spec/CHIO_LADDER.md"
    ));
    let mut ladder_rows = Vec::new();
    let mut in_json = false;
    let mut block = String::new();
    for line in ladder.lines() {
        if line == "```json" {
            in_json = true;
            block.clear();
        } else if in_json && line == "```" {
            let value: serde_json::Value = serde_json::from_str(&block)
                .unwrap_or_else(|error| panic!("ladder JSON block must parse: {error}"));
            if let Some(actions) = value
                .get("action_classes")
                .and_then(serde_json::Value::as_array)
            {
                ladder_rows.extend(
                    actions
                        .iter()
                        .filter(|action| {
                            action.get("co_sign").and_then(serde_json::Value::as_str)
                                == Some("n_of_m")
                        })
                        .cloned(),
                );
            }
            in_json = false;
        } else if in_json {
            block.push_str(line);
            block.push('\n');
        }
    }

    let registrations = registered_frost_actions();
    assert_eq!(ladder_rows.len(), registrations.len());
    for row in ladder_rows {
        let action_class = row["id"]
            .as_str()
            .unwrap_or_else(|| panic!("ladder action must have an id"));
        let matches: Vec<_> = registrations
            .iter()
            .filter(|registration| registration.ladder_action_class == action_class)
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "{action_class} must have one registry row"
        );
        let registration = matches[0];
        let quorum = &row["co_sign_quorum"];
        assert_eq!(quorum["n"].as_u64(), Some(u64::from(registration.quorum_n)));
        assert_eq!(quorum["m"].as_u64(), Some(u64::from(registration.quorum_m)));
        assert_eq!(quorum["scope"].as_str(), Some(registration.quorum_scope));
        let canonical = chio_core_types::canonical_json_bytes(&row)
            .unwrap_or_else(|error| panic!("ladder row must canonicalize: {error}"));
        assert_eq!(
            registration
                .ladder_contract_digest()
                .unwrap_or_else(|error| panic!("registry digest must compute: {error}")),
            chio_core_types::sha256_hex(&canonical),
            "{action_class} registry row must be byte-exact"
        );
    }
}

#[test]
fn frost_roster_published_schemas_validate_signed_fixtures() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let family = root.join("spec/schemas/chio-frost/v1");
    for (schema, fixture) in [
        ("roster.schema.json", "fixtures/roster.positive.json"),
        (
            "epoch-checkpoint.schema.json",
            "fixtures/epoch-checkpoint.positive.json",
        ),
        (
            "authorization-slot-checkpoint.schema.json",
            "fixtures/authorization-slot-checkpoint.positive.json",
        ),
        (
            "authorization.schema.json",
            "fixtures/authorization.positive.json",
        ),
    ] {
        chio_spec_validate::validate(&family.join(schema), &family.join(fixture))
            .unwrap_or_else(|error| panic!("{fixture} must satisfy {schema}: {error}"));
    }

    let roster_schema_path = family.join("roster.schema.json");
    let roster_schema = chio_spec_validate::load_json(&roster_schema_path)
        .unwrap_or_else(|error| panic!("roster schema must load: {error}"));
    let roster_path = family.join("fixtures/roster.positive.json");
    let roster_value = chio_spec_validate::load_json(&roster_path)
        .unwrap_or_else(|error| panic!("roster fixture must load: {error}"));
    for (case, mutate) in [
        (
            "unknown version",
            ("schema", serde_json::json!("chio.frost.roster.v9")),
        ),
        (
            "invalid domain",
            (
                "allowedDomains",
                serde_json::json!(["chio.frost.adjudication-panel-decision.v1"]),
            ),
        ),
        (
            "embedded key",
            (
                "rosterAuthorityPublicKey",
                serde_json::json!(authority().public_key().to_hex()),
            ),
        ),
    ] {
        let mut invalid = roster_value.clone();
        invalid[mutate.0] = mutate.1;
        assert!(
            chio_spec_validate::validate_value(
                &roster_schema_path,
                &roster_schema,
                &PathBuf::from(format!("<{case}>")),
                &invalid,
            )
            .is_err(),
            "{case} must reject at the published schema boundary"
        );
    }
    let mut missing_predecessor = roster_value;
    missing_predecessor
        .as_object_mut()
        .unwrap_or_else(|| panic!("roster fixture must be an object"))
        .remove("predecessorRosterDigest");
    assert!(chio_spec_validate::validate_value(
        &roster_schema_path,
        &roster_schema,
        &PathBuf::from("<missing predecessor>"),
        &missing_predecessor,
    )
    .is_err());

    let tampered_path = family.join("fixtures/roster.tampered-signature.json");
    chio_spec_validate::validate(&roster_schema_path, &tampered_path)
        .unwrap_or_else(|error| panic!("tampered signature remains schema-shaped: {error}"));
    let tampered_text = std::fs::read_to_string(&tampered_path)
        .unwrap_or_else(|error| panic!("tampered fixture must read: {error}"));
    let tampered: FrostRosterV1 = serde_json::from_str(&tampered_text)
        .unwrap_or_else(|error| panic!("tampered fixture must decode: {error}"));
    assert!(
        trust_store(authority().public_key())
            .verify_roster(&tampered)
            .is_err(),
        "schema validity cannot substitute for pinned signature verification"
    );
}
