use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_credit::obligation::{
    credit_facility_scope_digest, verify_credit_facility_bind, CreditFacilityBindBodyV1,
    CreditFacilityBindError, CreditFacilityBindInputV1, CreditFacilityBindTrustInputV1,
    CreditFacilityBindTrustV1, CreditFacilityBindVerificationContextV1, SignedCreditFacilityBindV1,
    VerifiedCreditFacilityBindV1,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const AUTHORITY_ID: &str = "credit-admission-authority";
const DEBTOR_ID: &str = "did:chio:debtor";
const CREDITOR_ID: &str = "did:chio:creditor";
const DESTINATION: &str = "acct:creditor";
const ISSUED_AT_UNIX_MS: u64 = 1_000;
const EXPIRES_AT_UNIX_MS: u64 = 1_100;
const DUE_AT_UNIX_MS: u64 = 5_000;

fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

fn input() -> CreditFacilityBindInputV1 {
    CreditFacilityBindInputV1 {
        operation_id: digest("operation"),
        request_id: "request-1".to_owned(),
        economic_intent_digest: digest("economic-intent"),
        facility_id: "facility:working-capital".to_owned(),
        facility_artifact_digest: digest("facility-artifact"),
        authority_set_digest: digest("credit-authority-set"),
        debtor_id: DEBTOR_ID.to_owned(),
        original_creditor_id: CREDITOR_ID.to_owned(),
        original_settlement_destination_ref: DESTINATION.to_owned(),
        capability_id: "capability:metered-tool".to_owned(),
        tool_server: "research-server".to_owned(),
        tool_name: "search".to_owned(),
        amount: MonetaryAmount {
            units: 1_250,
            currency: "USD".to_owned(),
        },
        effective_ceiling: MonetaryAmount {
            units: 5_000,
            currency: "USD".to_owned(),
        },
        expected_exposure_version: 9,
        expected_exposure_fence: 11,
        due_at_unix_ms: DUE_AT_UNIX_MS,
        action_nonce: "credit-admission-nonce-1".to_owned(),
        issued_at_unix_ms: ISSUED_AT_UNIX_MS,
        expires_at_unix_ms: EXPIRES_AT_UNIX_MS,
        authority_id: AUTHORITY_ID.to_owned(),
        authority_key_epoch: 3,
        debtor_key_epoch: 5,
        creditor_key_epoch: 7,
    }
}

struct Fixture {
    authority: Keypair,
    debtor: Keypair,
    creditor: Keypair,
    signed: SignedCreditFacilityBindV1,
    trust: CreditFacilityBindTrustV1,
}

fn trust_input(
    authority: &Keypair,
    debtor: &Keypair,
    creditor: &Keypair,
) -> CreditFacilityBindTrustInputV1 {
    CreditFacilityBindTrustInputV1 {
        authority_id: AUTHORITY_ID.to_owned(),
        authority_key: authority.public_key(),
        authority_key_epoch: 3,
        debtor_id: DEBTOR_ID.to_owned(),
        debtor_key: debtor.public_key(),
        debtor_key_epoch: 5,
        creditor_id: CREDITOR_ID.to_owned(),
        creditor_key: creditor.public_key(),
        creditor_key_epoch: 7,
        max_lifetime_ms: 100,
    }
}

fn fixture() -> Result<Fixture, CreditFacilityBindError> {
    let authority = Keypair::from_seed(&[21; 32]);
    let debtor = Keypair::from_seed(&[22; 32]);
    let creditor = Keypair::from_seed(&[23; 32]);
    let signed = SignedCreditFacilityBindV1::sign(
        CreditFacilityBindBodyV1::new(input())?,
        &authority,
        &debtor,
        &creditor,
    )?;
    let trust = CreditFacilityBindTrustV1::new(trust_input(&authority, &debtor, &creditor))?;
    Ok(Fixture {
        authority,
        debtor,
        creditor,
        signed,
        trust,
    })
}

fn verify(
    bytes: &[u8],
    trust: &CreditFacilityBindTrustV1,
    trusted_at_unix_ms: u64,
) -> Result<VerifiedCreditFacilityBindV1, CreditFacilityBindError> {
    verify_credit_facility_bind(
        bytes,
        &CreditFacilityBindVerificationContextV1 {
            trust,
            trusted_at_unix_ms,
        },
    )
}

fn validate_schema(artifact: &impl serde::Serialize) -> TestResult {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-economy/credit-facility-bind.v1.json");
    let schema = chio_spec_validate::load_json(&path)?;
    chio_spec_validate::validate_value(
        &path,
        &schema,
        &std::path::PathBuf::from("<credit-facility-bind>"),
        &serde_json::to_value(artifact)?,
    )?;
    Ok(())
}

fn substituted_bytes(
    bytes: &[u8],
    pointer: &str,
    replacement: serde_json::Value,
) -> TestResult<Vec<u8>> {
    let mut value: serde_json::Value = serde_json::from_slice(bytes)?;
    let Some(target) = value.pointer_mut(pointer) else {
        return Err(format!("missing JSON pointer {pointer}").into());
    };
    *target = replacement;
    Ok(canonical_json_bytes(&value)?)
}

#[derive(Clone, Copy, Debug)]
enum Role {
    Authority,
    Debtor,
    Creditor,
}

#[test]
fn facility_bind_round_trips_and_verifies_exact_terms() -> TestResult {
    let fixture = fixture()?;
    let canonical = fixture.signed.canonical_bytes()?;
    validate_schema(&fixture.signed)?;
    let parsed = SignedCreditFacilityBindV1::from_canonical_bytes(&canonical)?;
    assert_eq!(parsed, fixture.signed);
    assert_eq!(parsed.canonical_bytes()?, canonical);

    let verified = verify(&canonical, &fixture.trust, ISSUED_AT_UNIX_MS)?;
    let body = verified.body();
    assert_eq!(verified.canonical_bytes(), canonical);
    assert_eq!(verified.artifact_digest(), sha256_hex(&canonical));
    assert_eq!(verified.body_digest(), body.body_digest()?);
    assert_eq!(
        verified.trust_configuration_digest(),
        fixture.trust.configuration_digest()
    );
    assert_ne!(
        verified.authority_signature_digest(),
        verified.debtor_signature_digest()
    );
    assert_ne!(
        verified.authority_signature_digest(),
        verified.creditor_signature_digest()
    );
    assert_ne!(
        verified.debtor_signature_digest(),
        verified.creditor_signature_digest()
    );
    assert_eq!(body.operation_id(), digest("operation"));
    assert_eq!(body.request_id(), "request-1");
    assert_eq!(body.economic_intent_digest(), digest("economic-intent"));
    assert_eq!(body.facility_id(), "facility:working-capital");
    assert_eq!(body.facility_artifact_digest(), digest("facility-artifact"));
    assert_eq!(body.authority_set_digest(), digest("credit-authority-set"));
    assert_eq!(body.debtor_id(), DEBTOR_ID);
    assert_eq!(body.original_creditor_id(), CREDITOR_ID);
    assert_eq!(body.original_settlement_destination_ref(), DESTINATION);
    assert_eq!(body.amount().units, 1_250);
    assert_eq!(body.amount().currency, "USD");
    assert_eq!(body.effective_ceiling().units, 5_000);
    assert_eq!(body.expected_exposure_version(), 9);
    assert_eq!(body.expected_exposure_fence(), 11);
    assert_eq!(body.due_at_unix_ms(), DUE_AT_UNIX_MS);
    assert_eq!(body.issued_at_unix_ms(), ISSUED_AT_UNIX_MS);
    assert_eq!(body.expires_at_unix_ms(), EXPIRES_AT_UNIX_MS);
    assert_eq!(body.authority_id(), AUTHORITY_ID);
    assert_eq!(body.authority_key_epoch(), 3);
    assert_eq!(body.debtor_key_epoch(), 5);
    assert_eq!(body.creditor_key_epoch(), 7);
    assert_eq!(
        body.scope_digest(),
        credit_facility_scope_digest(
            DEBTOR_ID,
            "capability:metered-tool",
            "research-server",
            "search",
            "USD",
        )?
    );
    assert_eq!(
        CreditFacilityBindTrustV1::new(trust_input(
            &fixture.authority,
            &fixture.debtor,
            &fixture.creditor,
        ))?
        .configuration_digest(),
        fixture.trust.configuration_digest()
    );
    Ok(())
}

#[test]
fn facility_bind_rejects_noncanonical_unknown_and_semantically_substituted_bytes() -> TestResult {
    let fixture = fixture()?;
    let canonical = fixture.signed.canonical_bytes()?;
    let noncanonical = serde_json::to_vec_pretty(&fixture.signed)?;
    assert!(matches!(
        SignedCreditFacilityBindV1::from_canonical_bytes(&noncanonical),
        Err(CreditFacilityBindError::Canonicalization(_))
    ));
    assert!(matches!(
        verify(&noncanonical, &fixture.trust, ISSUED_AT_UNIX_MS),
        Err(CreditFacilityBindError::Canonicalization(_))
    ));

    let unknown = substituted_bytes(
        &canonical,
        "/body/schema",
        serde_json::json!("chio.credit.facility-bind.v9"),
    )?;
    assert_eq!(
        SignedCreditFacilityBindV1::from_canonical_bytes(&unknown),
        Err(CreditFacilityBindError::InvalidField("schema"))
    );

    for (pointer, replacement) in [
        (
            "/body/operationId",
            serde_json::json!(digest("other-operation")),
        ),
        ("/body/requestId", serde_json::json!("request-2")),
        (
            "/body/economicIntentDigest",
            serde_json::json!(digest("other-intent")),
        ),
        ("/body/facilityId", serde_json::json!("facility:other")),
        (
            "/body/facilityArtifactDigest",
            serde_json::json!(digest("other-facility-artifact")),
        ),
        (
            "/body/authoritySetDigest",
            serde_json::json!(digest("other-authority-set")),
        ),
        ("/body/debtorId", serde_json::json!("did:chio:other-debtor")),
        (
            "/body/originalCreditorId",
            serde_json::json!("did:chio:other-creditor"),
        ),
        (
            "/body/originalSettlementDestinationRef",
            serde_json::json!("acct:other-creditor"),
        ),
        (
            "/body/payeeBindingDigest",
            serde_json::json!(digest("other-payee")),
        ),
        ("/body/amount/units", serde_json::json!(1_251)),
        ("/body/amount/currency", serde_json::json!("EUR")),
        ("/body/effectiveCeiling/units", serde_json::json!(5_001)),
        ("/body/dueAtUnixMs", serde_json::json!(DUE_AT_UNIX_MS + 1)),
        (
            "/body/scopeDigest",
            serde_json::json!(digest("other-scope")),
        ),
        (
            "/body/capabilityId",
            serde_json::json!("capability:other-tool"),
        ),
        ("/body/toolServer", serde_json::json!("other-server")),
        ("/body/toolName", serde_json::json!("other-tool")),
        ("/body/authorityId", serde_json::json!("other-authority")),
        ("/body/actionNonce", serde_json::json!("other-nonce")),
        ("/body/expectedExposureVersion", serde_json::json!(10)),
        ("/body/expectedExposureFence", serde_json::json!(10)),
    ] {
        let substituted = substituted_bytes(&canonical, pointer, replacement)?;
        assert!(
            verify(&substituted, &fixture.trust, ISSUED_AT_UNIX_MS).is_err(),
            "substitution at {pointer} was accepted"
        );
    }
    Ok(())
}

#[test]
fn facility_bind_requires_each_configured_role_key_epoch_and_signature() -> TestResult {
    let fixture = fixture()?;
    let canonical = fixture.signed.canonical_bytes()?;
    let rogue = Keypair::from_seed(&[24; 32]);

    for role in [Role::Authority, Role::Debtor, Role::Creditor] {
        let forged = match role {
            Role::Authority => SignedCreditFacilityBindV1::sign(
                fixture.signed.body().clone(),
                &rogue,
                &fixture.debtor,
                &fixture.creditor,
            )?,
            Role::Debtor => SignedCreditFacilityBindV1::sign(
                fixture.signed.body().clone(),
                &fixture.authority,
                &rogue,
                &fixture.creditor,
            )?,
            Role::Creditor => SignedCreditFacilityBindV1::sign(
                fixture.signed.body().clone(),
                &fixture.authority,
                &fixture.debtor,
                &rogue,
            )?,
        };
        assert_eq!(
            verify(
                &forged.canonical_bytes()?,
                &fixture.trust,
                ISSUED_AT_UNIX_MS,
            ),
            Err(CreditFacilityBindError::SignatureVerification),
            "forged {role:?} key was accepted"
        );

        let mut wrong_key = trust_input(&fixture.authority, &fixture.debtor, &fixture.creditor);
        let mut wrong_epoch = trust_input(&fixture.authority, &fixture.debtor, &fixture.creditor);
        match role {
            Role::Authority => {
                wrong_key.authority_key = rogue.public_key();
                wrong_epoch.authority_key_epoch += 1;
            }
            Role::Debtor => {
                wrong_key.debtor_key = rogue.public_key();
                wrong_epoch.debtor_key_epoch += 1;
            }
            Role::Creditor => {
                wrong_key.creditor_key = rogue.public_key();
                wrong_epoch.creditor_key_epoch += 1;
            }
        }
        for trust in [
            CreditFacilityBindTrustV1::new(wrong_key)?,
            CreditFacilityBindTrustV1::new(wrong_epoch)?,
        ] {
            assert_eq!(
                verify(&canonical, &trust, ISSUED_AT_UNIX_MS),
                Err(CreditFacilityBindError::SignatureVerification),
                "wrong {role:?} trust was accepted"
            );
        }
    }

    let mut altered_input = input();
    altered_input.request_id = "request-with-other-signatures".to_owned();
    let altered = SignedCreditFacilityBindV1::sign(
        CreditFacilityBindBodyV1::new(altered_input)?,
        &fixture.authority,
        &fixture.debtor,
        &fixture.creditor,
    )?;
    let altered_value = serde_json::to_value(altered)?;
    for signature_field in ["authoritySignature", "debtorSignature", "creditorSignature"] {
        let pointer = format!("/{signature_field}/signature");
        let Some(replacement) = altered_value.pointer(&pointer) else {
            return Err(format!("missing JSON pointer {pointer}").into());
        };
        let substituted = substituted_bytes(&canonical, &pointer, replacement.clone())?;
        assert_eq!(
            verify(&substituted, &fixture.trust, ISSUED_AT_UNIX_MS),
            Err(CreditFacilityBindError::SignatureVerification),
            "wrong {signature_field} was accepted"
        );
    }
    Ok(())
}

#[test]
fn facility_bind_rejects_pairwise_role_aliases_and_signature_slot_swaps() -> TestResult {
    let fixture = fixture()?;
    let body = fixture.signed.body().clone();

    for (authority, debtor, creditor) in [
        (&fixture.authority, &fixture.authority, &fixture.creditor),
        (&fixture.authority, &fixture.debtor, &fixture.authority),
        (&fixture.authority, &fixture.debtor, &fixture.debtor),
    ] {
        assert_eq!(
            SignedCreditFacilityBindV1::sign(body.clone(), authority, debtor, creditor),
            Err(CreditFacilityBindError::InvalidField("signature_roles"))
        );
    }

    let base_trust = trust_input(&fixture.authority, &fixture.debtor, &fixture.creditor);
    for (left, right) in [
        (Role::Authority, Role::Debtor),
        (Role::Authority, Role::Creditor),
        (Role::Debtor, Role::Creditor),
    ] {
        let mut shared_key = base_trust.clone();
        let key = match left {
            Role::Authority => shared_key.authority_key.clone(),
            Role::Debtor => shared_key.debtor_key.clone(),
            Role::Creditor => shared_key.creditor_key.clone(),
        };
        match right {
            Role::Authority => shared_key.authority_key = key,
            Role::Debtor => shared_key.debtor_key = key,
            Role::Creditor => shared_key.creditor_key = key,
        }
        assert_eq!(
            CreditFacilityBindTrustV1::new(shared_key),
            Err(CreditFacilityBindError::InvalidField("trusted_roles"))
        );

        let mut shared_id = base_trust.clone();
        let id = match left {
            Role::Authority => shared_id.authority_id.clone(),
            Role::Debtor => shared_id.debtor_id.clone(),
            Role::Creditor => shared_id.creditor_id.clone(),
        };
        match right {
            Role::Authority => shared_id.authority_id = id,
            Role::Debtor => shared_id.debtor_id = id,
            Role::Creditor => shared_id.creditor_id = id,
        }
        assert_eq!(
            CreditFacilityBindTrustV1::new(shared_id),
            Err(CreditFacilityBindError::InvalidField("trusted_roles"))
        );
    }

    let canonical = fixture.signed.canonical_bytes()?;
    for (left, right) in [
        ("authoritySignature", "debtorSignature"),
        ("authoritySignature", "creditorSignature"),
        ("debtorSignature", "creditorSignature"),
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(&canonical)?;
        let left_value = value[left].clone();
        value[left] = value[right].clone();
        value[right] = left_value;
        assert_eq!(
            verify(
                &canonical_json_bytes(&value)?,
                &fixture.trust,
                ISSUED_AT_UNIX_MS,
            ),
            Err(CreditFacilityBindError::SignatureVerification)
        );
    }
    Ok(())
}

#[test]
fn facility_bind_enforces_current_time_and_configured_lifetime() -> TestResult {
    let fixture = fixture()?;
    let canonical = fixture.signed.canonical_bytes()?;
    assert_eq!(
        verify(&canonical, &fixture.trust, ISSUED_AT_UNIX_MS - 1),
        Err(CreditFacilityBindError::NotCurrent)
    );
    assert_eq!(
        verify(&canonical, &fixture.trust, EXPIRES_AT_UNIX_MS),
        Err(CreditFacilityBindError::NotCurrent)
    );
    assert!(verify(&canonical, &fixture.trust, EXPIRES_AT_UNIX_MS - 1).is_ok());

    let mut short_lifetime = trust_input(&fixture.authority, &fixture.debtor, &fixture.creditor);
    short_lifetime.max_lifetime_ms = EXPIRES_AT_UNIX_MS - ISSUED_AT_UNIX_MS - 1;
    let short_lifetime = CreditFacilityBindTrustV1::new(short_lifetime)?;
    assert_eq!(
        verify(&canonical, &short_lifetime, ISSUED_AT_UNIX_MS),
        Err(CreditFacilityBindError::NotCurrent)
    );
    Ok(())
}
