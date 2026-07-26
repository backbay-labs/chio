use super::*;
use chio_core::crypto::Keypair;

const EXTENSION: &[u8] = b"opaque-signed-broker-capability";

type ClaimMutation = fn(&mut VerifiedSupplementalQuotaClaim);
type NamedClaimMutation = (&'static str, ClaimMutation);
type ExpectedClaimMutation = (SupplementalQuotaError, ClaimMutation);

fn key(seed: u8) -> PublicKey {
    Keypair::from_seed(&[seed; 32]).public_key()
}

fn digest(hex_digit: char) -> String {
    hex_digit.to_string().repeat(64)
}

#[derive(Clone)]
struct StubVerifier {
    claim: Result<VerifiedSupplementalQuotaClaim, SupplementalQuotaVerifierError>,
}

impl SupplementalQuotaVerifier for StubVerifier {
    fn verify(
        &self,
        signed_extension: &[u8],
        _context: &SupplementalQuotaVerificationContext,
    ) -> Result<VerifiedSupplementalQuotaClaim, SupplementalQuotaVerifierError> {
        if signed_extension != EXTENSION {
            return Err(SupplementalQuotaVerifierError::new(
                "extension bytes changed",
            ));
        }
        self.claim.clone()
    }
}

fn context() -> SupplementalQuotaVerificationContext {
    let mut negotiated_features = CapabilityNegotiation::v1_default();
    negotiated_features
        .features
        .insert(BROKER_CAPABILITY_EXECUTION_PROFILE.to_string(), true);
    SupplementalQuotaVerificationContext {
        capability_id: "cap-leaf".to_string(),
        capability_digest: digest('1'),
        request_namespace_digest: digest('2'),
        operation_id: digest('3'),
        subject: key(1),
        request_id: "request-7".to_string(),
        normalized_destination: "https://api.example.test:443/v1/run?mode=exact".to_string(),
        arguments_hash: digest('4'),
        negotiated_profile: BROKER_CAPABILITY_EXECUTION_PROFILE.to_string(),
        negotiated_features,
        verifier_binding: SupplementalQuotaVerifierBinding {
            verifier_identity: "chio-secret-broker/verifier.v1".to_string(),
            configuration_digest: digest('5'),
        },
    }
}

fn claim(
    context: &SupplementalQuotaVerificationContext,
) -> Result<VerifiedSupplementalQuotaClaim, SupplementalQuotaError> {
    let supplemental_revocation_ids = vec!["broker-capability-9".to_string()];
    Ok(VerifiedSupplementalQuotaClaim {
        profile: context.negotiated_profile.clone(),
        broker_capability_id: "broker-capability-9".to_string(),
        issuer: key(2),
        request_constraint_digest: digest('6'),
        max_invocations: 12,
        authorization_artifact_digest: supplemental_authorization_artifact_digest(EXTENSION),
        supplemental_revocation_ids,
        expires_at: 200,
        request_binding_hash: supplemental_request_binding_hash(context)?,
        capability_id: context.capability_id.clone(),
        capability_digest: context.capability_digest.clone(),
        request_namespace_digest: context.request_namespace_digest.clone(),
        operation_id: context.operation_id.clone(),
        subject: context.subject.clone(),
        request_id: context.request_id.clone(),
        normalized_destination: context.normalized_destination.clone(),
        arguments_hash: context.arguments_hash.clone(),
        negotiated_features: context.negotiated_features.clone(),
    })
}

fn verifier(claim: VerifiedSupplementalQuotaClaim) -> StubVerifier {
    StubVerifier { claim: Ok(claim) }
}

fn assert_claim_error(
    context: &SupplementalQuotaVerificationContext,
    expected: SupplementalQuotaError,
    mutate: fn(&mut VerifiedSupplementalQuotaClaim),
) -> Result<(), SupplementalQuotaError> {
    let mut mismatched = claim(context)?;
    mutate(&mut mismatched);
    let verifier = verifier(mismatched);
    assert_eq!(
        verify_supplemental_quota(Some(&verifier), EXTENSION, context, 100),
        Err(expected)
    );
    Ok(())
}

#[test]
fn verifies_opaque_artifact_and_derives_request_bound_quota() -> Result<(), SupplementalQuotaError>
{
    let context = context();
    let expected = claim(&context)?;
    let verifier = verifier(expected.clone());

    let verified = verify_supplemental_quota(Some(&verifier), EXTENSION, &context, 100)?;

    assert_eq!(verified.profile(), BROKER_CAPABILITY_EXECUTION_PROFILE);
    assert_eq!(
        verified.owner_id(),
        derive_broker_quota_owner_id(
            "broker-capability-9",
            &key(2),
            &context.normalized_destination,
            &digest('6'),
        )?
    );
    assert_eq!(verified.broker_capability_id(), "broker-capability-9");
    assert_eq!(verified.max_invocations(), 12);
    assert_eq!(
        verified.authorization_artifact_digest(),
        supplemental_authorization_artifact_digest(EXTENSION)
    );
    assert_eq!(verified.expires_at(), 200);
    assert_eq!(verified.capability_id(), context.capability_id.as_str());
    assert_eq!(
        verified.capability_digest(),
        context.capability_digest.as_str()
    );
    assert_eq!(
        verified.request_namespace_digest(),
        context.request_namespace_digest.as_str()
    );
    assert_eq!(verified.operation_id(), context.operation_id.as_str());
    assert_eq!(verified.verifier_binding(), &context.verifier_binding);
    assert_eq!(
        verified.request_binding_hash(),
        expected.request_binding_hash
    );
    Ok(())
}

#[test]
fn missing_and_unknown_verifiers_fail_closed() -> Result<(), SupplementalQuotaError> {
    let context = context();
    assert_eq!(
        verify_supplemental_quota(None, EXTENSION, &context, 100),
        Err(SupplementalQuotaError::MissingVerifier)
    );

    let mut unknown_context = context.clone();
    unknown_context.negotiated_profile = "chio.unknown.v1".to_string();
    let verifier = verifier(claim(&context)?);
    assert_eq!(
        verify_supplemental_quota(Some(&verifier), EXTENSION, &unknown_context, 100),
        Err(SupplementalQuotaError::UnknownProfile(
            "chio.unknown.v1".to_string()
        ))
    );

    let rejecting = StubVerifier {
        claim: Err(SupplementalQuotaVerifierError::new("bad signature")),
    };
    assert!(matches!(
        verify_supplemental_quota(Some(&rejecting), EXTENSION, &context, 100),
        Err(SupplementalQuotaError::VerifierRejected(_))
    ));
    Ok(())
}

#[test]
fn every_echoed_request_field_is_rechecked() -> Result<(), SupplementalQuotaError> {
    let context = context();
    let mutations: &[NamedClaimMutation] = &[
        (
            "capability_id",
            |claim: &mut VerifiedSupplementalQuotaClaim| claim.capability_id.push('x'),
        ),
        ("capability_digest", |claim| {
            claim.capability_digest = digest('a')
        }),
        ("request_namespace_digest", |claim| {
            claim.request_namespace_digest = digest('a');
        }),
        ("operation_id", |claim| claim.operation_id = digest('a')),
        ("subject", |claim| claim.subject = key(9)),
        ("request_id", |claim| claim.request_id.push('x')),
        ("normalized_destination", |claim| {
            claim.normalized_destination.push('x');
        }),
        ("arguments_hash", |claim| claim.arguments_hash = digest('a')),
        ("negotiated_features", |claim| {
            claim.negotiated_features.features.clear();
        }),
    ];
    for &(field, mutate) in mutations {
        assert_claim_error(
            &context,
            SupplementalQuotaError::ContextMismatch(field),
            mutate,
        )?;
    }
    Ok(())
}

#[test]
fn derived_and_cryptographic_bindings_are_rechecked() -> Result<(), SupplementalQuotaError> {
    let context = context();
    let mutations: &[ExpectedClaimMutation] = &[
        (SupplementalQuotaError::ArtifactDigestMismatch, |claim| {
            claim.authorization_artifact_digest = digest('a');
        }),
        (SupplementalQuotaError::RequestBindingMismatch, |claim| {
            claim.request_binding_hash = digest('a');
        }),
        (
            SupplementalQuotaError::EmptyClaimField("broker_capability_id"),
            |claim| claim.broker_capability_id.clear(),
        ),
        (
            SupplementalQuotaError::Expired {
                expires_at: 100,
                now: 100,
            },
            |claim| claim.expires_at = 100,
        ),
        (
            SupplementalQuotaError::UnknownProfile("chio.unknown.v1".to_string()),
            |claim| claim.profile = "chio.unknown.v1".to_string(),
        ),
    ];

    for (expected_error, mutate) in mutations {
        assert_claim_error(&context, expected_error.clone(), *mutate)?;
    }
    Ok(())
}

#[test]
fn namespace_operation_and_verifier_evidence_change_the_request_binding(
) -> Result<(), SupplementalQuotaError> {
    let baseline_context = context();
    let baseline = supplemental_request_binding_hash(&baseline_context)?;

    let mut changed_namespace = baseline_context.clone();
    changed_namespace.request_namespace_digest = digest('a');
    let mut changed_operation = baseline_context.clone();
    changed_operation.operation_id = digest('a');
    let mut changed_identity = baseline_context.clone();
    changed_identity
        .verifier_binding
        .verifier_identity
        .push_str("-other");
    let mut changed_configuration = baseline_context.clone();
    changed_configuration.verifier_binding.configuration_digest = digest('a');

    let baseline_claim = claim(&baseline_context)?;
    for changed in [&changed_identity, &changed_configuration] {
        let verifier = verifier(baseline_claim.clone());
        assert_eq!(
            verify_supplemental_quota(Some(&verifier), EXTENSION, changed, 100),
            Err(SupplementalQuotaError::RequestBindingMismatch)
        );
    }

    for changed in [
        changed_namespace,
        changed_operation,
        changed_identity,
        changed_configuration,
    ] {
        assert_ne!(supplemental_request_binding_hash(&changed)?, baseline);
    }
    Ok(())
}

#[test]
fn verified_claim_cannot_be_rebound_to_another_capability() -> Result<(), SupplementalQuotaError> {
    let context = context();
    let verifier = verifier(claim(&context)?);
    let verified = verify_supplemental_quota(Some(&verifier), EXTENSION, &context, 100)?;
    let ancestors = vec!["cap-parent".to_string(), "cap-root".to_string()];

    let complete = canonical_revocation_set_for_verified_claim("cap-leaf", &ancestors, &verified)?;
    assert_eq!(
        complete.ids().to_vec(),
        vec![
            "broker-capability-9".to_string(),
            "cap-leaf".to_string(),
            "cap-parent".to_string(),
            "cap-root".to_string(),
        ]
    );
    assert_eq!(
        canonical_revocation_set_for_verified_claim("cap-other", &ancestors, &verified),
        Err(SupplementalQuotaError::ContextMismatch("capability_id"))
    );
    Ok(())
}

#[test]
fn canonical_revocation_set_rejects_duplicates_and_noncanonical_input() {
    let duplicate = CanonicalRevocationSet::canonicalize(vec![
        "cap-leaf".to_string(),
        "cap-root".to_string(),
        "cap-root".to_string(),
    ]);
    assert_eq!(
        duplicate,
        Err(SupplementalQuotaError::DuplicateRevocationId(
            "cap-root".to_string()
        ))
    );

    assert_eq!(
        validate_canonical_revocation_ids(&["z".to_string(), "a".to_string()]),
        Err(SupplementalQuotaError::RevocationIdsNotCanonical)
    );
    assert_eq!(
        CanonicalRevocationSet::canonicalize(Vec::new()),
        Err(SupplementalQuotaError::EmptyRevocationSet)
    );
}

#[test]
fn canonical_revocation_set_uses_utf8_byte_order_and_checked_parts(
) -> Result<(), SupplementalQuotaError> {
    let canonical = CanonicalRevocationSet::canonicalize(vec![
        "\u{1f600}".to_string(),
        "\u{e000}".to_string(),
        "ascii".to_string(),
    ])?;
    assert_eq!(
        canonical.ids().to_vec(),
        vec![
            "ascii".to_string(),
            "\u{e000}".to_string(),
            "\u{1f600}".to_string(),
        ]
    );
    assert_eq!(
        CanonicalRevocationSet::from_canonical_parts(
            canonical.ids().to_vec(),
            canonical.digest().to_string(),
        )?,
        canonical
    );

    let mut noncanonical = canonical.ids().to_vec();
    noncanonical.swap(0, 1);
    assert_eq!(
        CanonicalRevocationSet::from_canonical_parts(noncanonical, canonical.digest().to_string(),),
        Err(SupplementalQuotaError::RevocationIdsNotCanonical)
    );
    assert_eq!(
        CanonicalRevocationSet::from_canonical_parts(canonical.ids().to_vec(), digest('a')),
        Err(SupplementalQuotaError::RevocationDigestMismatch)
    );
    Ok(())
}

#[test]
fn trust_boundary_limits_and_revocation_policy_fail_closed() -> Result<(), SupplementalQuotaError> {
    let context = context();
    let valid_verifier = verifier(claim(&context)?);
    let oversized = vec![0; MAX_SUPPLEMENTAL_AUTHORIZATION_BYTES + 1];
    assert!(matches!(
        verify_supplemental_quota(Some(&valid_verifier), &oversized, &context, 100),
        Err(SupplementalQuotaError::LimitExceeded {
            field: "signed_extension",
            ..
        })
    ));

    let mut deny_all = claim(&context)?;
    deny_all.max_invocations = 0;
    let deny_verifier = verifier(deny_all);
    let verified = verify_supplemental_quota(Some(&deny_verifier), EXTENSION, &context, 100)?;
    assert_eq!(verified.max_invocations(), 0);

    let mut no_revocation = claim(&context)?;
    no_revocation.supplemental_revocation_ids.clear();
    let no_revocation_verifier = verifier(no_revocation);
    assert_eq!(
        verify_supplemental_quota(Some(&no_revocation_verifier), EXTENSION, &context, 100,),
        Err(SupplementalQuotaError::EmptySupplementalRevocationIds)
    );

    let mut too_many = claim(&context)?;
    too_many.supplemental_revocation_ids = (0..=MAX_SUPPLEMENTAL_REVOCATION_IDS)
        .map(|index| format!("revocation-{index:03}"))
        .collect();
    let too_many_verifier = verifier(too_many);
    assert!(matches!(
        verify_supplemental_quota(Some(&too_many_verifier), EXTENSION, &context, 100),
        Err(SupplementalQuotaError::LimitExceeded {
            field: "supplemental_revocation_ids",
            ..
        })
    ));

    let too_many_ids = (0..=MAX_ADMISSION_REVOCATION_IDS)
        .map(|index| format!("ancestor-{index:03}"))
        .collect::<Vec<_>>();
    assert!(matches!(
        CanonicalRevocationSet::canonicalize(too_many_ids),
        Err(SupplementalQuotaError::LimitExceeded {
            field: "admission_revocation_ids",
            ..
        })
    ));

    let mut oversized_context = context.clone();
    oversized_context.capability_id = "x".repeat(MAX_SUPPLEMENTAL_CONTEXT_FIELD_BYTES + 1);
    assert!(matches!(
        verify_supplemental_quota(Some(&valid_verifier), EXTENSION, &oversized_context, 100),
        Err(SupplementalQuotaError::LimitExceeded {
            field: "capability_id",
            ..
        })
    ));

    let mut invalid_digest_context = context.clone();
    invalid_digest_context.arguments_hash = "A".repeat(64);
    assert_eq!(
        verify_supplemental_quota(
            Some(&valid_verifier),
            EXTENSION,
            &invalid_digest_context,
            100,
        ),
        Err(SupplementalQuotaError::InvalidSha256Digest(
            "arguments_hash"
        ))
    );

    let mut too_many_features_context = context.clone();
    for index in 0..MAX_SUPPLEMENTAL_NEGOTIATED_FEATURES {
        too_many_features_context
            .negotiated_features
            .features
            .insert(format!("extra_feature_{index}"), true);
    }
    assert!(matches!(
        verify_supplemental_quota(
            Some(&valid_verifier),
            EXTENSION,
            &too_many_features_context,
            100,
        ),
        Err(SupplementalQuotaError::LimitExceeded {
            field: "negotiated_features",
            ..
        })
    ));

    let mut oversized_revocation_id = claim(&context)?;
    oversized_revocation_id.supplemental_revocation_ids =
        vec!["r".repeat(MAX_SUPPLEMENTAL_REVOCATION_ID_BYTES + 1)];
    let oversized_revocation_verifier = verifier(oversized_revocation_id);
    assert!(matches!(
        verify_supplemental_quota(
            Some(&oversized_revocation_verifier),
            EXTENSION,
            &context,
            100,
        ),
        Err(SupplementalQuotaError::LimitExceeded {
            field: "supplemental_revocation_id",
            ..
        })
    ));
    Ok(())
}

#[test]
fn capture_recheck_rejects_omission_addition_and_mutation() -> Result<(), SupplementalQuotaError> {
    let expected = CanonicalRevocationSet::canonicalize(vec![
        "cap-leaf".to_string(),
        "cap-root".to_string(),
        "cap-parent".to_string(),
        "broker-capability-9".to_string(),
    ])?;
    expected.verify_exact(expected.ids(), expected.digest())?;

    let omitted = expected
        .ids()
        .iter()
        .filter(|id| id.as_str() != "cap-parent")
        .cloned()
        .collect::<Vec<_>>();
    let omitted_digest = domain_separated_digest(ADMISSION_REVOCATION_SET_DOMAIN, &omitted)?;
    assert_eq!(
        expected.verify_exact(&omitted, &omitted_digest),
        Err(SupplementalQuotaError::RevocationSetMismatch)
    );

    let mut added = expected.ids().to_vec();
    added.push("supplemental-z".to_string());
    let added_digest = domain_separated_digest(ADMISSION_REVOCATION_SET_DOMAIN, &added)?;
    assert_eq!(
        expected.verify_exact(&added, &added_digest),
        Err(SupplementalQuotaError::RevocationSetMismatch)
    );

    let mut mutated = expected.ids().to_vec();
    mutated[0].push('x');
    mutated.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    assert_eq!(
        expected.verify_exact(&mutated, expected.digest()),
        Err(SupplementalQuotaError::RevocationDigestMismatch)
    );
    Ok(())
}

#[test]
fn changing_any_owner_component_changes_the_derived_id() -> Result<(), SupplementalQuotaError> {
    let issuer = key(2);
    let baseline = derive_broker_quota_owner_id(
        "broker-capability",
        &issuer,
        "https://api.example.test:443/v1/run",
        "constraint-digest",
    )?;
    for changed in [
        derive_broker_quota_owner_id(
            "other-capability",
            &issuer,
            "https://api.example.test:443/v1/run",
            "constraint-digest",
        )?,
        derive_broker_quota_owner_id(
            "broker-capability",
            &key(3),
            "https://api.example.test:443/v1/run",
            "constraint-digest",
        )?,
        derive_broker_quota_owner_id(
            "broker-capability",
            &issuer,
            "https://other.example.test:443/v1/run",
            "constraint-digest",
        )?,
        derive_broker_quota_owner_id(
            "broker-capability",
            &issuer,
            "https://api.example.test:443/v1/run",
            "other-constraint",
        )?,
    ] {
        assert_ne!(changed, baseline);
    }
    Ok(())
}

#[test]
fn canonical_hash_vectors_are_stable() -> Result<(), Box<dyn std::error::Error>> {
    let mut vector_context = context();
    vector_context.capability_id = "cap-vector".to_string();
    vector_context.subject =
        PublicKey::from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")?;
    vector_context.request_id = "request-vector".to_string();

    assert_eq!(
        supplemental_request_binding_hash(&vector_context)?,
        "1b1987d7de992ce3333df06f1ba985500b9d25dac2e80faed071907900cf9c22"
    );
    assert_eq!(
        derive_broker_quota_owner_id(
            "broker-vector",
            &vector_context.subject,
            &vector_context.normalized_destination,
            &digest('6'),
        )?,
        "978c0098aaae831c9a9b03709bd8ca53c4bf16e78d29f57a093c6196554be758"
    );
    assert_eq!(
        CanonicalRevocationSet::canonicalize(vec![
            "cap-vector".to_string(),
            "ancestor-vector".to_string(),
            "broker-vector".to_string(),
        ])?
        .digest(),
        "f3dc8e99b98d7bfe2816b647861bad5f61cf62a73b320d9fb917e5bf23146914"
    );
    assert_eq!(
        supplemental_authorization_artifact_digest(EXTENSION),
        "2fc7ae5360b28c4d44c0f80584872794ae5519fda8abc5921c32ec8166638360"
    );
    Ok(())
}
