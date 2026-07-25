#![forbid(clippy::unwrap_used, clippy::expect_used)]

use chio_core::Keypair;
use chio_credentials::{
    build_agent_passport_v2, create_passport_presentation_challenge_v2,
    decode_versioned_agent_passport, inspect_agent_passport_v2,
    inspect_passport_presentation_challenge_v2, inspect_passport_presentation_response_v2,
    inspect_passport_source_manifest_v2_signature, inspect_presented_agent_passport_v2,
    issue_financial_credential, issue_passport_source_manifest_v2, issue_reputation_credential,
    respond_to_passport_presentation_challenge_v2, try_downgrade_v2_passport, upgrade_v1_passport,
    AgentPassport, AgentPassportV2, AttestationWindow, ChioCredentialEvidence, CredentialError,
    CredentialProof, CreditScorecardConfidenceV1, CreditScorecardCredentialSubjectV1,
    CreditScorecardImportedSignalContextV1, CreditScorecardRiskBandV1,
    ExposureHistoryCredentialSubjectV1, ExposureHistoryPositionV1, FinancialCredentialEnvelope,
    FinancialCredentialEvidenceV1, FinancialCredentialFamilyV1, FinancialCredentialSubjectV1,
    FinancialCredentialWindowV1, FinancialSourceDisclosureV1, LossHistoryCredentialSubjectV1,
    OfflinePassportPresentationChallengeUseStoreV2, PassportCredentialV2, PassportValidityWindowV2,
    PremiumHistoryCredentialSubjectV1, SettlementReliabilityCredentialSubjectV1,
    SignedPassportPresentationChallengeV2, SignedPassportSourceManifestV2, TrustTier,
    VersionedAgentPassport, FINANCIAL_AGENT_PASSPORT_SCHEMA_V1,
};
use chio_did::DidChio;
use chio_reputation::{
    BoundaryPressureMetrics, DelegationHygieneMetrics, HistoryDepthMetrics,
    IncidentCorrelationMetrics, LeastPrivilegeMetrics, LocalReputationScorecard, MetricValue,
    ReliabilityMetrics, ResourceStewardshipMetrics, SpecializationMetrics,
};

const ISSUED_AT: u64 = 1_710_000_000;
const EXPIRES_AT: u64 = ISSUED_AT + 86_400;

const fn validity(issued_at: u64, expires_at: u64) -> PassportValidityWindowV2 {
    PassportValidityWindowV2 {
        issued_at,
        expires_at,
    }
}

trait TestResultExt<T, E> {
    fn test_ok(self, context: &str) -> T;
}

impl<T, E> TestResultExt<T, E> for Result<T, E>
where
    E: std::fmt::Display,
{
    fn test_ok(self, context: &str) -> T {
        match self {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error}"),
        }
    }
}

fn did(keypair: &Keypair) -> String {
    DidChio::from_public_key(keypair.public_key())
        .test_ok("derive DID")
        .to_string()
}

fn validate_schema(
    name: &str,
    artifact: &impl serde::Serialize,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-trust/v1")
        .join(name);
    let schema = chio_spec_validate::load_json(&path)?;
    let value = serde_json::to_value(artifact)?;
    chio_spec_validate::validate_value(
        &path,
        &schema,
        &std::path::PathBuf::from("<financial-passport-v2>"),
        &value,
    )?;
    Ok(())
}

fn scorecard(subject_key: &str) -> LocalReputationScorecard {
    LocalReputationScorecard {
        subject_key: subject_key.to_string(),
        computed_at: ISSUED_AT,
        boundary_pressure: BoundaryPressureMetrics {
            deny_ratio: MetricValue::Known(0.1),
            policies_observed: 1,
            receipts_observed: 3,
        },
        resource_stewardship: ResourceStewardshipMetrics {
            average_utilization: MetricValue::Known(0.6),
            fit_score: MetricValue::Known(0.9),
            capped_grants_observed: 1,
        },
        least_privilege: LeastPrivilegeMetrics {
            score: MetricValue::Known(0.8),
            capabilities_observed: 1,
        },
        history_depth: HistoryDepthMetrics {
            score: MetricValue::Known(0.7),
            receipt_count: 3,
            active_days: 3,
            first_seen: Some(ISSUED_AT - 100),
            last_seen: Some(ISSUED_AT),
            span_days: 3,
            activity_ratio: MetricValue::Known(1.0),
        },
        specialization: SpecializationMetrics {
            score: MetricValue::Known(0.5),
            distinct_tools: 2,
        },
        delegation_hygiene: DelegationHygieneMetrics {
            score: MetricValue::Known(0.9),
            delegations_observed: 1,
            scope_reduction_rate: MetricValue::Known(1.0),
            ttl_reduction_rate: MetricValue::Known(1.0),
            budget_reduction_rate: MetricValue::Known(1.0),
        },
        reliability: ReliabilityMetrics {
            score: MetricValue::Known(0.95),
            completion_rate: MetricValue::Known(1.0),
            cancellation_rate: MetricValue::Known(0.0),
            incompletion_rate: MetricValue::Known(0.0),
            receipts_observed: 3,
        },
        incident_correlation: IncidentCorrelationMetrics {
            score: MetricValue::Unknown,
            incidents_observed: None,
        },
        composite_score: MetricValue::Known(0.82),
        effective_weight_sum: 0.9,
    }
}

fn reputation_credential(issuer: &Keypair, holder: &Keypair) -> PassportCredentialV2 {
    reputation_credential_with_composite(issuer, holder, 0.82)
}

fn reputation_credential_with_composite(
    issuer: &Keypair,
    holder: &Keypair,
    composite: f64,
) -> PassportCredentialV2 {
    let mut scorecard = scorecard(&holder.public_key().to_hex());
    scorecard.composite_score = MetricValue::Known(composite);
    PassportCredentialV2::Reputation(Box::new(
        issue_reputation_credential(
            issuer,
            scorecard,
            ChioCredentialEvidence {
                query: AttestationWindow {
                    since: Some(ISSUED_AT - 100),
                    until: ISSUED_AT,
                },
                receipt_count: 3,
                receipt_ids: vec!["r1".to_string(), "r2".to_string(), "r3".to_string()],
                checkpoint_roots: vec!["root".to_string()],
                receipt_log_urls: Vec::new(),
                lineage_records: 1,
                uncheckpointed_receipts: 0,
                runtime_attestation: None,
            },
            ISSUED_AT,
            EXPIRES_AT,
        )
        .test_ok("issue reputation credential"),
    ))
}

fn reputation_credential_at(
    issuer: &Keypair,
    holder: &Keypair,
    issued_at: u64,
    expires_at: u64,
) -> PassportCredentialV2 {
    PassportCredentialV2::Reputation(Box::new(
        issue_reputation_credential(
            issuer,
            scorecard(&holder.public_key().to_hex()),
            ChioCredentialEvidence {
                query: AttestationWindow {
                    since: Some(ISSUED_AT - 100),
                    until: ISSUED_AT,
                },
                receipt_count: 3,
                receipt_ids: vec!["r1".to_string(), "r2".to_string(), "r3".to_string()],
                checkpoint_roots: vec!["root".to_string()],
                receipt_log_urls: Vec::new(),
                lineage_records: 1,
                uncheckpointed_receipts: 0,
                runtime_attestation: None,
            },
            issued_at,
            expires_at,
        )
        .test_ok("issue dated reputation credential"),
    ))
}

fn passport_v1(holder: &Keypair) -> AgentPassport {
    AgentPassport {
        schema: "chio.agent-passport.v1".to_string(),
        subject: did(holder),
        credentials: Vec::new(),
        merkle_roots: vec!["root".to_string()],
        enterprise_identity_provenance: Vec::new(),
        issued_at: "2024-03-09T16:00:00Z".to_string(),
        valid_until: "2024-03-10T16:00:00Z".to_string(),
        trust_tier: None,
    }
}

fn valid_passport_v1(issuer: &Keypair, holder: &Keypair) -> AgentPassport {
    let credential = match reputation_credential(issuer, holder) {
        PassportCredentialV2::Reputation(credential) => *credential,
        PassportCredentialV2::Financial(_) => unreachable!("reputation fixture is typed"),
    };
    AgentPassport {
        schema: "chio.agent-passport.v1".to_string(),
        subject: did(holder),
        credentials: vec![credential],
        merkle_roots: vec!["root".to_string()],
        enterprise_identity_provenance: Vec::new(),
        issued_at: "2024-03-09T16:00:00Z".to_string(),
        valid_until: "2024-03-10T16:00:00Z".to_string(),
        trust_tier: None,
    }
}

fn synthetic_financial_credential(
    subject: FinancialCredentialSubjectV1,
) -> FinancialCredentialEnvelope {
    let family = subject.family();
    let issuer = did(&Keypair::from_seed(&[31; 32]));
    FinancialCredentialEnvelope {
        schema: family.schema().to_string(),
        family,
        credential_id: "00".repeat(32),
        context: vec![
            "https://www.w3.org/2018/credentials/v1".to_string(),
            "https://chio.world/credentials/v1".to_string(),
        ],
        credential_type: vec![
            "VerifiableCredential".to_string(),
            family.credential_type().to_string(),
        ],
        issuer: issuer.clone(),
        issuer_key_epoch: 1,
        issuance_date: "2024-03-09T16:00:00Z".to_string(),
        expiration_date: "2024-03-10T16:00:00Z".to_string(),
        credential_subject: subject,
        evidence: FinancialCredentialEvidenceV1 {
            window: FinancialCredentialWindowV1 {
                starts_at: ISSUED_AT - 100,
                ends_at: ISSUED_AT,
            },
            source_disclosure: FinancialSourceDisclosureV1::Bundled {
                artifacts: Vec::new(),
            },
            source_completeness_attestations: Vec::new(),
        },
        source_evidence_class: chio_core::capability::governance::ProvenanceEvidenceClass::Asserted,
        presentation_evidence_class:
            chio_core::capability::governance::ProvenanceEvidenceClass::Asserted,
        proof: CredentialProof {
            proof_type: "Ed25519Signature2020".to_string(),
            created: "2024-03-09T16:00:00Z".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            verification_method: format!("{issuer}#key-1"),
            proof_value: "00".repeat(64),
        },
    }
}

fn money(units: u64) -> chio_core::capability::scope::MonetaryAmount {
    chio_core::capability::scope::MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
}

fn financial_subjects() -> Vec<FinancialCredentialSubjectV1> {
    let id = did(&Keypair::from_seed(&[7; 32]));
    vec![
        FinancialCredentialSubjectV1::CreditScorecard(CreditScorecardCredentialSubjectV1 {
            id: id.clone(),
            band: CreditScorecardRiskBandV1::Prime,
            confidence: CreditScorecardConfidenceV1::High,
            overall_score: 0.9,
            probationary: false,
            imported_signals: CreditScorecardImportedSignalContextV1 {
                imported_signal_count: 0,
                accepted_imported_signal_count: 0,
            },
        }),
        FinancialCredentialSubjectV1::ExposureHistory(ExposureHistoryCredentialSubjectV1 {
            id: id.clone(),
            positions: vec![ExposureHistoryPositionV1 {
                governed_max: money(10),
                reserved: money(2),
                settled: money(7),
                pending: money(1),
                failed: money(0),
                provisional_loss: money(0),
                recovered: money(0),
            }],
        }),
        FinancialCredentialSubjectV1::SettlementReliability(
            SettlementReliabilityCredentialSubjectV1 {
                id: id.clone(),
                on_time_count: 2,
                obligation_count: 3,
                on_time_ratio_bps: 6_666,
            },
        ),
        FinancialCredentialSubjectV1::PremiumHistory(PremiumHistoryCredentialSubjectV1 {
            id: id.clone(),
            quoted_count: 1,
            quoted_amounts: vec![money(1)],
        }),
        FinancialCredentialSubjectV1::LossHistory(LossHistoryCredentialSubjectV1 {
            id,
            delinquency_count: 1,
            recovery_count: 0,
            reserve_release_count: 0,
            reserve_slash_count: 0,
            write_off_count: 0,
            outstanding_amounts: vec![money(1)],
        }),
    ]
}

#[test]
fn financial_subjects_are_typed_strict_and_raw_issuance_is_not_an_api() {
    let expected = [
        FinancialCredentialFamilyV1::CreditScorecard,
        FinancialCredentialFamilyV1::ExposureHistory,
        FinancialCredentialFamilyV1::SettlementReliability,
        FinancialCredentialFamilyV1::PremiumHistory,
        FinancialCredentialFamilyV1::LossHistory,
    ];
    for (subject, family) in financial_subjects().into_iter().zip(expected) {
        assert_eq!(subject.family(), family);
        let mut value = serde_json::to_value(&subject).test_ok("serialize subject");
        value["claims"]["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<FinancialCredentialSubjectV1>(value).is_err());
    }

    let _: fn(
        &Keypair,
        u64,
        chio_credit::financial_credentials::VerifiedFinancialCredentialIssuanceV1,
        u64,
        u64,
    ) -> Result<FinancialCredentialEnvelope, CredentialError> = issue_financial_credential;
}

#[test]
fn financial_decode_rejects_unknown_schema_wrong_family_and_disabled_reliability() {
    let mut subjects = financial_subjects().into_iter();
    let credit = synthetic_financial_credential(
        subjects
            .next()
            .unwrap_or_else(|| panic!("credit fixture is present")),
    );
    let mut unknown = serde_json::to_value(&credit).test_ok("serialize unknown-schema fixture");
    unknown["schema"] = serde_json::json!("chio.fincred.unknown.v1");
    let unknown = serde_json::to_vec(&unknown).test_ok("encode unknown-schema fixture");
    assert!(matches!(
        chio_credentials::decode_financial_credential(&unknown),
        Err(CredentialError::UnsupportedFinancialCredentialSchema(schema))
            if schema == "chio.fincred.unknown.v1"
    ));

    let mut wrong_family = serde_json::to_value(&credit).test_ok("serialize wrong-family fixture");
    wrong_family["family"] = serde_json::json!("exposure_history");
    let wrong_family = serde_json::to_vec(&wrong_family).test_ok("encode wrong-family fixture");
    assert!(matches!(
        chio_credentials::decode_financial_credential(&wrong_family),
        Err(CredentialError::FinancialCredentialSchemaFamilyMismatch { .. })
    ));

    let reliability = synthetic_financial_credential(
        subjects
            .nth(1)
            .unwrap_or_else(|| panic!("reliability fixture is present")),
    );
    let reliability = serde_json::to_vec(&reliability).test_ok("encode reliability fixture");
    assert!(matches!(
        chio_credentials::decode_financial_credential(&reliability),
        Err(CredentialError::FinancialReliabilityProofSubstrateUnavailable)
    ));
}

#[test]
fn version_dispatch_is_schema_first_and_downgrade_never_drops_v2_state() {
    let holder = Keypair::from_seed(&[9; 32]);
    let v1 = passport_v1(&holder);
    let v2 = upgrade_v1_passport(v1.clone());
    assert_eq!(v2.schema, FINANCIAL_AGENT_PASSPORT_SCHEMA_V1);
    assert_eq!(try_downgrade_v2_passport(v2).test_ok("downgrade"), v1);

    let unknown = br#"{"schema":"chio.agent-passport.v99","credentials":"bad"}"#;
    assert!(matches!(
        decode_versioned_agent_passport(unknown),
        Err(CredentialError::UnsupportedVersionedPassportSchema(schema))
            if schema == "chio.agent-passport.v99"
    ));

    let issuer = Keypair::from_seed(&[10; 32]);
    let credential = reputation_credential(&issuer, &holder);
    let mut v2 = upgrade_v1_passport(v1);
    v2.credentials.push(credential.clone());
    assert_eq!(
        try_downgrade_v2_passport(v2.clone())
            .test_ok("downgrade reputation-only v2")
            .credentials
            .len(),
        1
    );
    let (manifest, _) = issue_passport_source_manifest_v2(
        &issuer,
        &did(&holder),
        &[credential],
        ISSUED_AT,
        EXPIRES_AT,
    )
    .test_ok("issue financial manifest");
    v2.source_manifest = Some(manifest);
    assert!(matches!(
        try_downgrade_v2_passport(v2),
        Err(CredentialError::PassportDowngradeWouldLoseData)
    ));
}

#[test]
fn manifest_caps_expiry_and_rejects_not_yet_valid_credentials() {
    let issuer = Keypair::from_seed(&[11; 32]);
    let holder = Keypair::from_seed(&[12; 32]);
    let credential = reputation_credential(&issuer, &holder);
    let (manifest, _) = issue_passport_source_manifest_v2(
        &issuer,
        &did(&holder),
        std::slice::from_ref(&credential),
        ISSUED_AT,
        EXPIRES_AT + 1_000,
    )
    .test_ok("issue source manifest");
    assert_eq!(manifest.body.expires_at, EXPIRES_AT);
    assert!(matches!(
        inspect_passport_source_manifest_v2_signature(&manifest, EXPIRES_AT + 1),
        Err(CredentialError::CredentialExpired)
    ));
    assert!(matches!(
        issue_passport_source_manifest_v2(
            &issuer,
            &did(&holder),
            &[credential],
            ISSUED_AT - 1,
            EXPIRES_AT,
        ),
        Err(CredentialError::CredentialNotYetValid)
    ));
}

#[test]
fn validated_v2_builder_binds_manifest_credentials_and_schema_first_admission() {
    let issuer = Keypair::from_seed(&[21; 32]);
    let holder = Keypair::from_seed(&[22; 32]);
    let credential = reputation_credential_with_composite(&issuer, &holder, 0.83);
    let (passport, proofs) = build_agent_passport_v2(
        &issuer,
        did(&holder),
        vec![credential],
        vec!["root".to_string()],
        Vec::new(),
        validity(ISSUED_AT, EXPIRES_AT + 1_000),
        None,
    )
    .test_ok("build bound v2 passport");
    assert_eq!(passport.valid_until, "2024-03-10T16:00:00Z");
    assert_eq!(proofs.len(), 1);
    validate_schema("financial-agent-passport.schema.json", &passport)
        .test_ok("validate v2 passport schema");
    inspect_agent_passport_v2(&passport, ISSUED_AT + 1).test_ok("inspect bound passport");
    let encoded = serde_json::to_vec(&passport).test_ok("encode bound passport");
    assert!(matches!(
        decode_versioned_agent_passport(&encoded),
        Ok(VersionedAgentPassport::V2(_))
    ));

    let mut unknown_schema = passport.clone();
    unknown_schema.schema = "chio.agent-passport.v9".to_string();
    let encoded = serde_json::to_vec(&unknown_schema).test_ok("encode unknown schema");
    assert!(matches!(
        decode_versioned_agent_passport(&encoded),
        Err(CredentialError::UnsupportedVersionedPassportSchema(schema))
            if schema == "chio.agent-passport.v9"
    ));

    let mut substituted = passport;
    substituted.credentials[0] = reputation_credential_with_composite(&issuer, &holder, 0.93);
    let encoded = serde_json::to_vec(&substituted).test_ok("encode substituted passport");
    assert!(matches!(
        decode_versioned_agent_passport(&encoded),
        Err(CredentialError::InvalidVersionedPassport(_))
    ));

    let legacy = valid_passport_v1(&issuer, &holder);
    let upgraded = upgrade_v1_passport(legacy.clone());
    validate_schema("financial-agent-passport.schema.json", &upgraded)
        .test_ok("validate lossless upgrade schema");
    let encoded = serde_json::to_vec(&upgraded).test_ok("encode lossless upgrade");
    let mut tampered_upgrade = upgraded.clone();
    match &mut tampered_upgrade.credentials[0] {
        PassportCredentialV2::Reputation(credential) => {
            credential.proof.proof_value = "00".repeat(64);
        }
        PassportCredentialV2::Financial(_) => panic!("legacy upgrade remains reputation-only"),
    }
    let tampered = serde_json::to_vec(&tampered_upgrade).test_ok("encode tampered legacy upgrade");
    assert!(matches!(
        decode_versioned_agent_passport(&tampered),
        Err(CredentialError::InvalidVersionedPassport(_))
    ));
    let decoded = match decode_versioned_agent_passport(&encoded).test_ok("decode lossless upgrade")
    {
        VersionedAgentPassport::V2(passport) => *passport,
        VersionedAgentPassport::V1(_) => {
            panic!("financial schema dispatches to financial passport")
        }
    };
    inspect_agent_passport_v2(&decoded, ISSUED_AT + 1).test_ok("inspect lossless upgrade");
    assert_eq!(
        try_downgrade_v2_passport(decoded).test_ok("downgrade lossless upgrade"),
        legacy
    );

    let financial_without_manifest = AgentPassportV2 {
        schema: FINANCIAL_AGENT_PASSPORT_SCHEMA_V1.to_string(),
        subject: did(&holder),
        credentials: vec![PassportCredentialV2::Financial(Box::new(
            synthetic_financial_credential(
                financial_subjects()
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| panic!("credit fixture is present")),
            ),
        ))],
        merkle_roots: Vec::new(),
        enterprise_identity_provenance: Vec::new(),
        issued_at: "2024-03-09T16:00:00Z".to_string(),
        valid_until: "2024-03-10T16:00:00Z".to_string(),
        trust_tier: None,
        source_manifest: None,
    };
    assert!(matches!(
        inspect_agent_passport_v2(&financial_without_manifest, ISSUED_AT + 1),
        Err(CredentialError::InvalidFinancialCredential(reason))
            if reason.contains("signed source manifest")
    ));
    assert!(validate_schema(
        "financial-agent-passport.schema.json",
        &financial_without_manifest
    )
    .is_err());
}

#[test]
fn upgraded_v2_rejects_a_nested_reputation_credential_before_its_issuance() {
    let issuer = Keypair::from_seed(&[23; 32]);
    let holder = Keypair::from_seed(&[24; 32]);
    let current = reputation_credential_at(&issuer, &holder, ISSUED_AT, EXPIRES_AT);
    let future = reputation_credential_at(&issuer, &holder, ISSUED_AT + 100, EXPIRES_AT + 100);
    let credentials = [current, future]
        .into_iter()
        .map(|credential| match credential {
            PassportCredentialV2::Reputation(credential) => *credential,
            PassportCredentialV2::Financial(_) => unreachable!("reputation fixture is typed"),
        })
        .collect();
    let passport = upgrade_v1_passport(AgentPassport {
        schema: "chio.agent-passport.v1".to_string(),
        subject: did(&holder),
        credentials,
        merkle_roots: vec!["root".to_string()],
        enterprise_identity_provenance: Vec::new(),
        issued_at: "2024-03-09T16:00:00Z".to_string(),
        valid_until: "2024-03-10T16:00:00Z".to_string(),
        trust_tier: None,
    });

    assert!(matches!(
        inspect_agent_passport_v2(&passport, ISSUED_AT + 50),
        Err(CredentialError::CredentialNotYetValid)
    ));
}

#[test]
fn holder_signed_v2_response_is_exactly_selected_and_consumed_once() {
    let issuer = Keypair::from_seed(&[13; 32]);
    let holder = Keypair::from_seed(&[14; 32]);
    let verifier = Keypair::from_seed(&[25; 32]);
    let credential = reputation_credential(&issuer, &holder);
    let (manifest, proofs) = issue_passport_source_manifest_v2(
        &issuer,
        &did(&holder),
        std::slice::from_ref(&credential),
        ISSUED_AT,
        EXPIRES_AT,
    )
    .test_ok("issue source manifest");
    let selector = chio_credentials::PassportCredentialSelectorV2 {
        family: proofs[0].leaf.family.clone(),
        credential_ref_digest: proofs[0].leaf.credential_ref_digest.clone(),
    };
    let challenge = create_passport_presentation_challenge_v2(
        &verifier,
        1,
        "challenge-a",
        "nonce-a",
        manifest.body.source_passport_id.clone(),
        vec![selector],
        validity(ISSUED_AT, ISSUED_AT + 100),
    )
    .test_ok("create challenge");
    let response = respond_to_passport_presentation_challenge_v2(
        &holder,
        manifest.clone(),
        vec![credential.clone()],
        proofs.clone(),
        &challenge,
        ISSUED_AT + 1,
    )
    .test_ok("respond to challenge");
    let changed_time_response = respond_to_passport_presentation_challenge_v2(
        &holder,
        manifest,
        vec![credential],
        proofs,
        &challenge,
        ISSUED_AT + 2,
    )
    .test_ok("respond again to same challenge");
    let mut uses = OfflinePassportPresentationChallengeUseStoreV2::default();
    inspect_passport_presentation_response_v2(&response, &challenge, ISSUED_AT + 1, &mut uses)
        .test_ok("inspect response");
    assert!(matches!(
        inspect_passport_presentation_response_v2(
            &changed_time_response,
            &challenge,
            ISSUED_AT + 2,
            &mut uses,
        ),
        Err(CredentialError::PresentationReplay)
    ));
}

#[test]
fn invalid_holder_signature_does_not_consume_the_challenge() {
    let issuer = Keypair::from_seed(&[15; 32]);
    let holder = Keypair::from_seed(&[16; 32]);
    let verifier = Keypair::from_seed(&[26; 32]);
    let credential = reputation_credential(&issuer, &holder);
    let (manifest, proofs) = issue_passport_source_manifest_v2(
        &issuer,
        &did(&holder),
        std::slice::from_ref(&credential),
        ISSUED_AT,
        EXPIRES_AT,
    )
    .test_ok("issue source manifest");
    let challenge = create_passport_presentation_challenge_v2(
        &verifier,
        1,
        "challenge-b",
        "nonce-b",
        manifest.body.source_passport_id.clone(),
        vec![chio_credentials::PassportCredentialSelectorV2 {
            family: proofs[0].leaf.family.clone(),
            credential_ref_digest: proofs[0].leaf.credential_ref_digest.clone(),
        }],
        validity(ISSUED_AT, ISSUED_AT + 100),
    )
    .test_ok("create challenge");
    let response = respond_to_passport_presentation_challenge_v2(
        &holder,
        manifest,
        vec![credential],
        proofs,
        &challenge,
        ISSUED_AT + 1,
    )
    .test_ok("respond to challenge");
    let mut invalid = response.clone();
    invalid.proof.proof_value = "00".repeat(64);
    let mut uses = OfflinePassportPresentationChallengeUseStoreV2::default();
    assert!(matches!(
        inspect_passport_presentation_response_v2(&invalid, &challenge, ISSUED_AT + 1, &mut uses,),
        Err(CredentialError::InvalidPresentationSignature)
    ));
    inspect_passport_presentation_response_v2(&response, &challenge, ISSUED_AT + 1, &mut uses)
        .test_ok("valid response after invalid response");
}

#[test]
fn presentation_selectors_reject_omission_extra_substitution_and_leaf_mismatch() {
    let issuer = Keypair::from_seed(&[19; 32]);
    let holder = Keypair::from_seed(&[20; 32]);
    let verifier = Keypair::from_seed(&[27; 32]);
    let credentials = vec![
        reputation_credential_with_composite(&issuer, &holder, 0.81),
        reputation_credential_with_composite(&issuer, &holder, 0.91),
    ];
    let (manifest, proofs) = issue_passport_source_manifest_v2(
        &issuer,
        &did(&holder),
        &credentials,
        ISSUED_AT,
        EXPIRES_AT,
    )
    .test_ok("issue two-credential source manifest");
    let selectors = proofs
        .iter()
        .map(|proof| chio_credentials::PassportCredentialSelectorV2 {
            family: proof.leaf.family.clone(),
            credential_ref_digest: proof.leaf.credential_ref_digest.clone(),
        })
        .collect::<Vec<_>>();
    let exact = create_passport_presentation_challenge_v2(
        &verifier,
        1,
        "challenge-exact",
        "nonce-exact",
        manifest.body.source_passport_id.clone(),
        selectors.clone(),
        validity(ISSUED_AT, ISSUED_AT + 100),
    )
    .test_ok("create exact challenge");

    assert!(matches!(
        respond_to_passport_presentation_challenge_v2(
            &holder,
            manifest.clone(),
            vec![credentials[0].clone()],
            proofs.clone(),
            &exact,
            ISSUED_AT + 1,
        ),
        Err(CredentialError::PresentationSelectorMismatch)
    ));

    let one_selector = create_passport_presentation_challenge_v2(
        &verifier,
        1,
        "challenge-extra",
        "nonce-extra",
        manifest.body.source_passport_id.clone(),
        vec![selectors[0].clone()],
        validity(ISSUED_AT, ISSUED_AT + 100),
    )
    .test_ok("create single-selector challenge");
    assert!(matches!(
        respond_to_passport_presentation_challenge_v2(
            &holder,
            manifest.clone(),
            credentials.clone(),
            proofs.clone(),
            &one_selector,
            ISSUED_AT + 1,
        ),
        Err(CredentialError::PresentationSelectorMismatch)
    ));

    let mut substituted_selectors = selectors;
    substituted_selectors[0].credential_ref_digest = "aa".repeat(32);
    let substituted = create_passport_presentation_challenge_v2(
        &verifier,
        1,
        "challenge-substitution",
        "nonce-substitution",
        manifest.body.source_passport_id.clone(),
        substituted_selectors,
        validity(ISSUED_AT, ISSUED_AT + 100),
    )
    .test_ok("create substituted challenge");
    assert!(matches!(
        respond_to_passport_presentation_challenge_v2(
            &holder,
            manifest.clone(),
            credentials.clone(),
            proofs.clone(),
            &substituted,
            ISSUED_AT + 1,
        ),
        Err(CredentialError::PresentationSelectorMismatch)
    ));

    let mut mismatched_proofs = proofs;
    mismatched_proofs[0].leaf.credential_ref_digest = "bb".repeat(32);
    assert!(matches!(
        respond_to_passport_presentation_challenge_v2(
            &holder,
            manifest,
            credentials,
            mismatched_proofs,
            &exact,
            ISSUED_AT + 1,
        ),
        Err(CredentialError::InvalidFinancialCredential(_))
    ));
}

#[test]
fn v2_passport_and_presentation_reject_unknown_fields() {
    let holder = Keypair::from_seed(&[17; 32]);
    let issuer = Keypair::from_seed(&[18; 32]);
    let verifier = Keypair::from_seed(&[28; 32]);
    let credential = reputation_credential(&issuer, &holder);
    let (passport, _) = build_agent_passport_v2(
        &issuer,
        did(&holder),
        vec![credential.clone()],
        vec!["root".to_string()],
        Vec::new(),
        validity(ISSUED_AT, EXPIRES_AT),
        None,
    )
    .test_ok("build v2 passport");
    validate_schema("financial-agent-passport.schema.json", &passport)
        .test_ok("validate v2 passport schema");
    let mut passport = serde_json::to_value(passport).test_ok("serialize v2 passport");
    passport["unknown"] = serde_json::json!(true);
    assert!(validate_schema("financial-agent-passport.schema.json", &passport).is_err());
    assert!(serde_json::from_value::<chio_credentials::AgentPassportV2>(passport).is_err());

    let mut credential_with_unknown =
        serde_json::to_value(&credential).test_ok("serialize credential carrier");
    credential_with_unknown["unknown"] = serde_json::json!(true);
    assert!(
        serde_json::from_value::<chio_credentials::PassportCredentialV2>(credential_with_unknown)
            .is_err()
    );
    let mut nested_credential_with_unknown =
        serde_json::to_value(&credential).test_ok("serialize nested credential");
    nested_credential_with_unknown["credential"]["unknown"] = serde_json::json!(true);
    assert!(
        serde_json::from_value::<chio_credentials::PassportCredentialV2>(
            nested_credential_with_unknown
        )
        .is_err()
    );
    let (manifest, proofs) = issue_passport_source_manifest_v2(
        &issuer,
        &did(&holder),
        std::slice::from_ref(&credential),
        ISSUED_AT,
        EXPIRES_AT,
    )
    .test_ok("issue source manifest");
    let mut manifest_with_unknown =
        serde_json::to_value(&manifest).test_ok("serialize source manifest envelope");
    manifest_with_unknown["unknown"] = serde_json::json!(true);
    assert!(
        serde_json::from_value::<SignedPassportSourceManifestV2>(manifest_with_unknown).is_err()
    );
    let challenge = create_passport_presentation_challenge_v2(
        &verifier,
        1,
        "challenge-c",
        "nonce-c",
        manifest.body.source_passport_id.clone(),
        vec![chio_credentials::PassportCredentialSelectorV2 {
            family: proofs[0].leaf.family.clone(),
            credential_ref_digest: proofs[0].leaf.credential_ref_digest.clone(),
        }],
        validity(ISSUED_AT, ISSUED_AT + 100),
    )
    .test_ok("create challenge");
    let response = respond_to_passport_presentation_challenge_v2(
        &holder,
        manifest,
        vec![credential],
        proofs,
        &challenge,
        ISSUED_AT + 1,
    )
    .test_ok("respond to challenge");
    let mut unknown_schema = response.presentation.clone();
    unknown_schema.schema = "chio.agent-passport.presentation.v9".to_string();
    assert!(matches!(
        inspect_presented_agent_passport_v2(&unknown_schema, &challenge, ISSUED_AT + 1),
        Err(CredentialError::InvalidFinancialCredential(reason))
            if reason.contains("presented passport schema")
    ));
    assert!(validate_schema(
        "presented-financial-agent-passport.schema.json",
        &unknown_schema
    )
    .is_err());
    validate_schema(
        "presented-financial-agent-passport.schema.json",
        &response.presentation,
    )
    .test_ok("validate presented passport schema");
    let mut presentation =
        serde_json::to_value(response.presentation).test_ok("serialize presentation");
    presentation["unknown"] = serde_json::json!(true);
    assert!(validate_schema(
        "presented-financial-agent-passport.schema.json",
        &presentation
    )
    .is_err());
    assert!(
        serde_json::from_value::<chio_credentials::PresentedAgentPassportV2>(presentation).is_err()
    );
}

#[test]
fn signed_v2_challenge_rejects_digest_signature_and_unknown_field_tampering() {
    let issuer = Keypair::from_seed(&[41; 32]);
    let holder = Keypair::from_seed(&[42; 32]);
    let verifier = Keypair::from_seed(&[43; 32]);
    let credential = reputation_credential(&issuer, &holder);
    let (manifest, proofs) = issue_passport_source_manifest_v2(
        &issuer,
        &did(&holder),
        std::slice::from_ref(&credential),
        ISSUED_AT,
        EXPIRES_AT,
    )
    .test_ok("issue source manifest");
    let challenge = create_passport_presentation_challenge_v2(
        &verifier,
        7,
        "challenge-signed",
        "nonce-signed",
        manifest.body.source_passport_id.clone(),
        vec![chio_credentials::PassportCredentialSelectorV2 {
            family: proofs[0].leaf.family.clone(),
            credential_ref_digest: proofs[0].leaf.credential_ref_digest.clone(),
        }],
        validity(ISSUED_AT, ISSUED_AT + 100),
    )
    .test_ok("create signed challenge");
    inspect_passport_presentation_challenge_v2(&challenge, ISSUED_AT + 1)
        .test_ok("inspect signed challenge");
    validate_schema(
        "financial-passport-presentation-challenge.schema.json",
        &challenge,
    )
    .test_ok("validate signed challenge schema");

    let mut wrong_digest = challenge.clone();
    wrong_digest.body.challenge_digest = "aa".repeat(32);
    assert!(matches!(
        respond_to_passport_presentation_challenge_v2(
            &holder,
            manifest.clone(),
            vec![credential.clone()],
            proofs.clone(),
            &wrong_digest,
            ISSUED_AT + 1,
        ),
        Err(CredentialError::InvalidChallengeDigest)
    ));

    let mut wrong_signature = challenge.clone();
    wrong_signature.signature =
        chio_core::Signature::from_hex(&"00".repeat(64)).test_ok("parse invalid signature fixture");
    assert!(matches!(
        respond_to_passport_presentation_challenge_v2(
            &holder,
            manifest,
            vec![credential],
            proofs,
            &wrong_signature,
            ISSUED_AT + 1,
        ),
        Err(CredentialError::InvalidChallengeSignature)
    ));

    let mut unknown_envelope =
        serde_json::to_value(&challenge).test_ok("serialize challenge envelope");
    unknown_envelope["unknown"] = serde_json::json!(true);
    assert!(
        serde_json::from_value::<SignedPassportPresentationChallengeV2>(unknown_envelope).is_err()
    );
    let mut unknown_body = serde_json::to_value(challenge).test_ok("serialize challenge body");
    unknown_body["body"]["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<SignedPassportPresentationChallengeV2>(unknown_body).is_err());
}

#[test]
fn manifest_present_passport_rejects_outer_metadata_tampering_and_addition() {
    let issuer = Keypair::from_seed(&[44; 32]);
    let holder = Keypair::from_seed(&[45; 32]);
    let credential = reputation_credential(&issuer, &holder);
    let (passport, _) = build_agent_passport_v2(
        &issuer,
        did(&holder),
        vec![credential],
        vec!["root".to_string()],
        Vec::new(),
        validity(ISSUED_AT, EXPIRES_AT),
        None,
    )
    .test_ok("build authenticated metadata passport");

    let mut roots = passport.clone();
    roots.merkle_roots.push("added-root".to_string());
    assert!(inspect_agent_passport_v2(&roots, ISSUED_AT + 1).is_err());

    let mut provenance = passport.clone();
    provenance.enterprise_identity_provenance.push(
        chio_credentials::EnterpriseIdentityProvenance {
            provider_id: "provider".to_string(),
            provider_record_id: None,
            provider_kind: "oidc".to_string(),
            federation_method: chio_core::session::EnterpriseFederationMethod::Jwt,
            principal: "principal".to_string(),
            subject_key: holder.public_key().to_hex(),
            client_id: None,
            object_id: None,
            tenant_id: None,
            organization_id: None,
            groups: Vec::new(),
            roles: Vec::new(),
            source_subject: None,
            attribute_sources: std::collections::BTreeMap::new(),
            trust_material_ref: None,
        },
    );
    assert!(inspect_agent_passport_v2(&provenance, ISSUED_AT + 1).is_err());

    let mut tier = passport;
    tier.trust_tier = Some(TrustTier::Verified);
    assert!(inspect_agent_passport_v2(&tier, ISSUED_AT + 1).is_err());
}
