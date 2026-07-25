#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chio_reputation::{LocalReputationScorecard, MetricValue};
    use serde_json::{json, Value};

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

    fn did_from_public_key(public_key: chio_core::PublicKey) -> DidChio {
        DidChio::from_public_key(public_key).expect("ed25519 key")
    }

    fn sample_scorecard(subject_key: &str) -> LocalReputationScorecard {
        LocalReputationScorecard {
            subject_key: subject_key.to_string(),
            computed_at: 1_710_000_000,
            boundary_pressure: chio_reputation::BoundaryPressureMetrics {
                deny_ratio: MetricValue::Known(0.1),
                policies_observed: 1,
                receipts_observed: 3,
            },
            resource_stewardship: chio_reputation::ResourceStewardshipMetrics {
                average_utilization: MetricValue::Known(0.6),
                fit_score: MetricValue::Known(0.9),
                capped_grants_observed: 1,
            },
            least_privilege: chio_reputation::LeastPrivilegeMetrics {
                score: MetricValue::Known(0.8),
                capabilities_observed: 1,
            },
            history_depth: chio_reputation::HistoryDepthMetrics {
                score: MetricValue::Known(0.7),
                receipt_count: 3,
                active_days: 3,
                first_seen: Some(1_709_900_000),
                last_seen: Some(1_710_000_000),
                span_days: 3,
                activity_ratio: MetricValue::Known(1.0),
            },
            specialization: chio_reputation::SpecializationMetrics {
                score: MetricValue::Known(0.5),
                distinct_tools: 2,
            },
            delegation_hygiene: chio_reputation::DelegationHygieneMetrics {
                score: MetricValue::Known(0.9),
                delegations_observed: 1,
                scope_reduction_rate: MetricValue::Known(1.0),
                ttl_reduction_rate: MetricValue::Known(1.0),
                budget_reduction_rate: MetricValue::Known(1.0),
            },
            reliability: chio_reputation::ReliabilityMetrics {
                score: MetricValue::Known(0.95),
                completion_rate: MetricValue::Known(1.0),
                cancellation_rate: MetricValue::Known(0.0),
                incompletion_rate: MetricValue::Known(0.0),
                receipts_observed: 3,
            },
            incident_correlation: chio_reputation::IncidentCorrelationMetrics {
                score: MetricValue::Unknown,
                incidents_observed: None,
            },
            composite_score: MetricValue::Known(0.82),
            effective_weight_sum: 0.9,
        }
    }

    fn sample_evidence() -> ChioCredentialEvidence {
        ChioCredentialEvidence {
            query: AttestationWindow {
                since: Some(1_709_900_000),
                until: 1_710_000_000,
            },
            receipt_count: 3,
            receipt_ids: vec![
                "rcpt-1".to_string(),
                "rcpt-2".to_string(),
                "rcpt-3".to_string(),
            ],
            checkpoint_roots: vec!["abc123".to_string()],
            receipt_log_urls: vec!["https://trust.example.com/v1/receipts".to_string()],
            lineage_records: 1,
            uncheckpointed_receipts: 0,
            runtime_attestation: None,
        }
    }

    fn sample_enterprise_identity_context() -> EnterpriseIdentityContext {
        EnterpriseIdentityContext {
            provider_id: "enterprise-login".to_string(),
            provider_record_id: Some("enterprise-login".to_string()),
            provider_kind: "oidc_jwks".to_string(),
            federation_method: EnterpriseFederationMethod::Jwt,
            principal: "oidc:https://issuer.enterprise.example#sub:user-123".to_string(),
            subject_key: "enterprise-subject-key".to_string(),
            client_id: Some("client-123".to_string()),
            object_id: Some("object-123".to_string()),
            tenant_id: Some("tenant-123".to_string()),
            organization_id: Some("org-123".to_string()),
            groups: vec!["eng".to_string(), "ops".to_string()],
            roles: vec!["operator".to_string()],
            source_subject: Some("user-123".to_string()),
            attribute_sources: BTreeMap::from([
                ("principal".to_string(), "sub".to_string()),
                ("groups".to_string(), "groups".to_string()),
                ("roles".to_string(), "roles".to_string()),
            ]),
            trust_material_ref: Some("jwks:enterprise-login".to_string()),
        }
    }

    fn sample_passport(subject_seed: u8, issuer_seed: u8) -> AgentPassport {
        let subject = Keypair::from_seed(&[subject_seed; 32]);
        let issuer = Keypair::from_seed(&[issuer_seed; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = did_from_public_key(subject.public_key());
        build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport")
    }

    fn rewrite_portable_compact(
        compact: &str,
        issuer: &Keypair,
        mutate: impl FnOnce(&mut serde_json::Map<String, Value>, &mut Vec<String>),
    ) -> String {
        let segments = compact.split('~').collect::<Vec<_>>();
        let compact_jwt = segments[0];
        let mut disclosures = segments
            .iter()
            .skip(1)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string())
            .collect::<Vec<_>>();
        let jwt_parts = compact_jwt.split('.').collect::<Vec<_>>();
        let header_b64 = jwt_parts[0];
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(jwt_parts[1].as_bytes())
            .expect("decode payload");
        let payload_value: Value = serde_json::from_slice(&payload_bytes).expect("payload json");
        let Some(mut payload_object) = payload_value.as_object().cloned() else {
            panic!("payload object");
        };
        mutate(&mut payload_object, &mut disclosures);
        let payload_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&Value::Object(payload_object)).test_ok("serialize payload"),
        );
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature_b64 =
            URL_SAFE_NO_PAD.encode(issuer.sign(signing_input.as_bytes()).to_bytes());
        let compact_jwt = format!("{signing_input}.{signature_b64}");
        format!("{compact_jwt}~{}~", disclosures.join("~"))
    }

    #[test]
    fn enterprise_provenance_field_helper_rejects_blank_values() {
        require_enterprise_identity_provenance_field("provider", "providerId").unwrap();
        let err = require_enterprise_identity_provenance_field(" \t\n", "subjectKey").unwrap_err();
        assert!(matches!(
            err,
            CredentialError::MissingEnterpriseIdentityProvenanceField {
                field: "subjectKey"
            }
        ));
    }

    #[test]
    fn new_passport_artifacts_use_chio_schema_ids() {
        let signer = Keypair::from_seed(&[1u8; 32]);
        let holder = Keypair::from_seed(&[7u8; 32]);
        let credential = issue_reputation_credential(
            &signer,
            sample_scorecard(&holder.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let holder_did = did_from_public_key(holder.public_key());
        let passport =
            build_agent_passport(&holder_did.to_string(), vec![credential]).expect("passport");
        let policy = create_signed_passport_verifier_policy(
            &signer,
            "rp-default",
            "https://rp.example.com",
            1_710_000_000,
            1_710_086_400,
            PassportVerifierPolicy::default(),
        )
        .expect("policy");
        let challenge = create_passport_presentation_challenge(
            "https://rp.example.com",
            "nonce-123",
            1_710_000_010,
            1_710_000_310,
            PassportPresentationOptions::default(),
            Some(policy.body.policy.clone()),
        )
        .expect("challenge");
        let response = respond_to_passport_presentation_challenge(
            &holder,
            &passport,
            &challenge,
            1_710_000_020,
        )
        .expect("response");

        assert_eq!(passport.schema, PASSPORT_SCHEMA);
        assert_eq!(policy.body.schema, PASSPORT_VERIFIER_POLICY_SCHEMA);
        assert_eq!(challenge.schema, PASSPORT_PRESENTATION_CHALLENGE_SCHEMA);
        assert_eq!(response.schema, PASSPORT_PRESENTATION_RESPONSE_SCHEMA);
    }

    #[test]
    fn passport_artifacts_with_canonical_schema_verify() {
        let signer = Keypair::from_seed(&[1u8; 32]);
        let holder = Keypair::from_seed(&[7u8; 32]);
        let credential = issue_reputation_credential(
            &signer,
            sample_scorecard(&holder.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let holder_did = did_from_public_key(holder.public_key());
        let mut passport =
            build_agent_passport(&holder_did.to_string(), vec![credential]).expect("passport");
        passport.schema = PASSPORT_SCHEMA.to_string();
        verify_agent_passport(&passport, 1_710_000_100).expect("passport verify");

        let policy = PassportVerifierPolicy::default();
        let policy_body = SignedPassportVerifierPolicyBody {
            schema: PASSPORT_VERIFIER_POLICY_SCHEMA.to_string(),
            policy_id: "rp-default".to_string(),
            verifier: "https://rp.example.com".to_string(),
            signer_public_key: signer.public_key(),
            created_at: 1_710_000_000,
            expires_at: 1_710_086_400,
            policy: policy.clone(),
        };
        let (policy_signature, _) = signer
            .sign_canonical(&policy_body)
            .expect("sign verifier policy");
        let signed_policy = SignedPassportVerifierPolicy {
            body: policy_body,
            signature: policy_signature,
        };
        verify_signed_passport_verifier_policy(&signed_policy).test_ok("verifier policy verify");

        let mut challenge = create_passport_presentation_challenge(
            "https://rp.example.com",
            "nonce-123",
            1_710_000_010,
            1_710_000_310,
            PassportPresentationOptions::default(),
            Some(policy),
        )
        .expect("challenge");
        challenge.schema = PASSPORT_PRESENTATION_CHALLENGE_SCHEMA.to_string();
        verify_passport_presentation_challenge(&challenge, 1_710_000_020)
            .expect("challenge verify");

        let mut response = respond_to_passport_presentation_challenge(
            &holder,
            &passport,
            &challenge,
            1_710_000_020,
        )
        .expect("response");
        response.schema = PASSPORT_PRESENTATION_RESPONSE_SCHEMA.to_string();
        let unsigned = UnsignedPassportPresentationResponse {
            schema: response.schema.clone(),
            challenge: response.challenge.clone(),
            passport: response.passport.clone(),
        };
        let (response_signature, _) = holder.sign_canonical(&unsigned).test_ok("sign response");
        response.proof.proof_value = response_signature.to_hex();
        verify_passport_presentation_response(&response, Some(&challenge), 1_710_000_120)
            .expect("response verify");
    }

    #[test]
    fn issued_credential_verifies_against_issuer_did() {
        let issuer = Keypair::from_seed(&[9u8; 32]);
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");

        verify_reputation_credential(&credential, 1_710_010_000).expect("verify");
    }

    #[test]
    fn passport_verification_accepts_multi_issuer_bundle() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let credential_a = issue_reputation_credential(
            &Keypair::from_seed(&[1u8; 32]),
            sample_scorecard(&subject),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let credential_b = issue_reputation_credential(
            &Keypair::from_seed(&[2u8; 32]),
            sample_scorecard(&subject),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let did = did_from_public_key(
            chio_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );

        let passport = build_agent_passport(&did.to_string(), vec![credential_a, credential_b])
            .expect("multi-issuer passport");
        let verification = verify_agent_passport(&passport, 1_710_010_000).expect("verify");
        assert_eq!(verification.issuer, None);
        assert_eq!(verification.issuer_count, 2);
        assert_eq!(verification.issuers.len(), 2);
    }

    #[test]
    fn legacy_cross_issuer_portfolio_evaluation_is_unsupported() {
        let portfolio = CrossIssuerPortfolio {
            schema: CROSS_ISSUER_PORTFOLIO_SCHEMA.to_string(),
            portfolio_id: "legacy-portfolio".to_string(),
            subject: "did:chio:legacy".to_string(),
            entries: Vec::new(),
            migrations: Vec::new(),
        };
        let trust_pack = create_signed_cross_issuer_trust_pack(
            &Keypair::from_seed(&[9u8; 32]),
            "legacy-pack",
            "https://rp.example.com",
            1_710_000_000,
            1_710_086_400,
            CrossIssuerTrustPackPolicy::default(),
        )
        .test_ok("legacy trust pack");

        assert!(matches!(
            evaluate_cross_issuer_portfolio(&portfolio, 1_710_000_200, &trust_pack),
            Err(CredentialError::UnsupportedLegacyCrossIssuerV1)
        ));
    }

    #[test]
    fn cross_issuer_portfolio_rejects_duplicate_migration_ids() {
        let migrated_passport = sample_passport(5, 1);
        let old_subject = migrated_passport.subject.clone();
        let target_subject =
            did_from_public_key(Keypair::from_seed(&[8u8; 32]).public_key()).to_string();
        let issuer = migrated_passport.credentials[0].unsigned.issuer.clone();
        let passport_id = passport_artifact_id(&migrated_passport).expect("passport id");
        let migration_a = create_signed_cross_issuer_migration(
            &Keypair::from_seed(&[9u8; 32]),
            CreateSignedCrossIssuerMigrationArgs {
                migration_id: "migration-dup".to_string(),
                attester: "https://rp.example.com/migrations/a".to_string(),
                from_issuer: issuer.clone(),
                to_issuer: issuer.clone(),
                from_subject: old_subject.clone(),
                to_subject: target_subject.clone(),
                prior_passport_ids: vec![passport_id.clone()],
                reason: "issuer migration".to_string(),
                continuity_ref: "ledger://continuity/a".to_string(),
                issued_at: 1_710_000_000,
                expires_at: Some(1_710_086_400),
            },
        )
        .expect("migration");
        let migration_b = create_signed_cross_issuer_migration(
            &Keypair::from_seed(&[10u8; 32]),
            CreateSignedCrossIssuerMigrationArgs {
                migration_id: "migration-dup".to_string(),
                attester: "https://rp.example.com/migrations/b".to_string(),
                from_issuer: issuer.clone(),
                to_issuer: issuer,
                from_subject: old_subject,
                to_subject: target_subject.clone(),
                prior_passport_ids: vec![passport_id],
                reason: "issuer migration".to_string(),
                continuity_ref: "ledger://continuity/b".to_string(),
                issued_at: 1_710_000_000,
                expires_at: Some(1_710_086_400),
            },
        )
        .expect("migration");
        let portfolio = CrossIssuerPortfolio {
            schema: CROSS_ISSUER_PORTFOLIO_SCHEMA.to_string(),
            portfolio_id: "portfolio-4".to_string(),
            subject: target_subject,
            entries: vec![CrossIssuerPortfolioEntry {
                entry_id: "migrated".to_string(),
                profile_family: PASSPORT_SCHEMA.to_string(),
                source_kind: CrossIssuerPortfolioEntryKind::Migrated,
                source: Some("https://issuer-a.example/migration".to_string()),
                passport: migrated_passport,
                lifecycle: None,
                certification_refs: vec!["cert-alpha".to_string()],
                migration_id: Some("migration-dup".to_string()),
            }],
            migrations: vec![migration_a, migration_b],
        };

        let error = verify_cross_issuer_portfolio(&portfolio, 1_710_000_200)
            .expect_err("duplicate migration ids");
        assert!(matches!(
            error,
            CredentialError::InvalidCrossIssuerPortfolio(_)
        ));
    }

    #[test]
    fn cross_issuer_trust_pack_rejects_tampered_signature_boundary() {
        let signer = Keypair::from_seed(&[9u8; 32]);
        let mut trust_pack = create_signed_cross_issuer_trust_pack(
            &signer,
            "pack-4",
            "https://rp.example.com",
            1_710_000_000,
            1_710_086_400,
            CrossIssuerTrustPackPolicy {
                allowed_profile_families: [PASSPORT_SCHEMA.to_string()].into_iter().collect(),
                ..CrossIssuerTrustPackPolicy::default()
            },
        )
        .expect("trust pack");
        trust_pack.body.verifier = "https://tampered.example.com".to_string();

        let trust = CrossIssuerTrustRegistryV2::new(CrossIssuerTrustRegistryConfigV2 {
            verifier_keys: vec![VerifierTrustKeyV2 {
                verifier_id: "https://rp.example.com".to_string(),
                signer_key_id: "legacy-verifier".to_string(),
                signer_key_epoch: 1,
                public_key: signer.public_key(),
                status: TrustedKeyStatusV2::Active,
            }],
            ..CrossIssuerTrustRegistryConfigV2::default()
        })
        .test_ok("legacy verifier trust");
        let error = verify_signed_cross_issuer_trust_pack(&trust_pack, 1_710_000_200, &trust)
            .expect_err("tampered trust pack");
        assert!(matches!(
            error,
            CredentialError::InvalidCrossIssuerTrustPack(_)
        ));
    }

    #[test]
    fn verifier_policy_reports_mixed_multi_issuer_results() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let issuer_a = Keypair::from_seed(&[1u8; 32]);
        let issuer_b = Keypair::from_seed(&[2u8; 32]);
        let credential_a = issue_reputation_credential(
            &issuer_a,
            sample_scorecard(&subject),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let credential_b = issue_reputation_credential(
            &issuer_b,
            sample_scorecard(&subject),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = did_from_public_key(
            chio_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential_a, credential_b])
                .expect("passport");
        let accepted_issuer = passport.credentials[0].unsigned.issuer.clone();
        let rejected_issuer = passport.credentials[1].unsigned.issuer.clone();

        let evaluation = evaluate_agent_passport(
            &passport,
            1_710_010_000,
            &PassportVerifierPolicy {
                issuer_allowlist: [accepted_issuer.clone()].into_iter().collect(),
                ..PassportVerifierPolicy::default()
            },
        )
        .expect("evaluation");

        assert!(evaluation.accepted);
        assert_eq!(evaluation.verification.issuer_count, 2);
        assert_eq!(evaluation.matched_credential_indexes, vec![0]);
        assert_eq!(evaluation.matched_issuers, vec![accepted_issuer.clone()]);
        assert_eq!(evaluation.credential_results[0].issuer, accepted_issuer);
        assert!(evaluation.credential_results[0].accepted);
        assert_eq!(evaluation.credential_results[1].issuer, rejected_issuer);
        assert!(!evaluation.credential_results[1].accepted);
    }

    #[test]
    fn passport_verification_surfaces_enterprise_identity_provenance() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let enterprise_identity =
            EnterpriseIdentityProvenance::from(&sample_enterprise_identity_context());
        let credential = issue_reputation_credential_with_enterprise_identity(
            &issuer,
            sample_scorecard(&subject),
            sample_evidence(),
            Some(enterprise_identity.clone()),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = did_from_public_key(
            chio_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");

        assert_eq!(
            passport.enterprise_identity_provenance,
            vec![enterprise_identity.clone()]
        );

        let verification = verify_agent_passport(&passport, 1_710_010_000).expect("verify");
        assert_eq!(
            verification.enterprise_identity_provenance,
            vec![enterprise_identity]
        );
    }

    #[test]
    fn passport_verification_rejects_tampered_enterprise_identity_provenance() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let credential = issue_reputation_credential_with_enterprise_identity(
            &issuer,
            sample_scorecard(&subject),
            sample_evidence(),
            Some(EnterpriseIdentityProvenance::from(
                &sample_enterprise_identity_context(),
            )),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = did_from_public_key(
            chio_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );
        let mut passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");
        passport.enterprise_identity_provenance.clear();

        let error = verify_agent_passport(&passport, 1_710_010_000).expect_err("tampered passport");
        assert!(matches!(
            error,
            CredentialError::PassportEnterpriseIdentityProvenanceMismatch
        ));
    }

    #[test]
    fn verifier_policy_can_require_enterprise_identity_provenance() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = did_from_public_key(
            chio_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");

        let evaluation = evaluate_agent_passport(
            &passport,
            1_710_010_000,
            &PassportVerifierPolicy {
                require_enterprise_identity_provenance: true,
                ..PassportVerifierPolicy::default()
            },
        )
        .expect("evaluation");

        assert!(!evaluation.accepted);
        assert!(!evaluation.credential_results[0].enterprise_identity_present);
        assert!(evaluation.credential_results[0]
            .reasons
            .iter()
            .any(|reason| reason.contains("enterprise identity provenance")));
    }

    #[test]
    fn verifier_policy_rejects_multi_issuer_bundle_when_no_credential_matches() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let credential_a = issue_reputation_credential(
            &Keypair::from_seed(&[1u8; 32]),
            sample_scorecard(&subject),
            sample_evidence(),
            1_900_000_000,
            1_900_086_400,
        )
        .expect("credential");
        let credential_b = issue_reputation_credential(
            &Keypair::from_seed(&[2u8; 32]),
            sample_scorecard(&subject),
            sample_evidence(),
            1_900_000_000,
            1_900_086_400,
        )
        .expect("credential");
        let subject_did = did_from_public_key(
            chio_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential_a, credential_b])
                .expect("passport");

        let evaluation = evaluate_agent_passport(
            &passport,
            1_900_010_000,
            &PassportVerifierPolicy {
                issuer_allowlist: [
                    "did:chio:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                        .to_string(),
                ]
                .into_iter()
                .collect(),
                ..PassportVerifierPolicy::default()
            },
        )
        .expect("evaluation");

        assert!(!evaluation.accepted);
        assert!(evaluation.matched_credential_indexes.is_empty());
        assert!(evaluation.matched_issuers.is_empty());
        assert_eq!(evaluation.credential_results.len(), 2);
        assert!(evaluation
            .credential_results
            .iter()
            .all(|result| !result.accepted));
    }

    #[test]
    fn presentation_can_filter_credentials_by_issuer() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = did_from_public_key(
            chio_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );
        let passport = build_agent_passport(&subject_did.to_string(), vec![credential.clone()])
            .expect("passport");

        let presented = present_agent_passport(
            &passport,
            &PassportPresentationOptions {
                issuer_allowlist: [credential.unsigned.issuer.clone()].into_iter().collect(),
                max_credentials: Some(1),
            },
        )
        .expect("presented passport");

        assert_eq!(presented.credentials.len(), 1);
        verify_agent_passport(&presented, 1_710_010_000).expect("verify presented passport");
    }

    #[test]
    fn verifier_policy_accepts_matching_single_issuer_passport() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = did_from_public_key(
            chio_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");

        let evaluation = evaluate_agent_passport(
            &passport,
            1_710_010_000,
            &PassportVerifierPolicy {
                issuer_allowlist: [passport.credentials[0].unsigned.issuer.clone()]
                    .into_iter()
                    .collect(),
                min_composite_score: Some(0.80),
                min_reliability: Some(0.90),
                max_boundary_pressure: Some(0.20),
                min_receipt_count: Some(3),
                min_lineage_records: Some(1),
                min_history_days: Some(3),
                max_attestation_age_days: Some(7),
                require_checkpoint_coverage: true,
                require_receipt_log_urls: true,
                ..PassportVerifierPolicy::default()
            },
        )
        .expect("evaluate");

        assert!(evaluation.accepted);
        assert_eq!(evaluation.matched_credential_indexes, vec![0]);
        assert!(evaluation.credential_results[0].accepted);
    }

    #[test]
    fn verifier_policy_rejects_unknown_metric_and_stale_attestation() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let mut evidence = sample_evidence();
        evidence.uncheckpointed_receipts = 1;
        evidence.receipt_log_urls.clear();
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject),
            evidence,
            1_710_000_000,
            1_720_000_000,
        )
        .expect("credential");
        let subject_did = did_from_public_key(
            chio_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");

        let evaluation = evaluate_agent_passport(
            &passport,
            1_712_000_000,
            &PassportVerifierPolicy {
                min_composite_score: Some(0.90),
                max_attestation_age_days: Some(1),
                require_checkpoint_coverage: true,
                require_receipt_log_urls: true,
                ..PassportVerifierPolicy::default()
            },
        )
        .expect("evaluate");

        assert!(!evaluation.accepted);
        assert!(evaluation.matched_credential_indexes.is_empty());
        let reasons = &evaluation.credential_results[0].reasons;
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("composite_score")),
            "expected composite score rejection"
        );
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("uncheckpointed")),
            "expected checkpoint rejection"
        );
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("receipt log URLs")),
            "expected receipt-log rejection"
        );
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("attestation_age_days")),
            "expected attestation-age rejection"
        );
    }

    #[test]
    fn verifier_policy_accepts_if_any_credential_matches_without_fake_aggregation() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let mut weaker = sample_scorecard(&subject);
        weaker.composite_score = MetricValue::Known(0.40);
        weaker.reliability.score = MetricValue::Known(0.60);
        let stronger = sample_scorecard(&subject);

        let weak_credential = issue_reputation_credential(
            &issuer,
            weaker,
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("weak credential");
        let strong_credential = issue_reputation_credential(
            &issuer,
            stronger,
            sample_evidence(),
            1_710_000_100,
            1_710_086_400,
        )
        .expect("strong credential");
        let subject_did = did_from_public_key(
            chio_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );
        let passport = build_agent_passport(
            &subject_did.to_string(),
            vec![weak_credential, strong_credential],
        )
        .expect("passport");

        let evaluation = evaluate_agent_passport(
            &passport,
            1_710_010_000,
            &PassportVerifierPolicy {
                min_composite_score: Some(0.80),
                min_reliability: Some(0.90),
                ..PassportVerifierPolicy::default()
            },
        )
        .expect("evaluate");

        assert!(evaluation.accepted);
        assert_eq!(evaluation.matched_credential_indexes, vec![1]);
        assert!(!evaluation.credential_results[0].accepted);
        assert!(evaluation.credential_results[1].accepted);
    }

    #[test]
    fn challenge_bound_presentation_verifies_and_evaluates_policy() {
        let subject = Keypair::from_seed(&[7u8; 32]);
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = did_from_public_key(subject.public_key());
        let passport = build_agent_passport(&subject_did.to_string(), vec![credential.clone()])
            .expect("passport");
        let challenge = create_passport_presentation_challenge(
            "https://rp.example.com",
            "nonce-123",
            1_710_000_050,
            1_710_000_350,
            PassportPresentationOptions {
                issuer_allowlist: [credential.unsigned.issuer.clone()].into_iter().collect(),
                max_credentials: Some(1),
            },
            Some(PassportVerifierPolicy {
                issuer_allowlist: [credential.unsigned.issuer.clone()].into_iter().collect(),
                min_composite_score: Some(0.80),
                min_reliability: Some(0.90),
                require_checkpoint_coverage: true,
                require_receipt_log_urls: true,
                ..PassportVerifierPolicy::default()
            }),
        )
        .expect("challenge");

        let response = respond_to_passport_presentation_challenge(
            &subject,
            &passport,
            &challenge,
            1_710_000_100,
        )
        .expect("response");
        let verification =
            verify_passport_presentation_response(&response, Some(&challenge), 1_710_000_120)
                .expect("verify");

        assert_eq!(verification.subject, subject_did.to_string());
        assert_eq!(verification.verifier, "https://rp.example.com");
        assert_eq!(verification.nonce, "nonce-123");
        assert_eq!(verification.credential_count, 1);
        assert!(verification.accepted);
        assert!(
            verification
                .policy_evaluation
                .as_ref()
                .expect("policy evaluation")
                .accepted
        );
    }

    #[test]
    fn challenge_requires_non_empty_verifier_and_nonce() {
        assert!(matches!(
            create_passport_presentation_challenge(
                " \t",
                "nonce-123",
                1_710_000_050,
                1_710_000_350,
                PassportPresentationOptions::default(),
                None,
            ),
            Err(CredentialError::MissingChallengeVerifier)
        ));
        assert!(matches!(
            create_passport_presentation_challenge(
                "https://rp.example.com",
                "\n",
                1_710_000_050,
                1_710_000_350,
                PassportPresentationOptions::default(),
                None,
            ),
            Err(CredentialError::MissingChallengeNonce)
        ));
        assert!(matches!(
            create_passport_presentation_challenge(
                " https://rp.example.com",
                "nonce-123",
                1_710_000_050,
                1_710_000_350,
                PassportPresentationOptions::default(),
                None,
            ),
            Err(CredentialError::MissingChallengeVerifier)
        ));
        assert!(matches!(
            create_passport_presentation_challenge(
                "https://rp.example.com",
                "nonce-123 ",
                1_710_000_050,
                1_710_000_350,
                PassportPresentationOptions::default(),
                None,
            ),
            Err(CredentialError::MissingChallengeNonce)
        ));
        assert!(matches!(
            create_passport_presentation_challenge(
                "https://rp.example.com\nbad",
                "nonce-123",
                1_710_000_050,
                1_710_000_350,
                PassportPresentationOptions::default(),
                None,
            ),
            Err(CredentialError::MissingChallengeVerifier)
        ));
        assert!(matches!(
            create_passport_presentation_challenge(
                "https://rp.example.com",
                "nonce-123\nnonce-456",
                1_710_000_050,
                1_710_000_350,
                PassportPresentationOptions::default(),
                None,
            ),
            Err(CredentialError::MissingChallengeNonce)
        ));

        let mut challenge = create_passport_presentation_challenge(
            "https://rp.example.com",
            "nonce-123",
            1_710_000_050,
            1_710_000_350,
            PassportPresentationOptions::default(),
            None,
        )
        .expect("challenge");
        challenge.nonce = " ".to_string();
        assert!(matches!(
            verify_passport_presentation_challenge(&challenge, 1_710_000_100),
            Err(CredentialError::MissingChallengeNonce)
        ));
        challenge.nonce = "nonce-123".to_string();
        challenge.verifier = "https://rp.example.com ".to_string();
        assert!(matches!(
            verify_passport_presentation_challenge(&challenge, 1_710_000_100),
            Err(CredentialError::MissingChallengeVerifier)
        ));
        challenge.verifier = "https://rp.example.com".to_string();
        challenge.nonce = "nonce-123\nnonce-456".to_string();
        assert!(matches!(
            verify_passport_presentation_challenge(&challenge, 1_710_000_100),
            Err(CredentialError::MissingChallengeNonce)
        ));
    }

    #[test]
    fn challenge_bound_presentation_rejects_holder_mismatch() {
        let subject = Keypair::from_seed(&[7u8; 32]);
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = did_from_public_key(subject.public_key());
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");
        let challenge = create_passport_presentation_challenge(
            "https://rp.example.com",
            "nonce-123",
            1_710_000_050,
            1_710_000_350,
            PassportPresentationOptions::default(),
            None,
        )
        .expect("challenge");

        let error = respond_to_passport_presentation_challenge(
            &Keypair::from_seed(&[8u8; 32]),
            &passport,
            &challenge,
            1_710_000_100,
        )
        .expect_err("holder mismatch should fail");
        assert!(matches!(error, CredentialError::PresentationHolderMismatch));
    }

    #[test]
    fn challenge_bound_presentation_rejects_tampered_signature() {
        let subject = Keypair::from_seed(&[7u8; 32]);
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = did_from_public_key(subject.public_key());
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");
        let challenge = create_passport_presentation_challenge(
            "https://rp.example.com",
            "nonce-123",
            1_710_000_050,
            1_710_000_350,
            PassportPresentationOptions::default(),
            None,
        )
        .expect("challenge");
        let mut response = respond_to_passport_presentation_challenge(
            &subject,
            &passport,
            &challenge,
            1_710_000_100,
        )
        .expect("response");
        response.challenge.nonce = "tampered".to_string();

        let error = verify_passport_presentation_response(&response, None, 1_710_000_120)
            .expect_err("tampered signature should fail");
        assert!(matches!(
            error,
            CredentialError::InvalidPresentationSignature
        ));
    }

    #[test]
    fn challenge_bound_presentation_rejects_expired_challenge() {
        let subject = Keypair::from_seed(&[7u8; 32]);
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = did_from_public_key(subject.public_key());
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");
        let challenge = create_passport_presentation_challenge(
            "https://rp.example.com",
            "nonce-123",
            1_710_000_050,
            1_710_000_150,
            PassportPresentationOptions::default(),
            None,
        )
        .expect("challenge");
        let response = respond_to_passport_presentation_challenge(
            &subject,
            &passport,
            &challenge,
            1_710_000_100,
        )
        .expect("response");

        let error =
            verify_passport_presentation_response(&response, Some(&challenge), 1_710_000_200)
                .expect_err("expired challenge should fail");
        assert!(matches!(error, CredentialError::ChallengeExpired));
    }

    #[test]
    fn challenge_bound_presentation_reports_policy_rejection_without_structural_failure() {
        let subject = Keypair::from_seed(&[7u8; 32]);
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = did_from_public_key(subject.public_key());
        let passport = build_agent_passport(&subject_did.to_string(), vec![credential.clone()])
            .expect("passport");
        let challenge = create_passport_presentation_challenge(
            "https://rp.example.com",
            "nonce-123",
            1_710_000_050,
            1_710_000_350,
            PassportPresentationOptions {
                issuer_allowlist: [credential.unsigned.issuer.clone()].into_iter().collect(),
                max_credentials: Some(1),
            },
            Some(PassportVerifierPolicy {
                issuer_allowlist: [credential.unsigned.issuer.clone()].into_iter().collect(),
                min_composite_score: Some(0.99),
                require_checkpoint_coverage: true,
                require_receipt_log_urls: true,
                ..PassportVerifierPolicy::default()
            }),
        )
        .expect("challenge");
        let response = respond_to_passport_presentation_challenge(
            &subject,
            &passport,
            &challenge,
            1_710_000_100,
        )
        .expect("response");

        let verification =
            verify_passport_presentation_response(&response, Some(&challenge), 1_710_000_120)
                .expect("verify");

        assert!(!verification.accepted);
        assert!(
            !verification
                .policy_evaluation
                .as_ref()
                .expect("policy evaluation")
                .accepted
        );
    }

    #[test]
    fn oid4vci_passport_metadata_offer_and_response_validate() {
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let subject = Keypair::from_seed(&[7u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = did_from_public_key(subject.public_key());
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");

        let metadata =
            default_oid4vci_passport_issuer_metadata("https://trust.example.com").expect("meta");
        let offer = build_oid4vci_passport_offer(
            &metadata,
            CHIO_PASSPORT_OID4VCI_CREDENTIAL_CONFIGURATION_ID,
            "pre-auth-code",
            &passport,
            1_710_000_300,
        )
        .expect("offer");
        offer
            .validate_against_metadata(&metadata)
            .expect("offer valid");

        let token_request = Oid4vciTokenRequest {
            grant_type: OID4VCI_PRE_AUTHORIZED_GRANT_TYPE.to_string(),
            pre_authorized_code: offer
                .pre_authorized_code()
                .expect("pre auth code")
                .to_string(),
        };
        token_request.validate().expect("token request valid");

        let credential_request = Oid4vciCredentialRequest {
            credential_configuration_id: Some(
                CHIO_PASSPORT_OID4VCI_CREDENTIAL_CONFIGURATION_ID.to_string(),
            ),
            format: Some(CHIO_PASSPORT_OID4VCI_FORMAT.to_string()),
            subject: passport.subject.clone(),
        };
        let resolved_configuration_id = credential_request
            .validate_against_metadata(&metadata)
            .expect("credential request valid");
        assert_eq!(
            resolved_configuration_id,
            CHIO_PASSPORT_OID4VCI_CREDENTIAL_CONFIGURATION_ID
        );

        let response =
            Oid4vciCredentialResponse::new(CHIO_PASSPORT_OID4VCI_FORMAT, passport.clone())
                .expect("response");
        response
            .validate(
                1_710_000_100,
                Some(CHIO_PASSPORT_OID4VCI_FORMAT),
                Some(&passport.subject),
            )
            .expect("credential response valid");
    }

    #[test]
    fn oid4vci_credential_request_rejects_subject_and_format_mismatch() {
        let metadata =
            default_oid4vci_passport_issuer_metadata("https://trust.example.com").expect("meta");
        let request = Oid4vciCredentialRequest {
            credential_configuration_id: Some(
                CHIO_PASSPORT_OID4VCI_CREDENTIAL_CONFIGURATION_ID.to_string(),
            ),
            format: Some("wrong-format".to_string()),
            subject: "did:example:not-chio".to_string(),
        };

        let error = request
            .validate_against_metadata(&metadata)
            .expect_err("mismatched request should fail");
        assert!(matches!(
            error,
            CredentialError::Did(_) | CredentialError::InvalidOid4vciCredentialRequest(_)
        ));
    }

    #[test]
    fn oid4vci_metadata_and_response_can_carry_passport_status_distribution() {
        let issuer = Keypair::from_seed(&[2u8; 32]);
        let subject = Keypair::from_seed(&[8u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = did_from_public_key(subject.public_key());
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");
        let passport_id = passport_artifact_id(&passport).expect("passport id");

        let distribution = PassportStatusDistribution {
            resolve_urls: vec![
                "https://trust.example.com/v1/public/passport/statuses/resolve".to_string(),
            ],
            cache_ttl_secs: Some(300),
        };
        let metadata = default_oid4vci_passport_issuer_metadata_with_status_distribution(
            "https://trust.example.com",
            distribution.clone(),
        )
        .expect("metadata with status distribution");
        metadata.validate().expect("metadata valid");
        assert_eq!(
            metadata
                .chio_profile
                .as_ref()
                .expect("chio profile")
                .passport_status_distribution,
            distribution
        );

        let response = Oid4vciCredentialResponse::new_with_status_reference(
            CHIO_PASSPORT_OID4VCI_FORMAT,
            passport.clone(),
            Some(Oid4vciChioPassportStatusReference {
                passport_id: passport_id.clone(),
                distribution: distribution.clone(),
            }),
        )
        .expect("response");
        response
            .validate(
                1_710_000_100,
                Some(CHIO_PASSPORT_OID4VCI_FORMAT),
                Some(&passport.subject),
            )
            .expect("credential response with status reference valid");
    }

    #[test]
    fn oid4vci_metadata_with_signing_key_advertises_portable_projection() {
        let issuer = Keypair::from_seed(&[5u8; 32]);
        let metadata = default_oid4vci_passport_issuer_metadata_with_signing_key(
            "https://trust.example.com",
            PassportStatusDistribution::default(),
            Some(&issuer.public_key()),
        )
        .expect("portable metadata");
        metadata.validate().expect("portable metadata valid");

        assert_eq!(
            metadata.jwks_uri.as_deref(),
            Some("https://trust.example.com/.well-known/jwks.json")
        );
        let portable_configuration = metadata
            .credential_configurations_supported
            .get(CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID)
            .expect("portable credential configuration");
        assert_eq!(
            portable_configuration.format,
            CHIO_PASSPORT_SD_JWT_VC_FORMAT
        );
        let portable_profile = portable_configuration
            .portable_profile
            .as_ref()
            .expect("portable profile");
        assert_eq!(
            portable_profile.type_metadata_url,
            "https://trust.example.com/.well-known/chio-passport-sd-jwt-vc"
        );
        assert_eq!(
            portable_profile.portable_identity_binding.subject_binding,
            portable_profile.subject_binding
        );
        assert_eq!(
            portable_profile.portable_identity_binding.issuer_identity,
            portable_profile.issuer_identity
        );
        assert_eq!(
            portable_profile
                .portable_identity_binding
                .chio_provenance_anchor,
            "did:chio"
        );
        assert!(portable_profile
            .portable_claim_catalog
            .selectively_disclosable_claims
            .iter()
            .any(|claim| claim == "chio_issuer_dids"));
        assert_eq!(portable_profile.proof_family, "dc+sd-jwt");
        assert!(portable_profile.supports_selective_disclosure);

        let jwt_vc_configuration = metadata
            .credential_configurations_supported
            .get(CHIO_PASSPORT_JWT_VC_JSON_CREDENTIAL_CONFIGURATION_ID)
            .expect("jwt vc credential configuration");
        assert_eq!(
            jwt_vc_configuration.format,
            CHIO_PASSPORT_JWT_VC_JSON_FORMAT
        );
        let jwt_vc_profile = jwt_vc_configuration
            .portable_profile
            .as_ref()
            .expect("jwt vc portable profile");
        assert_eq!(
            jwt_vc_profile.type_metadata_url,
            "https://trust.example.com/.well-known/chio-passport-jwt-vc-json"
        );
        assert_eq!(jwt_vc_profile.proof_family, "vc+jwt");
        assert!(!jwt_vc_profile.supports_selective_disclosure);
        assert!(jwt_vc_profile
            .portable_claim_catalog
            .always_disclosed_claims
            .iter()
            .any(|claim| claim == "vc.credentialSubject.chioPassportId"));

        let type_metadata = build_chio_passport_sd_jwt_type_metadata("https://trust.example.com")
            .test_ok("type metadata");
        assert_eq!(type_metadata.format, CHIO_PASSPORT_SD_JWT_VC_FORMAT);
        assert_eq!(
            type_metadata.jwks_url,
            "https://trust.example.com/.well-known/jwks.json"
        );
        assert_eq!(
            type_metadata.portable_identity_binding.subject_binding,
            type_metadata.subject_binding
        );
        assert_eq!(
            type_metadata.portable_identity_binding.issuer_identity,
            type_metadata.issuer_identity
        );
        assert!(type_metadata
            .portable_claim_catalog
            .optional_claims
            .iter()
            .any(|claim| claim == "chio_passport_status"));

        let jwt_vc_type_metadata =
            build_chio_passport_jwt_vc_json_type_metadata("https://trust.example.com")
                .expect("jwt vc type metadata");
        assert_eq!(
            jwt_vc_type_metadata.format,
            CHIO_PASSPORT_JWT_VC_JSON_FORMAT
        );
        assert_eq!(
            jwt_vc_type_metadata.jwks_url,
            "https://trust.example.com/.well-known/jwks.json"
        );
        assert_eq!(jwt_vc_type_metadata.proof_family, "vc+jwt");
        assert!(!jwt_vc_type_metadata.supports_selective_disclosure);
        assert!(jwt_vc_type_metadata
            .portable_claim_catalog
            .always_disclosed_claims
            .iter()
            .any(|claim| claim == "vc.credentialSubject.chioIssuerDids"));

        let jwks = build_portable_issuer_jwks("https://trust.example.com", &issuer.public_key())
            .expect("jwks");
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].alg, "EdDSA");
    }

    #[test]
    fn portable_sd_jwt_passport_projection_roundtrip_verifies() {
        let issuer = Keypair::from_seed(&[6u8; 32]);
        let subject = Keypair::from_seed(&[9u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = did_from_public_key(subject.public_key());
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");
        let passport_id = passport_artifact_id(&passport).expect("passport id");

        let envelope = issue_chio_passport_sd_jwt_vc(
            &passport,
            "https://trust.example.com",
            &issuer,
            1_710_000_100,
            None,
        )
        .expect("portable envelope");
        let verification =
            verify_chio_passport_sd_jwt_vc(&envelope.compact, &issuer.public_key(), 1_710_000_200)
                .test_ok("portable verification");
        assert_eq!(verification.passport_id, passport_id);
        assert_eq!(verification.subject_did, passport.subject);
        assert_eq!(verification.issuer, "https://trust.example.com");

        let response = Oid4vciCredentialResponse::new_portable_sd_jwt(
            CHIO_PASSPORT_SD_JWT_VC_FORMAT,
            envelope.compact.clone(),
            envelope.passport_id.clone(),
            envelope.subject_did.clone(),
            None,
            envelope.issuer_jwk.clone(),
        )
        .expect("portable response");
        response
            .validate(
                1_710_000_200,
                Some(CHIO_PASSPORT_SD_JWT_VC_FORMAT),
                Some(&passport.subject),
            )
            .expect("portable response valid");
        assert_eq!(response.subject_hint(), Some(passport.subject.as_str()));
        assert_eq!(response.passport_id_hint(), Some(passport_id.as_str()));
        assert_eq!(
            response
                .credential
                .write_output_bytes()
                .expect("portable output bytes"),
            envelope.compact.as_bytes()
        );
    }

    #[test]
    fn portable_jwt_vc_json_passport_projection_roundtrip_verifies() {
        let issuer = Keypair::from_seed(&[31u8; 32]);
        let subject = Keypair::from_seed(&[32u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = did_from_public_key(subject.public_key());
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");
        let passport_id = passport_artifact_id(&passport).expect("passport id");

        let envelope = issue_chio_passport_jwt_vc_json(
            &passport,
            "https://trust.example.com",
            &issuer,
            1_710_000_100,
            None,
        )
        .expect("portable jwt vc envelope");
        let verification = verify_chio_passport_jwt_vc_json(
            &envelope.compact,
            &issuer.public_key(),
            1_710_000_200,
        )
        .expect("portable jwt vc verification");
        assert_eq!(verification.passport_id, passport_id);
        assert_eq!(verification.subject_did, passport.subject);
        assert_eq!(verification.issuer, "https://trust.example.com");

        let response = Oid4vciCredentialResponse::new_portable_jwt_vc_json(
            CHIO_PASSPORT_JWT_VC_JSON_FORMAT,
            envelope.compact.clone(),
            envelope.passport_id.clone(),
            envelope.subject_did.clone(),
            None,
            envelope.issuer_jwk.clone(),
        )
        .expect("portable jwt vc response");
        response
            .validate(
                1_710_000_200,
                Some(CHIO_PASSPORT_JWT_VC_JSON_FORMAT),
                Some(&passport.subject),
            )
            .expect("portable jwt vc response valid");
        assert_eq!(response.subject_hint(), Some(passport.subject.as_str()));
        assert_eq!(response.passport_id_hint(), Some(passport_id.as_str()));
    }

    #[test]
    fn portable_response_rejects_mismatched_compact_profile_format() {
        let issuer = Keypair::from_seed(&[41u8; 32]);
        let subject = Keypair::from_seed(&[42u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = did_from_public_key(subject.public_key());
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");
        let envelope = issue_chio_passport_sd_jwt_vc(
            &passport,
            "https://trust.example.com",
            &issuer,
            1_710_000_100,
            None,
        )
        .expect("portable envelope");

        let response = Oid4vciCredentialResponse::new_portable_jwt_vc_json(
            CHIO_PASSPORT_JWT_VC_JSON_FORMAT,
            envelope.compact,
            passport_artifact_id(&passport).expect("passport id"),
            passport.subject.clone(),
            None,
            envelope.issuer_jwk,
        )
        .expect("portable response");
        let error = response
            .validate(
                1_710_000_200,
                Some(CHIO_PASSPORT_JWT_VC_JSON_FORMAT),
                Some(&passport.subject),
            )
            .expect_err("mismatched compact profile should fail");
        match error {
            CredentialError::InvalidOid4vciCredentialResponse(message) => {
                assert!(message.contains("portable jwt vc"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn portable_sd_jwt_rejects_missing_holder_binding() {
        let issuer = Keypair::from_seed(&[11u8; 32]);
        let subject = Keypair::from_seed(&[12u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = did_from_public_key(subject.public_key());
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");
        let envelope = issue_chio_passport_sd_jwt_vc(
            &passport,
            "https://trust.example.com",
            &issuer,
            1_710_000_100,
            None,
        )
        .expect("portable envelope");
        let compact = rewrite_portable_compact(&envelope.compact, &issuer, |payload, _| {
            payload.remove("cnf");
        });

        let error = verify_chio_passport_sd_jwt_vc(&compact, &issuer.public_key(), 1_710_000_200)
            .expect_err("missing holder binding should fail");
        match error {
            CredentialError::InvalidOid4vciCredentialResponse(message) => {
                assert!(message.contains("cnf.jwk"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn portable_sd_jwt_rejects_unknown_disclosure_claims() {
        let issuer = Keypair::from_seed(&[13u8; 32]);
        let subject = Keypair::from_seed(&[14u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = did_from_public_key(subject.public_key());
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");
        let envelope = issue_chio_passport_sd_jwt_vc(
            &passport,
            "https://trust.example.com",
            &issuer,
            1_710_000_100,
            None,
        )
        .expect("portable envelope");
        let compact =
            rewrite_portable_compact(&envelope.compact, &issuer, |payload, disclosures| {
                let (salt, _, value) =
                    parse_sd_jwt_disclosure(&disclosures[0]).test_ok("parse disclosure");
                let replacement = json!([salt, "chio_unknown_claim", value]);
                disclosures[0] = URL_SAFE_NO_PAD
                    .encode(serde_json::to_vec(&replacement).test_ok("encode disclosure"));
                payload.insert(
                    "_sd".to_string(),
                    Value::Array(
                        disclosures
                            .iter()
                            .map(|disclosure| Value::String(sd_jwt_disclosure_digest(disclosure)))
                            .collect(),
                    ),
                );
            });

        let error = verify_chio_passport_sd_jwt_vc(&compact, &issuer.public_key(), 1_710_000_200)
            .expect_err("unknown disclosure claim should fail");
        match error {
            CredentialError::InvalidOid4vciCredentialResponse(message) => {
                assert!(message.contains("not part of the supported Chio profile"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn portable_sd_jwt_allows_subset_disclosure_for_presentation() {
        let issuer = Keypair::from_seed(&[19u8; 32]);
        let subject = Keypair::from_seed(&[20u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = did_from_public_key(subject.public_key());
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");
        let envelope = issue_chio_passport_sd_jwt_vc(
            &passport,
            "https://trust.example.com",
            &issuer,
            1_710_000_100,
            None,
        )
        .expect("portable envelope");
        let segments = envelope.compact.split('~').collect::<Vec<_>>();
        let filtered = format!("{}~{}~", segments[0], segments[1]);
        let verification =
            verify_chio_passport_sd_jwt_vc(&filtered, &issuer.public_key(), 1_710_000_200)
                .test_ok("subset disclosure verification");
        assert_eq!(verification.disclosure_claims, vec!["chio_issuer_dids"]);
    }

    #[test]
    fn oid4vp_request_and_direct_post_roundtrip_verifies() {
        let authority = Keypair::from_seed(&[21u8; 32]);
        let issuer = Keypair::from_seed(&[22u8; 32]);
        let subject = Keypair::from_seed(&[23u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = did_from_public_key(subject.public_key());
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");
        let envelope = issue_chio_passport_sd_jwt_vc(
            &passport,
            "https://trust.example.com",
            &issuer,
            1_710_000_100,
            None,
        )
        .expect("portable envelope");
        let request = Oid4vpRequestObject {
            client_id: "https://verifier.example.com".to_string(),
            client_id_scheme: OID4VP_CLIENT_ID_SCHEME_REDIRECT_URI.to_string(),
            response_uri: "https://verifier.example.com/v1/public/passport/oid4vp/direct-post"
                .to_string(),
            response_mode: OID4VP_RESPONSE_MODE_DIRECT_POST_JWT.to_string(),
            response_type: OID4VP_RESPONSE_TYPE_VP_TOKEN.to_string(),
            nonce: "nonce-1".to_string(),
            state: "state-1".to_string(),
            iat: 1_710_000_100,
            exp: 1_710_000_400,
            jti: "oid4vp-1".to_string(),
            request_uri: "https://verifier.example.com/v1/public/passport/oid4vp/requests/oid4vp-1"
                .to_string(),
            dcql_query: Oid4vpDcqlQuery {
                credentials: vec![Oid4vpRequestedCredential {
                    id: "chio-passport".to_string(),
                    format: CHIO_PASSPORT_SD_JWT_VC_FORMAT.to_string(),
                    vct: CHIO_PASSPORT_SD_JWT_VC_TYPE.to_string(),
                    claims: vec!["chio_issuer_dids".to_string()],
                    issuer_allowlist: vec!["https://trust.example.com".to_string()],
                }],
            },
            identity_assertion: None,
        };
        let request_jwt = sign_oid4vp_request_object(&request, &authority).expect("request jwt");
        let verified_request = verify_signed_oid4vp_request_object(
            &request_jwt,
            &authority.public_key(),
            1_710_000_200,
        )
        .test_ok("verify request jwt");
        assert_eq!(verified_request, request);
        let transport =
            build_oid4vp_request_transport(&request, &authority).expect("request transport");
        let descriptor = build_wallet_exchange_descriptor_for_oid4vp(
            &request,
            &transport.request_jwt,
            "https://verifier.example.com/v1/public/passport/wallet-exchanges/oid4vp-1",
            &transport.same_device_url,
            "https://verifier.example.com/v1/public/passport/oid4vp/launch/oid4vp-1",
            None,
        )
        .expect("wallet exchange descriptor");
        assert_eq!(descriptor.exchange_id, request.jti);
        assert_eq!(descriptor.relay_url, descriptor.cross_device_url);
        let issued_state = WalletExchangeTransactionState::issued(
            &descriptor.exchange_id,
            &request.jti,
            request.iat,
            request.exp,
        );
        issued_state
            .validate()
            .expect("issued wallet exchange transaction");

        let response_jwt =
            respond_to_oid4vp_request(&subject, &envelope.compact, &request, 1_710_000_200)
                .expect("respond to oid4vp request");
        let verification = verify_oid4vp_direct_post_response(
            &response_jwt,
            &request,
            &issuer.public_key(),
            1_710_000_220,
        )
        .expect("verify oid4vp response");
        assert_eq!(verification.passport_id, envelope.passport_id);
        assert_eq!(verification.subject_did, passport.subject);
        assert_eq!(verification.disclosure_claims, vec!["chio_issuer_dids"]);
    }

    #[test]
    fn wallet_exchange_validation_rejects_contradictory_state() {
        let state = WalletExchangeTransactionState {
            exchange_id: "exchange-1".to_string(),
            request_id: "request-1".to_string(),
            status: WalletExchangeTransactionStatus::Consumed,
            issued_at: 10,
            expires_at: 20,
            updated_at: 15,
            consumed_at: None,
        };
        let error = state
            .validate()
            .expect_err("consumed state without consumed_at should fail");
        assert!(error.to_string().contains("consumed_at"));
    }

    #[test]
    fn oid4vp_request_validation_rejects_mismatched_identity_assertion_binding() {
        let request = Oid4vpRequestObject {
            client_id: "https://verifier.example.com".to_string(),
            client_id_scheme: OID4VP_CLIENT_ID_SCHEME_REDIRECT_URI.to_string(),
            response_uri: "https://verifier.example.com/v1/public/passport/oid4vp/direct-post"
                .to_string(),
            response_mode: OID4VP_RESPONSE_MODE_DIRECT_POST_JWT.to_string(),
            response_type: OID4VP_RESPONSE_TYPE_VP_TOKEN.to_string(),
            nonce: "nonce-1".to_string(),
            state: "state-1".to_string(),
            iat: 1_710_000_100,
            exp: 1_710_000_400,
            jti: "oid4vp-1".to_string(),
            request_uri: "https://verifier.example.com/v1/public/passport/oid4vp/requests/oid4vp-1"
                .to_string(),
            dcql_query: Oid4vpDcqlQuery {
                credentials: vec![Oid4vpRequestedCredential {
                    id: "chio-passport".to_string(),
                    format: CHIO_PASSPORT_SD_JWT_VC_FORMAT.to_string(),
                    vct: CHIO_PASSPORT_SD_JWT_VC_TYPE.to_string(),
                    claims: vec!["chio_issuer_dids".to_string()],
                    issuer_allowlist: vec!["https://trust.example.com".to_string()],
                }],
            },
            identity_assertion: Some(ChioIdentityAssertion {
                verifier_id: "https://verifier.example.com".to_string(),
                subject: "alice@example.com".to_string(),
                continuity_id: "session-123".to_string(),
                issued_at: 1_710_000_100,
                expires_at: 1_710_000_300,
                provider: Some("oidc".to_string()),
                session_hint: Some("resume".to_string()),
                bound_request_id: Some("wrong-request".to_string()),
            }),
        };

        let error = request
            .validate(1_710_000_150)
            .expect_err("mismatched bound_request_id should fail");
        assert!(error.to_string().contains("bound_request_id"));
    }

    #[test]
    fn passport_lifecycle_validation_rejects_contradictory_fields() {
        let subject = Keypair::from_seed(&[3u8; 32]);
        let issuer = Keypair::from_seed(&[4u8; 32]);
        let invalid_record = PassportLifecycleRecord {
            passport_id: "sha256:test".to_string(),
            subject: did_from_public_key(subject.public_key()).to_string(),
            issuers: vec![did_from_public_key(issuer.public_key()).to_string()],
            issuer_count: 1,
            published_at: 1_710_000_000,
            updated_at: 1_710_000_000,
            status: PassportLifecycleState::Active,
            superseded_by: Some("sha256:newer".to_string()),
            revoked_at: None,
            revoked_reason: None,
            distribution: PassportStatusDistribution::default(),
            valid_until: "2026-03-28T00:00:00Z".to_string(),
        };
        let error = invalid_record
            .validate()
            .expect_err("contradictory active lifecycle should fail");
        assert!(matches!(
            error,
            CredentialError::InvalidPassportLifecycle(_)
        ));

        let invalid_resolution = PassportLifecycleResolution {
            passport_id: "sha256:test".to_string(),
            subject: String::new(),
            issuers: Vec::new(),
            issuer_count: 0,
            state: PassportLifecycleState::NotFound,
            published_at: None,
            updated_at: None,
            superseded_by: None,
            revoked_at: None,
            revoked_reason: None,
            distribution: PassportStatusDistribution {
                resolve_urls: vec![
                    "https://trust.example.com/v1/public/passport/statuses/resolve".to_string(),
                ],
                cache_ttl_secs: Some(300),
            },
            valid_until: String::new(),
            source: None,
        };
        let error = invalid_resolution
            .validate()
            .expect_err("not-found lifecycle with distribution should fail");
        assert!(matches!(
            error,
            CredentialError::InvalidPassportLifecycle(_)
        ));

        let invalid_distribution = PassportStatusDistribution {
            resolve_urls: vec![
                "https://trust.example.com/v1/public/passport/statuses/resolve".to_string(),
            ],
            cache_ttl_secs: None,
        };
        let error = invalid_distribution
            .validate()
            .expect_err("distribution without ttl should fail");
        assert!(matches!(
            error,
            CredentialError::InvalidPassportLifecycle(_)
        ));
    }

    /// Passport revocation bridge: a Revoked PassportLifecycleRecord
    /// projects into a chio_revocation_oracle::PassportRevocationEvent
    /// that the oracle can ingest, while non-revoked states project to
    /// None. The projection is read-only on the credentials side so it
    /// cannot regress the named `property_passport` invariants.
    #[test]
    fn revoked_lifecycle_record_projects_into_oracle_bridge_event() {
        let subject = Keypair::from_seed(&[5u8; 32]);
        let issuer = Keypair::from_seed(&[6u8; 32]);
        let record = PassportLifecycleRecord {
            passport_id: "sha256:revoked-passport".to_string(),
            subject: did_from_public_key(subject.public_key()).to_string(),
            issuers: vec![did_from_public_key(issuer.public_key()).to_string()],
            issuer_count: 1,
            published_at: 1_710_000_000,
            updated_at: 1_710_000_500,
            status: PassportLifecycleState::Revoked,
            superseded_by: None,
            revoked_at: Some(1_710_000_500),
            revoked_reason: Some("compromised key material".to_string()),
            distribution: PassportStatusDistribution::default(),
            valid_until: "2026-03-28T00:00:00Z".to_string(),
        };
        let event = record
            .to_revocation_event()
            .expect("revoked record projects without bridge error")
            .expect("revoked record projects into Some(_)");
        assert_eq!(event.passport_id, record.passport_id);
        assert_eq!(event.subject, record.subject);
        assert_eq!(event.revoked_at_unix_ms, 1_710_000_500);
        assert_eq!(
            event.revoked_reason.as_deref(),
            Some("compromised key material")
        );
    }

    #[test]
    fn non_revoked_lifecycle_record_projects_into_none() {
        let subject = Keypair::from_seed(&[7u8; 32]);
        let issuer = Keypair::from_seed(&[8u8; 32]);
        let record = PassportLifecycleRecord {
            passport_id: "sha256:active-passport".to_string(),
            subject: did_from_public_key(subject.public_key()).to_string(),
            issuers: vec![did_from_public_key(issuer.public_key()).to_string()],
            issuer_count: 1,
            published_at: 1_710_000_000,
            updated_at: 1_710_000_000,
            status: PassportLifecycleState::Active,
            superseded_by: None,
            revoked_at: None,
            revoked_reason: None,
            distribution: PassportStatusDistribution::default(),
            valid_until: "2026-03-28T00:00:00Z".to_string(),
        };
        let projection = record
            .to_revocation_event()
            .expect("active record never errors at the bridge");
        assert!(projection.is_none(), "active records do not produce events");
    }
}
