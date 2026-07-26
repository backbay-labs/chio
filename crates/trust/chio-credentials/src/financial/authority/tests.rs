use super::*;
use std::cell::RefCell;

const NOW: u64 = 1_710_000_100;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn did(keypair: &Keypair) -> TestResult<String> {
    Ok(DidChio::from_public_key(keypair.public_key())?.to_string())
}

fn digest(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn decision(
    signer: &Keypair,
    verifier_id: &str,
    signer_key_epoch: u64,
) -> TestResult<SignedEntryActivationDecisionV2> {
    Ok(sign_entry_activation_decision_v2(
        signer,
        EntryActivationDecisionInputV2 {
            pack_id: "pack-1".to_string(),
            verifier_id: verifier_id.to_string(),
            signer_key_id: "verifier-key".to_string(),
            signer_key_epoch,
            entry_id: "entry-1".to_string(),
            source_passport_id: digest(1),
            source_manifest_digest: digest(2),
            presentation_digest: digest(3),
            credential_bindings: vec![EntryActivationCredentialBindingV2 {
                credential_id: digest(4),
                family: FinancialCredentialFamilyV1::PremiumHistory,
                envelope_digest: digest(5),
            }],
            issuer: did(&Keypair::from_seed(&[61; 32]))?,
            profile_family: "financial".to_string(),
            source_kind: CrossIssuerPortfolioEntryKind::Imported,
            certification_refs: vec!["cert-1".to_string()],
            lifecycle_evidence_digest: digest(6),
            lifecycle_pin_digest: digest(7),
            migration_envelope_digests: Vec::new(),
            decision: EntryActivationDispositionV2::Activate,
            reason: "locally admitted".to_string(),
            decided_at: NOW,
        },
    )?)
}

fn verifier_registry(
    verifier: &Keypair,
    verifier_id: &str,
    epoch: u64,
    status: TrustedKeyStatusV2,
) -> TestResult<CrossIssuerTrustRegistryV2> {
    Ok(CrossIssuerTrustRegistryV2::new(
        CrossIssuerTrustRegistryConfigV2 {
            verifier_keys: vec![VerifierTrustKeyV2 {
                verifier_id: verifier_id.to_string(),
                signer_key_id: "verifier-key".to_string(),
                signer_key_epoch: epoch,
                public_key: verifier.public_key(),
                status,
            }],
            ..CrossIssuerTrustRegistryConfigV2::default()
        },
    )?)
}

fn pack(
    signer: &Keypair,
    verifier_id: &str,
    epoch: u64,
) -> TestResult<SignedCrossIssuerTrustPackV2> {
    Ok(sign_cross_issuer_trust_pack_v2(
        signer,
        CrossIssuerTrustPackInputV2 {
            pack_id: "pack-1".to_string(),
            verifier_id: verifier_id.to_string(),
            signer_key_id: "verifier-key".to_string(),
            signer_key_epoch: epoch,
            created_at: NOW - 10,
            expires_at: NOW + 100,
            policy: CrossIssuerTrustPackPolicyV2::default(),
            decisions: vec![decision(signer, verifier_id, epoch)?],
        },
    )?)
}

#[test]
fn self_consistent_unregistered_trust_pack_never_roots_authority() -> TestResult {
    let trusted = Keypair::from_seed(&[62; 32]);
    let attacker = Keypair::from_seed(&[63; 32]);
    let registry = verifier_registry(&trusted, "verifier-a", 4, TrustedKeyStatusV2::Active)?;
    let attacker_pack = pack(&attacker, "verifier-a", 4)?;

    assert!(matches!(
        verify_signed_cross_issuer_trust_pack_v2(&attacker_pack, &registry, NOW),
        Err(CredentialError::FinancialAuthority(reason))
            if reason.contains("trusted verifier key")
    ));
    Ok(())
}

#[test]
fn unknown_or_inactive_verifier_epoch_is_rejected() -> TestResult {
    let verifier = Keypair::from_seed(&[64; 32]);
    let signed = pack(&verifier, "verifier-a", 5)?;
    let unknown = verifier_registry(&verifier, "verifier-a", 4, TrustedKeyStatusV2::Active)?;
    let inactive = verifier_registry(&verifier, "verifier-a", 5, TrustedKeyStatusV2::Inactive)?;

    for registry in [&unknown, &inactive] {
        assert!(matches!(
            verify_signed_cross_issuer_trust_pack_v2(&signed, registry, NOW),
            Err(CredentialError::FinancialAuthority(_))
        ));
    }
    let active = verifier_registry(&verifier, "verifier-a", 5, TrustedKeyStatusV2::Active)?;
    assert!(
        verify_signed_cross_issuer_trust_pack_v2(&signed, &active, signed.body.expires_at,)
            .is_err()
    );
    Ok(())
}

#[test]
fn manifest_authority_resolves_independently_to_one_active_local_key() -> TestResult {
    let issuer = Keypair::from_seed(&[74; 32]);
    let issuer_did = did(&issuer)?;
    let verification_method = DidChio::from_str(&issuer_did)?.verification_method_id();
    let registry = CrossIssuerTrustRegistryV2::new(CrossIssuerTrustRegistryConfigV2 {
        issuer_keys: vec![IssuerTrustKeyV2 {
            issuer_did: issuer_did.clone(),
            verification_method: verification_method.clone(),
            key_epoch: 9,
            public_key: issuer.public_key(),
            status: TrustedKeyStatusV2::Active,
        }],
        ..CrossIssuerTrustRegistryConfigV2::default()
    })?;

    assert_eq!(
        registry
            .manifest_issuer_key(&issuer_did, &issuer.public_key())?
            .key_epoch,
        9
    );
    assert!(registry
        .manifest_issuer_key(&issuer_did, &Keypair::from_seed(&[75; 32]).public_key())
        .is_err());

    let ambiguous = CrossIssuerTrustRegistryV2::new(CrossIssuerTrustRegistryConfigV2 {
        issuer_keys: vec![
            IssuerTrustKeyV2 {
                issuer_did: issuer_did.clone(),
                verification_method: verification_method.clone(),
                key_epoch: 9,
                public_key: issuer.public_key(),
                status: TrustedKeyStatusV2::Active,
            },
            IssuerTrustKeyV2 {
                issuer_did: issuer_did.clone(),
                verification_method,
                key_epoch: 10,
                public_key: issuer.public_key(),
                status: TrustedKeyStatusV2::Active,
            },
        ],
        ..CrossIssuerTrustRegistryConfigV2::default()
    })?;
    assert!(ambiguous
        .manifest_issuer_key(&issuer_did, &issuer.public_key())
        .is_err());
    Ok(())
}

#[derive(Clone)]
struct FixedClock(u64);

impl TrustedClock for FixedClock {
    fn now(&self) -> Result<u64, FinancialAuthorityAvailabilityError> {
        Ok(self.0)
    }
}

struct ResolverFixture {
    checkpoint: RefCell<Option<SignedIssuerLifecycleCheckpointV2>>,
    result: RefCell<Option<SignedCrossIssuerLifecycleResultV2>>,
    unavailable: RefCell<bool>,
}

impl ResolverFixture {
    fn set(
        &self,
        checkpoint: SignedIssuerLifecycleCheckpointV2,
        result: SignedCrossIssuerLifecycleResultV2,
    ) {
        *self.checkpoint.borrow_mut() = Some(checkpoint);
        *self.result.borrow_mut() = Some(result);
    }
}

impl CrossIssuerLifecycleResolver for ResolverFixture {
    fn issuer_checkpoint(
        &self,
        _resolver_identity: &str,
        _issuer_did: &str,
        _now: u64,
    ) -> Result<SignedIssuerLifecycleCheckpointV2, FinancialAuthorityAvailabilityError> {
        if *self.unavailable.borrow() {
            return Err(FinancialAuthorityAvailabilityError::Unavailable);
        }
        self.checkpoint
            .borrow()
            .clone()
            .ok_or(FinancialAuthorityAvailabilityError::Unavailable)
    }

    fn passport_result(
        &self,
        _resolver_identity: &str,
        _issuer_did: &str,
        _source_passport_id: &str,
        _now: u64,
    ) -> Result<SignedCrossIssuerLifecycleResultV2, FinancialAuthorityAvailabilityError> {
        if *self.unavailable.borrow() {
            return Err(FinancialAuthorityAvailabilityError::Unavailable);
        }
        self.result
            .borrow()
            .clone()
            .ok_or(FinancialAuthorityAvailabilityError::Unavailable)
    }
}

struct GenerationAnchorFixture {
    signer: Keypair,
    anchor_id: String,
    key_epoch: u64,
    current: RefCell<Option<SignedIssuerLifecycleGenerationPinV2>>,
    unavailable: RefCell<bool>,
}

impl CrossIssuerLifecycleGenerationAnchor for GenerationAnchorFixture {
    fn compare_and_swap(
        &self,
        checkpoint: &SignedIssuerLifecycleCheckpointV2,
    ) -> Result<SignedIssuerLifecycleGenerationPinV2, FinancialAuthorityAvailabilityError> {
        if *self.unavailable.borrow() {
            return Err(FinancialAuthorityAvailabilityError::Unavailable);
        }
        let previous = self.current.borrow().clone();
        if let Some(previous) = previous.as_ref() {
            if checkpoint.body.store_generation < previous.body.store_generation {
                return Err(FinancialAuthorityAvailabilityError::Stale);
            }
            if checkpoint.body.store_generation == previous.body.store_generation
                && checkpoint.body.checkpoint_digest != previous.body.checkpoint_digest
            {
                return Err(FinancialAuthorityAvailabilityError::Conflict);
            }
            if checkpoint.body.checkpoint_digest == previous.body.checkpoint_digest {
                return Ok(previous.clone());
            }
        }
        let pin = sign_issuer_lifecycle_generation_pin_v2(
            &self.signer,
            &self.anchor_id,
            self.key_epoch,
            checkpoint,
            previous.as_ref().map(|pin| pin.body.pin_digest.as_str()),
        )
        .map_err(|_| FinancialAuthorityAvailabilityError::Conflict)?;
        *self.current.borrow_mut() = Some(pin.clone());
        Ok(pin)
    }
}

struct HighWaterFixture {
    signer: Keypair,
    store_id: String,
    key_epoch: u64,
    current: RefCell<Option<SignedLifecycleCheckpointPinV2>>,
    unavailable: RefCell<bool>,
}

impl CrossIssuerLifecycleHighWaterStore for HighWaterFixture {
    fn compare_and_swap(
        &self,
        candidate: &LifecycleCheckpointPinCandidateV2,
    ) -> Result<SignedLifecycleCheckpointPinV2, FinancialAuthorityAvailabilityError> {
        if *self.unavailable.borrow() {
            return Err(FinancialAuthorityAvailabilityError::Unavailable);
        }
        let previous = self.current.borrow().clone();
        if let Some(previous) = previous.as_ref() {
            if candidate.store_generation < previous.body.store_generation
                || candidate.status_version < previous.body.status_version
                || candidate.trusted_clock_high_water < previous.body.trusted_clock_high_water
            {
                return Err(FinancialAuthorityAvailabilityError::Stale);
            }
            if candidate.status_version == previous.body.status_version
                && (candidate.status != previous.body.status
                    || candidate.result_digest != previous.body.result_digest)
            {
                return Err(FinancialAuthorityAvailabilityError::Conflict);
            }
            if candidate.result_digest == previous.body.result_digest {
                return Ok(previous.clone());
            }
        }
        let pin = sign_lifecycle_checkpoint_pin_v2(
            &self.signer,
            &self.store_id,
            self.key_epoch,
            candidate,
            previous.as_ref().map(|pin| pin.body.pin_digest.as_str()),
        )
        .map_err(|_| FinancialAuthorityAvailabilityError::Conflict)?;
        *self.current.borrow_mut() = Some(pin.clone());
        Ok(pin)
    }
}

struct LifecycleFixture {
    resolver_key: Keypair,
    issuer_did: String,
    source_passport_id: String,
    manifest_digest: String,
    resolver: ResolverFixture,
    generation_anchor: GenerationAnchorFixture,
    high_water: HighWaterFixture,
    trust: CrossIssuerTrustRegistryV2,
}

impl LifecycleFixture {
    fn new() -> TestResult<Self> {
        let issuer = Keypair::from_seed(&[65; 32]);
        let resolver_key = Keypair::from_seed(&[66; 32]);
        let anchor_key = Keypair::from_seed(&[67; 32]);
        let high_water_key = Keypair::from_seed(&[68; 32]);
        let issuer_did = did(&issuer)?;
        let trust = CrossIssuerTrustRegistryV2::new(CrossIssuerTrustRegistryConfigV2 {
            issuer_keys: vec![IssuerTrustKeyV2 {
                issuer_did: issuer_did.clone(),
                verification_method: DidChio::from_str(&issuer_did)?.verification_method_id(),
                key_epoch: 3,
                public_key: issuer.public_key(),
                status: TrustedKeyStatusV2::Active,
            }],
            lifecycle_resolver_keys: vec![LifecycleResolverTrustKeyV2 {
                resolver_identity: "resolver-a".to_string(),
                signer_key_id: "resolver-key".to_string(),
                signer_key_epoch: 2,
                public_key: resolver_key.public_key(),
                status: TrustedKeyStatusV2::Active,
            }],
            lifecycle_generation_anchor_keys: vec![LifecycleGenerationAnchorTrustKeyV2 {
                anchor_id: "anchor-a".to_string(),
                signer_key_epoch: 4,
                public_key: anchor_key.public_key(),
                status: TrustedKeyStatusV2::Active,
            }],
            lifecycle_high_water_keys: vec![LifecycleHighWaterTrustKeyV2 {
                store_id: "high-water-a".to_string(),
                signer_key_epoch: 5,
                public_key: high_water_key.public_key(),
                status: TrustedKeyStatusV2::Active,
            }],
            ..CrossIssuerTrustRegistryConfigV2::default()
        })?;
        Ok(Self {
            resolver_key: resolver_key.clone(),
            issuer_did,
            source_passport_id: digest(10),
            manifest_digest: digest(11),
            resolver: ResolverFixture {
                checkpoint: RefCell::new(None),
                result: RefCell::new(None),
                unavailable: RefCell::new(false),
            },
            generation_anchor: GenerationAnchorFixture {
                signer: anchor_key,
                anchor_id: "anchor-a".to_string(),
                key_epoch: 4,
                current: RefCell::new(None),
                unavailable: RefCell::new(false),
            },
            high_water: HighWaterFixture {
                signer: high_water_key,
                store_id: "high-water-a".to_string(),
                key_epoch: 5,
                current: RefCell::new(None),
                unavailable: RefCell::new(false),
            },
            trust,
        })
    }

    fn set_status(
        &self,
        generation: u64,
        version: u64,
        status: CrossIssuerLifecycleStatusV2,
        predecessor_checkpoint_digest: Option<String>,
    ) -> TestResult {
        let snapshot = sign_single_passport_lifecycle_snapshot_v2(
            &self.resolver_key,
            SinglePassportLifecycleSnapshotInputV2 {
                resolver_identity: "resolver-a".to_string(),
                signer_key_id: "resolver-key".to_string(),
                signer_key_epoch: 2,
                issuer_did: self.issuer_did.clone(),
                store_generation: generation,
                status_version: version,
                status,
                source_passport_id: self.source_passport_id.clone(),
                source_manifest_digest: self.manifest_digest.clone(),
                effective_at: NOW - 1,
                trusted_clock_high_water: NOW,
                predecessor_checkpoint_digest,
            },
        )?;
        self.resolver.set(snapshot.checkpoint, snapshot.result);
        Ok(())
    }

    fn resolve(&self) -> Result<VerifiedCrossIssuerLifecycleV2, CredentialError> {
        resolve_cross_issuer_lifecycle_v2(
            "resolver-a",
            &self.issuer_did,
            &self.source_passport_id,
            &self.manifest_digest,
            &self.trust,
            &self.resolver,
            &self.generation_anchor,
            &self.high_water,
            &FixedClock(NOW),
        )
    }
}

fn verified_financial_set_fixture() -> TestResult<VerifiedFinancialCredentialSet> {
    Ok(VerifiedFinancialCredentialSet {
        source_passport_id: digest(1),
        source_manifest_digest: digest(2),
        presentation_digest: digest(3),
        credentials: vec![VerifiedFinancialCredentialBindingV2 {
            credential_id: digest(4),
            family: FinancialCredentialFamilyV1::PremiumHistory,
            issuer: did(&Keypair::from_seed(&[61; 32]))?,
            issuer_key_epoch: 1,
            body_digest: digest(8),
            envelope_digest: digest(5),
            source_evidence_class:
                chio_core::capability::governance::ProvenanceEvidenceClass::Asserted,
            presentation_evidence_class:
                chio_core::capability::governance::ProvenanceEvidenceClass::Asserted,
            source_proof_digests: vec![digest(9)],
        }],
        policy_id: "policy-a".to_string(),
        policy_body_digest: digest(10),
        policy_generation: 1,
        lifecycle_generation: 1,
        lifecycle_status_version: 1,
        lifecycle_result_digest: digest(6),
        lifecycle_generation_pin_digest: digest(11),
        lifecycle_checkpoint_pin_digest: digest(7),
        lifecycle_checkpoint_digest: digest(12),
        lifecycle_source_index_proof_digest: digest(13),
    })
}

fn financial_policy() -> TestResult<FinancialVerifierPolicyV1> {
    Ok(create_financial_verifier_policy_v1(
        FinancialVerifierPolicyInputV1 {
            policy_id: "policy-a".to_string(),
            tenant: "tenant-a".to_string(),
            verifier: "verifier-a".to_string(),
            accepted_issuers: BTreeSet::from([did(&Keypair::from_seed(&[61; 32]))?]),
            accepted_families: BTreeSet::from([FinancialCredentialFamilyV1::PremiumHistory]),
            thresholds: FinancialVerifierThresholdsV1 {
                min_credit_score: None,
                max_open_exposure_ratio_bps: None,
                min_settlement_reliability_bps: None,
                max_loss_event_count: None,
                max_premium_units_by_currency: BTreeMap::new(),
            },
            max_credential_age_seconds: 300,
            not_before: NOW - 10,
            expires_at: NOW + 10,
            configuration_generation: 7,
        },
    )?)
}

#[test]
fn policy_resolution_pins_exact_pointer_generation_scope_and_time() -> TestResult {
    let policy = financial_policy()?;
    let activation = FinancialVerifierPolicyActivationV1 {
        tenant: policy.tenant.clone(),
        verifier: policy.verifier.clone(),
        policy_id: policy.policy_id.clone(),
        configuration_generation: policy.configuration_generation,
        body_digest: policy.body_digest.clone(),
    };
    let registry =
        FinancialVerifierPolicyRegistry::new(vec![policy.clone()], vec![activation.clone()])?;

    assert_eq!(
        registry
            .resolve("tenant-a", "verifier-a", NOW)?
            .body_digest(),
        policy.body_digest
    );
    assert!(registry.resolve("tenant-a", "verifier-b", NOW).is_err());
    assert!(registry
        .resolve("tenant-a", "verifier-a", policy.not_before - 1)
        .is_err());
    assert!(registry
        .resolve("tenant-a", "verifier-a", policy.expires_at)
        .is_err());

    let mut wrong_generation = activation.clone();
    wrong_generation.configuration_generation += 1;
    assert!(
        FinancialVerifierPolicyRegistry::new(vec![policy.clone()], vec![wrong_generation],)
            .is_err()
    );
    let mut wrong_body = activation;
    wrong_body.body_digest = digest(99);
    assert!(FinancialVerifierPolicyRegistry::new(vec![policy], vec![wrong_body]).is_err());
    Ok(())
}

#[test]
fn revocation_is_pinned_before_denial_and_stale_active_cannot_reopen() -> TestResult {
    let fixture = LifecycleFixture::new()?;
    fixture.set_status(1, 10, CrossIssuerLifecycleStatusV2::Active, None)?;
    fixture.resolve()?;
    let predecessor = fixture
        .generation_anchor
        .current
        .borrow()
        .as_ref()
        .map(|pin| pin.body.checkpoint_digest.clone());
    fixture.set_status(2, 11, CrossIssuerLifecycleStatusV2::Revoked, predecessor)?;
    assert!(matches!(
        fixture.resolve(),
        Err(CredentialError::FinancialAuthority(reason)) if reason.contains("not active")
    ));
    assert_eq!(
        fixture
            .high_water
            .current
            .borrow()
            .as_ref()
            .map(|pin| pin.body.status),
        Some(CrossIssuerLifecycleStatusV2::Revoked)
    );
    fixture.set_status(1, 10, CrossIssuerLifecycleStatusV2::Active, None)?;
    assert!(matches!(
        fixture.resolve(),
        Err(CredentialError::FinancialAuthority(reason)) if reason.contains("generation anchor")
    ));
    Ok(())
}

#[test]
fn generation_rollback_and_same_generation_conflict_deny_before_lookup() -> TestResult {
    let fixture = LifecycleFixture::new()?;
    fixture.set_status(2, 10, CrossIssuerLifecycleStatusV2::Active, None)?;
    fixture.resolve()?;
    fixture.set_status(1, 11, CrossIssuerLifecycleStatusV2::Active, None)?;
    assert!(fixture.resolve().is_err());
    fixture.set_status(2, 12, CrossIssuerLifecycleStatusV2::Active, None)?;
    assert!(fixture.resolve().is_err());
    Ok(())
}

#[test]
fn resolver_and_high_water_outage_fail_closed() -> TestResult {
    let fixture = LifecycleFixture::new()?;
    fixture.set_status(1, 10, CrossIssuerLifecycleStatusV2::Active, None)?;
    *fixture.resolver.unavailable.borrow_mut() = true;
    assert!(fixture.resolve().is_err());
    *fixture.resolver.unavailable.borrow_mut() = false;
    *fixture.high_water.unavailable.borrow_mut() = true;
    assert!(fixture.resolve().is_err());
    Ok(())
}

#[test]
fn migration_envelope_substitution_is_rejected() -> TestResult {
    let attester = Keypair::from_seed(&[69; 32]);
    let verifier = Keypair::from_seed(&[70; 32]);
    let verifier_id = "verifier-a";
    let registry = CrossIssuerTrustRegistryV2::new(CrossIssuerTrustRegistryConfigV2 {
        verifier_keys: verifier_registry(&verifier, verifier_id, 4, TrustedKeyStatusV2::Active)?
            .verifier_keys(),
        migration_attester_keys: vec![MigrationAttesterTrustKeyV2 {
            attester_id: "attester-a".to_string(),
            signer_key_id: "migration-key".to_string(),
            signer_key_epoch: 9,
            public_key: attester.public_key(),
            status: TrustedKeyStatusV2::Active,
        }],
        activation_metadata: vec![IssuerActivationMetadataV2 {
            issuer_did: did(&Keypair::from_seed(&[61; 32]))?,
            profile_family: "financial".to_string(),
            source_kind: CrossIssuerPortfolioEntryKind::Imported,
            certification_refs: vec!["cert-1".to_string()],
        }],
        ..CrossIssuerTrustRegistryConfigV2::default()
    })?;
    let migration_a = sign_cross_issuer_migration_v2(
        &attester,
        CrossIssuerMigrationInputV2 {
            migration_id: "migration-a".to_string(),
            attester_id: "attester-a".to_string(),
            signer_key_id: "migration-key".to_string(),
            signer_key_epoch: 9,
            from_issuer: did(&Keypair::from_seed(&[61; 32]))?,
            to_issuer: did(&Keypair::from_seed(&[71; 32]))?,
            from_subject: did(&Keypair::from_seed(&[72; 32]))?,
            to_subject: did(&Keypair::from_seed(&[73; 32]))?,
            prior_source_passport_ids: vec![digest(1)],
            reason: "rotation".to_string(),
            continuity_ref: "continuity-a".to_string(),
            issued_at: NOW - 10,
            expires_at: Some(NOW + 100),
        },
    )?;
    let migration_b = sign_cross_issuer_migration_v2(
        &attester,
        CrossIssuerMigrationInputV2 {
            migration_id: "migration-b".to_string(),
            ..migration_a.body.clone().into_input()
        },
    )?;
    let mut activation = decision(&verifier, verifier_id, 4)?;
    activation.body.migration_envelope_digests = vec![signed_envelope_digest(&migration_a)?];
    activation =
        sign_entry_activation_decision_v2(&verifier, activation.body.clone().into_input())?;
    let signed_pack = sign_cross_issuer_trust_pack_v2(
        &verifier,
        CrossIssuerTrustPackInputV2 {
            pack_id: "pack-1".to_string(),
            verifier_id: verifier_id.to_string(),
            signer_key_id: "verifier-key".to_string(),
            signer_key_epoch: 4,
            created_at: NOW - 10,
            expires_at: NOW + 100,
            policy: CrossIssuerTrustPackPolicyV2::default(),
            decisions: vec![activation.clone()],
        },
    )?;

    assert!(matches!(
        verify_entry_activation_decision_v2(
            &signed_pack,
            &activation,
            &verified_financial_set_fixture()?,
            &registry,
            std::slice::from_ref(&migration_b),
            NOW,
        ),
        Err(CredentialError::FinancialAuthority(reason))
            if reason.contains("migration")
    ));
    Ok(())
}

#[test]
fn v1_production_activation_is_unconditionally_unsupported() {
    assert!(matches!(
        reject_legacy_cross_issuer_v1_activation(),
        Err(CredentialError::UnsupportedLegacyCrossIssuerV1)
    ));
}
