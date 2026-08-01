use std::collections::BTreeMap;
use std::io;
use std::sync::Mutex;

use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde_json::Value;

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn key(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

fn runtime_registry(version: &str) -> TestResult<FiscalRuntimeAdapterRegistry> {
    FiscalRuntimeAdapterRegistry::new(
        format!("build-{version}"),
        "chio.fiscal.runtime.v1".to_owned(),
        (0..FISCAL_RUNTIME_ADAPTER_COUNT)
            .rev()
            .map(|index| {
                FiscalRuntimeAdapter::new(format!("adapter-{index}"), format!("{version}.{index}"))
            })
            .collect::<Result<Vec<_>, _>>()?,
    )
    .map_err(Into::into)
}

fn fiscal_fixture(name: &str) -> TestResult<Value> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../spec/schemas/chio-fiscal/v1/fixtures/{name}.positive.json"
    ));
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn assert_fiscal_fixture<T: serde::Serialize>(name: &str, expected: &T) -> TestResult {
    let actual = fiscal_fixture(name)?;
    let canonical_expected: Value = serde_json::from_slice(&canonical_json_bytes(expected)?)?;
    assert_eq!(actual, canonical_expected, "{name} fixture drifted");
    Ok(())
}

fn verify_fiscal_fixture_signature(name: &str) -> TestResult {
    let mut fixture = fiscal_fixture(name)?;
    let envelope: SignedExportEnvelope<Value> = serde_json::from_value(fixture.clone())?;
    assert!(envelope.verify_signature()?, "{name} signature is invalid");

    let fixture = fixture
        .as_object_mut()
        .ok_or_else(|| io::Error::other("signed fiscal fixture must be an object"))?;
    let signature = fixture
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::other("signed fiscal fixture must have a signature"))?;
    let last = signature
        .as_bytes()
        .last()
        .copied()
        .ok_or_else(|| io::Error::other("fiscal fixture signature must not be empty"))?;
    let mut signature = signature.to_owned();
    let last_index = signature.len() - 1;
    signature.replace_range(last_index.., if last == b'0' { "1" } else { "0" });
    fixture.insert("signature".to_owned(), signature.into());

    let envelope: SignedExportEnvelope<Value> =
        serde_json::from_value(Value::Object(fixture.clone()))?;
    assert!(
        !envelope.verify_signature()?,
        "{name} accepted a tampered signature"
    );
    Ok(())
}

fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_owned(),
    }
}

fn tier_params() -> FiscalParams {
    FiscalParams::TierLimits {
        ceilings: [usd(100), usd(200), usd(300), usd(400)],
    }
}

fn charter() -> TestResult<VerifiedFiscalCharter> {
    Ok(VerifiedFiscalCharter::verify(
        FiscalCharterBuilder {
            governing_operator_id: "operator.example".to_owned(),
            governed_domains: vec![
                FiscalDomain::TierLimits,
                FiscalDomain::MarketplaceDiscountPerHundred,
                FiscalDomain::DecisionPremiumBasisPoints,
                FiscalDomain::InsurancePremiumSchedule,
                FiscalDomain::OpenMarketFeeAndBondSchedule,
            ],
            signer_keys: vec![key(1).public_key(), key(2).public_key()],
            approval_threshold: 2,
            timelock_seconds: 10,
            proposal_ttl_seconds: 100,
            approval_ttl_seconds: 50,
            issued_at: 10,
            expires_at: 1_000,
            issued_by: "operator.example".to_owned(),
            sequence: 1,
            predecessor_charter_digest: None,
        }
        .sign(&key(9))?,
    )?)
}

fn schedule(
    charter: &VerifiedFiscalCharter,
    predecessor: Option<&VerifiedFiscalSchedule>,
) -> TestResult<VerifiedFiscalSchedule> {
    Ok(VerifiedFiscalSchedule::verify(
        FiscalScheduleBuilder {
            domain: FiscalDomain::TierLimits,
            params: tier_params(),
            valid_from: 70,
            valid_until: 900,
            issued_at: 70,
            issued_by: "operator.example".to_owned(),
        }
        .sign(charter, predecessor, &key(9))?,
        charter,
        predecessor,
    )?)
}

struct AmendmentFixture {
    charter: VerifiedFiscalCharter,
    schedule: VerifiedFiscalSchedule,
    proposal: VerifiedFiscalProposal,
    admission: VerifiedFiscalProposalAdmission,
    admission_state: FiscalProposalAdmissionState,
    trust: FiscalAdmissionTrustRegistry,
    approvals: Vec<SignedFiscalApproval>,
    activation: VerifiedFiscalActivation,
}

fn amendment_fixture() -> TestResult<AmendmentFixture> {
    let charter = charter()?;
    let schedule = schedule(&charter, None)?;
    let proposal = VerifiedFiscalProposal::verify(
        FiscalProposalBuilder {
            target: FiscalProposalTarget::Schedule {
                candidate: Box::new(schedule.signed().clone()),
            },
            rationale_digest: digest("tier rationale"),
            proposed_at: 50,
        }
        .sign(&key(1))?,
        &charter,
        None,
    )?;
    let admission_key = key(7);
    let trust = FiscalAdmissionTrustRegistry::new(vec![FiscalAdmissionAuthority::new(
        "operator.example".to_owned(),
        "local-admission".to_owned(),
        1,
        admission_key.public_key(),
    )?])?;
    let admission = VerifiedFiscalProposalAdmission::verify(
        FiscalProposalAdmissionBuilder {
            admission_sequence: 1,
            admitted_at: 55,
            admission_authority_id: "local-admission".to_owned(),
            signer_key_epoch: 1,
        }
        .sign(&proposal, &charter, &admission_key)?,
        &proposal,
        &charter,
        &trust,
        55,
    )?;
    let admission_state = FiscalProposalAdmissionState::admitted(&admission);
    let approvals = [key(1), key(2)]
        .into_iter()
        .map(|signer| {
            FiscalApprovalBuilder { approved_at: 56 }.sign(&proposal, &admission, &charter, &signer)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let signed_activation = FiscalActivationBuilder {
        target: FiscalActivationTarget::Schedule {
            schedule_id: schedule.body().schedule_id.clone(),
            supersedes_schedule_id: None,
        },
        approvals: approvals.clone(),
        activated_at: 70,
    }
    .sign(&proposal, &admission, &charter, &key(1))?;
    let staged_activation = VerifiedFiscalActivation::verify(
        signed_activation.clone(),
        &proposal,
        &admission,
        &admission_state,
        &charter,
        &trust,
        None,
        &[],
        70,
    )?;
    let activated_admission_state = admission_state.activate(
        staged_activation.digest().to_owned(),
        schedule.body().sequence,
    )?;
    let activation = VerifiedFiscalActivation::verify(
        signed_activation,
        &proposal,
        &admission,
        &activated_admission_state,
        &charter,
        &trust,
        None,
        &[],
        70,
    )?;
    Ok(AmendmentFixture {
        charter,
        schedule,
        proposal,
        admission,
        admission_state,
        trust,
        approvals,
        activation,
    })
}

fn successor_amendment(
    predecessor: &VerifiedFiscalSchedule,
    charter: &VerifiedFiscalCharter,
    trust: &FiscalAdmissionTrustRegistry,
) -> TestResult<(VerifiedFiscalSchedule, VerifiedFiscalActivation)> {
    let schedule = schedule(charter, Some(predecessor))?;
    let proposal = VerifiedFiscalProposal::verify(
        FiscalProposalBuilder {
            target: FiscalProposalTarget::Schedule {
                candidate: Box::new(schedule.signed().clone()),
            },
            rationale_digest: digest("successor rationale"),
            proposed_at: 71,
        }
        .sign(&key(1))?,
        charter,
        Some(predecessor),
    )?;
    let admission_key = key(7);
    let admission = VerifiedFiscalProposalAdmission::verify(
        FiscalProposalAdmissionBuilder {
            admission_sequence: 2,
            admitted_at: 72,
            admission_authority_id: "local-admission".to_owned(),
            signer_key_epoch: 1,
        }
        .sign(&proposal, charter, &admission_key)?,
        &proposal,
        charter,
        trust,
        72,
    )?;
    let admission_state = FiscalProposalAdmissionState::admitted(&admission);
    let approvals = [key(1), key(2)]
        .into_iter()
        .map(|signer| {
            FiscalApprovalBuilder { approved_at: 73 }.sign(&proposal, &admission, charter, &signer)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let signed_activation = FiscalActivationBuilder {
        target: FiscalActivationTarget::Schedule {
            schedule_id: schedule.body().schedule_id.clone(),
            supersedes_schedule_id: Some(predecessor.body().schedule_id.clone()),
        },
        approvals,
        activated_at: 82,
    }
    .sign(&proposal, &admission, charter, &key(1))?;
    let staged = VerifiedFiscalActivation::verify(
        signed_activation.clone(),
        &proposal,
        &admission,
        &admission_state,
        charter,
        trust,
        Some(predecessor),
        &[],
        82,
    )?;
    let activated_state = admission_state.activate(staged.digest().to_owned(), 2)?;
    let activation = VerifiedFiscalActivation::verify(
        signed_activation,
        &proposal,
        &admission,
        &activated_state,
        charter,
        trust,
        Some(predecessor),
        &[],
        82,
    )?;
    Ok((schedule, activation))
}

struct ContinuityFixture {
    amendment: AmendmentFixture,
    policy: FiscalGenesisPolicy,
    readiness: VerifiedFiscalRuntimeReadiness,
    activation_history: FiscalActivationHistory,
    charters: FiscalCharterRegistry,
    anchor_key: Keypair,
    genesis: VerifiedFiscalContinuityCheckpoint,
    activated: VerifiedFiscalContinuityCheckpoint,
    authority: FiscalAuthorityState,
}

fn never_domains() -> Vec<FiscalDomainState> {
    [
        FiscalDomain::TierLimits,
        FiscalDomain::MarketplaceDiscountPerHundred,
        FiscalDomain::DecisionPremiumBasisPoints,
        FiscalDomain::InsurancePremiumSchedule,
        FiscalDomain::OpenMarketFeeAndBondSchedule,
    ]
    .into_iter()
    .map(FiscalDomainState::never_activated)
    .collect()
}

fn activated_domains(head: FiscalScheduleHead) -> TestResult<Vec<FiscalDomainState>> {
    let mut domains = never_domains();
    domains[0] = FiscalDomainState::activated(FiscalDomain::TierLimits, head.clone(), head)?;
    Ok(domains)
}

fn continuity_fixture() -> TestResult<ContinuityFixture> {
    let amendment = amendment_fixture()?;
    let anchor_key = key(8);
    let mut bootstrap = BTreeMap::new();
    bootstrap.insert("USD".to_owned(), [100, 200, 300, 400]);
    let policy = FiscalGenesisPolicy::new(
        "operator.example".to_owned(),
        &amendment.charter,
        key(9).public_key(),
        "fiscal-anchor".to_owned(),
        "fiscal-main".to_owned(),
        1,
        anchor_key.public_key(),
        bootstrap,
    )?;
    let runtime_registry = runtime_registry("1")?;
    let readiness = VerifiedFiscalRuntimeReadiness::verify(
        FiscalRuntimeReadinessBuilder {
            readiness_sequence: 1,
            runtime_registry: runtime_registry.clone(),
            attested_at: 55,
        }
        .sign(&policy, &anchor_key)?,
        &policy,
        runtime_registry,
    )?;
    let charters = FiscalCharterRegistry::new(vec![amendment.charter.signed().clone()])?;
    let genesis = VerifiedFiscalContinuityCheckpoint::verify(
        FiscalContinuityCheckpointBuilder {
            continuity_sequence: 0,
            previous_checkpoint_digest: None,
            pinned_charter_id: amendment.charter.body().charter_id.clone(),
            pinned_charter_digest: amendment.charter.digest().to_owned(),
            pinned_charter_sequence: amendment.charter.body().sequence,
            runtime_readiness_digest: readiness.digest().to_owned(),
            domains: never_domains(),
            trusted_clock_high_water: 55,
            staged_transition: None,
        }
        .sign(&policy, &anchor_key)?,
        &policy,
        &charters,
    )?;
    let head = FiscalScheduleHead::from_signed(amendment.schedule.signed())?;
    let transition = FiscalStagedTransition::new(
        amendment.activation.body().activation_id.clone(),
        amendment.activation.digest().to_owned(),
    )?;
    let next = FiscalContinuityCheckpointBuilder {
        continuity_sequence: 1,
        previous_checkpoint_digest: Some(genesis.digest().to_owned()),
        pinned_charter_id: amendment.charter.body().charter_id.clone(),
        pinned_charter_digest: amendment.charter.digest().to_owned(),
        pinned_charter_sequence: amendment.charter.body().sequence,
        runtime_readiness_digest: readiness.digest().to_owned(),
        domains: activated_domains(head.clone())?,
        trusted_clock_high_water: 70,
        staged_transition: Some(transition),
    }
    .sign(&policy, &anchor_key)?;
    let advance = VerifiedFiscalContinuityAdvance::verify(
        &genesis,
        next,
        &policy,
        &charters,
        &FiscalContinuityChange::Activation {
            activation: Box::new(amendment.activation.clone()),
            readiness: Box::new(readiness.clone()),
            domain: FiscalDomain::TierLimits,
            schedule: Box::new(amendment.schedule.clone()),
        },
    )?;
    let anchor = TestAnchor {
        state: Mutex::new(AnchorState::Available(Box::new(genesis.signed().clone()))),
    };
    let commit = commit_fiscal_continuity_advance(&anchor, advance, &policy, &charters)?;
    let activated = commit.checkpoint().clone();
    let activation_history =
        FiscalActivationHistory::new(vec![commit.into_activation_authority()?])?;
    let authority = FiscalAuthorityState::from_checkpoint(
        &policy,
        &activated,
        FiscalBootstrapState::CharterPinned,
    )?;
    Ok(ContinuityFixture {
        amendment,
        policy,
        readiness,
        activation_history,
        charters,
        anchor_key,
        genesis,
        activated,
        authority,
    })
}

#[test]
fn runtime_adapter_registry_is_exact_sorted_and_canonical() -> TestResult {
    let registry = runtime_registry("registry")?;
    assert_eq!(registry.adapters().len(), FISCAL_RUNTIME_ADAPTER_COUNT);
    assert!(registry
        .adapters()
        .windows(2)
        .all(|pair| pair[0].id < pair[1].id));

    let bytes = registry.canonical_bytes()?;
    let decoded = FiscalRuntimeAdapterRegistry::from_canonical_bytes(&bytes)?;
    assert_eq!(decoded, registry);
    assert_eq!(decoded.digest()?, registry.digest()?);

    let mut incomplete = registry.adapters().to_vec();
    incomplete.pop();
    assert!(FiscalRuntimeAdapterRegistry::new(
        registry.build_id().to_owned(),
        registry.schema_version().to_owned(),
        incomplete,
    )
    .is_err());

    let duplicate = FiscalRuntimeAdapter::new("duplicate".to_owned(), "1".to_owned())?;
    assert!(FiscalRuntimeAdapterRegistry::new(
        "build-duplicate".to_owned(),
        "chio.fiscal.runtime.v1".to_owned(),
        vec![duplicate; FISCAL_RUNTIME_ADAPTER_COUNT],
    )
    .is_err());
    Ok(())
}

#[test]
fn continuity_advance_retains_reverifiable_canonical_evidence() -> TestResult {
    let fixture = continuity_fixture()?;
    let change = FiscalContinuityChange::Activation {
        activation: Box::new(fixture.amendment.activation.clone()),
        readiness: Box::new(fixture.readiness.clone()),
        domain: FiscalDomain::TierLimits,
        schedule: Box::new(fixture.amendment.schedule.clone()),
    };
    let advance = VerifiedFiscalContinuityAdvance::verify(
        &fixture.genesis,
        fixture.activated.signed().clone(),
        &fixture.policy,
        &fixture.charters,
        &change,
    )?;
    advance.reverify(&fixture.policy, &fixture.charters)?;

    let repeated = VerifiedFiscalContinuityAdvance::verify(
        &fixture.genesis,
        fixture.activated.signed().clone(),
        &fixture.policy,
        &fixture.charters,
        &change,
    )?;
    assert_eq!(
        advance.canonical_proof_bytes(),
        repeated.canonical_proof_bytes()
    );

    let proof: Value = serde_json::from_slice(advance.canonical_proof_bytes())?;
    assert_eq!(proof["schema"], FISCAL_CONTINUITY_ADVANCE_PROOF_SCHEMA);
    assert_eq!(proof["change"]["kind"], "activation");
    assert_eq!(
        proof["change"]["readiness"]["body"]["readinessId"],
        fixture.readiness.body().readiness_id
    );
    assert_eq!(
        proof["change"]["schedule"]["body"]["scheduleId"],
        fixture.amendment.schedule.body().schedule_id
    );
    assert_eq!(
        proof["change"]["runtimeRegistry"]["adapters"]
            .as_array()
            .map(Vec::len),
        Some(FISCAL_RUNTIME_ADAPTER_COUNT)
    );
    Ok(())
}

#[test]
fn published_fiscal_fixtures_match_runtime_types_and_signatures() -> TestResult {
    let fixture = continuity_fixture()?;
    assert_fiscal_fixture("charter", fixture.amendment.charter.signed())?;
    assert_fiscal_fixture("schedule", fixture.amendment.schedule.signed())?;
    assert_fiscal_fixture("genesis-policy", &fixture.policy)?;
    assert_fiscal_fixture("proposal", fixture.amendment.proposal.signed())?;
    assert_fiscal_fixture("proposal-admission", fixture.amendment.admission.signed())?;
    assert_fiscal_fixture(
        "approval",
        &fixture.amendment.activation.body().approvals[0],
    )?;
    assert_fiscal_fixture("activation", fixture.amendment.activation.signed())?;
    assert_fiscal_fixture("consumer-readiness", fixture.readiness.signed())?;
    assert_fiscal_fixture("continuity-checkpoint", fixture.genesis.signed())?;

    for name in [
        "charter",
        "schedule",
        "proposal",
        "proposal-admission",
        "approval",
        "activation",
        "consumer-readiness",
        "continuity-checkpoint",
    ] {
        verify_fiscal_fixture_signature(name)?;
    }

    let mut policy = fixture.policy;
    let usd = policy
        .bootstrap_tier_limits
        .get_mut("USD")
        .ok_or_else(|| io::Error::other("fiscal fixture must have USD bootstrap limits"))?;
    usd[0] = 101;
    assert!(matches!(
        policy.validate(&fixture.amendment.charter),
        Err(FiscalError::InvalidSelfId)
    ));
    Ok(())
}

#[test]
fn genesis_policy_rejects_a_charter_signed_by_an_unpinned_authority() -> TestResult {
    let charter = charter()?;
    let mut bootstrap = BTreeMap::new();
    bootstrap.insert("USD".to_owned(), [100, 200, 300, 400]);

    assert!(matches!(
        FiscalGenesisPolicy::new(
            "operator.example".to_owned(),
            &charter,
            key(6).public_key(),
            "fiscal-anchor".to_owned(),
            "fiscal-main".to_owned(),
            1,
            key(8).public_key(),
            bootstrap,
        ),
        Err(FiscalError::InvalidField("genesis.bootstrap_authority_key"))
    ));
    Ok(())
}

#[test]
fn valid_amendment_requires_local_admission_and_current_charter_threshold() -> TestResult {
    let fixture = amendment_fixture()?;
    assert_eq!(fixture.activation.body().activated_at, 70);
    assert_eq!(fixture.activation.body().approvals.len(), 2);
    assert_eq!(
        fixture.activation.body().charter_digest,
        fixture.charter.digest()
    );
    assert!(VerifiedFiscalActivation::verify(
        fixture.activation.signed().clone(),
        &fixture.proposal,
        &fixture.admission,
        &fixture.admission_state,
        &fixture.charter,
        &fixture.trust,
        None,
        &[],
        70,
    )
    .is_ok());
    Ok(())
}

#[test]
fn committed_activation_authority_is_not_clone() {
    trait AmbiguousIfClone<A> {
        fn check() {}
    }

    impl<T: ?Sized> AmbiguousIfClone<()> for T {}

    struct CloneMarker;

    impl<T: Clone> AmbiguousIfClone<CloneMarker> for T {}

    let _ = <VerifiedFiscalActivationAuthority as AmbiguousIfClone<_>>::check;
}

#[test]
fn duplicate_nonmember_and_below_threshold_approvals_reject() -> TestResult {
    let fixture = amendment_fixture()?;
    assert!(FiscalActivationBuilder {
        target: fixture.activation.body().target.clone(),
        approvals: vec![fixture.approvals[0].clone(), fixture.approvals[0].clone()],
        activated_at: 70,
    }
    .sign(
        &fixture.proposal,
        &fixture.admission,
        &fixture.charter,
        &key(1),
    )
    .is_err());

    let below_threshold = FiscalActivationBuilder {
        target: fixture.activation.body().target.clone(),
        approvals: vec![fixture.approvals[0].clone()],
        activated_at: 70,
    }
    .sign(
        &fixture.proposal,
        &fixture.admission,
        &fixture.charter,
        &key(1),
    )?;
    assert!(VerifiedFiscalActivation::verify(
        below_threshold,
        &fixture.proposal,
        &fixture.admission,
        &fixture.admission_state,
        &fixture.charter,
        &fixture.trust,
        None,
        &[],
        70,
    )
    .is_err());

    let outsider = FiscalApprovalBuilder { approved_at: 56 }.sign(
        &fixture.proposal,
        &fixture.admission,
        &fixture.charter,
        &key(4),
    )?;
    assert!(VerifiedFiscalApproval::verify(
        outsider,
        &fixture.proposal,
        &fixture.admission,
        &fixture.charter,
        70,
    )
    .is_err());
    Ok(())
}

#[test]
fn timelock_approval_expiry_and_untrusted_admission_reject() -> TestResult {
    let fixture = amendment_fixture()?;
    let before_timelock = FiscalActivationBuilder {
        target: fixture.activation.body().target.clone(),
        approvals: fixture.approvals.clone(),
        activated_at: 64,
    }
    .sign(
        &fixture.proposal,
        &fixture.admission,
        &fixture.charter,
        &key(1),
    )?;
    assert!(VerifiedFiscalActivation::verify(
        before_timelock,
        &fixture.proposal,
        &fixture.admission,
        &fixture.admission_state,
        &fixture.charter,
        &fixture.trust,
        None,
        &[],
        64,
    )
    .is_err());

    let at_approval_expiry = FiscalActivationBuilder {
        target: fixture.activation.body().target.clone(),
        approvals: fixture.approvals.clone(),
        activated_at: 106,
    }
    .sign(
        &fixture.proposal,
        &fixture.admission,
        &fixture.charter,
        &key(1),
    )?;
    assert!(VerifiedFiscalActivation::verify(
        at_approval_expiry,
        &fixture.proposal,
        &fixture.admission,
        &fixture.admission_state,
        &fixture.charter,
        &fixture.trust,
        None,
        &[],
        106,
    )
    .is_err());

    assert!(VerifiedFiscalProposalAdmission::verify(
        fixture.admission.signed().clone(),
        &fixture.proposal,
        &fixture.charter,
        &FiscalAdmissionTrustRegistry::default(),
        70,
    )
    .is_err());
    Ok(())
}

#[test]
fn successor_charter_cannot_self_authorize_rotation() -> TestResult {
    let current = charter()?;
    let successor = VerifiedFiscalCharter::verify(
        FiscalCharterBuilder {
            governing_operator_id: "operator.example".to_owned(),
            governed_domains: current.body().governed_domains.clone(),
            signer_keys: vec![key(3).public_key(), key(4).public_key()],
            approval_threshold: 2,
            timelock_seconds: 10,
            proposal_ttl_seconds: 100,
            approval_ttl_seconds: 50,
            issued_at: 70,
            expires_at: 900,
            issued_by: "operator.example".to_owned(),
            sequence: 2,
            predecessor_charter_digest: Some(current.digest().to_owned()),
        }
        .sign(&key(9))?,
    )?;
    let proposal = VerifiedFiscalProposal::verify(
        FiscalProposalBuilder {
            target: FiscalProposalTarget::CharterRotation {
                successor: Box::new(successor.signed().clone()),
            },
            rationale_digest: digest("rotation rationale"),
            proposed_at: 50,
        }
        .sign(&key(1))?,
        &current,
        None,
    )?;
    let admission_key = key(7);
    let trust = FiscalAdmissionTrustRegistry::new(vec![FiscalAdmissionAuthority::new(
        "operator.example".to_owned(),
        "local-admission".to_owned(),
        1,
        admission_key.public_key(),
    )?])?;
    let admission = VerifiedFiscalProposalAdmission::verify(
        FiscalProposalAdmissionBuilder {
            admission_sequence: 1,
            admitted_at: 55,
            admission_authority_id: "local-admission".to_owned(),
            signer_key_epoch: 1,
        }
        .sign(&proposal, &current, &admission_key)?,
        &proposal,
        &current,
        &trust,
        55,
    )?;
    let successor_approval =
        FiscalApprovalBuilder { approved_at: 56 }.sign(&proposal, &admission, &current, &key(3))?;
    assert!(VerifiedFiscalApproval::verify(
        successor_approval,
        &proposal,
        &admission,
        &current,
        70,
    )
    .is_err());
    Ok(())
}

#[test]
fn external_checkpoint_prevents_database_restore_from_reopening_fallback() -> TestResult {
    let fixture = continuity_fixture()?;
    let restored_authority = FiscalAuthorityState::from_checkpoint(
        &fixture.policy,
        &fixture.genesis,
        FiscalBootstrapState::BootstrapUnconfigured,
    )?;
    let resolution = resolve_fiscal_schedule::<FiscalParams>(
        FiscalContinuitySnapshot::Verified(&fixture.activated),
        &fixture.policy,
        &fixture.readiness,
        &fixture.activation_history,
        &restored_authority,
        &fixture.charters,
        &[],
        FiscalDomain::TierLimits,
        Some("USD"),
        70,
    );
    assert_eq!(
        resolution,
        FiscalResolution::Denied(FiscalDenialReason::AnchorRollbackOrDivergence)
    );
    Ok(())
}

#[test]
fn activation_history_rebuilds_only_from_the_complete_checkpoint_chain() -> TestResult {
    let fixture = continuity_fixture()?;
    let head = FiscalScheduleHead::from_signed(fixture.amendment.schedule.signed())?;
    let history = FiscalActivationHistory::from_checkpoint_history(
        vec![fixture.amendment.activation.clone()],
        &[fixture.genesis.clone(), fixture.activated.clone()],
        &fixture.activated,
    )?;
    assert!(history
        .verify_head(&head, FiscalDomain::TierLimits, 70)
        .is_ok());
    assert!(FiscalActivationHistory::from_checkpoint_history(
        vec![fixture.amendment.activation],
        std::slice::from_ref(&fixture.activated),
        &fixture.activated,
    )
    .is_err());
    Ok(())
}

#[test]
fn resolver_selects_activated_predecessor_digest_from_duplicate_schedule_ids() -> TestResult {
    let fixture = continuity_fixture()?;
    let (successor, successor_activation) = successor_amendment(
        &fixture.amendment.schedule,
        &fixture.amendment.charter,
        &fixture.amendment.trust,
    )?;
    let successor_head = FiscalScheduleHead::from_signed(successor.signed())?;
    let mut domains = fixture.activated.body().domains.clone();
    domains[0] = FiscalDomainState::activated(
        FiscalDomain::TierLimits,
        successor_head.clone(),
        successor_head,
    )?;
    let transition = FiscalStagedTransition::new(
        successor_activation.body().activation_id.clone(),
        successor_activation.digest().to_owned(),
    )?;
    let next = FiscalContinuityCheckpointBuilder {
        continuity_sequence: 2,
        previous_checkpoint_digest: Some(fixture.activated.digest().to_owned()),
        pinned_charter_id: fixture.amendment.charter.body().charter_id.clone(),
        pinned_charter_digest: fixture.amendment.charter.digest().to_owned(),
        pinned_charter_sequence: fixture.amendment.charter.body().sequence,
        runtime_readiness_digest: fixture.readiness.digest().to_owned(),
        domains,
        trusted_clock_high_water: 82,
        staged_transition: Some(transition),
    }
    .sign(&fixture.policy, &fixture.anchor_key)?;
    let advance = VerifiedFiscalContinuityAdvance::verify(
        &fixture.activated,
        next,
        &fixture.policy,
        &fixture.charters,
        &FiscalContinuityChange::Activation {
            activation: Box::new(successor_activation.clone()),
            readiness: Box::new(fixture.readiness.clone()),
            domain: FiscalDomain::TierLimits,
            schedule: Box::new(successor.clone()),
        },
    )?;
    let anchor = TestAnchor {
        state: Mutex::new(AnchorState::Available(Box::new(
            fixture.activated.signed().clone(),
        ))),
    };
    let commit =
        commit_fiscal_continuity_advance(&anchor, advance, &fixture.policy, &fixture.charters)?;
    let successor_checkpoint = commit.checkpoint().clone();
    let history = FiscalActivationHistory::from_checkpoint_history(
        vec![fixture.amendment.activation.clone(), successor_activation],
        &[
            fixture.genesis.clone(),
            fixture.activated.clone(),
            successor_checkpoint.clone(),
        ],
        &successor_checkpoint,
    )?;
    let authority = FiscalAuthorityState::from_checkpoint(
        &fixture.policy,
        &successor_checkpoint,
        FiscalBootstrapState::CharterPinned,
    )?;
    let duplicate_predecessor = VerifiedFiscalSchedule::verify(
        SignedFiscalSchedule::sign(fixture.amendment.schedule.body().clone(), &key(6))?,
        &fixture.amendment.charter,
        None,
    )?;

    let resolution = resolve_fiscal_schedule::<FiscalParams>(
        FiscalContinuitySnapshot::Verified(&successor_checkpoint),
        &fixture.policy,
        &fixture.readiness,
        &history,
        &authority,
        &fixture.charters,
        &[
            successor.signed().clone(),
            duplicate_predecessor.signed().clone(),
            fixture.amendment.schedule.signed().clone(),
        ],
        FiscalDomain::TierLimits,
        Some("USD"),
        82,
    );
    assert!(matches!(
        resolution,
        FiscalResolution::Governed {
            source: GovernedSource::Active,
            ..
        }
    ));
    Ok(())
}

#[test]
fn clock_rollback_anchor_outage_and_divergence_deny() -> TestResult {
    let fixture = continuity_fixture()?;
    for (snapshot, expected) in [
        (
            FiscalContinuitySnapshot::Unavailable,
            FiscalDenialReason::AnchorUnavailable,
        ),
        (
            FiscalContinuitySnapshot::Divergent,
            FiscalDenialReason::AnchorRollbackOrDivergence,
        ),
    ] {
        assert_eq!(
            resolve_fiscal_schedule::<FiscalParams>(
                snapshot,
                &fixture.policy,
                &fixture.readiness,
                &fixture.activation_history,
                &fixture.authority,
                &fixture.charters,
                &[fixture.amendment.schedule.signed().clone()],
                FiscalDomain::TierLimits,
                Some("USD"),
                70,
            ),
            FiscalResolution::Denied(expected)
        );
    }
    assert_eq!(
        resolve_fiscal_schedule::<FiscalParams>(
            FiscalContinuitySnapshot::Verified(&fixture.activated),
            &fixture.policy,
            &fixture.readiness,
            &fixture.activation_history,
            &fixture.authority,
            &fixture.charters,
            &[fixture.amendment.schedule.signed().clone()],
            FiscalDomain::TierLimits,
            Some("USD"),
            69,
        ),
        FiscalResolution::Denied(FiscalDenialReason::ClockRollback)
    );
    assert_eq!(
        resolve_fiscal_schedule::<FiscalParams>(
            FiscalContinuitySnapshot::Verified(&fixture.genesis),
            &fixture.policy,
            &fixture.readiness,
            &fixture.activation_history,
            &fixture.authority,
            &fixture.charters,
            &[fixture.amendment.schedule.signed().clone()],
            FiscalDomain::TierLimits,
            Some("USD"),
            55,
        ),
        FiscalResolution::Denied(FiscalDenialReason::AnchorRollbackOrDivergence)
    );
    Ok(())
}

#[test]
fn continuity_rejects_marker_clock_and_sequence_rollback() -> TestResult {
    let fixture = continuity_fixture()?;
    for (sequence, clock, domains) in [
        (2, 69, fixture.activated.body().domains.clone()),
        (3, 70, fixture.activated.body().domains.clone()),
        (2, 70, never_domains()),
    ] {
        let next = FiscalContinuityCheckpointBuilder {
            continuity_sequence: sequence,
            previous_checkpoint_digest: Some(fixture.activated.digest().to_owned()),
            pinned_charter_id: fixture.amendment.charter.body().charter_id.clone(),
            pinned_charter_digest: fixture.amendment.charter.digest().to_owned(),
            pinned_charter_sequence: fixture.amendment.charter.body().sequence,
            runtime_readiness_digest: fixture.readiness.digest().to_owned(),
            domains,
            trusted_clock_high_water: clock,
            staged_transition: fixture.activated.body().staged_transition.clone(),
        }
        .sign(&fixture.policy, &fixture.anchor_key)?;
        assert!(VerifiedFiscalContinuityAdvance::verify(
            &fixture.activated,
            next,
            &fixture.policy,
            &fixture.charters,
            &FiscalContinuityChange::ClockOnly,
        )
        .is_err());
    }
    let next_registry = runtime_registry("2")?;
    let next_readiness = VerifiedFiscalRuntimeReadiness::verify(
        FiscalRuntimeReadinessBuilder {
            readiness_sequence: 2,
            runtime_registry: next_registry.clone(),
            attested_at: 70,
        }
        .sign(&fixture.policy, &fixture.anchor_key)?,
        &fixture.policy,
        next_registry,
    )?;
    let readiness_checkpoint = FiscalContinuityCheckpointBuilder {
        continuity_sequence: 2,
        previous_checkpoint_digest: Some(fixture.activated.digest().to_owned()),
        pinned_charter_id: fixture.amendment.charter.body().charter_id.clone(),
        pinned_charter_digest: fixture.amendment.charter.digest().to_owned(),
        pinned_charter_sequence: fixture.amendment.charter.body().sequence,
        runtime_readiness_digest: next_readiness.digest().to_owned(),
        domains: fixture.activated.body().domains.clone(),
        trusted_clock_high_water: 70,
        staged_transition: fixture.activated.body().staged_transition.clone(),
    }
    .sign(&fixture.policy, &fixture.anchor_key)?;
    assert!(VerifiedFiscalContinuityAdvance::verify(
        &fixture.activated,
        readiness_checkpoint.clone(),
        &fixture.policy,
        &fixture.charters,
        &FiscalContinuityChange::ClockOnly,
    )
    .is_err());
    let advance = VerifiedFiscalContinuityAdvance::verify(
        &fixture.activated,
        readiness_checkpoint,
        &fixture.policy,
        &fixture.charters,
        &FiscalContinuityChange::Readiness {
            current: Box::new(fixture.readiness.clone()),
            next: Box::new(next_readiness.clone()),
        },
    )?;
    assert_eq!(
        advance.next().body().runtime_readiness_digest,
        next_readiness.digest()
    );
    Ok(())
}

#[test]
fn activation_requires_the_exact_current_runtime_readiness() -> TestResult {
    let fixture = continuity_fixture()?;
    let head = FiscalScheduleHead::from_signed(fixture.amendment.schedule.signed())?;
    let build_current = |runtime_readiness_digest: String| -> TestResult<_> {
        Ok(VerifiedFiscalContinuityCheckpoint::verify(
            FiscalContinuityCheckpointBuilder {
                continuity_sequence: 0,
                previous_checkpoint_digest: None,
                pinned_charter_id: fixture.amendment.charter.body().charter_id.clone(),
                pinned_charter_digest: fixture.amendment.charter.digest().to_owned(),
                pinned_charter_sequence: fixture.amendment.charter.body().sequence,
                runtime_readiness_digest,
                domains: never_domains(),
                trusted_clock_high_water: 55,
                staged_transition: None,
            }
            .sign(&fixture.policy, &fixture.anchor_key)?,
            &fixture.policy,
            &fixture.charters,
        )?)
    };
    let build_next = |current: &VerifiedFiscalContinuityCheckpoint,
                      runtime_readiness_digest: String|
     -> TestResult<_> {
        Ok(FiscalContinuityCheckpointBuilder {
            continuity_sequence: 1,
            previous_checkpoint_digest: Some(current.digest().to_owned()),
            pinned_charter_id: fixture.amendment.charter.body().charter_id.clone(),
            pinned_charter_digest: fixture.amendment.charter.digest().to_owned(),
            pinned_charter_sequence: fixture.amendment.charter.body().sequence,
            runtime_readiness_digest,
            domains: activated_domains(head.clone())?,
            trusted_clock_high_water: 70,
            staged_transition: Some(FiscalStagedTransition::new(
                fixture.amendment.activation.body().activation_id.clone(),
                fixture.amendment.activation.digest().to_owned(),
            )?),
        }
        .sign(&fixture.policy, &fixture.anchor_key)?)
    };

    let arbitrary_digest = digest("no readiness artifact");
    let arbitrary_current = build_current(arbitrary_digest.clone())?;
    assert!(VerifiedFiscalContinuityAdvance::verify(
        &arbitrary_current,
        build_next(&arbitrary_current, arbitrary_digest)?,
        &fixture.policy,
        &fixture.charters,
        &FiscalContinuityChange::Activation {
            activation: Box::new(fixture.amendment.activation.clone()),
            readiness: Box::new(fixture.readiness.clone()),
            domain: FiscalDomain::TierLimits,
            schedule: Box::new(fixture.amendment.schedule.clone()),
        },
    )
    .is_err());

    let substituted_registry = runtime_registry("substituted")?;
    let substituted = VerifiedFiscalRuntimeReadiness::verify(
        FiscalRuntimeReadinessBuilder {
            readiness_sequence: 2,
            runtime_registry: substituted_registry.clone(),
            attested_at: 55,
        }
        .sign(&fixture.policy, &fixture.anchor_key)?,
        &fixture.policy,
        substituted_registry,
    )?;
    assert!(VerifiedFiscalContinuityAdvance::verify(
        &fixture.genesis,
        fixture.activated.signed().clone(),
        &fixture.policy,
        &fixture.charters,
        &FiscalContinuityChange::Activation {
            activation: Box::new(fixture.amendment.activation.clone()),
            readiness: Box::new(substituted),
            domain: FiscalDomain::TierLimits,
            schedule: Box::new(fixture.amendment.schedule.clone()),
        },
    )
    .is_err());

    let future_registry = runtime_registry("future")?;
    let future = VerifiedFiscalRuntimeReadiness::verify(
        FiscalRuntimeReadinessBuilder {
            readiness_sequence: 2,
            runtime_registry: future_registry.clone(),
            attested_at: 71,
        }
        .sign(&fixture.policy, &fixture.anchor_key)?,
        &fixture.policy,
        future_registry,
    )?;
    let future_current = build_current(future.digest().to_owned())?;
    assert!(VerifiedFiscalContinuityAdvance::verify(
        &future_current,
        build_next(&future_current, future.digest().to_owned())?,
        &fixture.policy,
        &fixture.charters,
        &FiscalContinuityChange::Activation {
            activation: Box::new(fixture.amendment.activation.clone()),
            readiness: Box::new(future),
            domain: FiscalDomain::TierLimits,
            schedule: Box::new(fixture.amendment.schedule.clone()),
        },
    )
    .is_err());

    let mutations: [fn(&mut FiscalRuntimeReadiness); 2] = [
        |body: &mut FiscalRuntimeReadiness| {
            body.governing_operator_id = "other.example".to_owned();
        },
        |body: &mut FiscalRuntimeReadiness| {
            body.genesis_policy_id = digest("other policy id");
            body.genesis_policy_digest = digest("other policy body");
        },
    ];
    for mutate in mutations {
        let mut body = fixture.readiness.body().clone();
        mutate(&mut body);
        body.readiness_id = body.expected_id()?;
        let signed = SignedFiscalRuntimeReadiness::sign(body, &fixture.anchor_key)?;
        assert!(VerifiedFiscalRuntimeReadiness::verify(
            signed,
            &fixture.policy,
            fixture.readiness.runtime_registry().clone(),
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn continuity_binds_exact_schedule_domain_predecessor_and_charter_lineage() -> TestResult {
    let fixture = continuity_fixture()?;
    let exact_head = FiscalScheduleHead::from_signed(fixture.amendment.schedule.signed())?;
    let alternate_schedule = VerifiedFiscalSchedule::verify(
        SignedFiscalSchedule::sign(fixture.amendment.schedule.body().clone(), &key(6))?,
        &fixture.amendment.charter,
        None,
    )?;
    let alternate_head = FiscalScheduleHead::from_signed(alternate_schedule.signed())?;
    let transition = fixture.activated.body().staged_transition.clone();

    let alternate_next = FiscalContinuityCheckpointBuilder {
        continuity_sequence: 1,
        previous_checkpoint_digest: Some(fixture.genesis.digest().to_owned()),
        pinned_charter_id: fixture.amendment.charter.body().charter_id.clone(),
        pinned_charter_digest: fixture.amendment.charter.digest().to_owned(),
        pinned_charter_sequence: fixture.amendment.charter.body().sequence,
        runtime_readiness_digest: fixture.readiness.digest().to_owned(),
        domains: activated_domains(alternate_head.clone())?,
        trusted_clock_high_water: 70,
        staged_transition: transition.clone(),
    }
    .sign(&fixture.policy, &fixture.anchor_key)?;
    assert!(VerifiedFiscalContinuityAdvance::verify(
        &fixture.genesis,
        alternate_next,
        &fixture.policy,
        &fixture.charters,
        &FiscalContinuityChange::Activation {
            activation: Box::new(fixture.amendment.activation.clone()),
            readiness: Box::new(fixture.readiness.clone()),
            domain: FiscalDomain::TierLimits,
            schedule: Box::new(alternate_schedule),
        },
    )
    .is_err());

    let mut wrong_domain = never_domains();
    wrong_domain[3] = FiscalDomainState::activated(
        FiscalDomain::InsurancePremiumSchedule,
        exact_head.clone(),
        exact_head.clone(),
    )?;
    let wrong_domain_next = FiscalContinuityCheckpointBuilder {
        continuity_sequence: 1,
        previous_checkpoint_digest: Some(fixture.genesis.digest().to_owned()),
        pinned_charter_id: fixture.amendment.charter.body().charter_id.clone(),
        pinned_charter_digest: fixture.amendment.charter.digest().to_owned(),
        pinned_charter_sequence: fixture.amendment.charter.body().sequence,
        runtime_readiness_digest: fixture.readiness.digest().to_owned(),
        domains: wrong_domain,
        trusted_clock_high_water: 70,
        staged_transition: transition.clone(),
    }
    .sign(&fixture.policy, &fixture.anchor_key)?;
    assert!(VerifiedFiscalContinuityAdvance::verify(
        &fixture.genesis,
        wrong_domain_next,
        &fixture.policy,
        &fixture.charters,
        &FiscalContinuityChange::Activation {
            activation: Box::new(fixture.amendment.activation.clone()),
            readiness: Box::new(fixture.readiness.clone()),
            domain: FiscalDomain::InsurancePremiumSchedule,
            schedule: Box::new(fixture.amendment.schedule.clone()),
        },
    )
    .is_err());

    let replay = FiscalContinuityCheckpointBuilder {
        continuity_sequence: 2,
        previous_checkpoint_digest: Some(fixture.activated.digest().to_owned()),
        pinned_charter_id: fixture.amendment.charter.body().charter_id.clone(),
        pinned_charter_digest: fixture.amendment.charter.digest().to_owned(),
        pinned_charter_sequence: fixture.amendment.charter.body().sequence,
        runtime_readiness_digest: fixture.readiness.digest().to_owned(),
        domains: fixture.activated.body().domains.clone(),
        trusted_clock_high_water: 70,
        staged_transition: transition,
    }
    .sign(&fixture.policy, &fixture.anchor_key)?;
    assert!(VerifiedFiscalContinuityAdvance::verify(
        &fixture.activated,
        replay,
        &fixture.policy,
        &fixture.charters,
        &FiscalContinuityChange::Activation {
            activation: Box::new(fixture.amendment.activation.clone()),
            readiness: Box::new(fixture.readiness.clone()),
            domain: FiscalDomain::TierLimits,
            schedule: Box::new(fixture.amendment.schedule.clone()),
        },
    )
    .is_err());

    let rogue_charter = VerifiedFiscalCharter::verify(
        FiscalCharterBuilder {
            governing_operator_id: "operator.example".to_owned(),
            governed_domains: fixture.amendment.charter.body().governed_domains.clone(),
            signer_keys: vec![key(1).public_key(), key(2).public_key()],
            approval_threshold: 2,
            timelock_seconds: 10,
            proposal_ttl_seconds: 100,
            approval_ttl_seconds: 50,
            issued_at: 20,
            expires_at: 1_000,
            issued_by: "operator.example".to_owned(),
            sequence: 2,
            predecessor_charter_digest: Some(digest("unrelated charter")),
        }
        .sign(&key(9))?,
    )?;
    let rogue_registry = FiscalCharterRegistry::new(vec![
        fixture.amendment.charter.signed().clone(),
        rogue_charter.signed().clone(),
    ])?;
    let rogue_checkpoint = FiscalContinuityCheckpointBuilder {
        continuity_sequence: 1,
        previous_checkpoint_digest: Some(fixture.genesis.digest().to_owned()),
        pinned_charter_id: rogue_charter.body().charter_id.clone(),
        pinned_charter_digest: rogue_charter.digest().to_owned(),
        pinned_charter_sequence: rogue_charter.body().sequence,
        runtime_readiness_digest: fixture.readiness.digest().to_owned(),
        domains: never_domains(),
        trusted_clock_high_water: 70,
        staged_transition: None,
    }
    .sign(&fixture.policy, &fixture.anchor_key)?;
    assert!(VerifiedFiscalContinuityCheckpoint::verify(
        rogue_checkpoint,
        &fixture.policy,
        &rogue_registry,
    )
    .is_err());
    Ok(())
}

#[test]
fn fallback_is_anchor_attested_and_cannot_reappear_after_activation() -> TestResult {
    let fixture = continuity_fixture()?;
    let bootstrap_authority = FiscalAuthorityState::from_checkpoint(
        &fixture.policy,
        &fixture.genesis,
        FiscalBootstrapState::BootstrapUnconfigured,
    )?;
    assert_eq!(
        resolve_fiscal_schedule::<FiscalParams>(
            FiscalContinuitySnapshot::Verified(&fixture.genesis),
            &fixture.policy,
            &fixture.readiness,
            &fixture.activation_history,
            &bootstrap_authority,
            &fixture.charters,
            &[],
            FiscalDomain::TierLimits,
            Some("USD"),
            55,
        ),
        FiscalResolution::Fallback(FiscalFallbackReason::AuthoritativeBootstrap)
    );
    assert_eq!(
        resolve_fiscal_schedule::<FiscalParams>(
            FiscalContinuitySnapshot::Verified(&fixture.genesis),
            &fixture.policy,
            &fixture.readiness,
            &fixture.activation_history,
            &bootstrap_authority,
            &fixture.charters,
            &[],
            FiscalDomain::TierLimits,
            Some("EUR"),
            55,
        ),
        FiscalResolution::Denied(FiscalDenialReason::VerificationFailed)
    );
    assert_eq!(
        resolve_fiscal_schedule::<FiscalParams>(
            FiscalContinuitySnapshot::Verified(&fixture.activated),
            &fixture.policy,
            &fixture.readiness,
            &fixture.activation_history,
            &fixture.authority,
            &fixture.charters,
            &[],
            FiscalDomain::TierLimits,
            Some("USD"),
            70,
        ),
        FiscalResolution::Denied(FiscalDenialReason::NoValidLastKnownGood)
    );
    Ok(())
}

#[test]
fn resolver_enforces_lineage_currency_expiry_and_last_known_good() -> TestResult {
    let fixture = continuity_fixture()?;
    let signed_schedule = fixture.amendment.schedule.signed().clone();
    let empty_history = FiscalActivationHistory::default();
    assert_eq!(
        resolve_fiscal_schedule::<FiscalParams>(
            FiscalContinuitySnapshot::Verified(&fixture.activated),
            &fixture.policy,
            &fixture.readiness,
            &empty_history,
            &fixture.authority,
            &fixture.charters,
            std::slice::from_ref(&signed_schedule),
            FiscalDomain::TierLimits,
            Some("USD"),
            70,
        ),
        FiscalResolution::Denied(FiscalDenialReason::NoValidLastKnownGood)
    );
    let wrong_registry = runtime_registry("different")?;
    let wrong_readiness = VerifiedFiscalRuntimeReadiness::verify(
        FiscalRuntimeReadinessBuilder {
            readiness_sequence: 2,
            runtime_registry: wrong_registry.clone(),
            attested_at: 55,
        }
        .sign(&fixture.policy, &fixture.anchor_key)?,
        &fixture.policy,
        wrong_registry,
    )?;
    assert_eq!(
        resolve_fiscal_schedule::<FiscalParams>(
            FiscalContinuitySnapshot::Verified(&fixture.activated),
            &fixture.policy,
            &wrong_readiness,
            &fixture.activation_history,
            &fixture.authority,
            &fixture.charters,
            std::slice::from_ref(&signed_schedule),
            FiscalDomain::TierLimits,
            Some("USD"),
            70,
        ),
        FiscalResolution::Denied(FiscalDenialReason::VerificationFailed)
    );
    assert!(matches!(
        resolve_fiscal_schedule::<FiscalParams>(
            FiscalContinuitySnapshot::Verified(&fixture.activated),
            &fixture.policy,
            &fixture.readiness,
            &fixture.activation_history,
            &fixture.authority,
            &fixture.charters,
            std::slice::from_ref(&signed_schedule),
            FiscalDomain::TierLimits,
            Some("USD"),
            70,
        ),
        FiscalResolution::Governed {
            source: GovernedSource::Active,
            ..
        }
    ));
    assert_eq!(
        resolve_fiscal_schedule::<FiscalParams>(
            FiscalContinuitySnapshot::Verified(&fixture.activated),
            &fixture.policy,
            &fixture.readiness,
            &fixture.activation_history,
            &fixture.authority,
            &fixture.charters,
            std::slice::from_ref(&signed_schedule),
            FiscalDomain::TierLimits,
            Some("EUR"),
            70,
        ),
        FiscalResolution::Denied(FiscalDenialReason::NoValidLastKnownGood)
    );

    let successor = schedule(
        &fixture.amendment.charter,
        Some(&fixture.amendment.schedule),
    )?;
    let stale_head = FiscalScheduleHead::from_signed(successor.signed())?;
    let stale_checkpoint = VerifiedFiscalContinuityCheckpoint::verify(
        FiscalContinuityCheckpointBuilder {
            continuity_sequence: 2,
            previous_checkpoint_digest: Some(fixture.activated.digest().to_owned()),
            pinned_charter_id: fixture.amendment.charter.body().charter_id.clone(),
            pinned_charter_digest: fixture.amendment.charter.digest().to_owned(),
            pinned_charter_sequence: fixture.amendment.charter.body().sequence,
            runtime_readiness_digest: fixture.readiness.digest().to_owned(),
            domains: activated_domains(stale_head)?,
            trusted_clock_high_water: 70,
            staged_transition: fixture.activated.body().staged_transition.clone(),
        }
        .sign(&fixture.policy, &fixture.anchor_key)?,
        &fixture.policy,
        &fixture.charters,
    )?;
    let stale_authority = FiscalAuthorityState::from_checkpoint(
        &fixture.policy,
        &stale_checkpoint,
        FiscalBootstrapState::CharterPinned,
    )?;
    assert_eq!(
        resolve_fiscal_schedule::<FiscalParams>(
            FiscalContinuitySnapshot::Verified(&stale_checkpoint),
            &fixture.policy,
            &fixture.readiness,
            &fixture.activation_history,
            &stale_authority,
            &fixture.charters,
            &[successor.signed().clone()],
            FiscalDomain::TierLimits,
            Some("USD"),
            70,
        ),
        FiscalResolution::Denied(FiscalDenialReason::NoValidLastKnownGood)
    );

    let good_head = FiscalScheduleHead::from_signed(&signed_schedule)?;
    let missing_head = FiscalScheduleHead {
        schedule_id: digest("missing schedule"),
        schedule_digest: digest("missing envelope"),
        sequence: 2,
    };
    let mut recovered_domains = never_domains();
    recovered_domains[0] =
        FiscalDomainState::activated(FiscalDomain::TierLimits, missing_head, good_head)?;
    let recovered_checkpoint = VerifiedFiscalContinuityCheckpoint::verify(
        FiscalContinuityCheckpointBuilder {
            continuity_sequence: 2,
            previous_checkpoint_digest: Some(fixture.activated.digest().to_owned()),
            pinned_charter_id: fixture.amendment.charter.body().charter_id.clone(),
            pinned_charter_digest: fixture.amendment.charter.digest().to_owned(),
            pinned_charter_sequence: fixture.amendment.charter.body().sequence,
            runtime_readiness_digest: fixture.readiness.digest().to_owned(),
            domains: recovered_domains,
            trusted_clock_high_water: 70,
            staged_transition: fixture.activated.body().staged_transition.clone(),
        }
        .sign(&fixture.policy, &fixture.anchor_key)?,
        &fixture.policy,
        &fixture.charters,
    )?;
    let recovered_authority = FiscalAuthorityState::from_checkpoint(
        &fixture.policy,
        &recovered_checkpoint,
        FiscalBootstrapState::CharterPinned,
    )?;
    assert!(matches!(
        resolve_fiscal_schedule::<FiscalParams>(
            FiscalContinuitySnapshot::Verified(&recovered_checkpoint),
            &fixture.policy,
            &fixture.readiness,
            &fixture.activation_history,
            &recovered_authority,
            &fixture.charters,
            std::slice::from_ref(&signed_schedule),
            FiscalDomain::TierLimits,
            Some("USD"),
            70,
        ),
        FiscalResolution::Governed {
            source: GovernedSource::LastKnownGood,
            ..
        }
    ));
    Ok(())
}

enum AnchorState {
    Available(Box<SignedFiscalContinuityCheckpoint>),
    Unavailable,
}

struct TestAnchor {
    state: Mutex<AnchorState>,
}

impl FiscalStateAnchor for TestAnchor {
    fn read(&self) -> Result<SignedFiscalContinuityCheckpoint, FiscalStateAnchorError> {
        match &*self
            .state
            .lock()
            .map_err(|_| FiscalStateAnchorError::Unavailable)?
        {
            AnchorState::Available(checkpoint) => Ok(checkpoint.as_ref().clone()),
            AnchorState::Unavailable => Err(FiscalStateAnchorError::Unavailable),
        }
    }

    fn compare_and_swap(
        &self,
        expected_checkpoint_digest: &str,
        advance: &VerifiedFiscalContinuityAdvance,
    ) -> Result<SignedFiscalContinuityCheckpoint, FiscalStateAnchorError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| FiscalStateAnchorError::Unavailable)?;
        let AnchorState::Available(current) = &*state else {
            return Err(FiscalStateAnchorError::Unavailable);
        };
        let current_digest = sha256_hex(
            &canonical_json_bytes(current).map_err(|_| FiscalStateAnchorError::Divergence)?,
        );
        if current_digest != expected_checkpoint_digest
            || expected_checkpoint_digest != advance.current().digest()
        {
            return Err(FiscalStateAnchorError::Conflict);
        }
        let committed = advance.next().signed().clone();
        *state = AnchorState::Available(Box::new(committed.clone()));
        Ok(committed)
    }
}

struct FalseAcknowledgingAnchor {
    current: SignedFiscalContinuityCheckpoint,
}

impl FiscalStateAnchor for FalseAcknowledgingAnchor {
    fn read(&self) -> Result<SignedFiscalContinuityCheckpoint, FiscalStateAnchorError> {
        Ok(self.current.clone())
    }

    fn compare_and_swap(
        &self,
        _expected_checkpoint_digest: &str,
        _advance: &VerifiedFiscalContinuityAdvance,
    ) -> Result<SignedFiscalContinuityCheckpoint, FiscalStateAnchorError> {
        Ok(self.current.clone())
    }
}

#[test]
fn external_anchor_port_reads_authentically_and_cas_advances() -> TestResult {
    let fixture = continuity_fixture()?;
    let head = FiscalScheduleHead::from_signed(fixture.amendment.schedule.signed())?;
    let next = FiscalContinuityCheckpointBuilder {
        continuity_sequence: 1,
        previous_checkpoint_digest: Some(fixture.genesis.digest().to_owned()),
        pinned_charter_id: fixture.amendment.charter.body().charter_id.clone(),
        pinned_charter_digest: fixture.amendment.charter.digest().to_owned(),
        pinned_charter_sequence: fixture.amendment.charter.body().sequence,
        runtime_readiness_digest: fixture.readiness.digest().to_owned(),
        domains: activated_domains(head.clone())?,
        trusted_clock_high_water: 70,
        staged_transition: Some(FiscalStagedTransition::new(
            fixture.amendment.activation.body().activation_id.clone(),
            fixture.amendment.activation.digest().to_owned(),
        )?),
    }
    .sign(&fixture.policy, &fixture.anchor_key)?;
    let advance = VerifiedFiscalContinuityAdvance::verify(
        &fixture.genesis,
        next,
        &fixture.policy,
        &fixture.charters,
        &FiscalContinuityChange::Activation {
            activation: Box::new(fixture.amendment.activation.clone()),
            readiness: Box::new(fixture.readiness.clone()),
            domain: FiscalDomain::TierLimits,
            schedule: Box::new(fixture.amendment.schedule.clone()),
        },
    )?;
    let anchor = TestAnchor {
        state: Mutex::new(AnchorState::Available(Box::new(
            fixture.genesis.signed().clone(),
        ))),
    };
    assert_eq!(
        read_verified_fiscal_checkpoint(&anchor, &fixture.policy, &fixture.charters)?.digest(),
        fixture.genesis.digest()
    );
    let commit = commit_fiscal_continuity_advance(
        &anchor,
        advance.clone(),
        &fixture.policy,
        &fixture.charters,
    )?;
    assert_eq!(
        read_verified_fiscal_checkpoint(&anchor, &fixture.policy, &fixture.charters)?.digest(),
        advance.next().digest()
    );
    let authority = commit.into_activation_authority()?;
    assert_eq!(authority.checkpoint_digest(), advance.next().digest());
    let history = FiscalActivationHistory::new(vec![authority])?;
    assert!(history
        .verify_head(&head, FiscalDomain::TierLimits, 70)
        .is_ok());
    let recovered = recover_fiscal_continuity_advance(
        &anchor,
        advance.clone(),
        &fixture.policy,
        &fixture.charters,
    )?;
    assert!(FiscalActivationHistory::new(vec![recovered.into_activation_authority()?]).is_ok());

    let false_acknowledgement = FalseAcknowledgingAnchor {
        current: fixture.genesis.signed().clone(),
    };
    assert!(matches!(
        commit_fiscal_continuity_advance(
            &false_acknowledgement,
            advance,
            &fixture.policy,
            &fixture.charters,
        ),
        Err(FiscalStateAnchorError::Divergence)
    ));
    let unavailable = TestAnchor {
        state: Mutex::new(AnchorState::Unavailable),
    };
    assert!(matches!(
        read_verified_fiscal_checkpoint(&unavailable, &fixture.policy, &fixture.charters),
        Err(FiscalStateAnchorError::Unavailable)
    ));
    Ok(())
}

#[test]
fn checkpoint_strict_decode_and_expiry_boundary_fail_closed() -> TestResult {
    let fixture = continuity_fixture()?;
    let bytes = fixture.activated.canonical_bytes()?;
    assert_eq!(
        VerifiedFiscalContinuityCheckpoint::from_canonical_bytes(
            &bytes,
            &fixture.policy,
            &fixture.charters,
        )?
        .digest(),
        fixture.activated.digest()
    );
    let mut noncanonical = bytes;
    noncanonical.push(b'\n');
    assert!(VerifiedFiscalContinuityCheckpoint::from_canonical_bytes(
        &noncanonical,
        &fixture.policy,
        &fixture.charters,
    )
    .is_err());

    let expired_checkpoint = VerifiedFiscalContinuityCheckpoint::verify(
        FiscalContinuityCheckpointBuilder {
            continuity_sequence: 2,
            previous_checkpoint_digest: Some(fixture.activated.digest().to_owned()),
            pinned_charter_id: fixture.amendment.charter.body().charter_id.clone(),
            pinned_charter_digest: fixture.amendment.charter.digest().to_owned(),
            pinned_charter_sequence: fixture.amendment.charter.body().sequence,
            runtime_readiness_digest: fixture.readiness.digest().to_owned(),
            domains: fixture.activated.body().domains.clone(),
            trusted_clock_high_water: 900,
            staged_transition: fixture.activated.body().staged_transition.clone(),
        }
        .sign(&fixture.policy, &fixture.anchor_key)?,
        &fixture.policy,
        &fixture.charters,
    )?;
    let expired_authority = FiscalAuthorityState::from_checkpoint(
        &fixture.policy,
        &expired_checkpoint,
        FiscalBootstrapState::CharterPinned,
    )?;
    assert_eq!(
        resolve_fiscal_schedule::<FiscalParams>(
            FiscalContinuitySnapshot::Verified(&expired_checkpoint),
            &fixture.policy,
            &fixture.readiness,
            &fixture.activation_history,
            &expired_authority,
            &fixture.charters,
            &[fixture.amendment.schedule.signed().clone()],
            FiscalDomain::TierLimits,
            Some("USD"),
            900,
        ),
        FiscalResolution::Denied(FiscalDenialReason::NoValidLastKnownGood)
    );
    Ok(())
}
