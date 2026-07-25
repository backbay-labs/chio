use std::collections::BTreeMap;
use std::fs;

use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::{sha256_hex, Keypair};
use chio_fiscal::{
    FiscalActivationBuilder, FiscalActivationTarget, FiscalAdmissionAuthority,
    FiscalAdmissionTrustRegistry, FiscalApprovalBuilder, FiscalAuthorityState,
    FiscalBootstrapState, FiscalCharterBuilder, FiscalCharterRegistry, FiscalContinuityChange,
    FiscalContinuityCheckpointBuilder, FiscalDomain, FiscalDomainState, FiscalGenesisPolicy,
    FiscalParams, FiscalProposalAdmissionBuilder, FiscalProposalAdmissionState,
    FiscalProposalBuilder, FiscalProposalTarget, FiscalRuntimeAdapter,
    FiscalRuntimeAdapterRegistry, FiscalRuntimeReadinessBuilder, FiscalScheduleBuilder,
    FiscalScheduleHead, FiscalStagedTransition, VerifiedFiscalActivation, VerifiedFiscalCharter,
    VerifiedFiscalContinuityAdvance, VerifiedFiscalContinuityCheckpoint, VerifiedFiscalProposal,
    VerifiedFiscalProposalAdmission, VerifiedFiscalRuntimeReadiness, VerifiedFiscalSchedule,
    FISCAL_RUNTIME_ADAPTER_COUNT,
};
use tempfile::TempDir;

use super::*;
use crate::SqliteAuthorityStore;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn key(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn domains() -> Vec<FiscalDomainState> {
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

fn registry(version: &str) -> TestResult<FiscalRuntimeAdapterRegistry> {
    Ok(FiscalRuntimeAdapterRegistry::new(
        format!("build-{version}"),
        "chio.fiscal.runtime.v1".to_owned(),
        (0..FISCAL_RUNTIME_ADAPTER_COUNT)
            .map(|index| {
                FiscalRuntimeAdapter::new(format!("adapter-{index}"), format!("{version}.{index}"))
            })
            .collect::<Result<Vec<_>, _>>()?,
    )?)
}

struct FiscalFixture {
    policy: FiscalGenesisPolicy,
    charter: VerifiedFiscalCharter,
    readiness: VerifiedFiscalRuntimeReadiness,
    genesis: VerifiedFiscalContinuityCheckpoint,
    authority: FiscalAuthorityState,
    next_readiness: VerifiedFiscalRuntimeReadiness,
    next_checkpoint: VerifiedFiscalContinuityCheckpoint,
    next_authority: FiscalAuthorityState,
    advance: VerifiedFiscalContinuityAdvance,
}

fn fiscal_fixture() -> TestResult<FiscalFixture> {
    let charter = VerifiedFiscalCharter::verify(
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
    )?;
    let anchor_key = key(8);
    let mut bootstrap = BTreeMap::new();
    bootstrap.insert("USD".to_owned(), [100, 200, 300, 400]);
    let policy = FiscalGenesisPolicy::new(
        "operator.example".to_owned(),
        &charter,
        key(9).public_key(),
        "fiscal-anchor".to_owned(),
        "fiscal-main".to_owned(),
        1,
        anchor_key.public_key(),
        bootstrap,
    )?;
    let readiness_registry = registry("1")?;
    let readiness = VerifiedFiscalRuntimeReadiness::verify(
        FiscalRuntimeReadinessBuilder {
            readiness_sequence: 1,
            runtime_registry: readiness_registry.clone(),
            attested_at: 50,
        }
        .sign(&policy, &anchor_key)?,
        &policy,
        readiness_registry,
    )?;
    let charters = FiscalCharterRegistry::new(vec![charter.signed().clone()])?;
    let genesis = VerifiedFiscalContinuityCheckpoint::verify(
        FiscalContinuityCheckpointBuilder {
            continuity_sequence: 0,
            previous_checkpoint_digest: None,
            pinned_charter_id: charter.body().charter_id.clone(),
            pinned_charter_digest: charter.digest().to_owned(),
            pinned_charter_sequence: 1,
            runtime_readiness_digest: readiness.digest().to_owned(),
            domains: domains(),
            trusted_clock_high_water: 50,
            staged_transition: None,
        }
        .sign(&policy, &anchor_key)?,
        &policy,
        &charters,
    )?;
    let authority = FiscalAuthorityState::from_checkpoint(
        &policy,
        &genesis,
        FiscalBootstrapState::CharterPinned,
    )?;
    let next_registry = registry("2")?;
    let next_readiness = VerifiedFiscalRuntimeReadiness::verify(
        FiscalRuntimeReadinessBuilder {
            readiness_sequence: 2,
            runtime_registry: next_registry.clone(),
            attested_at: 60,
        }
        .sign(&policy, &anchor_key)?,
        &policy,
        next_registry,
    )?;
    let next_signed = FiscalContinuityCheckpointBuilder {
        continuity_sequence: 1,
        previous_checkpoint_digest: Some(genesis.digest().to_owned()),
        pinned_charter_id: charter.body().charter_id.clone(),
        pinned_charter_digest: charter.digest().to_owned(),
        pinned_charter_sequence: 1,
        runtime_readiness_digest: next_readiness.digest().to_owned(),
        domains: domains(),
        trusted_clock_high_water: 60,
        staged_transition: None,
    }
    .sign(&policy, &anchor_key)?;
    let change = FiscalContinuityChange::Readiness {
        current: Box::new(readiness.clone()),
        next: Box::new(next_readiness.clone()),
    };
    let advance = VerifiedFiscalContinuityAdvance::verify(
        &genesis,
        next_signed,
        &policy,
        &charters,
        &change,
    )?;
    let next_checkpoint = advance.next().clone();
    let next_authority = FiscalAuthorityState::from_checkpoint(
        &policy,
        &next_checkpoint,
        FiscalBootstrapState::CharterPinned,
    )?;
    Ok(FiscalFixture {
        policy,
        charter,
        readiness,
        genesis,
        authority,
        next_readiness,
        next_checkpoint,
        next_authority,
        advance,
    })
}

struct FiscalActivationFixture {
    schedule: VerifiedFiscalSchedule,
    proposal: VerifiedFiscalProposal,
    admitted: FiscalProposalAdmissionState,
    activated: FiscalProposalAdmissionState,
    activation: VerifiedFiscalActivation,
    next_checkpoint: VerifiedFiscalContinuityCheckpoint,
    next_authority: FiscalAuthorityState,
    advance: VerifiedFiscalContinuityAdvance,
}

struct FiscalRotationFixture {
    successor_charter: VerifiedFiscalCharter,
    successor_schedule: VerifiedFiscalSchedule,
    proposal: VerifiedFiscalProposal,
    admitted: FiscalProposalAdmissionState,
    activated: FiscalProposalAdmissionState,
    activation: VerifiedFiscalActivation,
    next_checkpoint: VerifiedFiscalContinuityCheckpoint,
    next_authority: FiscalAuthorityState,
    advance: VerifiedFiscalContinuityAdvance,
    charters: FiscalCharterRegistry,
}

fn fiscal_activation_fixture(fixture: &FiscalFixture) -> TestResult<FiscalActivationFixture> {
    let schedule = VerifiedFiscalSchedule::verify(
        FiscalScheduleBuilder {
            domain: FiscalDomain::TierLimits,
            params: FiscalParams::TierLimits {
                ceilings: [100_u64, 200, 300, 400].map(|units| MonetaryAmount {
                    units,
                    currency: "USD".to_owned(),
                }),
            },
            valid_from: 70,
            valid_until: 900,
            issued_at: 70,
            issued_by: "operator.example".to_owned(),
        }
        .sign(&fixture.charter, None, &key(9))?,
        &fixture.charter,
        None,
    )?;
    let proposal = VerifiedFiscalProposal::verify(
        FiscalProposalBuilder {
            target: FiscalProposalTarget::Schedule {
                candidate: Box::new(schedule.signed().clone()),
            },
            rationale_digest: sha256_hex(b"tier amendment"),
            proposed_at: 50,
        }
        .sign(&key(1))?,
        &fixture.charter,
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
        .sign(&proposal, &fixture.charter, &admission_key)?,
        &proposal,
        &fixture.charter,
        &trust,
        55,
    )?;
    let admitted = FiscalProposalAdmissionState::admitted(&admission);
    let approvals = [key(1), key(2)]
        .into_iter()
        .map(|signer| {
            FiscalApprovalBuilder { approved_at: 56 }.sign(
                &proposal,
                &admission,
                &fixture.charter,
                &signer,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let signed_activation = FiscalActivationBuilder {
        target: FiscalActivationTarget::Schedule {
            schedule_id: schedule.body().schedule_id.clone(),
            supersedes_schedule_id: None,
        },
        approvals,
        activated_at: 70,
    }
    .sign(&proposal, &admission, &fixture.charter, &key(1))?;
    let staged_activation = VerifiedFiscalActivation::verify(
        signed_activation.clone(),
        &proposal,
        &admission,
        &admitted,
        &fixture.charter,
        &trust,
        None,
        &[],
        70,
    )?;
    let activated = admitted.activate(staged_activation.digest().to_owned(), 1)?;
    let activation = VerifiedFiscalActivation::verify(
        signed_activation,
        &proposal,
        &admission,
        &activated,
        &fixture.charter,
        &trust,
        None,
        &[],
        70,
    )?;
    let head = FiscalScheduleHead::from_signed(schedule.signed())?;
    let mut next_domains = domains();
    next_domains[0] = FiscalDomainState::activated(FiscalDomain::TierLimits, head.clone(), head)?;
    let next_signed = FiscalContinuityCheckpointBuilder {
        continuity_sequence: 1,
        previous_checkpoint_digest: Some(fixture.genesis.digest().to_owned()),
        pinned_charter_id: fixture.charter.body().charter_id.clone(),
        pinned_charter_digest: fixture.charter.digest().to_owned(),
        pinned_charter_sequence: fixture.charter.body().sequence,
        runtime_readiness_digest: fixture.readiness.digest().to_owned(),
        domains: next_domains,
        trusted_clock_high_water: 70,
        staged_transition: Some(FiscalStagedTransition::new(
            activation.body().activation_id.clone(),
            activation.digest().to_owned(),
        )?),
    }
    .sign(&fixture.policy, &key(8))?;
    let charters = FiscalCharterRegistry::new(vec![fixture.charter.signed().clone()])?;
    let advance = VerifiedFiscalContinuityAdvance::verify(
        &fixture.genesis,
        next_signed,
        &fixture.policy,
        &charters,
        &FiscalContinuityChange::Activation {
            activation: Box::new(activation.clone()),
            readiness: Box::new(fixture.readiness.clone()),
            domain: FiscalDomain::TierLimits,
            schedule: Box::new(schedule.clone()),
        },
    )?;
    let next_checkpoint = advance.next().clone();
    let next_authority = FiscalAuthorityState::from_checkpoint(
        &fixture.policy,
        &next_checkpoint,
        FiscalBootstrapState::CharterPinned,
    )?;
    Ok(FiscalActivationFixture {
        schedule,
        proposal,
        admitted,
        activated,
        activation,
        next_checkpoint,
        next_authority,
        advance,
    })
}

fn fiscal_rotation_fixture(
    fixture: &FiscalFixture,
    current: &FiscalActivationFixture,
) -> TestResult<FiscalRotationFixture> {
    let successor_charter = VerifiedFiscalCharter::verify(
        FiscalCharterBuilder {
            governing_operator_id: "operator.example".to_owned(),
            governed_domains: fixture.charter.body().governed_domains.clone(),
            signer_keys: vec![key(3).public_key(), key(4).public_key()],
            approval_threshold: 2,
            timelock_seconds: 10,
            proposal_ttl_seconds: 100,
            approval_ttl_seconds: 50,
            issued_at: 60,
            expires_at: 950,
            issued_by: "operator.example".to_owned(),
            sequence: 2,
            predecessor_charter_digest: Some(fixture.charter.digest().to_owned()),
        }
        .sign(&key(9))?,
    )?;
    let successor_schedule = VerifiedFiscalSchedule::verify_rotation_replacement(
        FiscalScheduleBuilder {
            domain: FiscalDomain::TierLimits,
            params: current.schedule.body().params.clone(),
            valid_from: current.schedule.body().valid_from,
            valid_until: current.schedule.body().valid_until,
            issued_at: current.schedule.body().issued_at,
            issued_by: "operator.example".to_owned(),
        }
        .sign_rotation_replacement(&successor_charter, &current.schedule, &key(9))?,
        &successor_charter,
        &current.schedule,
    )
    .map_err(|error| std::io::Error::other(format!("verify replacement schedule: {error}")))?;
    let proposal = VerifiedFiscalProposal::verify(
        FiscalProposalBuilder {
            target: FiscalProposalTarget::CharterRotation {
                successor: Box::new(successor_charter.signed().clone()),
            },
            rationale_digest: sha256_hex(b"charter rotation"),
            proposed_at: 72,
        }
        .sign(&key(1))?,
        &fixture.charter,
        None,
    )
    .map_err(|error| std::io::Error::other(format!("verify rotation proposal: {error}")))?;
    let admission_key = key(7);
    let trust = FiscalAdmissionTrustRegistry::new(vec![FiscalAdmissionAuthority::new(
        "operator.example".to_owned(),
        "local-admission".to_owned(),
        1,
        admission_key.public_key(),
    )?])?;
    let admission = VerifiedFiscalProposalAdmission::verify(
        FiscalProposalAdmissionBuilder {
            admission_sequence: 2,
            admitted_at: 73,
            admission_authority_id: "local-admission".to_owned(),
            signer_key_epoch: 1,
        }
        .sign(&proposal, &fixture.charter, &admission_key)?,
        &proposal,
        &fixture.charter,
        &trust,
        73,
    )?;
    let admitted = FiscalProposalAdmissionState::admitted(&admission);
    let approvals = [key(1), key(2)]
        .into_iter()
        .map(|signer| {
            FiscalApprovalBuilder { approved_at: 74 }.sign(
                &proposal,
                &admission,
                &fixture.charter,
                &signer,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let signed_activation = FiscalActivationBuilder {
        target: FiscalActivationTarget::CharterRotation {
            successor_charter_digest: successor_charter.digest().to_owned(),
            predecessor_charter_digest: fixture.charter.digest().to_owned(),
            successor_schedules: vec![successor_schedule.signed().clone()],
        },
        approvals,
        activated_at: 83,
    }
    .sign(&proposal, &admission, &fixture.charter, &key(1))?;
    let staged_activation = VerifiedFiscalActivation::verify(
        signed_activation.clone(),
        &proposal,
        &admission,
        &admitted,
        &fixture.charter,
        &trust,
        None,
        std::slice::from_ref(&current.schedule),
        83,
    )
    .map_err(|error| std::io::Error::other(format!("verify staged rotation: {error}")))?;
    let activated = admitted.activate(staged_activation.digest().to_owned(), 2)?;
    let activation = VerifiedFiscalActivation::verify(
        signed_activation,
        &proposal,
        &admission,
        &activated,
        &fixture.charter,
        &trust,
        None,
        std::slice::from_ref(&current.schedule),
        83,
    )
    .map_err(|error| std::io::Error::other(format!("verify consumed rotation: {error}")))?;
    let successor_head = FiscalScheduleHead::from_signed(successor_schedule.signed())?;
    let mut replacement_domains = current.next_checkpoint.body().domains.clone();
    replacement_domains[0] = FiscalDomainState::activated(
        FiscalDomain::TierLimits,
        successor_head.clone(),
        successor_head,
    )?;
    let next_signed = FiscalContinuityCheckpointBuilder {
        continuity_sequence: 2,
        previous_checkpoint_digest: Some(current.next_checkpoint.digest().to_owned()),
        pinned_charter_id: successor_charter.body().charter_id.clone(),
        pinned_charter_digest: successor_charter.digest().to_owned(),
        pinned_charter_sequence: successor_charter.body().sequence,
        runtime_readiness_digest: fixture.readiness.digest().to_owned(),
        domains: replacement_domains.clone(),
        trusted_clock_high_water: 83,
        staged_transition: Some(FiscalStagedTransition::new(
            activation.body().activation_id.clone(),
            activation.digest().to_owned(),
        )?),
    }
    .sign(&fixture.policy, &key(8))?;
    let charters = FiscalCharterRegistry::new(vec![
        fixture.charter.signed().clone(),
        successor_charter.signed().clone(),
    ])?;
    let advance = VerifiedFiscalContinuityAdvance::verify(
        &current.next_checkpoint,
        next_signed,
        &fixture.policy,
        &charters,
        &FiscalContinuityChange::CharterRotation {
            activation: Box::new(activation.clone()),
            readiness: Box::new(fixture.readiness.clone()),
            predecessor_schedules: vec![current.schedule.clone()],
            replacement_domains,
        },
    )
    .map_err(|error| std::io::Error::other(format!("verify charter rotation advance: {error}")))?;
    let next_checkpoint = advance.next().clone();
    let next_authority = FiscalAuthorityState::from_checkpoint(
        &fixture.policy,
        &next_checkpoint,
        FiscalBootstrapState::CharterPinned,
    )?;
    Ok(FiscalRotationFixture {
        successor_charter,
        successor_schedule,
        proposal,
        admitted,
        activated,
        activation,
        next_checkpoint,
        next_authority,
        advance,
        charters,
    })
}

struct StoreFixture {
    _temp: TempDir,
    database: std::path::PathBuf,
    lock_root: std::path::PathBuf,
}

fn store_fixture() -> TestResult<StoreFixture> {
    let temp = tempfile::tempdir()?;
    secure_temp_directory(temp.path());
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    fs::create_dir(&lock_root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&lock_root, std::fs::Permissions::from_mode(0o700))
            .expect("secure directory");
    }
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    Ok(StoreFixture {
        _temp: temp,
        database,
        lock_root,
    })
}

#[test]
fn fiscal_schema_migrates_the_single_open_transition_guard() -> TestResult {
    let mut connection = rusqlite::Connection::open_in_memory()?;
    initialize_fiscal_schema(&mut connection)?;
    connection.execute(
        "UPDATE chio_store_schema_versions SET version = 1 WHERE store_key = 'fiscal'",
        [],
    )?;
    connection.execute("DROP INDEX fiscal_one_open_transition", [])?;

    initialize_fiscal_schema(&mut connection)?;

    let version: i32 = connection.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = 'fiscal'",
        [],
        |row| row.get(0),
    )?;
    let index_present: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'index' AND name = 'fiscal_one_open_transition')",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(version, FISCAL_STORE_SUPPORTED_SCHEMA_VERSION);
    assert!(index_present);
    Ok(())
}

#[test]
fn fiscal_schema_migrates_the_legacy_envelope_digest_binding() -> TestResult {
    let mut connection = rusqlite::Connection::open_in_memory()?;
    initialize_fiscal_schema(&mut connection)?;
    connection.execute(
        "UPDATE chio_store_schema_versions SET version = 2 WHERE store_key = 'fiscal'",
        [],
    )?;
    connection.execute_batch(
        "DROP TRIGGER fiscal_legacy_fee_schedule_bindings_immutable;
         DROP TRIGGER fiscal_legacy_fee_schedule_bindings_no_delete;
         ALTER TABLE fiscal_legacy_fee_schedule_bindings DROP COLUMN legacy_envelope_digest;",
    )?;

    initialize_fiscal_schema(&mut connection)?;

    let digest_column_present = connection
        .prepare("PRAGMA table_info(fiscal_legacy_fee_schedule_bindings)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .any(|column| column == "legacy_envelope_digest");
    assert!(digest_column_present);
    Ok(())
}

#[test]
fn fiscal_schema_migrates_atomic_charter_rotation_tables() -> TestResult {
    let mut connection = rusqlite::Connection::open_in_memory()?;
    initialize_fiscal_schema(&mut connection)?;
    connection.execute(
        "UPDATE chio_store_schema_versions SET version = 4 WHERE store_key = 'fiscal'",
        [],
    )?;
    connection.execute_batch(
        "DROP TRIGGER fiscal_staged_rotation_schedules_no_delete;
         DROP TRIGGER fiscal_staged_rotation_schedules_immutable;
         DROP TRIGGER fiscal_staged_rotation_mutations_no_delete;
         DROP TRIGGER fiscal_staged_rotation_mutations_immutable;
         DROP TABLE fiscal_staged_rotation_schedules;
         DROP TABLE fiscal_staged_rotation_mutations;",
    )?;

    initialize_fiscal_schema(&mut connection)?;

    let tables: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name IN ('fiscal_staged_rotation_mutations', 'fiscal_staged_rotation_schedules')",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(tables, 2);
    Ok(())
}

#[test]
fn fiscal_schema_migrates_durable_admission_sequence() -> TestResult {
    let mut connection = rusqlite::Connection::open_in_memory()?;
    initialize_fiscal_schema(&mut connection)?;
    connection.execute(
        "UPDATE chio_store_schema_versions SET version = 5 WHERE store_key = 'fiscal'",
        [],
    )?;
    connection.execute("DROP TABLE fiscal_admission_sequence", [])?;

    initialize_fiscal_schema(&mut connection)?;

    assert_eq!(
        connection.query_row(
            "SELECT current_sequence FROM fiscal_admission_sequence WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        0
    );
    Ok(())
}

#[test]
fn fiscal_genesis_is_exact_idempotent_and_survives_restart() -> TestResult {
    let files = store_fixture()?;
    let fixture = fiscal_fixture()?;
    let authority = SqliteAuthorityStore::open_serving(&files.database, &files.lock_root)?;
    let fence = authority.mutation_fence();
    let store = authority.fiscal_store();
    store.initialize_genesis(
        &fixture.policy,
        &fixture.authority,
        &fixture.charter,
        &fixture.readiness,
        &fixture.genesis,
        &fence,
    )?;
    store.initialize_genesis(
        &fixture.policy,
        &fixture.authority,
        &fixture.charter,
        &fixture.readiness,
        &fixture.genesis,
        &fence,
    )?;
    assert_eq!(store.load_authority_state()?, fixture.authority);
    drop(store);
    drop(authority);

    let reopened = SqliteAuthorityStore::open_serving(&files.database, &files.lock_root)?;
    let reopened_store = reopened.fiscal_store();
    assert_eq!(reopened_store.load_authority_state()?, fixture.authority);
    assert_eq!(reopened_store.load_genesis_policy()?, fixture.policy);
    assert_eq!(
        reopened_store
            .load_charter_registry()?
            .resolve(
                fixture.charter.body().charter_id.as_str(),
                fixture.charter.digest()
            )?
            .signed(),
        fixture.charter.signed()
    );
    let readiness =
        reopened_store.load_runtime_readiness(fixture.readiness.digest(), &fixture.policy)?;
    assert_eq!(readiness.digest(), fixture.readiness.digest());
    assert_eq!(
        readiness.runtime_registry(),
        fixture.readiness.runtime_registry()
    );
    assert!(reopened_store.load_signed_schedules()?.is_empty());
    Ok(())
}

#[test]
fn fiscal_admission_is_store_assigned_and_one_per_proposal() -> TestResult {
    let files = store_fixture()?;
    let fixture = fiscal_fixture()?;
    let activation = fiscal_activation_fixture(&fixture)?;
    let authority = SqliteAuthorityStore::open_serving(&files.database, &files.lock_root)?;
    let fence = authority.mutation_fence();
    let store = authority.fiscal_store();
    store.initialize_genesis(
        &fixture.policy,
        &fixture.authority,
        &fixture.charter,
        &fixture.readiness,
        &fixture.genesis,
        &fence,
    )?;
    store.persist_schedule(&activation.schedule, &fence)?;
    store.persist_proposal(&activation.proposal, &fence)?;

    let admission = store.admit_proposal(
        &activation.proposal,
        &fixture.charter,
        "local-admission",
        1,
        &key(7),
        55,
        &fence,
    )?;

    assert_eq!(admission.body().admission_sequence, 1);
    assert_eq!(admission.signed(), &activation.admitted.signed_admission);
    assert_eq!(
        store
            .load_admission_state(&admission.body().admission_id)?
            .signed_admission,
        *admission.signed()
    );
    assert!(matches!(
        store.admit_proposal(
            &activation.proposal,
            &fixture.charter,
            "local-admission",
            1,
            &key(7),
            56,
            &fence,
        ),
        Err(FiscalStoreError::Conflict)
    ));
    drop(store);
    drop(authority);

    let reopened = SqliteAuthorityStore::open_serving(&files.database, &files.lock_root)?;
    let connection = rusqlite::Connection::open(&files.database)?;
    assert_eq!(
        connection.query_row(
            "SELECT current_sequence FROM fiscal_admission_sequence WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        1
    );
    drop(reopened);
    Ok(())
}

#[test]
fn staged_fiscal_advance_is_invisible_until_anchor_ack_and_finalize() -> TestResult {
    let files = store_fixture()?;
    let fixture = fiscal_fixture()?;
    let authority = SqliteAuthorityStore::open_serving(&files.database, &files.lock_root)?;
    let fence = authority.mutation_fence();
    let store = authority.fiscal_store();
    store.initialize_genesis(
        &fixture.policy,
        &fixture.authority,
        &fixture.charter,
        &fixture.readiness,
        &fixture.genesis,
        &fence,
    )?;
    store.persist_runtime_readiness(&fixture.next_readiness, &fence)?;
    let staged = store.stage_advance(&fixture.advance, &fixture.next_authority, &fence)?;
    assert_eq!(staged.status, FiscalStageStatus::DbStaged);
    assert_eq!(store.load_authority_state()?, fixture.authority);
    assert_eq!(
        store
            .stage_advance(&fixture.advance, &fixture.next_authority, &fence)?
            .transition_id,
        staged.transition_id
    );
    drop(store);
    drop(authority);

    let reopened = SqliteAuthorityStore::open_serving(&files.database, &files.lock_root)?;
    let reopened_fence = reopened.mutation_fence();
    let store = reopened.fiscal_store();
    assert_eq!(
        store.load_transition(&staged.transition_id)?.status,
        FiscalStageStatus::DbStaged
    );
    let anchored = store.mark_anchor_advanced(
        &staged.transition_id,
        &fixture.next_checkpoint,
        &reopened_fence,
    )?;
    assert_eq!(anchored.status, FiscalStageStatus::FiscalAnchorAdvanced);
    assert_eq!(store.load_authority_state()?, fixture.authority);
    let finalized = store.finalize_advance(
        &staged.transition_id,
        &fixture.next_checkpoint,
        &fixture.next_authority,
        &reopened_fence,
    )?;
    assert_eq!(finalized.status, FiscalStageStatus::DbFinalized);
    assert_eq!(store.load_authority_state()?, fixture.next_authority);
    assert_eq!(
        fixture.next_checkpoint.body().runtime_readiness_digest,
        fixture.next_readiness.digest()
    );
    Ok(())
}

#[test]
fn activation_finalize_atomically_consumes_admission_and_flips_schedule() -> TestResult {
    let files = store_fixture()?;
    let fixture = fiscal_fixture()?;
    let activation = fiscal_activation_fixture(&fixture)?;
    let authority = SqliteAuthorityStore::open_serving(&files.database, &files.lock_root)?;
    let fence = authority.mutation_fence();
    let store = authority.fiscal_store();
    store.initialize_genesis(
        &fixture.policy,
        &fixture.authority,
        &fixture.charter,
        &fixture.readiness,
        &fixture.genesis,
        &fence,
    )?;
    store.persist_schedule(&activation.schedule, &fence)?;
    store.persist_proposal(&activation.proposal, &fence)?;
    store.persist_admission_state(&activation.admitted, None, &fence)?;
    store.persist_activation(&activation.activation, &fence)?;
    assert!(store.load_signed_activations()?.is_empty());

    let staged = store
        .stage_activation_advance(
            &activation.advance,
            &activation.next_authority,
            &activation.activation,
            &activation.activated,
            &activation.schedule,
            None,
            &fence,
        )
        .map_err(|error| std::io::Error::other(format!("stage activation: {error}")))?;
    assert_eq!(staged.status, FiscalStageStatus::DbStaged);
    assert!(store.load_signed_activations()?.is_empty());
    assert_eq!(
        fiscal_activation_projection(&files.database, &activation)?,
        ("admitted".to_owned(), 1, "staged".to_owned())
    );
    store.mark_anchor_advanced(&staged.transition_id, &activation.next_checkpoint, &fence)?;
    store.finalize_advance(
        &staged.transition_id,
        &activation.next_checkpoint,
        &activation.next_authority,
        &fence,
    )?;
    assert_eq!(
        fiscal_activation_projection(&files.database, &activation)?,
        ("activated".to_owned(), 2, "active".to_owned())
    );
    assert_eq!(store.load_authority_state()?, activation.next_authority);
    assert_eq!(store.load_signed_activations()?.len(), 1);
    assert_eq!(
        store
            .load_verified_schedule(
                &activation.schedule.body().schedule_id,
                &FiscalCharterRegistry::new(vec![fixture.charter.signed().clone()])?,
            )?
            .signed(),
        activation.schedule.signed()
    );
    Ok(())
}

#[test]
fn charter_rotation_finalize_atomically_flips_charter_and_all_schedules() -> TestResult {
    let files = store_fixture()?;
    let fixture = fiscal_fixture()?;
    let current = fiscal_activation_fixture(&fixture)?;
    let rotation = fiscal_rotation_fixture(&fixture, &current)?;
    let authority = SqliteAuthorityStore::open_serving(&files.database, &files.lock_root)?;
    let fence = authority.mutation_fence();
    let store = authority.fiscal_store();
    store
        .initialize_genesis(
            &fixture.policy,
            &fixture.authority,
            &fixture.charter,
            &fixture.readiness,
            &fixture.genesis,
            &fence,
        )
        .map_err(|error| std::io::Error::other(format!("initialize rotation store: {error}")))?;
    store
        .persist_schedule(&current.schedule, &fence)
        .map_err(|error| std::io::Error::other(format!("persist current schedule: {error}")))?;
    store
        .persist_proposal(&current.proposal, &fence)
        .map_err(|error| std::io::Error::other(format!("persist current proposal: {error}")))?;
    store
        .persist_admission_state(&current.admitted, None, &fence)
        .map_err(|error| std::io::Error::other(format!("persist current admission: {error}")))?;
    store
        .persist_activation(&current.activation, &fence)
        .map_err(|error| std::io::Error::other(format!("persist current activation: {error}")))?;
    let current_stage = store
        .stage_activation_advance(
            &current.advance,
            &current.next_authority,
            &current.activation,
            &current.activated,
            &current.schedule,
            None,
            &fence,
        )
        .map_err(|error| std::io::Error::other(format!("stage current activation: {error}")))?;
    store
        .mark_anchor_advanced(
            &current_stage.transition_id,
            &current.next_checkpoint,
            &fence,
        )
        .map_err(|error| std::io::Error::other(format!("mark current anchored: {error}")))?;
    store
        .finalize_advance(
            &current_stage.transition_id,
            &current.next_checkpoint,
            &current.next_authority,
            &fence,
        )
        .map_err(|error| std::io::Error::other(format!("finalize current activation: {error}")))?;

    store
        .persist_charter(&rotation.successor_charter, &fence)
        .map_err(|error| std::io::Error::other(format!("persist successor charter: {error}")))?;
    store
        .persist_schedule(&rotation.successor_schedule, &fence)
        .map_err(|error| std::io::Error::other(format!("persist successor schedule: {error}")))?;
    store
        .persist_proposal(&rotation.proposal, &fence)
        .map_err(|error| std::io::Error::other(format!("persist rotation proposal: {error}")))?;
    store
        .persist_admission_state(&rotation.admitted, None, &fence)
        .map_err(|error| std::io::Error::other(format!("persist rotation admission: {error}")))?;
    store
        .persist_activation(&rotation.activation, &fence)
        .map_err(|error| std::io::Error::other(format!("persist rotation activation: {error}")))?;
    let staged = store
        .stage_charter_rotation_advance(
            &rotation.advance,
            &rotation.next_authority,
            &rotation.activation,
            &rotation.activated,
            &rotation.successor_charter,
            std::slice::from_ref(&rotation.successor_schedule),
            &fixture.charter,
            std::slice::from_ref(&current.schedule),
            &fence,
        )
        .map_err(|error| std::io::Error::other(format!("stage charter rotation: {error}")))?;
    assert_eq!(
        fiscal_rotation_projection(&files.database, &fixture, &current, &rotation)?,
        (
            "admitted".to_owned(),
            "pinned".to_owned(),
            "proposed".to_owned(),
            "active".to_owned(),
            "staged".to_owned(),
        )
    );
    store
        .mark_anchor_advanced(&staged.transition_id, &rotation.next_checkpoint, &fence)
        .map_err(|error| std::io::Error::other(format!("mark rotation anchored: {error}")))?;
    store
        .finalize_advance(
            &staged.transition_id,
            &rotation.next_checkpoint,
            &rotation.next_authority,
            &fence,
        )
        .map_err(|error| std::io::Error::other(format!("finalize charter rotation: {error}")))?;
    assert_eq!(
        fiscal_rotation_projection(&files.database, &fixture, &current, &rotation)?,
        (
            "activated".to_owned(),
            "superseded".to_owned(),
            "active".to_owned(),
            "superseded".to_owned(),
            "active".to_owned(),
        )
    );
    assert_eq!(
        store.load_authority_state().map_err(|error| {
            std::io::Error::other(format!("load authority after rotation: {error}"))
        })?,
        rotation.next_authority
    );
    assert_eq!(
        rotation
            .charters
            .resolve(
                &rotation.next_checkpoint.body().pinned_charter_id,
                &rotation.next_checkpoint.body().pinned_charter_digest,
            )?
            .digest(),
        rotation.successor_charter.digest()
    );
    assert_eq!(
        store
            .load_verified_schedule(
                &rotation.successor_schedule.body().schedule_id,
                &rotation.charters,
            )?
            .signed(),
        rotation.successor_schedule.signed()
    );
    Ok(())
}

#[test]
fn discarded_activation_stage_preserves_admission_and_candidate_state() -> TestResult {
    let files = store_fixture()?;
    let fixture = fiscal_fixture()?;
    let activation = fiscal_activation_fixture(&fixture)?;
    let authority = SqliteAuthorityStore::open_serving(&files.database, &files.lock_root)?;
    let fence = authority.mutation_fence();
    let store = authority.fiscal_store();
    store.initialize_genesis(
        &fixture.policy,
        &fixture.authority,
        &fixture.charter,
        &fixture.readiness,
        &fixture.genesis,
        &fence,
    )?;
    store.persist_schedule(&activation.schedule, &fence)?;
    store.persist_proposal(&activation.proposal, &fence)?;
    store.persist_admission_state(&activation.admitted, None, &fence)?;
    store.persist_activation(&activation.activation, &fence)?;
    let staged = store.stage_activation_advance(
        &activation.advance,
        &activation.next_authority,
        &activation.activation,
        &activation.activated,
        &activation.schedule,
        None,
        &fence,
    )?;

    store.discard_unanchored_stage(&staged.transition_id, &fence)?;

    assert_eq!(
        fiscal_activation_projection(&files.database, &activation)?,
        ("admitted".to_owned(), 1, "staged".to_owned())
    );
    assert_eq!(store.load_authority_state()?, fixture.authority);
    Ok(())
}

fn fiscal_activation_projection(
    database: &std::path::Path,
    activation: &FiscalActivationFixture,
) -> TestResult<(String, i64, String)> {
    let connection = rusqlite::Connection::open(database)?;
    let admission = connection.query_row(
        "SELECT status, state_version FROM fiscal_proposal_admissions WHERE admission_id = ?1",
        [&activation.admitted.signed_admission.body.admission_id],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
    )?;
    let schedule_state = connection.query_row(
        "SELECT lifecycle_state FROM fiscal_schedules WHERE schedule_id = ?1",
        [&activation.schedule.body().schedule_id],
        |row| row.get::<_, String>(0),
    )?;
    Ok((admission.0, admission.1, schedule_state))
}

fn fiscal_rotation_projection(
    database: &std::path::Path,
    fixture: &FiscalFixture,
    current: &FiscalActivationFixture,
    rotation: &FiscalRotationFixture,
) -> TestResult<(String, String, String, String, String)> {
    let connection = rusqlite::Connection::open(database)?;
    let admission = connection.query_row(
        "SELECT status FROM fiscal_proposal_admissions WHERE admission_id = ?1",
        [&rotation.admitted.signed_admission.body.admission_id],
        |row| row.get::<_, String>(0),
    )?;
    let predecessor_charter = connection.query_row(
        "SELECT lifecycle_state FROM fiscal_charters WHERE charter_id = ?1",
        [&fixture.charter.body().charter_id],
        |row| row.get::<_, String>(0),
    )?;
    let successor_charter = connection.query_row(
        "SELECT lifecycle_state FROM fiscal_charters WHERE charter_id = ?1",
        [&rotation.successor_charter.body().charter_id],
        |row| row.get::<_, String>(0),
    )?;
    let predecessor_schedule = connection.query_row(
        "SELECT lifecycle_state FROM fiscal_schedules WHERE schedule_id = ?1",
        [&current.schedule.body().schedule_id],
        |row| row.get::<_, String>(0),
    )?;
    let successor_schedule = connection.query_row(
        "SELECT lifecycle_state FROM fiscal_schedules WHERE schedule_id = ?1",
        [&rotation.successor_schedule.body().schedule_id],
        |row| row.get::<_, String>(0),
    )?;
    Ok((
        admission,
        predecessor_charter,
        successor_charter,
        predecessor_schedule,
        successor_schedule,
    ))
}

#[test]
fn unanchored_fiscal_stage_can_be_discarded_without_advancing_authority() -> TestResult {
    let files = store_fixture()?;
    let fixture = fiscal_fixture()?;
    let authority = SqliteAuthorityStore::open_serving(&files.database, &files.lock_root)?;
    let fence = authority.mutation_fence();
    let store = authority.fiscal_store();
    store.initialize_genesis(
        &fixture.policy,
        &fixture.authority,
        &fixture.charter,
        &fixture.readiness,
        &fixture.genesis,
        &fence,
    )?;
    store.persist_runtime_readiness(&fixture.next_readiness, &fence)?;
    let staged = store.stage_advance(&fixture.advance, &fixture.next_authority, &fence)?;
    let discarded = store.discard_unanchored_stage(&staged.transition_id, &fence)?;
    assert_eq!(discarded.status, FiscalStageStatus::Discarded);
    assert_eq!(store.load_authority_state()?, fixture.authority);
    assert_eq!(sha256_hex(&discarded.proof_json), staged.transition_id);
    Ok(())
}

fn secure_temp_directory(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("secure temp directory");
    }
    #[cfg(not(unix))]
    let _ = path;
}
