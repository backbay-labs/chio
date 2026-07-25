use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::economic_continuity::{
    verify_economic_state_batch_advance, verify_economic_state_view, EconomicContentV1,
    EconomicResourceHeadV1, EconomicResourceKeyV1, EconomicStateAnchorError,
    EconomicStateAnchorPins, EconomicStateAnchorViewV1, EconomicStateBatchV1,
    EconomicStateTransitionV1, EconomicTransitionAuthorizationV1, EconomicTransitionProofVerifier,
    VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView,
    CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA, CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA,
    CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
};
use chio_kernel::admission_operation::{
    AdmissionDigest, AdmissionIdentifier, AdmissionOperationBindingInputV1,
    AdmissionOperationBindingV1, AdmissionOperationCommand, AdmissionOperationKind,
    AdmissionOperationStore, AdmissionOperationV1, AdmissionParticipantRequirements,
    AdmissionRequestBindingV1, AuthenticatedRequestNamespace, QualifiedAdmissionOperationStoreExt,
    SideEffectClass,
};
use serde_json::json;
use tempfile::TempDir;

use super::*;
use crate::SqliteAuthorityStore;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    _temp: TempDir,
    _authority: SqliteAuthorityStore,
    cache: SqliteEconomicStateCache,
    fence: chio_core::StoreMutationFence,
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().expect("tempdir");
    secure_temp_directory(temp.path());
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    fs::create_dir(&lock_root).expect("create lock root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&lock_root, std::fs::Permissions::from_mode(0o700))
            .expect("secure directory");
    }
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision authority");
    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open authority");
    let fence = authority.mutation_fence();
    let cache = authority.economic_state_cache();
    Fixture {
        _temp: temp,
        _authority: authority,
        cache,
        fence,
    }
}

fn digest(label: &str) -> String {
    sha256_hex(label.as_bytes())
}

fn pins() -> EconomicStateAnchorPins {
    EconomicStateAnchorPins {
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        signer_public_key: Keypair::from_seed(&[0x41; 32]).public_key(),
    }
}

fn key() -> EconomicResourceKeyV1 {
    EconomicResourceKeyV1 {
        resource_family: "clearing_round".to_owned(),
        scope_id: "market-1".to_owned(),
        resource_id: "round-1".to_owned(),
    }
}

fn head() -> TestResult<EconomicResourceHeadV1> {
    let state = EconomicContentV1::Inline {
        value: json!({"roundId": "round-1", "state": "open"}),
    };
    Ok(EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        resource_key: key(),
        head_version: 1,
        resource_version: 1,
        lifecycle_fence: 1,
        lifecycle_state: "open".to_owned(),
        state_digest: state.digest()?,
        state,
        operation_id: None,
        effect_idempotency_key: None,
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: 100,
        predecessor_digest: None,
    })
}

fn signed_view(
    checkpoint_sequence: u64,
    checkpoint_digest: String,
    heads: Vec<EconomicResourceHeadV1>,
    absent_resource_keys: Vec<EconomicResourceKeyV1>,
) -> TestResult<EconomicStateAnchorViewV1> {
    let mut view = EconomicStateAnchorViewV1 {
        schema: CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA.to_owned(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        checkpoint_sequence,
        checkpoint_digest,
        heads_root: String::new(),
        heads,
        absent_resource_keys,
        request_replays_root: String::new(),
        request_replays: Vec::new(),
        absent_request_keys: Vec::new(),
        observed_at: 100 + checkpoint_sequence,
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    view.seal(&Keypair::from_seed(&[0x41; 32]))?;
    Ok(view)
}

#[derive(Debug)]
struct DirectVerifier;

impl EconomicTransitionProofVerifier for DirectVerifier {
    fn verify_transition(
        &self,
        _current: Option<&EconomicResourceHeadV1>,
        _transition: &EconomicStateTransitionV1,
    ) -> Result<EconomicTransitionAuthorizationV1, EconomicStateAnchorError> {
        Ok(EconomicTransitionAuthorizationV1::Direct)
    }
}

fn verified_advance() -> TestResult<(VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView)>
{
    verified_advance_for_operation(None)
}

fn verified_advance_for_operation(
    operation_id: Option<String>,
) -> TestResult<(VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView)> {
    let resource_head = head()?;
    let current = verify_economic_state_view(
        signed_view(1, digest("checkpoint-1"), Vec::new(), vec![key()])?,
        &pins(),
    )?;
    let mut batch = EconomicStateBatchV1 {
        schema: CHIO_ECONOMIC_STATE_BATCH_SCHEMA.to_owned(),
        batch_id: String::new(),
        checkpoint_digest: String::new(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        checkpoint_sequence: 2,
        previous_checkpoint_digest: Some(current.view().checkpoint_digest.clone()),
        expected_heads_root: String::new(),
        next_heads_root: String::new(),
        transitions: vec![EconomicStateTransitionV1 {
            resource_key: key(),
            expected_head_digest: None,
            next_head: resource_head.clone(),
            transition_proof_digest: digest("transition-proof"),
            prepared_effect: None,
        }],
        effect_slots: Vec::new(),
        request_replays: Vec::new(),
        operation_id,
        issued_at: 101,
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    batch.seal(&Keypair::from_seed(&[0x41; 32]))?;
    let advance = verify_economic_state_batch_advance(&current, batch, &pins(), &DirectVerifier)?;
    let committed = verify_economic_state_view(
        signed_view(
            2,
            advance.batch().checkpoint_digest.clone(),
            vec![resource_head],
            Vec::new(),
        )?,
        &pins(),
    )?;
    Ok((advance, committed))
}

fn verified_channel_shaped_advance() -> TestResult<VerifiedEconomicStateBatchAdvance> {
    let channel_key = EconomicResourceKeyV1 {
        resource_family: chio_settle::channel::CHANNEL_LIFECYCLE_RESOURCE_FAMILY.to_owned(),
        scope_id: "market-1".to_owned(),
        resource_id: digest("channel-resource"),
    };
    let mut resource_head = head()?;
    resource_head.resource_key = channel_key.clone();
    let current = verify_economic_state_view(
        signed_view(
            1,
            digest("channel-checkpoint-1"),
            Vec::new(),
            vec![channel_key.clone()],
        )?,
        &pins(),
    )?;
    let mut batch = EconomicStateBatchV1 {
        schema: CHIO_ECONOMIC_STATE_BATCH_SCHEMA.to_owned(),
        batch_id: String::new(),
        checkpoint_digest: String::new(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        checkpoint_sequence: 2,
        previous_checkpoint_digest: Some(current.view().checkpoint_digest.clone()),
        expected_heads_root: String::new(),
        next_heads_root: String::new(),
        transitions: vec![EconomicStateTransitionV1 {
            resource_key: channel_key,
            expected_head_digest: None,
            next_head: resource_head,
            transition_proof_digest: digest("channel-transition-proof"),
            prepared_effect: None,
        }],
        effect_slots: Vec::new(),
        request_replays: Vec::new(),
        operation_id: Some(digest("channel-operation")),
        issued_at: 101,
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    batch.seal(&Keypair::from_seed(&[0x41; 32]))?;
    Ok(verify_economic_state_batch_advance(
        &current,
        batch,
        &pins(),
        &DirectVerifier,
    )?)
}

fn verified_successor(
    current: &VerifiedEconomicStateView,
) -> TestResult<(VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView)> {
    let current_head = current
        .view()
        .heads
        .first()
        .ok_or("current head is missing")?;
    let mut next_head = current_head.clone();
    next_head.head_version += 1;
    next_head.resource_version += 1;
    next_head.lifecycle_fence += 1;
    next_head.trusted_clock_high_water += 1;
    next_head.predecessor_digest = Some(current_head.digest()?);
    let state = EconomicContentV1::Inline {
        value: json!({"roundId": "round-1", "state": "finalized"}),
    };
    next_head.state_digest = state.digest()?;
    next_head.state = state;
    next_head.lifecycle_state = "finalized".to_owned();
    let mut batch = EconomicStateBatchV1 {
        schema: CHIO_ECONOMIC_STATE_BATCH_SCHEMA.to_owned(),
        batch_id: String::new(),
        checkpoint_digest: String::new(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        checkpoint_sequence: current.view().checkpoint_sequence + 1,
        previous_checkpoint_digest: Some(current.view().checkpoint_digest.clone()),
        expected_heads_root: String::new(),
        next_heads_root: String::new(),
        transitions: vec![EconomicStateTransitionV1 {
            resource_key: key(),
            expected_head_digest: Some(current_head.digest()?),
            next_head: next_head.clone(),
            transition_proof_digest: digest("successor-transition-proof"),
            prepared_effect: None,
        }],
        effect_slots: Vec::new(),
        request_replays: Vec::new(),
        operation_id: None,
        issued_at: 102,
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    batch.seal(&Keypair::from_seed(&[0x41; 32]))?;
    let advance = verify_economic_state_batch_advance(current, batch, &pins(), &DirectVerifier)?;
    let committed = verify_economic_state_view(
        signed_view(
            advance.batch().checkpoint_sequence,
            advance.batch().checkpoint_digest.clone(),
            vec![next_head],
            Vec::new(),
        )?,
        &pins(),
    )?;
    Ok((advance, committed))
}

fn identifier(field: &'static str, value: &str) -> AdmissionIdentifier {
    AdmissionIdentifier::try_new(field, value).expect("valid identifier")
}

fn admission_digest(field: &'static str, byte: char) -> AdmissionDigest {
    AdmissionDigest::try_new(field, byte.to_string().repeat(64)).expect("valid digest")
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_millis(),
    )
    .expect("system time fits u64")
}

fn prepared_economic_operation(
    fence: &chio_core::StoreMutationFence,
    request_id: &str,
) -> AdmissionOperationV1 {
    let namespace = AuthenticatedRequestNamespace::for_local_system(identifier(
        "coordinator_authority_id",
        "economic-cache-test",
    ))
    .expect("request namespace");
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::GovernedEconomicMutation,
        namespace,
        request_id: identifier("request_id", request_id),
        capability_id: identifier("capability_id", "economic-cache-capability"),
        authorization_capability_hash: admission_digest("authorization_capability_hash", 'a'),
        request_binding: AdmissionRequestBindingV1::new(
            admission_digest("immutable_request_hash", 'b'),
            AdmissionParticipantRequirements::NONE,
        )
        .expect("request binding"),
        policy_hash: admission_digest("policy_hash", 'c'),
        effect_class: SideEffectClass::Monetary,
    })
    .expect("operation binding");
    AdmissionOperationV1::prepare(binding, fence.owner_epoch).expect("prepared operation")
}

#[test]
fn stage_retains_exact_bytes_and_rejects_a_stale_serving_fence() -> TestResult {
    let fixture = fixture();
    let (advance, _) = verified_advance()?;
    let staged = fixture
        .cache
        .stage_batch(&advance, None, &fixture.fence, 1_000)?;
    assert_eq!(staged.status(), EconomicStateStageStatus::DbStaged);
    assert_eq!(staged.batch(), advance.batch());
    assert_eq!(staged.base_view(), advance.current().view());
    assert_eq!(staged.version(), 1);

    let replay = fixture
        .cache
        .stage_batch(&advance, None, &fixture.fence, 1_001)?;
    assert_eq!(replay, staged);

    let mut stale = fixture.fence.clone();
    stale.owner_epoch += 1;
    assert!(matches!(
        fixture.cache.stage_batch(&advance, None, &stale, 1_002),
        Err(EconomicStateCacheError::Fenced)
    ));
    Ok(())
}

#[test]
fn generic_stage_rejects_channel_content_even_under_a_generic_descriptor() -> TestResult {
    let fixture = fixture();
    let advance = verified_channel_shaped_advance()?;
    let descriptor = EconomicStateStageDescriptor::new(
        "generic.replay.v1",
        "generic-channel-label",
        &json!({"kind": "generic"}),
    )?;

    assert!(matches!(
        fixture.cache.stage_batch_with_descriptor(
            &advance,
            None,
            Some(descriptor),
            &fixture.fence,
            1_000,
        ),
        Err(EconomicStateCacheError::Conflict)
    ));
    assert!(fixture
        .cache
        .load_stage(&advance.batch().batch_id)?
        .is_none());
    Ok(())
}

#[test]
fn stage_commits_one_exact_consumer_descriptor_with_the_batch() -> TestResult {
    let fixture = fixture();
    let (advance, committed) = verified_advance()?;
    let descriptor_body = json!({
        "roundId": "round-1",
        "roundCoreDigest": digest("round-core"),
        "transitionProofDigest": digest("transition-proof"),
    });
    let descriptor =
        EconomicStateStageDescriptor::new("clearing_round", "round-1", &descriptor_body)?;
    let staged = fixture.cache.stage_batch_with_descriptor(
        &advance,
        None,
        Some(descriptor.clone()),
        &fixture.fence,
        1_000,
    )?;
    assert_eq!(staged.descriptor(), Some(&descriptor));
    assert_eq!(
        staged
            .descriptor()
            .ok_or("missing consumer descriptor")?
            .decode::<serde_json::Value>()?,
        descriptor_body
    );

    let replay = fixture.cache.stage_batch_with_descriptor(
        &advance,
        None,
        Some(descriptor),
        &fixture.fence,
        1_001,
    )?;
    assert_eq!(replay, staged);

    let conflicting = EconomicStateStageDescriptor::new(
        "clearing_round",
        "round-1",
        &json!({"roundId": "round-2"}),
    )?;
    assert!(matches!(
        fixture.cache.stage_batch_with_descriptor(
            &advance,
            None,
            Some(conflicting),
            &fixture.fence,
            1_002,
        ),
        Err(EconomicStateCacheError::Conflict)
    ));
    assert!(matches!(
        fixture
            .cache
            .stage_batch(&advance, None, &fixture.fence, 1_003),
        Err(EconomicStateCacheError::Conflict)
    ));
    let (successor, _) = verified_successor(&committed)?;
    assert!(matches!(
        fixture.cache.stage_batch_with_descriptor(
            &successor,
            None,
            Some(EconomicStateStageDescriptor::new(
                "clearing_round",
                "round-1",
                &descriptor_body,
            )?),
            &fixture.fence,
            1_004,
        ),
        Err(EconomicStateCacheError::Conflict)
    ));
    Ok(())
}

#[test]
fn reserved_descriptor_and_admission_checkpoint_are_one_stage_fence() -> TestResult {
    let fixture = fixture();
    let (advance, committed) = verified_advance()?;
    let descriptor_body = json!({"proof": digest("proof-1")});
    let descriptor = EconomicStateStageDescriptor::new(
        CLEARING_LIFECYCLE_REPLAY_DESCRIPTOR_KIND,
        digest("proof-1"),
        &descriptor_body,
    )?;
    let staged = fixture.cache.stage_clearing_lifecycle_batch(
        &advance,
        descriptor.clone(),
        Some(EconomicStageAdmissionCheckpoint {
            store_id: &fixture.fence.store_uuid,
            sequence: 0,
            digest: crate::admission_operation_store::GENESIS_CHAIN_DIGEST,
        }),
        &fixture.fence,
        1_000,
    )?;
    assert_eq!(staged.descriptor(), Some(&descriptor));
    assert_eq!(
        fixture.cache.load_stage_by_descriptor(
            CLEARING_LIFECYCLE_REPLAY_DESCRIPTOR_KIND,
            &digest("proof-1"),
        )?,
        Some(staged)
    );

    let (successor, _) = verified_successor(&committed)?;
    let stale = EconomicStateStageDescriptor::new(
        CLEARING_LIFECYCLE_REPLAY_DESCRIPTOR_KIND,
        digest("proof-2"),
        &json!({"proof": digest("proof-2")}),
    )?;
    assert!(matches!(
        fixture.cache.stage_clearing_lifecycle_batch(
            &successor,
            stale,
            Some(EconomicStageAdmissionCheckpoint {
                store_id: &fixture.fence.store_uuid,
                sequence: 1,
                digest: &digest("missing-admission-commit"),
            }),
            &fixture.fence,
            1_001,
        ),
        Err(EconomicStateCacheError::Conflict)
    ));
    assert!(matches!(
        fixture.cache.stage_batch_with_descriptor(
            &successor,
            None,
            Some(EconomicStateStageDescriptor::new(
                CLEARING_LIFECYCLE_REPLAY_DESCRIPTOR_KIND,
                digest("proof-1"),
                &descriptor_body,
            )?),
            &fixture.fence,
            1_002,
        ),
        Err(EconomicStateCacheError::Conflict)
    ));
    Ok(())
}

#[test]
fn generic_staging_rejects_reserved_admission_terminal_projection() -> TestResult {
    let fixture = fixture();
    let (advance, _) = verified_advance()?;
    let descriptor = EconomicStateStageDescriptor::new(
        ADMISSION_TERMINAL_PROJECTION_DESCRIPTOR_KIND,
        digest("operation-1"),
        &json!({"projection": digest("projection-1")}),
    )?;

    assert!(matches!(
        fixture.cache.stage_batch_with_descriptor(
            &advance,
            None,
            Some(descriptor),
            &fixture.fence,
            1_000,
        ),
        Err(EconomicStateCacheError::Conflict)
    ));
    Ok(())
}

#[test]
fn committed_view_match_preserves_the_generic_single_transition_path() -> TestResult {
    let (advance, committed) = verified_advance()?;

    assert!(committed_view_matches_batch(
        committed.view(),
        advance.batch()
    ));
    Ok(())
}

#[test]
fn committed_view_match_binds_all_channel_heads_by_resource_identity() -> TestResult {
    let (advance, _) = verified_advance()?;
    let mut heads = Vec::new();
    let mut transitions = Vec::new();
    for resource_family in [
        "channel_escrow_reservation",
        "channel_lifecycle",
        "effect_slot",
    ]
    .into_iter()
    {
        let mut next_head = head()?;
        next_head.resource_key = EconomicResourceKeyV1 {
            resource_family: resource_family.to_owned(),
            scope_id: "channel-scope".to_owned(),
            resource_id: "channel-1".to_owned(),
        };
        let state = EconomicContentV1::Inline {
            value: json!({"resourceFamily": resource_family}),
        };
        next_head.state_digest = state.digest()?;
        next_head.state = state;
        transitions.push(EconomicStateTransitionV1 {
            resource_key: next_head.resource_key.clone(),
            expected_head_digest: Some(digest(&format!("prior-{resource_family}"))),
            next_head: next_head.clone(),
            transition_proof_digest: digest(&format!("proof-{resource_family}")),
            prepared_effect: None,
        });
        heads.push(next_head);
    }
    let committed = signed_view(2, digest("channel-checkpoint"), heads, Vec::new())?;
    let mut batch = advance.batch().clone();
    batch.transitions = transitions;

    assert_eq!(
        batch.transitions[2].resource_key.resource_family,
        "effect_slot"
    );
    assert!(committed_view_matches_batch(&committed, &batch));

    for transition in &batch.transitions {
        let mut substituted = committed.clone();
        let head = substituted
            .heads
            .iter_mut()
            .find(|head| head.resource_key == transition.resource_key)
            .ok_or("committed transition head is missing")?;
        head.lifecycle_state = "substituted".to_owned();
        assert!(!committed_view_matches_batch(&substituted, &batch));
    }
    Ok(())
}

#[test]
fn version_one_cache_migrates_descriptor_identity_without_rewriting_stages() -> TestResult {
    let mut connection = Connection::open_in_memory()?;
    connection.execute_batch(
        r#"
        CREATE TABLE economic_state_stages (
            batch_id TEXT PRIMARY KEY,
            checkpoint_sequence INTEGER NOT NULL,
            checkpoint_digest TEXT NOT NULL,
            base_view_json BLOB NOT NULL,
            batch_json BLOB NOT NULL,
            committed_view_json BLOB,
            operation_binding_json BLOB,
            status TEXT NOT NULL,
            reason TEXT,
            stage_version INTEGER NOT NULL,
            snapshot_digest TEXT NOT NULL,
            created_at_unix_ms INTEGER NOT NULL,
            updated_at_unix_ms INTEGER NOT NULL
        );
        CREATE TABLE economic_state_stage_heads (
            batch_id TEXT NOT NULL,
            resource_key_digest TEXT NOT NULL,
            resource_key_json BLOB NOT NULL,
            head_digest TEXT NOT NULL,
            head_json BLOB NOT NULL
        );
        CREATE TABLE economic_state_heads (
            resource_key_digest TEXT PRIMARY KEY,
            resource_key_json BLOB NOT NULL,
            head_digest TEXT NOT NULL,
            head_json BLOB NOT NULL,
            checkpoint_sequence INTEGER NOT NULL,
            checkpoint_digest TEXT NOT NULL,
            source_batch_id TEXT NOT NULL
        );
        CREATE TABLE economic_state_stage_commits (
            batch_id TEXT NOT NULL,
            stage_version INTEGER NOT NULL,
            status TEXT NOT NULL,
            snapshot_digest TEXT NOT NULL,
            previous_commit_digest TEXT NOT NULL,
            commit_digest TEXT NOT NULL,
            store_uuid TEXT NOT NULL,
            store_lease_id TEXT NOT NULL,
            store_owner_epoch INTEGER NOT NULL,
            recorded_at_unix_ms INTEGER NOT NULL
        );
        CREATE TRIGGER economic_state_stage_identity_immutable
        BEFORE UPDATE OF batch_id, checkpoint_sequence, checkpoint_digest,
            base_view_json, batch_json, operation_binding_json, created_at_unix_ms
        ON economic_state_stages
        BEGIN
            SELECT RAISE(ABORT, 'economic stage identity is immutable');
        END;
        "#,
    )?;
    crate::check_schema_version(
        &connection,
        ECONOMIC_STATE_CACHE_SCHEMA_KEY,
        1,
        ECONOMIC_STATE_CACHE_SCHEMA_ANCHORS,
    )?;
    crate::stamp_schema_version(&connection, ECONOMIC_STATE_CACHE_SCHEMA_KEY, 1)?;

    let (advance, _) = verified_advance()?;
    let mut legacy_stage = EconomicStateStageRecord {
        base_view: advance.current().view().clone(),
        batch: advance.batch().clone(),
        committed_view: None,
        operation_binding: None,
        descriptor: None,
        status: EconomicStateStageStatus::DbStaged,
        reason: None,
        version: 1,
        created_at_unix_ms: 1_000,
        updated_at_unix_ms: 1_000,
        snapshot_digest: String::new(),
    };
    legacy_stage.snapshot_digest = stage_snapshot_digest(&legacy_stage, &[])?;
    connection.execute(
        r#"
        INSERT INTO economic_state_stages (
            batch_id, checkpoint_sequence, checkpoint_digest,
            base_view_json, batch_json, committed_view_json,
            operation_binding_json, status, reason, stage_version,
            snapshot_digest, created_at_unix_ms, updated_at_unix_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, 'db_staged', NULL, 1, ?6, 1000, 1000)
        "#,
        rusqlite::params![
            &legacy_stage.batch.batch_id,
            i64::try_from(legacy_stage.batch.checkpoint_sequence)?,
            &legacy_stage.batch.checkpoint_digest,
            canonical_json_bytes(&legacy_stage.base_view)?,
            legacy_stage.batch.canonical_bytes()?,
            &legacy_stage.snapshot_digest,
        ],
    )?;
    connection.execute(
        r#"
        INSERT INTO economic_state_stage_commits (
            batch_id, stage_version, status, snapshot_digest,
            previous_commit_digest, commit_digest, store_uuid,
            store_lease_id, store_owner_epoch, recorded_at_unix_ms
        ) VALUES (?1, 1, 'db_staged', ?2, ?3, ?4, 'store-1', 'lease-1', 1, 1000)
        "#,
        rusqlite::params![
            &legacy_stage.batch.batch_id,
            &legacy_stage.snapshot_digest,
            GENESIS_STAGE_COMMIT_DIGEST,
            digest("legacy-stage-commit"),
        ],
    )?;

    initialize_economic_state_cache_schema(&mut connection)?;

    let columns = connection
        .prepare("SELECT name FROM pragma_table_info('economic_state_stages') ORDER BY cid")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    for expected in [
        "descriptor_kind",
        "descriptor_key",
        "descriptor_digest",
        "descriptor_json",
    ] {
        assert!(columns.iter().any(|column| column == expected));
    }
    let version: i32 = connection.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = ?1",
        [ECONOMIC_STATE_CACHE_SCHEMA_KEY],
        |row| row.get(0),
    )?;
    assert_eq!(version, ECONOMIC_STATE_CACHE_SUPPORTED_SCHEMA_VERSION);
    let transaction = connection.transaction()?;
    let migrated = load_stage_tx(&transaction, &legacy_stage.batch.batch_id)?
        .ok_or("migrated stage is missing")?;
    assert_eq!(migrated, legacy_stage);
    transaction.commit()?;

    connection.execute_batch("DROP INDEX economic_state_stages_descriptor_identity")?;
    crate::stamp_schema_version(&connection, ECONOMIC_STATE_CACHE_SCHEMA_KEY, 2)?;
    initialize_economic_state_cache_schema(&mut connection)?;
    let descriptor_index: bool = connection.query_row(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM sqlite_schema
            WHERE type = 'index'
              AND name = 'economic_state_stages_descriptor_identity'
        )
        "#,
        [],
        |row| row.get(0),
    )?;
    assert!(descriptor_index);
    Ok(())
}

#[test]
fn only_an_anchor_advanced_stage_can_publish_cached_heads() -> TestResult {
    let fixture = fixture();
    let (advance, committed) = verified_advance()?;
    let batch_id = advance.batch().batch_id.clone();
    fixture
        .cache
        .stage_batch(&advance, None, &fixture.fence, 1_000)?;
    assert!(fixture.cache.load_finalized_head(&key())?.is_none());
    assert!(matches!(
        fixture
            .cache
            .finalize_stage(&batch_id, &fixture.fence, 1_001),
        Err(EconomicStateCacheError::InvalidTransition { .. })
    ));

    let advanced = fixture.cache.record_anchor_advanced(
        &advance,
        &committed,
        &pins(),
        &fixture.fence,
        1_002,
    )?;
    assert_eq!(
        advanced.status(),
        EconomicStateStageStatus::EconomicAnchorAdvanced
    );
    assert_eq!(advanced.committed_view(), Some(committed.view()));
    assert!(fixture.cache.load_finalized_head(&key())?.is_none());

    let finalized = fixture
        .cache
        .finalize_stage(&batch_id, &fixture.fence, 1_003)?;
    assert_eq!(finalized.status(), EconomicStateStageStatus::DbFinalized);
    assert_eq!(fixture.cache.load_finalized_head(&key())?, Some(head()?));
    Ok(())
}

#[test]
fn discarded_unanchored_stage_never_exposes_or_reopens_state() -> TestResult {
    let fixture = fixture();
    let (advance, committed) = verified_advance()?;
    let batch_id = advance.batch().batch_id.clone();
    fixture
        .cache
        .stage_batch(&advance, None, &fixture.fence, 1_000)?;
    let discarded = fixture.cache.discard_unanchored_stage(
        &batch_id,
        "operation no longer authorizes recovery",
        &fixture.fence,
        1_001,
    )?;
    assert_eq!(discarded.status(), EconomicStateStageStatus::Discarded);
    assert!(fixture.cache.load_finalized_head(&key())?.is_none());
    assert!(fixture
        .cache
        .record_anchor_advanced(&advance, &committed, &pins(), &fixture.fence, 1_002,)
        .is_err());
    Ok(())
}

#[test]
fn late_finalize_of_an_older_stage_cannot_regress_the_current_head() -> TestResult {
    let fixture = fixture();
    let (older, older_committed) = verified_advance()?;
    fixture
        .cache
        .stage_batch(&older, None, &fixture.fence, 1_000)?;
    fixture.cache.record_anchor_advanced(
        &older,
        &older_committed,
        &pins(),
        &fixture.fence,
        1_001,
    )?;

    let (newer, newer_committed) = verified_successor(&older_committed)?;
    fixture
        .cache
        .stage_batch(&newer, None, &fixture.fence, 1_002)?;
    fixture.cache.record_anchor_advanced(
        &newer,
        &newer_committed,
        &pins(),
        &fixture.fence,
        1_003,
    )?;
    fixture
        .cache
        .finalize_stage(&newer.batch().batch_id, &fixture.fence, 1_004)?;
    let newest_head = newer.batch().transitions[0].next_head.clone();
    assert_eq!(
        fixture.cache.load_finalized_head(&key())?,
        Some(newest_head.clone())
    );

    fixture
        .cache
        .finalize_stage(&older.batch().batch_id, &fixture.fence, 1_005)?;
    assert_eq!(
        fixture.cache.load_finalized_head(&key())?,
        Some(newest_head)
    );
    Ok(())
}

#[test]
fn finalized_stage_recomputes_retained_head_digests() -> TestResult {
    let fixture = fixture();
    let (advance, committed) = verified_advance()?;
    let batch_id = advance.batch().batch_id.clone();
    fixture
        .cache
        .stage_batch(&advance, None, &fixture.fence, 1_000)?;
    fixture
        .cache
        .record_anchor_advanced(&advance, &committed, &pins(), &fixture.fence, 1_001)?;
    fixture
        .cache
        .finalize_stage(&batch_id, &fixture.fence, 1_002)?;

    let mut tampered = head()?;
    let state = EconomicContentV1::Inline {
        value: json!({"roundId": "round-1", "state": "tampered"}),
    };
    tampered.lifecycle_state = "tampered".to_owned();
    tampered.state_digest = state.digest()?;
    tampered.state = state;
    let tampered_bytes = canonical_json_bytes(&tampered)?;
    {
        let connection = fixture.cache.connection()?;
        connection.execute_batch("DROP TRIGGER economic_state_stage_heads_immutable")?;
        connection.execute(
            "UPDATE economic_state_stage_heads SET head_json = ?1 WHERE batch_id = ?2",
            rusqlite::params![&tampered_bytes, &batch_id],
        )?;
        connection.execute(
            "UPDATE economic_state_heads SET head_json = ?1 WHERE source_batch_id = ?2",
            rusqlite::params![&tampered_bytes, &batch_id],
        )?;
    }

    assert!(matches!(
        fixture.cache.load_stage(&batch_id),
        Err(EconomicStateCacheError::Invariant(_))
    ));
    Ok(())
}

#[test]
fn operation_bound_stage_requires_the_exact_current_recovery_claim() -> TestResult {
    let fixture = fixture();
    let operations = fixture._authority.admission_operation_store();
    let operation = prepared_economic_operation(&fixture.fence, "request-stage-1");
    let now = now_ms();
    operations.begin(&operation, &fixture.fence, now)?;
    let claimant = identifier("claimant_id", "economic-stage-recovery");
    let lease = operations.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &claimant,
        now + 1,
        now + 1_001,
        &fixture.fence,
    )?;
    let (advance, _) = verified_advance_for_operation(Some(
        operation.binding().operation_id().as_str().to_owned(),
    ))?;

    let staged = fixture.cache.stage_batch(
        &advance,
        Some(EconomicOperationStageContext::new(&operation, &lease)),
        &fixture.fence,
        now + 2,
    )?;
    let binding = staged
        .operation_binding()
        .ok_or("operation binding is missing")?;
    assert_eq!(
        binding.operation_id(),
        operation.binding().operation_id().as_str()
    );
    assert_eq!(binding.operation_version(), operation.version());
    assert_eq!(binding.operation_state(), operation.state());
    Ok(())
}

#[test]
fn operation_bound_stage_expiry_is_durable_and_ijson_bounded() -> TestResult {
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
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let fence = authority.mutation_fence();
    let cache = authority.economic_state_cache();
    let operations = authority.admission_operation_store();
    let operation = prepared_economic_operation(&fence, "request-stage-expiry-restart");
    let now = now_ms();
    let not_after = now + 500;
    operations.begin(&operation, &fence, now)?;
    let lease = operations.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &identifier("claimant_id", "economic-stage-recovery"),
        now + 1,
        now + 1_001,
        &fence,
    )?;
    let (advance, _) = verified_advance_for_operation(Some(
        operation.binding().operation_id().as_str().to_owned(),
    ))?;
    let context =
        EconomicOperationStageContext::new(&operation, &lease).with_not_after_unix_ms(not_after)?;
    let staged = cache.stage_batch(&advance, Some(context), &fence, now + 2)?;
    assert_eq!(staged.not_after_unix_ms(), Some(not_after));
    assert_eq!(
        staged
            .operation_binding()
            .ok_or("operation binding is missing")?
            .not_after_unix_ms(),
        Some(not_after)
    );
    assert!(EconomicOperationStageContext::new(&operation, &lease)
        .with_not_after_unix_ms(0)
        .is_err());
    assert!(EconomicOperationStageContext::new(&operation, &lease)
        .with_not_after_unix_ms(MAX_TRUSTED_UNIX_MS + 1)
        .is_err());
    let batch_id = advance.batch().batch_id.clone();
    drop(operations);
    drop(cache);
    drop(authority);

    let reopened = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let loaded = reopened
        .economic_state_cache()
        .load_stage(&batch_id)?
        .ok_or("economic stage is missing after restart")?;
    assert_eq!(loaded.not_after_unix_ms(), Some(not_after));
    Ok(())
}

#[test]
fn operation_bound_stage_replay_rejects_a_different_expiry() -> TestResult {
    let fixture = fixture();
    let operations = fixture._authority.admission_operation_store();
    let operation = prepared_economic_operation(&fixture.fence, "request-stage-expiry-replay");
    let now = now_ms();
    operations.begin(&operation, &fixture.fence, now)?;
    let lease = operations.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &identifier("claimant_id", "economic-stage-recovery"),
        now + 1,
        now + 1_001,
        &fixture.fence,
    )?;
    let (advance, _) = verified_advance_for_operation(Some(
        operation.binding().operation_id().as_str().to_owned(),
    ))?;
    let first =
        EconomicOperationStageContext::new(&operation, &lease).with_not_after_unix_ms(now + 500)?;
    fixture
        .cache
        .stage_batch(&advance, Some(first), &fixture.fence, now + 2)?;
    let conflicting =
        EconomicOperationStageContext::new(&operation, &lease).with_not_after_unix_ms(now + 501)?;

    assert!(matches!(
        fixture
            .cache
            .stage_batch(&advance, Some(conflicting), &fixture.fence, now + 3),
        Err(EconomicStateCacheError::Conflict)
    ));
    Ok(())
}

#[test]
fn operation_bound_stage_expiry_rejects_invalid_stored_bindings() -> TestResult {
    for invalid in [0, MAX_TRUSTED_UNIX_MS + 1] {
        let fixture = fixture();
        let operations = fixture._authority.admission_operation_store();
        let operation = prepared_economic_operation(&fixture.fence, "request-stage-expiry-hostile");
        let now = now_ms();
        operations.begin(&operation, &fixture.fence, now)?;
        let lease = operations.claim_recovery(
            operation.binding().operation_id(),
            operation.version(),
            &identifier("claimant_id", "economic-stage-recovery"),
            now + 1,
            now + 1_001,
            &fixture.fence,
        )?;
        let (advance, _) = verified_advance_for_operation(Some(
            operation.binding().operation_id().as_str().to_owned(),
        ))?;
        let context = EconomicOperationStageContext::new(&operation, &lease)
            .with_not_after_unix_ms(now + 500)?;
        let staged = fixture
            .cache
            .stage_batch(&advance, Some(context), &fixture.fence, now + 2)?;
        let mut stored = serde_json::to_value(
            staged
                .operation_binding()
                .ok_or("operation binding is missing")?,
        )?;
        stored
            .as_object_mut()
            .ok_or("operation binding is not an object")?
            .insert("notAfterUnixMs".to_owned(), json!(invalid));
        let encoded = canonical_json_bytes(&stored)?;
        let mut connection = fixture.cache.connection()?;
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "DROP TRIGGER economic_state_stage_identity_immutable;
             DROP TRIGGER economic_state_stage_versioned;",
        )?;
        transaction.execute(
            "UPDATE economic_state_stages SET operation_binding_json = ?1 WHERE batch_id = ?2",
            rusqlite::params![encoded, &advance.batch().batch_id],
        )?;

        assert!(matches!(
            load_stage_tx(&transaction, &advance.batch().batch_id),
            Err(EconomicStateCacheError::Invariant(message))
                if message.contains("not_after_unix_ms")
        ));
    }
    Ok(())
}

#[test]
fn operation_bound_stage_replay_rechecks_the_current_recovery_claim() -> TestResult {
    let fixture = fixture();
    let operations = fixture._authority.admission_operation_store();
    let operation = prepared_economic_operation(&fixture.fence, "request-stage-replay-race");
    let now = now_ms();
    operations.begin(&operation, &fixture.fence, now)?;
    let claimant = identifier("claimant_id", "economic-stage-recovery");
    let lease = operations.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &claimant,
        now + 1,
        now + 1_001,
        &fixture.fence,
    )?;
    let (advance, _) = verified_advance_for_operation(Some(
        operation.binding().operation_id().as_str().to_owned(),
    ))?;
    let context = EconomicOperationStageContext::new(&operation, &lease);
    fixture
        .cache
        .stage_batch(&advance, Some(context), &fixture.fence, now + 2)?;

    let command = AdmissionOperationCommand::new(
        operation.binding().operation_id().clone(),
        operation.version(),
        lease.clone(),
        Vec::new(),
        Some(chio_kernel::admission_operation::AdmissionOperationState::MutationReady),
        None,
        None,
    )?;
    operations.compare_and_swap(&command, now + 3)?;

    assert!(matches!(
        fixture
            .cache
            .stage_batch(&advance, Some(context), &fixture.fence, now + 4),
        Err(EconomicStateCacheError::Fenced)
    ));
    Ok(())
}

#[test]
fn operation_version_race_fences_stage_before_any_resource_is_visible() -> TestResult {
    let fixture = fixture();
    let operations = fixture._authority.admission_operation_store();
    let operation = prepared_economic_operation(&fixture.fence, "request-stage-race");
    let now = now_ms();
    operations.begin(&operation, &fixture.fence, now)?;
    let claimant = identifier("claimant_id", "economic-stage-recovery");
    let lease = operations.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &claimant,
        now + 1,
        now + 1_001,
        &fixture.fence,
    )?;
    let command = AdmissionOperationCommand::new(
        operation.binding().operation_id().clone(),
        operation.version(),
        lease.clone(),
        Vec::new(),
        Some(chio_kernel::admission_operation::AdmissionOperationState::MutationReady),
        None,
        None,
    )?;
    operations.compare_and_swap(&command, now + 2)?;
    let (advance, _) = verified_advance_for_operation(Some(
        operation.binding().operation_id().as_str().to_owned(),
    ))?;

    assert!(matches!(
        fixture.cache.stage_batch(
            &advance,
            Some(EconomicOperationStageContext::new(&operation, &lease)),
            &fixture.fence,
            now + 3,
        ),
        Err(EconomicStateCacheError::Fenced)
    ));
    assert!(fixture.cache.load_finalized_head(&key())?.is_none());
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
