use chio_core_types::crypto::Keypair;
use chio_runtime_core::{
    ChioRuntimeError, InMemoryRuntimeAdmissionStore, JsonRuntimeAdmissionStore,
    RuntimeAdmissionBundle, RuntimeAdmissionStore, RuntimeEvidenceManifestEntry,
    RuntimeOrchestrationProfile, RuntimeRequestBinding, RuntimeTrustFloorEntry,
    SqliteRuntimeOrchestrationStore, TreatyScope, CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA,
    CHIO_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA, CHIO_TREATY_SCOPE_SCHEMA,
};
use chio_swarm_authority::{
    SwarmAuthorityBundle, SwarmBudgetPool, SwarmContinuationToken, SwarmDelegationWitnessChain,
    SwarmJoinReceipt, SwarmRevocationEpoch, SwarmRoutePlanReceipt, SwarmTaskGraph,
};

#[derive(Default)]
struct StoreWithoutTreatyContinuationSupport {
    inner: InMemoryRuntimeAdmissionStore,
}

impl RuntimeAdmissionStore for StoreWithoutTreatyContinuationSupport {
    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChioRuntimeError> {
        self.inner.bundle(admission_id)
    }

    fn consume_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.inner.consume_destructive_lease(lease_id, admission_id)
    }

    fn release_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.inner.release_destructive_lease(lease_id, admission_id)
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError> {
        self.inner.runtime_trust_floor(verifier_id, key_id)
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError> {
        self.inner.record_runtime_trust_floor(entry)
    }
}

#[test]
fn store_without_treaty_continuation_support_fails_closed() {
    let store = StoreWithoutTreatyContinuationSupport::default();

    match store.consume_treaty_continuation("continue-unsupported", "admission-1") {
        Ok(()) => panic!("default treaty continuation consume must fail closed"),
        Err(error) => assert_rejected_code(error, "chio_treaty_continuation_store_unsupported"),
    }

    match store.release_treaty_continuation("continue-unsupported", "admission-1") {
        Ok(()) => panic!("default treaty continuation release must fail closed"),
        Err(error) => assert_rejected_code(error, "chio_treaty_continuation_store_unsupported"),
    }
}

fn assert_rejected_code(error: ChioRuntimeError, expected: &'static str) {
    match error {
        ChioRuntimeError::Rejected { code, .. } => assert_eq!(code, expected),
        other => panic!("expected {expected}, got {other:?}"),
    }
}

#[test]
fn in_memory_runtime_admission_store_insert_bundle_is_idempotent(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let original = bundle();
    store.insert_bundle(original.clone())?;
    store.insert_bundle(original)?;

    let mut conflicting = bundle();
    conflicting.workflow_id = "wf-conflict".to_string();
    match store.insert_bundle(conflicting) {
        Ok(()) => Err("conflicting bundle insert unexpectedly succeeded".into()),
        Err(error) => {
            assert_eq!(error.code(), "duplicate_admission_bundle");
            Ok(())
        }
    }
}

#[test]
fn json_runtime_admission_store_persists_swarm_authority_bundle(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-admission.json");
    let bundle = swarm_authority_bundle_fixture()?;

    {
        let store = JsonRuntimeAdmissionStore::open(&path)?;
        store.insert_swarm_authority_bundle(bundle.clone())?;
        store.insert_swarm_authority_bundle(bundle.clone())?;
    }

    let reopened = JsonRuntimeAdmissionStore::open(&path)?;
    let loaded = reopened
        .swarm_authority_bundle(&bundle.task_graph.graph_id)?
        .ok_or_else(|| std::io::Error::other("swarm authority bundle missing after restart"))?;
    assert_eq!(loaded, bundle);

    let mut conflicting = bundle;
    conflicting.now_unix_ms += 1;
    match reopened.insert_swarm_authority_bundle(conflicting) {
        Ok(()) => Err("conflicting swarm authority bundle insert unexpectedly succeeded".into()),
        Err(error) => {
            assert_eq!(error.code(), "duplicate_swarm_authority_bundle_mismatch");
            Ok(())
        }
    }
}

#[test]
fn sqlite_runtime_orchestration_store_records_swarm_authority_bundle_created_at(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-swarm-authority.sqlite3");
    let bundle = swarm_authority_bundle_fixture()?;
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;

    store.insert_swarm_authority_bundle(bundle.clone())?;

    let connection = rusqlite::Connection::open(&path)?;
    let created_at_unix_ms: i64 = connection.query_row(
        "SELECT created_at_unix_ms FROM runtime_swarm_authority_bundles WHERE task_graph_id = ?1",
        rusqlite::params![bundle.task_graph.graph_id],
        |row| row.get(0),
    )?;
    assert!(created_at_unix_ms > 0);
    Ok(())
}

#[test]
fn sqlite_runtime_orchestration_store_persists_replay_fence_and_status(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-orchestration.sqlite3");
    {
        let store = SqliteRuntimeOrchestrationStore::open(&path)?;
        store.insert_bundle(bundle())?;
        store.record_run_state(
            "runtime-orchestration-1",
            "proof_accepted",
            None,
            1_800_000_001_000,
        )?;
        store.record_step_state(chio_runtime_core::RuntimeOrchestrationStepState {
            step_index: 1,
            admission_id: "adm-live-1".to_string(),
            state: "proof_accepted".to_string(),
            destructive: true,
            admission_report_sha256: Some("1".repeat(64)),
            tool_receipt_sha256: Some("2".repeat(64)),
            lease_id: Some("lease-live-1".to_string()),
        })?;
        store.consume_destructive_lease("lease-live-1", "adm-live-1")?;
    }

    let reopened = SqliteRuntimeOrchestrationStore::open(&path)?;
    let replay = reopened.consume_destructive_lease("lease-live-1", "adm-live-1");
    match replay {
        Ok(()) => panic!("expected destructive lease replay rejection"),
        Err(error) => assert_eq!(error.code(), "destructive_lease_replay"),
    }
    let profile = RuntimeOrchestrationProfile {
        schema: CHIO_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA.to_string(),
        profile_id: "profile-runtime-orchestration".to_string(),
        local_kernel_id: "kernel.vendor-b".to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        mode: "enforce".to_string(),
        max_concurrent_runs: 2,
        fail_closed_on: vec!["evidence_hash_mismatch".to_string()],
    };
    let profile_sha256 = chio_runtime_core::runtime_orchestration_profile_sha256(&profile)?;
    let status = reopened.status_report(&profile, profile_sha256, 1_800_000_002_000, true)?;
    assert_eq!(status.store_backend, "sqlite");
    assert_eq!(status.consumed_lease_count, 1);
    assert_eq!(status.run_counts.get("proof_accepted"), Some(&1));
    Ok(())
}

#[test]
fn sqlite_runtime_orchestration_store_persists_treaty_evidence_idempotently(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-treaty.sqlite3");
    let treaty = treaty_scope();
    let treaty_sha256 = chio_runtime_core::treaty_scope_sha256(&treaty)?;

    {
        let store = SqliteRuntimeOrchestrationStore::open(&path)?;
        store.insert_treaty_runtime_artifact("treaty_scope", &treaty.treaty_id, &treaty)?;
        store.insert_treaty_runtime_artifact("treaty_scope", &treaty.treaty_id, &treaty)?;

        let mut mismatched = treaty.clone();
        mismatched.expires_at_unix_ms += 1;
        let duplicate =
            store.insert_treaty_runtime_artifact("treaty_scope", &treaty.treaty_id, &mismatched);
        match duplicate {
            Ok(()) => panic!("expected treaty evidence id mismatch rejection"),
            Err(error) => assert_eq!(error.code(), "duplicate_treaty_runtime_artifact_mismatch"),
        }
    }

    let reopened = SqliteRuntimeOrchestrationStore::open(&path)?;
    let record = reopened
        .treaty_runtime_artifact("treaty_scope", &treaty.treaty_id)?
        .ok_or_else(|| std::io::Error::other("treaty evidence missing after restart"))?;
    assert_eq!(record.evidence_kind, "treaty_scope");
    assert_eq!(record.evidence_id, treaty.treaty_id);
    assert_eq!(record.artifact_sha256, treaty_sha256);
    assert_eq!(
        serde_json::from_value::<TreatyScope>(record.raw_json)?,
        treaty
    );
    Ok(())
}

#[test]
fn sqlite_runtime_orchestration_store_preserves_same_artifact_hash_per_run(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-artifacts.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let entry = RuntimeEvidenceManifestEntry {
        role: "proof_package".to_string(),
        path: "proof-package.json".to_string(),
        sha256: "7".repeat(64),
        byte_count: 4096,
    };

    store.record_evidence_artifact("runtime-run-a", &entry, 1_800_000_000_000)?;
    store.record_evidence_artifact("runtime-run-b", &entry, 1_800_000_000_001)?;

    let connection = rusqlite::Connection::open(&path)?;
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM runtime_evidence_artifacts WHERE artifact_sha256 = ?1",
        rusqlite::params![entry.sha256],
        |row| row.get(0),
    )?;
    assert_eq!(count, 2);
    Ok(())
}

fn binding() -> RuntimeRequestBinding {
    RuntimeRequestBinding {
        request_id: "req-live-destructive".to_string(),
        capability_id: "cap-live-1".to_string(),
        server_id: "vendor-ledger".to_string(),
        tool_name: "close_account".to_string(),
        tool_args_sha256: "a".repeat(64),
        origin_kernel_id: Some("kernel.buyer".to_string()),
        host_kernel_id: "kernel.vendor-b".to_string(),
    }
}

fn bundle() -> RuntimeAdmissionBundle {
    RuntimeAdmissionBundle {
        schema: CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA.to_string(),
        admission_id: "adm-live-1".to_string(),
        binding: binding(),
        workflow_id: "wf-live-1".to_string(),
        workflow_grant_id: "grant-live-1".to_string(),
        step_index: 1,
        destructive: true,
        lease_id: Some("lease-live-1".to_string()),
        governance_receipt_id: Some("gov-live-1".to_string()),
        trust_bundle_sha256: "b".repeat(64),
        verification_context_sha256: "c".repeat(64),
    }
}

fn swarm_authority_bundle_fixture() -> Result<SwarmAuthorityBundle, serde_json::Error> {
    Ok(SwarmAuthorityBundle {
        task_graph: serde_json::from_str::<SwarmTaskGraph>(include_str!(
            "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/task-graph.json"
        ))?,
        continuation_tokens: vec![
            serde_json::from_str::<SwarmContinuationToken>(include_str!(
                "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/continuation-child-a.json"
            ))?,
            serde_json::from_str::<SwarmContinuationToken>(include_str!(
                "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/continuation-child-b.json"
            ))?,
        ],
        witness_chains: vec![
            serde_json::from_str::<SwarmDelegationWitnessChain>(include_str!(
                "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/witness-child-a.json"
            ))?,
            serde_json::from_str::<SwarmDelegationWitnessChain>(include_str!(
                "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/witness-child-b.json"
            ))?,
        ],
        join_receipts: vec![serde_json::from_str::<SwarmJoinReceipt>(include_str!(
            "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/join-receipt.json"
        ))?],
        route_plan_receipts: vec![
            serde_json::from_str::<SwarmRoutePlanReceipt>(include_str!(
                "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/route-child-a.json"
            ))?,
            serde_json::from_str::<SwarmRoutePlanReceipt>(include_str!(
                "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/route-child-b.json"
            ))?,
        ],
        budget_pool: serde_json::from_str::<SwarmBudgetPool>(include_str!(
            "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/budget-pool.json"
        ))?,
        revocation_epoch: serde_json::from_str::<SwarmRevocationEpoch>(include_str!(
            "../../../../fixtures/proof-room/swarm-authority/valid-recursive-delegation/revocation-epoch.json"
        ))?,
        terminal_receipts: Vec::new(),
        now_unix_ms: 1_800_000_001_000,
    })
}

fn treaty_scope() -> TreatyScope {
    let buyer_key = Keypair::generate();
    let vendor_key = Keypair::generate();
    TreatyScope {
        schema: CHIO_TREATY_SCOPE_SCHEMA.to_string(),
        treaty_id: "treaty-buyer-vendor".to_string(),
        participant_kernel_ids: vec!["kernel.buyer".to_string(), "kernel.vendor-b".to_string()],
        participant_public_keys: vec![buyer_key.public_key(), vendor_key.public_key()],
        ladder_manifest_sha256s: vec!["a".repeat(64), "b".repeat(64)],
        allowed_action_classes: vec!["workflow.destructive.vendor_call".to_string()],
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        revocation_epoch_sha256: "c".repeat(64),
        trust_bundle_sha256: "b".repeat(64),
    }
}
