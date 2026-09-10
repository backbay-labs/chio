//! Real Chio directed-batch lane. It carries observations, never tool dispatch.
use anyhow::Result;
use chio_agent_os_shared::{events::now_ms, graph::digest, json, Run, Value};
use chio_core::crypto::Keypair;
use chio_federation::pheromone_gossip::*;
use chio_federation_transport_iroh::{
    admission::DirectoryGate, lanes::pheromone::PheromoneBatchHandler,
};
use chio_pheromone::*;
use chio_pheromone_relay::{PheromoneRelayError, RelayBatchReceiver, SqlitePheromoneRelayStore};
use chio_pheromone_runtime::{store::SqlitePheromoneRuntimeStore, *};
use std::{path::Path, sync::Arc};
pub const TREATY: &str = "personal-task-observations";
const NAMESPACE: &str = "dev.chio.personal";
const CLASS: &str = "task.result";
struct NoWorkflow;
impl WorkflowContextResolver for NoWorkflow {
    fn resolve(
        &self,
        _: &PheromoneWorkflowContext,
    ) -> std::result::Result<(), PheromoneRuntimeError> {
        Err(PheromoneRuntimeError::InvalidField(
            "Workflow attachments require a separate verifier".into(),
        ))
    }
}
struct Receiver {
    gate: DirectoryGate,
    local: String,
    store: SqlitePheromoneRuntimeStore,
    run: Run,
}
#[async_trait::async_trait]
impl RelayBatchReceiver for Receiver {
    async fn receive_batch(
        &self,
        batch: PheromoneGossipBatch,
        sender: String,
        now: u64,
    ) -> std::result::Result<PheromoneReceiveReport, PheromoneRelayError> {
        self.receive(batch, sender, now)
            .map_err(|e| PheromoneRelayError::EndpointDenied(e.to_string()))
    }
    async fn recorded_report_for_batch(
        &self,
        hash: &str,
        sender: &str,
    ) -> std::result::Result<Option<PheromoneReceiveReport>, PheromoneRelayError> {
        self.store
            .lookup_receive_report_by_batch(hash, sender)
            .map_err(|e| PheromoneRelayError::Sqlite(e.to_string()))
    }
}
impl Receiver {
    fn receive(
        &self,
        batch: PheromoneGossipBatch,
        sender: String,
        now: u64,
    ) -> Result<PheromoneReceiveReport> {
        let directory = self.gate.directory();
        anyhow::ensure!(
            directory.expires_at_unix_ms() > now,
            "Directory expired before observation admission"
        );
        let public = directory
            .resolve_passport_key(&sender)
            .ok_or_else(|| anyhow::anyhow!("Sender was removed"))?
            .clone();
        let hash =
            digest(&json!({"treaty":TREATY,"namespace":NAMESPACE,"class":CLASS,"capacity":16}))?;
        let start = (now / 3_600_000) * 3_600_000;
        let end = start + 3_600_000;
        let mut scarcity = PheromoneScarcityPolicy {
            schema: PHEROMONE_SCARCITY_POLICY_SCHEMA.into(),
            policy_id: "personal-results-v1".into(),
            reputation_epoch: 10,
            window_id: String::new(),
            window_start_unix_ms: start,
            window_end_unix_ms: end,
            token_capacity: 16,
            newcomer_horizon_epochs: 8,
            treaty_scope: vec![TREATY.into()],
            subject_class_namespace: NAMESPACE.into(),
            subject_class: CLASS.into(),
            observation_cost_verification: ObservationCostVerificationMode::NotRequired,
            verifier_id: self.local.clone(),
            runtime_policy_sha256: hash.clone(),
            policy_sha256: String::new(),
            active_peers_epoch: 10,
        };
        scarcity.window_id = scarcity_window_id(&scarcity, TREATY)?;
        scarcity.policy_sha256 = scarcity_policy_sha256(&scarcity)?;
        let context = PheromoneValidationContext {
            now_unix_ms: now,
            replay_window_ms: 300_000,
            active_peers_in_treaty: 9,
            active_reputation_epoch: 10,
            known_reputation_epochs: vec![10],
            passports: vec![PassportAdmission {
                kernel_id: sender.clone(),
                public_key: public,
                valid_from_unix_ms: start,
                valid_until_unix_ms: end,
                first_seen_epoch: 1,
                revoked: false,
            }],
            kernel_public_keys: vec![],
            subject_classes: vec![SubjectClassPolicy {
                subject_class: CLASS.into(),
                subject_class_namespace: NAMESPACE.into(),
                allowed_treaties: vec![TREATY.into()],
                cost_commitment: CostCommitmentPolicy::NotRequired,
                destructive: false,
            }],
            max_deposits_per_pair: 16,
            scarcity_policies: vec![scarcity],
            runtime_policy_sha256: Some(hash),
            runtime_policy_issuer_public_keys: vec![],
            observation_cost_verifier_roots: vec![],
            runtime_trust_floor_state: Default::default(),
        };
        let policy = PheromoneTransitPolicy {
            schema: PHEROMONE_TRANSIT_POLICY_SCHEMA.into(),
            accepted_hubs: vec![],
            allowed_ingress_treaties: vec![TREATY.into()],
            allowed_egress_treaties: vec![TREATY.into()],
            allowed_subject_class_namespaces: vec![NAMESPACE.into()],
            valid_from_unix_ms: start,
            valid_until_unix_ms: end,
            max_hops: 1,
            required_action_class_id: "task.observation".into(),
            pinned_ladder_refs: vec![],
        };
        let report = self.store.receive_batch(
            &batch,
            &policy,
            &PheromoneReceiverConfig {
                recipient_kernel_id: self.local.clone(),
                authenticated_sender_kernel_id: sender,
                validation_context: context,
            },
            &NoWorkflow,
        )?;
        self.run.emit(
            "network.observation",
            &self.local,
            "Received a signed observation over Iroh",
            json!({"report":report,"batch":batch,"pid":std::process::id()}),
        )?;
        Ok(report)
    }
}
pub fn handler(
    root: &Path,
    local: String,
    gate: DirectoryGate,
    run: Run,
) -> Result<PheromoneBatchHandler> {
    let receiver = Receiver {
        local,
        gate: gate.clone(),
        store: SqlitePheromoneRuntimeStore::open(root.join("observations.db"))?,
        run,
    };
    let scopegate = gate.clone();
    Ok(PheromoneBatchHandler::new(
        gate,
        Arc::new(receiver),
        Arc::new(SqlitePheromoneRelayStore::open(root.join("relay.db"))?),
        Arc::new(now_ms),
        Arc::new(move |sender, batch| {
            let directory = scopegate.directory();
            if directory.expires_at_unix_ms() <= now_ms()
                || batch.frames.len() > 8
                || batch.treaty_id != TREATY
                || !directory.is_treaty_party(TREATY, sender)
            {
                return Err(PheromoneRelayError::EndpointDenied(
                    "Sender is not a current member of the personal task treaty".into(),
                ));
            }
            Ok(())
        }),
    )
    .with_max_batch_bytes(128_000))
}
pub fn batch(
    passport: &Keypair,
    local: &str,
    recipient: &str,
    result: Value,
) -> Result<PheromoneGossipBatch> {
    let now = now_ms();
    let public = passport.public_key();
    let deposit = sign_deposit(
        PheromoneDepositBody {
            schema: PHEROMONE_DEPOSIT_SCHEMA.into(),
            kernel_id: local.into(),
            agent_passport_key_hash: agent_passport_key_hash(&public),
            agent_passport_jwk_thumbprint: agent_passport_jwk_thumbprint(&public),
            subject_class: CLASS.into(),
            subject_class_namespace: NAMESPACE.into(),
            indicator: result,
            severity: Severity::Low,
            confidence: 1.0,
            timestamp_unix_ms: now,
            decay_half_life_secs: 600.0,
            evaporation_floor: None,
            nonce: uuid::Uuid::new_v4().to_string(),
            treaty_scope: vec![TREATY.into()],
            cost_commitment: None,
            workflow_context: None,
        },
        passport,
    )?;
    Ok(PheromoneGossipBatch {
        schema: PHEROMONE_GOSSIP_BATCH_SCHEMA.into(),
        recipient_kernel_id: recipient.into(),
        treaty_id: TREATY.into(),
        frames: vec![PheromoneDepositGossip {
            schema: PHEROMONE_GOSSIP_SCHEMA.into(),
            origin_kernel_id: local.into(),
            gossiping_peer_kernel_id: local.into(),
            treaty_id: TREATY.into(),
            ts_unix_ms: now,
            transit_chain: None,
            deposit,
        }],
        flushed_at_unix_ms: now,
    })
}
