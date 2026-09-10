//! Receiver-owned admission, real SQLite concentration, and direct HTTP delivery.
use anyhow::Result;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use chio_agent_os_shared::{events::now_ms, graph::digest, json, Run, Value};
use chio_core::crypto::Keypair;
use chio_federation::pheromone_gossip::*;
use chio_pheromone::*;
use chio_pheromone_runtime::store::SqlitePheromoneRuntimeStore;
use chio_pheromone_runtime::*;
use std::{path::Path, sync::Arc};
pub const NAMESPACE: &str = "dev.chio.research";
pub const TREATY: &str = "research-observations";
pub const SENDER: &str = "did:chio:research-observer";
pub const RECEIVER: &str = "did:chio:research-coordinator";
pub const CLASSES: [&str; 3] = ["discover", "contradiction", "reproduce"];
struct NoWorkflowClaims;
impl WorkflowContextResolver for NoWorkflowClaims {
    fn resolve(
        &self,
        _: &PheromoneWorkflowContext,
    ) -> std::result::Result<(), PheromoneRuntimeError> {
        // This starter admits signed observations grounded in corpus passages.
        // It never invents a verified cross-organization workflow attachment.
        Err(PheromoneRuntimeError::InvalidField(
            "This receiver does not accept workflow proof attachments".into(),
        ))
    }
}
struct ReceiverState {
    store: SqlitePheromoneRuntimeStore,
    context: PheromoneValidationContext,
    policy: PheromoneTransitPolicy,
    token: String,
    run: Run,
}
async fn receive(
    State(state): State<Arc<ReceiverState>>,
    headers: HeaderMap,
    Json(batch): Json<PheromoneGossipBatch>,
) -> std::result::Result<Json<Value>, (StatusCode, String)> {
    if headers.get("authorization").and_then(|v| v.to_str().ok())
        != Some(&format!("Bearer {}", state.token))
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Use the configured observer identity".into(),
        ));
    }
    let mut context = state.context.clone();
    context.now_unix_ms = now_ms();
    let config = PheromoneReceiverConfig {
        recipient_kernel_id: RECEIVER.into(),
        authenticated_sender_kernel_id: SENDER.into(),
        validation_context: context,
    };
    let report = state
        .store
        .receive_batch(&batch, &state.policy, &config, &NoWorkflowClaims)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let value = json!(report);
    state
        .run
        .emit(
            "observation.received",
            "receiving-host",
            if report.accepted {
                "Admitted signed observations"
            } else {
                "Refused an observation batch"
            },
            value.clone(),
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(value))
}
pub struct Signals {
    state: Arc<ReceiverState>,
    pub endpoint: String,
    server: tokio::task::JoinHandle<()>,
    pub observer: Keypair,
    pub timestamp: u64,
}
impl Drop for Signals {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Signals {
    pub async fn start(directory: &Path, run: Run) -> Result<Self> {
        let observer = Keypair::generate();
        let now = now_ms();
        let policy_hash = digest(
            &json!({"namespace":NAMESPACE,"treaty":TREATY,"capacity":2,"classes":CLASSES,"first_seen_epoch":1}),
        )?;
        let mut policies = Vec::new();
        for class in CLASSES {
            let mut policy = PheromoneScarcityPolicy {
                schema: PHEROMONE_SCARCITY_POLICY_SCHEMA.into(),
                policy_id: format!("research:{class}"),
                reputation_epoch: 10,
                window_id: String::new(),
                window_start_unix_ms: now - 86_400_000,
                window_end_unix_ms: now + 7_200_000,
                token_capacity: 2,
                newcomer_horizon_epochs: 8,
                treaty_scope: vec![TREATY.into()],
                subject_class_namespace: NAMESPACE.into(),
                subject_class: class.into(),
                observation_cost_verification: ObservationCostVerificationMode::NotRequired,
                verifier_id: RECEIVER.into(),
                runtime_policy_sha256: policy_hash.clone(),
                policy_sha256: String::new(),
                active_peers_epoch: 10,
            };
            policy.window_id = scarcity_window_id(&policy, TREATY)?;
            policy.policy_sha256 = scarcity_policy_sha256(&policy)?;
            policies.push(policy);
        }
        let context = PheromoneValidationContext {
            now_unix_ms: now,
            replay_window_ms: 86_400_000,
            active_peers_in_treaty: 1,
            active_reputation_epoch: 10,
            known_reputation_epochs: vec![10],
            passports: vec![PassportAdmission {
                kernel_id: SENDER.into(),
                public_key: observer.public_key(),
                valid_from_unix_ms: now - 86_400_000,
                valid_until_unix_ms: now + 7_200_000,
                first_seen_epoch: 1,
                revoked: false,
            }],
            kernel_public_keys: Vec::new(),
            subject_classes: CLASSES
                .iter()
                .map(|class| SubjectClassPolicy {
                    subject_class: (*class).into(),
                    subject_class_namespace: NAMESPACE.into(),
                    allowed_treaties: vec![TREATY.into()],
                    cost_commitment: CostCommitmentPolicy::NotRequired,
                    destructive: false,
                })
                .collect(),
            max_deposits_per_pair: 8,
            scarcity_policies: policies,
            runtime_policy_sha256: Some(policy_hash),
            runtime_policy_issuer_public_keys: Vec::new(),
            observation_cost_verifier_roots: Vec::new(),
            runtime_trust_floor_state: Default::default(),
        };
        let policy = PheromoneTransitPolicy {
            schema: PHEROMONE_TRANSIT_POLICY_SCHEMA.into(),
            accepted_hubs: vec![],
            allowed_ingress_treaties: vec![TREATY.into()],
            allowed_egress_treaties: vec![TREATY.into()],
            allowed_subject_class_namespaces: vec![NAMESPACE.into()],
            valid_from_unix_ms: now - 86_400_000,
            valid_until_unix_ms: now + 7_200_000,
            max_hops: 1,
            required_action_class_id: "research.observation".into(),
            pinned_ladder_refs: vec![],
        };
        let state = Arc::new(ReceiverState {
            store: SqlitePheromoneRuntimeStore::open(directory.join("observations.db"))?,
            context,
            policy,
            token: uuid::Uuid::new_v4().to_string(),
            run,
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let app = Router::new()
            .route("/observations", post(receive))
            .layer(axum::extract::DefaultBodyLimit::max(64_000))
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self {
            state,
            endpoint,
            server,
            observer,
            timestamp: now,
        })
    }
    pub fn deposit(
        &self,
        class: &str,
        indicator: Value,
        confidence: f64,
        age_secs: u64,
        half_life: f64,
    ) -> Result<PheromoneDeposit> {
        let public = self.observer.public_key();
        Ok(sign_deposit(
            PheromoneDepositBody {
                schema: PHEROMONE_DEPOSIT_SCHEMA.into(),
                kernel_id: SENDER.into(),
                agent_passport_key_hash: agent_passport_key_hash(&public),
                agent_passport_jwk_thumbprint: agent_passport_jwk_thumbprint(&public),
                subject_class: class.into(),
                subject_class_namespace: NAMESPACE.into(),
                indicator,
                severity: Severity::Medium,
                confidence,
                timestamp_unix_ms: self.timestamp.saturating_sub(age_secs * 1000),
                decay_half_life_secs: half_life,
                evaporation_floor: None,
                nonce: uuid::Uuid::new_v4().to_string(),
                treaty_scope: vec![TREATY.into()],
                cost_commitment: None,
                workflow_context: None,
            },
            &self.observer,
        )?)
    }
    pub async fn deliver(&self, deposit: PheromoneDeposit) -> Result<Value> {
        let now = now_ms();
        let batch = PheromoneGossipBatch {
            schema: PHEROMONE_GOSSIP_BATCH_SCHEMA.into(),
            recipient_kernel_id: RECEIVER.into(),
            treaty_id: TREATY.into(),
            frames: vec![PheromoneDepositGossip {
                schema: PHEROMONE_GOSSIP_SCHEMA.into(),
                origin_kernel_id: SENDER.into(),
                gossiping_peer_kernel_id: SENDER.into(),
                treaty_id: TREATY.into(),
                ts_unix_ms: now,
                transit_chain: None,
                deposit,
            }],
            flushed_at_unix_ms: now,
        };
        Ok(reqwest::Client::new()
            .post(format!("{}/observations", self.endpoint))
            .bearer_auth(&self.state.token)
            .json(&batch)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
    pub fn concentrations(
        &self,
        query_seconds: u64,
        weight: f64,
    ) -> Result<Vec<PheromoneConcentration>> {
        let mut context = self.state.context.clone();
        context.now_unix_ms = self.timestamp + query_seconds * 1000;
        let weights = StaticPeerWeightProvider::new(10, [(SENDER.into(), weight)]);
        CLASSES
            .iter()
            .map(|class| {
                self.state
                    .store
                    .query_concentration(
                        class,
                        NAMESPACE,
                        context.now_unix_ms,
                        10,
                        &context,
                        &weights,
                    )
                    .map_err(Into::into)
            })
            .collect()
    }
    pub async fn denials(&self, original: &PheromoneDeposit) -> Result<Value> {
        let replay = self.deliver(original.clone()).await?;
        anyhow::ensure!(replay["accepted"] == false, "A replay was admitted");
        let mut tampered = original.clone();
        tampered.body.confidence = 0.01;
        let invalid = self.deliver(tampered).await?;
        anyhow::ensure!(
            invalid["accepted"] == false,
            "A modified signature was admitted"
        );
        let second = self.deposit(
            &original.body.subject_class,
            original.body.indicator.clone(),
            0.5,
            0,
            60.0,
        )?;
        anyhow::ensure!(
            self.deliver(second).await?["accepted"] == true,
            "The second scarcity token was unexpectedly refused"
        );
        let third = self.deposit(
            &original.body.subject_class,
            original.body.indicator.clone(),
            0.5,
            0,
            60.0,
        )?;
        let scarce = self.deliver(third).await?;
        anyhow::ensure!(
            scarce["accepted"] == false,
            "Exhausted scarcity policy admitted a third observation"
        );
        Ok(json!({"replay":replay,"tampered":invalid,"scarcity":scarce}))
    }
}
