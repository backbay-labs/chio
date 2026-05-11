//! Local Chiodos pheromone gossip artifacts.
//!
//! This module mirrors the revocation gossip queue style but keeps pheromone
//! transit local and artifact-first. It does not open sockets, run timers, or
//! decide runtime policy.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::{Mutex, PoisonError};

use chio_pheromone::PheromoneDeposit;
use serde::{Deserialize, Serialize};

pub const PHEROMONE_GOSSIP_SCHEMA: &str = "chio.pheromone-deposit-gossip.v1";
pub const PHEROMONE_GOSSIP_BATCH_SCHEMA: &str = "chio.pheromone-batch.v1";
pub const PHEROMONE_TRANSIT_CHAIN_SCHEMA: &str = "chio.pheromone-transit-chain.v1";
pub const PHEROMONE_TRANSIT_POLICY_SCHEMA: &str = "chio.pheromone-transit-policy.v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PheromoneGossipError {
    #[error("unsupported_schema: {0}")]
    UnsupportedSchema(String),
    #[error("origin_mismatch: {0}")]
    OriginMismatch(String),
    #[error("treaty_scope_violation: {0}")]
    TreatyScopeViolation(String),
    #[error("transit_chain_invalid: {0}")]
    TransitChainInvalid(String),
    #[error("transit_policy_violation: {0}")]
    TransitPolicyViolation(String),
    #[error("unknown_peer: {0}")]
    UnknownPeer(String),
    #[error("batch_recipient_mismatch: {0}")]
    BatchRecipientMismatch(String),
    #[error("batch_treaty_mismatch: {0}")]
    BatchTreatyMismatch(String),
    #[error("authenticated_sender_mismatch: {0}")]
    AuthenticatedSenderMismatch(String),
    #[error("invalid_configuration: {0}")]
    InvalidConfiguration(String),
    #[error("queue_poisoned: pheromone gossip queue lock is poisoned")]
    QueuePoisoned,
}

impl PheromoneGossipError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedSchema(_) => "unsupported_schema",
            Self::OriginMismatch(_) => "origin_mismatch",
            Self::TreatyScopeViolation(_) => "treaty_scope_violation",
            Self::TransitChainInvalid(_) => "transit_chain_invalid",
            Self::TransitPolicyViolation(_) => "transit_policy_violation",
            Self::UnknownPeer(_) => "unknown_peer",
            Self::BatchRecipientMismatch(_) => "batch_recipient_mismatch",
            Self::BatchTreatyMismatch(_) => "batch_treaty_mismatch",
            Self::AuthenticatedSenderMismatch(_) => "authenticated_sender_mismatch",
            Self::InvalidConfiguration(_) => "invalid_configuration",
            Self::QueuePoisoned => "queue_poisoned",
        }
    }
}

impl<T> From<PoisonError<T>> for PheromoneGossipError {
    fn from(_: PoisonError<T>) -> Self {
        Self::QueuePoisoned
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PheromoneDepositGossip {
    pub schema: String,
    pub deposit: PheromoneDeposit,
    pub origin_kernel_id: String,
    pub gossiping_peer_kernel_id: String,
    pub treaty_id: String,
    pub ts_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transit_chain: Option<PheromoneTransitChain>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PheromoneGossipBatch {
    pub schema: String,
    pub recipient_kernel_id: String,
    pub treaty_id: String,
    pub frames: Vec<PheromoneDepositGossip>,
    pub flushed_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PheromoneGossipBatchVerificationContext {
    pub now_unix_ms: u64,
    pub recipient_kernel_id: String,
    pub authenticated_sender_kernel_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PheromoneTransitChain {
    pub hops: Vec<PheromoneTransitHop>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PheromoneTransitHop {
    pub from_kernel_id: String,
    pub to_kernel_id: String,
    pub treaty_id: String,
    pub ladder_manifest_id: String,
    pub ladder_manifest_sha256: String,
    pub ladder_manifest_expires_at_unix_ms: u64,
    pub ladder_intersection_id: String,
    pub action_class_id: String,
    pub emitted_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PheromoneTransitPolicy {
    pub schema: String,
    pub accepted_hubs: Vec<String>,
    pub allowed_ingress_treaties: Vec<String>,
    pub allowed_egress_treaties: Vec<String>,
    pub allowed_subject_class_namespaces: Vec<String>,
    pub valid_from_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub max_hops: usize,
    pub required_action_class_id: String,
}

pub fn verify_pheromone_gossip_frame(
    frame: &PheromoneDepositGossip,
    policy: &PheromoneTransitPolicy,
    now_unix_ms: u64,
) -> Result<(), PheromoneGossipError> {
    if policy.schema != PHEROMONE_TRANSIT_POLICY_SCHEMA {
        return Err(PheromoneGossipError::UnsupportedSchema(
            policy.schema.clone(),
        ));
    }
    if frame.schema != PHEROMONE_GOSSIP_SCHEMA {
        return Err(PheromoneGossipError::UnsupportedSchema(
            frame.schema.clone(),
        ));
    }
    if frame.origin_kernel_id != frame.deposit.body.kernel_id {
        return Err(PheromoneGossipError::OriginMismatch(format!(
            "origin {} does not match deposit kernel {}",
            frame.origin_kernel_id, frame.deposit.body.kernel_id
        )));
    }
    if !policy
        .allowed_subject_class_namespaces
        .contains(&frame.deposit.body.subject_class_namespace)
    {
        return Err(PheromoneGossipError::TransitPolicyViolation(format!(
            "subject namespace {} is not allowed",
            frame.deposit.body.subject_class_namespace
        )));
    }
    if now_unix_ms < policy.valid_from_unix_ms || now_unix_ms >= policy.valid_until_unix_ms {
        return Err(PheromoneGossipError::TransitPolicyViolation(
            "transit policy is not live".to_string(),
        ));
    }
    match &frame.transit_chain {
        None => verify_direct_frame(frame),
        Some(chain) => verify_relay_frame(frame, chain, policy, now_unix_ms),
    }
}

pub fn verify_pheromone_gossip_batch(
    batch: &PheromoneGossipBatch,
    policy: &PheromoneTransitPolicy,
    context: &PheromoneGossipBatchVerificationContext,
) -> Result<(), PheromoneGossipError> {
    if batch.schema != PHEROMONE_GOSSIP_BATCH_SCHEMA {
        return Err(PheromoneGossipError::UnsupportedSchema(
            batch.schema.clone(),
        ));
    }
    if batch.recipient_kernel_id != context.recipient_kernel_id {
        return Err(PheromoneGossipError::BatchRecipientMismatch(format!(
            "batch recipient {} does not match receiver {}",
            batch.recipient_kernel_id, context.recipient_kernel_id
        )));
    }
    for frame in &batch.frames {
        if frame.treaty_id != batch.treaty_id {
            return Err(PheromoneGossipError::BatchTreatyMismatch(format!(
                "frame treaty {} does not match batch treaty {}",
                frame.treaty_id, batch.treaty_id
            )));
        }
        if frame.gossiping_peer_kernel_id != context.authenticated_sender_kernel_id {
            return Err(PheromoneGossipError::AuthenticatedSenderMismatch(format!(
                "frame gossiping peer {} does not match authenticated sender {}",
                frame.gossiping_peer_kernel_id, context.authenticated_sender_kernel_id
            )));
        }
        match &frame.transit_chain {
            None => {
                if frame.origin_kernel_id != context.authenticated_sender_kernel_id {
                    return Err(PheromoneGossipError::AuthenticatedSenderMismatch(format!(
                        "direct frame origin {} does not match authenticated sender {}",
                        frame.origin_kernel_id, context.authenticated_sender_kernel_id
                    )));
                }
            }
            Some(chain) => {
                let last = chain.hops.last().ok_or_else(|| {
                    PheromoneGossipError::TransitChainInvalid("missing last hop".to_string())
                })?;
                if last.to_kernel_id != context.recipient_kernel_id {
                    return Err(PheromoneGossipError::BatchRecipientMismatch(format!(
                        "final transit recipient {} does not match receiver {}",
                        last.to_kernel_id, context.recipient_kernel_id
                    )));
                }
            }
        }
        verify_pheromone_gossip_frame(frame, policy, context.now_unix_ms)?;
    }
    Ok(())
}

fn verify_direct_frame(frame: &PheromoneDepositGossip) -> Result<(), PheromoneGossipError> {
    if frame
        .deposit
        .body
        .treaty_scope
        .iter()
        .any(|treaty| treaty == &frame.treaty_id)
    {
        Ok(())
    } else {
        Err(PheromoneGossipError::TreatyScopeViolation(format!(
            "direct treaty {} is not in deposit scope",
            frame.treaty_id
        )))
    }
}

fn verify_relay_frame(
    frame: &PheromoneDepositGossip,
    chain: &PheromoneTransitChain,
    policy: &PheromoneTransitPolicy,
    now_unix_ms: u64,
) -> Result<(), PheromoneGossipError> {
    if chain.hops.is_empty() {
        return Err(PheromoneGossipError::TransitChainInvalid(
            "transit chain is empty".to_string(),
        ));
    }
    if chain.hops.len() > policy.max_hops {
        return Err(PheromoneGossipError::TransitChainInvalid(
            "transit chain exceeds hop cap".to_string(),
        ));
    }
    let first = chain.hops.first().ok_or_else(|| {
        PheromoneGossipError::TransitChainInvalid("missing first hop".to_string())
    })?;
    let last = chain
        .hops
        .last()
        .ok_or_else(|| PheromoneGossipError::TransitChainInvalid("missing last hop".to_string()))?;
    if first.from_kernel_id != frame.origin_kernel_id {
        return Err(PheromoneGossipError::TransitChainInvalid(
            "first hop does not start at deposit origin".to_string(),
        ));
    }
    if !frame
        .deposit
        .body
        .treaty_scope
        .iter()
        .any(|treaty| treaty == &first.treaty_id)
    {
        return Err(PheromoneGossipError::TransitChainInvalid(
            "first hop treaty is not in deposit scope".to_string(),
        ));
    }
    if last.treaty_id != frame.treaty_id {
        return Err(PheromoneGossipError::TransitChainInvalid(
            "last hop treaty does not match frame treaty".to_string(),
        ));
    }
    if last.from_kernel_id != frame.gossiping_peer_kernel_id {
        return Err(PheromoneGossipError::TransitChainInvalid(
            "gossiping peer is not the final relay".to_string(),
        ));
    }
    if !policy.allowed_ingress_treaties.contains(&first.treaty_id) {
        return Err(PheromoneGossipError::TransitPolicyViolation(
            "ingress treaty is not allowed".to_string(),
        ));
    }
    if !policy.allowed_egress_treaties.contains(&last.treaty_id) {
        return Err(PheromoneGossipError::TransitPolicyViolation(
            "egress treaty is not allowed".to_string(),
        ));
    }
    let mut kernels = BTreeSet::new();
    for (index, hop) in chain.hops.iter().enumerate() {
        if hop.action_class_id != policy.required_action_class_id {
            return Err(PheromoneGossipError::TransitPolicyViolation(format!(
                "hop action class {} is not accepted",
                hop.action_class_id
            )));
        }
        if hop.ladder_manifest_expires_at_unix_ms <= now_unix_ms {
            return Err(PheromoneGossipError::TransitChainInvalid(
                "hop ladder manifest is stale".to_string(),
            ));
        }
        if hop.ladder_manifest_sha256.len() != 64 {
            return Err(PheromoneGossipError::TransitChainInvalid(
                "hop ladder manifest hash is malformed".to_string(),
            ));
        }
        if !kernels.insert(hop.from_kernel_id.clone()) {
            return Err(PheromoneGossipError::TransitChainInvalid(
                "transit chain repeats a kernel".to_string(),
            ));
        }
        if index > 0 {
            let previous = &chain.hops[index - 1];
            if previous.to_kernel_id != hop.from_kernel_id {
                return Err(PheromoneGossipError::TransitChainInvalid(
                    "transit chain breaks hop adjacency".to_string(),
                ));
            }
        }
    }
    if !kernels.insert(last.to_kernel_id.clone()) {
        return Err(PheromoneGossipError::TransitChainInvalid(
            "transit chain repeats final kernel".to_string(),
        ));
    }
    let has_accepted_hub = chain
        .hops
        .iter()
        .any(|hop| policy.accepted_hubs.contains(&hop.from_kernel_id));
    if !has_accepted_hub {
        return Err(PheromoneGossipError::TransitPolicyViolation(
            "transit chain has no accepted relay hub".to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub struct PheromoneGossipPushQueue {
    local_kernel_id: String,
    capacity_per_peer_treaty: usize,
    inner: Mutex<HashMap<(String, String), VecDeque<PheromoneDeposit>>>,
}

impl PheromoneGossipPushQueue {
    pub fn new(
        local_kernel_id: impl Into<String>,
        capacity_per_peer_treaty: usize,
    ) -> Result<Self, PheromoneGossipError> {
        let local_kernel_id = local_kernel_id.into();
        if local_kernel_id.trim().is_empty() {
            return Err(PheromoneGossipError::InvalidConfiguration(
                "local_kernel_id must not be empty".to_string(),
            ));
        }
        if capacity_per_peer_treaty == 0 {
            return Err(PheromoneGossipError::InvalidConfiguration(
                "capacity_per_peer_treaty must be > 0".to_string(),
            ));
        }
        Ok(Self {
            local_kernel_id,
            capacity_per_peer_treaty,
            inner: Mutex::new(HashMap::new()),
        })
    }

    pub fn subscribe(
        &self,
        peer_kernel_id: &str,
        treaty_id: &str,
    ) -> Result<(), PheromoneGossipError> {
        let mut guard = self.inner.lock()?;
        guard
            .entry((peer_kernel_id.to_string(), treaty_id.to_string()))
            .or_insert_with(|| VecDeque::with_capacity(self.capacity_per_peer_treaty));
        Ok(())
    }

    pub fn enqueue(&self, deposit: PheromoneDeposit) -> Result<usize, PheromoneGossipError> {
        let mut guard = self.inner.lock()?;
        let mut delivered = 0_usize;
        for ((_, treaty), queue) in guard.iter_mut() {
            if !deposit
                .body
                .treaty_scope
                .iter()
                .any(|scoped_treaty| scoped_treaty == treaty)
            {
                continue;
            }
            if queue.len() == self.capacity_per_peer_treaty {
                queue.pop_front();
            }
            queue.push_back(deposit.clone());
            delivered = delivered.saturating_add(1);
        }
        Ok(delivered)
    }

    pub fn flush_batches_at(
        &self,
        flushed_at_unix_ms: u64,
    ) -> Result<Vec<PheromoneGossipBatch>, PheromoneGossipError> {
        let mut guard = self.inner.lock()?;
        let mut keys: Vec<(String, String)> = guard.keys().cloned().collect();
        keys.sort();
        let mut batches = Vec::new();
        for key in keys {
            if let Some(queue) = guard.get_mut(&key) {
                if queue.is_empty() {
                    continue;
                }
                let (recipient, treaty) = key;
                let frames = queue
                    .drain(..)
                    .map(|deposit| PheromoneDepositGossip {
                        schema: PHEROMONE_GOSSIP_SCHEMA.to_string(),
                        origin_kernel_id: deposit.body.kernel_id.clone(),
                        gossiping_peer_kernel_id: self.local_kernel_id.clone(),
                        treaty_id: treaty.clone(),
                        ts_unix_ms: flushed_at_unix_ms,
                        transit_chain: None,
                        deposit,
                    })
                    .collect();
                batches.push(PheromoneGossipBatch {
                    schema: PHEROMONE_GOSSIP_BATCH_SCHEMA.to_string(),
                    recipient_kernel_id: recipient,
                    treaty_id: treaty,
                    frames,
                    flushed_at_unix_ms,
                });
            }
        }
        Ok(batches)
    }
}
