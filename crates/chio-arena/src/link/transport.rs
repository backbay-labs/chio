use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};

const DEFAULT_CHANNEL_CAPACITY: usize = 32;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LinkEnvelope {
    pub from_agent: String,
    pub to_agent: String,
    pub step_id: String,
    pub payload: Value,
}

#[derive(Debug, Clone)]
pub struct KernelEndpoint {
    id: String,
    peer_id: String,
    tx: mpsc::Sender<LinkEnvelope>,
    rx: Arc<Mutex<mpsc::Receiver<LinkEnvelope>>>,
}

impl KernelEndpoint {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    pub async fn send(&self, step_id: impl Into<String>, payload: Value) -> Result<(), LinkError> {
        let envelope = LinkEnvelope {
            from_agent: self.id.clone(),
            to_agent: self.peer_id.clone(),
            step_id: step_id.into(),
            payload,
        };
        self.tx
            .send(envelope)
            .await
            .map_err(|_| LinkError::PeerClosed {
                peer_id: self.peer_id.clone(),
            })
    }

    pub async fn recv(&self) -> Option<LinkEnvelope> {
        self.rx.lock().await.recv().await
    }
}

#[derive(Debug)]
pub struct KernelLink {
    left: KernelEndpoint,
    right: KernelEndpoint,
}

impl KernelLink {
    pub fn pair(left_id: impl Into<String>, right_id: impl Into<String>) -> Self {
        Self::pair_with_capacity(left_id, right_id, DEFAULT_CHANNEL_CAPACITY)
    }

    pub fn pair_with_capacity(
        left_id: impl Into<String>,
        right_id: impl Into<String>,
        capacity: usize,
    ) -> Self {
        let left_id = left_id.into();
        let right_id = right_id.into();
        let (left_tx, right_rx) = mpsc::channel(capacity);
        let (right_tx, left_rx) = mpsc::channel(capacity);
        Self {
            left: KernelEndpoint {
                id: left_id.clone(),
                peer_id: right_id.clone(),
                tx: left_tx,
                rx: Arc::new(Mutex::new(left_rx)),
            },
            right: KernelEndpoint {
                id: right_id,
                peer_id: left_id,
                tx: right_tx,
                rx: Arc::new(Mutex::new(right_rx)),
            },
        }
    }

    pub fn into_endpoints(self) -> (KernelEndpoint, KernelEndpoint) {
        (self.left, self.right)
    }
}

#[derive(Debug, Error)]
pub enum LinkError {
    #[error("kernel link peer {peer_id} is closed")]
    PeerClosed { peer_id: String },
}
