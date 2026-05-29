use crate::{
    sign_relay_http_request, PeerDirectory, PheromoneRelayError, RelayHttpSigningInput,
    PHEROMONE_BATCH_RELAY_PATH,
};
use chio_core_types::Keypair;
use chio_federation::PheromoneGossipBatch;
use chio_pheromone_runtime::PheromoneReceiveReport;
use std::time::Duration;

pub struct PheromoneRelayClient {
    directory: PeerDirectory,
    keypair: Keypair,
    now_unix_ms: u64,
    freshness_window_ms: u64,
    client: reqwest::Client,
}

impl PheromoneRelayClient {
    pub fn new(
        directory: PeerDirectory,
        keypair: Keypair,
        now_unix_ms: u64,
        freshness_window_ms: u64,
    ) -> Result<Self, PheromoneRelayError> {
        // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: relay peer endpoints come
        // from a signed PeerDirectory; threading an HttpEgressContract
        // through PeerDirectoryEntry is a dedicated refactor, not yet wired.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(freshness_window_ms.max(1)))
            .build()
            .map_err(|error| PheromoneRelayError::Http(error.to_string()))?;
        Ok(Self {
            directory,
            keypair,
            now_unix_ms,
            freshness_window_ms,
            client,
        })
    }

    pub async fn post_batch(
        &self,
        sender_kernel_id: &str,
        recipient_kernel_id: &str,
        batch: &PheromoneGossipBatch,
        nonce: &str,
    ) -> Result<PheromoneReceiveReport, PheromoneRelayError> {
        let url = self
            .directory
            .endpoint_for(recipient_kernel_id, PHEROMONE_BATCH_RELAY_PATH)?;
        let request = sign_relay_http_request(RelayHttpSigningInput {
            sender_kernel_id,
            recipient_kernel_id,
            method: "POST",
            path: PHEROMONE_BATCH_RELAY_PATH,
            nonce,
            sent_at_unix_ms: self.now_unix_ms,
            payload: batch,
            keypair: &self.keypair,
        })?;
        let response = self
            .client
            .post(url)
            .json(&request)
            // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: paired with builder above.
            .send()
            .await
            .map_err(|error| PheromoneRelayError::TransportError(error.to_string()))?;
        if !response.status().is_success() {
            let status = response.status();
            let detail = response
                .text()
                .await
                .unwrap_or_else(|error| error.to_string());
            return Err(PheromoneRelayError::TransportError(format!(
                "relay POST failed with {status}: {detail}"
            )));
        }
        response
            .json::<PheromoneReceiveReport>()
            .await
            .map_err(|error| PheromoneRelayError::Json(error.to_string()))
    }

    #[must_use]
    pub fn freshness_window_ms(&self) -> u64 {
        self.freshness_window_ms
    }
}
