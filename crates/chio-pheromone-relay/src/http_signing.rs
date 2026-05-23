use crate::{
    canonical_sha256, PeerDirectory, PheromoneRelayError, RelayNonceRecorder,
    PHEROMONE_RELAY_HTTP_REQUEST_SCHEMA,
};
use chio_core_types::Keypair;
use chio_core_types::Signature;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PheromoneRelayHttpRequest {
    pub schema: String,
    pub sender_kernel_id: String,
    pub recipient_kernel_id: String,
    pub method: String,
    pub path: String,
    pub body_sha256: String,
    pub nonce: String,
    pub sent_at_unix_ms: u64,
    pub payload: Value,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PheromoneRelayHttpRequestSigningBody {
    schema: String,
    sender_kernel_id: String,
    recipient_kernel_id: String,
    method: String,
    path: String,
    body_sha256: String,
    nonce: String,
    sent_at_unix_ms: u64,
}

impl PheromoneRelayHttpRequest {
    pub fn verify_payload<T: DeserializeOwned>(
        &self,
        directory: &PeerDirectory,
        context: &RelayHttpVerificationContext,
        nonce_store: &(impl RelayNonceRecorder + ?Sized),
    ) -> Result<T, PheromoneRelayError> {
        self.verify_envelope(directory, context, nonce_store)?;
        serde_json::from_value(self.payload.clone()).map_err(PheromoneRelayError::from)
    }

    fn verify_envelope(
        &self,
        directory: &PeerDirectory,
        context: &RelayHttpVerificationContext,
        nonce_store: &(impl RelayNonceRecorder + ?Sized),
    ) -> Result<(), PheromoneRelayError> {
        if self.schema != PHEROMONE_RELAY_HTTP_REQUEST_SCHEMA {
            return Err(PheromoneRelayError::UnsupportedSchema(self.schema.clone()));
        }
        if self.recipient_kernel_id != context.local_kernel_id {
            return Err(PheromoneRelayError::RecipientMismatch(format!(
                "request recipient {} does not match local receiver {}",
                self.recipient_kernel_id, context.local_kernel_id
            )));
        }
        if self.method != context.method {
            return Err(PheromoneRelayError::MethodMismatch(format!(
                "request method {} does not match {}",
                self.method, context.method
            )));
        }
        if self.path != context.path {
            return Err(PheromoneRelayError::PathMismatch(format!(
                "request path {} does not match {}",
                self.path, context.path
            )));
        }
        let peer = directory.peer(&self.sender_kernel_id)?;
        let signing_body = self.signing_body();
        if !peer
            .public_key
            .verify_canonical(&signing_body, &self.signature)
            .map_err(|error| PheromoneRelayError::CanonicalJson(error.to_string()))?
        {
            return Err(PheromoneRelayError::SignatureInvalid);
        }
        let actual_hash = canonical_sha256(&self.payload)?;
        if actual_hash != self.body_sha256 {
            return Err(PheromoneRelayError::BodyHashMismatch(format!(
                "payload hash {} does not match signed hash {}",
                actual_hash, self.body_sha256
            )));
        }
        let skew = self.sent_at_unix_ms.abs_diff(context.now_unix_ms);
        if skew > context.freshness_window_ms {
            return Err(PheromoneRelayError::RelayRequestStale(format!(
                "request skew {skew}ms exceeds {}ms",
                context.freshness_window_ms
            )));
        }
        nonce_store.record_relay_nonce(
            &self.sender_kernel_id,
            &self.nonce,
            context
                .now_unix_ms
                .saturating_add(context.freshness_window_ms),
        )
    }

    fn signing_body(&self) -> PheromoneRelayHttpRequestSigningBody {
        PheromoneRelayHttpRequestSigningBody {
            schema: self.schema.clone(),
            sender_kernel_id: self.sender_kernel_id.clone(),
            recipient_kernel_id: self.recipient_kernel_id.clone(),
            method: self.method.clone(),
            path: self.path.clone(),
            body_sha256: self.body_sha256.clone(),
            nonce: self.nonce.clone(),
            sent_at_unix_ms: self.sent_at_unix_ms,
        }
    }
}

pub struct RelayHttpSigningInput<'a, T: Serialize + ?Sized> {
    pub sender_kernel_id: &'a str,
    pub recipient_kernel_id: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub nonce: &'a str,
    pub sent_at_unix_ms: u64,
    pub payload: &'a T,
    pub keypair: &'a Keypair,
}

pub fn sign_relay_http_request<T: Serialize + ?Sized>(
    input: RelayHttpSigningInput<'_, T>,
) -> Result<PheromoneRelayHttpRequest, PheromoneRelayError> {
    let payload = serde_json::to_value(input.payload)?;
    let body_sha256 = canonical_sha256(&payload)?;
    let signing_body = PheromoneRelayHttpRequestSigningBody {
        schema: PHEROMONE_RELAY_HTTP_REQUEST_SCHEMA.to_string(),
        sender_kernel_id: input.sender_kernel_id.to_string(),
        recipient_kernel_id: input.recipient_kernel_id.to_string(),
        method: input.method.to_string(),
        path: input.path.to_string(),
        body_sha256,
        nonce: input.nonce.to_string(),
        sent_at_unix_ms: input.sent_at_unix_ms,
    };
    let (signature, _) = input
        .keypair
        .sign_canonical(&signing_body)
        .map_err(|error| PheromoneRelayError::CanonicalJson(error.to_string()))?;
    Ok(PheromoneRelayHttpRequest {
        schema: signing_body.schema,
        sender_kernel_id: signing_body.sender_kernel_id,
        recipient_kernel_id: signing_body.recipient_kernel_id,
        method: signing_body.method,
        path: signing_body.path,
        body_sha256: signing_body.body_sha256,
        nonce: signing_body.nonce,
        sent_at_unix_ms: signing_body.sent_at_unix_ms,
        payload,
        signature,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayHttpVerificationContext {
    pub local_kernel_id: String,
    pub method: String,
    pub path: String,
    pub now_unix_ms: u64,
    pub freshness_window_ms: u64,
}
