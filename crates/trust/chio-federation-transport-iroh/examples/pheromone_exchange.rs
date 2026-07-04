//! Example: lane a (pheromone directed batches) end-to-end over loopback QUIC.
//!
//! Operator A dials operator B on the pheromone lane and delivers one
//! `PheromoneGossipBatch` using the crate's real client, `deliver_batch_over_iroh`.
//! Operator B resolves the authenticated sender from the cryptographically
//! authenticated `EndpointId` through the `DirectoryGate` (the ONE hop that, on
//! the shipped HTTP path, comes from HTTP-signature verification), then feeds that
//! resolved `kernel_id` as `authenticated_sender_kernel_id` into the REAL,
//! unchanged `chio-federation` per-frame verifier (`verify_pheromone_gossip_batch`,
//! pheromone_gossip.rs:236/244). The verifier accepts only because the transport
//! resolved the right sender; a spoofed sender fails closed.
//!
//! Why the acceptor here is a small in-example handler, not the crate's
//! `PheromoneBatchHandler`: that handler takes an `Arc<dyn RelayBatchReceiver>`
//! whose `receive_batch` returns `PheromoneReceiveReport`, a type that lives in
//! `chio-pheromone-runtime` (not a dependency of this crate and not re-exported).
//! The crate's own lane test hits the same wall and stands up a `CannedReportHandler`
//! double for exactly this reason. This example mirrors that double using only
//! public APIs (the real gate, the real wire client, the real per-frame verifier),
//! so the transport path and the load-bearing sender binding are genuine.
//!
//! Run: `cargo run -p chio-federation-transport-iroh --example pheromone_exchange`

use std::error::Error;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use chio_core_types::canonical_json_bytes;
use chio_core_types::sha256_hex;
use chio_core_types::Keypair;
use chio_federation::pheromone_gossip::verify_pheromone_gossip_batch;
use chio_federation::pheromone_gossip::PheromoneDepositGossip;
use chio_federation::pheromone_gossip::PheromoneGossipBatch;
use chio_federation::pheromone_gossip::PheromoneGossipBatchVerificationContext;
use chio_federation::pheromone_gossip::PheromoneTransitPolicy;
use chio_federation::pheromone_gossip::PHEROMONE_GOSSIP_BATCH_SCHEMA;
use chio_federation::pheromone_gossip::PHEROMONE_GOSSIP_SCHEMA;
use chio_federation::pheromone_gossip::PHEROMONE_TRANSIT_POLICY_SCHEMA;
use chio_federation_transport_iroh::admission::DirectoryGate;
use chio_federation_transport_iroh::identity::transport_endorsement_preimage;
use chio_federation_transport_iroh::identity::TransportDirectoryBundleBody;
use chio_federation_transport_iroh::identity::TransportDirectoryBundleDocument;
use chio_federation_transport_iroh::identity::TransportDirectoryBundleTrust;
use chio_federation_transport_iroh::identity::TransportDirectoryDocument;
use chio_federation_transport_iroh::identity::TransportDirectoryEntry;
use chio_federation_transport_iroh::identity::TrustedTransportDirectoryIssuer;
use chio_federation_transport_iroh::identity::TRANSPORT_DIRECTORY_BUNDLE_SCHEMA;
use chio_federation_transport_iroh::lanes::pheromone::deliver_batch_over_iroh;
use chio_federation_transport_iroh::lanes::pheromone::ALPN_PHEROMONE_BATCH;
use chio_federation_transport_iroh::lanes::pheromone::MAX_PHEROMONE_BATCH_BYTES;
use iroh::endpoint::presets;
use iroh::endpoint::Connection;
use iroh::protocol::AcceptError;
use iroh::protocol::ProtocolHandler;
use iroh::protocol::Router;
use iroh::Endpoint;
use iroh::EndpointAddr;
use iroh::EndpointId;
use iroh::RelayMode;
use iroh::SecretKey;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;

const NOW: u64 = 1_766_000_000_500;
const OPERATOR_A: &str = "did:chio:operator-a";
const OPERATOR_B: &str = "did:chio:operator-b";
const TREATY: &str = "treaty:operator-a-operator-b:support-ops";
const NAMESPACE: &str = "dev.chio.support";

const OPERATOR_B_SEED: u8 = 31;
const OPERATOR_A_SEED: u8 = 30;
const MALLORY_SEED: u8 = 98;

fn endpoint_id(seed: u8) -> EndpointId {
    SecretKey::from_bytes(&[seed; 32]).public()
}

/// Build a load-time-verified directory (mirrors the crate's test fixtures) and
/// wrap it in a gate. Each entry binds `kernel_id` to the transport `EndpointId`
/// derived from `transport_seed`.
fn build_gate(entries: &[(&str, u8, u8)]) -> Result<DirectoryGate, Box<dyn Error>> {
    let issuer = Keypair::from_seed(&[240u8; 32]);
    let peers = entries
        .iter()
        .map(|(kernel_id, passport_seed, transport_seed)| {
            let passport = Keypair::from_seed(&[*passport_seed; 32]);
            let transport = endpoint_id(*transport_seed);
            TransportDirectoryEntry {
                kernel_id: (*kernel_id).to_string(),
                passport_public_key: passport.public_key(),
                transport_endpoint_id: transport,
                passport_endorsement: passport
                    .sign(&transport_endorsement_preimage(kernel_id, &transport)),
                revocation_signers: Vec::new(),
                removed: false,
            }
        })
        .collect::<Vec<_>>();
    let directory = TransportDirectoryDocument {
        schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
        local_kernel_id: OPERATOR_B.to_string(),
        peers,
        treaties: Vec::new(),
    };
    let directory_sha256 = sha256_hex(&canonical_json_bytes(&directory)?);
    let body = TransportDirectoryBundleBody {
        schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
        issuer: "did:chio:issuer".to_string(),
        key_id: "issuer-key-1".to_string(),
        directory_sha256,
        version: 1,
        previous_version_sha256: None,
        issued_at_unix_ms: NOW - 1,
        expires_at_unix_ms: NOW + 1,
    };
    let (signature, _) = issuer.sign_canonical(&body)?;
    let bundle = TransportDirectoryBundleDocument {
        schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
        body,
        directory,
        signature,
    };
    let trust = TransportDirectoryBundleTrust {
        issuers: vec![TrustedTransportDirectoryIssuer {
            issuer: "did:chio:issuer".to_string(),
            key_id: "issuer-key-1".to_string(),
            public_key: issuer.public_key(),
        }],
        version_floor: 0,
        expected_previous_version_sha256: None,
        now_unix_ms: NOW,
    };
    Ok(DirectoryGate::new(Arc::new(bundle.verify_bundle(&trust)?)))
}

async fn bind_endpoint(seed: u8, gate: Option<DirectoryGate>) -> Result<Endpoint, Box<dyn Error>> {
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[seed; 32]))
        .relay_mode(RelayMode::Disabled)
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| error.to_string())?;
    if let Some(gate) = gate {
        builder = builder.hooks(gate);
    }
    Ok(builder.bind().await.map_err(|error| error.to_string())?)
}

fn direct_addr(endpoint: &Endpoint) -> Result<EndpointAddr, Box<dyn Error>> {
    let socket = endpoint
        .bound_sockets()
        .into_iter()
        .next()
        .ok_or("endpoint bound no socket")?;
    Ok(EndpointAddr::new(endpoint.id()).with_ip_addr(socket))
}

/// A well-formed `chio_core_types::Signature` in its JSON form. The direct-frame
/// verifier checks sender equality, not the deposit signature, so any parseable
/// signature exercises the sender-binding path (mirrors the crate's lane test).
fn signature_value() -> Result<serde_json::Value, Box<dyn Error>> {
    let sig = Keypair::from_seed(&[9u8; 32]).sign(b"pheromone-example-fixture");
    Ok(serde_json::to_value(sig)?)
}

/// A single-frame direct batch authored by `author` (both `origin` and
/// `gossiping_peer`), scoped to `TREATY`. Built by deserialization so the example
/// need not name `chio-pheromone`'s deposit type.
fn direct_batch(author: &str) -> Result<PheromoneGossipBatch, Box<dyn Error>> {
    let frame = serde_json::json!({
        "schema": PHEROMONE_GOSSIP_SCHEMA,
        "deposit": {
            "schema": "chio.pheromone-deposit.v1",
            "kernel_id": author,
            "agent_passport_key_hash": "a".repeat(64),
            "agent_passport_jwk_thumbprint": "b".repeat(43),
            "subject_class": "support.prompt_injection",
            "subject_class_namespace": NAMESPACE,
            "indicator": {"digest": "c".repeat(64)},
            "severity": "high",
            "confidence": 0.8,
            "timestamp_unix_ms": NOW,
            "decay_half_life_secs": 3_600.0,
            "nonce": "nonce-operator-a-001",
            "treaty_scope": [TREATY],
            "signature": signature_value()?,
        },
        "origin_kernel_id": author,
        "gossiping_peer_kernel_id": author,
        "treaty_id": TREATY,
        "ts_unix_ms": NOW,
    });
    let frame: PheromoneDepositGossip = serde_json::from_value(frame)?;
    Ok(PheromoneGossipBatch {
        schema: PHEROMONE_GOSSIP_BATCH_SCHEMA.to_string(),
        recipient_kernel_id: OPERATOR_B.to_string(),
        treaty_id: TREATY.to_string(),
        frames: vec![frame],
        flushed_at_unix_ms: NOW,
    })
}

fn live_policy() -> PheromoneTransitPolicy {
    PheromoneTransitPolicy {
        schema: PHEROMONE_TRANSIT_POLICY_SCHEMA.to_string(),
        accepted_hubs: Vec::new(),
        allowed_ingress_treaties: vec![TREATY.to_string()],
        allowed_egress_treaties: vec![TREATY.to_string()],
        allowed_subject_class_namespaces: vec![NAMESPACE.to_string()],
        valid_from_unix_ms: NOW - 1_000,
        valid_until_unix_ms: NOW + 1_000,
        max_hops: 4,
        required_action_class_id: "action:demo".to_string(),
        pinned_ladder_refs: Vec::new(),
    }
}

async fn read_u32_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, Box<dyn Error>> {
    let len = reader.read_u32().await? as usize;
    if len > MAX_PHEROMONE_BATCH_BYTES {
        return Err("pheromone frame exceeds the transport cap".into());
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_u32_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
) -> Result<(), Box<dyn Error>> {
    let len = u32::try_from(bytes.len())?;
    writer.write_u32(len).await?;
    writer.write_all(bytes).await?;
    writer.flush().await?;
    Ok(())
}

/// Operator B's acceptor. It resolves the authenticated sender via the real gate,
/// then drives the real `chio-federation` verifier with that resolved kernel id.
#[derive(Clone)]
struct ReceiverHandler {
    gate: DirectoryGate,
    policy: Arc<PheromoneTransitPolicy>,
}

impl std::fmt::Debug for ReceiverHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiverHandler").finish_non_exhaustive()
    }
}

impl ReceiverHandler {
    async fn handle(&self, conn: &Connection) -> Result<(), Box<dyn Error>> {
        // The ONE hop that replaces the shipped HTTP-signed sender: the resolved
        // kernel id bound to the authenticated EndpointId.
        let sender = self
            .gate
            .resolve(&conn.remote_id())
            .ok_or("unadmitted endpoint reached the pheromone handler")?;
        println!(
            "  [B] authenticated EndpointId {} -> kernel_id {sender:?}",
            conn.remote_id().fmt_short()
        );

        let (mut send, mut recv) = conn.accept_bi().await.map_err(|error| error.to_string())?;
        let raw = read_u32_frame(&mut recv).await?;
        let batch: PheromoneGossipBatch = serde_json::from_slice(&raw)?;

        // Drive the REAL, unchanged per-frame verifier with the transport-resolved
        // sender as authenticated_sender_kernel_id (pheromone_gossip.rs:236/244).
        let context = PheromoneGossipBatchVerificationContext {
            now_unix_ms: NOW,
            recipient_kernel_id: batch.recipient_kernel_id.clone(),
            authenticated_sender_kernel_id: sender.clone(),
        };
        let verdict = verify_pheromone_gossip_batch(&batch, &self.policy, &context);
        let accepted = verdict.is_ok();
        println!("  [B] verify_pheromone_gossip_batch -> accepted={accepted}");

        // A COMPLETE receive report, mirroring the runtime `PheromoneReceiveReport`.
        // The dial side rejects a partial report before marking a batch delivered, so
        // every required field is present (plus a diagnostic `verifierOutcome`, which
        // the forward-compatible validation ignores).
        let frame_count = batch.frames.len() as u64;
        let report = serde_json::json!({
            "schema": "chio.pheromone-receive-report.v1",
            "accepted": accepted,
            "batchOutcome": if accepted { "accepted" } else { "rejected" },
            "acceptedFrameCount": if accepted { frame_count } else { 0 },
            "rejectedFrameCount": if accepted { 0 } else { frame_count },
            "batchSha256": "0".repeat(64),
            "recipientKernelId": batch.recipient_kernel_id,
            "authenticatedSenderKernelId": sender,
            "receivedAtUnixMs": NOW,
            "frames": [],
            "verifierOutcome": match &verdict {
                Ok(()) => "accepted".to_string(),
                Err(error) => error.to_string(),
            },
        });
        let bytes = serde_json::to_vec(&report)?;
        write_u32_frame(&mut send, &bytes).await?;
        send.finish().map_err(|error| error.to_string())?;
        conn.closed().await;
        Ok(())
    }
}

impl ProtocolHandler for ReceiverHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        self.handle(&conn)
            .await
            .map_err(|error| AcceptError::from_err(std::io::Error::other(error.to_string())))
    }
}

async fn deliver_with_timeout(
    endpoint: &Endpoint,
    addr: EndpointAddr,
    batch: &PheromoneGossipBatch,
) -> Result<bool, String> {
    match tokio::time::timeout(
        Duration::from_secs(15),
        deliver_batch_over_iroh(endpoint, addr, batch),
    )
    .await
    {
        Ok(Ok(outcome)) => Ok(outcome.accepted),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_elapsed) => Err("delivery timed out".to_string()),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("== lane a: pheromone directed batch (operator A -> operator B) ==\n");

    // B's directory admits operator A (bound to A's transport key). Mallory is
    // bound to nothing.
    let gate = build_gate(&[(OPERATOR_A, 1, OPERATOR_A_SEED)])?;

    let acceptor = bind_endpoint(OPERATOR_B_SEED, Some(gate.clone())).await?;
    let router = Router::builder(acceptor)
        .accept(
            ALPN_PHEROMONE_BATCH,
            ReceiverHandler {
                gate,
                policy: Arc::new(live_policy()),
            },
        )
        .spawn();
    let acceptor_addr = direct_addr(router.endpoint())?;

    // Operator A: admitted. Its batch is authored by OPERATOR_A, so the resolved
    // sender and the frame author agree and the verifier accepts.
    let operator_a = bind_endpoint(OPERATOR_A_SEED, None).await?;
    let batch = direct_batch(OPERATOR_A)?;
    println!(
        "operator A delivers a 1-frame batch on {:?}:",
        String::from_utf8_lossy(ALPN_PHEROMONE_BATCH)
    );
    let admitted_ok = match deliver_with_timeout(&operator_a, acceptor_addr.clone(), &batch).await {
        Ok(accepted) => {
            println!("  [A] peer report: accepted={accepted}\n");
            accepted
        }
        Err(error) => {
            println!("  [A] delivery failed: {error}\n");
            false
        }
    };

    // Mallory: unadmitted. The gate rejects at handshake before the handler runs.
    let mallory = bind_endpoint(MALLORY_SEED, None).await?;
    println!("an unadmitted operator (mallory) attempts the same delivery:");
    let mallory_rejected = match deliver_with_timeout(&mallory, acceptor_addr, &batch).await {
        Ok(accepted) => {
            println!("  [mallory] UNEXPECTEDLY delivered, accepted={accepted}");
            false
        }
        Err(error) => {
            println!("  [mallory] rejected before any handler ran: {error}");
            true
        }
    };

    router.shutdown().await.ok();

    println!("\nfail-closed summary:");
    println!("  admitted sender resolved + batch accepted: {admitted_ok}");
    println!("  unadmitted sender rejected at the gate:     {mallory_rejected}");
    if admitted_ok && mallory_rejected {
        println!("\nOK: the transport-resolved kernel_id fed the real verifier and it accepted.");
        Ok(())
    } else {
        Err("pheromone lane invariant violated".into())
    }
}
