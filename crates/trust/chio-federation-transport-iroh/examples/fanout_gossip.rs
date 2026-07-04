//! Example: lane c (cross-operator fan-out) end-to-end over a loopback
//! iroh-gossip swarm.
//!
//! Three admitted operators join one per-treaty gossip topic in a chain
//! (A seed; B bootstraps from A; C from B). A authors a self-signed pheromone
//! deposit and broadcasts it; C receives it RELAYED through B. In gossip,
//! `Message::delivered_from` is the forwarding NEIGHBOR (here B), NOT the author
//! (A), so authorship must be established FROM THE PAYLOAD ALONE: the
//! transport-independent frame verifier plus the embedded deposit's OWN
//! self-signature, checked against the origin operator's passport key resolved by
//! `origin_kernel_id` (never from `delivered_from`).
//!
//! The load-bearing property: a frame relayed by an ADMITTED neighbor but whose
//! deposit self-signature is invalid is REJECTED. Being forwarded by a trusted,
//! directory-admitted swarm member does not launder a bad payload, because
//! `delivered_from` is never an input to verification.
//!
//! Run: `cargo run -p chio-federation-transport-iroh --example fanout_gossip`

use std::error::Error;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use chio_core_types::canonical_json_bytes;
use chio_core_types::sha256_hex;
use chio_core_types::Keypair;
use chio_federation::pheromone_gossip::PheromoneDepositGossip;
use chio_federation::pheromone_gossip::PheromoneTransitPolicy;
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
use chio_federation_transport_iroh::identity::VerifiedDirectory;
use chio_federation_transport_iroh::identity::TRANSPORT_DIRECTORY_BUNDLE_SCHEMA;
use chio_federation_transport_iroh::lanes::fanout::decode_and_verify_fanout_frame;
use chio_federation_transport_iroh::lanes::fanout::FanoutError;
use chio_federation_transport_iroh::lanes::fanout::FanoutLane;
use chio_federation_transport_iroh::lanes::fanout::FanoutTopic;
use chio_federation_transport_iroh::lanes::fanout::StaticOriginKeys;
use chio_federation_transport_iroh::lanes::fanout::StaticTreatyMembership;
use chio_pheromone::sign_deposit;
use chio_pheromone::PheromoneDepositBody;
use chio_pheromone::Severity;
use chio_pheromone::PHEROMONE_DEPOSIT_SCHEMA;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::Endpoint;
use iroh::EndpointAddr;
use iroh::EndpointId;
use iroh::RelayMode;
use iroh::SecretKey;
use iroh_gossip::Gossip;

const NOW: u64 = 1_700_000_000_000;
const NAMESPACE: &str = "chio/agents";
const TREATY: &str = "treaty:reputation-clearing";
const AUTHOR: &str = "did:chio:author";

const NODE_A_SEED: u8 = 61;
const NODE_B_SEED: u8 = 62;
const NODE_C_SEED: u8 = 63;

fn endpoint_id(seed: u8) -> EndpointId {
    SecretKey::from_bytes(&[seed; 32]).public()
}

/// Build a load-time-verified directory admitting every node's transport
/// endpoint and wrap it in a gate. All three swarm members are admitted, so every
/// gossip connection passes the accept-time gate (the "admitted neighbor" story).
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
        local_kernel_id: "did:chio:swarm".to_string(),
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
    let verified: VerifiedDirectory = bundle.verify_bundle(&trust)?;
    Ok(DirectoryGate::new(Arc::new(verified)))
}

/// One swarm node: a gated endpoint, an iroh-gossip protocol handler mounted on a
/// router, and a `FanoutLane` over the gossip handle.
struct Node {
    id: EndpointId,
    addr: EndpointAddr,
    lookup: MemoryLookup,
    lane: FanoutLane,
    router: Router,
}

async fn spawn_node(seed: u8, gate: DirectoryGate) -> Result<Node, Box<dyn Error>> {
    let lookup = MemoryLookup::new();
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[seed; 32]))
        .relay_mode(RelayMode::Disabled)
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| error.to_string())?
        .hooks(gate)
        .address_lookup(lookup.clone())
        .bind()
        .await
        .map_err(|error| error.to_string())?;
    let socket = endpoint
        .bound_sockets()
        .into_iter()
        .next()
        .ok_or("node bound no socket")?;
    let id = endpoint.id();
    let addr = EndpointAddr::new(id).with_ip_addr(socket);

    // Spawn gossip and mount it on a router under its own ALPN (gossip owns the
    // ALPN; this lane does not invent one). Membership is gated upstream.
    let gossip = Gossip::builder().spawn(endpoint.clone());
    // Build the lane before the router moves `endpoint`: the lane derives its
    // authenticated local id from this endpoint, so it must see the real one.
    let lane = FanoutLane::new(gossip.clone(), &endpoint);
    let router = Router::builder(endpoint)
        .accept(iroh_gossip::ALPN, gossip)
        .spawn();
    Ok(Node {
        id,
        addr,
        lookup,
        lane,
        router,
    })
}

fn live_policy() -> PheromoneTransitPolicy {
    PheromoneTransitPolicy {
        schema: PHEROMONE_TRANSIT_POLICY_SCHEMA.to_string(),
        accepted_hubs: Vec::new(),
        allowed_ingress_treaties: Vec::new(),
        allowed_egress_treaties: Vec::new(),
        allowed_subject_class_namespaces: vec![NAMESPACE.to_string()],
        valid_from_unix_ms: NOW - 1,
        valid_until_unix_ms: NOW + 1_000_000,
        max_hops: 4,
        required_action_class_id: "action".to_string(),
        pinned_ladder_refs: Vec::new(),
    }
}

/// Build a self-signed deposit frame authored by `author`. When `tamper` is set,
/// a signed-but-frame-irrelevant field is mutated AFTER signing: the frame-level
/// checks still pass, but the deposit self-signature no longer matches.
fn build_frame(
    author: &Keypair,
    nonce: &str,
    tamper: bool,
) -> Result<PheromoneDepositGossip, Box<dyn Error>> {
    let body = PheromoneDepositBody {
        schema: PHEROMONE_DEPOSIT_SCHEMA.to_string(),
        kernel_id: AUTHOR.to_string(),
        agent_passport_key_hash: "passport-key-hash".to_string(),
        agent_passport_jwk_thumbprint: "passport-thumbprint".to_string(),
        subject_class: "malicious-tool".to_string(),
        subject_class_namespace: NAMESPACE.to_string(),
        indicator: serde_json::json!({ "kind": "observation" }),
        severity: Severity::High,
        confidence: 0.8,
        timestamp_unix_ms: NOW,
        decay_half_life_secs: 3600.0,
        evaporation_floor: None,
        nonce: nonce.to_string(),
        treaty_scope: vec![TREATY.to_string()],
        cost_commitment: None,
        workflow_context: None,
    };
    let deposit = sign_deposit(body, author).map_err(|error| error.to_string())?;
    let mut frame = PheromoneDepositGossip {
        schema: PHEROMONE_GOSSIP_SCHEMA.to_string(),
        deposit,
        origin_kernel_id: AUTHOR.to_string(),
        // The re-gossiping hub, deliberately NOT the author: fan-out does not
        // require gossiping_peer == author (unlike the direct lanes).
        gossiping_peer_kernel_id: "did:chio:relay-hub".to_string(),
        treaty_id: TREATY.to_string(),
        ts_unix_ms: NOW,
        transit_chain: None,
    };
    if tamper {
        frame.deposit.body.confidence = 0.123_456;
    }
    Ok(frame)
}

/// The receive-side verification context (payload-only; never `delivered_from`).
struct Verifier<'a> {
    origin_keys: &'a StaticOriginKeys,
    membership: &'a StaticTreatyMembership,
    policy: &'a PheromoneTransitPolicy,
}

/// Rebroadcast fresh frames (from `make_frame`) on `author_topic` until
/// `receiver_topic` yields a payload the predicate accepts, or the deadline
/// lapses. Fresh nonces avoid gossip dedup between attempts.
async fn drive<M, F>(
    author_topic: &FanoutTopic,
    receiver_topic: &mut FanoutTopic,
    verifier: &Verifier<'_>,
    mut make_frame: M,
    mut accept: F,
) -> Result<bool, Box<dyn Error>>
where
    M: FnMut(u64) -> Result<PheromoneDepositGossip, Box<dyn Error>>,
    F: FnMut(EndpointId, &Result<PheromoneDepositGossip, FanoutError>) -> bool,
{
    let deadline = Instant::now() + Duration::from_secs(20);
    // Bind the raw decode to the receiver's own treaty so a foreign-treaty frame
    // could never be accepted on this swarm (captured before the receive borrow).
    let receiver_treaty = receiver_topic.treaty_id().to_string();
    let mut attempt = 0u64;
    while Instant::now() < deadline {
        let frame = make_frame(attempt)?;
        attempt += 1;
        author_topic.broadcast(&frame).await?;
        match tokio::time::timeout(Duration::from_millis(400), receiver_topic.next_payload()).await
        {
            Ok(Some(Ok(message))) => {
                let verdict = decode_and_verify_fanout_frame(
                    &message.content,
                    &receiver_treaty,
                    verifier.origin_keys,
                    verifier.membership,
                    verifier.policy,
                    NOW,
                );
                if accept(message.delivered_from, &verdict) {
                    return Ok(true);
                }
            }
            Ok(Some(Err(error))) => return Err(error.to_string().into()),
            Ok(None) => return Err("gossip topic closed unexpectedly".into()),
            Err(_elapsed) => continue,
        }
    }
    Ok(false)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("== lane c: cross-operator fan-out over an iroh-gossip swarm ==\n");

    let gate = build_gate(&[
        ("did:chio:node-a", 1, NODE_A_SEED),
        ("did:chio:node-b", 2, NODE_B_SEED),
        ("did:chio:node-c", 3, NODE_C_SEED),
    ])?;

    // Chain topology: A (seed) <- B <- C. B must know A's address; C must know
    // B's; the seed needs nobody (relay + discovery are disabled on loopback).
    let node_a = spawn_node(NODE_A_SEED, gate.clone()).await?;
    let node_b = spawn_node(NODE_B_SEED, gate.clone()).await?;
    let node_c = spawn_node(NODE_C_SEED, gate).await?;
    node_b.lookup.add_endpoint_info(node_a.addr.clone());
    node_c.lookup.add_endpoint_info(node_b.addr.clone());

    // The issuer-signed per-treaty party set the fan-out gate consults. Every node
    // (and the frame author) is a party to TREATY, so join and receive both admit;
    // a non-party would be rejected with FanoutError::TreatyMembershipDenied.
    // The join gate resolves each node's authenticated EndpointId to its kernel id
    // through this same membership, so bind every node's endpoint here.
    let membership = StaticTreatyMembership::new()
        .with(
            TREATY,
            [
                "did:chio:node-a",
                "did:chio:node-b",
                "did:chio:node-c",
                AUTHOR,
            ],
        )
        .with_endpoint(node_a.id, "did:chio:node-a")
        .with_endpoint(node_b.id, "did:chio:node-b")
        .with_endpoint(node_c.id, "did:chio:node-c");

    println!("joining topic for {TREATY:?} (A seed; B<-A; C<-B) ...");
    let joined = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(
            node_a
                .lane
                .subscribe_treaty(TREATY, "did:chio:node-a", &membership, vec![]),
            node_b
                .lane
                .subscribe_treaty(TREATY, "did:chio:node-b", &membership, vec![node_a.id]),
            node_c
                .lane
                .subscribe_treaty(TREATY, "did:chio:node-c", &membership, vec![node_b.id]),
        )
    })
    .await
    .map_err(|_elapsed| "gossip join timed out")?;
    let a_topic = joined.0?;
    // B's topic is the relay hop: hold it so B keeps forwarding A -> C.
    let _b_topic = joined.1?;
    let mut c_topic = joined.2?;
    println!(
        "  joined; topic id {}\n",
        hex_short(a_topic.topic_id().as_bytes())
    );

    // The author's passport key, trusted by C's origin resolver. This is resolved
    // from the PAYLOAD origin, never from delivered_from.
    let author = Keypair::from_seed(&[9u8; 32]);
    let origin_keys = StaticOriginKeys::new().with(AUTHOR, author.public_key());
    let policy = live_policy();
    let verifier = Verifier {
        origin_keys: &origin_keys,
        membership: &membership,
        policy: &policy,
    };

    // ---- 1. Valid self-signed frame: accepted; delivered_from is the relay ---
    println!("A broadcasts a VALID self-signed deposit authored by {AUTHOR:?}:");
    let valid_ok = drive(
        &a_topic,
        &mut c_topic,
        &verifier,
        |attempt| build_frame(&author, &format!("valid-{attempt}"), false),
        |delivered_from, verdict| match verdict {
            Ok(frame) => {
                let relayed = delivered_from == node_b.id;
                println!(
                    "  [C] received: delivered_from={} (relay B={}), payload origin_kernel_id={:?}",
                    delivered_from.fmt_short(),
                    node_b.id.fmt_short(),
                    frame.origin_kernel_id
                );
                println!("  [C] origin-verified from the payload -> ACCEPTED (delivered_from ignored, relayed={relayed})");
                true
            }
            Err(_) => false,
        },
    )
    .await?;

    // ---- 2. Tampered frame from the same admitted relay: rejected ------------
    println!("\nA broadcasts a frame with an INVALID deposit signature (relayed by admitted B):");
    let tampered_rejected = drive(
        &a_topic,
        &mut c_topic,
        &verifier,
        |attempt| build_frame(&author, &format!("tampered-{attempt}"), true),
        |delivered_from, verdict| match verdict {
            Err(FanoutError::DepositSignatureInvalid) => {
                println!(
                    "  [C] received via admitted neighbor delivered_from={} -> REJECTED (DepositSignatureInvalid)",
                    delivered_from.fmt_short()
                );
                true
            }
            // Skip any leftover valid frames still in flight from phase 1.
            _ => false,
        },
    )
    .await?;

    // Graceful teardown: drop the topic subscriptions, then shut the routers down
    // so the gossip actors stop cleanly (an abrupt runtime drop can otherwise
    // cancel a gossip forwarder task mid-flight and log a teardown panic).
    drop(a_topic);
    drop(_b_topic);
    drop(c_topic);
    node_a.router.shutdown().await.ok();
    node_b.router.shutdown().await.ok();
    node_c.router.shutdown().await.ok();

    println!("\nfail-closed summary:");
    println!("  valid relayed frame accepted from payload:        {valid_ok}");
    println!("  tampered frame from admitted neighbor rejected:   {tampered_rejected}");
    if valid_ok && tampered_rejected {
        println!("\nOK: authorship comes from the signed payload; delivered_from never launders a frame.");
        Ok(())
    } else {
        Err("fan-out lane invariant violated".into())
    }
}

/// Short hex prefix of a byte slice, for a readable topic id in the log.
fn hex_short(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(5)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
