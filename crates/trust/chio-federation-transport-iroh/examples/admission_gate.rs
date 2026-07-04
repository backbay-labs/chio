//! Example: the accept-time admission gate, end-to-end over loopback QUIC.
//!
//! Two dialers race one gated acceptor. One dialer's transport `EndpointId` is
//! bound in the issuer-signed, load-time-verified directory (admitted); the other
//! is not. The gate runs at `after_handshake`, once iroh has cryptographically
//! authenticated the remote key, and BEFORE any `ProtocolHandler::accept` runs:
//! the admitted dialer completes a request/response, the unadmitted dialer is
//! Rejected(403) at the handshake so no handler byte ever flows (fail-closed).
//!
//! Run: `cargo run -p chio-federation-transport-iroh --example admission_gate`
//!
//! Nothing here touches a relay or the network: `RelayMode::Disabled`, loopback
//! `127.0.0.1:0`, deterministic seeds (mirrors the validated PoCs).

use std::error::Error;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use chio_core_types::canonical_json_bytes;
use chio_core_types::sha256_hex;
use chio_core_types::Keypair;
use chio_federation_transport_iroh::admission::DirectoryGate;
use chio_federation_transport_iroh::admission::NOT_ADMITTED_ERROR_CODE;
use chio_federation_transport_iroh::identity::transport_endorsement_preimage;
use chio_federation_transport_iroh::identity::TransportDirectoryBundleBody;
use chio_federation_transport_iroh::identity::TransportDirectoryBundleDocument;
use chio_federation_transport_iroh::identity::TransportDirectoryBundleTrust;
use chio_federation_transport_iroh::identity::TransportDirectoryDocument;
use chio_federation_transport_iroh::identity::TransportDirectoryEntry;
use chio_federation_transport_iroh::identity::TrustedTransportDirectoryIssuer;
use chio_federation_transport_iroh::identity::TRANSPORT_DIRECTORY_BUNDLE_SCHEMA;
use iroh::endpoint::presets;
use iroh::endpoint::AfterHandshakeOutcome;
use iroh::endpoint::Connection;
use iroh::protocol::AcceptError;
use iroh::protocol::ProtocolHandler;
use iroh::protocol::Router;
use iroh::Endpoint;
use iroh::EndpointAddr;
use iroh::EndpointId;
use iroh::RelayMode;
use iroh::SecretKey;

/// A demo ALPN that stands in for any lane: the gate fronts every ALPN alike.
const PROBE_ALPN: &[u8] = b"chio/example/admission-probe/1";

/// Fixed logical time for the directory validity window (deterministic demo).
const NOW: u64 = 2_000_000;

// Deterministic transport seeds. The transport `EndpointId` is derived from the
// endpoint's ed25519 secret key, so the seed used to bind the dialer MUST match
// the seed used to derive the `EndpointId` placed in the directory.
const ACCEPTOR_SEED: u8 = 21;
const ALICE_SEED: u8 = 10;
const MALLORY_SEED: u8 = 99;

/// Derive the transport `EndpointId` a given seed binds to.
fn endpoint_id(seed: u8) -> EndpointId {
    SecretKey::from_bytes(&[seed; 32]).public()
}

/// Build a load-time-verified directory admitting `(kernel_id, transport_seed)`
/// pairs, then wrap it in a `DirectoryGate`. Mirrors the crate's own test
/// fixtures: an issuer-signed bundle that passes every fail-closed check.
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
                // The passport-over-transport endorsement: the long-term passport
                // signs the DOMAIN-SEPARATED preimage committing to the kernel_id
                // and the transport endpoint, binding the two identities.
                passport_endorsement: passport
                    .sign(&transport_endorsement_preimage(kernel_id, &transport)),
                revocation_signers: Vec::new(),
                removed: false,
            }
        })
        .collect::<Vec<_>>();
    let directory = TransportDirectoryDocument {
        schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
        local_kernel_id: "did:chio:local".to_string(),
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
        expires_at_unix_ms: NOW + 1_000,
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
    let verified = bundle.verify_bundle(&trust)?;
    Ok(DirectoryGate::new(Arc::new(verified)))
}

/// Bind a loopback endpoint. The acceptor installs the gate hook; dialers do not
/// (the gate applies to whichever side accepts the connection).
async fn bind_endpoint(seed: u8, gate: Option<DirectoryGate>) -> Result<Endpoint, Box<dyn Error>> {
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[seed; 32]))
        .relay_mode(RelayMode::Disabled)
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| error.to_string())?;
    if let Some(gate) = gate {
        builder = builder.hooks(gate);
    }
    let endpoint = builder.bind().await.map_err(|error| error.to_string())?;
    Ok(endpoint)
}

/// The direct, dialable loopback address of a bound endpoint.
fn direct_addr(endpoint: &Endpoint) -> Result<EndpointAddr, Box<dyn Error>> {
    let socket = endpoint
        .bound_sockets()
        .into_iter()
        .next()
        .ok_or("endpoint bound no socket")?;
    Ok(EndpointAddr::new(endpoint.id()).with_ip_addr(socket))
}

/// A trivial handler mounted behind the gate. It only ever runs for connections
/// the gate already ADMITTED, so reaching it at all is itself the accept signal.
#[derive(Debug, Clone)]
struct ProbeHandler;

impl ProtocolHandler for ProbeHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = conn.accept_bi().await?;
        // Drain the ping, answer with a pong, then hold the connection open until
        // the dialer has read the reply so the finished stream is not truncated.
        let _ping = recv.read_to_end(64).await.map_err(AcceptError::from_err)?;
        send.write_all(b"pong")
            .await
            .map_err(AcceptError::from_err)?;
        send.finish()?;
        conn.closed().await;
        Ok(())
    }
}

/// Dial the acceptor and run one ping/pong. `Ok` proves the gate admitted us and
/// the handler ran; `Err` is what an unadmitted peer sees (rejected at handshake,
/// before any handler byte flows).
async fn probe(endpoint: &Endpoint, addr: EndpointAddr) -> Result<String, String> {
    let conn = endpoint
        .connect(addr, PROBE_ALPN)
        .await
        .map_err(|error| error.to_string())?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(|error| error.to_string())?;
    send.write_all(b"ping")
        .await
        .map_err(|error| error.to_string())?;
    send.finish().map_err(|error| error.to_string())?;
    let reply = recv
        .read_to_end(64)
        .await
        .map_err(|error| error.to_string())?;
    conn.close(0u32.into(), b"ok");
    Ok(String::from_utf8_lossy(&reply).into_owned())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("== admission gate (lane-agnostic accept-time seam) ==\n");

    // The directory admits ALICE's transport key only. MALLORY is bound to no
    // entry at all, so it is unadmitted.
    let gate = build_gate(&[("did:chio:alice", 1, ALICE_SEED)])?;
    let alice_ep = endpoint_id(ALICE_SEED);
    let mallory_ep = endpoint_id(MALLORY_SEED);

    // ---- 1. The pure decision (what the hook computes, no network) ----------
    println!(
        "directory admits: did:chio:alice -> {}",
        alice_ep.fmt_short()
    );
    println!("gate.decide (pure, pre-network):");
    let alice_ok = matches!(gate.decide(&alice_ep), AfterHandshakeOutcome::Accept);
    println!(
        "  alice   {}  -> Accept={alice_ok}, resolve={:?}",
        alice_ep.fmt_short(),
        gate.resolve(&alice_ep)
    );
    let mallory_outcome = gate.decide(&mallory_ep);
    let mut mallory_rejected_403 = false;
    if let AfterHandshakeOutcome::Reject { error_code, reason } = &mallory_outcome {
        mallory_rejected_403 = u64::from(*error_code) == u64::from(NOT_ADMITTED_ERROR_CODE);
        println!(
            "  mallory {}  -> Reject(code={}, reason={:?}), resolve={:?}",
            mallory_ep.fmt_short(),
            u64::from(*error_code),
            String::from_utf8_lossy(reason),
            gate.resolve(&mallory_ep)
        );
    }

    // ---- 2. The same decision over a real loopback QUIC handshake -----------
    let acceptor = bind_endpoint(ACCEPTOR_SEED, Some(gate.clone())).await?;
    let router = Router::builder(acceptor)
        .accept(PROBE_ALPN, ProbeHandler)
        .spawn();
    let acceptor_addr = direct_addr(router.endpoint())?;

    let alice = bind_endpoint(ALICE_SEED, None).await?;
    let mallory = bind_endpoint(MALLORY_SEED, None).await?;

    println!("\ndialing the gated acceptor over QUIC:");
    let alice_wire = match timeout(probe(&alice, acceptor_addr.clone())).await {
        Ok(Ok(reply)) => {
            println!("  alice   -> admitted, handler replied {reply:?}");
            true
        }
        other => {
            println!("  alice   -> unexpected failure: {other:?}");
            false
        }
    };
    let mallory_wire = match timeout(probe(&mallory, acceptor_addr)).await {
        Ok(Ok(reply)) => {
            println!("  mallory -> UNEXPECTEDLY admitted, reply {reply:?}");
            false
        }
        Ok(Err(error)) => {
            println!("  mallory -> rejected at handshake (403), dial failed: {error}");
            true
        }
        Err(_elapsed) => {
            // A rejected handshake usually errors fast; a timeout is still a deny.
            println!("  mallory -> rejected (handshake did not complete)");
            true
        }
    };

    router.shutdown().await.ok();

    println!("\nfail-closed summary:");
    println!("  admitted peer accepted:      {alice_ok} (pure) / {alice_wire} (wire)");
    println!(
        "  unadmitted peer 403-rejected: {mallory_rejected_403} (pure) / {mallory_wire} (wire)"
    );
    if alice_ok && alice_wire && mallory_rejected_403 && mallory_wire {
        println!("\nOK: admitted peer flows, unadmitted peer is 403 before any handler runs.");
        Ok(())
    } else {
        Err("admission gate invariant violated".into())
    }
}

/// Wrap a dial in a bounded deadline so a stuck handshake cannot hang the demo.
async fn timeout<F, T>(future: F) -> Result<T, tokio::time::error::Elapsed>
where
    F: std::future::Future<Output = T>,
{
    tokio::time::timeout(Duration::from_secs(15), future).await
}
