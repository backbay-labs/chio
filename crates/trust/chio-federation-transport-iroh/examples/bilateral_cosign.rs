//! Example: lane d (bilateral DSSE co-sign) end-to-end over loopback QUIC.
//!
//! Org B requests a DSSE co-signature from Org A over a dedicated-ALPN
//! bidirectional QUIC RPC (categorically NOT gossip: an in-flight statement must
//! not leak to non-parties). Org A's accept-time gate 403-rejects any unadmitted
//! Org B; past the gate, Org A verifies `org_b_signature` over the exact
//! `pae_bytes` against Org B's pinned passport key AND binds the authenticated
//! `EndpointId` to the claimed `org_b_kernel_id`. Only then does Org A co-sign the
//! SAME opaque bytes (never re-derived). On any failure it answers with a typed
//! error and NEVER signs.
//!
//! This example drives the crate's real client (`IrohBilateralCoSigner`) against
//! the real server handler (`BilateralCoSignHandler`): a full co-sign whose
//! response verifies over `pae_bytes`, and an Org B that claims a different kernel
//! id than it authenticated as, refused without a signature.
//!
//! Run: `cargo run -p chio-federation-transport-iroh --example bilateral_cosign`

use std::collections::HashMap;
use std::error::Error;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use chio_core_types::canonical_json_bytes;
use chio_core_types::sha256_hex;
use chio_core_types::Keypair;
use chio_core_types::PublicKey;
use chio_federation::bilateral::BilateralCoSigningError;
use chio_federation::bilateral::DsseCoSigningRequest;
use chio_federation::bilateral::DsseCoSigningResponse;
use chio_federation::bilateral::BILATERAL_DSSE_COSIGNING_SCHEMA;
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
use chio_federation_transport_iroh::lanes::bilateral::BilateralCoSignHandler;
use chio_federation_transport_iroh::lanes::bilateral::IrohBilateralCoSigner;
use chio_federation_transport_iroh::lanes::bilateral::PinnedPassportKeys;
use chio_federation_transport_iroh::lanes::bilateral::ALPN_BILATERAL;
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::Endpoint;
use iroh::EndpointAddr;
use iroh::EndpointId;
use iroh::RelayMode;
use iroh::SecretKey;

const NOW: u64 = 2_000_000;
const ORG_A: &str = "did:chio:org-a";
const ORG_B: &str = "did:chio:org-b";

/// A federation participant: an ed25519 transport identity plus a long-term
/// passport keypair (the algorithm-agnostic co-signing key material).
struct Peer {
    kernel_id: String,
    transport_secret: SecretKey,
    transport_id: EndpointId,
    passport: Keypair,
}

impl Peer {
    fn new(kernel_id: &str, transport_seed: u8, passport_seed: u8) -> Self {
        let transport_secret = SecretKey::from_bytes(&[transport_seed; 32]);
        let transport_id = transport_secret.public();
        Self {
            kernel_id: kernel_id.to_string(),
            transport_secret,
            transport_id,
            passport: Keypair::from_seed(&[passport_seed; 32]),
        }
    }

    fn entry(&self) -> TransportDirectoryEntry {
        TransportDirectoryEntry {
            kernel_id: self.kernel_id.clone(),
            passport_public_key: self.passport.public_key(),
            transport_endpoint_id: self.transport_id,
            passport_endorsement: self.passport.sign(&transport_endorsement_preimage(
                &self.kernel_id,
                &self.transport_id,
            )),
            revocation_signers: Vec::new(),
            removed: false,
        }
    }
}

/// Build a load-time-verified directory admitting the given peers.
fn verified_directory(peers: &[&Peer]) -> Result<Arc<VerifiedDirectory>, Box<dyn Error>> {
    let issuer = Keypair::from_seed(&[240u8; 32]);
    let directory = TransportDirectoryDocument {
        schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
        local_kernel_id: ORG_A.to_string(),
        peers: peers.iter().map(|peer| peer.entry()).collect(),
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
    Ok(Arc::new(bundle.verify_bundle(&trust)?))
}

/// Stand up Org A: a gated loopback endpoint with the co-sign handler mounted on
/// the bilateral ALPN. Returns Org A's dialable address and the live router.
async fn spawn_org_a(
    org_a: &Peer,
    gate: DirectoryGate,
    passport_keys: Arc<dyn PinnedPassportKeys>,
) -> Result<(EndpointAddr, Router), Box<dyn Error>> {
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(org_a.transport_secret.clone())
        .relay_mode(RelayMode::Disabled)
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| error.to_string())?
        .hooks(gate.clone())
        .bind()
        .await
        .map_err(|error| error.to_string())?;
    let socket = endpoint
        .bound_sockets()
        .into_iter()
        .next()
        .ok_or("org a bound no socket")?;
    let addr = EndpointAddr::new(org_a.transport_id).with_ip_addr(socket);

    let handler = BilateralCoSignHandler::new(
        gate,
        org_a.kernel_id.clone(),
        org_a.passport.clone(),
        passport_keys,
    );
    let router = Router::builder(endpoint)
        .accept(ALPN_BILATERAL, handler)
        .spawn();
    Ok((addr, router))
}

/// Build Org B: a loopback client endpoint plus a co-signer that dials `addr` for
/// `org_a_kernel_id`.
async fn spawn_org_b(
    org_b: &Peer,
    org_a_kernel_id: &str,
    addr: EndpointAddr,
) -> Result<IrohBilateralCoSigner, Box<dyn Error>> {
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(org_b.transport_secret.clone())
        .relay_mode(RelayMode::Disabled)
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| error.to_string())?
        .bind()
        .await
        .map_err(|error| error.to_string())?;
    let mut book: HashMap<String, EndpointAddr> = HashMap::new();
    book.insert(org_a_kernel_id.to_string(), addr);
    Ok(IrohBilateralCoSigner::new(endpoint, Arc::new(book)))
}

/// Org A's pinned Org B passport keys (the algorithm-agnostic verify set).
fn pinned_org_b(org_b: &Peer) -> Arc<dyn PinnedPassportKeys> {
    let mut keys: HashMap<String, PublicKey> = HashMap::new();
    keys.insert(org_b.kernel_id.clone(), org_b.passport.public_key());
    Arc::new(keys)
}

async fn cosign_with_timeout(
    cosigner: &IrohBilateralCoSigner,
    request: &DsseCoSigningRequest,
) -> Result<Result<DsseCoSigningResponse, BilateralCoSigningError>, String> {
    tokio::time::timeout(
        Duration::from_secs(15),
        cosigner.request_dsse_cosignature_over_iroh(request),
    )
    .await
    .map_err(|_elapsed| "co-sign timed out".to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("== lane d: bilateral DSSE co-sign (Org B -> Org A) ==\n");

    let org_a = Peer::new(ORG_A, 51, 1);
    let org_b = Peer::new(ORG_B, 52, 2);
    let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b])?);

    let org_a_public = org_a.passport.public_key();
    let (addr, router) = spawn_org_a(&org_a, gate, pinned_org_b(&org_b)).await?;
    let cosigner = spawn_org_b(&org_b, ORG_A, addr).await?;

    // ---- 1. A full co-sign: the response verifies over the exact pae_bytes ---
    let pae_bytes = b"DSSEv1 opaque bilateral pae preimage".to_vec();
    let request = DsseCoSigningRequest::new(
        ORG_A.to_string(),
        org_b.kernel_id.clone(),
        pae_bytes.clone(),
        // Org B signs the PAE bytes with its passport key.
        org_b.passport.sign(&pae_bytes),
    );
    println!(
        "Org B requests a co-signature over {} pae bytes:",
        pae_bytes.len()
    );
    let cosign_ok = match cosign_with_timeout(&cosigner, &request).await {
        Ok(Ok(response)) => {
            let verifies = org_a_public.verify(&pae_bytes, &response.org_a_signature);
            let rejects_other = !org_a_public.verify(b"other bytes", &response.org_a_signature);
            println!("  -> Org A co-signed (schema={:?})", response.schema);
            println!("     org_a_signature verifies over pae_bytes:      {verifies}");
            println!("     org_a_signature rejects a different message:  {rejects_other}");
            verifies && rejects_other && response.schema == BILATERAL_DSSE_COSIGNING_SCHEMA
        }
        Ok(Err(error)) => {
            println!("  -> unexpected co-sign failure: {error}");
            false
        }
        Err(error) => {
            println!("  -> {error}");
            false
        }
    };

    // ---- 2. Org B claims a different kernel id than it authenticated as ------
    let spoof_pae = b"pae for a spoofed org_b".to_vec();
    let spoof_request = DsseCoSigningRequest::new(
        ORG_A.to_string(),
        "did:chio:evil-impersonator".to_string(),
        spoof_pae.clone(),
        org_b.passport.sign(&spoof_pae),
    );
    println!("\nOrg B (authenticated as {ORG_B}) claims to be did:chio:evil-impersonator:");
    let spoof_rejected = match cosign_with_timeout(&cosigner, &spoof_request).await {
        Ok(Err(BilateralCoSigningError::UnknownPeer(peer))) => {
            println!("  -> refused without signing: UnknownPeer({peer:?})");
            peer == "did:chio:evil-impersonator"
        }
        Ok(Err(other)) => {
            println!("  -> refused without signing: {other}");
            true
        }
        Ok(Ok(_response)) => {
            println!("  -> UNEXPECTEDLY co-signed for a spoofed identity");
            false
        }
        Err(error) => {
            println!("  -> {error}");
            false
        }
    };

    router.shutdown().await.ok();

    println!("\nfail-closed summary:");
    println!("  co-signature verifies over pae_bytes:        {cosign_ok}");
    println!("  spoofed org_b refused without a signature:   {spoof_rejected}");
    if cosign_ok && spoof_rejected {
        println!("\nOK: Org A co-signs the exact bytes only for the authenticated counterparty.");
        Ok(())
    } else {
        Err("bilateral co-sign invariant violated".into())
    }
}
