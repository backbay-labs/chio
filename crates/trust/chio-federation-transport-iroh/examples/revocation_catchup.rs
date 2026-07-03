//! Example: lane e (revocation catch-up) end-to-end over loopback iroh-blobs.
//!
//! A revocation authority publishes signed epoch roots as content-addressed
//! blobs. A follower fetches a manifest range over iroh-blobs and verifies every
//! fetched root against a PINNED signer key. iroh-blobs gives BLAKE3 verified
//! streaming (integrity: the bytes match the requested hash) but NOT authenticity;
//! so each fetched blob is re-checked against the pinned verifying key before it
//! is trusted. A legitimately signed root is accepted; a FORGED root - one that
//! claims the same `signer_id` but is signed by a different key - is rejected
//! `BadSignature` and yields no history (all-or-nothing).
//!
//! Why the blobs catch-up path and not the direct revocation-lane push: the direct
//! `RevocationHandler::accept` returns without awaiting `conn.closed()`, so on
//! loopback the connection tears down before the dialer reads the reply frame
//! (the pheromone and bilateral handlers avoid this by holding the connection
//! open). The iroh-blobs substrate, served by iroh-blobs' own protocol handler,
//! transfers cleanly; the ADAPTER-SPEC pairs the two lanes for exactly this bulk
//! transfer. Both share the SAME pinned-signer authenticity check.
//!
//! Run: `cargo run -p chio-federation-transport-iroh --example revocation_catchup`

use std::error::Error;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use chio_core_types::canonical_json_bytes;
use chio_core_types::sha256_hex;
use chio_core_types::Keypair;
use chio_federation_transport_iroh::admission::DirectoryGate;
use chio_federation_transport_iroh::catchup::BlobCatchupClient;
use chio_federation_transport_iroh::catchup::CatchupError;
use chio_federation_transport_iroh::identity::TransportDirectoryBundleBody;
use chio_federation_transport_iroh::identity::TransportDirectoryBundleDocument;
use chio_federation_transport_iroh::identity::TransportDirectoryBundleTrust;
use chio_federation_transport_iroh::identity::TransportDirectoryDocument;
use chio_federation_transport_iroh::identity::TransportDirectoryEntry;
use chio_federation_transport_iroh::identity::TrustedTransportDirectoryIssuer;
use chio_federation_transport_iroh::identity::VerifiedDirectory;
use chio_federation_transport_iroh::identity::TRANSPORT_DIRECTORY_BUNDLE_SCHEMA;
use chio_federation_transport_iroh::lanes::revocation::SignerBinding;
use chio_federation_transport_iroh::lanes::revocation::VerifiedSignerDirectory;
use chio_revocation_oracle::Ed25519RootSigner;
use chio_revocation_oracle::EpochRoot;
use chio_revocation_oracle::SignedEpochRoot;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::Endpoint;
use iroh::EndpointAddr;
use iroh::EndpointId;
use iroh::RelayMode;
use iroh::SecretKey;
use iroh_blobs::Hash;

const NOW: u64 = 2_000_000;
const SIGNER_ID: &str = "oracle-a";
// 64-hex ed25519 seeds: the pinned key vs. a forger's key.
const PINNED_SEED: &str = "0101010101010101010101010101010101010101010101010101010101010101";
const FORGER_SEED: &str = "0202020202020202020202020202020202020202020202020202020202020202";

const AUTHORITY_SEED: u8 = 41;
const FOLLOWER_SEED: u8 = 40;
const FOLLOWER_KERNEL: &str = "did:chio:follower";
const AUTHORITY_KERNEL: &str = "did:chio:revocation-authority";

fn endpoint_id(seed: u8) -> EndpointId {
    SecretKey::from_bytes(&[seed; 32]).public()
}

/// Build a load-time-verified admission directory admitting `(kernel_id,
/// transport_seed)` pairs and wrap it in a gate. The authority admits the
/// follower so the follower's blob fetch is not 403-rejected at the handshake.
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
                passport_endorsement: passport.sign(transport.as_bytes()),
                removed: false,
            }
        })
        .collect::<Vec<_>>();
    let directory = TransportDirectoryDocument {
        schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
        local_kernel_id: AUTHORITY_KERNEL.to_string(),
        peers,
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

async fn bind_endpoint(
    seed: u8,
    gate: Option<DirectoryGate>,
    lookup: Option<MemoryLookup>,
) -> Result<Endpoint, Box<dyn Error>> {
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[seed; 32]))
        .relay_mode(RelayMode::Disabled)
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| error.to_string())?;
    if let Some(gate) = gate {
        builder = builder.hooks(gate);
    }
    if let Some(lookup) = lookup {
        builder = builder.address_lookup(lookup);
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

fn signed_root(signer: &Ed25519RootSigner, epoch: u64) -> Result<SignedEpochRoot, Box<dyn Error>> {
    let root = EpochRoot {
        epoch,
        root_hash: [u8::try_from(epoch % 256).unwrap_or(0); 32],
        leaf_count: usize::try_from(epoch).unwrap_or(0),
        issued_at_unix_ms: 1_700_000_000_000 + epoch,
    };
    Ok(SignedEpochRoot::sign(root, signer)?)
}

/// A unique scratch directory for a durable blob store (cleaned up on exit).
fn scratch_dir(label: &str) -> Result<std::path::PathBuf, Box<dyn Error>> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "chio-revocation-catchup-{label}-{}-{nanos}",
        std::process::id()
    ));
    Ok(dir)
}

async fn fetch_with_timeout(
    client: &BlobCatchupClient,
    authority: EndpointId,
    manifest: &[(u64, Hash)],
) -> Result<Result<Vec<SignedEpochRoot>, CatchupError>, String> {
    tokio::time::timeout(
        Duration::from_secs(20),
        client.fetch_range(SIGNER_ID, authority, manifest),
    )
    .await
    .map_err(|_elapsed| "fetch timed out".to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("== lane e: revocation catch-up over iroh-blobs (pinned-signer authenticity) ==\n");

    let pinned = Ed25519RootSigner::from_signing_key(SIGNER_ID, PINNED_SEED)?;
    let forger = Ed25519RootSigner::from_signing_key(SIGNER_ID, FORGER_SEED)?;

    // The follower pins signer "oracle-a" to the AUTHORITY endpoint (the origin it
    // is allowed to pull from) and to the PINNED verifying key.
    let pinned_signers = Arc::new(VerifiedSignerDirectory::from_bindings([(
        SIGNER_ID.to_string(),
        SignerBinding {
            endpoint: endpoint_id(AUTHORITY_SEED),
            verifier: pinned.verifier(),
        },
    )])?);

    // ---- Authority: gated endpoint + iroh-blobs provider --------------------
    let gate = build_gate(&[(FOLLOWER_KERNEL, 1, FOLLOWER_SEED)])?;
    let authority_endpoint = bind_endpoint(AUTHORITY_SEED, Some(gate), None).await?;
    let authority_dir = scratch_dir("authority")?;
    let authority_client = BlobCatchupClient::load(
        &authority_dir,
        authority_endpoint.clone(),
        pinned_signers.clone(),
    )
    .await?;
    let authority_addr = direct_addr(&authority_endpoint)?;
    let authority_id = endpoint_id(AUTHORITY_SEED);
    let router = Router::builder(authority_endpoint)
        .accept(iroh_blobs::ALPN, authority_client.blobs_protocol())
        .spawn();

    // Publish an epoch-5 root under the pinned key, and a FORGED epoch-6 root.
    let good_hash = authority_client
        .publish_signed_root(&signed_root(&pinned, 5)?)
        .await?;
    let forged_hash = authority_client
        .publish_signed_root(&signed_root(&forger, 6)?)
        .await?;
    println!("authority published:");
    println!("  epoch 5 (pinned key)  -> blob {good_hash}");
    println!("  epoch 6 (forger key)  -> blob {forged_hash}");

    // ---- Follower: fetch + verify against the pinned signer -----------------
    let lookup = MemoryLookup::new();
    lookup.add_endpoint_info(authority_addr);
    let follower_endpoint = bind_endpoint(FOLLOWER_SEED, None, Some(lookup)).await?;
    let follower_dir = scratch_dir("follower")?;
    let follower_client =
        BlobCatchupClient::load(&follower_dir, follower_endpoint, pinned_signers).await?;

    println!("\nfollower fetches epoch 5 (pinned-signer manifest):");
    let good_ok = match fetch_with_timeout(&follower_client, authority_id, &[(5, good_hash)]).await
    {
        Ok(Ok(roots)) => {
            let epochs: Vec<u64> = roots.iter().map(|r| r.root.epoch).collect();
            println!("  -> verified + caught up epochs {epochs:?}");
            epochs == vec![5]
        }
        Ok(Err(error)) => {
            println!("  -> unexpected verification failure: {error}");
            false
        }
        Err(error) => {
            println!("  -> {error}");
            false
        }
    };

    println!("\nfollower fetches epoch 6 (FORGED root under the same signer_id):");
    let forged_rejected =
        match fetch_with_timeout(&follower_client, authority_id, &[(6, forged_hash)]).await {
            Ok(Ok(roots)) => {
                println!("  -> UNEXPECTEDLY accepted {} root(s)", roots.len());
                false
            }
            Ok(Err(CatchupError::BadSignature(signer))) => {
                println!("  -> rejected BadSignature(signer_id={signer:?}), nothing caught up");
                signer == SIGNER_ID
            }
            Ok(Err(other)) => {
                println!("  -> rejected ({other}) - fail-closed, but not the signature check");
                false
            }
            Err(error) => {
                println!("  -> {error}");
                false
            }
        };

    router.shutdown().await.ok();
    let _ = std::fs::remove_dir_all(&authority_dir);
    let _ = std::fs::remove_dir_all(&follower_dir);

    println!("\nfail-closed summary:");
    println!("  pinned-signer root fetched + verified: {good_ok}");
    println!("  forged root rejected on authenticity:  {forged_rejected}");
    if good_ok && forged_rejected {
        println!(
            "\nOK: BLAKE3 integrity is not authenticity; only the pinned-signer root is trusted."
        );
        Ok(())
    } else {
        Err("revocation catch-up invariant violated".into())
    }
}
