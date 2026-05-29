//! Negative conformance test: witness-lane impersonation.
//!
//! Threats covered:
//!
//! - Body-hash substitution: a malicious mirror returns an entry
//!   whose `body.spec.content.hash.value` does NOT match
//!   `sha256(canonical_jcs(batch.body))`. The verifier must reject
//!   on `BodyHashMismatch`.
//! - UUID substitution: the mirror responds to GET <uuid-X> with an
//!   entry keyed under <uuid-Y>. The verifier must reject on
//!   `Decode("rekor returned no entry for uuid ...")`.
//! - SET forgery: the mirror returns a syntactically-valid Rekor
//!   entry with a `signedEntryTimestamp` signed by an attacker-held
//!   key (NOT the pinned Sigstore key). The verifier must reject on
//!   `SignatureInvalid`.
//!
//! Test scaffolding: a `tiny_http` mock binds 127.0.0.1:0 and a
//! `RekorClient::new(...).with_trusted_keys(...)` is configured with
//! the test's ephemeral P-256 key so the honest path works without
//! reaching the production Sigstore log.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use chio_anchor::{
    batch_body_hash, build_anchor_batch, build_ots_inclusion_proof, build_rekor_entry_body_b64,
    build_rekor_entry_body_b64_with_hash, build_rekor_publish_response,
    build_rekor_publish_response_with_set, sign_set_with_test_key,
    verify_anchor_batch_with_witness_policy_async, verifying_key_to_pem, AnchorBatchWitness,
    AnchorBatchWitnessKind, AnchorWitnessClient, AnchorWitnessError, OtsClient, RekorClient,
    VerifiedWitnessCache, WitnessPolicy, WitnessReceipt, WitnessState,
};
use chio_core::hashing::{sha256, Hash};
use chio_core::Keypair;
use p256::ecdsa::SigningKey;
use tiny_http::{Method, Response, Server};

struct MockServer {
    base_url: String,
    shutdown: Option<mpsc::Sender<()>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockServer {
    fn start<F>(handler: F) -> Self
    where
        F: Fn(&tiny_http::Request) -> tiny_http::Response<std::io::Cursor<Vec<u8>>>
            + Send
            + Sync
            + 'static,
    {
        let server = Server::http("127.0.0.1:0").expect("bind tiny_http");
        let port = server.server_addr().to_ip().expect("ip").port();
        let base_url = format!("http://127.0.0.1:{port}");
        let (tx, rx) = mpsc::channel::<()>();
        let handler = Arc::new(handler);
        let server = Arc::new(server);
        let server_clone = Arc::clone(&server);
        let handler_clone = Arc::clone(&handler);
        let handle = thread::spawn(move || loop {
            if rx.try_recv().is_ok() {
                break;
            }
            match server_clone.recv_timeout(Duration::from_millis(50)) {
                Ok(Some(req)) => {
                    let resp = handler_clone(&req);
                    let _ = req.respond(resp);
                }
                Ok(None) => {}
                Err(_) => break,
            }
        });
        MockServer {
            base_url,
            shutdown: Some(tx),
            handle: Some(handle),
        }
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        if let Some(sender) = self.shutdown.take() {
            let _ = sender.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn sample_batch() -> chio_anchor::AnchorBatch {
    let kp = Keypair::generate();
    let witness = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Rekor,
        witness_id: "rekor:placeholder".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    build_anchor_batch(
        vec!["ck-1".to_string(), "ck-2".to_string(), "ck-3".to_string()],
        witness,
        1_700_000_000,
        &kp,
    )
    .unwrap()
}

/// Test fixture: an ephemeral P-256 keypair plus the matching
/// trusted-key PEM string. The mock server signs SETs with the
/// SigningKey; the RekorClient is configured (via with_trusted_keys)
/// to trust the matching VerifyingKey PEM.
struct TestRekorKey {
    signing: SigningKey,
    pem: String,
}

fn fresh_test_rekor_key() -> TestRekorKey {
    let mut rng = rand::rngs::OsRng;
    let signing = SigningKey::random(&mut rng);
    let pem = verifying_key_to_pem(signing.verifying_key()).unwrap();
    TestRekorKey { signing, pem }
}

#[test]
fn rekor_publish_round_trips_a_batch_against_a_faithful_mock() {
    let batch = sample_batch();
    let body_b64 = build_rekor_entry_body_b64(&batch).unwrap();
    let body_b64_owned = body_b64.clone();
    let test_key = fresh_test_rekor_key();
    let pem = test_key.pem.clone();
    let log_id = "0".repeat(64);
    let log_id_for_handler = log_id.clone();
    let signing_for_handler = test_key.signing.clone();

    let server = MockServer::start(move |req| {
        let set = sign_set_with_test_key(
            &body_b64_owned,
            1_700_000_010,
            &log_id_for_handler,
            12345,
            &signing_for_handler,
        )
        .unwrap();
        let body = build_rekor_publish_response_with_set(
            "uuid-honest-1",
            &body_b64_owned,
            1_700_000_010,
            12345,
            &set,
        );
        let payload = serde_json::to_vec(&body).unwrap();
        let _ = req.method();
        Response::from_data(payload)
            .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
    });

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let client = RekorClient::new(server.base_url.clone(), 0)
        .unwrap()
        .with_trusted_keys(vec![pem]);
    let receipt = runtime
        .block_on(client.publish(&batch))
        .expect("honest mock with valid SET must produce a witness receipt");
    assert_eq!(receipt.kind, AnchorBatchWitnessKind::Rekor);
    assert_eq!(receipt.witness_root, batch.body.tree_root);
    assert_eq!(receipt.body_hash, batch_body_hash(&batch).unwrap());
}

#[test]
fn rekor_publish_rejects_lane_that_returns_a_forged_body_hash() {
    let batch = sample_batch();
    // Lane returns a Rekor body that commits to sha256("imposter")
    // instead of sha256(canonical(batch.body)). The body-hash check
    // fires BEFORE the SET check on the publish path, so the test
    // doesn't need a valid SET.
    let forged_hash_hex = sha256(b"chio.anchor_batch.imposter").to_hex();
    let forged_b64 = build_rekor_entry_body_b64_with_hash(&batch, &forged_hash_hex).unwrap();
    let forged_b64_owned = forged_b64.clone();

    let server = MockServer::start(move |req| {
        let body = build_rekor_publish_response(
            "uuid-impersonator-1",
            &forged_b64_owned,
            1_700_000_010,
            999,
        );
        let payload = serde_json::to_vec(&body).unwrap();
        let _ = req.method();
        Response::from_data(payload)
            .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
    });

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let client = RekorClient::new(server.base_url.clone(), 0).unwrap();
    let err = runtime
        .block_on(client.publish(&batch))
        .expect_err("publish must reject lane-side body-hash mismatch");
    match err {
        AnchorWitnessError::BodyHashMismatch { lane, batch: real } => {
            assert_eq!(lane, forged_hash_hex);
            assert_eq!(real, batch_body_hash(&batch).unwrap().to_hex());
        }
        other => panic!("expected BodyHashMismatch, got {other:?}"),
    }
}

#[test]
fn rekor_verify_inclusion_rejects_lane_that_returns_a_substituted_entry() {
    let batch = sample_batch();
    let real_body_hash = batch_body_hash(&batch).unwrap();

    // The verifier already holds an honest receipt (we pre-populated
    // it from a previous successful publish). At verify_inclusion
    // time, the mirror has been compromised: GET /entries/<uuid>
    // returns a Rekor body whose hash.value points at a different
    // batch.
    let receipt = WitnessReceipt {
        kind: AnchorBatchWitnessKind::Rekor,
        external_uuid: "uuid-attacked".to_string(),
        published_at: 1_700_000_010,
        inclusion_proof: vec![],
        witness_root: batch.body.tree_root,
        body_hash: real_body_hash,
    };

    let forged_hash_hex = sha256(b"chio.anchor_batch.different-batch").to_hex();
    let forged_b64 = build_rekor_entry_body_b64_with_hash(&batch, &forged_hash_hex).unwrap();
    let forged_b64_owned = forged_b64.clone();
    let server = MockServer::start(move |req| {
        let response_body =
            build_rekor_publish_response("uuid-attacked", &forged_b64_owned, 1_700_000_010, 42);
        let payload = serde_json::to_vec(&response_body).unwrap();
        let _ = req.method();
        Response::from_data(payload)
            .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
    });

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let client = RekorClient::new(server.base_url.clone(), 0).unwrap();
    let err = runtime
        .block_on(client.verify_inclusion(&receipt))
        .expect_err("verify_inclusion must reject lane substitution");
    match err {
        AnchorWitnessError::BodyHashMismatch { lane, batch: held } => {
            assert_eq!(lane, forged_hash_hex);
            assert_eq!(held, real_body_hash.to_hex());
        }
        other => panic!("expected BodyHashMismatch on verify_inclusion, got {other:?}"),
    }
}

#[test]
fn rekor_verify_inclusion_rejects_uuid_substitution() {
    // The receipt claims uuid-X, but the mirror responds to
    // GET /entries/uuid-X with an entry keyed under uuid-Y. Real
    // production Rekor mirrors that try this attack get caught here.
    let batch = sample_batch();
    let real_body_hash = batch_body_hash(&batch).unwrap();
    let receipt = WitnessReceipt {
        kind: AnchorBatchWitnessKind::Rekor,
        external_uuid: "uuid-original-receipt".to_string(),
        published_at: 1_700_000_010,
        inclusion_proof: vec![],
        witness_root: batch.body.tree_root,
        body_hash: real_body_hash,
    };

    let body_b64 = build_rekor_entry_body_b64(&batch).unwrap();
    let body_b64_owned = body_b64.clone();
    let server = MockServer::start(move |req| {
        // Always reply with a SUBSTITUTED uuid keyspace, no matter
        // which uuid the verifier asked for.
        let payload_value = build_rekor_publish_response(
            "uuid-attacker-replaced",
            &body_b64_owned,
            1_700_000_010,
            7,
        );
        let payload = serde_json::to_vec(&payload_value).unwrap();
        let _ = req.method();
        Response::from_data(payload)
            .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
    });

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let client = RekorClient::new(server.base_url.clone(), 0).unwrap();
    let err = runtime
        .block_on(client.verify_inclusion(&receipt))
        .expect_err("verify_inclusion must reject uuid substitution");
    match err {
        AnchorWitnessError::Decode(message) => {
            assert!(
                message.contains("rekor returned no entry for uuid"),
                "expected uuid-substitution decode error, got: {message}"
            );
        }
        other => panic!("expected Decode error on uuid substitution, got {other:?}"),
    }

    // Required by `tiny_http::Method` import lint.
    let _ = Method::Get;
}

/// A malicious mirror returns a SET signed by an attacker-held
/// key. Even though the body-hash matches our batch, the verifier
/// must refuse the entry because the SET does not verify under any
/// pinned Rekor public key.
#[test]
fn rekor_verify_inclusion_rejects_set_signed_by_untrusted_key() {
    let batch = sample_batch();
    let real_body_hash = batch_body_hash(&batch).unwrap();
    let receipt = WitnessReceipt {
        kind: AnchorBatchWitnessKind::Rekor,
        external_uuid: "uuid-set-forgery".to_string(),
        published_at: 1_700_000_010,
        inclusion_proof: vec![],
        witness_root: batch.body.tree_root,
        body_hash: real_body_hash,
    };

    let body_b64 = build_rekor_entry_body_b64(&batch).unwrap();
    let body_b64_owned = body_b64.clone();
    // Attacker key: NOT the production Rekor key, NOT the verifier's
    // pinned key. The attacker can produce a syntactically valid SET
    // but it must fail verification under the trusted set.
    let attacker = fresh_test_rekor_key();
    let attacker_signing = attacker.signing.clone();
    let log_id = "0".repeat(64);
    let log_id_for_handler = log_id.clone();

    let server = MockServer::start(move |req| {
        let forged_set = sign_set_with_test_key(
            &body_b64_owned,
            1_700_000_010,
            &log_id_for_handler,
            42,
            &attacker_signing,
        )
        .unwrap();
        let response_body = build_rekor_publish_response_with_set(
            "uuid-set-forgery",
            &body_b64_owned,
            1_700_000_010,
            42,
            &forged_set,
        );
        let payload = serde_json::to_vec(&response_body).unwrap();
        let _ = req.method();
        Response::from_data(payload)
            .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
    });

    // Verifier client trusts an unrelated key (a freshly-minted one,
    // standing in for the pinned Sigstore key). The forged SET must
    // not verify under it.
    let trusted = fresh_test_rekor_key();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let client = RekorClient::new(server.base_url.clone(), 0)
        .unwrap()
        .with_trusted_keys(vec![trusted.pem.clone()]);
    let err = runtime
        .block_on(client.verify_inclusion(&receipt))
        .expect_err("verify_inclusion must reject SET signed by untrusted key");
    match err {
        AnchorWitnessError::SignatureInvalid(msg) => {
            assert!(
                msg.contains("rekor SET signature did not verify"),
                "expected SET-signature rejection, got: {msg}"
            );
        }
        other => panic!("expected SignatureInvalid on SET forgery, got {other:?}"),
    }
}

/// Positive control: when the SET is signed by a key in the
/// client's trusted set, verify_inclusion accepts the entry. Pairs
/// with the negative test above so a regression in either direction
/// is observable.
#[test]
fn rekor_verify_inclusion_accepts_set_signed_by_trusted_key() {
    let batch = sample_batch();
    let real_body_hash = batch_body_hash(&batch).unwrap();
    let receipt = WitnessReceipt {
        kind: AnchorBatchWitnessKind::Rekor,
        external_uuid: "uuid-set-honest".to_string(),
        published_at: 1_700_000_010,
        inclusion_proof: vec![],
        witness_root: batch.body.tree_root,
        body_hash: real_body_hash,
    };
    let body_b64 = build_rekor_entry_body_b64(&batch).unwrap();
    let body_b64_owned = body_b64.clone();
    let test_key = fresh_test_rekor_key();
    let signing_for_handler = test_key.signing.clone();
    let log_id = "0".repeat(64);
    let log_id_for_handler = log_id.clone();

    let server = MockServer::start(move |req| {
        let set = sign_set_with_test_key(
            &body_b64_owned,
            1_700_000_010,
            &log_id_for_handler,
            42,
            &signing_for_handler,
        )
        .unwrap();
        let response_body = build_rekor_publish_response_with_set(
            "uuid-set-honest",
            &body_b64_owned,
            1_700_000_010,
            42,
            &set,
        );
        let payload = serde_json::to_vec(&response_body).unwrap();
        let _ = req.method();
        Response::from_data(payload)
            .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
    });

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let client = RekorClient::new(server.base_url.clone(), 0)
        .unwrap()
        .with_trusted_keys(vec![test_key.pem.clone()]);
    runtime
        .block_on(client.verify_inclusion(&receipt))
        .expect("SET signed by a trusted key must verify");
}

#[test]
fn require_public_witness_rejects_ots_marker_without_trusted_bitcoin_evidence() {
    let kp = Keypair::generate();
    let witness = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Ots,
        witness_id: "ots:self-asserted".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    let mut batch = build_anchor_batch(
        vec!["ck-ots-1".to_string(), "ck-ots-2".to_string()],
        witness,
        1_700_000_000,
        &kp,
    )
    .unwrap();
    let body_hash = batch_body_hash(&batch).unwrap();
    let inclusion_proof = build_ots_inclusion_proof(&body_hash, 900_000).unwrap();
    batch.body.witness_state = WitnessState::Witnessed {
        receipt: WitnessReceipt {
            kind: AnchorBatchWitnessKind::Ots,
            external_uuid: body_hash.to_hex(),
            published_at: 1_700_000_010,
            inclusion_proof,
            witness_root: batch.body.tree_root,
            body_hash,
        },
        observed_at: 1_700_000_010,
    };
    let signed = chio_anchor::AnchorBatch::sign(batch.body, &kp).unwrap();
    let policy = WitnessPolicy {
        require_public_witness: true,
        stale_window_seconds: 60 * 60,
    };
    let client = OtsClient::new("http://127.0.0.1:9", 0).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let err = runtime
        .block_on(verify_anchor_batch_with_witness_policy_async(
            &signed,
            &policy,
            1_700_000_100,
            Some(&client),
            &VerifiedWitnessCache::new(),
        ))
        .expect_err("OTS marker-only receipts must not satisfy require_public_witness");
    let msg = err.to_string();
    assert!(
        msg.contains("advisory-only") || msg.contains("trusted Bitcoin header"),
        "expected OTS trusted-evidence rejection, got: {msg}"
    );
}
