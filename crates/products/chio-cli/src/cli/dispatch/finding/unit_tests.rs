use super::*;

use super::finding_challenge::{
    load_challenge_evidence_document, prepare_challenge, FINDING_CHALLENGE_EVIDENCE_MAX_BYTES,
};
use super::finding_verify::{strict_finding_ingress, AcceptedFinding};
use crate::cli_entrypoint_support::parse_cli;
use base64::Engine as _;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core_types::receipt::decision::{Decision, ToolCallAction};
use chio_core_types::receipt::kinds::TrustLevel;
use chio_core_types::{canonical_json_bytes, canonical_json_string};
use chio_finding::{
    compute_finding_id, derive_purchase_key, sign_finding, verify_signed_challenge, Finding,
    FindingAffectedDelivery, FindingBuyerSubmission, FindingChallengeAuthorization,
    FindingChallengeEvidence, FindingChallengeStanding, FindingCheckpointRef,
    FindingClaimedVerdict, FindingDescriptor, FindingDisputeBondClass, FindingDisputeFeeEvent,
    FindingDisputeFeeTerminal, FindingDisputeLockRef, FindingEvidenceClass,
    FindingGuaranteeClass, FindingOutcomeClass, FindingPredicate, FindingPurchaseRecord,
    FindingReceiptRef, FindingRecipeEnvironment, FindingRecipePhase, FindingRecipePhaseKind,
    FindingReplayObservation, FindingReplayRecipeInput, FindingReplayReproduction,
    FindingReplayTerminalResult, FindingResourceCaps, FindingVenueAuditAuthorization,
    SignedFindingPurchaseRecord, FINDING_PURCHASE_RECORD_SCHEMA_V1,
    FINDING_REPLAY_OBSERVATION_SCHEMA_V1, FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1,
    FINDING_SCHEMA_V1,
};
use chio_open_market::purchase_verification::{
    derive_payment_operation_id, derive_purchase_intent_id,
};
use wiremock::matchers::{body_string, header, method, path as path_matcher, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const GOLDEN_FINDING_RAW: &str = include_str!(
    "../../../../../../../fixtures/proof-room/finding/verified-fix-basic/finding.json"
);
const GOLDEN_FINDING_ID: &str = "dc721f80b183eb65945ba4754d9ba6b131d3c8309d8a7bff710f4160b9d7d817";
const GOLDEN_PROFILE_RAW: &str = include_str!(
    "../../../../../../../fixtures/proof-room/finding/verifier-profile-basic/profile.json"
);
const GOLDEN_GOVERNANCE_AUTHORITY: &str =
    "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
const GOLDEN_PRODUCTION_SIGNER: &str =
    "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a";

fn loopback_bind_available() -> bool {
    std::net::TcpListener::bind(("127.0.0.1", 0)).is_ok()
}

/// The published fixture is stored pretty-printed for review; the venue
/// only ever accepts the canonical serialization, so tests that stand in
/// for a published artifact canonicalize first.
fn canonical_golden_finding() -> String {
    String::from_utf8(chio_core_types::canonical_json_bytes_from_str(GOLDEN_FINDING_RAW).unwrap())
        .unwrap()
}

fn write_temp(dir: &tempfile::TempDir, name: &str, contents: &str) -> PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, contents).unwrap();
    path
}

fn oversized_support_file(dir: &tempfile::TempDir, name: &str) -> PathBuf {
    write_temp(
        dir,
        name,
        &"x".repeat(super::finding_verify::FINDING_VERIFY_SUPPORT_MAX_BYTES + 1),
    )
}

struct LiveBuyFixture {
    finding_id: String,
    raw_finding: String,
    request: FindingPurchaseRequest,
    result: FindingPurchaseResult,
}

fn live_buy_fixture() -> LiveBuyFixture {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let issuer = Keypair::from_seed(&[71; 32]);
    let buyer = Keypair::from_seed(&[72; 32]);
    let kernel = Keypair::from_seed(&[73; 32]);
    let purchase_authority = Keypair::from_seed(&[74; 32]);
    let payload = br#"{"fix":"verified through the public route"}"#;
    let media_type = "application/json";
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(payload);
    let reveal = serde_json::json!({
        "media_type": media_type,
        "payload_b64": payload_b64,
    });
    let payload_sha256 = chio_core_types::sha256_hex(
        &chio_core_types::canonical_json_bytes(&reveal).unwrap(),
    );
    let mut finding = Finding {
        schema: FINDING_SCHEMA_V1.to_owned(),
        finding_id: String::new(),
        descriptor: FindingDescriptor {
            topic: "repo:test/live-buy".to_owned(),
            context_sha256: "1".repeat(64),
            outcome_class: FindingOutcomeClass::VerifiedFix,
        },
        guarantee_class: FindingGuaranteeClass::Asserted,
        payload_sha256,
        payload_media_type: media_type.to_owned(),
        evidence_receipt_ids: Vec::new(),
        evidence_checkpoint_ref: "checkpoint:test/live-buy".to_owned(),
        evidence_cost: MonetaryAmount {
            units: 0,
            currency: "USD".to_owned(),
        },
        runtime_assurance_tier: None,
        evidence_class: FindingEvidenceClass::Asserted,
        replay_recipe_sha256: None,
        intent_commitment_receipt_id: None,
        bond_ref: "bond:test/live-buy".to_owned(),
        status_feed_ref: "status:test/live-buy".to_owned(),
        license_ref: None,
        price_hint_ref: None,
        issuer: issuer.public_key(),
        issued_at: now.saturating_sub(60),
        expires_at: now.saturating_add(3_600),
        signature: String::new(),
    };
    finding.finding_id = compute_finding_id(&finding).unwrap();
    let finding = sign_finding(finding, &issuer).unwrap();
    let raw_finding = String::from_utf8(chio_core_types::canonical_json_bytes(&finding).unwrap())
        .unwrap();
    let payer = buyer.public_key().to_hex();
    let request = FindingPurchaseRequest::new(
        finding.finding_id.clone(),
        400,
        "USD".to_owned(),
        Some(payer.clone()),
        Some(900),
    )
    .unwrap();
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: String::new(),
            timestamp: now,
            capability_id: "capability-live-buy".to_owned(),
            tool_server: "finding-server.test".to_owned(),
            tool_name: "read_finding".to_owned(),
            action: ToolCallAction::from_parameters(serde_json::json!({
                "finding_id": finding.finding_id,
            }))
            .unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: finding.payload_sha256.clone(),
            policy_hash: "2".repeat(64),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: kernel.public_key(),
            bbs_projection_version: None,
        },
        &kernel,
    )
    .unwrap();
    let accepted_bid_envelope_sha256 = "3".repeat(64);
    let reservation_id = "8".repeat(64);
    let purchase_intent_id = derive_purchase_intent_id(&reservation_id);
    let authoritative_payment_operation_id = derive_payment_operation_id(&reservation_id);
    let record = FindingPurchaseRecord {
        schema: FINDING_PURCHASE_RECORD_SCHEMA_V1.to_owned(),
        purchase_key: derive_purchase_key(
            &accepted_bid_envelope_sha256,
            &authoritative_payment_operation_id,
        ),
        purchase_intent_id: purchase_intent_id.clone(),
        authoritative_payment_operation_id: authoritative_payment_operation_id.clone(),
        buyer: buyer.public_key(),
        payer: buyer.public_key(),
        finding_id: finding.finding_id.clone(),
        listing_id: "listing-live-buy".to_owned(),
        accepted_bid_envelope_sha256,
        venue_admission_envelope_sha256: "6".repeat(64),
        accepted_price: MonetaryAmount {
            units: 300,
            currency: "USD".to_owned(),
        },
        realized_spend: MonetaryAmount {
            units: 300,
            currency: "USD".to_owned(),
        },
        seller_backing_envelope_sha256: "7".repeat(64),
        encumbrance_id: "encumbrance-live-buy".to_owned(),
        delivery_receipt_id: receipt.id.clone(),
        payment_reference: authoritative_payment_operation_id.clone(),
        payout_destination: "0x1111111111111111111111111111111111111111".to_owned(),
        recorded_at: now,
    };
    let signed_record = SignedFindingPurchaseRecord::sign(record, &purchase_authority).unwrap();
    let result = FindingPurchaseResult {
        schema: chio_control_plane::trust_control::finding_purchase_routes::FINDING_PURCHASE_RESULT_SCHEMA
            .to_owned(),
        request_id: request.request_id.clone(),
        finding_id: finding.finding_id.clone(),
        payer,
        payer_key: buyer.public_key(),
        reservation_id,
        purchase_intent_id,
        authoritative_payment_operation_id,
        verdict: FindingPurchaseVerdict::Allow,
        settlement: chio_control_plane::trust_control::finding_purchase_routes::FindingPurchaseSettlementTerminal::Captured,
        accepted_price: MonetaryAmount {
            units: 300,
            currency: "USD".to_owned(),
        },
        realized_spend: MonetaryAmount {
            units: 300,
            currency: "USD".to_owned(),
        },
        delivery_receipt: receipt,
        purchase_record: Some(signed_record),
        failed_delivery: None,
        output: Some(
            chio_control_plane::trust_control::finding_purchase_routes::FindingPurchasedOutput {
                media_type: media_type.to_owned(),
                payload_b64,
            },
        ),
    };
    result.validate_shape(&request).unwrap();
    LiveBuyFixture {
        finding_id: finding.finding_id,
        raw_finding,
        request,
        result,
    }
}

#[test]
fn publish_subcommand_parses() {
    let cli = parse_cli(["chio", "finding", "publish", "--file", "finding.json"]).unwrap();
    match cli.command {
        Commands::Finding {
            command: FindingCommands::Publish { file },
        } => assert_eq!(file, PathBuf::from("finding.json")),
        _ => panic!("expected finding publish command"),
    }
}

#[test]
fn search_subcommand_parses() {
    let cli = parse_cli([
        "chio",
        "finding",
        "search",
        "--topic-prefix",
        "repo:backbay/chio",
        "--context-sha256",
        &"a".repeat(64),
        "--after",
        GOLDEN_FINDING_ID,
        "--limit",
        "25",
    ])
    .unwrap();
    match cli.command {
        Commands::Finding {
            command:
                FindingCommands::Search {
                    topic_prefix,
                    context_sha256,
                    after,
                    limit,
                },
        } => {
            assert_eq!(topic_prefix, "repo:backbay/chio");
            assert_eq!(context_sha256.as_deref(), Some("a".repeat(64).as_str()));
            assert_eq!(after.as_deref(), Some(GOLDEN_FINDING_ID));
            assert_eq!(limit, Some(25));
        }
        _ => panic!("expected finding search command"),
    }
}

#[test]
fn verify_subcommand_parses() {
    let cli = parse_cli([
        "chio",
        "finding",
        "verify",
        "--file",
        "finding.json",
        "--trust-roots",
        "roots.json",
        "--evidence",
        "evidence.json",
        "--recipe",
        "recipe.bin",
    ])
    .unwrap();
    match cli.command {
        Commands::Finding {
            command:
                FindingCommands::Verify {
                    file,
                    id,
                    trust_roots,
                    evidence,
                    recipe,
                    integrity_only,
                },
        } => {
            assert_eq!(file, Some(PathBuf::from("finding.json")));
            assert_eq!(id, None);
            assert_eq!(trust_roots, Some(PathBuf::from("roots.json")));
            assert_eq!(evidence, Some(PathBuf::from("evidence.json")));
            assert_eq!(recipe, Some(PathBuf::from("recipe.bin")));
            assert!(!integrity_only);
        }
        _ => panic!("expected finding verify command"),
    }
}

#[test]
fn verify_integrity_only_parses() {
    let cli = parse_cli([
        "chio",
        "finding",
        "verify",
        "--id",
        GOLDEN_FINDING_ID,
        "--integrity-only",
    ])
    .unwrap();
    match cli.command {
        Commands::Finding {
            command:
                FindingCommands::Verify {
                    file,
                    id,
                    integrity_only,
                    ..
                },
        } => {
            assert_eq!(file, None);
            assert_eq!(id.as_deref(), Some(GOLDEN_FINDING_ID));
            assert!(integrity_only);
        }
        _ => panic!("expected finding verify command"),
    }
}

#[test]
fn verify_refuses_both_artifact_sources() {
    let parsed = parse_cli([
        "chio",
        "finding",
        "verify",
        "--file",
        "finding.json",
        "--id",
        GOLDEN_FINDING_ID,
    ]);
    assert!(parsed.is_err(), "--file and --id must not combine");
}

#[test]
fn verify_refuses_evidence_inputs_with_integrity_only() {
    let parsed = parse_cli([
        "chio",
        "finding",
        "verify",
        "--file",
        "finding.json",
        "--integrity-only",
        "--trust-roots",
        "roots.json",
    ]);
    assert!(
        parsed.is_err(),
        "integrity-only must not accept evidence inputs"
    );
}

#[test]
fn buy_subcommand_parses() {
    let cli = parse_cli([
        "chio",
        "finding",
        "buy",
        "--id",
        GOLDEN_FINDING_ID,
        "--max-price",
        "4200",
        "--currency",
        "USD",
        "--payer",
        "buyer-1",
        "--deadline-secs",
        "900",
    ])
    .unwrap();
    match cli.command {
        Commands::Finding {
            command:
                FindingCommands::Buy {
                    id,
                    max_price,
                    currency,
                    payer,
                    deadline_secs,
                },
        } => {
            assert_eq!(id, GOLDEN_FINDING_ID);
            assert_eq!(max_price, 4_200);
            assert_eq!(currency, "USD");
            assert_eq!(payer.as_deref(), Some("buyer-1"));
            assert_eq!(deadline_secs, Some(900));
        }
        _ => panic!("expected finding buy command"),
    }
}

#[test]
fn buy_requires_a_venue_url_and_service_token() {
    let missing_url = cmd_finding_buy(
        GOLDEN_FINDING_ID,
        4_200,
        "USD",
        None,
        None,
        false,
        None,
        Some("token"),
    )
    .unwrap_err()
    .to_string();
    assert!(missing_url.contains("--control-url"));

    let missing_token = cmd_finding_buy(
        GOLDEN_FINDING_ID,
        4_200,
        "USD",
        None,
        None,
        false,
        Some("http://127.0.0.1:1"),
        None,
    )
    .unwrap_err()
    .to_string();
    assert!(missing_token.contains("--control-token"));
}

#[test]
fn status_subcommand_parses() {
    let cli = parse_cli([
        "chio",
        "finding",
        "status",
        "--id",
        GOLDEN_FINDING_ID,
        "--feed",
        "status-feed/venue-01",
    ])
    .unwrap();
    match cli.command {
        Commands::Finding {
            command: FindingCommands::Status { id, feed },
        } => {
            assert_eq!(id, GOLDEN_FINDING_ID);
            assert_eq!(feed, "status-feed/venue-01");
        }
        _ => panic!("expected finding status command"),
    }
}

#[test]
fn status_requires_a_venue_url() {
    let error = cmd_finding_status(
        GOLDEN_FINDING_ID,
        "status-feed/venue-01",
        false,
        None,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("--control-url"), "unexpected error: {error}");
}

#[test]
fn finding_ids_must_be_lowercase_content_addresses() {
    assert!(require_finding_id(GOLDEN_FINDING_ID).is_ok());
    assert!(require_finding_id(&GOLDEN_FINDING_ID.to_uppercase()).is_err());
    assert!(require_finding_id("not-a-digest").is_err());
}

#[test]
fn publish_requires_a_venue_url() {
    let error = cmd_finding_publish(Path::new("finding.json"), false, None, Some("token"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("--control-url"), "unexpected error: {error}");
}

#[test]
fn publish_requires_a_service_token() {
    let error = cmd_finding_publish(
        Path::new("finding.json"),
        false,
        Some("http://127.0.0.1:1"),
        None,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("--control-token"),
        "unexpected error: {error}"
    );
}

#[test]
fn publish_refuses_an_artifact_above_the_body_bound() {
    let dir = tempfile::tempdir().unwrap();
    let oversized = "\u{20}".repeat(FINDING_PUBLISH_MAX_BODY_BYTES + 1);
    let path = write_temp(&dir, "oversized.json", &oversized);
    let error = cmd_finding_publish(&path, false, Some("http://127.0.0.1:1"), Some("token"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("publish bound"), "unexpected error: {error}");
}

#[test]
fn search_requires_a_venue_url() {
    let error = cmd_finding_search("repo:", None, None, None, false, None)
        .unwrap_err()
        .to_string();
    assert!(error.contains("--control-url"), "unexpected error: {error}");
}

#[test]
fn search_rejects_a_malformed_context_digest() {
    let error = cmd_finding_search(
        "repo:",
        Some("nothex"),
        None,
        None,
        false,
        Some("http://127.0.0.1:1"),
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("--context-sha256"),
        "unexpected error: {error}"
    );
}

#[test]
fn verify_requires_exactly_one_artifact_source() {
    let error = cmd_finding_verify(None, None, None, None, None, true, false, None)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("--file or --id"),
        "unexpected error: {error}"
    );
}

#[test]
fn verify_rejects_bytes_that_are_not_the_canonical_serialization() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_temp(&dir, "pretty.json", GOLDEN_FINDING_RAW);
    let error = cmd_finding_verify(Some(&path), None, None, None, None, true, false, None)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("canonical serialization"),
        "unexpected error: {error}"
    );
}

#[test]
fn verify_accepts_the_canonical_artifact_under_integrity_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_temp(&dir, "finding.json", &canonical_golden_finding());
    cmd_finding_verify(Some(&path), None, None, None, None, true, true, None).unwrap();
}

#[test]
fn finding_plain_text_escapes_terminal_controls() {
    let hostile = "safe\n\u{1b}[2Jforged\rline";
    let escaped = terminal_safe(hostile);
    assert_eq!(escaped, "safe\\n\\u{1b}[2Jforged\\rline");
    assert!(!escaped.chars().any(char::is_control));
}

#[test]
fn verify_caps_every_support_file_before_parsing() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = write_temp(&dir, "finding.json", &canonical_golden_finding());
    let roots = write_temp(&dir, "trust-roots.json", &golden_trust_roots());

    for (kind, trust_roots, evidence, recipe) in [
        (
            "trust-roots",
            Some(oversized_support_file(&dir, "oversized-roots.json")),
            None,
            None,
        ),
        (
            "evidence",
            Some(roots.clone()),
            Some(oversized_support_file(&dir, "oversized-evidence.json")),
            None,
        ),
        (
            "recipe",
            Some(roots.clone()),
            None,
            Some(oversized_support_file(&dir, "oversized-recipe.bin")),
        ),
    ] {
        let error = cmd_finding_verify(
            Some(&artifact),
            None,
            trust_roots.as_deref(),
            evidence.as_deref(),
            recipe.as_deref(),
            false,
            true,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains(kind) && error.contains("524288 byte"),
            "unexpected {kind} error: {error}"
        );
    }
}

#[test]
fn verify_refuses_to_call_integrity_alone_evidence_verification() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_temp(&dir, "finding.json", &canonical_golden_finding());
    let error = cmd_finding_verify(Some(&path), None, None, None, None, false, true, None)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("--trust-roots") && error.contains("--integrity-only"),
        "unexpected error: {error}"
    );
}

/// Trust roots pinning the published profile with no evidence resolved
/// behind them, which is exactly the shape that must report facets as
/// unavailable rather than collapsing them into a verified badge.
fn golden_trust_roots() -> String {
    let profile: serde_json::Value = serde_json::from_str(GOLDEN_PROFILE_RAW).unwrap();
    serde_json::to_string(&serde_json::json!({
        "governance_authority": GOLDEN_GOVERNANCE_AUTHORITY,
        "profile": profile,
        "admitted_kernel_keys": [GOLDEN_PRODUCTION_SIGNER],
        "collateral_authority": GOLDEN_PRODUCTION_SIGNER,
        "trusted_time": 1_784_880_000_u64,
    }))
    .unwrap()
}

#[test]
fn verify_names_every_required_facet_it_could_not_establish() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = write_temp(&dir, "finding.json", &canonical_golden_finding());
    let roots = write_temp(&dir, "trust-roots.json", &golden_trust_roots());

    let error = cmd_finding_verify(
        Some(&artifact),
        None,
        Some(&roots),
        None,
        None,
        false,
        false,
        None,
    )
    .unwrap_err()
    .to_string();

    assert!(
        error.contains("required facets not verified"),
        "unexpected error: {error}"
    );
    for facet in [
        "receipt_authenticity",
        "checkpoint_membership",
        "bond_backing",
    ] {
        assert!(error.contains(facet), "{facet} missing from: {error}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_sends_the_artifact_bytes_verbatim_under_the_service_token() {
    if !loopback_bind_available() {
        eprintln!("skipping finding publish transport test: loopback bind denied");
        return;
    }
    let artifact = canonical_golden_finding();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_matcher("/v1/findings/publish"))
        .and(header("authorization", "Bearer venue-token"))
        .and(body_string(artifact.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "findingId": GOLDEN_FINDING_ID,
            "artifactSha256": "a".repeat(64),
        })))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let path = write_temp(&dir, "finding.json", &artifact);
    let uri = server.uri();
    tokio::task::spawn_blocking(move || {
        cmd_finding_publish(&path, true, Some(&uri), Some("venue-token"))
    })
    .await
    .unwrap()
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn search_encodes_the_index_query_parameters() {
    if !loopback_bind_available() {
        eprintln!("skipping finding search transport test: loopback bind denied");
        return;
    }
    let context = "a".repeat(64);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_matcher("/v1/findings/search"))
        .and(query_param("topicPrefix", "repo:backbay/chio"))
        .and(query_param("contextSha256", context.as_str()))
        .and(query_param("cursor", GOLDEN_FINDING_ID))
        .and(query_param("limit", "25"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": [{
                "findingId": GOLDEN_FINDING_ID,
                "artifactSha256": "b".repeat(64),
                "topic": "repo:backbay/chio#test-failure",
                "contextSha256": context,
                "issuedAt": 1_784_880_000_u64,
                "expiresAt": 1_792_656_000_u64,
            }],
            "count": 1,
        })))
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    tokio::task::spawn_blocking(move || {
        cmd_finding_search(
            "repo:backbay/chio",
            Some(&context),
            Some(GOLDEN_FINDING_ID),
            Some(25),
            false,
            Some(&uri),
        )
    })
    .await
    .unwrap()
    .unwrap();
}

/// The venue is never dialed by the local gates, so the refusals that fire
/// before the fetch can name a URL that does not resolve.
const UNREACHABLE_VENUE: &str = "http://127.0.0.1:1";

const CHALLENGE_TERMS_DIGEST: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const CHALLENGE_BACKING_DIGEST: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";
const CHALLENGE_PROFILE_DIGEST: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";
const CHALLENGE_FAILED_DELIVERY_DIGEST: &str =
    "4444444444444444444444444444444444444444444444444444444444444444";
const CHALLENGE_PURCHASE_RECORD_DIGEST: &str =
    "5555555555555555555555555555555555555555555555555555555555555555";
const CHALLENGE_RECEIPT_DIGEST: &str =
    "6666666666666666666666666666666666666666666666666666666666666666";
const CHALLENGE_CHECKPOINT_DIGEST: &str =
    "7777777777777777777777777777777777777777777777777777777777777777";
const CHALLENGE_BUNDLE_DIGEST: &str =
    "8888888888888888888888888888888888888888888888888888888888888888";

fn challenger_keypair() -> Keypair {
    Keypair::from_seed(&[41_u8; 32])
}

fn write_challenger_key(dir: &tempfile::TempDir, keypair_seed: [u8; 32]) -> PathBuf {
    write_temp(dir, "challenger.seed", &hex::encode(keypair_seed))
}

fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
}

fn challenge_receipt_ref(receipt_id: &str) -> FindingReceiptRef {
    FindingReceiptRef {
        receipt_id: receipt_id.to_string(),
        receipt_sha256: CHALLENGE_RECEIPT_DIGEST.to_string(),
    }
}

fn challenge_checkpoint_ref() -> FindingCheckpointRef {
    FindingCheckpointRef {
        checkpoint_ref: "checkpoints/venue-wedge/9001".to_string(),
        checkpoint_sha256: CHALLENGE_CHECKPOINT_DIGEST.to_string(),
    }
}

fn challenge_affected_delivery() -> FindingAffectedDelivery {
    FindingAffectedDelivery {
        receipt_id: "delivery-receipt-42".to_string(),
        receipt_sha256: CHALLENGE_RECEIPT_DIGEST.to_string(),
        checkpoint_ref: "checkpoints/venue-wedge/9001".to_string(),
        checkpoint_sha256: CHALLENGE_CHECKPOINT_DIGEST.to_string(),
    }
}

fn buyer_authorization(
    challenger: &Keypair,
    standing: FindingChallengeStanding,
) -> FindingChallengeAuthorization {
    FindingChallengeAuthorization::BuyerSubmission(Box::new(FindingBuyerSubmission {
        challenger: challenger.public_key(),
        dispute_fee_terminal: FindingDisputeFeeTerminal {
            fee_schedule_envelope_sha256: CHALLENGE_TERMS_DIGEST.to_string(),
            event: FindingDisputeFeeEvent::ChallengeFiling,
            payer: challenger.public_key(),
            amount: usd(2_500),
            beneficiary_pool_principal_id: "pool:challenge-administration".to_string(),
            rail_destination: "rail:venue-ledger:challenge-admin".to_string(),
        },
        dispute_lock_ref: FindingDisputeLockRef {
            lock_id: "dispute-lock-42".to_string(),
            class: FindingDisputeBondClass::Dispute,
            fee_schedule_envelope_sha256: CHALLENGE_TERMS_DIGEST.to_string(),
            amount: usd(10_000),
            expiry: 1_760_000_000,
        },
        standing,
    }))
}

fn venue_audit_authorization() -> FindingChallengeAuthorization {
    FindingChallengeAuthorization::VenueAudit(FindingVenueAuditAuthorization {
        audit_epoch_envelope_sha256: CHALLENGE_TERMS_DIGEST.to_string(),
        selection_digest: CHALLENGE_BACKING_DIGEST.to_string(),
        authorization_digest: CHALLENGE_PROFILE_DIGEST.to_string(),
    })
}

fn digest_mismatch_evidence() -> FindingChallengeEvidence {
    FindingChallengeEvidence::DigestMismatch {
        failed_delivery_envelope_sha256: CHALLENGE_FAILED_DELIVERY_DIGEST.to_string(),
        deny_receipt_ref: challenge_receipt_ref("deny-receipt-42"),
        deny_checkpoint_ref: challenge_checkpoint_ref(),
    }
}

fn evidence_invalid_evidence() -> FindingChallengeEvidence {
    FindingChallengeEvidence::EvidenceInvalid {
        challenged_evidence_receipt_refs: vec![challenge_receipt_ref("evidence-receipt-1")],
        challenged_checkpoint_ref: challenge_checkpoint_ref(),
        purchase_record_envelope_sha256: CHALLENGE_PURCHASE_RECORD_DIGEST.to_string(),
    }
}

fn replay_recipe() -> FindingReplayRecipeInput {
    FindingReplayRecipeInput {
        schema: FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1.to_string(),
        decision_rule_ref: "decision/replay-v1".to_string(),
        verifier_profile_envelope_sha256: CHALLENGE_PROFILE_DIGEST.to_string(),
        context_sha256: CHALLENGE_RECEIPT_DIGEST.to_string(),
        payload_sha256: CHALLENGE_CHECKPOINT_DIGEST.to_string(),
        runner_server: "finding-server".to_string(),
        runner_tool: "finding.replay".to_string(),
        runner_manifest_sha256: CHALLENGE_TERMS_DIGEST.to_string(),
        phases: vec![
            FindingRecipePhase {
                phase: FindingRecipePhaseKind::Baseline,
                input_bundle_sha256: CHALLENGE_BUNDLE_DIGEST.to_string(),
                payload_application: "not_applied".to_string(),
            },
            FindingRecipePhase {
                phase: FindingRecipePhaseKind::Candidate,
                input_bundle_sha256: CHALLENGE_BACKING_DIGEST.to_string(),
                payload_application: "apply_patch_v1".to_string(),
            },
        ],
        parameters_sha256: CHALLENGE_TERMS_DIGEST.to_string(),
        environment: FindingRecipeEnvironment {
            runtime_image_sha256: CHALLENGE_TERMS_DIGEST.to_string(),
            platform: "linux/amd64".to_string(),
            network_policy: "deny_all".to_string(),
            clock_policy: "fixed:1700000000".to_string(),
            randomness_policy: "seed:42".to_string(),
            locale: "C".to_string(),
            timezone: "UTC".to_string(),
        },
        resource_bounds: FindingResourceCaps {
            max_recipe_bytes: 262_144,
            max_evidence_receipts: 64,
            max_runtime_secs: 900,
            max_memory_bytes: 2_147_483_648,
        },
        predicate: FindingPredicate::BaselineFailsCandidatePassesV1,
        pre_run_template_sha256: CHALLENGE_TERMS_DIGEST.to_string(),
        claimed_verdict: FindingClaimedVerdict::PredicateHolds,
    }
}

fn replay_observation(
    recipe_digest: &str,
    phase: FindingRecipePhaseKind,
) -> FindingReplayObservation {
    FindingReplayObservation {
        schema: FINDING_REPLAY_OBSERVATION_SCHEMA_V1.to_string(),
        recipe_digest: recipe_digest.to_string(),
        verifier_profile_digest: CHALLENGE_PROFILE_DIGEST.to_string(),
        phase_id: phase,
        runner_manifest_digest: CHALLENGE_TERMS_DIGEST.to_string(),
        resolved_input_bundle_digest: match phase {
            FindingRecipePhaseKind::Baseline => CHALLENGE_BUNDLE_DIGEST.to_string(),
            FindingRecipePhaseKind::Candidate => CHALLENGE_BACKING_DIGEST.to_string(),
        },
        environment_digest: CHALLENGE_CHECKPOINT_DIGEST.to_string(),
        terminal_result: FindingReplayTerminalResult::Completed,
        exit_code: match phase {
            FindingRecipePhaseKind::Baseline => 1,
            FindingRecipePhaseKind::Candidate => 0,
        },
        report_digest: match phase {
            FindingRecipePhaseKind::Baseline => CHALLENGE_RECEIPT_DIGEST.to_string(),
            FindingRecipePhaseKind::Candidate => CHALLENGE_BACKING_DIGEST.to_string(),
        },
        replay_run_id: "replay-run-42".to_string(),
    }
}

fn replay_contradiction_evidence() -> FindingChallengeEvidence {
    let recipe = replay_recipe();
    let recipe_digest = recipe.canonical_sha256().unwrap();
    let reproduction = vec![
        FindingReplayReproduction {
            receipt_ref: challenge_receipt_ref("replay-receipt-baseline"),
            checkpoint_ref: challenge_checkpoint_ref(),
            observation_bytes: canonical_json_string(&replay_observation(
                &recipe_digest,
                FindingRecipePhaseKind::Baseline,
            ))
            .unwrap(),
        },
        FindingReplayReproduction {
            receipt_ref: challenge_receipt_ref("replay-receipt-candidate"),
            checkpoint_ref: challenge_checkpoint_ref(),
            observation_bytes: canonical_json_string(&replay_observation(
                &recipe_digest,
                FindingRecipePhaseKind::Candidate,
            ))
            .unwrap(),
        },
    ];
    FindingChallengeEvidence::ReplayContradiction {
        reproduction,
        recipe_preimage: canonical_json_string(&recipe).unwrap(),
        purchase_record_envelope_sha256: CHALLENGE_PURCHASE_RECORD_DIGEST.to_string(),
    }
}

fn class_evidence(class: FindingChallengeClassArg) -> FindingChallengeEvidence {
    match class {
        FindingChallengeClassArg::DigestMismatch => digest_mismatch_evidence(),
        FindingChallengeClassArg::EvidenceInvalid => evidence_invalid_evidence(),
        FindingChallengeClassArg::ReplayContradiction => replay_contradiction_evidence(),
    }
}

/// A denied reveal creates no purchase record, so the digest-mismatch class
/// stands on the failed-delivery terminal while the other two stand on the
/// purchase record.
fn class_standing(class: FindingChallengeClassArg) -> FindingChallengeStanding {
    match class {
        FindingChallengeClassArg::DigestMismatch => FindingChallengeStanding::FailedDelivery {
            failed_delivery_id: CHALLENGE_RECEIPT_DIGEST.to_string(),
            failed_delivery_envelope_sha256: CHALLENGE_FAILED_DELIVERY_DIGEST.to_string(),
        },
        _ => FindingChallengeStanding::FinalizedPurchase {
            purchase_key: CHALLENGE_RECEIPT_DIGEST.to_string(),
            purchase_record_envelope_sha256: CHALLENGE_PURCHASE_RECORD_DIGEST.to_string(),
        },
    }
}

fn challenge_document(
    authorization: &FindingChallengeAuthorization,
    evidence: &FindingChallengeEvidence,
) -> String {
    canonical_json_string(&serde_json::json!({
        "affected_deliveries": [serde_json::to_value(challenge_affected_delivery()).unwrap()],
        "authorization": serde_json::to_value(authorization).unwrap(),
        "evidence": serde_json::to_value(evidence).unwrap(),
        "filed_at": 1_750_000_000_u64,
        "listing": {
            "backing_envelope_sha256": CHALLENGE_BACKING_DIGEST,
            "listing_id": "finding-listing-01",
            "profile_envelope_sha256": CHALLENGE_PROFILE_DIGEST,
            "terms_envelope_sha256": CHALLENGE_TERMS_DIGEST,
            "venue_admission_envelope_sha256": CHALLENGE_RECEIPT_DIGEST,
        },
    }))
    .unwrap()
}

fn buyer_document(challenger: &Keypair, class: FindingChallengeClassArg) -> String {
    challenge_document(
        &buyer_authorization(challenger, class_standing(class)),
        &class_evidence(class),
    )
}

fn venue_audit_document(class: FindingChallengeClassArg) -> String {
    challenge_document(&venue_audit_authorization(), &class_evidence(class))
}

/// The published fixture commits to `deterministic_replay` and `verified`,
/// the pairing every challenge class is compatible with.
fn accepted_golden_finding() -> AcceptedFinding {
    strict_finding_ingress(canonical_golden_finding(), "golden finding").unwrap()
}

/// An `asserted` finding has no evidence to invalidate and committed no
/// recipe to contradict, so only the digest-mismatch class can target it.
fn accepted_asserted_finding() -> AcceptedFinding {
    let issuer = Keypair::from_seed(&[10_u8; 32]);
    let mut finding = Finding {
        schema: FINDING_SCHEMA_V1.to_string(),
        finding_id: String::new(),
        descriptor: FindingDescriptor {
            topic: "repo:backbay/chio#test-failure".to_string(),
            context_sha256: "a".repeat(64),
            outcome_class: FindingOutcomeClass::VerifiedFix,
        },
        guarantee_class: FindingGuaranteeClass::Asserted,
        payload_sha256: "b".repeat(64),
        payload_media_type: "text/x-diff".to_string(),
        evidence_receipt_ids: Vec::new(),
        evidence_checkpoint_ref: "ckpt-1".to_string(),
        evidence_cost: usd(4_200),
        runtime_assurance_tier: None,
        evidence_class: FindingEvidenceClass::Asserted,
        replay_recipe_sha256: None,
        intent_commitment_receipt_id: None,
        bond_ref: "bond-req-1".to_string(),
        status_feed_ref: "finding-status/test".to_string(),
        license_ref: None,
        price_hint_ref: None,
        issuer: issuer.public_key(),
        issued_at: 1_784_880_000,
        expires_at: 1_792_656_000,
        signature: String::new(),
    };
    finding.finding_id = compute_finding_id(&finding).unwrap();
    let signed = sign_finding(finding, &issuer).unwrap();
    let raw = canonical_json_string(&signed).unwrap();
    strict_finding_ingress(raw, "asserted finding").unwrap()
}

fn load_document(dir: &tempfile::TempDir, contents: &str) -> PathBuf {
    write_temp(dir, "challenge-evidence.json", contents)
}

#[test]
fn challenge_subcommand_parses() {
    let cli = parse_cli([
        "chio",
        "finding",
        "challenge",
        "--finding",
        GOLDEN_FINDING_ID,
        "--class",
        "replay-contradiction",
        "--evidence",
        "evidence.json",
        "--challenger-key",
        "challenger.seed",
        "--dry-run",
    ])
    .unwrap();
    match cli.command {
        Commands::Finding {
            command:
                FindingCommands::Challenge {
                    finding,
                    class,
                    evidence,
                    challenger_key,
                    venue_audit,
                    dry_run,
                },
        } => {
            assert_eq!(finding, GOLDEN_FINDING_ID);
            assert_eq!(class, FindingChallengeClassArg::ReplayContradiction);
            assert_eq!(evidence, PathBuf::from("evidence.json"));
            assert_eq!(challenger_key, Some(PathBuf::from("challenger.seed")));
            assert!(!venue_audit);
            assert!(dry_run);
        }
        _ => panic!("expected finding challenge command"),
    }
}

#[test]
fn challenge_venue_audit_subcommand_parses() {
    let cli = parse_cli([
        "chio",
        "finding",
        "challenge",
        "--finding",
        GOLDEN_FINDING_ID,
        "--class",
        "digest-mismatch",
        "--evidence",
        "evidence.json",
        "--venue-audit",
    ])
    .unwrap();
    match cli.command {
        Commands::Finding {
            command:
                FindingCommands::Challenge {
                    class,
                    challenger_key,
                    venue_audit,
                    dry_run,
                    ..
                },
        } => {
            assert_eq!(class, FindingChallengeClassArg::DigestMismatch);
            assert_eq!(challenger_key, None);
            assert!(venue_audit);
            assert!(!dry_run);
        }
        _ => panic!("expected finding challenge command"),
    }
}

#[test]
fn challenge_evidence_invalid_class_parses() {
    let cli = parse_cli([
        "chio",
        "finding",
        "challenge",
        "--finding",
        GOLDEN_FINDING_ID,
        "--class",
        "evidence-invalid",
        "--evidence",
        "evidence.json",
        "--challenger-key",
        "challenger.seed",
    ])
    .unwrap();
    match cli.command {
        Commands::Finding {
            command: FindingCommands::Challenge { class, .. },
        } => assert_eq!(class, FindingChallengeClassArg::EvidenceInvalid),
        _ => panic!("expected finding challenge command"),
    }
}

#[test]
fn challenge_refuses_a_challenger_key_with_a_venue_audit() {
    let parsed = parse_cli([
        "chio",
        "finding",
        "challenge",
        "--finding",
        GOLDEN_FINDING_ID,
        "--class",
        "digest-mismatch",
        "--evidence",
        "evidence.json",
        "--venue-audit",
        "--challenger-key",
        "challenger.seed",
    ]);
    assert!(
        parsed.is_err(),
        "the audit branch carries no challenger, so it must not accept a challenger key"
    );
}

#[test]
fn challenge_rejects_an_unknown_class() {
    let parsed = parse_cli([
        "chio",
        "finding",
        "challenge",
        "--finding",
        GOLDEN_FINDING_ID,
        "--class",
        "wrong-media",
        "--evidence",
        "evidence.json",
    ]);
    assert!(parsed.is_err(), "the evidence class vocabulary is closed");
}

#[test]
fn challenge_requires_the_class_finding_and_evidence_flags() {
    for argv in [
        vec![
            "chio",
            "finding",
            "challenge",
            "--class",
            "digest-mismatch",
            "--evidence",
            "evidence.json",
        ],
        vec![
            "chio",
            "finding",
            "challenge",
            "--finding",
            GOLDEN_FINDING_ID,
            "--evidence",
            "evidence.json",
        ],
        vec![
            "chio",
            "finding",
            "challenge",
            "--finding",
            GOLDEN_FINDING_ID,
            "--class",
            "digest-mismatch",
        ],
    ] {
        assert!(
            parse_cli(argv.clone()).is_err(),
            "expected a parse failure for {argv:?}"
        );
    }
}

#[test]
fn challenge_requires_a_venue_url() {
    let dir = tempfile::tempdir().unwrap();
    let challenger = challenger_keypair();
    let document = load_document(
        &dir,
        &buyer_document(&challenger, FindingChallengeClassArg::DigestMismatch),
    );
    let key = write_challenger_key(&dir, [41_u8; 32]);
    let error = cmd_finding_challenge(
        GOLDEN_FINDING_ID,
        FindingChallengeClassArg::DigestMismatch,
        &document,
        Some(&key),
        false,
        true,
        false,
        None,
        None,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("--control-url"), "unexpected error: {error}");
}

#[test]
fn challenge_refuses_a_class_the_document_does_not_carry() {
    let dir = tempfile::tempdir().unwrap();
    let challenger = challenger_keypair();
    let key = write_challenger_key(&dir, [41_u8; 32]);
    for (carried, named) in [
        (
            FindingChallengeClassArg::DigestMismatch,
            FindingChallengeClassArg::EvidenceInvalid,
        ),
        (
            FindingChallengeClassArg::EvidenceInvalid,
            FindingChallengeClassArg::ReplayContradiction,
        ),
        (
            FindingChallengeClassArg::ReplayContradiction,
            FindingChallengeClassArg::DigestMismatch,
        ),
    ] {
        let document = load_document(&dir, &buyer_document(&challenger, carried));
        let error = cmd_finding_challenge(
            GOLDEN_FINDING_ID,
            named,
            &document,
            Some(&key),
            false,
            true,
            false,
            Some(UNREACHABLE_VENUE),
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("--class") && error.contains("does not match"),
            "unexpected error for {carried:?} named as {named:?}: {error}"
        );
    }
}

#[test]
fn challenge_refuses_a_venue_audit_over_a_buyer_submission() {
    let dir = tempfile::tempdir().unwrap();
    let challenger = challenger_keypair();
    let document = load_document(
        &dir,
        &buyer_document(&challenger, FindingChallengeClassArg::DigestMismatch),
    );
    let error = cmd_finding_challenge(
        GOLDEN_FINDING_ID,
        FindingChallengeClassArg::DigestMismatch,
        &document,
        None,
        true,
        true,
        false,
        Some(UNREACHABLE_VENUE),
        None,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("dispute fee") && error.contains("dispute bond"),
        "unexpected error: {error}"
    );
}

#[test]
fn challenge_refuses_an_audit_document_without_the_audit_flag() {
    let dir = tempfile::tempdir().unwrap();
    let document = load_document(
        &dir,
        &venue_audit_document(FindingChallengeClassArg::DigestMismatch),
    );
    let key = write_challenger_key(&dir, [41_u8; 32]);
    let error = cmd_finding_challenge(
        GOLDEN_FINDING_ID,
        FindingChallengeClassArg::DigestMismatch,
        &document,
        Some(&key),
        false,
        true,
        false,
        Some(UNREACHABLE_VENUE),
        None,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("--venue-audit"), "unexpected error: {error}");
}

#[test]
fn challenge_refuses_a_buyer_submission_without_a_challenger_key() {
    let dir = tempfile::tempdir().unwrap();
    let challenger = challenger_keypair();
    let document = load_document(
        &dir,
        &buyer_document(&challenger, FindingChallengeClassArg::DigestMismatch),
    );
    let error = cmd_finding_challenge(
        GOLDEN_FINDING_ID,
        FindingChallengeClassArg::DigestMismatch,
        &document,
        None,
        false,
        true,
        false,
        Some(UNREACHABLE_VENUE),
        None,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("--challenger-key"),
        "unexpected error: {error}"
    );
}

#[test]
fn challenge_refuses_a_key_that_is_not_the_named_challenger() {
    let dir = tempfile::tempdir().unwrap();
    let challenger = challenger_keypair();
    let document = load_document(
        &dir,
        &buyer_document(&challenger, FindingChallengeClassArg::DigestMismatch),
    );
    let other_key = write_challenger_key(&dir, [42_u8; 32]);
    let parsed = load_challenge_evidence_document(&document).unwrap();
    let error = prepare_challenge(&accepted_golden_finding(), parsed, Some(&other_key))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("names") && error.contains(&challenger.public_key().to_hex()),
        "unexpected error: {error}"
    );
}

#[test]
fn challenge_refuses_a_malformed_evidence_document() {
    let dir = tempfile::tempdir().unwrap();
    let broken = load_document(&dir, "{ not json");
    let error = load_challenge_evidence_document(&broken)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("strict canonical I-JSON"),
        "unexpected error: {error}"
    );

    let wrong_shape = write_temp(
        &dir,
        "wrong-shape.json",
        &canonical_json_string(&serde_json::json!({ "filed_at": 1_750_000_000_u64 })).unwrap(),
    );
    let error = load_challenge_evidence_document(&wrong_shape)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("not a challenge evidence document"),
        "unexpected error: {error}"
    );
}

#[test]
fn challenge_refuses_a_non_canonical_evidence_document() {
    let dir = tempfile::tempdir().unwrap();
    let challenger = challenger_keypair();
    let canonical = buyer_document(&challenger, FindingChallengeClassArg::DigestMismatch);
    let value: serde_json::Value = serde_json::from_str(&canonical).unwrap();
    let pretty = load_document(&dir, &serde_json::to_string_pretty(&value).unwrap());
    let error = load_challenge_evidence_document(&pretty)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("canonical serialization"),
        "unexpected error: {error}"
    );
}

#[test]
fn challenge_refuses_an_evidence_document_above_the_ingest_bound() {
    let dir = tempfile::tempdir().unwrap();
    let oversized = "\u{20}".repeat(FINDING_CHALLENGE_EVIDENCE_MAX_BYTES + 1);
    let path = load_document(&dir, &oversized);
    let error = load_challenge_evidence_document(&path)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("challenge evidence bound"),
        "unexpected error: {error}"
    );
}

/// The assembled body is checked against the registered schema before its
/// own validator runs, so a field the schema constrains is refused by the
/// schema rather than by the later structural pass.
#[test]
fn challenge_refuses_a_body_the_registered_schema_rejects() {
    let dir = tempfile::tempdir().unwrap();
    let challenger = challenger_keypair();
    let key = write_challenger_key(&dir, [41_u8; 32]);
    let mut value: serde_json::Value = serde_json::from_str(&buyer_document(
        &challenger,
        FindingChallengeClassArg::DigestMismatch,
    ))
    .unwrap();
    value["listing"]["listing_id"] = serde_json::Value::String(String::new());
    let document = load_document(&dir, &canonical_json_string(&value).unwrap());

    let parsed = load_challenge_evidence_document(&document).unwrap();
    let error = prepare_challenge(&accepted_golden_finding(), parsed, Some(&key))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("rejected by the challenge schema"),
        "unexpected error: {error}"
    );
}

#[test]
fn challenge_accepts_every_class_against_a_compatible_finding() {
    let dir = tempfile::tempdir().unwrap();
    let challenger = challenger_keypair();
    let key = write_challenger_key(&dir, [41_u8; 32]);
    for class in [
        FindingChallengeClassArg::DigestMismatch,
        FindingChallengeClassArg::EvidenceInvalid,
        FindingChallengeClassArg::ReplayContradiction,
    ] {
        let document = load_document(&dir, &buyer_document(&challenger, class));
        let parsed = load_challenge_evidence_document(&document).unwrap();
        let prepared = prepare_challenge(&accepted_golden_finding(), parsed, Some(&key))
            .unwrap_or_else(|error| panic!("{class:?} rejected: {error}"));
        assert_eq!(prepared.challenge.evidence.kind(), class.kind());
        assert_eq!(prepared.challenge.finding_id, GOLDEN_FINDING_ID);
    }
}

#[test]
fn challenge_refuses_a_class_the_targeted_finding_forbids() {
    let dir = tempfile::tempdir().unwrap();
    let challenger = challenger_keypair();
    let key = write_challenger_key(&dir, [41_u8; 32]);
    let asserted = accepted_asserted_finding();

    for class in [
        FindingChallengeClassArg::EvidenceInvalid,
        FindingChallengeClassArg::ReplayContradiction,
    ] {
        let document = load_document(&dir, &buyer_document(&challenger, class));
        let parsed = load_challenge_evidence_document(&document).unwrap();
        let error = prepare_challenge(&asserted, parsed, Some(&key))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("cannot challenge finding"),
            "unexpected error for {class:?}: {error}"
        );
    }

    // The same asserted finding still admits the class whose standing is the
    // failed-delivery terminal rather than anything the finding claimed.
    let document = load_document(
        &dir,
        &buyer_document(&challenger, FindingChallengeClassArg::DigestMismatch),
    );
    let parsed = load_challenge_evidence_document(&document).unwrap();
    prepare_challenge(&asserted, parsed, Some(&key)).unwrap();
}

#[test]
fn challenge_signs_under_the_challenger_the_document_names() {
    let dir = tempfile::tempdir().unwrap();
    let challenger = challenger_keypair();
    let key = write_challenger_key(&dir, [41_u8; 32]);
    let document = load_document(
        &dir,
        &buyer_document(&challenger, FindingChallengeClassArg::EvidenceInvalid),
    );
    let parsed = load_challenge_evidence_document(&document).unwrap();
    let prepared = prepare_challenge(&accepted_golden_finding(), parsed, Some(&key)).unwrap();

    let signed = prepared
        .signed
        .as_ref()
        .expect("buyer submissions are signed");
    assert_eq!(signed.signer_key, challenger.public_key());
    // The pinned audit authority is irrelevant to a buyer submission, which
    // the artifact authorizes by the challenger its body names.
    verify_signed_challenge(signed, &Keypair::from_seed(&[9_u8; 32]).public_key()).unwrap();
}

#[test]
fn challenge_venue_audit_carries_no_signature() {
    let dir = tempfile::tempdir().unwrap();
    let document = load_document(
        &dir,
        &venue_audit_document(FindingChallengeClassArg::ReplayContradiction),
    );
    let parsed = load_challenge_evidence_document(&document).unwrap();
    let prepared = prepare_challenge(&accepted_golden_finding(), parsed, None).unwrap();
    assert!(
        prepared.signed.is_none(),
        "the audit branch is signed by the venue's pinned audit authority"
    );
}

#[test]
fn challenge_dry_run_digests_match_an_independent_computation() {
    let dir = tempfile::tempdir().unwrap();
    let challenger = challenger_keypair();
    let key = write_challenger_key(&dir, [41_u8; 32]);
    let document = load_document(
        &dir,
        &buyer_document(&challenger, FindingChallengeClassArg::DigestMismatch),
    );
    let parsed = load_challenge_evidence_document(&document).unwrap();
    let accepted = accepted_golden_finding();
    let prepared = prepare_challenge(&accepted, parsed, Some(&key)).unwrap();

    let canonical = canonical_json_string(&prepared.challenge).unwrap();
    assert_eq!(prepared.canonical_challenge, canonical);
    assert_eq!(
        prepared.challenge_sha256,
        sha256_hex(canonical.as_bytes()),
        "the reported digest must be taken over the emitted bytes"
    );

    let mut without_id = prepared.challenge.clone();
    without_id.challenge_id = String::new();
    assert_eq!(
        prepared.challenge.challenge_id,
        sha256_hex(&canonical_json_bytes(&without_id).unwrap()),
        "the challenge id is the content address of the body with the id cleared"
    );

    assert_eq!(
        prepared.challenge.finding_artifact_sha256,
        sha256_hex(canonical_golden_finding().as_bytes()),
        "the challenge binds the exact artifact bytes the venue served"
    );
    assert_eq!(prepared.challenge.finding_id, accepted.finding.finding_id);
}

#[tokio::test(flavor = "multi_thread")]
async fn challenge_dry_run_emits_the_canonical_challenge_without_transmitting() {
    if !loopback_bind_available() {
        eprintln!("skipping finding challenge dry-run transport test: loopback bind denied");
        return;
    }
    let server = challenge_venue().await;
    let dir = tempfile::tempdir().unwrap();
    let challenger = challenger_keypair();
    let key = write_challenger_key(&dir, [41_u8; 32]);
    let document = load_document(
        &dir,
        &buyer_document(&challenger, FindingChallengeClassArg::DigestMismatch),
    );

    let uri = server.uri();
    tokio::task::spawn_blocking(move || {
        cmd_finding_challenge(
            GOLDEN_FINDING_ID,
            FindingChallengeClassArg::DigestMismatch,
            &document,
            Some(&key),
            false,
            true,
            true,
            Some(&uri),
            None,
        )
    })
    .await
    .unwrap()
    .unwrap();
}

#[test]
fn live_challenge_requires_service_authorization_before_contacting_the_venue() {
    let dir = tempfile::tempdir().unwrap();
    let challenger = challenger_keypair();
    let key = write_challenger_key(&dir, [41_u8; 32]);
    let document = load_document(
        &dir,
        &buyer_document(&challenger, FindingChallengeClassArg::DigestMismatch),
    );
    let error = cmd_finding_challenge(
        GOLDEN_FINDING_ID,
        FindingChallengeClassArg::DigestMismatch,
        &document,
        Some(&key),
        false,
        false,
        false,
        Some(UNREACHABLE_VENUE),
        None,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("--control-token"), "unexpected error: {error}");
}

#[test]
fn live_venue_audit_is_reserved_for_the_pinned_scheduler() {
    let dir = tempfile::tempdir().unwrap();
    let document = load_document(
        &dir,
        &venue_audit_document(FindingChallengeClassArg::DigestMismatch),
    );
    let error = cmd_finding_challenge(
        GOLDEN_FINDING_ID,
        FindingChallengeClassArg::DigestMismatch,
        &document,
        None,
        true,
        false,
        false,
        Some(UNREACHABLE_VENUE),
        Some("service-secret"),
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("venue audit scheduler") && error.contains("--dry-run"),
        "unexpected error: {error}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn challenge_without_dry_run_posts_the_exact_canonical_envelope() {
    if !loopback_bind_available() {
        eprintln!("skipping finding challenge submission test: loopback bind denied");
        return;
    }
    let server = challenge_venue().await;
    let dir = tempfile::tempdir().unwrap();
    let challenger = challenger_keypair();
    let key = write_challenger_key(&dir, [41_u8; 32]);
    let document = load_document(
        &dir,
        &buyer_document(&challenger, FindingChallengeClassArg::DigestMismatch),
    );
    let expected = prepare_challenge(
        &accepted_golden_finding(),
        load_challenge_evidence_document(&document).unwrap(),
        Some(&key),
    )
    .unwrap();
    let canonical_envelope = canonical_json_string(
        expected
            .signed
            .as_ref()
            .expect("buyer challenge carries a signed envelope"),
    )
    .unwrap();
    let expected_lock_id = match &expected.challenge.authorization {
        FindingChallengeAuthorization::BuyerSubmission(submission) => {
            submission.dispute_lock_ref.lock_id.clone()
        }
        FindingChallengeAuthorization::VenueAudit(_) => {
            panic!("buyer fixture unexpectedly produced a venue-audit challenge")
        }
    };
    Mock::given(method("POST"))
        .and(path_matcher(format!(
            "/v1/findings/{GOLDEN_FINDING_ID}/challenges"
        )))
        .and(header("authorization", "Bearer service-secret"))
        .and(header("content-type", "application/json"))
        .and(body_string(canonical_envelope))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "challengeId": expected.challenge.challenge_id,
                    "authorizationBranch": "buyer_submission",
                    "write": "inserted",
                    "disputeFeeIntentKey": "fee-intent-01",
                    "disputeBondLockId": expected_lock_id
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    tokio::task::spawn_blocking(move || {
        cmd_finding_challenge(
            GOLDEN_FINDING_ID,
            FindingChallengeClassArg::DigestMismatch,
            &document,
            Some(&key),
            false,
            false,
            false,
            Some(&uri),
            Some("service-secret"),
        )
    })
    .await
    .unwrap()
    .unwrap();
}

async fn challenge_venue() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_matcher(format!("/v1/findings/{GOLDEN_FINDING_ID}")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(canonical_golden_finding()),
        )
        .expect(1)
        .mount(&server)
        .await;
    server
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_by_id_runs_the_strict_ingress_over_the_served_bytes() {
    if !loopback_bind_available() {
        eprintln!("skipping finding verify transport test: loopback bind denied");
        return;
    }
    let artifact = canonical_golden_finding();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_matcher(format!("/v1/findings/{GOLDEN_FINDING_ID}")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(artifact),
        )
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    tokio::task::spawn_blocking(move || {
        cmd_finding_verify(
            None,
            Some(GOLDEN_FINDING_ID),
            None,
            None,
            None,
            true,
            true,
            Some(&uri),
        )
    })
    .await
    .unwrap()
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_by_id_rejects_a_different_valid_artifact() {
    if !loopback_bind_available() {
        eprintln!("skipping finding verify transport test: loopback bind denied");
        return;
    }
    let requested_id = "a".repeat(64);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_matcher(format!("/v1/findings/{requested_id}")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(canonical_golden_finding()),
        )
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    let error = tokio::task::spawn_blocking(move || {
        cmd_finding_verify(
            None,
            Some(&requested_id),
            None,
            None,
            None,
            true,
            true,
            Some(&uri),
        )
    })
    .await
    .unwrap()
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("venue returned finding") && error.contains("requested id"),
        "unexpected error: {error}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn buy_drives_the_authenticated_live_purchase_roundtrip() {
    if !loopback_bind_available() {
        eprintln!("skipping finding buy transport test: loopback bind denied");
        return;
    }
    let fixture = live_buy_fixture();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_matcher(format!(
            "/v1/findings/{}",
            fixture.finding_id
        )))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(fixture.raw_finding.clone()),
        )
        .expect(1)
        .mount(&server)
        .await;
    let request_body = String::from_utf8(
        chio_core_types::canonical_json_bytes(&fixture.request).unwrap(),
    )
    .unwrap();
    let response_body = String::from_utf8(
        chio_core_types::canonical_json_bytes(&fixture.result).unwrap(),
    )
    .unwrap();
    Mock::given(method("POST"))
        .and(path_matcher(format!(
            "/v1/findings/{}/purchase",
            fixture.finding_id
        )))
        .and(header("authorization", "Bearer venue-token"))
        .and(header("content-type", "application/json"))
        .and(body_string(request_body))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(response_body),
        )
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    let finding_id = fixture.finding_id;
    let payer = fixture.result.payer;
    tokio::task::spawn_blocking(move || {
        cmd_finding_buy(
            &finding_id,
            400,
            "USD",
            Some(&payer),
            Some(900),
            true,
            Some(&uri),
            Some("venue-token"),
        )
    })
    .await
    .unwrap()
    .unwrap();
}
