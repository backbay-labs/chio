use super::*;

use crate::cli_entrypoint_support::parse_cli;
use base64::Engine as _;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core_types::receipt::decision::{Decision, ToolCallAction};
use chio_core_types::receipt::kinds::TrustLevel;
use chio_finding::{
    compute_finding_id, derive_purchase_key, sign_finding, Finding, FindingDescriptor,
    FindingEvidenceClass, FindingGuaranteeClass, FindingOutcomeClass, FindingPurchaseRecord,
    SignedFindingPurchaseRecord, FINDING_PURCHASE_RECORD_SCHEMA_V1, FINDING_SCHEMA_V1,
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
        payout_destination: "rail:test:seller".to_owned(),
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
