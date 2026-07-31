use super::*;

use crate::cli_entrypoint_support::parse_cli;
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
fn buy_reports_the_missing_reveal_coordinator() {
    let error = cmd_finding_buy().unwrap_err().to_string();
    assert!(
        error.contains("reveal coordinator"),
        "unexpected buy error: {error}"
    );
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
