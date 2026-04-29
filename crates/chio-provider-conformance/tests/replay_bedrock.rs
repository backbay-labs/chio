#![cfg(feature = "fixtures-bedrock")]

use std::fs;

use chio_provider_conformance::{
    bedrock_fixture_paths, load_fixture, replay_bedrock_fixture, ReplayMode,
};

#[test]
fn replays_all_bedrock_fixtures_with_canonical_byte_assertions() {
    let paths = match bedrock_fixture_paths() {
        Ok(paths) => paths,
        Err(error) => panic!("load Bedrock fixture paths: {error}"),
    };
    assert_eq!(
        paths.len(),
        12,
        "Bedrock corpus must contain exactly 12 NDJSON fixtures"
    );

    let mut total_invocations = 0;
    let mut total_verdicts = 0;
    let mut total_lowered = 0;
    let mut batch = 0;
    let mut stream = 0;
    let mut no_tool_call = 0;
    let mut assumed_role_sessions = 0;
    let mut direct_role_principals = 0;
    let mut kernel_denials = 0;
    let mut principal_unknown_denials = 0;

    for path in paths {
        if let Err(error) = load_fixture(&path) {
            panic!("parse {}: {error}", path.display());
        }

        let fixture_text = match fs::read_to_string(&path) {
            Ok(fixture_text) => fixture_text,
            Err(error) => panic!("read {}: {error}", path.display()),
        };
        assert!(
            fixture_text.contains("\"x-chio-bedrock-region\":\"us-east-1\""),
            "{} did not pin Bedrock region",
            path.display()
        );
        assert!(
            fixture_text.contains("arn:aws:"),
            "{} did not carry deterministic fake IAM provenance",
            path.display()
        );
        assert!(
            !fixture_text.contains("arn:aws:iam::000000000000"),
            "{} used the placeholder ARN instead of a documented fake principal",
            path.display()
        );
        if fixture_text.contains("\"assumed_role_session_arn\":\"arn:aws:sts::") {
            assumed_role_sessions += 1;
        }
        if fixture_text.contains("\"assumed_role_session_arn\":null") {
            direct_role_principals += 1;
        }
        if fixture_text.contains("\"verdict\":\"deny\"") {
            kernel_denials += 1;
        }
        if fixture_text.contains("\"kind\":\"principal_unknown\"") {
            principal_unknown_denials += 1;
        }

        let outcome = match replay_bedrock_fixture(&path) {
            Ok(outcome) => outcome,
            Err(error) => panic!("replay {}: {error}", path.display()),
        };

        total_invocations += outcome.invocations;
        total_verdicts += outcome.verdicts;
        total_lowered += outcome.lowered_responses;

        match outcome.mode {
            ReplayMode::Batch => batch += 1,
            ReplayMode::Stream => stream += 1,
            ReplayMode::NoToolCall => no_tool_call += 1,
        }
    }

    assert_eq!(total_invocations, 12);
    assert_eq!(total_verdicts, 12);
    assert_eq!(total_lowered, 6);
    assert_eq!(batch, 7);
    assert_eq!(stream, 4);
    assert_eq!(no_tool_call, 1);
    assert!(
        assumed_role_sessions >= 2,
        "Bedrock corpus must include assumed-role session provenance"
    );
    assert!(
        direct_role_principals >= 2,
        "Bedrock corpus must include direct IAM caller provenance"
    );
    assert_eq!(
        kernel_denials, 2,
        "Bedrock corpus must include the two planned deny fixtures"
    );
    assert_eq!(
        principal_unknown_denials, 1,
        "Bedrock corpus must include principal_unknown IAM denial"
    );
}
