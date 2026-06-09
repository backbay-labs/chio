#![cfg(feature = "fixtures-anthropic")]

use std::fs;

use chio_provider_conformance::{
    anthropic_fixture_paths, load_fixture, replay_anthropic_fixture, ReplayMode,
};

#[test]
fn replays_all_anthropic_fixtures_with_canonical_byte_assertions() {
    let paths = match anthropic_fixture_paths() {
        Ok(paths) => paths,
        Err(error) => panic!("load Anthropic fixture paths: {error}"),
    };
    assert_eq!(
        paths.len(),
        12,
        "Anthropic corpus must contain exactly 12 NDJSON fixtures"
    );

    let mut total_invocations = 0;
    let mut total_verdicts = 0;
    let mut total_lowered = 0;
    let mut batch = 0;
    let mut stream = 0;
    let mut no_tool_call = 0;
    let mut server_tool_sessions = 0;
    let mut kernel_denials = 0;

    for path in paths {
        if let Err(error) = load_fixture(&path) {
            panic!("parse {}: {error}", path.display());
        }

        let fixture_text = match fs::read_to_string(&path) {
            Ok(fixture_text) => fixture_text,
            Err(error) => panic!("read {}: {error}", path.display()),
        };
        assert!(
            fixture_text.contains("\"anthropic-version\":\"2023-06-01\""),
            "{} did not pin anthropic-version",
            path.display()
        );
        if fixture_text.contains("\"anthropic-beta\":\"computer-use-2025-01-24\"") {
            server_tool_sessions += 1;
        }
        if fixture_text.contains("\"verdict\":\"deny\"") {
            kernel_denials += 1;
        }

        let outcome = match replay_anthropic_fixture(&path) {
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
    assert_eq!(total_lowered, 8);
    assert_eq!(batch, 7);
    assert_eq!(stream, 4);
    assert_eq!(no_tool_call, 1);
    assert!(
        server_tool_sessions >= 2,
        "Anthropic corpus must include at least two server-tool sessions"
    );
    assert_eq!(
        kernel_denials, 1,
        "Anthropic corpus must include exactly one kernel denial fixture"
    );
}
