//! Chio provider conformance replay harness.
//!
//! The crate loads deterministic provider traffic captures, reconstructs
//! native adapter inputs, and asserts byte-stable canonical JSON outputs
//! against the captured conformance corpus.

#![forbid(unsafe_code)]

pub mod assertions;
pub mod capture;
pub mod replay;

pub use assertions::{
    assert_canonical_json_eq, assert_verdict_eq, canonical_json_bytes_for, AssertionError,
};
pub use capture::{
    fixture_root, provider_fixture_dir, provider_fixture_path, CaptureDirection, CaptureRecord,
    CapturedVerdictKind, CAPTURE_SCHEMA,
};
pub use replay::{
    anthropic_fixture_dir, anthropic_fixture_paths, bedrock_fixture_dir, bedrock_fixture_paths,
    load_fixture, openai_fixture_dir, openai_fixture_paths, replay_anthropic_fixture,
    replay_bedrock_fixture, replay_openai_fixture, CapturedVerdict, ComparableInvocation,
    ProviderCaptureFixture, ReplayError, ReplayMode, ReplayOutcome,
};
