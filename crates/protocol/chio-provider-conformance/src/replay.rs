//! Replay OpenAI provider captures through the native adapter surface.

#![cfg_attr(
    not(any(
        feature = "fixtures-openai",
        feature = "fixtures-anthropic",
        feature = "fixtures-bedrock",
        feature = "fixtures-gemini",
        feature = "fixtures-mistral",
        feature = "fixtures-groq",
        feature = "fixtures-ollama",
        feature = "fixtures-cohere"
    )),
    allow(dead_code, unused_imports)
)]

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

#[cfg(any(
    feature = "fixtures-openai",
    feature = "fixtures-anthropic",
    feature = "fixtures-bedrock"
))]
use std::collections::BTreeSet;

#[cfg(any(
    feature = "fixtures-openai",
    feature = "fixtures-anthropic",
    feature = "fixtures-bedrock",
    feature = "fixtures-gemini",
    feature = "fixtures-mistral",
    feature = "fixtures-groq",
    feature = "fixtures-ollama",
    feature = "fixtures-cohere"
))]
use chio_tool_call_fabric::ToolResult;
use chio_tool_call_fabric::{
    DenyReason, Principal, ProviderError, ProviderId, ProviderRequest, ReceiptId, Redaction,
    ToolInvocation, VerdictResult,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[cfg(any(
    feature = "fixtures-openai",
    feature = "fixtures-anthropic",
    feature = "fixtures-bedrock",
    feature = "fixtures-gemini",
    feature = "fixtures-mistral",
    feature = "fixtures-groq",
    feature = "fixtures-ollama",
    feature = "fixtures-cohere"
))]
use crate::assertions::canonical_json_bytes_for;
use crate::assertions::{assert_canonical_json_eq, assert_verdict_eq, AssertionError};
use crate::capture::{CaptureDirection, CaptureRecord, CapturedVerdictKind, CAPTURE_SCHEMA};

#[path = "replay/additional_providers.rs"]
mod additional_providers;
#[path = "replay/anthropic.rs"]
mod anthropic;
#[path = "replay/bedrock.rs"]
mod bedrock;
#[path = "replay/fixture.rs"]
mod fixture;
#[path = "replay/openai.rs"]
mod openai;
#[path = "replay/payload.rs"]
mod payload;
#[path = "replay/assert.rs"]
mod replay_assert;
#[path = "replay/stream.rs"]
mod stream;

pub use additional_providers::{
    replay_cohere_fixture, replay_gemini_fixture, replay_groq_fixture, replay_mistral_fixture,
    replay_ollama_fixture,
};
pub use anthropic::replay_anthropic_fixture;
pub use bedrock::replay_bedrock_fixture;
pub use fixture::{
    anthropic_fixture_dir, anthropic_fixture_paths, bedrock_fixture_dir, bedrock_fixture_paths,
    cohere_fixture_dir, cohere_fixture_paths, gemini_fixture_dir, gemini_fixture_paths,
    groq_fixture_dir, groq_fixture_paths, load_fixture, mistral_fixture_dir, mistral_fixture_paths,
    ollama_fixture_dir, ollama_fixture_paths, openai_fixture_dir, openai_fixture_paths,
    CapturedVerdict, ComparableInvocation, ComparableProvenance, ProviderCaptureFixture,
    ReplayError, ReplayMode, ReplayOutcome,
};
pub use openai::replay_openai_fixture;

#[cfg(feature = "fixtures-anthropic")]
use anthropic::anthropic_tool_result_payload;
#[cfg(feature = "fixtures-bedrock")]
use bedrock::{bedrock_tool_result_payload, BedrockFixturePrincipal};
use fixture::invalid_fixture;
#[cfg(test)]
use fixture::{fixture_paths_for_dir, required_field};
#[cfg(feature = "fixtures-anthropic")]
use payload::anthropic_response_has_no_tool_uses;
#[cfg(feature = "fixtures-anthropic")]
use payload::anthropic_workspace_id_from_payload;
#[cfg(feature = "fixtures-bedrock")]
use payload::bedrock_principal_from_payload;
#[cfg(feature = "fixtures-bedrock")]
use payload::bedrock_response_has_no_tool_uses;
#[cfg(any(
    feature = "fixtures-gemini",
    feature = "fixtures-mistral",
    feature = "fixtures-groq",
    feature = "fixtures-ollama",
    feature = "fixtures-cohere"
))]
use payload::header_from_payload;
#[cfg(feature = "fixtures-openai")]
use payload::org_id_from_payload;
#[cfg(feature = "fixtures-openai")]
use payload::response_has_no_tool_calls;
#[cfg(feature = "fixtures-anthropic")]
use replay_assert::assert_anthropic_lowered_responses;
#[cfg(feature = "fixtures-bedrock")]
use replay_assert::assert_bedrock_lowered_responses;
#[cfg(feature = "fixtures-openai")]
use replay_assert::assert_openai_lowered_responses;
use replay_assert::{
    assert_replayed_invocations, assert_replayed_verdicts, captured_deny_reason,
    captured_redactions,
};
#[cfg(feature = "fixtures-bedrock")]
use stream::fixture_bedrock_stream_bytes;
#[cfg(feature = "fixtures-ollama")]
use stream::fixture_ollama_ndjson_bytes;
#[cfg(feature = "fixtures-openai")]
use stream::stream_event_item;
#[cfg(any(
    feature = "fixtures-openai",
    feature = "fixtures-anthropic",
    feature = "fixtures-cohere"
))]
use stream::{event_name, fixture_sse_bytes};

#[cfg(test)]
#[path = "replay/tests.rs"]
mod tests;
