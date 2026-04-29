//! Canonical-JSON round-trip fixtures for the lift / lower contract.
//!
//! Each fixture under `fixtures/lift_lower/<provider>/<name>.json` is a single
//! canonical-JSON encoding (RFC 8785 / JCS) of a [`ToolInvocation`]. The test
//! walks every provider directory, parses each fixture, re-encodes it through
//! `canonical_json_bytes`, and asserts byte-for-byte equality. An adapter's
//! `lift` must produce a `ToolInvocation` whose canonical encoding equals the
//! wire fixture; its `lower` consumer must accept the same canonical bytes.
//!
//! Re-record protocol: set `CHIO_BLESS_LIFT_LOWER=1` and re-run this test to
//! regenerate the fixture files from the in-source builders below. The default
//! mode never writes; CI keeps the fixtures pinned by failing on byte drift.
//!
//! House rules:
//! - No em dashes (U+2014) anywhere in code, comments, or rendered output.
//! - `unwrap_used` / `expect_used` are denied workspace-wide; we allow them
//!   inside this test file because fixture authoring is a controlled
//!   in-source builder pipeline, not production code.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use chio_core::canonical::canonical_json_bytes;
use chio_tool_call_fabric::{Principal, ProvenanceStamp, ProviderId, ToolInvocation};

/// Bless-mode environment variable. When set to `1`, the test regenerates the
/// nine fixture files from the in-source builders below instead of asserting
/// equality. Default (unset) mode is read-only and CI never blesses.
const BLESS_ENV: &str = "CHIO_BLESS_LIFT_LOWER";

/// Root of the on-disk fixture corpus, relative to the crate manifest dir.
fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/lift_lower")
}

/// Build a `SystemTime` from whole milliseconds since UNIX_EPOCH so the
/// canonical-JSON byte form is deterministic across architectures.
fn ms(epoch_ms: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_millis(epoch_ms)
}

/// One fixture record: provider directory, file basename (without `.json`),
/// and the in-memory `ToolInvocation` whose canonical encoding the file must
/// match byte-for-byte.
struct Fixture {
    provider_dir: &'static str,
    name: &'static str,
    invocation: ToolInvocation,
}

impl Fixture {
    fn path(&self) -> PathBuf {
        fixtures_root()
            .join(self.provider_dir)
            .join(format!("{}.json", self.name))
    }
}

// -- Builders --------------------------------------------------------------
//
// Each builder constructs one `ToolInvocation` whose shape mirrors what the
// corresponding native provider adapter will surface in M07 Phase 2/3/4. The
// `arguments` field carries the inner tool-call argument blob as
// canonical-JSON bytes (RFC 8785), matching the contract set by
// `ProviderAdapter::lift` in `crates/chio-tool-call-fabric/src/lib.rs`.

fn arguments_bytes(value: &serde_json::Value) -> Vec<u8> {
    canonical_json_bytes(value).expect("arguments canonicalise")
}

fn openai_single_tool() -> ToolInvocation {
    ToolInvocation {
        provider: ProviderId::OpenAi,
        tool_name: "get_weather".to_string(),
        arguments: arguments_bytes(&serde_json::json!({
            "location": "San Francisco, CA",
            "unit": "celsius",
        })),
        provenance: ProvenanceStamp {
            provider: ProviderId::OpenAi,
            request_id: "resp_2026_04_25_single_tool".to_string(),
            api_version: "responses.2026-04-25".to_string(),
            principal: Principal::OpenAiOrg {
                org_id: "org_chio_demo".to_string(),
            },
            received_at: ms(1_745_452_800_000),
        },
    }
}

fn openai_multi_tool() -> ToolInvocation {
    ToolInvocation {
        provider: ProviderId::OpenAi,
        tool_name: "search_web".to_string(),
        arguments: arguments_bytes(&serde_json::json!({
            "queries": ["chio mediation", "openai responses api"],
            "max_results": 5,
        })),
        provenance: ProvenanceStamp {
            provider: ProviderId::OpenAi,
            request_id: "resp_2026_04_25_parallel_tool_calls".to_string(),
            api_version: "responses.2026-04-25".to_string(),
            principal: Principal::OpenAiOrg {
                org_id: "org_chio_demo".to_string(),
            },
            received_at: ms(1_745_452_801_000),
        },
    }
}

fn openai_streaming_init() -> ToolInvocation {
    ToolInvocation {
        provider: ProviderId::OpenAi,
        tool_name: "create_calendar_event".to_string(),
        arguments: arguments_bytes(&serde_json::json!({
            "title": "Chio sync",
            "start": "2026-04-28T15:00:00Z",
            "duration_minutes": 30,
        })),
        provenance: ProvenanceStamp {
            provider: ProviderId::OpenAi,
            request_id: "resp_2026_04_25_streaming_init".to_string(),
            api_version: "responses.2026-04-25".to_string(),
            principal: Principal::OpenAiOrg {
                org_id: "org_chio_demo".to_string(),
            },
            received_at: ms(1_745_452_802_000),
        },
    }
}

fn anthropic_single_tool_use() -> ToolInvocation {
    ToolInvocation {
        provider: ProviderId::Anthropic,
        tool_name: "get_stock_price".to_string(),
        arguments: arguments_bytes(&serde_json::json!({
            "ticker": "ANTH",
        })),
        provenance: ProvenanceStamp {
            provider: ProviderId::Anthropic,
            request_id: "msg_01abcdEFGHJK1234567890mn".to_string(),
            api_version: "anthropic.2023-06-01".to_string(),
            principal: Principal::AnthropicWorkspace {
                workspace_id: "wks_chio_demo".to_string(),
            },
            received_at: ms(1_745_452_803_000),
        },
    }
}

fn anthropic_parallel_tool_use() -> ToolInvocation {
    ToolInvocation {
        provider: ProviderId::Anthropic,
        tool_name: "translate_text".to_string(),
        arguments: arguments_bytes(&serde_json::json!({
            "source_lang": "en",
            "target_langs": ["es", "fr", "de"],
            "text": "Chio mediates tool calls across providers.",
        })),
        provenance: ProvenanceStamp {
            provider: ProviderId::Anthropic,
            request_id: "msg_02zxcvBNMLKJ0987654321qw".to_string(),
            api_version: "anthropic.2023-06-01".to_string(),
            principal: Principal::AnthropicWorkspace {
                workspace_id: "wks_chio_demo".to_string(),
            },
            received_at: ms(1_745_452_804_000),
        },
    }
}

fn anthropic_server_tool() -> ToolInvocation {
    // Server tool surface (computer_use family). Per M07 Phase 3 task 4, this
    // shape lifts an Anthropic `tool_use` block whose tool name resolves to
    // a server-side tool such as `text_editor`. The fixture pins the wire
    // shape ahead of the server-tools allowlist landing in Phase 3.
    ToolInvocation {
        provider: ProviderId::Anthropic,
        tool_name: "text_editor".to_string(),
        arguments: arguments_bytes(&serde_json::json!({
            "command": "create",
            "path": "/workspace/notes.md",
            "file_text": "# Chio fixture\n",
        })),
        provenance: ProvenanceStamp {
            provider: ProviderId::Anthropic,
            request_id: "msg_03poiuYTREWQasdfghjklm".to_string(),
            api_version: "anthropic.2023-06-01".to_string(),
            principal: Principal::AnthropicWorkspace {
                workspace_id: "wks_chio_demo".to_string(),
            },
            received_at: ms(1_745_452_805_000),
        },
    }
}

fn bedrock_single_tool_use() -> ToolInvocation {
    ToolInvocation {
        provider: ProviderId::Bedrock,
        tool_name: "lookup_customer".to_string(),
        arguments: arguments_bytes(&serde_json::json!({
            "customer_id": "cust_8675309",
        })),
        provenance: ProvenanceStamp {
            provider: ProviderId::Bedrock,
            request_id: "bdrk_req_us_east_1_single_tool_use".to_string(),
            api_version: "bedrock.converse.v1".to_string(),
            principal: Principal::BedrockIam {
                caller_arn: "arn:aws:iam::123456789012:role/ChioAgentRole".to_string(),
                account_id: "123456789012".to_string(),
                assumed_role_session_arn: None,
            },
            received_at: ms(1_745_452_806_000),
        },
    }
}

fn bedrock_parallel_tool_use() -> ToolInvocation {
    ToolInvocation {
        provider: ProviderId::Bedrock,
        tool_name: "fetch_account_balance".to_string(),
        arguments: arguments_bytes(&serde_json::json!({
            "account_ids": ["acct_001", "acct_002"],
            "include_pending": true,
        })),
        provenance: ProvenanceStamp {
            provider: ProviderId::Bedrock,
            request_id: "bdrk_req_us_east_1_parallel_tool_uses".to_string(),
            api_version: "bedrock.converse.v1".to_string(),
            principal: Principal::BedrockIam {
                caller_arn: "arn:aws:iam::123456789012:role/ChioAgentRole".to_string(),
                account_id: "123456789012".to_string(),
                assumed_role_session_arn: None,
            },
            received_at: ms(1_745_452_807_000),
        },
    }
}

fn bedrock_assumed_role() -> ToolInvocation {
    // Exercises the Bedrock-specific `assumed_role_session_arn` provenance
    // field (M07 Phase 4 task 4 IAM principal disambiguation). The fixture
    // pins the canonical ordering of the assumed-role principal so adapters
    // never collapse caller and session identities.
    ToolInvocation {
        provider: ProviderId::Bedrock,
        tool_name: "approve_payout".to_string(),
        arguments: arguments_bytes(&serde_json::json!({
            "payout_id": "po_42",
            "amount_cents": 12_500,
        })),
        provenance: ProvenanceStamp {
            provider: ProviderId::Bedrock,
            request_id: "bdrk_req_us_east_1_assumed_role_principal".to_string(),
            api_version: "bedrock.converse.v1".to_string(),
            principal: Principal::BedrockIam {
                caller_arn: "arn:aws:iam::123456789012:role/ChioAgentRole".to_string(),
                account_id: "123456789012".to_string(),
                assumed_role_session_arn: Some(
                    "arn:aws:sts::123456789012:assumed-role/ChioAgentRole/session-1".to_string(),
                ),
            },
            received_at: ms(1_745_452_808_000),
        },
    }
}

/// The full nine-fixture corpus (3 per provider).
fn corpus() -> Vec<Fixture> {
    vec![
        Fixture {
            provider_dir: "openai",
            name: "single_tool",
            invocation: openai_single_tool(),
        },
        Fixture {
            provider_dir: "openai",
            name: "multi_tool",
            invocation: openai_multi_tool(),
        },
        Fixture {
            provider_dir: "openai",
            name: "streaming_init",
            invocation: openai_streaming_init(),
        },
        Fixture {
            provider_dir: "anthropic",
            name: "single_tool_use",
            invocation: anthropic_single_tool_use(),
        },
        Fixture {
            provider_dir: "anthropic",
            name: "parallel_tool_use",
            invocation: anthropic_parallel_tool_use(),
        },
        Fixture {
            provider_dir: "anthropic",
            name: "server_tool",
            invocation: anthropic_server_tool(),
        },
        Fixture {
            provider_dir: "bedrock",
            name: "single_tool_use",
            invocation: bedrock_single_tool_use(),
        },
        Fixture {
            provider_dir: "bedrock",
            name: "parallel_tool_use",
            invocation: bedrock_parallel_tool_use(),
        },
        Fixture {
            provider_dir: "bedrock",
            name: "assumed_role",
            invocation: bedrock_assumed_role(),
        },
    ]
}

// -- Tests -----------------------------------------------------------------

/// Round-trip every on-disk fixture through canonical JSON.
///
/// For each of the 9 fixtures we:
///   1. Read the fixture file (the on-the-wire canonical bytes).
///   2. Parse those bytes into a `ToolInvocation`.
///   3. Re-encode the parsed value via `canonical_json_bytes`.
///   4. Assert byte-for-byte equality with the file contents.
///   5. Assert the parsed value equals the in-source builder, so a manual
///      file edit cannot drift the wire shape away from the Rust contract.
///
/// In bless mode (`CHIO_BLESS_LIFT_LOWER=1`) the test instead writes the
/// canonical bytes to disk so a maintainer can regenerate after a deliberate
/// shape change. CI never sets the variable.
#[test]
fn lift_lower_fixtures_round_trip_canonical_json() {
    let bless = std::env::var(BLESS_ENV).map(|v| v == "1").unwrap_or(false);
    let corpus = corpus();
    assert_eq!(
        corpus.len(),
        9,
        "lift_lower fixture corpus must contain exactly 9 entries (3 per provider); got {}",
        corpus.len(),
    );

    for fixture in &corpus {
        let path = fixture.path();
        let canonical =
            canonical_json_bytes(&fixture.invocation).expect("fixture invocation canonicalises");

        if bless {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create fixture parent dir");
            }
            fs::write(&path, &canonical).expect("write blessed fixture");
            continue;
        }

        let on_disk =
            fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {}", path.display(), e));
        assert_eq!(
            on_disk,
            canonical,
            "fixture {} drifted from canonical-JSON encoding of in-source builder; \
             re-run with {}=1 after a deliberate shape change",
            path.display(),
            BLESS_ENV,
        );

        let parsed: ToolInvocation = serde_json::from_slice(&on_disk).unwrap_or_else(|e| {
            panic!("parse fixture {} as ToolInvocation: {}", path.display(), e)
        });
        assert_eq!(
            parsed,
            fixture.invocation,
            "fixture {} parses to a value that diverges from the in-source builder",
            path.display(),
        );

        let relifted = canonical_json_bytes(&parsed).expect("re-canonicalises after parse");
        assert_eq!(
            relifted,
            on_disk,
            "fixture {} is not stable under canonical-JSON re-encoding",
            path.display(),
        );
    }
}

/// Sanity check on directory layout: the on-disk corpus carries exactly
/// three fixtures per provider, all `.json`, so a future stray file (e.g.,
/// a tenth fixture or a back-up) trips CI.
#[test]
fn lift_lower_fixture_directories_have_three_json_files_each() {
    for provider_dir in ["openai", "anthropic", "bedrock"] {
        let dir = fixtures_root().join(provider_dir);
        let mut json_files: Vec<String> = fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read fixture dir {}: {}", dir.display(), e))
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .and_then(|s| s.to_str())
                    .map(|ext| ext == "json")
                    .unwrap_or(false)
            })
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        json_files.sort();
        assert_eq!(
            json_files.len(),
            3,
            "{} should contain exactly 3 .json fixtures, got {:?}",
            dir.display(),
            json_files,
        );
    }
}
