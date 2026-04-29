use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use chio_core::sha256_hex;
use chio_kernel::{
    KernelError, NestedFlowBridge, ToolCallChunk, ToolCallStream, ToolServerConnection,
    ToolServerStreamResult,
};
use chio_manifest::{validate_manifest, LatencyHint, ToolDefinition, ToolManifest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use url::form_urlencoded::{byte_serialize, Serializer as UrlFormSerializer};
use url::Url;

const DEFAULT_AGENT_CARD_PATH: &str = "/.well-known/agent-card.json";
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const A2A_VERSION_HEADER: &str = "A2A-Version";
const A2A_PROTOCOL_MAJOR: &str = "1.";
const A2A_PROTOCOL_VERSION_HEADER_VALUE: &str = "1.0";
const SSE_CONTENT_TYPE: &str = "text/event-stream";
const OAUTH_CACHE_SKEW_SECS: u64 = 30;
const TASK_REGISTRY_VERSION: &str = "chio.a2a-task-registry.v1";

include!("config.rs");
include!("partner_policy.rs");
include!("invoke.rs");
include!("protocol.rs");
include!("task_registry.rs");
include!("mapping.rs");
include!("discovery.rs");
include!("auth.rs");
include!("transport.rs");
include!("tests.rs");
#[cfg(feature = "fuzz")]
include!("fuzz.rs");
