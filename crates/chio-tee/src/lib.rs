//! Chio TEE shadow runner: captures kernel decisions and emits signed,
//! redacted replay frames.
//!
//! The runner is a sidecar that observes kernel-bound traffic through the
//! [`tap::TrafficTap`] hook surface and, per evaluation, redacts the
//! request/response payloads (fail-closed), persists the redacted blobs
//! encrypted under the tenant key, and appends a tenant-signed
//! `chio-tee-frame.v1` record to an append-only NDJSON capture file. That
//! capture stream is consumed downstream by `chio replay --bless`.
//!
//! The orchestrator lives in [`runner::ShadowRunner`]; the capture-frame
//! construction and NDJSON writer live in [`capture`].

#![forbid(unsafe_code)]

pub mod buffer;
pub mod capture;
pub mod config;
pub mod frame;
pub mod mode;
pub mod persist;
pub mod redact;
pub mod runner;
pub mod spool;
pub mod tap;

pub use buffer::RawPayloadBuffer;
pub use capture::{new_event_id, rfc3339_millis, sign_frame, CaptureError, CaptureWriter};
pub use config::{
    load_env_mode, load_tenant_manifest_mode, load_tenant_manifest_mode_from_str, load_toml_mode,
    parse_env_mode, parse_toml_mode_from_str, resolve_toml_path, ConfigError, DEFAULT_TOML_PATH,
    ENV_CONFIG_PATH, ENV_MODE,
};
pub use frame::{
    canonicalize as canonicalize_frame, parse as parse_frame, signing_payload, validate_signed,
    verify_tenant_sig, Frame, FrameError, FrameInputs, Otel, Provenance, Upstream, UpstreamSystem,
    Verdict, FRAME_VERSION, SCHEMA_ID, SCHEMA_VERSION,
};
pub use mode::{
    Direction, Mode, ModeInputs, MoteState, ParseModeError, ResolvedMode, Source, TransitionError,
};
pub use persist::{PersistedBlob, PersistenceError, TeeBlobPersistence};
pub use redact::{
    DefaultRedactor, RedactClass, RedactError, RedactPass, RedactedPayload, RedactionManifest,
    RedactionMatch, Redactor, RedactorError, PARANOID_ZERO_MATCH_THRESHOLD,
};
pub use runner::{
    Observation, RunSummary, RunnerConfig, RunnerError, ShadowRunner, DEFAULT_TEE_ID,
};
pub use spool::{SpoolError, SpooledTraffic, TeeBlobSpool};
pub use tap::{TapError, TapResult, TrafficTap};

/// Version reported by `chio-tee --version`.
pub const TEE_VERSION: &str = env!("CARGO_PKG_VERSION");
