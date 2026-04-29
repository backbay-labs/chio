//! Chio TEE shadow runner: replays kernel decisions inside a TEE for attestation.
//!
//! Phase 1 of M10. T1 lands the workspace member skeleton; T2-T9 fill in
//! the shadow runner + replay frame format.

#![forbid(unsafe_code)]

pub mod buffer;
pub mod config;
pub mod frame;
pub mod mode;
pub mod persist;
pub mod redact;
pub mod spool;
pub mod tap;

pub use buffer::RawPayloadBuffer;
pub use config::{
    load_env_mode, load_tenant_manifest_mode, load_tenant_manifest_mode_from_str, load_toml_mode,
    parse_env_mode, parse_toml_mode_from_str, resolve_toml_path, ConfigError, DEFAULT_TOML_PATH,
    ENV_CONFIG_PATH, ENV_MODE,
};
pub use frame::{
    canonicalize as canonicalize_frame, parse as parse_frame, Frame, FrameError, Otel, Provenance,
    Upstream, UpstreamSystem, Verdict, FRAME_VERSION, SCHEMA_ID, SCHEMA_VERSION,
};
pub use mode::{
    Direction, Mode, ModeInputs, MoteState, ParseModeError, ResolvedMode, Source, TransitionError,
};
pub use persist::{PersistedBlob, PersistenceError, TeeBlobPersistence};
pub use redact::{
    DefaultRedactor, RedactClass, RedactError, RedactPass, RedactedPayload, RedactionManifest,
    RedactionMatch, Redactor, RedactorError, PARANOID_ZERO_MATCH_THRESHOLD,
};
pub use spool::{SpoolError, SpooledTraffic, TeeBlobSpool};
pub use tap::{TapError, TapResult, TrafficTap};

pub const TEE_VERSION: &str = "0.1.0-skeleton";
