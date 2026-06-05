//! Zero-code reverse proxy that protects HTTP APIs with Chio signed receipts.
//!
//! `chio api protect` reads an OpenAPI spec, generates a default Chio policy,
//! and proxies all requests to the upstream API. Every request produces a
//! signed `HttpReceipt`. Side-effect routes (POST/PUT/PATCH/DELETE) require
//! a capability token; safe routes (GET/HEAD/OPTIONS) pass with audit receipts.
//!
//! ## Sidecar control routes and production boundaries
//!
//! The embedded sidecar exposes SDK helper routes under `/v1/*` and
//! `/chio/*`. Not every route performs kernel-mediated authorization:
//!
//! - **`POST /v1/evaluate`** (tool-call alias) signs an advisory
//!   `ChioReceipt` only. It checks local revocation and parameter-hash
//!   consistency; it does not validate capability scope or run the kernel
//!   guard pipeline. Successful responses set the `chio-trust-level: advisory`
//!   header and receipt `trust_level: advisory`. Treat this as observability,
//!   not as an allow/deny gate.
//! - **`POST /v1/capabilities/attenuate`** returns HTTP 501 with
//!   `chio-route-status: not-implemented`. Attenuation is not wired over HTTP.
//!
//! See [`README.md`](../README.md) for the full list of routes that are
//! not production authorization paths.

#![forbid(unsafe_code)]

mod error;
mod evaluator;
mod proxy;
mod spec_discovery;

pub use error::ProtectError;
pub use evaluator::{EvaluationResult, RequestEvaluator, RouteEntry};
pub use proxy::{ProtectConfig, ProtectProxy};
pub use spec_discovery::{discover_spec, load_spec_from_file};
