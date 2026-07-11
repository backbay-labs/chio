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
//! - **`POST /v1/evaluate/advisory`** signs an advisory `ChioReceipt` only.
//!   It checks local revocation and parameter-hash consistency; it does not
//!   validate capability scope or run the kernel guard pipeline. Successful
//!   responses set the `chio-trust-level: advisory` header and include
//!   `authorization: false` in the response body. Treat this route as
//!   observability, not as an allow/deny gate.
//! - **`POST /v1/capabilities/attenuate`** is a fail-closed control boundary.
//!   It returns HTTP 403 because attenuation requires the parent subject signer.
//!   Use the kernel delegation primitive or SDK-local signer helpers so that
//!   private key remains outside the sidecar.
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
pub use proxy::{ProtectConfig, ProtectProxy, DEFAULT_UPSTREAM_REQUEST_TIMEOUT};
pub use spec_discovery::{discover_spec, load_spec_from_file};
