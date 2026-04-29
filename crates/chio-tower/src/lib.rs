//! Tower middleware for Chio capability validation and receipt signing.
//!
//! Provides a `tower::Layer` that wraps any HTTP service with Chio evaluation:
//! extracting caller identity, evaluating requests against the Chio kernel,
//! and attaching signed receipts to responses.
//!
//! Works with replayable Tower request body types, including Axum's
//! `axum::body::Body` and bytes-backed HTTP bodies used in generic Tower/HTTP2
//! tests. Real `tonic::body::Body` replay remains a follow-on concern and is
//! not claimed as fully covered by the current middleware contract.
//!
//! # Example with Tower service
//!
//! ```rust
//! use chio_tower::ChioLayer;
//! use chio_core_types::crypto::Keypair;
//! use tower::Layer;
//!
//! let keypair = Keypair::generate();
//! let layer = ChioLayer::new(keypair, "policy-hash-abc".to_string());
//!
//! // Wrap any tower Service with Chio evaluation.
//! let inner = tower::service_fn(|_req: http::Request<http_body_util::Full<bytes::Bytes>>| async {
//!     Ok::<_, Box<dyn std::error::Error + Send + Sync>>(http::Response::new(()))
//! });
//! let _service = layer.layer(inner);
//! ```

mod error;
mod evaluator;
mod host_call;
mod identity;
mod kernel_service;
mod layer;
mod service;

pub use error::ChioTowerError;
pub use evaluator::{ChioEvaluator, EvaluationResult};
pub use host_call::{
    normalize_host_call_metric_label, HOST_CALL_FETCH_BLOB, HOST_CALL_GET_CONFIG,
    HOST_CALL_GET_TIME_UNIX_SECS, HOST_CALL_LOG, HOST_CALL_METRIC_LABEL_VALUES,
};
pub use identity::{extract_identity, IdentityExtractor};
pub use kernel_service::{
    build_layered, KernelRequest, KernelResponse, KernelService, KernelServiceError,
    KernelTraceLayer, KernelTraceService, TenantConcurrencyLimitLayer,
    TenantConcurrencyLimitService, TenantId,
};
pub use layer::ChioLayer;
pub use service::ChioService;
