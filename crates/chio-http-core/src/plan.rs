//! Plan-level evaluation HTTP surface.
//!
//! Mirrors the structure of [`crate::emergency`]: `chio-http-core` does
//! not embed an HTTP server, so this module exposes a substrate-agnostic
//! handler that accepts raw request bytes, delegates to the kernel, and
//! returns a structured response. Each substrate adapter wires the
//! handler into its own framework-native route handler.
//!
//! Unlike the emergency endpoints, `/evaluate-plan` does NOT require an
//! admin token: any caller in possession of a valid capability token
//! can ask the kernel whether a prospective plan would be allowed. The
//! pre-flight check is explicitly designed to be consulted often by
//! agent planners during plan generation.
//!
//! The handler returns `200 OK` regardless of the aggregate plan
//! verdict: denials are conveyed inside the JSON body, not as HTTP
//! status codes. Only malformed request bodies produce a 400.

use std::sync::Arc;

use chio_core_types::{PlanEvaluationRequest, PlanEvaluationResponse};
use chio_kernel::ChioKernel;
use serde::{Deserialize, Serialize};

/// Error surfaced by [`handle_evaluate_plan`] when the request body is
/// malformed. Aggregate plan denials are NOT represented here; those
/// are carried inside the successful response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanHandlerError {
    /// Request body could not be parsed as a `PlanEvaluationRequest`.
    BadRequest(String),
}

impl PlanHandlerError {
    /// HTTP status code for this error. Always 400 in v1.
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
        }
    }

    /// Stable machine-readable error code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
        }
    }

    /// Human-readable message.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::BadRequest(reason) => reason.clone(),
        }
    }

    /// Wire body for this error response, matching the emergency-
    /// handler error shape so adapters can reuse their serialisation.
    #[must_use]
    pub fn body(&self) -> serde_json::Value {
        serde_json::json!({
            "error": self.code(),
            "message": self.message(),
        })
    }
}

/// Handler for `POST /evaluate-plan`.
///
/// Takes the raw request body as bytes, parses it into a
/// [`PlanEvaluationRequest`], and returns the kernel's
/// [`PlanEvaluationResponse`]. Denials are always `Ok`: the HTTP layer
/// only errors out on malformed bodies.
pub fn handle_evaluate_plan(
    kernel: &Arc<ChioKernel>,
    body: &[u8],
) -> Result<PlanEvaluationResponse, PlanHandlerError> {
    let parsed: PlanEvaluationRequest = serde_json::from_slice(body).map_err(|error| {
        PlanHandlerError::BadRequest(format!("invalid evaluate-plan request body: {error}"))
    })?;

    Ok(kernel.evaluate_plan_blocking(&parsed))
}
