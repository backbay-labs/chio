//! Emergency kill-switch HTTP surface.
//!
//! This module is intentionally substrate-agnostic -- `chio-http-core`
//! does not embed an HTTP server. It exposes:
//!
//! - Route constants used by every substrate adapter
//!   (`chio-tower`, `chio-api-protect`, hosted sidecars).
//! - Request/response DTOs that serialize into the wire shapes
//!   documented in `STRUCTURAL-SECURITY-FIXES.md` section 5.4.
//! - Pure handler functions that take parsed inputs and return a
//!   structured response. Each substrate adapter calls the handler
//!   from its own framework route, preserving framework-native
//!   streaming, tracing, and error-mapping behavior.
//!
//! Authentication: the handlers require an `X-Admin-Token` header
//! whose value matches the string configured on [`EmergencyAdmin`].
//! No new middleware layer is introduced. Adapters that already have
//! their own auth middleware can either pass the caller's bearer
//! token through as the admin token (when configured that way) or
//! short-circuit the `expected_admin_token` check.

use std::sync::Arc;

use chio_kernel::{ChioKernel, KernelError};
use serde::{Deserialize, Serialize};

use crate::routes::{
    EMERGENCY_ADMIN_TOKEN_HEADER, EMERGENCY_RESUME_PATH, EMERGENCY_STATUS_PATH, EMERGENCY_STOP_PATH,
};

/// Canonical JSON body for `POST /emergency-stop`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyStopRequest {
    /// Operator-supplied rationale for the kill switch. Recorded on
    /// the kernel and surfaced via `/emergency-status` so runbooks
    /// can correlate the halt with an incident.
    pub reason: String,
}

/// Wire response for `POST /emergency-stop`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyStopResponse {
    /// Always `true` for a successful stop.
    pub stopped: bool,
}

/// Wire response for `POST /emergency-resume`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyResumeResponse {
    /// Always `false` for a successful resume.
    pub stopped: bool,
}

/// Wire response for `GET /emergency-status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyStatusResponse {
    /// Whether the kill switch is currently engaged.
    pub stopped: bool,

    /// RFC 3339 / ISO 8601 timestamp of the stop. `None` when the
    /// kernel has never been stopped or is currently resumed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,

    /// Operator-supplied reason for the current stop. `None` when
    /// the kernel is running normally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Errors returned by the emergency handlers. Each variant maps
/// cleanly onto an HTTP status code via [`EmergencyHandlerError::status`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmergencyHandlerError {
    /// `X-Admin-Token` header missing or does not match the configured value.
    /// Returns HTTP 401 and a minimal JSON error body.
    Unauthorized,

    /// Request body could not be parsed as the expected JSON shape. The
    /// operator supplied bad input; returns HTTP 400.
    BadRequest(String),

    /// Kernel-side failure while toggling the kill switch. Fail-closed:
    /// the handler has already engaged the stop (see
    /// [`handle_emergency_stop`]); this error just reports what went wrong
    /// after the flag flipped. Returns HTTP 500.
    Kernel(String),
}

impl EmergencyHandlerError {
    /// HTTP status code for this error.
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            Self::Unauthorized => 401,
            Self::BadRequest(_) => 400,
            Self::Kernel(_) => 500,
        }
    }

    /// Stable error code string (snake_case) for machine-readable error
    /// payloads. Adapters serialize `{ "error": "<code>", "message": ... }`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::BadRequest(_) => "bad_request",
            Self::Kernel(_) => "internal_error",
        }
    }

    /// Human-readable message.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Unauthorized => "missing or invalid X-Admin-Token header".to_string(),
            Self::BadRequest(reason) | Self::Kernel(reason) => reason.clone(),
        }
    }

    /// Wire body for this error response.
    #[must_use]
    pub fn body(&self) -> serde_json::Value {
        serde_json::json!({
            "error": self.code(),
            "message": self.message(),
        })
    }
}

impl From<KernelError> for EmergencyHandlerError {
    fn from(error: KernelError) -> Self {
        Self::Kernel(error.to_string())
    }
}

/// Admin handle bound to a kernel and a configured admin token.
///
/// The handle is cheap to clone (`Arc<ChioKernel>` + short strings) and
/// safe to share across threads. It holds the only reference to the
/// kernel needed by the emergency endpoints, so substrate adapters can
/// construct one `EmergencyAdmin` at startup and pass it to every
/// route registration.
#[derive(Clone)]
pub struct EmergencyAdmin {
    kernel: Arc<ChioKernel>,
    expected_admin_token: String,
}

impl std::fmt::Debug for EmergencyAdmin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmergencyAdmin")
            .field("admin_token_len", &self.expected_admin_token.len())
            .field(
                "admin_token_usable",
                &admin_token_usable(&self.expected_admin_token),
            )
            .finish_non_exhaustive()
    }
}

impl EmergencyAdmin {
    /// Create a new admin handle. `expected_admin_token` must match the
    /// value of the `X-Admin-Token` header on every incoming admin call.
    /// The token is compared with `==`; adapters that need constant-time
    /// comparison can wrap the check in their own middleware before
    /// delegating to the handler.
    #[must_use]
    pub fn new(kernel: Arc<ChioKernel>, expected_admin_token: String) -> Self {
        Self {
            kernel,
            expected_admin_token,
        }
    }

    /// Shared kernel reference, primarily for tests and for adapters
    /// that want to re-use the same `Arc<ChioKernel>` for other routes.
    #[must_use]
    pub fn kernel(&self) -> &Arc<ChioKernel> {
        &self.kernel
    }

    fn authorize(&self, admin_token: Option<&str>) -> Result<(), EmergencyHandlerError> {
        if !admin_token_usable(&self.expected_admin_token) {
            return Err(EmergencyHandlerError::Unauthorized);
        }
        match admin_token {
            Some(token) if token == self.expected_admin_token => Ok(()),
            _ => Err(EmergencyHandlerError::Unauthorized),
        }
    }
}

fn admin_token_usable(token: &str) -> bool {
    !token.trim().is_empty() && !token.chars().any(char::is_control)
}

/// Handler for `POST /emergency-stop`.
///
/// Fail-closed: if the token check passes, the kernel's `emergency_stop`
/// is invoked immediately. If it returns an error, the flag has still
/// been set (the kernel flips its atomic before any fallible step) so
/// the system is left in the safer stopped state even when the caller
/// sees a 500.
pub fn handle_emergency_stop(
    admin: &EmergencyAdmin,
    admin_token: Option<&str>,
    body: &[u8],
) -> Result<EmergencyStopResponse, EmergencyHandlerError> {
    admin.authorize(admin_token)?;

    let parsed: EmergencyStopRequest = serde_json::from_slice(body).map_err(|error| {
        EmergencyHandlerError::BadRequest(format!("invalid emergency-stop request body: {error}"))
    })?;

    admin.kernel.emergency_stop(&parsed.reason)?;

    Ok(EmergencyStopResponse { stopped: true })
}

/// Handler for `POST /emergency-resume`.
///
/// Body is ignored (any bytes, including empty, are accepted) so
/// adapters can keep wiring identical to `POST /emergency-stop`.
pub fn handle_emergency_resume(
    admin: &EmergencyAdmin,
    admin_token: Option<&str>,
    _body: &[u8],
) -> Result<EmergencyResumeResponse, EmergencyHandlerError> {
    admin.authorize(admin_token)?;
    admin.kernel.emergency_resume()?;
    Ok(EmergencyResumeResponse { stopped: false })
}

/// Handler for `GET /emergency-status`.
pub fn handle_emergency_status(
    admin: &EmergencyAdmin,
    admin_token: Option<&str>,
) -> Result<EmergencyStatusResponse, EmergencyHandlerError> {
    admin.authorize(admin_token)?;

    let stopped = admin.kernel.is_emergency_stopped();
    let since = admin
        .kernel
        .emergency_stopped_since()
        .and_then(|unix_secs| {
            // i64 is what chrono expects; secs fit comfortably for any
            // realistic operator timestamp.
            let secs = i64::try_from(unix_secs).ok()?;
            chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0).map(|dt| dt.to_rfc3339())
        });
    let reason = admin.kernel.emergency_stop_reason();

    Ok(EmergencyStatusResponse {
        stopped,
        since,
        reason,
    })
}

// Path constants re-exported at module scope so adapters can write
// `emergency::EMERGENCY_STOP_PATH`.
pub use crate::routes::EMERGENCY_ADMIN_TOKEN_HEADER as ADMIN_TOKEN_HEADER;
pub use crate::routes::EMERGENCY_RESUME_PATH as RESUME_PATH;
pub use crate::routes::EMERGENCY_STATUS_PATH as STATUS_PATH;
pub use crate::routes::EMERGENCY_STOP_PATH as STOP_PATH;

// Internal compile-time sanity: the module-level re-exports above must
// remain in sync with `routes::`. A `const _` guard catches drift if
// someone renames either set.
const _: &str = EMERGENCY_STOP_PATH;
const _: &str = EMERGENCY_RESUME_PATH;
const _: &str = EMERGENCY_STATUS_PATH;
const _: &str = EMERGENCY_ADMIN_TOKEN_HEADER;
