//! Route path constants shared across every HTTP substrate adapter.
//!
//! `chio-http-core` does not ship an HTTP server; it is the protocol-
//! agnostic types crate that every substrate (`chio-tower`,
//! `chio-api-protect`, hosted sidecars) builds on top of. Centralizing
//! the route strings here keeps each adapter in sync with the spec in
//! `docs/protocols/STRUCTURAL-SECURITY-FIXES.md` section 5.4.
//!
//! # Adapter wiring
//!
//! Every adapter is expected to:
//!
//! 1. Construct a single [`crate::emergency::EmergencyAdmin`] at
//!    startup, bound to an `Arc<ChioKernel>` and the operator-configured
//!    admin token.
//! 2. Register three framework-native routes on the paths defined
//!    here, pulling the token out of the [`EMERGENCY_ADMIN_TOKEN_HEADER`]
//!    request header and delegating to the corresponding
//!    `handle_emergency_*` function in [`crate::emergency`].
//! 3. Map [`crate::emergency::EmergencyHandlerError`] status codes and
//!    bodies onto the framework's response type without re-interpreting
//!    the semantics. No adapter should add extra authentication on top
//!    of `X-Admin-Token`; the handler already fails closed.
//!
//! The helper [`emergency_route_registrations`] returns a compact
//! description of every registration an adapter must perform, so
//! adapters can iterate over the triple instead of copying constants
//! at each call site.

use crate::method::HttpMethod;

/// `POST /emergency-stop` -- engage the kernel kill switch.
pub const EMERGENCY_STOP_PATH: &str = "/emergency-stop";

/// `POST /emergency-resume` -- disengage the kill switch.
pub const EMERGENCY_RESUME_PATH: &str = "/emergency-resume";

/// `GET /emergency-status` -- report current kill-switch state.
pub const EMERGENCY_STATUS_PATH: &str = "/emergency-status";

/// `POST /evaluate-plan` - plan-level pre-flight evaluation.
pub const EVALUATE_PLAN_PATH: &str = "/evaluate-plan";

/// `GET /approvals/pending` - list outstanding HITL approvals,
/// optionally filtered by query parameters.
pub const APPROVALS_PENDING_PATH: &str = "/approvals/pending";

/// `GET /approvals/{id}` -- fetch one approval (pending or resolved).
///
/// The `{id}` placeholder is substituted by the adapter's routing
/// layer; this constant is the route template string so adapters can
/// pass it to their router as-is.
pub const APPROVALS_GET_PATH: &str = "/approvals/{id}";

/// `POST /approvals/{id}/respond` -- submit a decision for a single
/// pending approval.
pub const APPROVALS_RESPOND_PATH: &str = "/approvals/{id}/respond";

/// `POST /approvals/batch/respond` -- submit decisions for multiple
/// pending approvals in one request.
pub const APPROVALS_BATCH_RESPOND_PATH: &str = "/approvals/batch/respond";

/// Describe every approval route an adapter must expose.
#[must_use]
pub const fn approval_route_registrations() -> [EmergencyRouteRegistration; 4] {
    [
        EmergencyRouteRegistration {
            method: HttpMethod::Get,
            path: APPROVALS_PENDING_PATH,
            name: "approvals_pending",
        },
        EmergencyRouteRegistration {
            method: HttpMethod::Get,
            path: APPROVALS_GET_PATH,
            name: "approvals_get",
        },
        EmergencyRouteRegistration {
            method: HttpMethod::Post,
            path: APPROVALS_RESPOND_PATH,
            name: "approvals_respond",
        },
        EmergencyRouteRegistration {
            method: HttpMethod::Post,
            path: APPROVALS_BATCH_RESPOND_PATH,
            name: "approvals_batch_respond",
        },
    ]
}

/// Header that carries the operator admin token on every emergency
/// call. Adapters must not expose these routes without requiring this
/// header; see [`crate::emergency::EmergencyAdmin::new`].
pub const EMERGENCY_ADMIN_TOKEN_HEADER: &str = "X-Admin-Token";

/// Route descriptor used by [`emergency_route_registrations`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmergencyRouteRegistration {
    /// HTTP method for this route.
    pub method: HttpMethod,
    /// URL path for this route.
    pub path: &'static str,
    /// Stable identifier adapters can use when emitting metrics.
    pub name: &'static str,
}

/// Compact description of every route a substrate adapter must expose
/// for the emergency kill switch. Returned as an array so adapters can
/// iterate without heap allocation.
#[must_use]
pub const fn emergency_route_registrations() -> [EmergencyRouteRegistration; 3] {
    [
        EmergencyRouteRegistration {
            method: HttpMethod::Post,
            path: EMERGENCY_STOP_PATH,
            name: "emergency_stop",
        },
        EmergencyRouteRegistration {
            method: HttpMethod::Post,
            path: EMERGENCY_RESUME_PATH,
            name: "emergency_resume",
        },
        EmergencyRouteRegistration {
            method: HttpMethod::Get,
            path: EMERGENCY_STATUS_PATH,
            name: "emergency_status",
        },
    ]
}

// ---------------------------------------------------------------------------
// Compliance score endpoint.
// ---------------------------------------------------------------------------

/// `POST /compliance/score` -- compute a 0..=1000 compliance score for
/// an agent over a window. Substrate adapters delegate to
/// [`crate::compliance::handle_compliance_score`].
pub const COMPLIANCE_SCORE_PATH: &str = "/compliance/score";

// ---------------------------------------------------------------------------
// Regulatory receipt export endpoint.
// ---------------------------------------------------------------------------

/// `GET /regulatory/receipts` -- read-only signed export of receipts
/// for regulators. Every response is a
/// [`crate::regulatory_api::SignedRegulatoryReceiptExport`].
pub const REGULATORY_RECEIPTS_PATH: &str = "/regulatory/receipts";

/// Header that carries the regulator token. Adapters must not expose
/// `/regulatory/*` without requiring this header; the handler fails
/// closed when the caller identity is missing.
pub const REGULATORY_TOKEN_HEADER: &str = "X-Regulatory-Token";

/// Route descriptors for the regulatory API. Appended after the
/// emergency and approval registrations; do not reorder existing entries.
#[must_use]
pub const fn regulatory_route_registrations() -> [EmergencyRouteRegistration; 2] {
    [
        EmergencyRouteRegistration {
            method: HttpMethod::Post,
            path: COMPLIANCE_SCORE_PATH,
            name: "compliance_score",
        },
        EmergencyRouteRegistration {
            method: HttpMethod::Get,
            path: REGULATORY_RECEIPTS_PATH,
            name: "regulatory_receipts",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emergency_route_constants_match_spec() {
        assert_eq!(EMERGENCY_STOP_PATH, "/emergency-stop");
        assert_eq!(EMERGENCY_RESUME_PATH, "/emergency-resume");
        assert_eq!(EMERGENCY_STATUS_PATH, "/emergency-status");
        assert_eq!(EMERGENCY_ADMIN_TOKEN_HEADER, "X-Admin-Token");
    }

    #[test]
    fn regulatory_route_constants_match_spec() {
        assert_eq!(COMPLIANCE_SCORE_PATH, "/compliance/score");
        assert_eq!(REGULATORY_RECEIPTS_PATH, "/regulatory/receipts");
        assert_eq!(REGULATORY_TOKEN_HEADER, "X-Regulatory-Token");

        let registrations = regulatory_route_registrations();
        assert_eq!(registrations.len(), 2);
        let names: Vec<&str> = registrations.iter().map(|r| r.name).collect();
        assert!(names.contains(&"compliance_score"));
        assert!(names.contains(&"regulatory_receipts"));
    }

    #[test]
    fn registrations_cover_all_three_endpoints() {
        let registrations = emergency_route_registrations();
        assert_eq!(registrations.len(), 3);
        let names: Vec<&str> = registrations.iter().map(|r| r.name).collect();
        assert!(names.contains(&"emergency_stop"));
        assert!(names.contains(&"emergency_resume"));
        assert!(names.contains(&"emergency_status"));

        let stop = registrations.iter().find(|r| r.name == "emergency_stop");
        assert!(
            matches!(stop, Some(r) if matches!(r.method, HttpMethod::Post)),
            "stop registration must exist and use POST"
        );

        let status = registrations.iter().find(|r| r.name == "emergency_status");
        assert!(
            matches!(status, Some(r) if matches!(r.method, HttpMethod::Get)),
            "status registration must exist and use GET"
        );
    }
}
