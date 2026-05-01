//! Kernel-side model-card binding refusal (M10.P4.T5).
//!
//! When `policy.weights_card_required` is `required` or
//! `required_with_pin`, the kernel refuses to bind a provider unless a
//! signed model card matches the loaded weights AND the requested
//! capability set is admissible under the card. This module is the
//! refusal-decision surface; the policy load path lives in `chio-policy`
//! (P4.T4) and the cosign bundle verify path lives in `chio-weights`
//! (P4.T3).
//!
//! # Refusal contract
//!
//! Provider bind verifies, in order:
//!
//! 1. The provider's loaded `weights_hash` (lowercase hex sha-256 of the
//!    canonical weights blob) byte-equals the card's `weights_hash`.
//!    Mismatch surfaces as
//!    [`WeightsBindingError::CardMismatch`] / `urn:chio:error:weights:card-mismatch`.
//! 2. The requested capability scope set is a subset of the card's
//!    `allowed_capability_set`. Any scope not in the set surfaces as
//!    [`WeightsBindingError::ScopeNotSubset`] / `urn:chio:error:weights:scope-not-subset`.
//! 3. No requested tool intersects the card's `banned_tools`. Banned tools
//!    reject at provider bind, not at first call. Surfaces as
//!    [`WeightsBindingError::ToolBanned`] / `urn:chio:error:weights:tool-banned`.
//!
//! All gates fail-closed: the first failing gate short-circuits.
//!
//! # Async discipline
//!
//! Per the M10.P4.T5 soft-dep, this module introduces NO `&mut self` on
//! the verifier surface. [`evaluate_weights_binding`] is a free function
//! over `&ModelCard` so it composes cleanly with the trajectory-1 M05
//! async kernel without locking.

use chio_weights::card::{ModelCard, StringSet};
use chio_weights::error::WeightsError;

/// The kernel-side bind-time decision surface error. Wraps
/// [`chio_weights::error::WeightsError`] so consumers get a single result
/// type to pattern-match on.
pub type WeightsBindingError = WeightsError;

/// Inputs the kernel collects at provider bind. The provider supplies its
/// loaded `weights_hash` and the operator supplies the requested
/// capability set. Banned-tool intersection is computed against the same
/// `requested_scopes` because the M07 provider matrix unifies tool
/// identifiers into the scope namespace.
#[derive(Debug, Clone)]
pub struct WeightsBindingRequest<'a> {
    /// Lowercase hex sha-256 of the provider's loaded weights blob.
    /// The provider computes this; the card binding refusal verifies
    /// byte-equality against the card's `weights_hash`.
    pub loaded_weights_hash: &'a str,
    /// Capability scope set the operator wants to grant against the
    /// bound provider. Subset containment against the card's
    /// `allowed_capability_set` is enforced.
    pub requested_scopes: &'a StringSet,
    /// Tool identifiers the operator wants to permit. Intersection with
    /// the card's `banned_tools` is enforced. May overlap or equal
    /// `requested_scopes` depending on the deployment model.
    pub requested_tools: &'a StringSet,
}

/// Evaluate the kernel binding refusal contract.
///
/// Returns `Ok(())` only when ALL three gates pass:
///
/// 1. `card.weights_hash == request.loaded_weights_hash`,
/// 2. `card.allowed_capability_set.covers(request.requested_scopes)`,
/// 3. `card.banned_tools.intersects(request.requested_tools)` is false.
///
/// Fail-closed: any failing gate returns the matching
/// [`WeightsBindingError`]. The first failing gate short-circuits;
/// deployments needing distinct telemetry per gate read the
/// [`WeightsError::urn`].
pub fn evaluate_weights_binding(
    card: &ModelCard,
    request: &WeightsBindingRequest<'_>,
) -> Result<(), WeightsBindingError> {
    // Gate 1: weights_hash byte-equality. Lowercase hex on both sides
    // (the card schema enforces lowercase at validate; the provider
    // normalises before passing in).
    if card.weights_hash != request.loaded_weights_hash {
        return Err(WeightsError::CardMismatch {
            expected: card.weights_hash.clone(),
            found: request.loaded_weights_hash.to_string(),
        });
    }

    // Gate 2: scope subset containment. We surface the FIRST scope that
    // fails so the error message is actionable.
    for scope in request.requested_scopes.iter() {
        if !card.allowed_capability_set.contains(scope) {
            return Err(WeightsError::ScopeNotSubset {
                scope: scope.to_string(),
            });
        }
    }

    // Gate 3: banned-tools intersection. Surface the FIRST overlap.
    for tool in request.requested_tools.iter() {
        if card.banned_tools.contains(tool) {
            return Err(WeightsError::ToolBanned {
                tool: tool.to_string(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn fixed_issued_at() -> chrono::DateTime<Utc> {
        match Utc.with_ymd_and_hms(2026, 4, 30, 12, 0, 0) {
            chrono::LocalResult::Single(t) => t,
            _ => panic!("fixed_issued_at fixture must construct"),
        }
    }

    fn good_card() -> ModelCard {
        let issued = fixed_issued_at();
        match ModelCard::new(
            "0000000000000000000000000000000000000000000000000000000000000001",
            StringSet::new(["tool:read", "tool:write"]),
            StringSet::new(["tool:exec"]),
            "public-internet",
            "https://example.com/issuer",
            issued,
            issued + chrono::Duration::days(30),
        ) {
            Ok(c) => c,
            Err(e) => panic!("good_card must construct: {e}"),
        }
    }

    #[test]
    fn binding_succeeds_when_all_gates_pass() {
        let card = good_card();
        let scopes = StringSet::new(["tool:read"]);
        let tools = StringSet::new(["tool:read"]);
        let req = WeightsBindingRequest {
            loaded_weights_hash:
                "0000000000000000000000000000000000000000000000000000000000000001",
            requested_scopes: &scopes,
            requested_tools: &tools,
        };
        assert!(evaluate_weights_binding(&card, &req).is_ok());
    }

    #[test]
    fn rejects_card_mismatch() {
        let card = good_card();
        let scopes = StringSet::new(["tool:read"]);
        let tools = StringSet::new(["tool:read"]);
        let req = WeightsBindingRequest {
            loaded_weights_hash:
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            requested_scopes: &scopes,
            requested_tools: &tools,
        };
        let err = match evaluate_weights_binding(&card, &req) {
            Err(e) => e,
            Ok(()) => panic!("must reject"),
        };
        assert_eq!(err.urn(), "urn:chio:error:weights:card-mismatch");
        assert!(matches!(err, WeightsError::CardMismatch { .. }));
    }

    #[test]
    fn rejects_scope_not_subset() {
        let card = good_card();
        let scopes = StringSet::new(["tool:read", "tool:admin"]);
        let tools = StringSet::default();
        let req = WeightsBindingRequest {
            loaded_weights_hash:
                "0000000000000000000000000000000000000000000000000000000000000001",
            requested_scopes: &scopes,
            requested_tools: &tools,
        };
        let err = match evaluate_weights_binding(&card, &req) {
            Err(e) => e,
            Ok(()) => panic!("must reject"),
        };
        assert_eq!(err.urn(), "urn:chio:error:weights:scope-not-subset");
        match err {
            WeightsError::ScopeNotSubset { scope } => {
                assert_eq!(scope, "tool:admin");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn rejects_banned_tool() {
        let card = good_card();
        let scopes = StringSet::new(["tool:read"]);
        let tools = StringSet::new(["tool:read", "tool:exec"]);
        let req = WeightsBindingRequest {
            loaded_weights_hash:
                "0000000000000000000000000000000000000000000000000000000000000001",
            requested_scopes: &scopes,
            requested_tools: &tools,
        };
        let err = match evaluate_weights_binding(&card, &req) {
            Err(e) => e,
            Ok(()) => panic!("must reject"),
        };
        assert_eq!(err.urn(), "urn:chio:error:weights:tool-banned");
        match err {
            WeightsError::ToolBanned { tool } => assert_eq!(tool, "tool:exec"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn gate_order_is_card_mismatch_first() {
        // Multiple gates fail simultaneously; the surface returns the
        // FIRST gate in declared order. This is part of the contract:
        // operators can rely on stable error codes for the first
        // misconfiguration they see.
        let card = good_card();
        let scopes = StringSet::new(["tool:admin"]);
        let tools = StringSet::new(["tool:exec"]);
        let req = WeightsBindingRequest {
            loaded_weights_hash:
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            requested_scopes: &scopes,
            requested_tools: &tools,
        };
        let err = match evaluate_weights_binding(&card, &req) {
            Err(e) => e,
            Ok(()) => panic!("must reject"),
        };
        assert!(matches!(err, WeightsError::CardMismatch { .. }));
    }

    #[test]
    fn empty_scopes_and_tools_pass_when_hash_matches() {
        let card = good_card();
        let scopes = StringSet::default();
        let tools = StringSet::default();
        let req = WeightsBindingRequest {
            loaded_weights_hash:
                "0000000000000000000000000000000000000000000000000000000000000001",
            requested_scopes: &scopes,
            requested_tools: &tools,
        };
        assert!(evaluate_weights_binding(&card, &req).is_ok());
    }
}
