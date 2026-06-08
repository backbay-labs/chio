use super::*;

pub(crate) fn decision_label(decision: &Option<Decision>) -> String {
    match decision {
        Some(Decision::Allow) => "allow".to_string(),
        Some(Decision::Deny { .. }) => "deny".to_string(),
        Some(Decision::Cancelled { .. }) => "cancelled".to_string(),
        Some(Decision::Incomplete { .. }) => "incomplete".to_string(),
        None => "none".to_string(),
    }
}

pub(crate) fn revoked_capability_verdict() -> Verdict {
    Verdict::deny_with_status(
        "capability token has been revoked",
        "CapabilityRevocation",
        403,
    )
}

pub(crate) fn verdict_http_status(verdict: &Verdict) -> u16 {
    match verdict {
        Verdict::Allow => 200,
        Verdict::Deny { http_status, .. } => *http_status,
        Verdict::Cancel { .. } | Verdict::Incomplete { .. } => 500,
    }
}
