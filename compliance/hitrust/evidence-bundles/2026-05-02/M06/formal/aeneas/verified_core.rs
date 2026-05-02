#![allow(dead_code)]

// Aeneas pilot source for pure Chio decision functions.
//
// This file intentionally avoids external crates, async code, unsafe code,
// heap allocation, and IO so Charon/Aeneas can extract a Lean model. It mirrors
// the proof-facing shape of chio-kernel-core decisions and is used as the first
// extraction lane before promoting Aeneas to production crate modules.

pub enum Decision {
    Allow,
    Deny,
}

pub fn time_window_valid(now: u64, issued_at: u64, expires_at: u64) -> bool {
    issued_at <= now && now < expires_at
}

pub fn dpop_subset(parent_required: bool, child_required: bool) -> bool {
    !parent_required || child_required
}

pub fn budget_precheck(
    remaining_invocations: u64,
    remaining_units: u64,
    invocation_cost: u64,
    unit_cost: u64,
) -> bool {
    invocation_cost <= remaining_invocations && unit_cost <= remaining_units
}

pub fn governed_approval_passes(approval_required: bool, approval_token_valid: bool) -> bool {
    !approval_required || approval_token_valid
}

pub fn evaluate_signature_time_scope(
    signature_valid: bool,
    scope_match: bool,
    now: u64,
    issued_at: u64,
    expires_at: u64,
) -> Decision {
    if !signature_valid {
        Decision::Deny
    } else if !time_window_valid(now, issued_at, expires_at) {
        Decision::Deny
    } else if !scope_match {
        Decision::Deny
    } else {
        Decision::Allow
    }
}

pub fn report_may_use_verified_label(label: u8) -> bool {
    label == 2
}
