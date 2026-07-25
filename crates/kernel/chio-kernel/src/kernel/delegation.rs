//! Kernel-side delegation step.
//!
//! Behind the `delegation` cargo feature, the kernel consults the
//! installed [`RevocationView`] on every delegated dispatch and denies
//! the capability if any link in its delegation chain (or the leaf
//! capability itself) appears in the revoked set.
//!
//! This is the trust-boundary's fail-closed step: when no view is
//! installed the helper returns `Ok(())`, falling back to the direct
//! per-row `RevocationStore` lookup that already runs on every dispatch.
//! When a view IS installed, the helper enforces:
//!
//! * Every `delegation_chain[i].capability_id` MUST NOT be present in
//!   the snapshot's `revoked` set.
//! * The leaf `cap.id` MUST NOT be present in the snapshot's `revoked`
//!   set.
//!
//! Either condition raises [`crate::kernel::KernelError::DelegationChainRevoked`]
//! (or [`crate::kernel::KernelError::CapabilityRevoked`] for the leaf),
//! matching the existing compatibility-path error taxonomy so SDK consumers do
//! not have to learn a new error variant.
//!
//! The module-level `cfg(feature = "delegation")` gate lives on the
//! `mod delegation;` declaration in `kernel/mod.rs`; no inner attribute
//! is needed here.

use std::sync::Arc;

use chio_core_types::capability::token::CapabilityToken;
use chio_kernel_core::{RevocationSnapshot, RevocationView, RevocationViewSubject};

use crate::kernel::{current_unix_timestamp, KernelError};

const DEFAULT_REVOCATION_VIEW_MAX_STALENESS_MS: u64 = 500;

/// Consult the installed [`RevocationView`] for every link in the
/// capability's delegation chain plus the leaf id itself. Returns
/// `Ok(())` when no view is installed (no-view-installed path) or when no link is
/// revoked.
///
/// Performance: the `RevocationView` is arc-swap-backed; a single
/// `load_full` happens at the top of this helper, after which all
/// lookups read the borrowed snapshot. The cost is dominated by the
/// `BTreeSet::contains` calls (one per chain link plus one for the
/// leaf), which is O(log n) on the revoked-subject set size.
pub(crate) fn consult_revocation_view(
    cap: &CapabilityToken,
    view: Option<&Arc<RevocationView>>,
) -> Result<(), KernelError> {
    let now_unix_ms = current_unix_timestamp().saturating_mul(1000);
    consult_revocation_view_at(
        cap,
        view,
        now_unix_ms,
        DEFAULT_REVOCATION_VIEW_MAX_STALENESS_MS,
    )
}

fn consult_revocation_view_at(
    cap: &CapabilityToken,
    view: Option<&Arc<RevocationView>>,
    now_unix_ms: u64,
    max_staleness_ms: u64,
) -> Result<(), KernelError> {
    let Some(view) = view else {
        return Ok(());
    };

    let snapshot = view.load();
    verify_snapshot_freshness(&snapshot, now_unix_ms, max_staleness_ms)?;

    for link in &cap.delegation_chain {
        let subject = RevocationViewSubject::new(link.capability_id.clone());
        if snapshot.is_revoked(&subject) {
            return Err(KernelError::DelegationChainRevoked(
                link.capability_id.clone(),
            ));
        }
    }

    let leaf_subject = RevocationViewSubject::new(cap.id.clone());
    if snapshot.is_revoked(&leaf_subject) {
        return Err(KernelError::CapabilityRevoked(cap.id.clone()));
    }

    Ok(())
}

fn verify_snapshot_freshness(
    snapshot: &RevocationSnapshot,
    now_unix_ms: u64,
    max_staleness_ms: u64,
) -> Result<(), KernelError> {
    if now_unix_ms < snapshot.issued_at_unix_ms {
        return Err(KernelError::DelegationInvalid(format!(
            "revocation view snapshot epoch {} is issued in the future",
            snapshot.epoch
        )));
    }
    let age_ms = now_unix_ms.saturating_sub(snapshot.issued_at_unix_ms);
    if age_ms > max_staleness_ms {
        return Err(KernelError::DelegationInvalid(format!(
            "revocation view snapshot epoch {} is stale: age {} ms exceeds {} ms",
            snapshot.epoch, age_ms, max_staleness_ms
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    use chio_core_types::capability::{
        attenuation::{DelegationLink, DelegationLinkBody},
        scope::{ChioScope, Operation, ToolGrant},
        token::CapabilityTokenBody,
    };
    use chio_core_types::crypto::Keypair;
    use chio_kernel_core::{RevocationSnapshot, RevocationViewSubject};
    use std::collections::BTreeSet;

    fn build_token(id: &str, chain_ids: &[&str]) -> CapabilityToken {
        let kp = Keypair::generate();
        let subject = Keypair::generate();
        let scope = ChioScope {
            grants: vec![ToolGrant {
                server_id: "srv".to_string(),
                tool_name: "tool".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        };
        let mut chain = Vec::new();
        // Build a fake delegation chain with the requested ids; signatures
        // do not matter for this consultation helper (the inline validator
        // re-checks them upstream).
        let mut last_kp = kp.clone();
        for cap_id in chain_ids {
            let next_kp = Keypair::generate();
            let body = DelegationLinkBody {
                capability_id: (*cap_id).to_string(),
                delegator: last_kp.public_key(),
                delegatee: next_kp.public_key(),
                attenuations: vec![],
                timestamp: 1500,
                scope_hash: None,
                aggregate_budget: None,
                cumulative_approval: None,
            };
            let link = DelegationLink::sign(body, &last_kp).unwrap();
            chain.push(link);
            last_kp = next_kp;
        }
        let body = CapabilityTokenBody {
            id: id.to_string(),
            issuer: kp.public_key(),
            subject: subject.public_key(),
            scope,
            issued_at: 1000,
            expires_at: 2000,
            delegation_chain: chain,
            aggregate_invocation_budget: None,
        };
        CapabilityToken::sign(body, &kp).unwrap()
    }

    const NOW_MS: u64 = 1_700_000_000_000;
    const MAX_STALENESS_MS: u64 = 500;

    fn install_view(epoch: u64, revoked: &[&str]) -> Arc<RevocationView> {
        install_view_at(epoch, revoked, NOW_MS)
    }

    fn install_view_at(
        epoch: u64,
        revoked: &[&str],
        issued_at_unix_ms: u64,
    ) -> Arc<RevocationView> {
        let view = Arc::new(RevocationView::new());
        let revoked_set: BTreeSet<RevocationViewSubject> = revoked
            .iter()
            .copied()
            .map(RevocationViewSubject::from)
            .collect();
        let snapshot = RevocationSnapshot {
            epoch,
            root_hash: [0_u8; 32],
            issued_at_unix_ms,
            revoked: revoked_set,
        };
        view.install_if_newer(snapshot).unwrap();
        view
    }

    #[test]
    fn no_view_installed_returns_ok() {
        let token = build_token("cap-leaf", &["cap-root"]);
        assert!(consult_revocation_view(&token, None).is_ok());
    }

    #[test]
    fn empty_view_denies_as_stale() {
        let token = build_token("cap-leaf", &["cap-root"]);
        let view = Arc::new(RevocationView::new());
        let err =
            consult_revocation_view_at(&token, Some(&view), NOW_MS, MAX_STALENESS_MS).unwrap_err();
        assert!(matches!(err, KernelError::DelegationInvalid(_)));
    }

    #[test]
    fn revoked_ancestor_denies() {
        let token = build_token("cap-leaf", &["cap-root", "cap-mid"]);
        let view = install_view(1, &["cap-root"]);
        let err =
            consult_revocation_view_at(&token, Some(&view), NOW_MS, MAX_STALENESS_MS).unwrap_err();
        assert!(
            matches!(err, KernelError::DelegationChainRevoked(ref id) if id == "cap-root"),
            "expected DelegationChainRevoked(cap-root), got {err:?}"
        );
    }

    #[test]
    fn revoked_leaf_denies() {
        let token = build_token("cap-leaf", &["cap-root"]);
        let view = install_view(1, &["cap-leaf"]);
        let err =
            consult_revocation_view_at(&token, Some(&view), NOW_MS, MAX_STALENESS_MS).unwrap_err();
        assert!(
            matches!(err, KernelError::CapabilityRevoked(ref id) if id == "cap-leaf"),
            "expected CapabilityRevoked(cap-leaf), got {err:?}"
        );
    }

    #[test]
    fn unrevoked_chain_returns_ok() {
        let token = build_token("cap-leaf", &["cap-root", "cap-mid"]);
        let view = install_view(1, &["cap-stranger"]);
        assert!(consult_revocation_view_at(&token, Some(&view), NOW_MS, MAX_STALENESS_MS).is_ok());
    }

    #[test]
    fn stale_snapshot_denies_even_without_revoked_subjects() {
        let token = build_token("cap-leaf", &["cap-root"]);
        let view = install_view_at(1, &[], NOW_MS - MAX_STALENESS_MS - 1);

        let err =
            consult_revocation_view_at(&token, Some(&view), NOW_MS, MAX_STALENESS_MS).unwrap_err();

        assert!(matches!(err, KernelError::DelegationInvalid(_)));
    }

    #[test]
    fn future_snapshot_denies_even_without_revoked_subjects() {
        let token = build_token("cap-leaf", &["cap-root"]);
        let view = install_view_at(1, &[], NOW_MS + 1);

        let err =
            consult_revocation_view_at(&token, Some(&view), NOW_MS, MAX_STALENESS_MS).unwrap_err();

        assert!(matches!(err, KernelError::DelegationInvalid(_)));
    }
}
