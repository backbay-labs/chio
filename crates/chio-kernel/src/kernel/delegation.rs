//! M04 Phase 3 kernel-side delegation step.
//!
//! Behind the `delegation_v2` cargo feature, the kernel consults the
//! installed [`RevocationView`] (M04 P2.T4) on every delegated dispatch
//! and denies the capability if any link in its delegation chain (or
//! the leaf capability itself) appears in the revoked set.
//!
//! This is the trust-boundary's fail-closed step: when no view is
//! installed the helper returns `Ok(())`, falling back to the legacy
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
//! matching the existing legacy-path error taxonomy so SDK consumers do
//! not have to learn a new error variant.
//!
//! The module-level `cfg(feature = "delegation_v2")` gate lives on the
//! `mod delegation;` declaration in `kernel/mod.rs`; no inner attribute
//! is needed here.

use std::sync::Arc;

use chio_core_types::CapabilityToken;
use chio_kernel_core::{RevocationView, RevocationViewSubject};

use crate::kernel::KernelError;

/// Consult the installed [`RevocationView`] for every link in the
/// capability's delegation chain plus the leaf id itself. Returns
/// `Ok(())` when no view is installed (legacy path) or when no link is
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
    let Some(view) = view else {
        return Ok(());
    };

    let snapshot = view.load();

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    use chio_core_types::capability::{
        CapabilityTokenBody, ChioScope, DelegationLink, DelegationLinkBody, Operation, ToolGrant,
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
        // do not matter for this consultation helper (the legacy validator
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
        };
        CapabilityToken::sign(body, &kp).unwrap()
    }

    fn install_view(epoch: u64, revoked: &[&str]) -> Arc<RevocationView> {
        let view = Arc::new(RevocationView::new());
        let revoked_set: BTreeSet<RevocationViewSubject> = revoked
            .iter()
            .copied()
            .map(RevocationViewSubject::from)
            .collect();
        let snapshot = RevocationSnapshot {
            epoch,
            root_hash: [0_u8; 32],
            issued_at_unix_ms: 1_700_000_000_000,
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
    fn empty_view_returns_ok() {
        let token = build_token("cap-leaf", &["cap-root"]);
        let view = Arc::new(RevocationView::new());
        assert!(consult_revocation_view(&token, Some(&view)).is_ok());
    }

    #[test]
    fn revoked_ancestor_denies() {
        let token = build_token("cap-leaf", &["cap-root", "cap-mid"]);
        let view = install_view(1, &["cap-root"]);
        let err = consult_revocation_view(&token, Some(&view)).unwrap_err();
        assert!(
            matches!(err, KernelError::DelegationChainRevoked(ref id) if id == "cap-root"),
            "expected DelegationChainRevoked(cap-root), got {err:?}"
        );
    }

    #[test]
    fn revoked_leaf_denies() {
        let token = build_token("cap-leaf", &["cap-root"]);
        let view = install_view(1, &["cap-leaf"]);
        let err = consult_revocation_view(&token, Some(&view)).unwrap_err();
        assert!(
            matches!(err, KernelError::CapabilityRevoked(ref id) if id == "cap-leaf"),
            "expected CapabilityRevoked(cap-leaf), got {err:?}"
        );
    }

    #[test]
    fn unrevoked_chain_returns_ok() {
        let token = build_token("cap-leaf", &["cap-root", "cap-mid"]);
        let view = install_view(1, &["cap-stranger"]);
        assert!(consult_revocation_view(&token, Some(&view)).is_ok());
    }
}
