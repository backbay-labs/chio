use chio_kernel::{InMemoryRevocationStore, RevocationStore};
use chio_kernel_core::{revocation_lookup_denies, RevocationCheckTarget};
use proptest::prelude::*;

use chio_test_support::prelude::*;

proptest! {
    #[test]
    fn snapshot_decision_matches_store_projection(
        token_revoked in any::<bool>(),
        ancestor_revoked in any::<bool>(),
    ) {
        let store = InMemoryRevocationStore::new();
        if token_revoked {
            store.revoke("cap-child").test_unwrap();
        }
        if ancestor_revoked {
            store.revoke("cap-parent").test_unwrap();
        }

        let projected_token = store.is_revoked("cap-child").test_unwrap();
        let projected_ancestor = store.is_revoked("cap-parent").test_unwrap();
        let runtime_decision = if revocation_lookup_denies(
            RevocationCheckTarget::PresentedToken,
            projected_token,
        ) {
            true
        } else {
            revocation_lookup_denies(RevocationCheckTarget::Ancestor, projected_ancestor)
        };

        prop_assert_eq!(runtime_decision, token_revoked || ancestor_revoked);
    }
}

#[test]
fn lazy_lookup_projection_distinguishes_token_and_ancestor_flags() {
    assert!(revocation_lookup_denies(
        RevocationCheckTarget::PresentedToken,
        true
    ));
    assert!(revocation_lookup_denies(
        RevocationCheckTarget::Ancestor,
        true
    ));
    assert!(!revocation_lookup_denies(
        RevocationCheckTarget::PresentedToken,
        false
    ));
    assert!(!revocation_lookup_denies(
        RevocationCheckTarget::Ancestor,
        false
    ));
}
