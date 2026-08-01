use super::*;

const STORE_UUID: &str = "018bcfe5-6800-7000-8000-000000000001";
const LEASE_ID: &str = "018bcfe5-6800-7000-8000-000000000002";

#[test]
fn scoped_identity_qualifies_deterministic_authority_ids() {
    let (_temp, database, lock_root) = fixture();
    let _scope = scope_fixed_authority_ids_for_current_thread(STORE_UUID, [LEASE_ID.to_string()])
        .expect("fixed identity scope");

    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open");

    assert_eq!(
        authority.mutation_fence(),
        StoreMutationFence {
            store_uuid: STORE_UUID.to_string(),
            lease_id: LEASE_ID.to_string(),
            owner_epoch: 1,
        }
    );
}

#[test]
fn scoped_identity_rejects_invalid_or_exhausted_ids() {
    assert!(
        scope_fixed_authority_ids_for_current_thread("not-a-uuid", [LEASE_ID.to_string()]).is_err()
    );
    assert!(scope_fixed_authority_ids_for_current_thread(
        STORE_UUID,
        ["018bcfe5-6800-4000-8000-000000000002".to_string()]
    )
    .is_err());

    let (_temp, database, lock_root) = fixture();
    let _scope = scope_fixed_authority_ids_for_current_thread(STORE_UUID, Vec::<String>::new())
        .expect("empty fixed identity scope");
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::Invalid(message))
            if message == "fixed authority lease ID set is exhausted"
    ));
}
