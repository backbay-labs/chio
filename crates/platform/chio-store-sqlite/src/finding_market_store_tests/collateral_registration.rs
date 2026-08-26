use std::sync::{Arc, Barrier};
use std::thread;

use super::*;

#[test]
fn concurrent_exact_allocation_registration_returns_atomic_replay() {
    let fixture = fixture();
    let finding_id = hex64('a');
    let collateral = keypair(21);
    let backing = Arc::new(backing_body(&finding_id, "vault:concurrent-collateral"));
    let envelope = Arc::new(envelope_string(backing.as_ref(), &collateral));
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let store = fixture.store.clone();
        let backing = Arc::clone(&backing);
        let envelope = Arc::clone(&envelope);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            store.register_allocation_idempotent(&envelope, &backing, NOW)
        }));
    }
    let mut outcomes = handles
        .into_iter()
        .map(|handle| {
            handle
                .join()
                .expect("registration thread")
                .expect("registration")
        })
        .collect::<Vec<_>>();
    outcomes.sort_by_key(|outcome| {
        matches!(
            outcome,
            FindingAllocationRegistrationOutcome::ExactReplay { .. }
        )
    });
    assert_eq!(
        outcomes,
        vec![
            FindingAllocationRegistrationOutcome::Registered { accepted_at: NOW },
            FindingAllocationRegistrationOutcome::ExactReplay { accepted_at: NOW },
        ]
    );
}
