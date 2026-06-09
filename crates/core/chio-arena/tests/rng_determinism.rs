use chio_arena::{ArenaRng, RngError};
use rand::RngCore;

#[test]
fn root_stream_is_byte_identical_across_runs() {
    let mut a = ArenaRng::new(0xdead_beef_cafe_f00d);
    let mut b = ArenaRng::new(0xdead_beef_cafe_f00d);
    let a_seq: Vec<u64> = (0..32).map(|_| a.root_mut().next_u64()).collect();
    let b_seq: Vec<u64> = (0..32).map(|_| b.root_mut().next_u64()).collect();
    assert_eq!(a_seq, b_seq);
}

#[test]
fn agent_substreams_diverge_and_are_reproducible() -> Result<(), RngError> {
    let agents = ["agent-a", "agent-b", "agent-c"];

    let mut first = ArenaRng::new(42);
    first.register_agents(agents)?;
    let first_snapshot = first.snapshot_next_u64s();

    let mut second = ArenaRng::new(42);
    second.register_agents(agents)?;
    let second_snapshot = second.snapshot_next_u64s();
    assert_eq!(first_snapshot, second_snapshot);

    // The three agent values must all be distinct.
    let values: Vec<u64> = first_snapshot.values().copied().collect();
    let mut seen = std::collections::BTreeSet::new();
    for value in &values {
        assert!(seen.insert(*value), "expected distinct sub-stream values");
    }
    Ok(())
}

#[test]
fn distinct_seeds_diverge() {
    let mut a = ArenaRng::new(1);
    let mut b = ArenaRng::new(2);
    assert_ne!(a.root_mut().next_u64(), b.root_mut().next_u64());
}

#[test]
fn duplicate_agent_registration_fails() -> Result<(), RngError> {
    let mut rng = ArenaRng::new(42);
    rng.register_agent("agent-a")?;
    assert!(matches!(
        rng.register_agent("agent-a"),
        Err(RngError::DuplicateAgent(_))
    ));
    Ok(())
}

#[test]
fn unknown_agent_lookup_fails() {
    let mut rng = ArenaRng::new(42);
    assert!(matches!(
        rng.agent_stream_mut("agent-z"),
        Err(RngError::UnknownAgent(_))
    ));
}
