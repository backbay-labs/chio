# TRJ4-042 behavioral sequence attack

- Test: `crates/chio-conformance/tests/threats/behavioral_sequence_attack.rs`
- Coverage: direct `BehavioralSequenceGuard` exercise.
- Negative case: session journal records `shell_exec`, then a configured forbidden `shell_exec -> write_file` transition returns `Verdict::Deny`.
