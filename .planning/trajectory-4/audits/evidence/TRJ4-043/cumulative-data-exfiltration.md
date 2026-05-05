# TRJ4-043 cumulative data exfiltration

- Test: `crates/chio-conformance/tests/threats/cumulative_data_exfiltration.rs`
- Coverage: direct `DataFlowGuard` exercise.
- Negative case: session journal cumulative read/write totals exceed `max_bytes_total` and return `Verdict::Deny`.
