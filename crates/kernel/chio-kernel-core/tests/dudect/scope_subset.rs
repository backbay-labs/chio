//! Timing-leak dudect harness for capability scope-subset evaluation.
//!
//! Gated behind the `dudect` Cargo feature so default `cargo test -p
//! chio-kernel-core` is unaffected; opt in via:
//!
//! ```bash
//! cargo test -p chio-kernel-core --features dudect --release scope_subset
//! ```
//!
//! # What this harness measures
//!
//! [`chio_kernel_core::NormalizedScope::is_subset_of`] is the authoritative
//! capability-algebra subset check used by the proof-facing evaluation
//! lane. It walks the child scope's tool grants and asks whether each one
//! is covered by any grant in the parent scope (`grants.iter().all(|g|
//! parent.grants.iter().any(|p| g.is_subset_of(p)))`). The inner
//! short-circuit (`Iterator::any`) returns as soon as a covering parent
//! grant is found.
//!
//! Whether the input data influences how *quickly* the subset check
//! resolves is the question this harness asks. The two input classes
//! place the matching parent grant at different positions:
//!
//! - `Class::Left`: the matching parent grant is the **first** entry of
//!   the parent's `grants` vector. The `any(...)` predicate short-circuits
//!   on the first iteration.
//! - `Class::Right`: the matching parent grant is the **last** entry of
//!   the parent's `grants` vector. The `any(...)` predicate runs through
//!   every entry before short-circuiting.
//!
//! Both classes resolve to the same verdict (`true`); the harness asks
//! whether the time taken to reach that verdict is data-dependent in a
//! way that an off-path attacker could use to learn something about
//! which parent grant matched. If the runtime distributions are
//! statistically distinguishable (Welch's t > 4.5 in two consecutive
//! runs), the subset check is timing-leaky.
//!
//! # Why this matters
//!
//! Scope evaluation lives on the verdict-producing hot path of every
//! capability-bearing tool call. A timing leak here would let a tenant
//! learn the structure of another tenant's parent capability through
//! response-time analysis. A `t < 4.5` result in two consecutive CI runs
//! is the documented pass criterion (`.github/workflows/dudect.yml`).

#![cfg(feature = "dudect")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_kernel_core::{NormalizedOperation, NormalizedScope, NormalizedToolGrant};
use dudect_bencher::rand::RngExt;
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};

/// Number of input pairs generated per harness invocation.
const SAMPLES_PER_RUN: usize = 100_000;

/// Fan-out width of the parent scope's `grants` vector. Wide enough that
/// the difference between matching at index 0 vs index `PARENT_FANOUT - 1`
/// produces a measurable runtime gap if the subset check short-circuits.
const PARENT_FANOUT: usize = 16;

/// Build a `NormalizedToolGrant` with deterministic shape but a unique
/// `tool_name` per index. The grant is intentionally minimal (no
/// constraints, no caps) so the per-grant subset check is dominated by
/// the `tool_name` and `server_id` string compares rather than constraint
/// containment math.
fn grant(server: &str, tool: &str) -> NormalizedToolGrant {
    NormalizedToolGrant {
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        operations: alloc_vec_invoke(),
        constraints: Vec::new(),
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

/// Helper that returns a single-element `Vec<NormalizedOperation>` containing
/// `Invoke`. Pulled out because the verbose vec-literal would otherwise
/// repeat at every call site.
fn alloc_vec_invoke() -> Vec<NormalizedOperation> {
    vec![NormalizedOperation::Invoke]
}

/// Build a parent scope whose `grants` vector has `PARENT_FANOUT` entries.
/// The matching grant for the child sits at `match_index`; every other
/// grant has a distinct `tool_name` so the subset check has to look at
/// every entry before finding the match (or before short-circuiting on it).
fn parent_scope_with_match_at(match_index: usize) -> NormalizedScope {
    let mut grants = Vec::with_capacity(PARENT_FANOUT);
    for i in 0..PARENT_FANOUT {
        let tool = if i == match_index {
            "tool_match".to_string()
        } else {
            format!("tool_other_{i:03}")
        };
        grants.push(grant("server.example", &tool));
    }
    NormalizedScope {
        grants,
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    }
}

/// Build a child scope with the single grant that is supposed to match
/// `tool_match` in the parent.
fn child_scope_matching() -> NormalizedScope {
    NormalizedScope {
        grants: vec![grant("server.example", "tool_match")],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    }
}

/// Dudect harness for `NormalizedScope::is_subset_of`.
///
/// Class definitions:
///
/// - `Class::Left`: parent has the matching grant at index 0. The
///   `parent.grants.iter().any(...)` short-circuits on the first iteration.
/// - `Class::Right`: parent has the matching grant at index
///   `PARENT_FANOUT - 1`. The `any(...)` runs through every entry.
///
/// Both classes resolve to `true`. We pre-build the inputs so the
/// per-iteration work measured by `run_one` only contains the
/// `is_subset_of` call.
fn scope_subset_bench(runner: &mut CtRunner, rng: &mut BenchRng) {
    let child = child_scope_matching();

    let mut inputs: Vec<(Class, NormalizedScope)> = Vec::with_capacity(SAMPLES_PER_RUN);
    for _ in 0..SAMPLES_PER_RUN {
        if rng.random::<bool>() {
            inputs.push((Class::Left, parent_scope_with_match_at(0)));
        } else {
            inputs.push((Class::Right, parent_scope_with_match_at(PARENT_FANOUT - 1)));
        }
    }

    for (class, parent) in inputs {
        runner.run_one(class, || {
            // Verdict is always `true` by construction; we are measuring
            // the time the check takes to return that verdict.
            let _ = child.is_subset_of(&parent);
        });
    }
}

ctbench_main!(scope_subset_bench);
