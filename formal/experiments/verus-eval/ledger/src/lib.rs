//! FV-B5 evaluation artifact: the FV-B3 reservation conservation law under
//! Verus. `sequential` calibrates the dialect against the proven sequential
//! algebra; `sync` is the concurrent tokenized state machine the spike
//! exists to evaluate. Nothing here is release evidence; see
//! `docs/formal/plan/FV-B5-verus-concurrency-evaluation.md`.

// VerusSync machines are CamelCase by upstream convention, and the macro
// names its generated module after the machine.
#![allow(non_snake_case)]

pub mod sequential;
pub mod sync;

#[cfg(any(mutation_terminal, mutation_overflow))]
pub mod mutations;
