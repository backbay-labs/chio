# formal/diff-tests Architecture

## Owner

`formal/diff-tests` owns executable differential evidence for the bounded Chio proof boundary. It is the Rust/spec drift gate named by `formal/proof-manifest.toml` and `spec/PROTOCOL.md`.

The crate intentionally contains two kinds of logic:

- an independent reference model in `src/spec.rs` for scope attenuation and
  the bounded treaty predicate fragment
- test harnesses that compare that model, production `chio-core` behavior, normalized `chio-kernel-core` behavior, and frozen cross-language vector corpora

## Boundaries

This crate does not own production authorization, receipt signing, canonical JSON, Merkle, anchor, or SDK behavior. It may import those crates only as comparison targets.

The reference model must stay small and separate from production implementation helpers. If a test needs a production value, build it from the same reference fixture data and compare outputs instead of sharing the production subset function with the reference model.

The normalized proof-facing AST is treated as a third implementation surface, not as the oracle. A passing test should mean the reference model, production runtime type, and normalized type agree on the current bounded semantics.

The treaty predicate oracle covers the production-shaped fields and
constructors represented by `PredicateLang.AdmissionView` and
`PredicateLang.Predicate`. It compares that bounded model with
`chio-runtime-core` but does not replace the production admission hook,
signature verification, continuation validation, evidence resolution, or
storage checks. Property tests use bounded trees that remain below the
production evaluator's depth and node limits.

## Counterexample Regressions

Apalache ITF traces are committed under `formal/tla/counterexamples/` and
converted with `cargo xtask formal itf-to-regression`. Generated tests live in
`formal/diff-tests/tests/` and use the
`regression_formal_<family>_<trace-digest>.rs` naming convention.

Each generated file contains an exact step table and two active native tests. The
trace-shape test pins the source digest, variables, state indices, loop marker,
and every variable value. The replay test invokes a registered production
mapping from `src/counterexample.rs`. Conversion fails without writing a file
when no completed mapping exists for the requested family or when the trace
does not contain a valid family-specific witness. The converter and replay use
the same strict family decoder, and generated witness constants must match the
runtime result.

The trace-shape support remains portable to `wasm32-unknown-unknown`. Full
kernel replay dependencies and the replay test are compiled only for non-wasm
targets; the required native workspace lane executes both tests.

The generated file embeds its source with `include_str!`, so the raw trace is a
compile-time dependency. `scripts/check-regression-tests.sh` deletion-guards
the generated test location in the same way as other regression tests. Each
deletion needs its own line containing both the deleted path or basename and an
issue reference.

## Invariants

- Child scopes may narrow authority but never widen it.
- Parent wildcard server, tool, resource, and prompt patterns may cover specific children; child wildcards do not widen past a specific parent.
- Parent invocation and monetary caps are preserved or narrowed by children.
- Parent DPoP requirements remain required after attenuation.
- Parent constraints must appear in child grants. Extra child constraints narrow authority.
- Canonical JSON and receipt vector tests are byte gates. Do not re-bless vectors or generated bindings from this crate.
- Anchored-root tests verify tuple compatibility and tamper rejection only. Production anchoring logic remains in `chio-anchor` and `chio-core`.
- Generated counterexample tests are never ignored. A new replay family must
  provide native production mapping code before the converter will emit a test.
- Treaty predicate refinement is evidence only for the supplied finite receipt
  domain. Empty or incomplete domains do not establish universal refinement.

## Review Rules

Before changing this crate, read `Cargo.toml`, `src/spec.rs`, `src/generators.rs`, the affected integration tests, `formal/proof-manifest.toml`, and the verified-core section of `spec/PROTOCOL.md`.

Changes should strengthen drift detection without expanding launch claims. If a new property is outside the bounded proof boundary, it belongs in conformance, release qualification, or the owning production crate instead.

Proptest regression seeds for canonical JSON live at
`tests/canonical_json_diff.proptest-regressions`, next to the owning test
module as required by proptest's file-per-module convention.
