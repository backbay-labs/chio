# formal/diff-tests Architecture

## Owner

`formal/diff-tests` owns executable differential evidence for the bounded Chio proof boundary. It is the Rust/spec drift gate named by `formal/proof-manifest.toml` and `spec/PROTOCOL.md`.

The crate intentionally contains two kinds of logic:

- an independent reference model in `src/spec.rs` for scope attenuation
- an independent reference model for the bounded treaty predicate fragment
- test harnesses that compare that model, production `chio-core` behavior, normalized `chio-kernel-core` behavior, and frozen cross-language vector corpora

## Boundaries

This crate does not own production authorization, receipt signing, canonical JSON, Merkle, anchor, or SDK behavior. It may import those crates only as comparison targets.

The reference model must stay small and separate from production implementation helpers. If a test needs a production value, build it from the same reference fixture data and compare outputs instead of sharing the production subset function with the reference model.

The normalized proof-facing AST is treated as a third implementation surface, not as the oracle. A passing test should mean the reference model, production runtime type, and normalized type agree on the current bounded semantics.

The treaty predicate oracle covers only the fields and constructors represented
by `PredicateLang.ReceiptView` and `PredicateLang.Predicate`. It compares that
model with `chio-runtime-core` but does not replace the production admission
hook, signature verification, continuation validation, evidence resolution, or
storage checks. Property tests use bounded trees that remain below the
production evaluator's depth and node limits.

## Invariants

- Child scopes may narrow authority but never widen it.
- Parent wildcard server, tool, resource, and prompt patterns may cover specific children; child wildcards do not widen past a specific parent.
- Parent invocation and monetary caps are preserved or narrowed by children.
- Parent DPoP requirements remain required after attenuation.
- Parent constraints must appear in child grants. Extra child constraints narrow authority.
- Canonical JSON and receipt vector tests are byte gates. Do not re-bless vectors or generated bindings from this crate.
- Anchored-root tests verify tuple compatibility and tamper rejection only. Production anchoring logic remains in `chio-anchor` and `chio-core`.
- Treaty predicate refinement is evidence only for the supplied finite receipt
  domain. Empty or incomplete domains do not establish universal refinement.

## Review Rules

Before changing this crate, read `Cargo.toml`, `src/spec.rs`, `src/generators.rs`, the affected integration tests, `formal/proof-manifest.toml`, and the verified-core section of `spec/PROTOCOL.md`.

Changes should strengthen drift detection without expanding launch claims. If a new property is outside the bounded proof boundary, it belongs in conformance, release qualification, or the owning production crate instead.
