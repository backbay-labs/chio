# Rust Modularization Patterns (Chio)

Reference catalog. Date: 2026-06-26. Status: companion to `2026-06-26-rust-file-decomposition-design.md`.

A reusable catalog of the module-decomposition patterns Chio uses to keep
hand-maintained Rust files small, focused, and independently testable. The
file-hygiene gate (`scripts/check-rust-file-hygiene.py`) enforces the ceilings;
this catalog is how you get and stay under them. Each oversized file in the
decomposition spec cites a pattern number from here, so this document is the
single source of truth for "how do I split this."

House rules honored throughout: no em dashes; fail-closed (errors deny, invalid
input rejects at load); `unwrap_used`/`expect_used` denied in non-test Rust.

---

## How to use this catalog

1. Find the file's dominant responsibility tangle (read its `fn`/`impl`/`struct`
   inventory and name-prefix groupings: `rg -o '^(pub )?(async )?fn ([a-z]+)_' f.rs | sort | uniq -c`).
2. Match it to a pattern below (most files are pattern 1 plus one other).
3. Split along responsibility seams, never by line count. A module must be
   describable in one sentence: what it does, how you use it, what it depends on.
4. Default to a facade `mod.rs` (pattern 1) so the public path is unchanged and
   no caller edits are needed.
5. Target every module under ~1,200 lines (ideally 300-800). The hard ceiling is
   2,000 (1,000 for `lib.rs`).

**The invariant that makes every split safe:** the public API and the test
surface do not change. A pure module move re-exported through a facade is
behavior-preserving by construction; the full test suite plus the hygiene gate
are the proof. If a split would change a public path or a test, it is no longer
mechanical and must be called out explicitly.

---

## Pattern 1 - Facade module + submodule tree

**When:** almost always; the default container move. A flat `foo.rs` has grown to
hold several concerns that are individually coherent.

**Move:** convert `foo.rs` into `foo/mod.rs` plus one submodule per concern.
`mod.rs` becomes a thin facade: `mod` declarations plus `pub use` re-exports of
exactly the items that were public before. Callers that wrote `crate::foo::Thing`
keep working unchanged.

```rust
// foo/mod.rs  (facade, < 100 lines)
mod assemble;
mod verify;
mod report;

pub use assemble::{assemble_bundle, BundleInputs};
pub use verify::{verify_bundle, VerifyError};
pub use report::Report;

// shared-but-private helpers stay here or move to foo/support.rs
```

**Why it is safe:** the re-export set is the old public surface verbatim;
`cargo build` fails if you miss one. No downstream edits.

**Pitfalls:** do not re-export `*` (it hides the surface and defeats the gate's
intent); list items explicitly. Keep `mod.rs` free of logic beyond wiring.

---

## Pattern 2 - Dispatch table split

**When:** a CLI/command hub with one giant `match` over subcommands, each arm
inlining its handler (Chio: `cli/dispatch.rs`, `cli/dispatch/proof.rs`, mercury
`commands/*`).

**Move:** one module per subcommand exposing a single entry `fn`; the dispatcher
becomes a thin `match` that only routes. Shared argument parsing and output
formatting move to a `dispatch/support.rs`.

```rust
// dispatch/mod.rs
mod verify; mod export; mod doctor; mod collect;
pub fn dispatch(cmd: ProofCommand) -> Result<(), CliError> {
    match cmd {
        ProofCommand::Verify(a) => verify::run(a),
        ProofCommand::Export(a) => export::run(a),
        ProofCommand::Doctor(a) => doctor::run(a),
        ProofCommand::Collect(a) => collect::run(a),
    }
}
```

**Why it is safe:** each `run` is the old arm body moved verbatim; the enum and
public dispatch signature are unchanged.

**Pitfalls:** resist a `commands::*` glob; keep the router exhaustive (no `_ =>`)
so a new subcommand cannot silently no-op.

---

## Pattern 3 - Verifier pipeline / stage-per-check

**When:** a verifier runs a sequence of independent checks against one artifact
and accumulates a verdict (Chio: `swarm-authority/verifier.rs`,
`runtime_security/artifacts.rs`, `passport_verifier.rs`, `settlement_proof.rs`,
`disclosure-lineage/verifier.rs`).

**Move:** each independent check becomes a named function in its own module with a
uniform signature `fn check_x(ctx: &VerifyCtx) -> Result<(), RejectReason>`. The
orchestrator just sequences them and is the only place that knows the order.
Fail-closed is preserved because every check still returns `Result` and the
orchestrator short-circuits on the first `Err`.

```rust
// verifier/mod.rs
mod context; mod signature; mod bindings; mod budget; mod revocation;
pub use context::VerifyCtx;
pub fn verify_bundle(ctx: &VerifyCtx) -> Result<Report, RejectReason> {
    signature::check(ctx)?;     // each module: one check, one reason vocabulary
    bindings::check(ctx)?;
    revocation::check(ctx)?;
    budget::check(ctx)?;
    Ok(Report::accepted(ctx))
}
```

**Why it is safe:** the check bodies and their `RejectReason`s are unchanged; only
their physical home moves. Negative fixtures keep asserting the same reasons.

**Pitfalls:** do not let a check silently become advisory during the move (the
exact failure mode prior Chio reviews caught). Keep the orchestrator's order and
each `?` intact; if a check needs shared derived state, compute it once in
`VerifyCtx`, never recompute divergently per module.

---

## Pattern 4 - Generator stages + shared support

**When:** a fixture/codegen generator that emits many artifact families and shares
a pile of cross-cutting helpers (Chio: `cli/dispatch/proof/fixture.rs`, 6,139
lines; xtask `fixtures*.rs`).

**Move:** one module per output domain (disclosure / risk / lineage / swarm /
settlement) - several already exist as `fixture_agent_web.rs`,
`fixture_cleanup.rs`; finish the set. Extract the cross-cutting verbs
(`normalize_*`, `sign_*`, `rebind_*`, `merge_*`, `write_*`) into a
`fixture/support/` module so each domain generator depends on the shared verbs,
not on its siblings.

```rust
// fixture/mod.rs
mod support;                       // normalize, sign, rebind, merge, write
mod disclosure; mod risk; mod lineage; mod swarm; mod settlement;
pub use support::FixtureCtx;
pub fn generate(domain: Domain, ctx: &mut FixtureCtx) -> Result<(), CliError> {
    match domain {
        Domain::Disclosure => disclosure::generate(ctx),
        Domain::Risk => risk::generate(ctx),
        // ...
    }
}
```

**Why it is safe:** generators are exercised by the fixture-contract tests and the
launch-acceptance gate; a behavior-preserving move keeps those green and the
regenerated fixtures byte-identical.

**Pitfalls:** the shared `support` verbs (signing/canonicalization/rebind) are the
load-bearing correctness core - move them once, do not fork per-domain copies.

---

## Pattern 5 - Service-handler grouping

**When:** an RPC/service runtime where dozens of request handlers live in one file
(Chio: `control-plane/trust_control/*`, `service_runtime.rs`).

**Move:** group handlers by bounded subdomain (issuance, risk-finance,
underwriting, capital-liability) into one module each; the runtime shell keeps
only wiring, dispatch, and shared middleware. Each handler module owns its
request/response types or imports them from a shared `service_types`.

**Why it is safe:** the public service trait / route table is unchanged; handlers
move verbatim behind the same dispatch.

**Pitfalls:** keep one dispatch table, not per-module routing that can drift;
shared types go in one `service_types` module, not duplicated.

---

## Pattern 6 - Store: schema / query / bootstrap split

**When:** a persistence module mixing DDL/migration, query construction, and
row<->struct mapping (Chio: `store-sqlite/receipt_store/*`, `budget_store/*`).

**Move:** three modules - `bootstrap` (schema, migrations, pragmas), `query`
(statement builders, parameter binding), `mapping` (row to domain type and back).
A thin `mod.rs` exposes the store handle and its methods.

**Why it is safe:** the store's public methods are unchanged; SQL strings and
mapping move verbatim. Store integration tests are the safety net.

**Pitfalls:** keep prepared-statement SQL next to the mapping it feeds, or split
so the column order is asserted in one place; a silent column/struct drift is a
data bug the compiler will not catch.

---

## Pattern 7 - Typed-section modules

**When:** a large type-definition file with many related structs/enums, their
impls, and large `const` tables or `match` arms (Chio: `core-types/session.rs`,
`crypto.rs`, `canonical.rs`, `policy/models.rs`).

**Move:** group related types + their impls into one module per concept
(`session/operation.rs`, `session/state.rs`); move big `const` lookup tables and
exhaustive `match` arms into a `data` submodule so the logic file stays readable.
Re-export the type names through the facade so `crate::session::Foo` is stable.

**Why it is safe:** types and impls move verbatim; serde derives and the wire
representation are unchanged (verify with the canonical-JSON / schema tests).

**Pitfalls:** do not split a type from its `impl` across a privacy boundary it
needs; keep `#[serde(...)]` and field order intact - reordering can change
canonical bytes.

---

## Pattern 8 - Transport / protocol layering

**When:** a protocol client/server file mixing wire codec, session state, and
auth/handshake (Chio: `mcp-remote/{oauth,session_core,http_service}`,
`mcp-adapter/transport.rs`, `ag-ui-proxy/proxy.rs`).

**Move:** separate layers - `codec` (framing, (de)serialization), `session`
(connection state machine, lifecycle), `auth` (handshake, token exchange,
refresh). Each layer depends downward only (auth -> session -> codec), never
sideways.

**Why it is safe:** the layers already exist conceptually; making them physical
modules with a one-directional dependency removes the tangle without changing the
wire behavior, which the protocol/edge integration tests pin.

**Pitfalls:** keep the dependency acyclic; if `session` and `auth` both need a
type, it belongs in `codec` or a shared `types` module, not imported in a cycle.

---

## Cross-cutting guidance

- **Facade everything.** Even when applying patterns 2-8, the container is still
  pattern 1: a `mod.rs` that re-exports the prior public surface. This is what
  makes splits zero-diff for callers.
- **One reason vocabulary per verifier.** When splitting a verifier (pattern 3),
  the `RejectReason`/error enum stays in one place and is shared; do not let each
  check invent ad hoc strings (Chio is migrating to dotted machine codes - keep
  that single source).
- **Move tests with their unit.** A `#[cfg(test)] mod tests` for moved code moves
  with it; large integration suites split by scenario (a `tests/<area>/` tree)
  but that is tracked separately from this catalog.
- **No behavior change in a split commit.** Decomposition commits are pure moves
  plus facade wiring. Any real change (fixing a check, tightening a type) is a
  separate commit with its own test, so review and `git bisect` stay meaningful.
- **Prove it.** Every split is done when: `cargo build --workspace` and
  `cargo test --workspace` pass, `cargo clippy --workspace -- -D warnings` and
  `cargo fmt --all -- --check` pass, and `scripts/check-rust-file-hygiene.py`
  shows the file under target (and the allowlist entry removed).

## Test-file decomposition (reference only; out of execution scope)

Oversized test suites (`*/tests/*.rs`, `tests.rs`) split by **scenario group**
into a `tests/<suite>/` submodule tree with a thin `mod.rs` aggregator and a
shared `support.rs` for fixtures/builders. This is the same pattern 1 facade idea
applied to `#[cfg(test)]`. It is catalogued here for completeness but is not part
of the current decomposition execution scope.
