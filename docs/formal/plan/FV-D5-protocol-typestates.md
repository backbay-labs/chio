# FV-D5: Machine-readable protocol state machines with generated typestates

Status: Implemented (2026-07-10)
Theme: D - Widen the verified frontier
Effort: M
Depends on: none
Feeds: [FV-C1](FV-C1-receipt-trace-validation.md), [FV-C5](FV-C5-proof-coverage-map.md)
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md), `crates/tooling/chio-spec-codegen/src/statemachines_pass.rs`, `spec/CHIO_BILATERAL_COSIGN_INVOCATION.md`

## Summary

Chio now carries validated state-machine inputs under `spec/statemachines/`.
The Rust codegen lane loads those inputs and emits committed Rust typestates,
conformance non-edge data, and a generated reference. The initial Rust machine
is limited to the strict bilateral DSSE producer that already exists in
`chio-federation`:

```text
Drafted -> HostSigned -> Cosigned -> EnvelopeVerified
```

The types encode call ordering. Hand-written handlers continue to own
canonical statement construction, Ed25519 signing, the bilateral co-signing
trait call, peer signature verification, envelope assembly, and strict DSSE
verification. No wire type or serialized byte shape changed.

The second input describes producer-carried `AnchorBatch::WitnessState`
metadata changes for generated documentation and conformance relation data.
It does not generate a Rust typestate and does not claim to encode verifier
routing, witness admission policy, a remote session, or the surrounding
protocol section.

## Implemented surface

### Validated inputs

- `spec/statemachines/bilateral_dsse_producer.toml` owns the four producer
  states, three messages, runtime guard labels, source citation, and Rust
  emission configuration.
- `spec/statemachines/anchor_witness_state.toml` owns a deliberately narrow
  metadata relation and emits only documentation and conformance data.
- `chio.statemachine.v1` rejects unknown states, unreachable states, dead
  non-terminal states, terminal states with outgoing transitions, duplicate
  `(state, message)` edges, duplicate guards, invalid identifiers, unsafe
  owner paths, duplicate outputs, and inconsistent Rust emission settings.
- Input files and generated output directories reject symlinks.

### Generated outputs

`cargo xtask codegen rust` now owns these outputs in addition to wire types:

- `crates/trust/chio-federation/src/_generated/bilateral_dsse_producer_typestate.rs`
- `crates/tooling/chio-conformance/tests/_generated/bilateral_dsse_producer_ordering.rs`
- `crates/tooling/chio-conformance/tests/_generated/anchor_witness_state_ordering.rs`
- `docs/reference/generated/STATE_MACHINES.md`

The generated Rust stage structs have private fields. Every transition consumes
the previous stage, so a stage cannot be reused after a successful transition.
The generated module includes compile-fail doctests for skipping directly from
`Drafted` to a co-signing action and for repeating the terminal verification
action from `EnvelopeVerified`.

The conformance outputs are complete relation data. For each machine they list
states, messages, transitions, guards, and every non-edge in the state-message
cross product. The hand-written `statemachine_ordering` conformance test checks
that every pair is exactly one edge or non-edge and pins the intended narrow
relations.

### Runtime adoption

The existing public
`sign_chio_bilateral_dsse_envelope_with_cosigner` signature is unchanged.

- With the `typestate` feature, it constructs `Drafted` and delegates through
  the three generated consuming transitions.
- Without the feature, it invokes the same hand-written handlers in order as
  an erased fallback.
- `chio-kernel` enables `chio-federation/typestate` on its production
  dependency, so the existing kernel bilateral DSSE path uses the typed flow.
- `chio-federation` remains buildable and testable without the feature.

The handler split follows actual producer stages rather than treating the
section 7 verifier algorithm as one producer state machine. This keeps the
types aligned with executable operations and leaves the independently tested
verifier intact.

## Drift and ownership

- `cargo xtask codegen rust --check` compares the complete expected output
  set byte for byte, rejects missing or stale files, and rejects marker-stamped
  managed files that no longer correspond to an input.
- `make codegen-check` includes that check through the existing Rust lane.
- `.github/workflows/spec-drift.yml` includes the federation, conformance, and
  reference outputs in its tracked-diff, untracked-file, and generated-header
  gates.
- `.github/CODEOWNERS` covers state-machine inputs, the generator, and all new
  generated outputs.
- A federation integration test independently scans its generated Rust source
  directory for the canonical regeneration header.

## Acceptance criteria

- [x] The loader rejects unknown states, unreachable states, dead
  non-terminal states, duplicate edges, and duplicate guards.
- [x] Regeneration is deterministic and check mode rejects stale, missing, and
  obsolete generated files.
- [x] Generated typestate fields are private and transitions consume `self`.
- [x] Compile-fail doctests cover a skipped state and a repeated terminal
  transition.
- [x] The kernel bilateral DSSE producer uses the typed flow through its
  production dependency feature.
- [x] The same public producer function remains available without the feature.
- [x] Runtime transition handlers perform real cryptographic work and fail
  closed on schema, signature, construction, or verification errors.
- [x] Generated conformance data covers every non-edge and a hand-written test
  verifies the complete relation.
- [x] The generated reference exists and `spec/PROTOCOL.md` is unchanged.
- [x] A second table passes through the documentation and conformance emitters
  without a machine-specific generator branch.

## Decisions

- The only Rust typestate in this implementation is the actual strict
  bilateral DSSE producer. Verifier steps and dynamic peer behavior are not
  relabeled as producer stages.
- The four stage names are `Drafted`, `HostSigned`, `Cosigned`, and
  `EnvelopeVerified`. The first local signature is the tool-host signature,
  so `HostSigned` is more precise than `LocallySigned`.
- The existing public monolithic function remains the compatibility boundary.
  Kernel adoption does not require a public signature change.
- The feature is opt-in for `chio-federation` and explicitly enabled by
  `chio-kernel`. This preserves a tested no-feature fallback while making the
  production path typed.
- Generated code owns ordering only. Runtime data-dependent checks stay in
  hand-written functions and return `Result` on every transition.
- Generated conformance files are relation data, not remote protocol drivers.
  They make non-edges reviewable and testable without claiming a remote peer
  exposes these in-process methods.
- The anchor witness input is documentation and conformance-only. Its scope is
  producer-carried metadata changes, not the full public-witness policy.
- The generated reference is derived material. The cited protocol text remains
  authoritative if the two disagree.

## Manifest and registry updates

- `formal/proof-manifest.toml`: no change. Generated types and tests are not
  proof artifacts.
- `formal/MAPPING.md`: no change. No formal model was derived from these
  tables.
- `formal/assumptions.toml`: no change. No assumption was added or retired.
- `formal/theorem-inventory.json`: no change. No theorem was added.
- `docs/reference/CLAIM_REGISTRY.md`: no change. This implementation does not
  license a release claim beyond its code and test surface.
