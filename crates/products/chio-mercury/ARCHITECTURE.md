# chio-mercury architecture

## Overview

`chio-mercury` is the product CLI for MERCURY, a Chio-based release-control and go-to-market
evidence workflow. It holds no evidence schema and no persistent state of its own: every command
reads or synthesizes Chio receipts, hands them to `chio-mercury-core` to build a typed,
`.validate()`-checked package, and writes the result to a fixed on-disk layout. It sits
downstream of the kernel: the packages it writes are evidence and reviewer artifacts, not inputs
the kernel evaluates.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/main.rs` | `mercury` binary: the `Cli`/`Commands` clap tree (about 20 subcommand groups) and dispatch into `commands::*`. |
| `src/commands.rs` | Crate root of the `commands` module: shared imports, the fixed owner/decision-string constants reused across lanes, and re-exports of every `cmd_mercury_*` entry point. |
| `src/commands/shared/mod.rs` | Declares the shared submodules and re-exports them into `commands` via `pub(super) use`. |
| `src/commands/shared/utils.rs` | Filesystem helpers: JSON read/write, empty-directory enforcement, relative-path display, file copy, bundle-manifest writing, and `bundle_manifest_file_name` path safety. |
| `src/commands/shared/types.rs` | CLI-local summary, manifest, and decision-record structs (distinct from `chio-mercury-core`'s types) for every lane through `broader-distribution`. |
| `src/commands/shared/builders.rs` | Builders for `chio-mercury-core` packages (proof, inquiry, assurance, governance-review, and the embedded-oem/trust-network/release-readiness/controlled-adoption/reference-distribution/broader-distribution profiles) plus the synthetic pilot receipt/capability/checkpoint helpers. |
| `src/commands/shared/population_configs.rs` | The three fixed assurance-suite reviewer-population configs (internal, auditor, counterparty review). |
| `src/commands/shared/tests.rs` | Unit tests for `bundle_manifest_file_name` rejection cases. |
| `src/commands/core_cli/mod.rs` | Re-exports for the base-workflow commands. |
| `src/commands/core_cli/commands.rs` | `cmd_mercury_{proof,inquiry}_export`, `cmd_mercury_verify`, `cmd_mercury_pilot_export`, `cmd_mercury_supervised_live_{export,qualify}`, `cmd_mercury_downstream_review_*`, `cmd_mercury_governance_workbench_*`. |
| `src/commands/core_cli/exports.rs` | `export_supervised_live_qualification`, `export_downstream_review`, `export_governance_workbench`, and the shared `export_mercury_run` / `export_pilot_scenario` / `export_supervised_live_capture` pipeline every lane bottoms out in. |
| `src/commands/core_cli/launch_commands.rs` | `cmd_mercury_*_{export,validate}` for assurance-suite, embedded-oem, trust-network, release-readiness, controlled-adoption, reference-distribution, broader-distribution. |
| `src/commands/assurance_release/mod.rs` | Re-exports the seven `export_*` functions below. |
| `src/commands/assurance_release/assurance_suite.rs` | `export_assurance_suite`: three reviewer-population review and investigation package sets, built on `governance_workbench`. |
| `src/commands/assurance_release/embedded_oem.rs` | `export_embedded_oem`: partner SDK bundle, built on `assurance_suite`. |
| `src/commands/assurance_release/trust_network.rs` | `export_trust_network`: checkpoint-witnessed exchange bundle, built on `embedded_oem`. |
| `src/commands/assurance_release/release_readiness.rs` | `export_release_readiness`: signed partner-delivery bundle, built on `trust_network`. |
| `src/commands/assurance_release/controlled_adoption.rs` | `export_controlled_adoption`: renewal/reference cohort, built on `release_readiness`. |
| `src/commands/assurance_release/reference_distribution.rs` | `export_reference_distribution`: landed-account bundle, built on `controlled_adoption`. |
| `src/commands/assurance_release/broader_distribution.rs` | `export_broader_distribution`: governed qualification bundle, built on `reference_distribution`. |
| `src/commands/account_delivery/mod.rs` | Re-exports for the two account-delivery lanes. |
| `src/commands/account_delivery/types.rs` | CLI-local summary/manifest/decision types for `selective-account-activation` and `delivery-continuity`. |
| `src/commands/account_delivery/export.rs` | `export_selective_account_activation` (built on `broader_distribution`) and `export_delivery_continuity` (built on `selective_account_activation`). |
| `src/commands/account_delivery/validation.rs` | `cmd_mercury_{selective_account_activation,delivery_continuity}_{export,validate}`. |
| `src/commands/selective_account_activation_support.rs` | CLI-local types and `build_selective_account_activation_profile` shared into `account_delivery`. |
| `src/commands/renewal_qualification_lane.rs` | `export_renewal_qualification` (built on `delivery_continuity`) and its `cmd_mercury_renewal_qualification_{export,validate}`. |
| `src/commands/second_account_expansion_lane.rs` | Same shape, built on `renewal_qualification`. |
| `src/commands/portfolio_program_lane.rs` | Same shape, built on `second_account_expansion`. |
| `src/commands/second_portfolio_program_lane.rs` | Same shape, built on `portfolio_program`. |
| `src/commands/third_program_lane.rs` | Same shape, built on `second_portfolio_program`. |
| `src/commands/program_family_lane.rs` | Same shape, built on `third_program`. |
| `src/commands/portfolio_revenue_boundary_lane.rs` | Same shape, built on `program_family`; the terminal lane in the chain. |

## Evidence chain

No lane command reads a previous invocation's output from disk. Instead each `export_<lane>`
function calls the previous lane's `export_<lane>` function directly and recurses back to
`export_supervised_live_qualification`, which synthesizes a fresh signed receipt chain,
checkpoint, and `MercuryProofPackage` from `chio-mercury-core` sample fixtures
(`MercurySupervisedLiveCapture::sample`, `MercuryPilotScenario::gold_release_control`). Every
invocation therefore regenerates the entire upstream chain; nothing persists between separate
command invocations.

Each level of the chain:

1. Runs the prior lane's `export_*` into a nested `<output>/<prior-lane>/` directory.
2. Copies the prior lane's package files into a local `*-evidence/` directory and re-derives
   their paths with `relative_display`.
3. Builds this lane's own profile and scope-freeze/manifest/claim-governance/approval/handoff
   artifacts, then assembles a `chio-mercury-core` package and calls `.validate()` on it.
4. Writes a `*-summary.json` that carries forward every upstream file path, so the next lane (or
   a human reviewer) can locate any artifact without re-walking the tree.

`cmd_mercury_<lane>_validate` wraps steps 1-4 under `<output>/<lane>/`, then writes
`validation-report.json` and a decision record: a fixed `approved_scope` string, a fixed
`deferred_scope` list, and a fixed `rationale`. This text is constant per lane and is not
computed from the export; it is a documentation artifact recording that the lane's claims stay
bounded, not a policy check the export can fail.

## Invariants and failure modes

- `ensure_empty_directory` fails closed: an export target must not exist yet, or must already be
  an empty directory. Exports never merge into or silently overwrite existing output.
- `bundle_manifest_file_name` rejects a `bundle_id` that is empty, whitespace-padded, `.`, `..`,
  or contains a path separator, `:`, or a control character, so a manifest identifier can never
  escape the output directory or collide ambiguously with another manifest's file name.
- Every assembled package calls `.validate()` before it is written; proof and inquiry packages
  additionally call `.verify(unix_now())` immediately after building. A package that fails its
  own validation or verification is never written to disk or reused by a downstream lane.
- `mercury verify` dispatches on the package's `schema` field and rejects any schema it does not
  recognize.
- Errors are `chio_control_plane::CliError` throughout; the crate defines no error type of its
  own.

## Dependencies

- `chio-mercury-core` - every typed package, profile, artifact, and schema constant this crate
  assembles; also supplies the sample fixtures the chain bootstraps from.
- `chio-control-plane` - `evidence_export::cmd_evidence_export` materializes a Chio evidence
  directory from the receipt store before proof-package construction; `CliError` is reused as
  this crate's error type.
- `chio-kernel` - `build_checkpoint` seals the synthetic pilot/supervised-live receipt ranges.
- `chio-store-sqlite` - `SqliteReceiptStore` backs the synthetic receipt population.
- `chio-core` is aliased to `chio-core-types` (`chio-core = { package = "chio-core-types", ... }`),
  not the `chio-core` facade crate. Used directly for `CapabilityToken`, `Keypair`, `ChioReceipt`,
  and canonical JSON/hashing when synthesizing pilot receipts.
- `clap` (derive) for the command tree; `chrono` for UTC date stamps in generated package IDs;
  `serde`/`serde_json` for every on-disk artifact.
