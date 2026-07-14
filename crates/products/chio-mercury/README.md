# chio-mercury

MERCURY is a Chio-based release-control and go-to-market evidence workflow. `chio-mercury` is
its product CLI: a single `mercury` binary that turns Chio evidence exports and receipt history
into a chain of signed proof, inquiry, reviewer, and adoption packages for one workflow at a
time. The typed package and profile contracts it assembles live in `chio-mercury-core`; this
crate owns command parsing, package chaining, and the on-disk export layout only.

## Responsibilities

- Parse the `mercury` command tree (`clap`) and dispatch each subcommand to one export or
  validate function.
- Assemble typed `chio-mercury-core` packages from a Chio evidence export
  (`chio_control_plane::evidence_export`), a SQLite receipt store (`chio-store-sqlite`), and
  kernel checkpoints (`chio_kernel::build_checkpoint`).
- Write a fixed, path-safe on-disk layout: profiles, copied upstream evidence, manifests, and
  `*-summary.json` files under the requested output directory.
- For every bounded product lane's `validate` command, additionally write a
  `validation-report.json` and a fixed-content decision record (`approved_scope`,
  `deferred_scope`, `rationale`).
- Verify `Proof Package v1` and `Inquiry Package v1` artifacts (`mercury verify`).

## Public API

This is a binary crate (`mercury`); there is no library surface. Base commands:

| Command | Purpose |
|---|---|
| `proof export` | Wrap a verified Chio evidence package into a `Proof Package v1`. |
| `inquiry export` | Derive an audience-redacted `Inquiry Package v1` from a proof package. |
| `pilot export` | Export the design-partner pilot corpus for the gold MERCURY workflow. |
| `supervised-live export` / `qualify` | Export a live/mirrored capture; generate the canonical qualification and reviewer package. |
| `verify --input <file> [--explain]` | Verify a `Proof Package v1` or `Inquiry Package v1`. |

Bounded product lanes: each exposes `export` (write the package to `<output>`) and `validate`
(nest the export under `<output>/<lane>/`, then write a validation report and decision record).
Lanes chain in this order; each one rebuilds every lane before it from `chio-mercury-core` sample
fixtures:

`downstream-review`, `governance-workbench` (both built from supervised-live qualification) ->
`assurance-suite` -> `embedded-oem` -> `trust-network` -> `release-readiness` ->
`controlled-adoption` -> `reference-distribution` -> `broader-distribution` ->
`selective-account-activation` -> `delivery-continuity` -> `renewal-qualification` ->
`second-account-expansion` -> `portfolio-program` -> `second-portfolio-program` ->
`third-program` -> `program-family` -> `portfolio-revenue-boundary`

## Usage

```sh
mercury proof export \
  --input evidence-package/ \
  --bundle-manifest bundle-manifest.json \
  --output proof-package.json

mercury --json verify --input proof-package.json

mercury broader-distribution validate --output broader-distribution-run/
```

## Testing

`cargo test -p chio-mercury`

`tests/cli.rs` builds the `mercury` binary and drives it through `CARGO_BIN_EXE_mercury`,
exercising every export and validate command end-to-end against real filesystem output (one
export test and one validate test per lane, plus proof/inquiry/pilot/supervised-live coverage).

## See also

- `chio-mercury-core` - typed MERCURY package, profile, and artifact contracts this CLI
  assembles and validates; also supplies the sample fixtures the chain bootstraps from.
- `chio-control-plane` - `evidence_export` for Chio evidence packages; `CliError` is reused as
  this crate's error type throughout.
- `chio-kernel` - `build_checkpoint` for the synthetic receipt store used by pilot and
  supervised-live exports.
- `chio-store-sqlite` - `SqliteReceiptStore` backing that synthetic receipt population.
