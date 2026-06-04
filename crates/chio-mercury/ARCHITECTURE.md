# chio-mercury Architecture

`chio-mercury` is the product CLI that turns typed MERCURY contracts from
`chio-mercury-core` plus Chio evidence exports into proof, inquiry, reviewer,
qualification, and distribution packages. It should stay a command orchestration
crate. Product evidence schemas and validators belong in `chio-mercury-core`;
receipt storage and evidence export mechanics belong in the Chio store, kernel,
and control-plane crates.

## Boundaries

- `main.rs` owns the `mercury` binary command tree and dispatch. It should keep
  command parsing thin and delegate behavior to `commands`.
- `commands.rs` owns CLI orchestration helpers, shared package writers, proof
  and inquiry export, verification, pilot export, supervised-live export, and
  the bounded product lane dispatch surface.
- `commands/shared.rs` contains shared filesystem, package, receipt-store, and
  profile builders that are included into the command module. These helpers form
  the export layout boundary.
- `commands/core_cli.rs`, `commands/assurance_release.rs`, `commands/account_delivery.rs`,
  and the lane modules own specific bounded MERCURY product export and validate
  workflows.
- `tests/cli.rs` exercises the binary-level user workflows and should cover
  fail-closed filesystem and package validation behavior that only exists in the
  CLI layer.

## Pain Points

- The command crate has grown around `include!`-based modules and large shared
  helper files. That makes package-layout invariants easy to miss because they
  are not all represented in core contract validation.
- Generated package paths mix fixed filenames and filenames derived from
  product identifiers. Any derived filename boundary must reject confusing or
  ambiguous names before writing artifacts.
- Core MERCURY validation is intentionally about typed product contracts. The
  CLI still owns local filesystem safety when valid product identifiers become
  filenames.

## Security And API Constraints

- Export commands must fail closed before emitting partial or misleading proof
  packages when user-supplied evidence, bundle manifests, or captures are
  malformed.
- Generated paths must remain inside the requested output tree and must be
  unambiguous in logs, summaries, and reviewer packages.
- Public CLI behavior should remain compatible for valid existing MERCURY
  bundle IDs and package exports.
- Canonical JSON bytes, receipt hashes, checkpoint continuity, and package
  verification semantics must remain unchanged.

## Affected Dependents

- `chio-mercury-core` supplies bundle manifests, pilot fixtures, supervised-live
  captures, and package validators consumed by this CLI.
- `chio-control-plane`, `chio-kernel`, and `chio-store-sqlite` provide evidence
  export, checkpoint, and receipt-store inputs.
- Product documentation and reviewer artifacts consume the generated package
  layout emitted by this crate.

## Planned Improvement

Harden the CLI export-layout boundary for derived bundle manifest filenames.
When a command writes multiple bundle manifests, the file stem is derived from
`MercuryBundleManifest::bundle_id`; that local filesystem projection must reject
control characters as well as path separators and padded names.
