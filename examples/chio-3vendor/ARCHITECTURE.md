# chio-three-vendor-example Architecture Notes

## Module Boundaries

This package owns deterministic three-vendor fixture generation for buyer,
provider, auditor, pheromone, authority, and runtime-spine flows. The package
has a library target and two binaries: `generate-chio-proof-package` for
interactive proof/report output and `generate-chio-three-vendor-fixtures` for
committed fixture regeneration and script-facing fixture modes.

## Pain Points

The library is currently only a blanket re-export of `chio-attest-loopback`,
while both binaries share behavior by text-including `src/main.rs`. That makes
the binary source the real owner of fixture generation, command parsing, output
path safety checks, and pheromone fixture assembly. It also builds and verifies
the full proof package before command dispatch, even for invalid usage and modes
that do not need the proof package.

## Security And API Constraints

The package must keep deterministic fixture bytes stable unless a generator
semantic changes intentionally. It must preserve symlink refusal for generated
output paths, fail closed on malformed transit-policy bodies, and keep signed
negative-case, authority-input, pheromone, verifier-report, and proof-package
outputs using the same backing Chio fixture APIs. Binaries should keep their
existing command names and flags.

## Affected Dependents

Workspace scripts call `generate-chio-three-vendor-fixtures` for authority,
pheromone, relay, and runtime proof gates. The README calls
`generate-chio-proof-package` for proof-package and report output. There are no
transitive crate API users beyond this package's local library target.

## Completed Material Improvement

Command dispatch now lives in the package library through a typed
`run_with_args` entrypoint used by tests and both binaries. The binary-to-binary
textual inclusion is gone, command parsing happens before expensive fixture
generation, and command boundary tests keep usage errors and side-effect modes
library-owned.
