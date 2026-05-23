# Chio Public Wording Boundary Closeout

## Goal

Close the remaining production-facing Chio wording leaks found during the
Chio architecture closeout without removing explicit legacy compatibility
surfaces.

## Scope

- `crates/chio-federation/src/lib.rs`
- `crates/chio-federation/tests/public_surface.rs`
- `crates/chio-cli/src/cli/types.rs`

## Red Tests

- Extend the federation public-surface guard to include root `lib.rs`
  production text. It should fail on the stale selective-disclosure comment.
- Add a CLI source guard that rejects stale `strict CHIO` wording in active
  explain help text while allowing hidden legacy command compatibility docs.

## Implementation

- Rewrite the federation selective-disclosure comment to Chio wording.
- Rewrite the CLI explain doc comment to Chio DSSE wording.

## Verification

- `CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo test -p chio-federation --test public_surface chio_federation_production_text_is_chio_named -- --nocapture`
- `CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo test -p chio-cli --bin chio cli_env_tests::explain_help_text_uses_chio_named_dsse_conformance_wording -- --nocapture`
- Focused package tests and clippy after the green patch.
