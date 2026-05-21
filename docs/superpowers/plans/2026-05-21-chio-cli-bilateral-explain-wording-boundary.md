# Chio CLI Bilateral Explain Wording Boundary

## Goal

Ensure active `chio receipt explain bilateral` output uses Chio/treaty-bound
wording and does not emit stale Chiodos spec paths or `strict CHIODOS`
phrasing.

## Scope

- `crates/chio-cli/src/cli/trust_commands.rs`
- `crates/chio-cli/tests/receipt_explain_bilateral.rs`
- `docs/architecture/CHIO_FINAL_ARCHITECTURE.md`

## Red Test

- Extend the CLI integration test to reject stale Chiodos wording in the JSON
  explain report.
- Extend the human-renderer test to reject the same stale wording in stdout.

## Implementation

- Rewrite bilateral explain strings to section-6 and treaty-bound bilateral
  invocation wording.
- Keep the legacy DualSignedReceipt warning semantically intact.

## Verification

- `CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo test -p chio-cli --test receipt_explain_bilateral -- --nocapture`
- `CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo clippy -p chio-cli --bin chio -- -D warnings`
- `git diff --check`
