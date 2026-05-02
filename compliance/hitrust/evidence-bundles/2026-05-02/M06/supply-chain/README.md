# supply-chain/

## Purpose

This directory holds the cargo-vet supply-chain audit metadata for the Chio
workspace. It records which crate versions have been reviewed, which upstream
audit feeds we trust, and the exemptions we tolerate while the audit set is
still being built out. Ownership lives with M09 (supply-chain hardening); the
audit set is the source of truth that `cargo vet --locked` checks against in
CI.

## Layout

- `audits.toml` -- our own `[[audits.<crate>]]` certifications. Each entry
  names a reviewer (`who`), a criteria level (`criteria`), the exact version
  audited, and a one-line justification (`notes`).
- `config.toml` -- workspace-level cargo-vet policy. Contains the
  `[imports.*]` blocks that pin upstream audit feeds (Mozilla, Bytecode
  Alliance, Google, ZcashFoundation), the per-crate policy overrides, and the
  `[[exemptions.<crate>]]` blocks that record crates we have not yet
  certified.
- `imports.lock` -- machine-generated cache of fetched upstream audits. Do not
  hand-edit; regenerate via cargo-vet so the lockfile stays consistent with
  `config.toml`.

## Adding a certification (the ritual)

```sh
cargo vet suggest                                             # see candidates
cargo vet certify <crate> <version> --criteria safe-to-deploy
# or hand-edit audits.toml with a [[audits.<crate>]] block
cargo vet --locked                                            # verify
git add supply-chain/audits.toml
```

`cargo vet certify` is the canonical entry point. Hand-editing `audits.toml`
is acceptable for batch work, provided each new block carries `who`,
`criteria`, `version`, and a `notes` justification. Keep notes short: name the
upstream maintainer or project, summarise the surface area (pure compute,
build-time only, OS APIs only), and call out any IO or unsafe usage. Always
finish with `cargo vet --locked` so the change reconciles against the
imported feeds and the workspace policy.

## Updating upstream feeds

```sh
cargo vet --locked                                            # confirm baseline
cargo vet import <name> <url>                                 # register + fetch
# to refresh existing imports, edit config.toml or run:
cargo vet regenerate imports
```

Refreshing imports rewrites `imports.lock`. Review the diff before committing
so an upstream feed cannot silently retract or re-target a certification we
depend on. New imports must land in `config.toml` under a stable short name
and a long-lived URL.

## Criteria reference

- `safe-to-run` -- the crate is safe to execute as part of `cargo test` or
  developer tooling, but may not be appropriate to ship in production
  binaries.
- `safe-to-deploy` -- the crate is safe to ship in production. This is the
  default level we certify against in this workspace; everything currently
  audited in `audits.toml` carries `safe-to-deploy`.
- `does-not-implement-crypto` -- explicitly asserts the crate does not
  implement cryptographic primitives. Useful for narrowing review scope on
  crates that touch security-sensitive code paths without being crypto
  themselves.

Full definitions and the precedence ordering live at
<https://mozilla.github.io/cargo-vet/audit-criteria.html>.

## Tier-1 reviewers

- `@bb-connor` -- single-owner trajectory per `OWNERS.toml`. All
  certifications in `audits.toml` are currently signed off by this owner. New
  reviewers should be added to `OWNERS.toml` first, then begin signing
  `audits.toml` entries with their handle.
