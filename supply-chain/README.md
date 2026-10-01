# supply-chain/

## Purpose

This directory holds the cargo-vet supply-chain audit metadata for the Chio
workspace. It records which crate versions have been reviewed, which upstream
audit feeds we trust, and the exemptions we tolerate while the audit set is
still being built out. The audit set is the source of truth that `cargo vet
--locked` checks against in CI.

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

- `Chio supply-chain reviewer` -- role identity used by the local cargo-vet
  audit set. Cargo-vet requires a non-empty `who` value for each local
  certification, but it does not require a personal GitHub handle. New human
  reviewers should be added to `OWNERS.toml` first, then begin signing
  `audits.toml` entries with the agreed reviewer identity.

## CLI 0.1.1 release maintenance

The CLI policy uses `audit-as-crates-io = false` because the released executable
is first-party code built from this workspace. Its launcher changes are reviewed
and tested in the source PR; an audit of a different crates.io CLI version must
not stand in for that review. The policy change does not remove dependency audits.

The Rustls 0.23.37 to 0.23.45 entry records an automated source delta review. The
existing bootstrap exemptions for aws-lc-rs, aws-lc-sys, aws-lc-fips-sys, DER and
rustls-webpki move to their exact patched lockfile versions and explicitly remain
unaudited. They are not represented as new cryptographic certifications. The
Wasmtime advisory exception is assessed separately in
[`docs/security/wasmtime-2026-0316.md`](../docs/security/wasmtime-2026-0316.md).

The owner approved these five exact bootstrap-version changes on 2026-10-01. The
required [PR justification](https://github.com/backbay-labs/chio/pull/25#issuecomment-5942169511)
records the unaudited boundary and removal condition; the exemption gate remains
enabled. This approval is separate from the two advisory exceptions.
