# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The first public baseline, version 0.1.0, is in preparation and has not yet
been tagged or released. It establishes the wire protocol, the policy and
guard runtime, the receipt and attestation pipeline, the federation and
settlement layers, and the multi-language SDK surface, together with the
supply-chain, fuzzing, and formal-verification apparatus that gate every
change. The entries below track changes accumulating toward that baseline.

### Added

- The cognition market: agents trade verified findings as signed,
  content-addressed artifacts, revealed through kernel-governed tool calls.
  Purchases settle under the kernel delivery contract (reversible hold,
  digest-checked reveal, capture only on matched delivery), backed by a
  challenge and slash lane with deterministic-replay evidence, signed status
  feeds with retraction propagation, quota-fenced redelivery, and pool
  purchasing. Ships as a qualified bounded single-operator profile on SQLite
  and a tenant-isolated hosted PostgreSQL profile behind an authenticated
  edge; cross-organization escrow remains conditional and unbuilt.

### Changed

- `chio-kernel` provides both a synchronous `evaluate_tool_call_blocking`
  entrypoint and an asynchronous `evaluate_tool_call` entrypoint.
- Consolidated the workspace clippy lint policy (`unwrap_used`/`expect_used`
  denied) into a single canonical `[workspace.lints]` block that member crates
  inherit, rather than duplicating it per crate.

### Security

- Narrowed the hosted market runtime database role to read-only on the
  derived spend accumulator, which only a security-definer trigger maintains.
  The role could otherwise forge a low total for its own tenant and pass the
  monthly ceiling that trigger enforces.
- Pinned every GitHub Actions workflow reference to an immutable commit SHA,
  closing the remaining floating `@v*`/`@stable` tags so CI cannot silently
  drift onto a new action release or compiler.
- Hardened the root container image: digest-pinned base images, a non-root
  runtime user, and OCI image labels, matching the sidecar and TEE images.

### Documentation

- Reconciled the `cargo-deny` configuration comments with the real waiver
  counts and rationale, removing stale or misleading caps.

[Unreleased]: https://github.com/backbay-labs/chio/commits/main
