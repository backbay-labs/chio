# Contributing to Chio

Thanks for your interest in contributing to Chio, the runtime and trust-control
layer that governs tool access for AI systems. This guide explains how to build,
test, and submit changes so that they land cleanly.

Chio is pre-release. Interfaces and wire surfaces can still change; when they do,
they must remain consistent with the normative protocol specification.

## Before you start

Please read the project guides first. They are the source of truth for
architecture and conventions, and this document defers to them:

- [AGENTS.md](AGENTS.md): canonical overview, the five components, the crate map,
  conventions, and key files. Read it first.
- [spec/PROTOCOL.md](spec/PROTOCOL.md): the normative protocol specification. Any
  wire-level change must agree with it.
- [docs/README.md](docs/README.md): index of the broader documentation set
  (architecture notes, runtime boundaries, integration guides).

## Reporting bugs and proposing changes

- Search existing issues before opening a new one.
- For bugs, include a minimal reproduction, the expected behavior, the actual
  behavior, and your toolchain version (`rustc --version`).
- For larger features or any change to the wire protocol, open an issue to
  discuss the design before sending a pull request. Wire-level changes must be
  reflected in [spec/PROTOCOL.md](spec/PROTOCOL.md).

Do not open public issues for security vulnerabilities. Follow the coordinated
disclosure process in [SECURITY.md](SECURITY.md) instead.

## Development setup

Chio is a Rust workspace. You need a recent Rust toolchain; the minimum
supported version is pinned in [rust-toolchain.toml](rust-toolchain.toml).
Using `rustup`, the pinned toolchain (including the `clippy` and `rustfmt`
components) is installed automatically when you build inside the repository.

```bash
git clone https://github.com/backbay-labs/chio.git
cd chio
cargo build --workspace
```

A cold `cargo build --workspace` can take several minutes.

## The verification gate

Run the full gate locally before you declare a change ready and before you open
a pull request. All four commands must pass:

```bash
cargo build --workspace && \
cargo test --workspace && \
cargo clippy --workspace -- -D warnings && \
cargo fmt --all -- --check
```

This is the minimal verification gate. Continuous integration runs a broader
PR-tier lane (structural checks, hygiene scripts, and the wasm-guards test
split). Equivalent shortcuts:

```bash
make help           # list all Makefile targets by tier
make gate           # minimal gate above (build, test, clippy, fmt-check)
make ci             # PR-tier CI (mirrors .github/workflows/ci.yml check job)
make codegen-check  # schema/codegen drift gate for spec changes
```

For the heavier local gate used before release qualification, run `make
ci-workspace`.

## House rules

- **Fail-closed.** Errors during evaluation deny access. Invalid policies are
  rejected at load time. New code must preserve this posture: never let an error
  path widen authority or silently allow a call.
- **No `unwrap` or `expect`.** Clippy enforces `unwrap_used = "deny"` and
  `expect_used = "deny"` across the workspace. Return and propagate errors
  instead.
- **Canonical JSON.** Signed payloads use canonical JSON (RFC 8785). Do not
  change the serialization of a signed structure without coordinating the wire
  and conformance impact.
- **No em dashes.** Do not use the em dash character (U+2014) anywhere in code,
  comments, or documentation. Use hyphens (`-`) or parentheses.

## Commit messages

Chio follows [Conventional Commits](https://www.conventionalcommits.org/). Use a
type prefix such as `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, or
`ci:`. Write commit subjects in the imperative mood and keep them focused on a
single logical change.

Examples:

```text
feat(kernel): add budget exhaustion verdict
fix(guards): deny on malformed egress allowlist entry
docs(spec): clarify capability continuation semantics
```

## Pull requests

1. Branch from `main`.
2. Keep the change focused; split unrelated work into separate pull requests.
3. Run the full verification gate above and confirm it passes.
4. Update documentation and, for any wire-level change,
   [spec/PROTOCOL.md](spec/PROTOCOL.md) in the same pull request.
5. Add or update tests that cover the change.
6. Describe what changed and why in the pull request body, and link any related
   issue.

Reviewers may ask for changes; please keep the discussion focused on the code
and the design.

## License of contributions

By contributing to Chio, you agree that your contributions are licensed under
the [Apache License, Version 2.0](LICENSE), the same license that covers the
project.

## Code of conduct

Participation in this project is governed by the
[Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you
are expected to uphold it. Report unacceptable behavior to
[security@backbay.io](mailto:security@backbay.io).
