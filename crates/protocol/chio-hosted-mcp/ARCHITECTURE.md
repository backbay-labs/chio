# chio-hosted-mcp architecture note

## Boundaries

- `src/lib.rs` is a compatibility and product-facing re-export layer for the
  hosted MCP runtime. It should expose the hosted entrypoint and the control
  plane primitives callers need to configure that entrypoint.
- Runtime behavior, HTTP routing, OAuth, DPoP, session lifecycle, receipt
  signing, and resumable session storage are owned by `chio-mcp-remote`.
- Authority, receipt, revocation, budget, federation, policy loading, and trust
  control helpers are owned by `chio-control-plane`.
- Integration tests under `tests/` own hosted-MCP product-path verification:
  auth flows, lifecycle, session isolation, structured errors, SIEM export, and
  fixture server support.

## Pain Points

- The library crate currently lists direct normal dependencies for test helper
  and downstream implementation crates even though its production surface only
  re-exports `chio-control-plane` and `chio-mcp-remote`.
- That makes the hosted compatibility layer look like it owns HTTP, crypto,
  SQLite, Axum, kernel, and adapter implementation details that actually live
  behind the remote runtime boundary.
- Unnecessary normal dependencies increase direct coupling and make future
  public-surface audits noisier.

## Security And API Constraints

- Preserve the public `serve_http(RemoteServeHttpConfig)` re-export.
- Preserve existing `chio-control-plane` re-exports because callers may depend
  on hosted configuration through this crate.
- Do not change hosted MCP wire behavior, OAuth admission, sender proof checks,
  session isolation, lifecycle states, receipt projection, or trust-control
  admin semantics.
- Keep test helper dependencies available only to integration tests unless the
  library surface actually references them.

## Affected Dependents

- `chio-cli` uses the underlying remote runtime directly and should not depend
  on this compatibility crate for implementation details.
- External users of `chio-hosted-mcp` should see the same public re-exports but
  a narrower direct dependency boundary.
- Integration tests still need HTTP, JSON, crypto, and URL helper crates as
  dev-dependencies.

## Planned Improvement

Constrain normal dependencies to the crates actually re-exported by
`src/lib.rs` and move hosted integration-test helper dependencies to
`dev-dependencies`. This is architectural because it makes the compatibility
crate's boundary match its public surface and reduces false ownership of the
remote runtime internals.
