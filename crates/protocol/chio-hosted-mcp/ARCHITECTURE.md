# chio-hosted-mcp architecture

## Overview

`chio-hosted-mcp` is a facade crate with no runtime logic of its own:
`src/lib.rs` holds two `pub use` statements and nothing else. Its production
dependency surface is exactly the two crates it re-exports, `chio-mcp-remote`
and `chio-control-plane`; everything used to exercise the hosted path in
tests (HTTP client, JWT/PKCE signing, SIEM export, kernel test context) is a
dev-dependency, not a production one. The crate holds no trust position of
its own: every fail-closed guarantee on the request path belongs to the
crates it re-exports.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Re-exports `serve_http` and `RemoteServeHttpConfig` from `chio-mcp-remote`, and kernel/store construction, authority keypair lifecycle, policy, trust-control, enterprise federation, `CliError`, and `JwtProviderProfile` from `chio-control-plane`. |

## Boundaries

- Owns no HTTP routing, OAuth 2.0/DPoP admission, session lifecycle, or
  receipt signing. That is `chio-mcp-remote`.
- Owns no authority, receipt, revocation, budget, policy, trust-control, or
  federation implementation. That is `chio-control-plane`.
- Defines no new types, traits, or functions; every re-exported name is
  defined in one of those two crates.
- Product-path verification (auth flows, session lifecycle, session
  isolation, structured error responses, SIEM export) lives in this crate's
  `tests/` directory even though the behavior under test is implemented
  elsewhere.

## Invariants and failure modes

- The `pub use` set is a compatibility contract: `chio-cli` and external
  hosted-MCP integrators depend on these names, so narrowing or removing one
  is a breaking change.
- This crate cannot weaken or strengthen the fail-closed behavior of what it
  re-exports (auth admission, cross-session drift rejection, receipt-or-
  nothing tool dispatch), because no request passes through code defined
  here.
- `#![allow(clippy::result_large_err)]` accommodates `CliError` (defined in
  `chio-control-plane`) at the re-export boundary; it is not a functional
  exception.

## Dependencies

Normal dependencies are re-export sources only: `chio-control-plane`
(operator and trust-control primitives) and `chio-mcp-remote` (the hosted
HTTP/SSE server, itself built on `chio-kernel`, `chio-mcp-adapter`,
`chio-control-plane`, and `chio-egress-contract`).

Dev-dependencies support the `tests/` integration suite only and are not part
of the library's production surface: `chio-kernel` and `chio-siem` (receipt
export verification), `reqwest` (blocking HTTP/SSE client), `tokio` (async
runtime for the SIEM exporter test), `base64`, `serde_json`, `sha2` (PKCE
challenge), and `url`. `chio-core` is aliased: `chio-core = { package =
"chio-core-types", ... }`, so `chio_core::` in the test code resolves to
`chio-core-types`, not the `chio-core` facade crate.
