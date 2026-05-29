# 07. OAuth Authorization Server: Usage Audit

> **Historical research note:** This document is background for PR 652, not the
> implementation plan of record. Use [00-overview-v2.md](00-overview-v2.md)
> and [18-decision-packet.md](18-decision-packet.md) for current planning.
> OAuth AS implementation tickets remain blocked until a dedicated ADR or
> equivalent decision note is accepted.

## TL;DR

The OAuth 2.1 authorization server at `crates/chio-mcp-remote/src/remote_mcp/oauth.rs` is **live, opt-in scaffolding** - not dead code, not on-by-default, and exercised by tests. The AS is gated by exactly one CLI flag, `--auth-server-seed-file` (see `crates/chio-cli/src/cli/types.rs:1675-1677`). When that flag is absent the AS module compiles in but no routes activate and the AS-only endpoints return 404. When present, six routes mount on the same axum router as the MCP edge and the AS issues Ed25519 JWTs bound to the local resource. Five integration tests in `crates/chio-cli/tests/mcp_auth_server.rs` hit it end-to-end against a real spawned `chio mcp serve-http` process. There is no evidence of an external customer running it in production, and the current planning verdict is narrower than this historical audit: the code is gated scaffolding, not a plan-ready product surface.

Recommended outcome: **(c) keep behind an optional feature flag** - effectively what the codebase already does. Couple that with the rename and scope-clamp from doc 03 so the surface stays bounded to the `chio-governed-rar-v1` profile.

## Static audit findings

### Module entry point and call graph

- The AS is `include!`d into `chio-mcp-remote` at `crates/chio-mcp-remote/src/lib.rs:10` (no feature gate; always compiled).
- `LocalAuthorizationServer` is declared in `crates/chio-mcp-remote/src/remote_mcp/session_core.rs:627`; methods (`authorization_page`, `approve_authorization`, `exchange_token`, `jwks`) live in `oauth.rs:22`.
- Construction: `crates/chio-mcp-remote/src/remote_mcp/http_service.rs:1727-1752` (`build_local_auth_server`). Returns `Ok(None)` if `config.auth_server_seed_path.is_none()` (line 1731). Without the seed, `state.local_auth_server` is `None` (`http_service.rs:198`).

Three downstream crates depend on `chio-mcp-remote`:

- `crates/chio-cli` (Cargo.toml:44) - the only production-facing consumer; calls `remote_mcp::serve_http(...)` at `crates/chio-cli/src/cli/runtime.rs:590-599`, dispatched from `chio mcp serve-http` (`crates/chio-cli/src/cli/dispatch.rs:118, 152`).
- `crates/chio-hosted-mcp` (Cargo.toml:20) - compatibility re-export per `crates/chio-control-plane/tests/runtime_boundaries.rs:22-46`.
- `crates/chio-conformance` (Cargo.toml:145) - exposes a `LocalOAuth` mode that spins the AS up as one of two supported auth postures (`crates/chio-conformance/src/runner.rs:36, 313, 420`; `crates/chio-conformance/src/bin/chio_conformance_runner.rs:77`).

No internal Chio code calls into `LocalAuthorizationServer` other than the four `handle_*` axum handlers and the conformance runner.

### Endpoint surface

Six AS-related routes mount on the same axum router that serves MCP (`http_service.rs:216-239`):

1. `/.well-known/oauth-protected-resource` and `.../mcp` - RFC 9728.
2. `/.well-known/oauth-authorization-server` and `.../{*rest}` - RFC 8414.
3. `/oauth/authorize` (GET, POST) - authorize endpoint plus consent-form approval.
4. `/oauth/token` - token + token-exchange.
5. `/oauth/jwks.json` - JWKS.

The mount is **not** feature-gated; routes are always registered. The four AS-only handlers guard on `state.local_auth_server.as_deref()` (`http_service.rs:813, 829, 846, 859`) and return `404 "local authorization server is not configured for this edge"` when the seed was not provided. Metadata endpoints similarly 404 (`http_service.rs:793-797`). Fail-closed by absence: dead-by-default at runtime.

### Configuration and bootstrap

The AS is enabled by exactly one CLI flag at `crates/chio-cli/src/cli/types.rs:1675-1677`: `--auth-server-seed-file <PathBuf>`. Default `None`. No environment-variable fallback. No `CHIO_*` secret bootstrap.

When set, the seed is loaded or created at `http_service.rs:1734` via `load_or_create_authority_keypair`, which lazily mints an Ed25519 keypair on first run. Adjacent optional knobs gate behavior once the AS is on: `auth_jwt_audience`, `auth_jwt_issuer`, `auth_scopes`, `auth_subject` (single-subject AS, see `docs/operations/HA_CONTROL_AUTH_PLAN.md:101-104`), `auth_code_ttl_secs`, `auth_access_token_ttl_secs`, `public_base_url` (drives the advertised issuer via `resolve_local_auth_issuer` at `http_service.rs:1713-1725`).

No `chio-config` defaults file or YAML scaffold references `auth_server_seed_path`. Purely operator-driven.

### Tests

Substantial coverage at three levels:

- Unit / module tests in `crates/chio-mcp-remote/src/remote_mcp/tests.rs` (75 test fns; 42 references to oauth/authorization/jwks/sender_constraint/token_exchange). Examples: `chio_oauth_discovery_profile_metadata_advertises_sender_constraints` (line 690), `chio_oauth_discovery_validation_rejects_profile_mismatch` (line 738).
- End-to-end integration tests in `crates/chio-cli/tests/mcp_auth_server.rs` (5 `#[test]` fns), each spawning a real `chio mcp serve-http` binary and exchanging real HTTP across the well-known discovery, `/oauth/authorize`, `/oauth/token`, and `/mcp` routes: lines 375, 747, 849, 967, 1101.
- Conformance `LocalOAuth` mode at `chio-conformance/src/runner.rs:313, 420`.

`docs/release/QUALIFICATION.md:337` and `docs/release/PARTNER_PROOF.md:190` list these tests as ship-gating evidence.

### Telemetry

**No AS-specific tracing or metrics** in `oauth.rs` or the AS handlers at `http_service.rs:789-866`. Telemetry in `http_service.rs` is dominated by SSE / session lifecycle warnings (lines 442, 517, 605, 718, 761, 914) plus a single boot-line `info!(listen_addr=...)` at 241. No `tracing::span!` inside OAuth handlers; no Prometheus / OpenTelemetry wiring in the crate. An operator standing up the AS gets zero usage telemetry. The telemetry vacuum is itself evidence: tested capability, not production-hardened.

### Public surface and customer-facing docs

The AS is documented as a public capability in multiple operator-facing places:

- `spec/PROTOCOL.md:1351-1453` defines `chio.oauth.authorization-context-report.v1`, `chio.oauth.authorization-profile.v1`, `chio.oauth.authorization-metadata.v1`, and the well-known issuer path. Normative.
- `docs/standards/CHIO_OAUTH_AUTHORIZATION_PROFILE.md` is a public profile spec ("first normative enterprise-facing authorization profile over governed receipt truth").
- `docs/operations/HA_CONTROL_AUTH_PLAN.md:89-106, 190-199` lists the hosted AS as a shipped deliverable.
- `docs/release/OPERATIONS_RUNBOOK.md:75` documents `--auth-server-seed-file` for operators.
- `docs/research/01-current-state.md:154` says Chio "crossed the 'real hosted auth server' threshold".
- `docs/archive/epics/E7-trust-plane-and-remote-runtime.md:53` lists "richer external identity-provider and federation support around the hosted authorization server" as planned work.

Unambiguously a public, normative product surface.

### Recent activity

`git log --follow` against `oauth.rs` returns six commits. Most recent touching the AS path: `1db38b966 fix(kernel): keep async tool dispatch send-safe` (async migration sweep). The most recent AS-specific stabilization is `7a33559a7 fix: restore grant short-circuit and stabilize auth server tests` on the integration test file. `feat(rename): arc -> chio` and `feat: integrate trajectory 4 lanes` also touched the file recently. No `#[deprecated]` markers, no bit-rot. 1896-line file with dense helpers (DPoP nonce store, RAR validators, transaction-context binding, identity-assertion continuity) - significant recent engineering effort, now in maintenance.

## Outcomes

### (a) Keep + rename + scope-clamp per doc 03

Right when Chio needs a defensible answer for "what when no upstream AS can express governed RAR + transaction context + sender constraint." This AS is the only code path that emits a token bundling `authorization_details` of type `chio_governed_tool`, a `chio_transaction_context` claim, and a `cnf` proof of family `chio_dpop_v1` / `chio_mtls_thumbprint_v1` / `chio_attestation_binding_v1`. Doc 03's clamp keeps it narrow: single-subject, single-resource, operator-approved, opt-in. Test investment is large; PROTOCOL.md and the standards doc are normative; conformance depends on it. Walking back here discards real, working, tested code.

Confidence: medium. Hinges on whether anyone outside Chio consumes AS-issued tokens against the profile.

### (b) Delete entirely

Right if no external party ever issued a token against this AS, no customer has the seed deployed, no downstream consumer of `chio.oauth.authorization-profile.v1` exists, and introspection / external-JWT-bearer / static-bearer (`oauth.rs:783-819`) covers every real posture. Then the AS is theatre - RFC coverage and a richer conformance suite, nothing load-bearing.

Plausible because: zero AS-specific telemetry; no `chio-config` default; one CLI flag with no env-var; conformance `LocalOAuth` is self-consumption; single-subject design is not what enterprises buy. If the "Chio is a PDP, not an IdP" pivot succeeds, this is a 1900-line liability.

Confidence: low. Risks breaking spec contracts that may be partner-load-bearing. Depends entirely on customer signal.

### (c) Keep behind an optional feature flag

Right in essentially every scenario short of full delete. The runtime already behaves as (c): dead-by-default, lights up only on opt-in. Remaining lift is small:

- Move AS-only types (`LocalAuthorizationServer`, `AuthorizationRequest`, `TokenRequestForm`, governed-RAR / transaction-context structs) behind a Cargo feature `auth-server-bridge` on `chio-mcp-remote` so they are not compiled into the default binary.
- Make the router mount conditional on the same feature; 404 path for unconfigured edges remains identical.
- Apply doc 03's rename and scope-clamp.
- Add minimal telemetry (issuance counter, error-class counter, span around `exchange_token`) before any partner depends on it.

Preserves test and conformance coverage, ships lighter defaults, keeps a clean delete path if customer interviews confirm no use. Cost: a few `#[cfg(feature = "...")]` annotations and a router-mount conditional.

Confidence on the recommendation: high. Confidence on whether (c) can later collapse to (b): medium - depends on customer signal.

## Recommendation and open questions

**Primary recommendation: outcome (c) - keep behind an optional Cargo feature, scope-clamped and renamed per doc 03.** This matches the runtime gating that already exists and lowers the surface for the common case.

**Confidence in the live-vs-dead verdict: high.** The AS is live in the sense that an operator who passes `--auth-server-seed-file` gets a working OAuth server with five end-to-end-tested flows and normative spec backing. It is *not* live in the sense of being on by default or instrumented for production ops.

**Confidence in the recommendation: medium.** The static audit cannot tell me whether any customer has run `chio mcp serve-http --auth-server-seed-file ...` against partner traffic, whether the `chio-governed-rar-v1` profile has external consumers, or whether walking the AS back to a feature flag would break any deployment contract. Those questions require customer interviews. Specifically:

1. Are any partners holding tokens minted by the AS? (Check `iss` claims in partner traffic.)
2. Does the conformance suite's `LocalOAuth` mode reflect a real customer scenario or is it a self-test?
3. Would any customer object to receiving the AS as a Cargo-feature-gated build rather than a default-on capability?
4. Is the absence of telemetry a sign of low production usage, or a known gap?

If the answer to (1) is "no" and (3) is "no concerns," outcome (b) becomes a real candidate. If (1) is "yes," outcome (a) becomes mandatory. Until those answers exist, outcome (c) is the lowest-regret move.
