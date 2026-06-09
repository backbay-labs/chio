# Agent Web Proof Envelope Implementation Plan

Status: implementation plan
Depends on: `../architecture/08-agent-web-proof-envelope-system.md`
Confidence: moderate.

## Objective

Make Chio proof portable across the agent web while keeping external-standard claims exact.

## Registry Acceptance

Agent Web envelopes, projection manifests, and interop verifier reports are detached Chio artifacts. Register them through `../indices/artifact-registry.md` and `../architecture/09-integration-contracts.md` before accepting them in a verifier. Treat external protocol objects as evidence subjects, not as replacements for Chio authority.

## Standards Source Gate

Use `../indices/external-standards-source-log.md` as both the input and update target for this plan. Any launch claim that names a standard must include the official source URL, access date, version or draft status when visible, Chio projection surface, verifier result, and at least one negative fixture.

## Phase 0 - Taxonomy And Copy Lint

Tasks:

1. Add taxonomy doc for MCP, A2A, ACP-Client, ACP-Commerce, AGNTCY-ACP, AG-UI, OpenAPI, AP2, x402, VC, BBS, SD-JWT, Sigstore, SLSA, in-toto, and DSSE.
2. Add copy lint that rejects bare `ACP`.
3. Add lint for "universal agent protocol" and "native proof across all protocols" style claims.
4. Add docs language for envelope versus protocol replacement.

Tests:

- bare `ACP` in launch docs fails;
- `ACP-Client` and `ACP-Commerce` pass;
- overbroad universal-protocol claim fails.

## Phase 1 - Envelope And Manifest Schemas

Tasks:

1. Define `chio.agent-web-proof-envelope.v1`.
2. Define `chio.agent-web.external-projection-manifest.v1`.
3. Define `chio.agent-web.interop-verifier-report.v1`.
4. Add canonical digest and signature binding rules.

Tests:

- valid envelope passes;
- missing external subject digest fails;
- unsupported claim without limitation fails.

## Phase 2 - Projection Library

Tasks:

1. Implement projection interface.
2. Add MCP projection.
3. Add A2A projection.
4. Add ACP-Client projection.
5. Add ACP-Commerce projection.
6. Add AG-UI projection.
7. Add OpenAPI projection.
8. Add AP2 and x402 projection.
9. Add VC/BBS/SD-JWT evidence projection.
10. Add Sigstore/SLSA/in-toto/DSSE supply-chain projection.

Tests:

- each projection emits manifest and envelope;
- each projection verifies digest binding;
- each projection marks unsupported fields.

## Phase 3 - Interop Verifier

Tasks:

1. Verify external object digest.
2. Verify Transaction Passport ref.
3. Verify projection manifest.
4. Verify Chio claim refs.
5. Emit limitation-aware interop report.

Tests:

- wrong external digest fails;
- wrong protocol version fails;
- sidecar-only claim is reported as sidecar-only;
- missing required external signature fails when manifest requires it.

## Phase 4 - Proof Room And CLI

Tasks:

1. Add CLI commands for envelope generation and verification.
2. Add Proof Room external envelope tab.
3. Show external object, Chio claim refs, limitations, and unsupported claims.
4. Add fixture catalog.

Tests:

- valid interop fixture renders;
- invalid digest fixture renders clear failure;
- unsupported claim appears in limitations.

## Phase 5 - Standards Review Gate

Tasks:

1. Re-check current official docs before launch for protocol versions and naming.
2. Record source URLs and access dates in a standards source file.
3. Add review checklist for all external claims.
4. Require a maintainer sign-off for any claim that says "standard", "compatible", "native", or "universal".

Exit criteria:

- external proof language is precise;
- every external protocol projection has a manifest and negative fixture;
- Chio is positioned as proof layer and envelope, not protocol replacement.
