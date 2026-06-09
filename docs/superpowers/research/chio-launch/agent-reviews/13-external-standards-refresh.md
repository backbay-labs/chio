# Agent 13 External Standards Refresh

Date: 2026-06-09
Agent: M
Access date for all external sources: 2026-06-09
Scope: standards-alignment audit for Chio launch research docs. This review uses primary or official sources only for external standards facts.
Confidence: high for names, source URLs, and broad claim boundaries; moderate for AP2, Agentic Commerce Protocol, x402, AG-UI, and A2A stability because those ecosystems are moving quickly.

## Executive Verdict

The current launch docs mostly have the right architecture: Chio should be positioned as a detached proof, receipt, and authorization envelope over external protocol objects, not as a replacement for MCP, A2A, ACP-Client, ACP-Commerce, AG-UI, OpenAPI, AP2, x402, VC 2.0, BBS, SD-JWT, Sigstore, SLSA, in-toto, or DSSE.

The unsafe parts are version drift and acronym drift:

1. A2A latest official public spec is Agent2Agent Protocol v0.3.0, not A2A v1.0.0.
2. OpenAPI latest published version is 3.2.0, not 3.1.1. Chio docs and parser evidence still support a narrower 3.0.x and 3.1.x story unless 3.2 fixtures are added.
3. SLSA current spec page is v1.2. The SLSA provenance predicate URI remains `https://slsa.dev/provenance/v1`, but launch sources should not describe v1.1 as current.
4. SD-JWT is RFC 9901. SD-JWT VC remains an IETF draft, so Chio can claim a bounded Chio passport projection, not generic SD-JWT VC wallet interoperability.
5. BBS in Chio is a receipt-projection privacy mechanism. W3C Data Integrity BBS Cryptosuites v1.0 is a Candidate Recommendation Draft, and Chio should not claim W3C VC Data Integrity BBS interoperability unless it actually emits and verifies that cryptosuite.
6. Sigstore verification exists locally, but Chio must not claim full Rekor transparency verification where Merkle inclusion or SET verification is not actually checked.
7. Bare `ACP` is launch poison. Use `ACP-Client` for Agent Client Protocol and `ACP-Commerce` for Agentic Commerce Protocol. Use `AGNTCY-ACP` only for historical Agent Connect Protocol references.

## Current Docs Audited

- `docs/superpowers/research/chio-launch/agent-drafts/08-external-standards-proof-envelope.md`
- `docs/superpowers/research/chio-launch/architecture/08-agent-web-proof-envelope-system.md`
- `docs/superpowers/research/chio-launch/plans/08-agent-web-proof-envelope-implementation.md`
- `docs/superpowers/research/chio-launch/indices/source-map.md`
- `docs/superpowers/research/chio-launch/indices/verification-gates.md`
- `docs/superpowers/research/chio-launch/indices/external-standards-source-log.md`
- `docs/superpowers/research/chio-launch/agent-drafts/02-commerce-order-settlement-context.md`
- `docs/standards/CHIO_PAYMENT_INTEROP_PROFILE.md`
- `docs/standards/CHIO_PORTABLE_TRUST_PROFILE.md`
- `docs/standards/CHIO_PROTOCOL_ALIGNMENT_MATRIX.md`
- `spec/OPENAPI-INTEGRATION.md`
- `spec/PROTOCOL.md`
- `spec/CHIO_BILATERAL_COSIGN_INVOCATION.md`
- `crates/chio-openapi/src/parser.rs`
- `crates/chio-attest-verify/src/sigstore.rs`
- `crates/chio-federation/src/bilateral_dsse.rs`

## Official Source Table

| Surface | Corrected name and status | Official source URLs | Access date |
| --- | --- | --- | --- |
| MCP | Model Context Protocol. Latest spec page redirects to version 2025-11-25. Authorization uses OAuth 2.1 resource-server language, Protected Resource Metadata, authorization server discovery, and Resource Indicators. | https://modelcontextprotocol.io/specification/2025-11-25 ; https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization | 2026-06-09 |
| A2A | Agent2Agent Protocol. Latest official public spec observed as v0.3.0. It defines Agent Cards, JSON-RPC 2.0, gRPC, HTTP+JSON/REST, tasks, streaming, push notifications, and compliance requirements. | https://a2a-protocol.org/v0.3.0/specification/ ; https://a2a-protocol.org/latest/specification/ | 2026-06-09 |
| ACP-Client | Agent Client Protocol v1. Use `ACP-Client` only as Chio launch shorthand. It is a JSON-RPC protocol for clients and agents, including initialization, sessions, tool calls, file system access, terminals, and `_meta` extensibility. | https://agentclientprotocol.com/protocol/v1/overview ; https://agentclientprotocol.com/protocol/v1/initialization ; https://agentclientprotocol.com/protocol/v1/extensibility | 2026-06-09 |
| ACP-Commerce | Agentic Commerce Protocol. Use `ACP-Commerce` only as Chio launch shorthand. Official docs use ACP for a commerce checkout protocol maintained by OpenAI and Stripe and currently described as beta in the public repository. | https://www.agenticcommerce.dev/ ; https://www.agenticcommerce.dev/docs ; https://www.agenticcommerce.dev/docs/reference/checkout ; https://agentic-commerce-protocol.com/docs/commerce/specs/payment ; https://github.com/agentic-commerce-protocol/agentic-commerce-protocol | 2026-06-09 |
| AG-UI | Agent User Interaction Protocol. It is an open, event-based protocol between user-facing frontends and agent backends. Events, messages, tools, and state deltas are evidence surfaces, not Chio authority. | https://docs.ag-ui.com/introduction ; https://docs.ag-ui.com/concepts/events ; https://docs.ag-ui.com/concepts/messages ; https://docs.ag-ui.com/concepts/tools ; https://docs.ag-ui.com/concepts/state | 2026-06-09 |
| OpenAPI | OpenAPI Specification. Latest published version is 3.2.0 dated 2025-09-19. Current Chio docs and parser comments describe OpenAPI 3.0 and 3.1 support; parser code accepts any `3.` prefix but that is not proof of 3.2 conformance. | https://spec.openapis.org/oas/v3.2.0.html ; https://spec.openapis.org/oas/latest.html ; https://spec.openapis.org/oas/v3.1.1.html | 2026-06-09 |
| AP2 | Agent Payments Protocol. Official AP2 docs describe an open protocol for agent payments, available as an extension for A2A and UCP, with standardization continuing in FIDO working groups. Its key model is verifiable digital credentials and mandates, including checkout and payment mandates. | https://ap2-protocol.org/ ; https://github.com/google-agentic-commerce/AP2 | 2026-06-09 |
| x402 | x402. Official docs call it an open payment standard built around HTTP 402 Payment Required. Facilitators verify and settle payments through `/verify` and `/settle` flows. | https://www.x402.org/ ; https://docs.x402.org/introduction ; https://docs.x402.org/core-concepts/facilitator ; https://docs.x402.org/core-concepts/client-server | 2026-06-09 |
| VC 2.0 | W3C Verifiable Credentials Data Model v2.0. W3C Recommendation dated 2025-05-15. It defines an issuer, holder, verifier data model for claims and presentations. | https://www.w3.org/TR/vc-data-model-2.0/ ; https://www.w3.org/TR/2025/REC-vc-data-model-2.0-20250515/ | 2026-06-09 |
| BBS | W3C Data Integrity BBS Cryptosuites v1.0 is a Candidate Recommendation Draft dated 2026-04-07. IRTF CFRG BBS Signatures remains an Internet-Draft observed as draft-irtf-cfrg-bbs-signatures-10. | https://www.w3.org/TR/vc-di-bbs/ ; https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/ | 2026-06-09 |
| SD-JWT | Selective Disclosure for JSON Web Tokens is RFC 9901. It defines SD-JWT, SD-JWT+KB, disclosures, holder presentation, and security/privacy considerations. | https://www.rfc-editor.org/rfc/rfc9901.html | 2026-06-09 |
| SD-JWT VC | SD-JWT-based Verifiable Digital Credentials is an IETF OAuth working group draft. Current draft defines media type `application/dc+sd-jwt`, `typ` value `dc+sd-jwt`, `vct`, issuer metadata, and type metadata rules. | https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/ | 2026-06-09 |
| Sigstore | Sigstore combines Cosign, Fulcio, Rekor, OIDC identity, and trust-root distribution. Rekor is the transparency log. Full launch claims require signature, certificate identity, trust root, and transparency evidence appropriate to the path being claimed. | https://docs.sigstore.dev/about/tooling/ ; https://docs.sigstore.dev/certificate_authority/overview/ ; https://docs.sigstore.dev/logging/overview/ ; https://docs.sigstore.dev/cosign/verifying/verify/ | 2026-06-09 |
| SLSA | Supply-chain Levels for Software Artifacts v1.2 is current. SLSA Build Provenance is an in-toto predicate with predicate type `https://slsa.dev/provenance/v1`; the predicate type deliberately stays at v1 across backwards-compatible minor updates. | https://slsa.dev/spec/v1.2/ ; https://slsa.dev/spec/v1.2/provenance ; https://slsa.dev/spec/v1.2/build-provenance | 2026-06-09 |
| in-toto | in-toto Attestation Framework uses Statement v1 to bind subjects to predicate types and predicate bodies. Stable in-toto spec and attestation framework are distinct. | https://in-toto.io/docs/specs/ ; https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md ; https://github.com/in-toto/attestation/blob/main/spec/v1/envelope.md | 2026-06-09 |
| DSSE | Dead Simple Signing Envelope. It signs arbitrary payload bytes using pre-authentication encoding, authenticates payload type, avoids canonicalization as a requirement of the envelope, and leaves key management out of scope. | https://github.com/secure-systems-lab/dsse ; https://github.com/secure-systems-lab/dsse/blob/master/protocol.md | 2026-06-09 |

## Safe Claim Matrix

| Surface | What Chio may safely claim | What Chio must avoid |
| --- | --- | --- |
| MCP | Chio can mediate MCP-compatible tool/resource/prompt calls through Chio-owned edges and bind MCP protocol objects, session ids, tool names, argument digests, resource binding, and receipts into a detached proof envelope. | Do not claim MCP itself enforces Chio capabilities. Do not call Chio a full OAuth authorization server product unless the product surface and tests exist. Do not freeze MCP auth assumptions before the 2025-11-25 resource metadata and client-id metadata changes. |
| A2A | Chio can bind A2A Agent Card source, skill id, message ids, context ids, task ids, lifecycle state, artifacts, streaming updates, and push-notification config to Chio receipt refs. | Do not claim A2A v1.0.0 conformance. Do not claim A2A tasks are Chio authority. Do not publish a versioned conformance claim without v0.3.0 fixture evidence or a later pinned official version. |
| ACP-Client | Chio can bind Agent Client Protocol v1 permission requests, file access, terminal commands, tool-call updates, sessions, protocol version negotiation, and `_meta` sidecar refs where Chio controls the edge. | Do not say bare `ACP`. Do not imply every observed proxy event is a signed Chio receipt. Do not treat `_meta` as standardized Chio proof semantics. |
| ACP-Commerce | Chio can bind Agentic Commerce Protocol checkout sessions, orders, delegated-payment tokens, max amount, expiry, merchant, PSP, payment token refs, and complete-checkout calls as commerce evidence under a Chio order context. | Do not call it `Agent Commerce Protocol`. Do not confuse it with Agent Client Protocol. Do not treat checkout or payment success as Chio tool authorization. Do not claim non-beta or general conformance without dated API-version fixtures. |
| AG-UI | Chio can bind AG-UI event ids, message ids, tool-call ids, state snapshots, state deltas, frontend tool definitions, mutating classifications, and payload hashes as UI evidence. | Do not claim AG-UI has native Chio receipt semantics. Do not treat UI event observation as authority unless the same action is bound to a verified Chio receipt. |
| OpenAPI | Chio can parse documented OpenAPI 3.0 and 3.1 inputs into Chio manifests, apply Chio vendor extensions, and bind operation id, method, path, request/response digest, route policy, and receipt refs. | Do not call OpenAPI 3.1.1 current. Do not claim OpenAPI 3.2 conformance until 3.2 fixtures and schema semantics are explicitly tested. Do not claim upstream OpenAPI descriptions attest Chio authority. |
| AP2 | Chio can bind AP2 checkout/payment mandate hashes, governed intent hash, amount, currency, merchant, payment method, expiry, and settlement dispatch refs as subordinate commerce evidence. | Do not claim AP2 native Chio support before an AP2-conformant fixture accepts the exact extension or sidecar path. Do not say AP2 authorizes Chio capabilities. |
| x402 | Chio can bind x402 payment requirements, `PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`, facilitator verify/settle responses, resource, amount, chain/network, token, payee, and Chio settlement dispatch refs. | Do not say x402 authorizes a tool call. Do not leak guard or policy internals to facilitators. Do not accept payment success as receipt success. |
| VC 2.0 | Chio can project selected passport or reputation facts into VC-compatible credentials when the artifact actually conforms to VC 2.0 and its securing mechanism. | Do not call every Chio passport claim a W3C VC claim. Do not claim generic VC wallet interoperability for Chio-native JSON receipts. |
| BBS | Chio can say it has or plans BBS-backed selective disclosure over Chio receipt projections if the BBS signature, nonce, disclosed fields, issuer key, and verifier policy are actually checked. | Do not claim W3C Data Integrity BBS Cryptosuites conformance unless Chio emits and verifies that W3C cryptosuite. Do not claim hidden predicate privacy until verifier profiles enforce excess disclosure and predicate semantics. |
| SD-JWT | Chio can use RFC 9901 SD-JWT as a selective disclosure mechanism where implemented. | Do not imply SD-JWT proves all Chio receipt truth. Do not omit holder binding and disclosure policy checks. |
| SD-JWT VC | Chio can claim a bounded Chio passport projection using `application/dc+sd-jwt` where its profile is implemented and verified. | Do not claim generic SD-JWT VC interoperability. Do not hide draft status when relying on SD-JWT VC details. |
| Sigstore | Chio can bind release artifacts, guard artifacts, OCI referrer bundles, Fulcio identity policy, Sigstore bundle digests, and Rekor metadata into supply-chain evidence. | Do not claim full transparency-log verification if Rekor Merkle inclusion or SET verification is not checked. Do not use Sigstore as runtime tool authorization. |
| SLSA | Chio can use SLSA Build Provenance for builds and release artifacts, usually inside in-toto Statements and DSSE or Sigstore envelopes. | Do not use SLSA as a runtime invocation predicate. Do not describe SLSA v1.1 as current. Do not confuse `https://slsa.dev/provenance/v1` with a v1.1-only source. |
| in-toto | Chio can use in-toto Statement v1 to bind subjects to predicates, including Chio-owned predicates such as `chio.bilateral-cosign-invocation.v1`. | Do not claim an unaccepted Chio predicate is already an in-toto standard predicate. Do not rewrite predicate types after signing. |
| DSSE | Chio can use DSSE as the signing envelope for in-toto Statements and Chio-owned statements. | Do not claim DSSE supplies policy, identity federation, transparency, or authorization. It is a signing envelope. |

## Corrections To Carry Into Launch Docs

1. Replace A2A version language.
   - Current risky text: `A2A v1.0.0` in `spec/PROTOCOL.md`.
   - Correct launch language: `Agent2Agent Protocol v0.3.0 as of access date 2026-06-09`, or unversioned `A2A` if no conformance fixture pins v0.3.0.

2. Replace current OpenAPI source language.
   - Current risky text: `OpenAPI 3.1.1 is the official specification`.
   - Correct launch language: `OpenAPI latest published version is 3.2.0 as of access date 2026-06-09; Chio currently documents support for 3.0.x and 3.1.x ingestion and must not claim 3.2 conformance without fixtures`.

3. Narrow OpenAPI parser claims.
   - Local fact: `spec/OPENAPI-INTEGRATION.md` says 3.0.x and 3.1.x, while `crates/chio-openapi/src/parser.rs` accepts any version beginning with `3.`.
   - Safe launch claim: `Chio ingests supported OpenAPI 3.x descriptions into Chio manifests and validates Chio extensions`, not `Chio conforms to every OpenAPI 3.x minor version`.

4. Normalize ACP naming.
   - Use `ACP-Client` for Agent Client Protocol.
   - Use `ACP-Commerce` for Agentic Commerce Protocol.
   - Use `AGNTCY-ACP` only for historical Agent Connect Protocol references.
   - Replace commerce draft phrases such as `ACP delegated payment`, `ACP token`, or `ACP adapter` with `ACP-Commerce delegated payment`, `ACP-Commerce token`, or `Agentic Commerce Protocol delegated payment` unless the referenced file is the Agent Client Protocol edge.

5. Update SLSA source language.
   - Correct source: SLSA v1.2.
   - Correct predicate wording: `SLSA Build Provenance uses predicateType https://slsa.dev/provenance/v1`.
   - Avoid: `SLSA v1.1 is current`.

6. Split SD-JWT and SD-JWT VC.
   - Correct: SD-JWT is RFC 9901.
   - Correct: SD-JWT VC is draft IETF OAuth work and uses `application/dc+sd-jwt` in the current draft.
   - Safe Chio claim: bounded Chio passport projection, not arbitrary credential ecosystem support.

7. Split BBS receipt projection from W3C BBS Data Integrity.
   - Correct: Chio receipt BBS projection is Chio-native unless it uses W3C Data Integrity BBS processing.
   - Correct: W3C VC-DI-BBS is a Candidate Recommendation Draft, not a finished W3C Recommendation.

8. Keep Sigstore claims honest.
   - Local fact: `crates/chio-attest-verify/src/sigstore.rs` states bundle and detached verification paths can mark `rekor_inclusion_verified = false`.
   - Safe launch claim: Chio can verify Sigstore signing identity and bundle metadata on supported paths; full Rekor inclusion proof verification must be claimed only where actually implemented.

9. Keep payment protocols subordinate.
   - AP2 mandates, x402 payment requirements, and ACP-Commerce delegated-payment tokens are commerce evidence.
   - They can satisfy payment or mandate preconditions only after Chio binds them to governed order context and receipt refs.
   - They cannot authorize tool execution by themselves.

## Public Copy Rules

Allowed:

- "Chio attaches a detached proof envelope to external protocol contexts by binding Chio receipts to MCP, A2A, ACP-Client, ACP-Commerce, AG-UI, OpenAPI, AP2, x402, VC 2.0, BBS, SD-JWT, Sigstore, SLSA, in-toto, and DSSE evidence."
- "Chio projects Transaction Passport evidence into external protocol objects by digest, signature, sidecar reference, metadata, or artifact reference where the external protocol safely permits it."
- "External protocols carry or reference Chio proof; the Chio receipt remains the authority for Chio-mediated actions."
- "Payment protocols provide payment or mandate evidence. Chio order context decides whether that evidence satisfies a governed commerce precondition."

Rejected:

- "Chio is the universal agent protocol."
- "All agent protocols verify Chio authority."
- "Every external protocol natively carries Chio proof."
- "ACP support" without qualifier.
- "OpenAPI 3.2 support" without 3.2 fixtures.
- "A2A v1.0.0 conformance" unless a future official A2A v1.0.0 source and fixture exist.
- "AP2 authorized the capability."
- "x402 authorized the tool."
- "Agentic Commerce Protocol settlement proves Chio authorization."
- "BBS proves Chio privacy" without runtime BBS receipts, verifier policy, nonce binding, and over-disclosure rejection.
- "SD-JWT VC support" when the implementation only supports a bounded Chio passport projection.
- "Sigstore proves runtime authorization."
- "SLSA proves runtime invocation authority."
- "in-toto accepted Chio bilateral invocation predicate" unless the predicate is actually adopted upstream.

## Verification Gate For Future Claims

Any launch claim that names an external standard should carry these fields in the proof room or source log:

1. standard name exactly as the official source uses it;
2. Chio shorthand, if any;
3. official URL;
4. access date;
5. official version, revision date, or draft status when visible;
6. local Chio artifact or crate that implements the bridge;
7. external subject digest;
8. Chio receipt id and receipt digest;
9. carrier type: native field, extension field, metadata, header, task artifact, DSSE envelope, Sigstore bundle, sidecar URL, or advisory note;
10. verifier result that separates native external validation from Chio-side validation;
11. negative fixture showing failure on wrong digest, stale authority, unsupported claim, or payment-only proof.

The launch standard for wording should be strict: "aligns with" means adjacent problem shape; "projects into" means sidecar or metadata binding; "compatible" means fixture-backed interop; "conforms" means version-pinned conformance evidence against the official source.
