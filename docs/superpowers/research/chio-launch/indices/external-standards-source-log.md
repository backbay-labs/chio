# External Standards Source Log

Status: refreshed source log
Access date: 2026-06-09
Confidence: high for source URLs and naming, moderate for standards that are still moving quickly.

## Official Sources Checked

| Surface | Official source | Launch interpretation |
| --- | --- | --- |
| MCP | https://modelcontextprotocol.io/specification/2025-11-25 | Latest MCP spec page currently redirects to version 2025-11-25. Chio may claim MCP projection only when Chio mediated the call or the envelope binds MCP objects by digest. |
| A2A | https://github.com/a2aproject/A2A/releases ; https://a2a-protocol.org/latest/ | Agent2Agent Protocol v1.0.0 shipped 2026-03-12 and v1.0.1 shipped 2026-05-28 per the official releases page; rechecked 2026-07-02. The prior entry read the version-pinned page https://a2a-protocol.org/v0.3.0/specification/ and wrongly recorded v0.3.0 as latest. Chio may bind A2A task evidence but should not claim A2A itself proves Chio authority. |
| ACP-Client | https://agentclientprotocol.com/protocol/v1/overview | Agent Client Protocol v1 is the correct name for IDE/client agent permission and session flows. Use `ACP-Client`, never bare `ACP`. |
| AG-UI | https://docs.ag-ui.com/concepts/events | AG-UI is an event-stream surface for agent/user interaction. Chio may bind AG-UI event digests as UI evidence, not as authority unless receipts bind the same action. |
| OpenAPI | https://spec.openapis.org/oas/v3.2.0.html | OpenAPI 3.2.0 is the latest published version observed on 2026-06-09. Current Chio docs and parser evidence support a narrower 3.0.x and 3.1.x ingestion story unless 3.2 fixtures are added. |
| x402 | https://www.x402.org/ | x402 is a payment-required/payment verification surface. Chio should treat it as payment evidence under commerce order context. |
| AP2 | https://github.com/google-agentic-commerce/AP2 | AP2 is Agent Payments Protocol sample/spec material. Chio should bind mandates and payment authorization context as subordinate commerce evidence. |
| ACP-Commerce | https://www.agenticcommerce.dev/ | Agentic Commerce Protocol is separate from ACP-Client and should be named `ACP-Commerce` in Chio launch docs. |
| VC 2.0 | https://www.w3.org/TR/vc-data-model-2.0/ | Use for credential data model alignment where Chio artifacts are actually encoded or projected as VCs. |
| BBS | https://www.w3.org/TR/vc-di-bbs/ | Use for BBS Data Integrity cryptosuite alignment. Do not claim BBS privacy unless runtime receipts and verifier profiles enforce it. |
| SD-JWT | https://www.rfc-editor.org/rfc/rfc9901.html | RFC 9901 is the selective disclosure JWT reference. Chio may use SD-JWT evidence lanes where implemented, not as proof of every Chio claim. |
| SD-JWT VC | https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc | Draft SD-JWT VC material can inform passport credential projection, but launch copy should mention draft status if relied on directly. |
| Sigstore | https://docs.sigstore.dev/ | Sigstore can support release and supply-chain transparency claims, not runtime authority claims by itself. |
| SLSA | https://slsa.dev/spec/v1.2/provenance | SLSA v1.2 is current. Avoid treating retired v1.1 text as current launch source. |
| in-toto | https://in-toto.io/Statement/v1 | in-toto Statement v1 can carry supply-chain attestations for Chio builds and tool servers. |
| DSSE | https://github.com/secure-systems-lab/dsse/blob/master/protocol.md | DSSE can wrap signed statements. It is a signing envelope, not a runtime authorization model. |

## Operational Interop Candidate Sources

These sources came from the third-wave interop debate. They widen Agent Web projection subjects, but do not widen Chio authority.

| Surface | Official source | Launch interpretation |
| --- | --- | --- |
| Standard Webhooks | https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md | Standard Webhooks defines a webhook signature convention. Chio may bind signed webhook deliveries and replay windows, but a webhook signature is not Chio authorization. |
| OpenAPI webhooks and callbacks | https://spec.openapis.org/oas/v3.2.0.html | OpenAPI 3.2 can describe webhooks and callbacks. Chio should not claim OpenAPI 3.2 webhook support until fixtures exist. |
| GraphQL | https://spec.graphql.org/ | Chio may project GraphQL schema digest, operation type, operation name, document digest, variables digest, and response digest. |
| GraphQL over HTTP | https://graphql.github.io/graphql-over-http/draft/ | Draft-aligned HTTP projection only. Rechecked 2026-06-11; fixture source versions must stay draft-labeled and must not claim subscription coverage through this draft. |
| AsyncAPI | https://www.asyncapi.com/docs/reference/specification/v3.0.0 | AsyncAPI describes event-driven API applications. Chio may bind event publish or consume evidence when Chio owns the mediation path. |
| CloudEvents | https://github.com/cloudevents/spec/tree/v1.0.2/cloudevents | CloudEvents provides event identity fields such as id, source, type, and specversion. Chio may bind event envelopes, not treat CloudEvents as authorization. |
| WebDriver | https://www.w3.org/TR/webdriver2/ | Browser automation projection source. Draft status should stay visible in launch docs. |
| WebDriver BiDi | https://www.w3.org/TR/webdriver-bidi/ | Bidirectional browser command and event transcript projection source. Draft status should stay visible. |
| Chrome DevTools Protocol | https://chromedevtools.github.io/devtools-protocol/ | Vendor-pinned browser automation evidence only. Do not claim neutral browser-standard conformance through CDP. |
| OAuth 2.0 | https://www.rfc-editor.org/rfc/rfc6749.html | OAuth evidence can support identity and bearer admission checks. OAuth tokens are not Chio capabilities. |
| OpenID Connect Core | https://openid.net/specs/openid-connect-core-1_0.html | OIDC identity evidence can bind issuer, subject, audience, nonce, and ID token verification. It is not tool authority by itself. |
| SCIM | https://www.rfc-editor.org/rfc/rfc7643.html ; https://www.rfc-editor.org/rfc/rfc7644.html | SCIM is identity lifecycle evidence. Deprovisioning can drive capability revocation, but SCIM does not authorize tool execution. |
| SPIFFE/SPIRE | https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE.md ; https://spiffe.io/docs/latest/spiffe-about/overview/ | Workload identity evidence for tool servers, connectors, sidecars, and clusters. SPIFFE does not delegate agent action authority. |
| Kubernetes admission | https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/ ; https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/ | Chio may claim prevent-boundary admission only for Chio-owned admission webhooks. |
| OCI image and distribution specs | https://github.com/opencontainers/image-spec/blob/main/spec.md ; https://github.com/opencontainers/distribution-spec/blob/main/spec.md | Trusted proof should bind digest-pinned image, artifact, descriptor, subject, and referrer evidence, not mutable tags. |
| Slack APIs | https://docs.slack.dev/apis/web-api/ ; https://docs.slack.dev/apis/events-api/ | Provider connector evidence for methods, objects, scopes, event ids, and response digests. Not a neutral agent standard. |
| Google Workspace APIs | https://developers.google.com/workspace/drive/api/guides/about-sdk ; https://developers.google.com/workspace/gmail/api/guides ; https://developers.google.com/workspace/calendar/api/guides/overview | Provider connector evidence for Drive, Gmail, and Calendar objects, methods, scopes, and response digests. |
| Mail and calendar formats | https://www.rfc-editor.org/rfc/rfc5322.html ; https://www.rfc-editor.org/rfc/rfc5545.html ; https://www.rfc-editor.org/rfc/rfc8621.html | RFC 5322, iCalendar, and JMAP Mail can provide message or event object digests where implemented. |

## Standards Wording Precision

Use these terms consistently in launch copy and standards-facing docs:

- `aligns with`: Chio solves a related problem or uses a comparable data shape, but does not claim wire compatibility or conformance.
- `projects into`: Chio emits a bounded external view, envelope, sidecar, digest binding, or credential projection from Chio receipt or Transaction Passport truth.
- `compatible with`: Chio can interoperate with the named protocol surface for the explicitly documented subset and fixture coverage.
- `conforms to`: Chio has a normative conformance basis for the named version, including cited source, parser or verifier behavior, and passing fixtures. Do not use this term for draft, preview, or shape-only support.

## Launch Copy Constraints

Allowed:

- "Chio projects its Transaction Passport into external protocol contexts."
- "Chio binds MCP, A2A, ACP-Client, ACP-Commerce, AG-UI, OpenAPI, AP2, x402, VC, BBS, SD-JWT, Sigstore, SLSA, in-toto, and DSSE evidence by digest, signature, or sidecar envelope where supported."

Rejected:

- "Chio is the universal agent protocol."
- "Every external agent protocol natively verifies Chio authority."
- "ACP support" without qualifier.
- "SLSA v1.1 is the current source."
- "A2A v0.3.0 is the latest official version." (The prior ban on "A2A v1.0.0 conformance" is lifted: its own condition, an official v1.0.0 source, is now satisfied by the 2026-03-12 v1.0.0 release recorded in the A2A row above.)
- "OpenAPI 3.2 support" without 3.2 fixtures.
- "Sigstore proves runtime authorization."
- "A webhook signature proves Chio authorization."
- "OAuth tokens are Chio capabilities."
- "SPIFFE delegates agent authority."
- "Kubernetes admission proves business transaction authority."
- "OCI tags are trusted artifact references."

## Required Refresh Gate

Before public launch, re-open this source set and record:

1. access date;
2. source URL;
3. source version if visible;
4. launch claim affected;
5. any changed terminology or version status.
