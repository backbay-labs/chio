# Agent 18 Agent Web Interop Debate

Date: 2026-06-09
Agent: 18
Role: agent-web and protocol interop maximalist
Scope: additional external surfaces Chio should support or explicitly model in the Agent Web proof envelope.
Status: research debate note
Confidence: high on the architectural boundary, high on official source URLs checked on 2026-06-09, moderate on fast-moving protocol version stability.

## Position

The current Agent Web envelope is directionally correct but too narrow for the surfaces real agents will hit after launch. MCP, A2A, ACP-Client, ACP-Commerce, AG-UI, OpenAPI, AP2, x402, VC, BBS, SD-JWT, Sigstore, SLSA, in-toto, and DSSE cover the agent-protocol and supply-chain spine. They do not cover the daily operational edge where autonomous agents actually mutate the world: webhook callbacks, GraphQL mutations, event-stream APIs, browser automation, desktop automation, SaaS connectors, identity lifecycle, workload identity, cluster admission, and OCI artifact references.

The aggressive answer is not to invent a universal Chio wire protocol. That would be the weak move. The stronger move is to make `chio.agent-web-proof-envelope.v1` accept more external subject families while keeping Chio authority exactly where the existing architecture puts it:

- Chio receipts and capability lineage remain authoritative for Chio-mediated actions.
- External protocol objects are evidence subjects.
- Connector, webhook, browser, RPA, identity, cluster, and OCI objects must be classified as native external proof, Chio-sidecar proof, digest-bound reference, advisory observation, or unsupported.
- If Chio did not mediate the effect before it crossed the trust boundary, the interop report must not say `prevent`.

## What To Add

| Surface | Add or model | Boundary class | Why it matters |
| --- | --- | --- | --- |
| Webhooks | Add as first-class external subjects, split into outbound agent-to-webhook dispatch and inbound governed callback receipt. | `prevent` only when Chio owns dispatch or callback verification; otherwise `detect_only`, `advisory_only`, or `cannot_see`. | Agents trigger Zapier, Make, n8n, Slack, GitHub, Stripe, and custom webhooks constantly. Ignoring this makes the agent-web story academic. |
| GraphQL | Add GraphQL and GraphQL-over-HTTP projection surfaces. | `prevent` for Chio-mediated query or mutation dispatch; `deferred` for subscriptions unless a concrete streaming binding is pinned. | Many SaaS APIs expose GraphQL mutations rather than OpenAPI-described REST. Treating this as generic HTTP loses operation, variable, schema, and field-selection semantics. |
| AsyncAPI | Add as event API description projection, not as a broker bridge by itself. | `prevent` only when paired with Chio event publish or consume mediation. | AsyncAPI is the OpenAPI-shaped description layer for event-driven APIs. It gives Chio channels, operations, messages, and protocol bindings. |
| CloudEvents | Add as event envelope projection. | `prevent` only when Chio mediated producer or consumer path. | CloudEvents supplies stable event identity fields (`id`, `source`, `type`, `specversion`) that map cleanly into evidence graph nodes and replay checks. |
| Browser automation | Add WebDriver and WebDriver BiDi as browser automation external subjects. Keep Chrome DevTools Protocol vendor-pinned and limited. | `prevent` only for Chio-mediated command dispatch; browser capability-only evaluation remains non-authoritative. | The agent web is not only API calls. Browser automation mutates real accounts behind cookies, forms, downloads, and storage. It needs a proof envelope. |
| RPA and desktop automation | Explicitly model as automation transcripts with OS/provider-specific evidence, not as one fake standard. | `prevent` when Chio mediates the action runner; otherwise `advisory_only`. | Enterprise agents will click desktop apps, ERP clients, browser extensions, and remote desktops. There is no single RPA standard to conform to. |
| Email and calendar | Add provider and standards projections for message send/read and calendar create/update. | `prevent` when Chio owns the connector call; `detect_only` for provider audit import. | Email and calendar writes are the highest-volume agent side effects after chat and docs. |
| Slack and Drive connectors | Add SaaS connector projection family. | `prevent` when Chio calls the provider API; `detect_only` for imported events. | Slack and Drive are operational memory and collaboration surfaces. The envelope must bind API method, OAuth scope, tenant, object id, and response digest. |
| OAuth and OIDC | Model as authorization and identity evidence, not as Chio capability tokens. | `prevent` at Chio bearer admission and sender-proof verification; otherwise identity evidence. | Existing Chio OAuth posture already says this is a bounded authorization bridge and verifier, not a general IdP. The Agent Web source log should reflect that. |
| SCIM | Model as lifecycle evidence. | `prevent` for Chio trust-control deprovisioning gates; not runtime tool authority. | Chio already has bounded SCIM lifecycle behavior. It should be evidence for enterprise identity state and revocation, not a runtime permission system. |
| SPIFFE and SPIRE | Model as workload identity evidence. | `prevent` only when a policy requires matching verified workload identity before admission. | Workload identity is the right substrate for tool server, connector, sidecar, and cluster workloads. It is not delegated action authority. |
| Kubernetes admission | Add admission review and webhook decision projection. | `prevent` when Chio admission webhook runs before persistence. | The repo already has Kubernetes admission webhooks. This is a strong deployment trust surface for agent tool servers and guard artifacts. |
| OCI refs | Add OCI image, artifact, distribution, and referrer projection. | `prevent` for cache/load admission; otherwise supply-chain evidence. | The guard registry already uses digest-pinned OCI refs and Sigstore referrers. Agent-web proof should bind deployed tool and guard artifacts by digest, not by tag. |

## Projection Rules

The first implementation should not add new signed artifact schema IDs. Use the three existing Agent Web schema IDs:

- `chio.agent-web-proof-envelope.v1`
- `chio.agent-web.external-projection-manifest.v1`
- `chio.agent-web.interop-verifier-report.v1`

The projection manifest should add a stricter vocabulary in its `source_protocol` and `claim_mapping` values. The architecture doc currently names a generic `source_protocol`; that is enough for the first slice if the values are pinned and linted.

Recommended source protocol values:

- `standard-webhooks`
- `openapi-webhook`
- `graphql`
- `graphql-over-http`
- `asyncapi`
- `cloudevents`
- `webdriver`
- `webdriver-bidi`
- `chrome-devtools-protocol`
- `desktop-rpa`
- `gmail-api`
- `jmap-mail`
- `rfc5322-message`
- `google-calendar-api`
- `icalendar`
- `slack-web-api`
- `slack-events-api`
- `google-drive-api`
- `oauth2`
- `openid-connect`
- `scim`
- `spiffe`
- `kubernetes-admission-review`
- `oci-image`
- `oci-artifact`
- `oci-distribution-referrer`

The interop verifier must report these five classes per claim:

- `native-external-proof`: the external protocol or provider independently proves the claim.
- `chio-sidecar-proof`: Chio proves it beside the external object.
- `digest-bound-reference`: the external object is only bound by digest.
- `advisory-observation`: Chio observed it after the fact or through provider audit import.
- `unsupported`: the projection cannot support the claim.

## Surface Details

### Webhooks

Chio should support two different webhook models and refuse to collapse them:

1. Outbound dispatch: an agent asks Chio to call a provider webhook or workflow endpoint. Chio can prevent misuse because policy runs before the HTTP POST leaves the boundary.
2. Inbound governed callback: Chio exposes a callback endpoint, validates sender signature, timestamp, idempotency key, tenant binding, and event schema before admitting the callback into a workflow.

Third-party ingress abuse against a customer-owned webhook endpoint is outside Chio unless Chio owns that endpoint. This is the n8n Chain D correction in the older protocol-strategy research. Chio can prevent prompt-injection-driven agent-to-webhook exfiltration; it cannot honestly claim to stop arbitrary internet traffic hitting someone else's webhook.

Projection fields:

- endpoint URL digest
- method
- canonical headers digest
- body digest
- provider signature reference
- signature scheme
- timestamp
- replay window
- idempotency key
- event type
- event id
- tenant or workspace id
- Chio receipt refs
- egress contract ref or inbound callback policy ref

Negative fixtures:

- valid Chio receipt but webhook body digest mismatch
- stale webhook timestamp
- duplicate webhook id inside replay window
- missing signature where manifest requires one
- Chio egress receipt bound to one endpoint but delivery sent to another endpoint
- inbound callback accepted without tenant binding

### GraphQL

GraphQL cannot stay hidden inside "HTTP API". A GraphQL mutation can look like one POST to `/graphql`, but the real authority surface is operation name, operation type, document hash, variables hash, selected fields, schema digest, endpoint URL, and auth context.

Chio should bind:

- endpoint URL
- schema digest
- operation type (`query`, `mutation`, `subscription`)
- operation name
- GraphQL document digest
- persisted query hash when used
- variables digest
- extensions digest
- response digest
- error digest
- caller OAuth/OIDC context when present
- Chio receipt refs

GraphQL-over-HTTP is useful but still draft as of the 2026-06-09 source check. Chio can cite it for request and response shape, but launch copy should say "GraphQL projection" or "GraphQL-over-HTTP draft-aligned projection" rather than conformance.

Negative fixtures:

- manifest says `query` but request executes `mutation`
- operation name omitted when the document contains multiple operations
- variables digest mismatch
- persisted query hash points to a different document
- response has partial errors but Chio report marks full success
- GraphQL-over-HTTP subscription claim made through the draft HTTP spec even though subscriptions are out of that draft's scope

### AsyncAPI And CloudEvents

AsyncAPI and CloudEvents solve different problems. AsyncAPI describes event-driven APIs; CloudEvents provides a common event envelope. Chio should use both without pretending either authorizes a tool call.

AsyncAPI projection should bind:

- AsyncAPI document digest
- application id
- server id and protocol
- channel address
- operation id
- operation action (`send` or `receive`)
- message id
- message payload schema digest
- security scheme summary
- protocol binding summary
- Chio event publish or consume receipt refs

CloudEvents projection should bind:

- `specversion`
- `id`
- `source`
- `type`
- `subject`
- `time`
- `datacontenttype`
- data digest
- extension attribute digest
- transport binding digest when present

Negative fixtures:

- CloudEvents `source` plus `id` replay
- CloudEvents `specversion` mismatch
- AsyncAPI operation action reversed from `receive` to `send`
- channel address mismatch
- message payload schema digest mismatch
- event consumed by Chio but projected as producer-side authority

### Browser Automation

Browser automation needs proof because it is a high-risk mutation surface: forms, downloads, cookies, local storage, navigation, and account actions. The existing `chio-kernel-browser` architecture already warns that browser capability-only evaluation never returns authoritative allow; a core allow is downgraded until mediated execution can issue a prevent-boundary receipt. That rule should carry into Agent Web projection.

Chio should add a browser automation source family:

- WebDriver for remote browser control
- WebDriver BiDi for bidirectional command and event streams
- Chrome DevTools Protocol only as a vendor-specific, version-pinned subject

Projection fields:

- browser session id digest
- user context or profile digest
- target URL digest
- command name
- command parameters digest
- DOM selector or accessibility locator digest
- navigation result digest
- screenshot digest when used
- download digest when used
- storage access classification
- network egress summary
- Chio receipt refs

Negative fixtures:

- screenshot-only evidence presented as proof of DOM action authority
- selector digest mismatch
- untrusted URL navigation allowed without scope
- storage read/write action with no storage scope
- file download digest missing
- CDP tip-of-tree command accepted without pinned protocol version

### RPA And Desktop Automation

RPA is not one standard. Chio should explicitly model it as an automation transcript family. The transcript can reference Microsoft UI Automation, Apple Accessibility, AT-SPI, Selenium/Appium, vendor RPA logs, or a Chio-controlled runner transcript, but Chio should not claim generic "RPA standard" conformance.

Projection fields:

- runner id
- host attestation ref
- OS family
- application id
- window or accessibility tree digest
- action type (`click`, `type`, `hotkey`, `read`, `copy`, `paste`, `drag`, `upload`, `download`)
- target locator digest
- input digest
- output observation digest
- redaction profile
- Chio receipt refs

Negative fixtures:

- pixel coordinate accepted without screen or accessibility tree digest
- clipboard write with no data digest
- application focus mismatch
- untrusted runner id
- host attestation missing when policy requires it
- transcript imported after the fact but classified as `prevent`

### Email, Calendar, Slack, And Drive Connectors

These are provider connectors, not neutral agent standards. That is fine. The proof envelope should say so.

Email projection should bind:

- provider API or protocol
- mailbox/account id digest
- message id
- RFC 5322 message digest when available
- thread id
- recipient digest list
- subject digest
- attachment digest list
- send or modify method
- OAuth scope set
- provider response digest
- Chio receipt refs

Calendar projection should bind:

- provider API or iCalendar object digest
- calendar id digest
- event id
- organizer and attendee digest lists
- time range
- recurrence digest
- conferencing link digest
- write method
- OAuth scope set
- Chio receipt refs

Slack projection should bind:

- workspace id digest
- channel id digest
- method name
- message or file id
- request body digest
- response `ok` and error code digest
- OAuth scope set
- event id for Events API imports
- Chio receipt refs

Drive projection should bind:

- drive id or shared drive id digest
- file id
- revision id
- MIME type
- permission change digest
- export or upload digest
- OAuth scope set
- Chio receipt refs

Negative fixtures:

- Slack `ok: false` response projected as successful action
- Gmail send proof without message digest
- calendar event update with time range altered after approval
- Drive permission grant not bound to file id and principal digest
- imported Slack event classified as Chio-mediated dispatch
- OAuth scope missing or broader than projection manifest permits

### OAuth, OIDC, SCIM, SPIFFE, And SPIRE

These should be identity and lifecycle projections. They must not become alternate capability tokens.

OAuth projection should bind:

- issuer
- subject digest
- audience/resource
- client id digest
- scope set
- authorization details digest
- sender constraint summary
- token introspection or JWT verification report digest
- Chio caller identity ref

OIDC projection should bind:

- issuer
- subject digest
- audience
- nonce when present
- authentication time when present
- `acr` or `amr` when policy uses it
- ID token verification report digest

SCIM projection should bind:

- provider id
- SCIM resource id
- user or group digest
- create/update/delete method
- active/inactive state
- deprovisioning receipt ref
- capability revocation refs

SPIFFE/SPIRE projection should bind:

- trust domain
- SPIFFE ID
- SVID type (`x509_svid` or `jwt_svid`)
- bundle digest
- workload attestation ref
- expiry
- Chio workload identity mapping ref

Negative fixtures:

- OAuth token audience does not match protected resource
- OIDC issuer mismatch
- SCIM user deleted but capability still accepted
- SCIM lifecycle event projected as runtime tool authority
- SPIFFE ID malformed or from wrong trust domain
- SPIFFE SVID accepted after expiry

### Kubernetes Admission

Kubernetes admission is one of the cleanest prevent-boundary surfaces because the decision occurs before API server persistence. The repo already has `sdks/k8s/webhooks`, minimal AdmissionReview types, fail-closed capability annotation handling, and tests for missing or invalid capability tokens.

Projection fields:

- cluster id digest
- API group, version, resource, kind
- namespace
- operation
- request UID
- user info digest
- object digest
- admission webhook configuration digest
- allowed boolean
- patch digest when mutating
- warning digest list
- Chio capability token digest
- Chio admission receipt ref

Negative fixtures:

- missing capability annotation
- unsigned or tampered capability
- self-asserted exemption annotation accepted
- required scope taken from pod annotation instead of webhook config
- response UID does not match request UID
- mutating patch not bound by digest

### OCI References

OCI refs are not merely supply-chain decoration. They decide what code, guard, tool server, or proof bundle gets loaded. Chio already has a strong local posture in `chio-guard-registry`: pull references require `oci://`, an explicit registry, and a lowercase `sha256:` digest; Sigstore referrer bundles are verified before cache admission when policy requires them.

Projection fields:

- registry
- repository
- digest
- media type
- descriptor digest
- descriptor size
- artifact type
- subject digest for referrers
- Sigstore bundle digest
- Rekor inclusion status when claimed
- cache admission report digest
- Chio receipt refs

Negative fixtures:

- tag-only OCI ref accepted as trusted
- uppercase or non-sha256 digest accepted
- referrer subject digest mismatch
- Sigstore bundle missing when policy requires it
- Rekor inclusion claimed when verifier report says it was not checked
- cached manifest digest differs from pinned digest

## Rejected Or Deferred Standards

| Surface | Verdict | Reason |
| --- | --- | --- |
| Generic RPA standard conformance | Rejected. | There is no single RPA standard that covers Windows UI Automation, Apple Accessibility, browser DOM automation, and vendor RPA logs. Model transcripts instead. |
| Chrome DevTools Protocol as primary browser standard | Deferred. | CDP is powerful but vendor-specific. The official docs distinguish stable 1.3 from tip-of-tree, and tip-of-tree can break at any time. Use WebDriver and WebDriver BiDi first. |
| GraphQL subscription conformance through GraphQL-over-HTTP | Rejected for launch. | GraphQL-over-HTTP draft text says subscriptions are out of scope. Use AsyncAPI, WebSocket, SSE, or provider-specific subscription evidence when pinned. |
| SaaS connector "standard" claim | Rejected. | Slack, Google Drive, Gmail, and Google Calendar are provider APIs. Chio can project method, object, scope, and response proof, not claim neutral connector standard conformance. |
| SCIM runtime authorization | Rejected. | SCIM is identity lifecycle and provisioning. Chio can use deprovisioning to revoke capabilities, but SCIM resources are not Chio capability tokens. |
| SPIFFE/SPIRE runtime delegation | Rejected. | SPIFFE identifies workloads. It does not authorize a specific agent action or delegate tool scope. |
| Kubernetes admission as transaction proof root | Rejected. | Admission proves cluster object admission, not business transaction authority. It belongs under deployment and workload evidence. |
| OCI tag trust | Rejected. | Tags move. Trusted proof must bind digest-pinned descriptors and referrers. |
| Generic inbound webhook abuse prevention | Rejected. | Chio cannot prevent inbound traffic to endpoints it does not own or mediate. It can prevent agent-to-webhook egress misuse and govern Chio-owned callback endpoints. |

## Exact Source Log Updates Needed

Add these rows to `docs/superpowers/research/chio-launch/indices/external-standards-source-log.md` after the current DSSE row. Access date for all rows: 2026-06-09.

| Surface | Official source | Launch interpretation |
| --- | --- | --- |
| Standard Webhooks | https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md | Community/open webhook signature convention with `webhook-id`, `webhook-timestamp`, and `webhook-signature`. Chio may bind signed webhook deliveries and replay windows, but must not treat all webhooks as Standard Webhooks unless the fixture uses those headers. |
| OpenAPI webhooks and callbacks | https://spec.openapis.org/oas/v3.2.0.html#webhooks-object ; https://spec.openapis.org/oas/v3.2.0.html#callback-object | OpenAPI can describe outbound webhook and callback shapes. Chio may bind OpenAPI-described webhook subjects by digest. Current Chio OpenAPI parser claims remain narrower until 3.2 webhook fixtures exist. |
| GraphQL | https://spec.graphql.org/ | Latest release observed on 2026-06-09 is September 2025, with a working draft dated 2026-06-04. Chio may project GraphQL operations, schema digest, document digest, operation name, variables, and response digest. |
| GraphQL over HTTP | https://graphql.github.io/graphql-over-http/draft/ | Stage 2 draft. Use only as draft-aligned HTTP request and response projection. Do not claim stable conformance or subscription coverage through this draft. |
| AsyncAPI | https://www.asyncapi.com/docs/reference/specification/v3.0.0 | AsyncAPI 3.0.0 describes event-driven API applications, servers, channels, operations, and messages. Chio may bind event publish and consume evidence when Chio owns the mediation path. |
| CloudEvents | https://github.com/cloudevents/spec/tree/v1.0.2/cloudevents ; https://github.com/cloudevents/spec/blob/main/cloudevents/spec.md | CloudEvents uses `specversion` value `1.0` for the current 1.0 family and gives stable `id`, `source`, and `type` identity fields. Chio may bind event envelopes, not treat CloudEvents as authorization. |
| WebDriver | https://www.w3.org/TR/webdriver2/ | W3C Working Draft dated 2026-05-28. Chio may use it as browser automation projection source, with draft status visible in launch docs. |
| WebDriver BiDi | https://www.w3.org/TR/webdriver-bidi/ | W3C Working Draft dated 2026-06-01. Chio may bind bidirectional browser command and event transcripts, with draft status visible. |
| Chrome DevTools Protocol | https://chromedevtools.github.io/devtools-protocol/ | Vendor-maintained Chromium protocol. Stable 1.3 is old and tip-of-tree changes frequently. Chio should only claim vendor-pinned CDP projection, not neutral browser standard conformance. |
| Microsoft UI Automation | https://learn.microsoft.com/en-us/windows/win32/winauto/entry-uiauto-win32 | Windows accessibility and automated testing framework. Chio may use it as an OS-specific RPA evidence source, not as cross-platform RPA standard coverage. |
| Apple Accessibility AXUIElement | https://developer.apple.com/documentation/applicationservices/axuielement_h | Apple Accessibility API reference page. Chio may use it as an Apple-platform automation evidence source, with implementation-source refresh required before ticketing because the public page requires JavaScript. |
| OAuth 2.0 | https://www.rfc-editor.org/rfc/rfc6749.html | OAuth 2.0 access tokens are limited-access HTTP authorization artifacts. Chio may consume, verify, or narrowly bridge OAuth evidence, but Chio capabilities remain separate. |
| OpenID Connect Core | https://openid.net/specs/openid-connect-core-1_0.html | OIDC Core 1.0 is identity on top of OAuth 2.0. Chio may bind issuer, subject, audience, nonce, and ID token verification evidence, not treat OIDC identity as tool authority. |
| SCIM core schema | https://www.rfc-editor.org/rfc/rfc7643.html | SCIM core schema represents users and groups for identity management. Chio may bind enterprise identity lifecycle evidence. |
| SCIM protocol | https://www.rfc-editor.org/rfc/rfc7644.html | SCIM protocol is HTTP-based identity management. Chio may bind create, update, delete, active state, and deprovisioning evidence. |
| SPIFFE/SPIRE | https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE.md ; https://spiffe.io/docs/latest/spiffe-about/overview/ | SPIFFE supplies workload identity through SPIFFE IDs, SVIDs, and Workload API. Chio may bind workload identity and trust domains, not use SPIFFE as delegated action authority. |
| Kubernetes admission | https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/ ; https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/ | Admission controllers intercept API server requests after authentication and authorization but before persistence. Admission webhooks exchange AdmissionReview JSON. Chio may claim prevent-boundary admission only for Chio-owned admission webhooks. |
| OCI image spec | https://github.com/opencontainers/image-spec/blob/main/spec.md | OCI image spec descriptors provide media type, metadata, and content address for referenced content. Chio should bind image and artifact evidence by digest. |
| OCI distribution spec | https://github.com/opencontainers/distribution-spec/blob/main/spec.md | OCI distribution pulls manifests by digest or tag; trusted Chio proof should require digest-pinned refs and explicit referrer subject matching where claimed. |
| Slack Web API | https://docs.slack.dev/apis/web-api/ | Slack Web API uses HTTP RPC-style methods and OAuth bearer tokens. Chio may bind method, workspace, object ids, request and response digests, and scopes. |
| Slack Events API | https://docs.slack.dev/apis/events-api/ | Slack Events API delivers subscribed events over HTTP endpoints or Socket Mode and ties events to OAuth scopes. Chio may bind imported event ids and scope context as event evidence. |
| Google Drive API | https://developers.google.com/workspace/drive/api/guides/about-sdk | Google Drive API is a REST API for Drive storage. Chio may bind file, revision, permission, upload, export, and OAuth scope evidence. |
| Gmail API | https://developers.google.com/workspace/gmail/api/guides | Gmail API is a REST API for authorized mailbox access and sending mail. Chio may bind message ids, message digests, send/modify methods, and scopes. |
| Google Calendar API | https://developers.google.com/workspace/calendar/api/guides/overview | Google Calendar API is a REST API exposing most Calendar web interface features. Chio may bind calendar ids, event ids, attendee and time-range digests, and scopes. |
| RFC 5322 Internet Message Format | https://www.rfc-editor.org/rfc/rfc5322.html | RFC 5322 defines Internet message format. Chio may bind RFC 5322 message digests as email evidence, while transport and mailbox provider behavior remain separate. |
| iCalendar | https://www.rfc-editor.org/rfc/rfc5545.html | RFC 5545 defines iCalendar objects and `text/calendar`. Chio may bind event object digests and recurrence evidence. |
| JMAP Mail | https://www.rfc-editor.org/rfc/rfc8621.html | JMAP Mail defines mail objects, submission, and push capability over JMAP. Chio may use it as a standards-based mail provider projection where implemented. |

## First Slice

Build the first slice as `cloud-event-webhook-projection`.

Reason: it covers the biggest missing operational surface with the least new schema churn. It also exercises the exact distinction Chio must get right: external event proof versus Chio authority.

Positive fixture:

1. Generate one Chio-mediated outbound webhook dispatch receipt.
2. Use a Standard Webhooks delivery shape carrying a CloudEvents payload.
3. Bind endpoint URL digest, headers digest, body digest, `webhook-id`, `webhook-timestamp`, `webhook-signature`, CloudEvents `specversion`, `id`, `source`, `type`, and data digest.
4. Emit `chio.agent-web.external-projection-manifest.v1` with `source_protocol: standard-webhooks` and nested `claim_mapping` for CloudEvents fields.
5. Emit `chio.agent-web-proof-envelope.v1` over the webhook delivery digest and receipt ref.
6. Emit `chio.agent-web.interop-verifier-report.v1` that marks:
   - webhook signature as `native-external-proof`;
   - Chio receipt authority as `chio-sidecar-proof`;
   - CloudEvents identity as `digest-bound-reference`;
   - any "webhook authorized the action" claim as `unsupported`.

First-slice negative fixtures:

- `webhook-body-digest-mismatch`
- `webhook-signature-missing`
- `webhook-timestamp-stale`
- `webhook-id-replay`
- `cloudevents-source-id-replay`
- `cloudevents-specversion-mismatch`
- `unsupported-native-authority-claim`
- `sidecar-proof-presented-as-native`
- `wrong-projection-protocol`
- `receipt-ref-not-found`

Required first-slice source-log update:

- Add `Standard Webhooks`
- Add `CloudEvents`
- Add `OpenAPI webhooks and callbacks` as a related source, but do not claim OpenAPI 3.2 webhook support until a separate OpenAPI 3.2 fixture exists.

No artifact-registry update is required for the first slice because the existing Agent Web schema IDs are enough.

## Second Slice

Build `graphql-mutation-projection` after the webhook slice.

Reason: it proves Chio can model semantic API actions that look like generic HTTP but are not semantically generic.

Positive fixture:

- one Chio-mediated GraphQL mutation;
- endpoint URL digest;
- schema digest;
- operation name;
- operation type `mutation`;
- document digest;
- variables digest;
- response digest;
- one Chio receipt ref;
- interop report marking GraphQL object facts as digest-bound and Chio receipt authority as sidecar proof.

Negative fixtures:

- mutation projected as query;
- multiple operations with omitted operation name;
- variable digest mismatch;
- persisted query hash mismatch;
- GraphQL response with errors projected as full success;
- GraphQL-over-HTTP draft conformance claim without source-log draft status.

## Registry Impact

First and second slices need no new signed schema IDs.

If browser automation or desktop RPA becomes a launch surface, add a separate registry-owner decision for:

- `chio.agent-web.automation-transcript.v1`

That artifact would be justified only if the verifier starts trusting Chio-signed automation transcripts directly. Until then, browser and RPA transcripts can remain external subjects bound by digest inside the existing Agent Web envelope.

## Copy Guardrails

Allowed:

- "Chio attaches proof envelopes to webhook, GraphQL, event, browser automation, connector, identity, workload, Kubernetes admission, and OCI artifact contexts."
- "Chio binds external event and connector objects by digest and separates external proof from Chio receipt authority."
- "Chio can govern agent-to-webhook dispatch when the dispatch path runs through Chio."
- "Chio can verify Chio-owned inbound callbacks before admitting them into a workflow."

Rejected:

- "Chio secures all webhooks."
- "A webhook signature proves Chio authorization."
- "GraphQL over HTTP gives Chio subscription conformance."
- "Slack/Drive/Gmail/Calendar are standard agent protocols."
- "OAuth tokens are Chio capabilities."
- "SCIM authorizes tool execution."
- "SPIFFE delegates agent authority."
- "Kubernetes admission proves business transaction authority."
- "OCI tags are trusted artifact references."
- "CDP support means browser-standard conformance."

## Final Verdict

Chio should widen the Agent Web envelope, but not widen Chio authority. The launch package should add webhook, GraphQL, AsyncAPI, CloudEvents, browser automation, RPA, email/calendar, Slack/Drive, OAuth/OIDC, SCIM, SPIFFE/SPIRE, Kubernetes admission, and OCI refs as explicit external subject families. The first concrete slice should be Standard Webhooks plus CloudEvents because it is small, operationally real, and forces the verifier to separate external signature proof from Chio receipt authority.
