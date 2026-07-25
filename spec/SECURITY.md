# Chio Security And Threat Model

**Version:** 1.0  
**Date:** 2026-04-13  
**Status:** Normative shipped surface

This document defines the standalone threat model for the Chio agent-kernel-tool
trust boundary. It complements [WIRE_PROTOCOL.md](WIRE_PROTOCOL.md): that
document defines message shapes and lifecycle flows; this document defines the
attacks those flows must resist and the minimum transport security posture
required for safe deployment.

The keywords **MUST**, **SHOULD**, and **MAY** are normative in this document.

## 1. Boundary

Chio's security boundary for this document is the path from one caller with
authority material to one mediated tool execution:

1. capability issuance or continuation on the trust-control surface
2. hosted or native delivery of that authority to the kernel
3. kernel admission and policy evaluation
4. transport from the kernel to the selected tool server
5. receipt generation and return

Out of scope:

- broader wallet, passport, and web3 settlement profiles except where they
  directly change sender constraint or delegation semantics at this boundary
- host OS hardening details beyond the transport and process-isolation
  requirements stated here

Primary assets protected by this boundary:

- capability tokens and delegation state
- session identifiers and sender-binding context
- kernel authenticity
- tool-server execution confinement
- receipt integrity and policy verdict provenance
- availability of the mediated runtime

The machine-readable companion artifact for this document is:

- `spec/security/chio-threat-model.v1.json`

## 2. Threat Register

The required threats for the shipped Chio boundary are:

| ID | Threat | Primary surface |
| --- | --- | --- |
| `capability_token_theft` | capability token theft or reuse by an unintended caller | trust-control, hosted MCP, native Chio |
| `kernel_impersonation` | a caller speaks to a fake kernel or hosted edge | hosted MCP, native Chio |
| `tool_server_escape` | the selected tool server exceeds its intended confinement | kernel-to-tool transport, host runtime |
| `native_channel_replay` | a captured native request or proof is replayed on the framed lane | native Chio |
| `resource_exhaustion_dos` | memory, stream, or concurrency pressure denies service | all surfaces |
| `delegation_chain_abuse` | an attacker widens, truncates, or otherwise abuses delegated authority | trust-control, kernel admission |
| `ssrf_via_http_substrate` | an agent crafts tool invocations that target internal network endpoints through the HTTP substrate | HTTP substrate, kernel-to-tool transport |
| `pii_phi_exposure` | a tool response leaks PII or PHI (SSN, MRN, ICD-10 codes, email, etc.) to the agent or downstream consumers | tool response pipeline |
| `agent_velocity_abuse` | a single agent overwhelms the system by issuing requests across many capabilities faster than intended | all surfaces |
| `cumulative_data_exfiltration` | an attacker exfiltrates data through many small requests that individually appear benign | session data flow |
| `behavioral_sequence_attack` | an attacker chains tool invocations in dangerous sequences (e.g., execute then overwrite, or skip required initialization) | session tool sequence |
| `wasm_guard_resource_exhaustion` | a malicious or buggy WASM guard module consumes unbounded CPU or memory | WASM guard runtime |
| `pq_signature_downgrade` | an attacker substitutes a classical-only signature where a post-quantum protected artifact is required | receipt, capability, and compliance-certificate verification |
| `tee_quote_forgery` | an attacker forges, replays, or misbinds a TEE quote to claim execution in a trusted runtime | hosted or native attestation verification |
| `passkey_credential_theft` | an attacker steals or abuses a passkey-backed credential path to obtain fresh capabilities | passkey issuer, capability issuance |
| `audience_confusion` | a capability minted for one audience is presented to another runtime or tool boundary | passkey issuer, kernel admission |
| `weights_hash_spoof` | a provider lies about loaded model weights to satisfy a signed model-card check | provider binding, model-card verification |
| `mobile_attestation_replay` | a replayed App Attest assertion or Play Integrity token bypasses issuer freshness checks | mobile capability issuance |
| `device_key_extraction` | mobile signing material is exported or misclassified outside Secure Enclave, StrongBox, or TEE custody | mobile device custody |
| `play_integrity_token_replay` | a stale Play Integrity JWS is reused to mint a fresh mobile capability | Android capability issuance |

### 2.1 Capability Token Theft

Attack:
an attacker captures a capability token, session artifact, or other authority
handle and attempts to reuse it from a different caller or at a later time.

Existing controls:

- capabilities are signed and time-bounded
- the kernel can require Chio-native DPoP per grant
- the hosted edge can enforce sender-constrained DPoP and mTLS thumbprint
  continuity
- revocation state exists for capability identifiers

Required mitigations:

- sensitive or cross-host flows **SHOULD** require sender constraint rather
  than rely on bearer-only capability use
- operators **SHOULD** pair capability lifetimes with the smallest feasible
  validity window
- deployments that scale across restart or failover **SHOULD** use durable or
  shared replay state for sender proofs

Residual risk:

- compatibility profiles still allow bearer-style capability use when DPoP or
  equivalent sender constraint is not required
- replay protection is weaker across restart or multi-node failover when proof
  nonce state is only process-local

### 2.2 Kernel Impersonation

Attack:
the caller establishes a session or native transport with a malicious service
that pretends to be the Chio kernel or hosted edge.

Existing controls:

- capabilities and receipts are signed artifacts rather than unsigned JSON
- threshold approval proposals are signed by an explicitly trusted active
  policy authority and bind the complete approval window and eligible set
- version negotiation is explicit on the hosted edge and exact-match on the
  native lane
- production tool-server transport is modeled as authenticated transport rather
  than anonymous raw TCP

Required mitigations:

- any cross-host hosted MCP or trust-control deployment **MUST** use TLS
- any cross-host native deployment **MUST** use TLS and **MUST** authenticate
  the remote peer before authority is treated as valid
- operator distributions **SHOULD** pin or otherwise securely provision Chio
  verifier keys, service certificates, or equivalent trust anchors
- approval collectors **MUST** reject stale policy hashes, mutated proposals,
  ineligible or duplicate signer keys, replayed token IDs or digests, and tokens
  outside the signed proposal window

Residual risk:

- plaintext local-development modes do not provide confidentiality or peer
  authenticity
- receipt verification still depends on the deployment's trust-anchor
  distribution discipline rather than one public transparency system

### 2.3 Tool Server Escape

Attack:
an admitted tool server process reads or mutates host state outside its
intended scope, or uses the kernel as a path to broader host compromise.

Existing controls:

- capability scope, tool name, and server id are mediated before invocation
- the kernel decides admission before any tool call reaches the server
- production tool-server transport is modeled as isolated transport rather than
  direct in-process mutation of kernel state

Required mitigations:

- tool servers **MUST** be treated as less trusted than the kernel unless they
  are part of the same reviewed binary and privilege domain
- cross-process or cross-host tool servers **MUST** run behind authenticated
  transport, and cross-host TCP **MUST** use mTLS
- operators **SHOULD** pair Chio mediation with OS or container confinement,
  least-privilege filesystem access, and outbound-network controls where the
  tool is not inherently trusted

Residual risk:

- Chio mediation cannot by itself sandbox arbitrary tool-server code
- a compromised tool process can still abuse whatever host privileges the
  operator granted it outside Chio

### 2.4 Native Channel Replay

Attack:
an attacker captures a native Chio frame or proof and replays it on the
length-prefixed channel to obtain duplicate or unauthorized execution.

Existing controls:

- the native lane is framed and typed, which limits parser ambiguity
- DPoP proofs can bind a request to capability id, tool target, action hash,
  sender key, freshness, and nonce uniqueness
- capabilities are time-bounded and can be revoked

Required mitigations:

- grants for replay-sensitive operations **SHOULD** require DPoP
- cross-host native traffic **MUST** use confidential authenticated transport
  so raw frames and proofs are not exposed on the network
- clustered or restart-tolerant deployments **SHOULD** avoid process-local-only
  nonce registries for high-value flows

Residual risk:

- the native framed lane has no independent in-band anti-replay marker outside
  the sender-proof and capability systems
- non-DPoP grants remain replayable within their validity window if the
  surrounding transport is exposed

### 2.5 Resource Exhaustion DoS

Attack:
an attacker attempts to consume memory, CPU, stream slots, or request capacity
to deny service to valid callers.

Existing controls:

- native frames larger than `16 MiB` are rejected
- hosted notification streams allow at most one active stream per session
- hosted sessions have explicit terminal states rather than silent resumption

Required mitigations:

- deployments **SHOULD** apply request-rate, concurrency, and time-budget
  limits at the hosted and trust-control edges
- operators **SHOULD** bound retained replay buffers, task queues, and
  per-session state
- high-value multi-tenant deployments **SHOULD** pair Chio with upstream load
  shedding and admission control

Residual risk:

- authenticated callers can still consume their own allowed budgets or queue
  share
- Chio's current size and lifecycle checks reduce but do not eliminate all
  asymmetric workload attacks

### 2.6 Delegation Chain Abuse

Attack:
an attacker attempts to widen scope during delegation, truncate lineage,
continue from the wrong parent, or exploit incomplete recursive validation.

Existing controls:

- trust-control delegated issuance already checks a signed delegation policy
  ceiling when one is supplied
- delegation-family aggregate budgets derive their owner and immutable maximum
  from a verified CA-signed direct-root binding
- descendants preserve the root binding and maximum, and combined quota
  capture mutates every applicable quota or none
- core helpers exist for delegation-chain validation and attenuation checks
- revocation state exists for capability identifiers

Required mitigations:

- delegated issuance **MUST NOT** exceed the signed delegation-policy ceiling
- family-scoped invocation limits **MUST NOT** derive authority from presented
  delegation-chain identifiers without the authenticated direct-root token
- kernels **MUST** reject any changed root commitment field, root-binding
  signature, descendant binding digest, or immutable family maximum
- runtime admission **SHOULD** resolve and validate complete parent lineage for
  high-trust delegated flows rather than trust presented metadata alone
- operators **SHOULD** revoke parent capabilities or delegation branches when
  downstream compromise is suspected

Residual risk:

- the current runtime boundary is stronger than unchecked delegation metadata
  but not yet a universally recursive, fail-closed delegated-authority proof
  system at every entry point
- revocation completeness is only as strong as the resolved lineage available
  to the runtime
- cross-node correctness depends on every admission node sharing the same
  durable quota and revocation authority

### 2.7 SSRF via HTTP Substrate

Attack:
an agent crafts tool invocations that target internal network endpoints
(RFC 1918 addresses, loopback, link-local, cloud metadata, Kubernetes service
endpoints) through the HTTP substrate, bypassing network-level controls by
routing requests through a trusted tool server.

Existing controls:

- the InternalNetworkGuard blocks egress to private, reserved, loopback,
  link-local, cloud metadata, and Kubernetes addresses
- DNS rebinding detection catches hostnames embedding private IP patterns
- encoded IP detection blocks hex, decimal, and octal obfuscated addresses
- IPv4-mapped IPv6 addresses are resolved and checked against IPv4 rules

Required mitigations:

- deployments exposing HTTP substrate endpoints **MUST** enable the
  InternalNetworkGuard with DNS rebinding detection
- operators **SHOULD** add deployment-specific internal hostnames to the
  `extra_blocked_hosts` list
- the guard **MUST** fail closed on any address parse ambiguity

Residual risk:

- DNS time-of-check/time-of-use gaps remain: a hostname that resolves to a
  public address during guard evaluation may resolve to a private address
  when the tool server makes the actual request
- the guard operates on hostnames and IPs presented in tool arguments; it
  does not inspect redirects that occur during tool execution

### 2.8 PII/PHI Exposure in Responses

Attack:
a tool response contains personally identifiable information (PII) or
protected health information (PHI) such as SSNs, medical record numbers,
ICD-10 codes, email addresses, or credit card numbers, which the agent then
exfiltrates or includes in outputs visible to unauthorized parties.

Existing controls:

- the ResponseSanitizationGuard scans responses for PII/PHI patterns with
  configurable sensitivity levels and block/redact actions
- pre-invocation scanning prevents PII in request arguments from reaching
  tool servers
- custom patterns can be added for deployment-specific sensitive data

Required mitigations:

- deployments handling healthcare or financial data **MUST** enable the
  ResponseSanitizationGuard at `Medium` sensitivity or higher
- operators **SHOULD** configure `Redact` mode rather than `Block` where
  partial results are acceptable, to reduce information loss
- operators **SHOULD** define custom patterns for any deployment-specific
  identifiers (employee IDs, internal account numbers)

Residual risk:

- regex-based pattern detection is inherently incomplete; novel PII formats
  or obfuscated values (base64-encoded SSNs, split across fields) may evade
  detection
- the ICD-10 pattern may produce false positives on short alphanumeric strings
  in non-medical contexts
- image or binary content in tool responses is not scanned

### 2.9 Agent Velocity Abuse

Attack:
a single agent issues requests at a rate far exceeding intended usage, either
to exhaust system resources, race condition exploit time-sensitive operations,
or generate excessive billing across multiple capabilities.

Existing controls:

- the AgentVelocityGuard enforces per-agent and per-session rate limits using
  token-bucket semantics with configurable burst factors
- separate buckets per agent prevent one agent's exhaustion from affecting
  others
- separate buckets per session prevent cross-session token sharing

Required mitigations:

- multi-tenant deployments **MUST** configure per-agent rate limits
- operators **SHOULD** set per-session limits to bound the damage from a
  single compromised capability
- operators **SHOULD** set burst factors close to 1.0 for high-value
  operations to prevent burst abuse

Residual risk:

- rate limits are process-local; a multi-node deployment without shared state
  allows an agent to consume its full budget on each node
- an attacker controlling multiple agent identities can multiply the effective
  rate by the number of identities

### 2.10 Cumulative Data Exfiltration

Attack:
an attacker extracts sensitive data through many small, individually
innocuous requests that cumulatively transfer a large volume of data out of
the protected system. Each request appears benign to per-request guards.

Existing controls:

- the DataFlowGuard reads cumulative bytes-read and bytes-written totals
  from the session journal and denies requests when configured limits are
  exceeded
- the DataTransferAdvisoryGuard provides early warning signals before hard
  limits are hit
- the session journal tracks all data flow with saturating arithmetic to
  prevent overflow

Required mitigations:

- deployments with sensitive data stores **MUST** configure DataFlowGuard
  limits appropriate to their data classification
- operators **SHOULD** pair DataFlowGuard with DataTransferAdvisoryGuard
  promotion rules to detect gradual exfiltration before the hard limit
- operators **SHOULD** set `max_bytes_total` in addition to individual
  read/write limits to catch mixed-mode exfiltration

Residual risk:

- data flow accounting is per-session; an attacker that establishes many
  short sessions can circumvent per-session limits
- byte counts reflect content-length, not semantic information density;
  compressed data may carry more information than the byte count suggests
- denied requests still count toward cumulative totals; the session is
  effectively terminated once a limit is hit

### 2.11 Behavioral Sequence Attacks

Attack:
an attacker chains tool invocations in dangerous sequences that bypass
safety assumptions. Examples include executing arbitrary code and then
overwriting audit logs, writing to sensitive paths without first reading
the existing content, or repeating a destructive operation many times in
succession.

Existing controls:

- the BehavioralSequenceGuard enforces four types of ordering constraints:
  required predecessors, forbidden transitions, max consecutive invocations,
  and required first tool
- the session journal tracks the complete tool invocation sequence including
  denied invocations

Required mitigations:

- operators **SHOULD** define forbidden transitions for known dangerous
  sequences in their deployment (e.g., `bash` followed by `write_file`)
- operators **SHOULD** require initialization tools as the first tool in
  sessions that depend on setup state
- operators **SHOULD** set max consecutive limits to prevent infinite loops
  on destructive operations

Residual risk:

- the guard cannot prevent dangerous sequences that span multiple sessions
- forbidden transitions only check the immediately preceding tool; a
  dangerous pair separated by an innocent tool in between will not be caught
- the guard operates on tool names, not on the semantic content of the
  invocations

### 2.12 WASM Guard Resource Exhaustion

Attack:
a malicious or buggy WASM guard module enters an infinite loop, allocates
unbounded memory, or performs excessive computation, consuming host resources
and denying service to the kernel.

Existing controls:

- WASM guards execute under a fuel budget (default 10,000,000 units) that
  limits CPU consumption per invocation
- fuel exhaustion immediately terminates the guest and the invocation is
  treated as denied (fail-closed)
- WASM guards execute in isolated linear memory with no access to host
  filesystem, network, or kernel state
- no host callback functions are exposed to the guest

Required mitigations:

- operators **MUST** set fuel limits appropriate to the complexity of their
  custom guards; the default of 10,000,000 units is suitable for simple
  pattern-matching guards
- operators **SHOULD** test WASM guards in advisory mode before enabling
  them as blocking guards in production
- operators **SHOULD** monitor fuel consumption to detect guards that
  consistently approach their fuel limit

Residual risk:

- linear memory allocation within the fuel budget is bounded by the WASM
  runtime's memory limits but not explicitly capped by Chio; a guard that
  allocates large amounts of memory within its fuel budget may increase host
  memory pressure
- compilation of WASM modules is not fuel-metered; a pathologically complex
  module could consume significant CPU during compilation

### 2.13 Post-Quantum Signature Downgrade

Attack:
an attacker replaces or strips post-quantum signature material so a verifier
accepts a classical-only artifact even when policy requires a post-quantum
protected receipt, capability, or compliance certificate.

Existing controls:

- capabilities and receipts are already signed artifacts
- capability, receipt, and compliance-certificate verifier surfaces preserve
  explicit algorithm identity for classical and hybrid signing paths
- capability verification, compliance-certificate verification, the core
  receipt verifier API, and governed parent-receipt validation can enforce
  `allow_classical`, `allow_hybrid`, or `pq_required`

Required mitigations:

- signed artifacts that opt into the post-quantum profile **MUST** carry
  policy-visible algorithm metadata
- receipt, capability, and compliance-certificate verification **MUST** reject
  classical-only artifacts when the configured cryptographic floor requires
  post-quantum protection
- migration tests **SHOULD** cover both classical compatibility and rejection
  of downgraded artifacts under a post-quantum-required policy

Residual risk:

- verifier paths that do not receive a policy `crypto_floor` still use the
  explicit `allow_hybrid` compatibility floor, which accepts classical and
  hybrid receipts but does not require post-quantum protection
- third-party or compatibility callers that invoke compatibility helpers such as
  receipt `verify_signature()` directly are not enforcing a post-quantum floor
  unless they route through the floor-aware verifier API

### 2.14 TEE Quote Forgery or Misbinding

Attack:
an attacker forges, replays, or misbinds TEE quote evidence so a verifier
accepts a runtime as confidential or hardware-attested when the quote does
not correspond to the kernel signing key and receipt root being verified.

Existing controls:

- receipt signatures already provide artifact integrity once the verifier has
  accepted the signing key
- attestation alone is not sufficient authorization under the transport rules
  in this document

Required mitigations:

- quote verifiers **MUST** validate platform evidence for Intel TDX, AMD
  SEV-SNP, and AWS Nitro before accepting confidential-runtime claims
- accepted quotes **MUST** bind report data to the kernel signing key and
  receipt root
- verifiers **MUST** fail closed on malformed, stale, mismatched, or
  unsupported quote evidence
- pinned positive and negative fixtures **SHOULD** cover each supported
  platform backend

Residual risk:

- platform quote verification is planned but not yet implemented in the
  shipped verifier crate
- TEE deployment claims currently depend on external operator evidence rather
  than independent Chio quote verification

### 2.15 Passkey Credential Theft

Attack:
an attacker steals, compromises, or abuses a passkey-backed credential path
and attempts to obtain fresh Chio capabilities from the issuer.

Existing controls:

- capabilities remain signed, time-bounded, and revocable
- kernel admission verifies capability signatures before use

Required mitigations:

- passkey-backed browser flows **MUST** present WebAuthn assertions to a
  server-side issuer rather than mint authority in the browser
- browser clients **MUST NOT** hold root capability or issuer signing material
- issuers **MUST** bind minted capabilities to the credential id, audience,
  scope set, and short expiry
- issuers **MUST** reject failed WebAuthn assertions and treat authenticator,
  challenge, or origin ambiguity as fail-closed

Residual risk:

- a compromised authenticator or issuer account can still request fresh
  capabilities until revocation propagates
- phishing resistance depends on correct relying-party and origin
  configuration by the deployment

### 2.16 Audience Confusion

Attack:
a capability minted for one audience is replayed or presented to another
runtime, hosted edge, or tool boundary that should not accept it.

Existing controls:

- Chio capabilities are signed artifacts with explicit scope and target data
- kernel admission already evaluates the requested tool boundary before
  invocation

Required mitigations:

- passkey-issued capabilities **MUST** carry an explicit audience in the
  signed envelope
- kernel verification **MUST** reject capabilities whose audience does not
  match the target runtime or tool boundary
- custody tests **SHOULD** include cross-audience presentation and envelope
  bit-flip cases

Residual risk:

- deployments that reuse broad audience names across environments can create
  operational confusion even when cryptographic checks are correct

### 2.17 Weights Hash Spoof

Attack:
a provider claims to have loaded one model artifact while actually running a
different weights blob, then relies on that false hash to satisfy model-card
policy.

Existing controls:

- provider binding is mediated by the kernel before tool execution
- Chio already has a shared attestation verifier path for signed provenance
  evidence
- runtime provider bindings persist model-card identity fields and provider
  health fails closed for required model-card modes when signed-card material,
  separately supplied runtime-observed loaded-weight evidence, or a matching
  live card digest is absent

Required mitigations:

- provider binding **MUST** require a signed model card when policy requires
  weights identity
- the signed card **MUST** bind the weights hash to allowed capabilities,
  banned tools, issuer, and validity window
- kernel binding **MUST** reject requested capabilities outside the card's
  allowed set and any requested tool listed as banned

Residual risk:

- until providers expose independently recomputable loaded-weight hashes, a
  malicious provider can lie about the loaded artifact before runtime health
  receives trustworthy provider-side loaded-weight evidence

### 2.18 Mobile Attestation Replay

Attack:
an attacker replays a valid App Attest assertion or Play Integrity token
against a later capability-mint request, bypassing issuer freshness checks.

Existing controls:

- mobile capability issuance is modeled as an issuer-mediated flow rather than
  a local-only bearer token grant
- Chio already treats missing attestation freshness as a deny-or-downgrade
  condition under the transport rules

Required mitigations:

- App Attest assertions and Play Integrity tokens **MUST** bind to a fresh
  issuer challenge or nonce
- the mobile issuer **MUST** reject stale, reused, or audience-mismatched
  attestation evidence fail-closed
- verifier fixtures **SHOULD** include replayed assertion and wrong-audience
  cases before coverage flips to covered

Residual risk:

- platform attestation services cannot compensate for deployments that reuse
  broad audiences or keep replay nonce state only in a volatile local process

### 2.19 Device Key Extraction

Attack:
a compromised mobile process exports or misclassifies signing material that
should remain bound to Secure Enclave, StrongBox, or TEE custody.

Existing controls:

- Chio mobile receipts are signed artifacts and capability issuance can bind
  the audience to a device-attested key id
- the mobile kernel adapter keeps the JSON-in / JSON-out boundary separate
  from platform keystore implementation details

Required mitigations:

- iOS signing keys **MUST** remain in Secure Enclave or App Attest managed
  storage
- Android signing keys **SHOULD** use StrongBox on API 28+ and **MUST** mark
  TEE fallback explicitly on API 26-27
- mobile receipts **MUST NOT** rely on exportable long-lived signing seeds
  when a hardware-backed key is available

Residual risk:

- a fully compromised mobile OS can still manipulate UI, timing, and network
  behavior; M07's custody claim is scoped to non-exportability and evidence
  binding, not total device compromise prevention

### 2.20 Play Integrity Token Replay

Attack:
an attacker reuses a stale Google Play Integrity JWS to mint a fresh mobile
capability after the original issuer nonce should have expired or been
consumed.

Existing controls:

- Play Integrity is only an input to issuer-side minting and does not
  authorize tool calls by itself
- Chio's custody nonce store already has replay-resistant patterns from the
  passkey issuer surface

Required mitigations:

- the Play Integrity verifier **MUST** assert nonce equality against
  issuer-generated nonce state
- accepted Play Integrity nonces **MUST** be consumed once and rejected on
  duplicate presentation
- stale, wrong-nonce, and wrong-package JWS fixtures **SHOULD** be part of the
  M07 verifier corpus before coverage flips to covered

Residual risk:

- Google-signed verdict freshness still depends on issuer nonce durability and
  clock policy; weak deployments can make valid tokens replayable by accepting
  stale nonce state

## 3. Transport Security Requirements

Transport requirements are surface-specific. The matrix below defines the
minimum shipped rules.

| Surface | TLS requirement | mTLS requirement | DPoP requirement | When transport security is absent |
| --- | --- | --- | --- | --- |
| Native Chio direct transport | **MUST** use TLS for any cross-host or untrusted-network deployment. Same-host UDS or loopback development **MAY** omit TLS. | **MUST** use mTLS when the remote peer identity is itself part of the authorization trust decision or when operators cross an untrusted boundary. | **MUST** use DPoP whenever the matched grant requires it. | Only same-host UDS or loopback development is conformant. Otherwise the deployment is nonconformant and capability/session material is considered exposed. |
| Hosted MCP HTTP (`/mcp`) | **MUST** use TLS for any remote or non-loopback deployment. Plain HTTP is only for loopback or explicit test harnesses. | **MUST** use mTLS when the active sender-constrained session profile binds to an mTLS thumbprint. Otherwise mTLS is optional, not universal. | **MUST** use DPoP when the active sender-constrained profile or downstream matched grant requires it. Missing required proof is a denial, not a downgrade. | Remote plaintext deployment is nonconformant. Session ids, proofs, and authority material are treated as observable and replayable. |
| Trust-control HTTP (`/v1/...`) | **MUST** use TLS for any remote or non-loopback deployment. Plain HTTP is only for local development and test harnesses. | **MUST** use mTLS for operator-internal service-to-service deployments that rely on transport identity rather than bearer auth alone. | DPoP is not the primary trust-control transport mechanism today. If sender-constrained issuance inputs are used, the receiving profile **MUST** preserve their required proof semantics downstream. | Remote plaintext deployment is nonconformant and downgrades issuance, revocation, and receipt-query confidentiality and authenticity to local-dev-only posture. |
| Kernel-to-tool transport | Same-host UDS **SHOULD** be preferred. If TCP or another network transport is used, TLS is implicit in the mTLS requirement. | Cross-host or cross-process TCP transport **MUST** use mTLS. Same-host UDS does not need mTLS because the OS path is the authenticated boundary. | DPoP does not replace kernel-to-tool transport authentication. Sender proof binds the caller to the capability, not the tool server to the kernel. | Unauthenticated network transport is nonconformant for production. Tool identity and confidentiality are not established. |

Additional rules:

- Attestation alone never substitutes for sender proof. If a profile binds an
  attestation digest, it **MUST** still pair that with DPoP or mTLS continuity
  over the same request.
- A deployment **MUST NOT** claim production-grade impersonation resistance,
  confidentiality, or replay resistance when it intentionally operates on
  plaintext remote transports.
- If a required transport security property is missing, the implementation
  **MUST** deny the request or restrict the deployment to an explicitly local
  development posture.

## 4. Implementation Guidance

- Same-host development can rely on loopback or UDS transport, but that is a
  deployment carve-out, not a general weakening of the production rules.
- Cross-host deployments should treat sender constraint and transport
  authentication as complementary:
  transport authentication proves the service identity; DPoP proves caller
  possession of the sender-bound key.
- Tool servers are not made safe by transport security alone. Chio mediation
  protects admission and auditability, but host-level sandboxing remains the
  operator's responsibility.

## 5. Machine-Readable Register

`spec/security/chio-threat-model.v1.json` is the normative machine-readable
representation of:

- the minimum threat set
- the mitigation and residual-risk mapping for each threat
- the transport requirements per surface

Implementations and future standards work **SHOULD** treat that artifact as the
stable registry for the shipped threat model.
