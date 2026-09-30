---
title: "The Chio Protocol: Signed Capabilities and Receipts for Mediated Tool Execution"
abbrev: "Chio Protocol"
category: std
docname: draft-whelan-chio-protocol-00
submissiontype: IETF
ipr: trust200902
v: 3
date: 2026-10-05
keyword:
  - agent
  - tool
  - capability
  - delegation
  - attenuation
  - receipt
  - mediation
  - MCP
venue:
  mail: agentproto@ietf.org
  arch: https://mailarchive.ietf.org/arch/browse/agentproto/
  github: backbay-labs/chio
author:
  - fullname: Connor Whelan
    organization: Backbay Industries
    email: connor@backbay.io

normative:
  RFC3279:
  RFC4648:
  RFC5234:
  RFC7405:
  RFC8126:
  RFC8259:
  RFC8032:
  RFC8446:
  RFC8785:
  RFC9110:
  RFC9162:
  RFC9449:
  FIPS180-4:
    title: "Secure Hash Standard (SHS)"
    author:
      - org: National Institute of Standards and Technology
    date: 2015-08
    seriesinfo:
      FIPS PUB: 180-4
      DOI: 10.6028/NIST.FIPS.180-4
    target: https://doi.org/10.6028/NIST.FIPS.180-4
  FIPS186-5:
    title: "Digital Signature Standard (DSS)"
    author:
      - org: National Institute of Standards and Technology
    date: 2023-02
    seriesinfo:
      FIPS PUB: 186-5
      DOI: 10.6028/NIST.FIPS.186-5
    target: https://doi.org/10.6028/NIST.FIPS.186-5
  FIPS204:
    title: "Module-Lattice-Based Digital Signature Standard"
    author:
      - org: National Institute of Standards and Technology
    date: 2024-08
    seriesinfo:
      FIPS PUB: 204
      DOI: 10.6028/NIST.FIPS.204
    target: https://doi.org/10.6028/NIST.FIPS.204
  SEC1:
    title: "SEC 1: Elliptic Curve Cryptography, Version 2.0"
    author:
      - org: Standards for Efficient Cryptography Group
    date: 2009-05
    target: https://www.secg.org/sec1-v2.pdf
  ISO4217:
    title: "Codes for the representation of currencies"
    author:
      - org: International Organization for Standardization
    date: 2015-08
    seriesinfo:
      ISO: "4217:2015"
    target: https://www.iso.org/iso-4217-currency-codes.html
  JSON-RPC:
    title: "JSON-RPC 2.0 Specification"
    author:
      - org: JSON-RPC Working Group
    date: 2013-01
    target: https://www.jsonrpc.org/specification
  MCP:
    title: "Model Context Protocol Specification, Version 2025-11-25"
    author:
      - org: Model Context Protocol
    date: 2025-11-25
    target: https://modelcontextprotocol.io/specification/2025-11-25
  SSE:
    title: "HTML Living Standard, Section 9.2: Server-sent events"
    author:
      - org: WHATWG
    date: false
    target: https://html.spec.whatwg.org/multipage/server-sent-events.html

informative:
  RFC7942:
  RFC8693:
  RFC8792:
  RFC9334:
  RFC9396:
  RFC9635:
  I-D.ietf-scitt-architecture:
  I-D.ietf-wimse-arch:
  VC-DATA-MODEL-2.0:
    title: "Verifiable Credentials Data Model v2.0"
    author:
      - org: World Wide Web Consortium
    date: 2025-05-15
    target: https://www.w3.org/TR/vc-data-model-2.0/
  OID4VCI:
    title: "OpenID for Verifiable Credential Issuance 1.0"
    author:
      - org: OpenID Foundation
    date: 2025
    target: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
  OID4VP:
    title: "OpenID for Verifiable Presentations 1.0"
    author:
      - org: OpenID Foundation
    date: 2025
    target: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
  A2A:
    title: "Agent2Agent (A2A) Protocol Specification"
    author:
      - org: Linux Foundation A2A Project
    date: false
    target: https://a2a-protocol.org/latest/specification/
  MACAROONS:
    title: "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud"
    author:
      - name: Arnar Birgisson
      - name: Joe Gibbs Politz
      - name: Ulfar Erlingsson
      - name: Ankur Taly
      - name: Michael Vrable
      - name: Mark Lentczner
    date: 2014-02
    seriesinfo:
      "Network and Distributed System Security Symposium": "NDSS 2014"
    target: https://www.ndss-symposium.org/ndss2014/programme/macaroons-cookies-contextual-caveats-decentralized-authorization-cloud/
  BISCUIT:
    title: "Biscuit, a bearer token with offline attenuation and decentralized verification"
    author:
      - org: Eclipse Biscuit
    date: false
    target: https://doc.biscuitsec.org/reference/specifications
  UCAN:
    title: "User Controlled Authorization Network (UCAN) Specification"
    author:
      - org: UCAN Working Group
    date: false
    target: https://github.com/ucan-wg/spec

--- abstract

This document specifies the Chio protocol, which mediates the tool calls
of software agents. Before a tool runs, a trusted mediator called the
kernel checks that the call is authorized by a signed capability token:
a time-bounded grant of named tools to a specific key. A token can be
delegated only in narrowed form, and each delegation step is bound to
the scope it narrows. The kernel then evaluates local policy, dispatches
the call, and signs a receipt that records the outcome, including
denials, cancellations, and calls that end before completion.

This document defines the capability token and receipt formats, their
canonical encoding and signatures, a framed transport between agent and
kernel, a binding to the Model Context Protocol, and HTTP interfaces for
issuance, delegation, receipt query, and revocation. It also defines
budgets and metering, governed transactions that require declared intent
and approval, and signed checkpoints over batches of receipts.

--- middle

# Introduction {#introduction}

Software agents call tools. They read and write files, query services,
send messages, and spend money on behalf of people and organizations.
In common deployments the agent holds the credentials for those tools
itself. The credentials usually grant more than the task requires, a
sub-agent that needs part of that authority receives a copy of all of
it, and the call leaves nothing that a third party can check to learn
what was authorized and what happened.

Chio separates authority from execution. The agent does not call tools
directly. It sends each call to a kernel, a mediator it does not control,
together with a capability token: a statement, signed by an issuer, that
a subject key may call named tools under stated constraints and limits
until a stated time. The kernel verifies the token, evaluates local
policy, dispatches the call to the tool server only if both permit it,
and signs a receipt that records the outcome. The kernel signs a receipt
for every call it evaluates, including calls it denies, calls that are
canceled, and calls that end before completion.

Delegation in Chio can only narrow authority. A token holder can issue a
token for part of its own scope to another key. Each delegation link is
signed and records a hash of the scope authorized at that step, and each
token carries a proof that its scope is contained in its parent's. A
kernel rejects a token whose claimed parent scope is not bound to its
delegation chain, so an issuer cannot claim a wider parent than it holds.

This document specifies the objects and exchanges that independent
implementations need in order to interoperate: capability tokens,
receipts, their canonical encoding and signatures, the native transport
between agent and kernel, a binding to the Model Context Protocol
{{MCP}}, and the HTTP interface of the trust-control service. It also
specifies three extensions that deployments use to bound spending and
to audit history: budgets and metering, governed transactions, and
receipt checkpoints.

## Design Goals {#goals}

Explicit authority:
: Every mediated call names the capability token that authorizes it.
  The kernel grants no authority that a presented token does not carry.

Narrowing delegation:
: A delegated token cannot grant more than its parent in any dimension:
  tools, operations, constraints, invocation counts, costs, or time.

Fail-closed evaluation:
: A failure to verify a token, a delegation chain, a proof, or a policy
  result denies the call.

A record of every outcome:
: The kernel signs a receipt for each evaluated call. The receipt
  distinguishes allowed, denied, canceled, and incomplete calls.

Portable verification:
: A party that holds a receipt and the kernel's public key can verify
  the receipt without contacting the kernel.

Transport independence:
: The native transport and the MCP binding carry the same capability
  tokens and receipts.

Algorithm agility:
: Keys and signatures identify their own algorithm, so classical and
  post-quantum hybrid signature suites can coexist in one deployment.

## Scope {#scope}

This document does not specify:

* a policy language or a set of guards. Each kernel evaluates its own
  local policy and records the results in receipts;

* how tool servers implement tools;

* a replacement for the Model Context Protocol, the Agent2Agent
  protocol {{A2A}}, or other agent communication protocols. Chio
  mediates calls that such protocols carry;

* an OAuth authorization server;

* payment settlement, standing relationships between operators, or
  portable identity credentials for agents. {{related-work}} lists these
  as candidate companion documents.

## Document Organization {#organization}

{{overview}} describes the roles and walks through one mediated call.
{{encoding}} through {{checkpoints}} define the signed objects: the
encoding and signature rules, capability tokens, receipts, budgets,
governed transactions, and checkpoints. {{native-transport}} through
{{trust-control}} define the exchanges: the native transport, the MCP
binding, and the trust-control interface. {{versioning}} and {{errors}}
define version negotiation and the error model. The remaining sections
cover security, privacy, IANA registrations, and implementation status.
{{examples}} and {{test-vectors}} give examples and test vectors
generated from the reference implementation.

# Conventions and Terminology {#terminology}

{::boilerplate bcp14-tagged}

This document uses the following terms.

Agent:
: A software actor that requests tool calls. The kernel does not trust
  an agent; an agent acts only through the capability tokens it presents.

Kernel:
: The trusted mediator that verifies capability tokens, evaluates
  policy, dispatches permitted calls to tool servers, and signs receipts.

Tool server:
: A service that implements tools, resources, or prompts, and receives
  calls only from a kernel.

Trust-control service:
: The service that issues and revokes capability tokens and answers
  queries over stored receipts.

Capability:
: The authority to call a set of tools, read a set of resources, or use
  a set of prompts, under stated constraints and limits.

Capability token:
: A signed, time-bounded JSON object that grants a capability to a
  subject key ({{capabilities}}).

Issuer:
: The key that signs a capability token.

Subject:
: The key to which a capability token is bound. Only the holder of the
  subject key can exercise the token when the token requires a sender
  proof.

Grant:
: One entry in a capability token's scope: a tool grant, a resource
  grant, or a prompt grant.

Delegation:
: Issuing a capability token from the authority of an existing token.

Delegation link:
: One signed step in a capability token's delegation chain.

Attenuation:
: A narrowing of authority along one or more dimensions: the grants
  themselves, their operations and constraints, invocation counts, cost
  ceilings, budget shares, or time.

Guard:
: A check that the kernel evaluates for a call before dispatch, as part
  of its local policy.

Receipt:
: A signed record of one call that a kernel evaluated ({{receipts}}).

Decision:
: The outcome that a receipt records for a mediated call: `allow`,
  `deny`, `cancelled`, or `incomplete`.

Checkpoint:
: A signed statement by a kernel that commits to a batch of receipts in
  a Merkle tree ({{checkpoints}}).

Code-formatted words such as `expires_at` are protocol element names
and values, which are case-sensitive. JSON is defined in {{RFC8259}}.

# Protocol Overview {#overview}

## Roles and Trust Boundaries {#roles}

{{fig-roles}} shows the roles and the four flows between them.

~~~ aasvg
      +-----------------------+
      | Trust-control service |
      +-----------+-----------+
                  |
                  | (1) capability token
                  v
            +-----------+  (2) call + token   +--------------+
            |   Agent   +-------------------->|    Kernel    |
            |           |<--------------------+              |
            +-----------+  result + receipt   +---+------+---+
                                                  |      |
                                     (3) dispatch |      | (4) receipt
                                                  v      v
                                   +-------------+  +-------------+
                                   | Tool server |  | Receipt log |
                                   +-------------+  +-------------+
~~~
{: #fig-roles title="Roles and Flows"}

The trust-control service issues a capability token to the agent (1).
The agent sends a call, with the token, to the kernel (2). The kernel
verifies the token, evaluates policy, and, if both permit the call,
dispatches it to the tool server (3). The kernel signs a receipt for the
outcome, returns it to the agent with the result, and records it (4).

The kernel is the only trusted component on the call path. It holds the
key that signs receipts and the configuration of trusted issuer keys.
The agent is untrusted: it can present any token it holds, and the
kernel verifies each one. A tool server receives only calls that the
kernel dispatched; it cannot create authority. The trust-control service
is trusted to issue and revoke tokens under the operator's policy.

## A Mediated Call {#mediated-call}

{{fig-call}} shows one call over the native transport ({{native-transport}}).

~~~ aasvg
  Agent                      Kernel                       Tool server
    |                          |                               |
    |  tool_call_request       |                               |
    |  (capability token)      |                               |
    +------------------------->|                               |
    |                          | verify token, chain,          |
    |                          | revocation, grant; run guards |
    |                          |                               |
    |                          |  dispatch                     |
    |                          +------------------------------>|
    |  tool_call_chunk (0..n)  |  output                       |
    |<-------------------------+<------------------------------+
    |                          |                               |
    |                          | sign receipt                  |
    |  tool_call_response      |                               |
    |  (result, receipt)       |                               |
    |<-------------------------+                               |
~~~
{: #fig-call title="One Mediated Call"}

A call proceeds as follows:

1. The agent sends a `tool_call_request` that carries a capability
   token, the target tool server and tool, and the call's parameters.

2. The kernel verifies the token: its signature, its validity interval,
   its delegation chain and attenuation proof, the revocation state of
   the token and of each delegation ancestor, the grant that matches the
   target, and a sender proof when the grant requires one
   ({{capability-verification}}).

3. The kernel evaluates its guards for the call. When budgets apply, it
   reserves the call's cost before dispatch ({{budgets}}).

4. If every check passes, the kernel dispatches the call. Output may
   stream back to the agent as `tool_call_chunk` messages.

5. The kernel signs a receipt over the outcome and returns it in the
   terminal `tool_call_response`. If a check fails, the kernel does not
   dispatch the call; it signs a receipt that records the denial and
   returns it in the same way.

## Protocol Surfaces {#surfaces}

Capability tokens and receipts are the same objects on every surface.
Three surfaces carry them:

| Surface | Carries | Encoding | Defined in |
|---|---|---|---|
| Native transport | Calls from agent to kernel | Length-prefixed canonical JSON | {{native-transport}} |
| MCP binding | Calls from MCP clients to a hosted kernel | JSON-RPC over HTTP with server-sent events | {{hosted-mcp}} |
| Trust-control interface | Issuance, delegation, receipt query, revocation | JSON over HTTP | {{trust-control}} |
{: #tab-surfaces title="Protocol Surfaces"}

The native transport has no initialization exchange. A native agent
obtains its capability tokens out of band, for example from the
trust-control service, and then sends calls.

# Encoding and Cryptography {#encoding}

This section is being written.

# Capability Tokens {#capabilities}

This section is being written.

## Sender Constraint {#sender-constraint}

This section is being written.

## Verification {#capability-verification}

This section is being written.

# Receipts {#receipts}

This section is being written.

# Budgets and Metering {#budgets}

This section is being written.

# Governed Transactions {#governed-transactions}

This section is being written.

# Receipt Checkpoints {#checkpoints}

This section is being written.

# Native Transport {#native-transport}

This section is being written.

# Hosted MCP Binding {#hosted-mcp}

This section is being written.

# Trust-Control Interface {#trust-control}

This section is being written.

# Versioning and Negotiation {#versioning}

This section is being written.

# Error Model {#errors}

This section is being written.

# Security Considerations {#security}

This section is being written.

# Privacy Considerations {#privacy}

This section is being written.

# IANA Considerations {#iana}

This section is being written.

# Implementation Status {#implementation-status}
{:removeinrfc="true"}

This section is being written.

--- back

# Examples {#examples}

{::include generated/appendix-a.md}

# Test Vectors {#test-vectors}

{::include generated/appendix-b.md}

# Relationship to Other Work {#related-work}

This appendix compares Chio with adjacent work. A comparison states
where the problems overlap; it does not claim wire compatibility unless
it says so.

## Agent Communication Protocols

The Model Context Protocol {{MCP}} defines how a client discovers and
calls the tools, resources, and prompts of a server. The Agent2Agent
protocol {{A2A}} defines how agents exchange tasks and messages. Chio
does not replace either. The MCP binding in {{hosted-mcp}} makes a Chio
kernel an MCP server whose tool calls it mediates, so an unmodified MCP
client can call tools through a kernel.

## Delegated Authorization

OAuth 2.0 Token Exchange {{RFC8693}}, Rich Authorization Requests
{{RFC9396}}, and GNAP {{RFC9635}} let an authorization server issue
narrowly scoped, delegated access. A Chio capability token plays a
related role, with three differences. A holder can attenuate a token
without contacting its issuer. Each delegation step is signed and binds
the scope it grants, so a verifier checks the whole chain offline. And
the token is checked by a kernel that also signs a record of each call
it authorized or refused. Chio defines its own capability and receipt
objects and does not claim GNAP compatibility.

DPoP {{RFC9449}} binds an OAuth access token to a key held by the
client. The sender proof in {{sender-constraint}} has the same goal for
capability tokens. It uses a Chio-specific proof format and is not
RFC 9449 on the native transport.

## Capability Tokens

Macaroons {{MACAROONS}}, Biscuit {{BISCUIT}}, and UCAN {{UCAN}} are
bearer or key-bound capability tokens that support offline attenuation.
Chio shares their model of narrowing authority by adding restrictions.
It differs in binding each delegation step to a hash of the scope it
grants, in bounding delegated budgets across sibling tokens
({{budgets}}), and in requiring a mediator that records every outcome
in a signed receipt.

## Workload Identity and Attestation

The WIMSE architecture {{I-D.ietf-wimse-arch}} addresses identity for
workloads that call one another across systems, and RATS {{RFC9334}}
defines how a verifier appraises attestation evidence. A Chio subject
is a public key. A deployment can bind that key to a workload identity
or accept attestation evidence at issuance ({{trust-control}}), but
attestation does not by itself authorize a call ({{security}}).

## Signed Evidence and Transparency

SCITT {{I-D.ietf-scitt-architecture}} defines signed statements and
transparency services that record them. Chio receipts and checkpoints
address a related problem: they let a party check what a kernel
authorized and executed. Chio is not a SCITT profile, and {{checkpoints}}
states the limits of the claims that checkpoints support.

## Verifiable Credentials

W3C Verifiable Credentials {{VC-DATA-MODEL-2.0}}, OpenID for Verifiable
Credential Issuance {{OID4VCI}}, and OpenID for Verifiable Presentations
{{OID4VP}} carry portable claims about a subject. Chio's portable
identity credentials for agents, which the reference implementation
issues through a bounded OID4VCI-compatible profile and presents through
an OID4VP-style profile, are outside the scope of this document.

## Candidate Companion Documents

The reference implementation carries mechanisms that this document does
not specify. Each could be specified in its own document:

* federation: standing relationships between operators, including peer
  handshakes, key pinning, and cross-operator delegation;

* portable identity and reputation credentials for agents;

* settlement of obligations recorded in receipts, and payment channels;

* public anchoring of checkpoints;

* mediation of arbitrary HTTP APIs through a local evaluation service;

* selective disclosure of receipt fields.

# Document History {#history}
{:removeinrfc="true"}

draft-whelan-chio-protocol-00:
: Initial version.

# Acknowledgments {#acknowledgments}
{:numbered="false"}

Chio builds on earlier work on capability-based authorization, in
particular macaroons, Biscuit, and UCAN, and on the IETF's work on
proof-of-possession tokens, workload identity, and transparency
services.
