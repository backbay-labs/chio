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

This document is being written. The abstract replaces this sentence.

--- middle

# Introduction {#introduction}

This section is being written.

# Conventions and Terminology {#terminology}

{::boilerplate bcp14-tagged}

# Protocol Overview {#overview}

This section is being written.

# Encoding and Cryptography {#encoding}

This section is being written.

# Capability Tokens {#capabilities}

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

This appendix is being written.

# Document History {#history}
{:removeinrfc="true"}

This appendix is being written.

# Acknowledgments {#acknowledgments}
{:numbered="false"}

This section is being written.
