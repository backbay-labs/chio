# Chio OAuth Authorization Profile

Status: normative profile reference only. Hosted OAuth AS product work remains
blocked until a dedicated ADR or equivalent decision note is accepted. This
document defines the shape any future hosted OAuth-family surface must project
from governed receipts; it does not make that hosted surface plan-ready.

This document defines Chio's first normative enterprise-facing authorization
profile over governed receipt truth.

## Scope

Chio maps signed governed receipt metadata into one narrow OAuth-family
authorization surface:

- report schema: `chio.oauth.authorization-context-report.v1`
- profile schema: `chio.oauth.authorization-profile.v1`
- profile id: `chio-governed-rar-v1`

The profile is intentionally derived. Chio does not mint a second mutable
authorization document alongside governed receipts.

## Authoritative Source

The authoritative source for this profile is the signed
`metadata.governed_transaction` block carried on Chio receipts.

If Chio cannot project a governed receipt into the profile truthfully, the
authorization-context export fails closed instead of emitting a partial or
best-effort projection.

## Authorization Details Mapping

Chio currently supports three `authorizationDetails[*].type` values:

- `chio_governed_tool`
  - primary governed tool action
  - `locations`: target tool server identifiers
  - `actions`: target tool names
  - `purpose`: optional operator or policy-readable purpose
  - `maxAmount`: optional explicit spend bound from the governed intent
- `chio_governed_commerce`
  - governed commerce scope
  - `commerce.seller`: seller or payee identifier
  - `commerce.sharedPaymentTokenId`: shared payment token or equivalent
    approval reference
- `chio_governed_metered_billing`
  - post-approval metered-billing envelope
  - `meteredBilling.settlementMode`: authorization-settlement posture
  - `meteredBilling.provider`: quote issuer
  - `meteredBilling.quoteId`: bounded quote identifier
  - `meteredBilling.billingUnit`: billable unit name
  - `meteredBilling.quotedUnits`: quoted units
  - `meteredBilling.quotedCost`: quoted monetary amount
  - `meteredBilling.maxBilledUnits`: optional hard unit ceiling

## Transaction Context Mapping

Chio carries approval-bound context outside `authorizationDetails` in
`transactionContext`:

- `intentId`
- `intentHash`
- `approvalTokenId`
- `approvalApproved`
- `approverKey`
- `runtimeAssuranceTier`
- `runtimeAssuranceSchema`
- `runtimeAssuranceVerifierFamily`
- `runtimeAssuranceVerifier`
- `runtimeAssuranceEvidenceSha256`
- `callChain`

This keeps the delegated-rights description and the approval or provenance
context distinct while preserving traceability back to one governed intent.

## Request-Time Contract

Any future hosted request-time authorization contract must stay bounded to the
same governed semantics:

- authorization request parameter: `authorization_details`
- authorization request parameter: `chio_transaction_context`
- access-token claim: `authorization_details`
- access-token claim: `chio_transaction_context`

The request-time contract accepts only Chio's documented governed detail types:

- `chio_governed_tool`
- `chio_governed_commerce`
- `chio_governed_metered_billing`

At least one `chio_governed_tool` row must be present, because Chio does not
admit a commerce-only or metered-only bearer token with no governed action.

Hosted request-time authorization remains derived and bounded:

- Chio may describe governed request scope before execution
- approval tokens still represent approval truth, not bearer authorization
- governed receipts remain the authoritative post-execution record
- unsupported detail types or malformed transaction context fail closed

`chio_transaction_context` may also carry one optional `identityAssertion`
object when the caller wants bounded continuity semantics:

- `verifierId`
  - must match the request `client_id`
- `subject`
  - verifier-local subject or login handle
- `continuityId`
  - verifier-local continuity or resumable-session identifier
- `issuedAt` / `expiresAt`
  - freshness bounds for the continuity object
- `provider`
  - optional identity source label such as `oidc`
- `sessionHint`
  - optional verifier-local resumption hint
- `boundRequestId`
  - optional request anchor when the same continuity object is bridged from
    the OID4VP wallet exchange lane

This object is always optional. Chio does not require an external identity
provider to use hosted authorization, and stale, mismatched, or contradictory
identity assertions fail closed.

The same request may also opt into one bounded sender-constrained contract:

- `chio_sender_dpop_public_key`
- `chio_sender_mtls_thumbprint_sha256`
- `chio_sender_attestation_sha256`

When Chio issues a token from that request, it carries the accepted sender
binding forward through `cnf`:

- `cnf.chioSenderKey`
- `cnf["x5t#S256"]`
- `cnf.chioAttestationSha256`

## Resource Binding

Any future hosted OAuth-family edge must make resource binding explicit:

- protected-resource metadata publishes one canonical `resource`
- authorization requests must include `resource`
- that request-time `resource` must match the protected-resource metadata
- bearer tokens must carry `aud`, `resource`, or both, and the runtime
  verifier requires one of them to match the protected resource

This keeps authorization-server metadata, protected-resource metadata, and
runtime admission aligned instead of allowing one metadata story and a
different live audience rule.

## Portable Identity Alignment

The hosted authorization profile must publish the same portable-identity
alignment used by Chio's portable credential metadata:

- `portableClaimCatalog`
  - the always-disclosed, selectively-disclosable, and optional Chio passport
    claim sets the standards-facing profile is willing to recognize
- `portableIdentityBinding`
  - portable subject claim: `sub`
  - subject confirmation material: `cnf.jwk`
  - Chio subject provenance claim: `chio_subject_did`
  - portable issuer claim: `iss`
  - Chio issuer provenance claim: `chio_issuer_dids`
  - Chio enterprise provenance claim: `chio_enterprise_identity_provenance`
  - Chio provenance anchor: `did:chio`
- `governedAuthBinding`
  - authoritative source: `metadata.governed_transaction`
  - governed intent binding fields: `intentId`, `intentHash`
  - governed approval binding fields:
    `approvalTokenId`, `approvalApproved`, `approverKey`
  - sender binding fields: `subjectKey`, `subjectKeySource`,
    `issuerKey`, `issuerKeySource`
  - runtime assurance binding fields:
    `runtimeAssuranceTier`, `runtimeAssuranceSchema`,
    `runtimeAssuranceVerifierFamily`, `runtimeAssuranceVerifier`,
    `runtimeAssuranceEvidenceSha256`
  - delegated call-chain field: `callChain`
  - optional identity continuity field: `identityAssertion`

This keeps Chio's standards-facing authorization story aligned with the
portable credential story instead of leaving the two surfaces as unrelated
derived projections.

## Sender-Constrained Semantics

Chio's enterprise authorization profile now makes sender binding explicit per
row in `senderConstraint`:

- `subjectKey`
  - the subject key bound to the capability that authorized the governed
    action
- `subjectKeySource`
  - `receipt_attribution` when the receipt carried explicit attribution
  - `capability_snapshot` when the subject key came from persisted capability
    lineage
- `issuerKey`
  - the issuer key bound to the capability lineage that authorized the
    governed action
- `issuerKeySource`
  - `receipt_attribution` when the receipt carried explicit issuer attribution
  - `capability_snapshot` when the issuer key came from persisted capability
    lineage
- `matchedGrantIndex`
  - the scope grant resolved for the governed action
- `proofRequired`
  - `true` when runtime admission requires explicit sender proof continuity
- `proofType`
  - currently `chio_dpop_v1`, `chio_mtls_thumbprint_v1`, or
    `chio_attestation_binding_v1` when proof is required
- `proofSchema`
  - currently `chio.dpop_proof.v1` for DPoP
  - omitted for header-bound mTLS and attestation confirmation
- `runtimeAssuranceBound`
  - `true` when `transactionContext.runtimeAssurance*` fields are populated
- `delegatedCallChainBound`
  - `true` when `transactionContext.callChain` carries corroborated provenance
    rather than a bare caller assertion

Chio's sender-binding story is therefore:

- every projected governed action is bound to one capability subject key
- every projected governed action is also bound to one capability issuer key
- DPoP may be required either by the matched grant or by explicit request-time
  sender binding
- mTLS thumbprint continuity is supported as an explicit request-time sender
  binding
- attestation binding is only a confirmation of already-carried runtime
  assurance evidence, must match
  `transactionContext.runtimeAssuranceSchema`,
  `transactionContext.runtimeAssuranceVerifierFamily`,
  `transactionContext.runtimeAssuranceEvidenceSha256`, and must be paired
  with DPoP or mTLS
- attestation alone never authorizes a sender
- missing, stale, replayed, or mismatched sender proofs fail closed
- runtime assurance and delegated call-chain context are visible as additional
  sender-bound conditions, not separate mutable trust documents

## Artifact Boundary

Chio now publishes an explicit runtime-versus-audit artifact boundary:

- access tokens are runtime-admission artifacts
- approval tokens are not runtime-admission artifacts by themselves
- Chio capabilities are not OAuth bearer artifacts
- reviewer evidence packages are not runtime-admission artifacts
- governed receipts remain audit evidence

This means Chio can expose approval, capability, and reviewer evidence in
machine-readable reports without turning those artifacts into an alternate
authorization side channel.

## Discovery Contract

Chio publishes the same profile semantics through OAuth-family metadata on the
hosted edge:

- protected-resource metadata:
  `/.well-known/oauth-protected-resource/mcp`
- authorization-server metadata:
  `/.well-known/oauth-authorization-server/{issuer-path}`

Both documents now publish `chio_authorization_profile`, which mirrors the
canonical profile id/schema plus:

- sender-constraint expectations
- request-time parameter and access-token-claim names
- resource indicator and audience-binding rules
- explicit runtime-versus-audit artifact boundaries

Discovery is informational only. It does not become a second source of
authority, and operators must not treat metadata publication as equivalent to
signed governed receipt truth.

## Fail-Closed Boundary

Chio does not emit the profile when:

- `intentId` or `intentHash` are missing or empty
- no `chio_governed_tool` detail can be derived
- a declared detail type lacks its required substructure
- approval fields are partially present and cannot be tied back to one
  approval token
- delegated call-chain context is malformed
- sender binding cannot be resolved to one subject key
- sender binding cannot be resolved to one issuer key
- receipt and capability-lineage subject or issuer keys disagree
- capability snapshot grant scope is missing or cannot resolve the matched
  governed action
- the row-level `subjectKey` and `senderConstraint.subjectKey` disagree
- the resolved sender-constraint proof requirement cannot be represented
  - any unsupported authorization-detail type would be required to describe the
  receipt truth

On the hosted edge, Chio also fails closed when the protected-resource metadata
and authorization-server metadata disagree about the published
`chio_authorization_profile` or when the advertised authorization server is not
listed in protected-resource metadata.

## Explicit Non-Goals

This profile does not claim:

- generic OAuth token issuance behavior
- generic runtime admission of approval tokens, capabilities, or reviewer
  evidence
- OpenID Connect identity assertions
- automatic trust bootstrap from discovery documents alone
- arbitrary mTLS transport semantics outside Chio's documented adapter surfaces
- arbitrary external authorization-details interoperability beyond Chio's
  documented governed receipt projection
