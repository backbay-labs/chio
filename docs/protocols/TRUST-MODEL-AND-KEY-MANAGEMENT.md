# Trust Model and Key Management

**Scope:** Trust roots, key hierarchy, rotation domains, hosted signing, verifier onboarding

> **Purpose**: Several protocol docs use a simplified "single kernel keypair"
> model to explain local deployments. This document defines the broader trust
> model needed for hosted, federated, and auditor-facing Chio deployments.

---

## 1. Why This Document Exists

Chio makes stronger claims than a normal observability layer:

- receipts are signed, not merely logged
- compliance certificates are verifiable by third parties
- revocation and delegation lineage matter across sessions
- hosted deployments may still claim customer-controlled trust

Those claims require an explicit trust model. Without one, phrases like
"customer-controlled signing" or "independent verification" are underspecified.

This document fills that gap.

---

## 2. Core Trust Assertions

Chio intends to support the following assertions:

1. A verifier can determine which keys are allowed to sign which Chio artifacts.
2. Historical artifacts remain verifiable after routine key rotation.
3. Hosted Chio infrastructure cannot silently substitute its own trust root for
   the customer's trust root.
4. Cross-org federation requires explicit trust-bundle exchange; no ambient
   trust is implied by protocol connectivity alone.
5. Any degraded evidence state is visible in the artifact model and does not
   masquerade as full attestation.

---

## 3. Key Roles

Chio should treat these as logically distinct roles even when a local
single-binary deployment collapses them onto one physical keypair.

### 3.1 Verifier Trust Bundle

The verifier trust bundle is the root input to verification. It tells a
verifier which issuers are trusted for which artifact classes.

Minimum contents:

- trusted root or intermediate Chio issuer keys
- issuer metadata: tenant, environment, validity interval, purpose
- revocation or retirement metadata for old keys
- artifact-scope constraints, such as "may sign receipts but not capability
  tokens"

### 3.2 Kernel Signing Key

Used to sign:

- `ChioReceipt`
- session compliance certificates
- other kernel-issued evidence artifacts

This key represents the execution environment that observed and enforced the
session.

### 3.3 Capability Authority Key

Used to sign:

- capability tokens
- delegated or attenuated grants when Chio is the issuing authority

This key represents authorization, not execution. It may be the same as the
kernel signer in local deployments, but they should be modeled separately.

### 3.4 Checkpoint Publisher Key

Used to sign:

- checkpoint manifests
- batch-root announcements
- external anchoring metadata

This key represents append-only publication, not per-operation enforcement.

### 3.5 Hosted Control-Plane Identity

Used to authenticate:

- trust-control APIs
- hosted receipt ingestion
- evidence export and operator APIs

This key or token authenticates the control plane, but should not be confused
with the artifact-signing trust root.

---

## 4. Default vs Production Profiles

### 4.1 Local Development Profile

Allowed simplification:

- one Ed25519 keypair may act as kernel signer and capability authority
- verifier trust may be a local static file
- no HSM or remote signing required

This is the profile described in most examples.

### 4.2 Self-Hosted Production Profile

Recommended separation:

- kernel signing key distinct from capability authority key
- historical trusted-key set retained for verification
- checkpoint publication key separate from both
- verifier trust bundle distributed explicitly to internal consumers

### 4.3 Hosted Customer-Controlled Signing Profile

Required property:

- the hosting provider may operate runtime infrastructure, but the artifact-
  signing key must remain under customer control or customer-auditable custody

Acceptable patterns:

- customer-managed HSM or KMS with delegated signing
- customer-operated signing sidecar
- dual-control signing service where the host cannot mint an unapproved issuer

Not acceptable:

- provider-controlled opaque signing with no customer-visible trust root

### 4.4 Federated Multi-Organization Profile

Required property:

- each organization distributes its trust bundle explicitly to counterparties

Federation should require:

- issuer identification by tenant/org
- artifact-purpose scoping
- validity intervals
- rollover policy
- revocation distribution or status lookup

---

## 5. Rotation Domains

Key rotation should be modeled by domain, not as one global event.

### 5.1 Kernel Signer Rotation

Effects:

- new receipts and certificates use the new key
- old receipts remain valid under the retained trusted-key history
- already-issued artifacts are not rewritten

### 5.2 Capability Authority Rotation

Effects:

- new capabilities are issued under the new authority key
- old capabilities remain verifiable until expiry or revocation, provided the
  old authority key remains in trusted history

### 5.3 Checkpoint Publisher Rotation

Effects:

- future checkpoint manifests switch to the new key
- old checkpoint signatures remain valid under the retained key history

### 5.4 Retirement Semantics

Retired does not mean deleted. Verifiers need:

- `valid_from`
- `valid_to`
- retirement reason
- whether the key may still verify historical artifacts

---

## 6. Verifier Onboarding

Verification requires more than a public key pasted into a config file.

Minimum verifier onboarding flow:

1. Obtain a trust bundle from the operator or customer through an authenticated
   channel.
2. Confirm issuer identity, environment, and artifact-purpose scope.
3. Load historical trusted keys, not just the current key.
4. Load revocation or retirement metadata if available.
5. Verify the artifact against both cryptographic validity and the trust-bundle
   policy.

Recommended distribution formats:

- signed trust bundle file checked into deployment config
- customer JWKS or equivalent key-discovery endpoint with explicit issuer
  binding
- versioned bundle snapshots for audit and rollback

Verifier onboarding should avoid trust-on-first-use for regulated or high-stakes
deployments.

---

## 7. Artifact-to-Key Mapping

| Artifact | Primary signer | Verification requirement |
|----------|----------------|--------------------------|
| Capability token | Capability authority key | Verifier trusts issuer for authorization artifacts |
| Chio receipt | Kernel signing key | Verifier trusts issuer for execution evidence |
| Session compliance certificate | Kernel signing key | Verifier trusts issuer for compliance artifacts and, ideally, can also inspect the receipt bundle |
| Checkpoint manifest | Checkpoint publisher key | Verifier trusts issuer for append-only publication |

The same physical key may cover multiple rows in local deployments, but the
artifact model should not require that collapse.

---

## 8. Hosted Signing Requirements

If Chio offers hosted managed service, the docs and product must answer:

- Who controls the signing key material?
- Can the customer rotate or revoke the issuer independently of the host?
- How does a verifier distinguish customer trust from provider transport auth?
- What evidence proves which runtime instance asked the signer to sign?

Minimum requirement for trustworthy hosted signing:

- the signer is bound to a customer-visible issuer identity
- signature requests are authenticated and auditable
- key rotation preserves historical verification
- the provider cannot silently replace the trust root presented to verifiers

---

## 9. Degraded Evidence States

Chio must distinguish these states explicitly:

- `fully_attested`
- `policy_enforced_but_unsigned`
- `signer_unavailable`
- `evidence_incomplete`

Verifier behavior:

- only `fully_attested` qualifies for full cross-protocol attestation claims
- degraded states may still be operationally useful, but they are not eligible
  for the same compliance assertions

This distinction is especially important for ACP-Client proxy integration and for
certificate generation.

---

## 10. Guidance for Other Protocol Docs

Other docs in `docs/protocols/` should follow these rules:

- when they use a single keypair in examples, label it as the default local
  profile
- when they mention hosted or customer-controlled signing, reference this doc
- when they define verification APIs, specify which trust bundle the verifier
  is expected to load
- when they mention federation, require explicit trust-bundle exchange

---

## 11. Open Questions

- Should verifier trust bundles be expressed as signed JSON, JWKS, or both?
- Should Chio define separate artifact-purpose claims in key metadata?
- How should remote attestation evidence be bound to the kernel signing key in
  hosted environments?
- Which rotation events should invalidate future certificate issuance versus
  merely changing the current issuer for new sessions?
