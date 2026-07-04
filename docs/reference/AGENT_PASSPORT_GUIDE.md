# Chio Agent Passport Guide

**Status:** alpha plus verifier infrastructure, lifecycle status distribution,
portable OID4VCI-compatible issuance, holder transport over public
challenge/submit routes, multi-issuer composition, and shared-evidence
analytics shipped

---

## Overview

Chio now ships Agent Passport verification and presentation on top of:

- local reputation scoring
- reputation-gated issuance
- `did:chio`
- signed receipt and checkpoint evidence
- signed reusable verifier policy artifacts
- replay-safe verifier challenge state
- truthful multi-issuer bundle verification and evaluation
- shared-evidence provenance in operator and comparison reporting

The current CLI surface is Chio-first, with `chio` retained as a compatibility
alias during the rename window:

```text
chio passport create
chio passport policy create
chio passport policy verify
chio passport policy list
chio passport policy get
chio passport policy upsert
chio passport policy delete
chio passport challenge create
chio passport challenge respond
chio passport challenge submit
chio passport challenge verify
chio passport evaluate
chio passport verify
chio passport present
chio passport issuance metadata
chio passport issuance offer
chio passport issuance token
chio passport issuance credential
chio passport status publish
chio passport status list
chio passport status get
chio passport status resolve
chio passport status revoke
```

The passport is a bundle of independently verifiable reputation credentials.
Each embedded credential is signed by the issuing operator key and identifies
both issuer and subject as `did:chio` DIDs.

`chio passport create` still produces a single-issuer passport from one local
operator signing key and one local receipt corpus. Verification, evaluation,
and presentation now also support same-subject passport bundles composed from
multiple independently signed issuer credentials.

Passport artifacts can now also carry typed
`enterpriseIdentityProvenance` data. This is optional and only appears when
the issuing operator explicitly supplies enterprise identity context during
passport creation; verification recomputes the passport-level provenance from
the embedded credentials and fails closed if the aggregate is tampered.

Chio issuance and verification use these schema identifiers and reject legacy
pre-Chio passport artifacts:

- `chio.agent-passport.v1`
- `chio.passport-verifier-policy.v1`
- `chio.agent-passport-presentation-challenge.v1`
- `chio.agent-passport-presentation-response.v1`

Issuer and subject identifiers currently remain `did:chio`. `did:chio` is the
shipped canonical DID method.

Chio now also publishes one bounded public identity-profile and wallet-routing
contract over the passport substrate in
`docs/standards/CHIO_PUBLIC_IDENTITY_PROFILE.md`. That profile may name
`did:web`, `did:key`, and `did:jwk` as compatibility inputs, but the shipped
passport artifact and projected portable responses still keep `did:chio` as the
signed provenance anchor.

## OID4VCI-Compatible Issuance

Chio now ships one conservative OID4VCI-style pre-authorized-code issuance lane
for the existing `AgentPassport` artifact plus two bounded projected portable
passport profiles. This is still a transport and delivery layer over Chio's
current passport truth surface, not a rewrite of Chio credentials into generic
`ldp_vc` or arbitrary VC wallet formats.

The shipped profile is:

- configuration id: `chio_agent_passport`
- format: `chio-agent-passport+json`
- issuer metadata: `/.well-known/openid-credential-issuer`
- operator-authenticated offer creation: `/v1/passport/issuance/offers`
- holder-facing token redemption: `/v1/passport/issuance/token`
- holder-facing credential redemption: `/v1/passport/issuance/credential`
- optional issuer-profile `chioProfile.passportStatusDistribution` advertisement
  when the operator has published a portable lifecycle resolve plane
- optional credential-response
  `chioCredentialContext.passportStatus` sidecar when the delivered passport is
  already published active with lifecycle distribution

Local CLI flow:

```text
chio passport issuance metadata \
  --issuer-url https://trust.example.com \
  --passport-status-url https://trust.example.com/v1/public/passport/statuses/resolve \
  --passport-status-cache-ttl-secs 300

chio passport issuance offer \
  --input passport.json \
  --output offer.json \
  --issuer-url https://trust.example.com \
  --passport-issuance-offers-file passport-issuance-offers.json \
  --passport-statuses-file passport-statuses.json

chio passport issuance token \
  --offer offer.json \
  --output token.json \
  --passport-issuance-offers-file passport-issuance-offers.json

chio passport issuance credential \
  --offer offer.json \
  --token token.json \
  --output delivered-passport.json \
  --passport-issuance-offers-file passport-issuance-offers.json \
  --passport-statuses-file passport-statuses.json
```

Remote trust-control flow:

```text
chio trust serve \
  --listen 127.0.0.1:8090 \
  --advertise-url https://trust.example.com \
  --service-token issuer-admin-token \
  --passport-issuance-offers-file passport-issuance-offers.json \
  --passport-statuses-file passport-statuses.json
```

Remote compatibility is bounded intentionally:

- `credential_issuer` is an operator-controlled HTTPS transport identifier
- the delivered credential still binds issuer and subject as `did:chio`
- offer creation stays on Chio's authenticated admin plane
- pre-authorized codes and access tokens are single-use and short-lived
- portable lifecycle support is only advertised when the issuer has a published
  read-only lifecycle resolve plane
- if the trust-control service is configured for portable lifecycle support,
  offer creation fails closed until the target passport is already published
  active into that lifecycle registry
- Chio now also publishes one bounded public identity-profile, wallet-
  directory, and routing contract for the documented passport profile family
- Chio still does not claim generic OID4VP, DIDComm, permissionless public-
  wallet, or arbitrary non-Chio credential compatibility

## Create

```text
chio \
  --receipt-db receipts.sqlite3 \
  --budget-db budgets.sqlite3 \
  passport create \
  --subject-public-key <agent-ed25519-hex> \
  --output passport.json \
  --signing-seed-file authority-seed.txt \
  --validity-days 30 \
  --enterprise-identity enterprise-identity.json \
  --receipt-log-url https://trust.example.com/v1/receipts \
  --require-checkpoints
```

What this does:

- assembles the local reputation corpus for the selected subject
- computes a deterministic local scorecard
- builds one signed `ChioReputationAttestation`
- wraps it in an `AgentPassport`
- optionally projects enterprise federation facts into typed
  `enterpriseIdentityProvenance` on the credential and the passport bundle

`--require-checkpoints` fails closed if any selected receipt lacks checkpoint
coverage.

## Verify

```text
chio passport verify --input passport.json
```

Verification checks:

- every embedded credential signature
- `did:chio` issuer and subject consistency
- credential validity windows
- single-subject passport consistency
- bundle `validUntil` does not exceed the minimum credential expiry
- passport-level `enterpriseIdentityProvenance` exactly matches the aggregate
  provenance carried by the embedded credentials
- reports a stable `passportId` derived from the signed passport artifact
- optionally reports `passportLifecycle` when a local registry or trust-control
  service is configured
- reports `issuerCount` and `issuers`, and only reports a single top-level
  `issuer` when the bundle actually has one issuer

## Lifecycle Status And Distribution

Chio now treats passport lifecycle as operator-managed truth instead of a
private convention. A relying party can distinguish:

- `active`: the published passport is current
- `stale`: the published passport is still current, but its last lifecycle
  update is older than the advertised cache TTL and must not be treated as
  fresh
- `superseded`: a newer passport for the same subject and issuer set replaced it
- `revoked`: the published passport was explicitly revoked
- `notFound`: no lifecycle record is available for that passport artifact id

Publish one passport into a local lifecycle registry:

```text
chio passport status publish \
  --input passport.json \
  --passport-statuses-file passport-statuses.json \
  --resolve-url https://trust.example.com/v1/public/passport/statuses/resolve \
  --cache-ttl-secs 300
```

Resolve or revoke one lifecycle record:

```text
chio passport status resolve \
  --passport-id <passport-artifact-id> \
  --passport-statuses-file passport-statuses.json

chio passport status revoke \
  --passport-id <passport-artifact-id> \
  --passport-statuses-file passport-statuses.json \
  --reason compromised
```

Lifecycle state is historical metadata layered beside the signed passport
artifact. Publishing a replacement supersedes the older artifact but does not
rewrite the old signed object or change what it verified at an earlier time.

If you expose lifecycle over trust-control, start the service with a dedicated
registry file:

```text
chio trust serve \
  --listen 127.0.0.1:8090 \
  --advertise-url https://trust.example.com \
  --service-token verifier-token \
  --passport-statuses-file passport-statuses.json
```

The service exposes the same publish/list/get/resolve/revoke surface remotely.
When `--advertise-url` is set, published records inherit
`https://.../v1/public/passport/statuses/resolve` as the default holder/verifier
resolution endpoint unless the operator overrides it explicitly. Public
resolution is only advertised when the distribution also carries an explicit
`cacheTtlSecs`, and resolutions now expose `updatedAt` so consumers can
distinguish current `active` state from fail-closed `stale` state.

`chio passport status resolve --control-url ...` now uses that public read path
when no `--control-token` is supplied. Admin-only lifecycle operations remain
operator-authenticated.

You can also advertise the lifecycle endpoint through the subject DID document:

```text
chio did resolve \
  --id did:chio:<subject> \
  --passport-status-url https://trust.example.com/v1/public/passport/statuses/resolve
```

This emits an `ChioPassportStatusService` DID service entry so relying parties
have one supported place to discover lifecycle state.

## Multi-Issuer Composition

Chio now accepts passport bundles that contain credentials from multiple
issuers when all credentials:

- independently verify
- name the same passport subject
- stay within their own issuance and expiration windows

The verifier contract remains conservative:

- no cross-issuer aggregate score is invented
- no synthetic bundle-level issuer is invented
- policy evaluation still runs per credential
- the passport is accepted when at least one credential satisfies the verifier
  policy
- evaluation output reports `matchedIssuers` plus `credentialResults[].issuer`

This means multi-issuer support is a verification/evaluation/presentation
feature, not a claim that Chio now synthesizes a new trust signal across
issuers.

## Cross-Issuer Portfolios

Chio now also defines one bounded cross-issuer portfolio layer over those same
passport artifacts:

- a portfolio can hold native, imported, or explicitly migrated passport
  entries
- each entry keeps its own issuer provenance and optional lifecycle state
- visibility of an entry does not imply local admission
- local activation comes only from one explicit signed trust pack
- subject rebinding requires one explicit signed migration artifact

That keeps cross-issuer portability honest:

- no synthetic cross-issuer trust score is invented
- no implicit subject continuity is inferred from similar display claims
- duplicate or mismatched migration provenance fails closed
- portfolio acceptance still reduces to explicit per-entry outcomes

## Evaluate

```text
chio passport evaluate \
  --input passport.json \
  --policy examples/policies/passport-verifier.yaml \
  --passport-statuses-file passport-statuses.json
```

This is the first relying-party verifier lane on top of the shipped passport
format. The verifier:

- performs the same structural passport verification as `chio passport verify`
- evaluates each embedded credential independently against a relying-party policy
- accepts the passport if at least one credential satisfies the policy
- does not invent cross-issuer aggregation semantics beyond those independent
  credential results

The policy file can require:

- issuer allowlisting
- minimum composite / reliability / least-privilege / delegation-hygiene scores
- maximum boundary pressure
- minimum receipt count, lineage records, and history span
- checkpoint coverage and receipt-log URLs
- enterprise identity provenance on each credential
- active lifecycle resolution through a local registry or trust-control
  service
- maximum attestation age

Lifecycle enforcement is explicit. Set `requireActiveLifecycle: true` when the
relying party wants fail-closed current-state checking instead of bare artifact
verification:

```yaml
issuerAllowlist:
  - "did:chio:..."
requireActiveLifecycle: true
```

When this flag is enabled:

- evaluation rejects `stale`, `superseded`, `revoked`, and `notFound`
  lifecycle states
- evaluation also rejects if neither `--passport-statuses-file` nor
  `--control-url` is available to resolve lifecycle state
- output includes `passportLifecycle` plus human-readable `passportReasons`
  describing the lifecycle denial

See [examples/policies/passport-verifier.yaml](../../examples/policies/passport-verifier.yaml).

## Reusable Verifier Policy Artifacts

```text
chio passport policy create \
  --output verifier-policy.json \
  --policy-id rp-default \
  --verifier https://rp.example.com \
  --signing-seed-file verifier-seed.txt \
  --policy examples/policies/passport-verifier.yaml \
  --expires-at 1900000000 \
  --verifier-policies-file verifier-policies.json

chio passport policy verify --input verifier-policy.json

chio passport policy list \
  --verifier-policies-file verifier-policies.json
```

Verifier policy artifacts are now signed documents that bind:

- `policyId`
- verifier identity
- signer public key
- creation and expiry timestamps
- the underlying `PassportVerifierPolicy`

The same artifact format works for local file-backed verifier registries and
remote trust-control admin APIs.

## Compare Against Live Local State

```text
chio reputation compare \
  --subject-public-key <agent-ed25519-hex> \
  --passport passport.json
```

This compares the portable passport artifact against the live local reputation
corpus and reports explicit per-credential drift as `local_minus_portable`.
The same comparison contract is also available over trust-control through
`POST /v1/reputation/compare/{subject_key}` and is now surfaced in the
dashboard portable comparison panel.

The comparison payload now also includes `sharedEvidence`, which reports:

- referenced remote share count
- referenced remote capability rows
- upstream share issuer/partner metadata
- local anchor capability ids and local receipt counts for downstream activity

It also now includes `importedTrust`, which keeps cross-org reputation visible
without rewriting the local reputation truth that the comparison is anchored
to. Each imported signal reports:

- share provenance (`shareId`, issuer, partner, signer key, import/export
  timestamps)
- the imported-trust policy that was applied locally
- whether the signal was accepted or rejected
- rejection reasons when local guardrails fail
- an `attenuatedCompositeScore` only for accepted imported evidence

The same segregation applies to `chio reputation local`: the top-level local
`scorecard` still reflects native local receipts and budgets, while
`importedTrust` reports evidence-backed remote signals separately.

Example:

```text
chio --json --receipt-db receipts.sqlite3 reputation local \
  --subject-public-key <agent-ed25519-hex>
```

Use this when a verifier or operator needs to inspect imported remote trust
without pretending it became first-party local history.

## Federated Issuance

```text
chio \
  --control-url https://trust.example.com \
  --control-token <service-token> \
  evidence import \
  --input upstream-evidence-package

chio trust federated-delegation-policy-create \
  --output delegation-policy.json \
  --signing-seed-file authority-seed.txt \
  --issuer local-org \
  --partner remote-org \
  --verifier https://trust.example.com \
  --capability-policy examples/policies/federated-parent.yaml \
  --parent-capability-id cap-upstream \
  --expires-at 1900000000

chio \
  --control-url https://trust.example.com \
  --control-token <service-token> \
  trust federated-issue \
  --presentation-response response.json \
  --challenge challenge.json \
  --capability-policy examples/policies/federated-child.yaml \
  --enterprise-identity enterprise-identity.json \
  --delegation-policy delegation-policy.json \
  --upstream-capability-id cap-upstream
```

This lane now supports verified bilateral evidence consumption plus a real
multi-hop continuation step. `chio evidence import` verifies the upstream
package before it is indexed locally, the delegation policy binds to an exact
upstream capability ID, and `chio trust federated-issue --upstream-capability-id ...`
persists a local delegation anchor that bridges to the imported parent without
pretending the foreign capability was natively issued by the local authority.

When `--enterprise-identity` is supplied, federated issue can also enter the
enterprise-provider lane. The lane is only active when
`enterpriseIdentity.providerRecordId` resolves to a validated
provider-admin record on the trust-control service. In that case:

- the capability policy is resolved as HushSpec and its origin profiles are
  matched against provider, tenant, organization, groups, and roles
- missing provider validation or missing enterprise origin matches deny instead
  of falling back to a weaker path
- successful responses include `enterpriseAudit` with provider provenance,
  canonical principal, subject key, tenant, organization, groups, roles,
  `attributeSources`, `trustMaterialRef`, and the matched origin profile
- successful responses now also include typed
  `enterpriseIdentityProvenance`, and the nested passport/presentation
  verification payload surfaces any portable provenance already embedded in the
  presented passport

If enterprise identity is present only for observability and no validated
provider-admin record is selected, federated issue stays on the legacy
bearer-only path and the response explains that the enterprise-provider lane
was not activated.

## Present

```text
chio passport present \
  --input passport.json \
  --output presented.json \
  --issuer did:chio:... \
  --max-credentials 1
```

This produces a filtered passport presentation for selective disclosure. The
presentation reuses the original signed credentials; it does not re-sign them.
For multi-issuer bundles, issuer filtering and `--max-credentials` apply across
the composed credential set.

## Challenge-Bound Presentation

```text
chio passport challenge create \
  --output challenge.json \
  --verifier https://rp.example.com \
  --ttl-secs 300 \
  --policy-id rp-default \
  --verifier-policies-file verifier-policies.json \
  --verifier-challenge-db verifier-challenges.sqlite3

chio passport challenge respond \
  --input passport.json \
  --challenge challenge.json \
  --holder-seed-file subject-seed.txt \
  --output response.json

chio passport challenge submit \
  --input response.json \
  --submit-url https://trust.example.com/v1/public/passport/challenges/verify

chio passport challenge verify \
  --input response.json \
  --challenge challenge.json \
  --verifier-policies-file verifier-policies.json \
  --verifier-challenge-db verifier-challenges.sqlite3 \
  --passport-statuses-file passport-statuses.json
```

This verifier loop is now reusable and replay-safe. The challenge document
carries:

- verifier identity
- `challengeId`
- nonce
- issuance and expiration timestamps
- optional selective-disclosure hints (`issuerAllowlist`, `maxCredentials`)
- either an embedded verifier policy or a `policyRef`

The holder response:

- reuses the original signed credentials
- filters the passport according to the challenge disclosure hints
- signs the embedded challenge plus presented passport with the passport
  subject key
- lets the verifier check freshness, proof-of-possession, and policy
  acceptance without custom glue code

When a challenge references `policyRef.policyId`, verification resolves the
stored signed policy, checks that its bound verifier matches the challenge
verifier, and consumes the replay-safe challenge record. Verification output
now exposes:

- `challengeId`
- `policyEvaluated`
- `policyId`
- `policySource`
- `passportId`
- optional `passportLifecycle`
- `replayState`

If the embedded or referenced policy sets `requireActiveLifecycle: true`,
challenge verification applies the same lifecycle fail-closed rules as
`passport evaluate`.

## Holder Transport

This adds one conservative holder-facing transport over the existing Chio
challenge and response artifacts. The proof material is unchanged:

- the verifier/admin still creates the signed
  `chio.agent-passport-presentation-challenge.v1`
- the holder still signs the existing
  `chio.agent-passport-presentation-response.v1`
- replay truth still lives in the verifier challenge store

What changed is transport:

- remote `passport challenge create` now returns optional typed `transport`
  metadata when trust-control is started with `--advertise-url`
- `transport.challengeUrl` is a holder-safe public read endpoint for the stored
  challenge
- `transport.submitUrl` is a holder-safe public submit endpoint for the signed
  holder response
- `passport challenge respond` now accepts `--challenge-url` instead of only a
  local `--challenge <path>`
- `passport challenge submit` lets a holder post the signed response to the
  public submit URL without an admin token

Remote holder flow:

```text
chio \
  --json \
  --control-url https://trust.example.com \
  --control-token verifier-token \
  passport challenge create \
  --output challenge.json \
  --verifier https://rp.example.com

chio passport challenge respond \
  --input passport.json \
  --challenge-url https://trust.example.com/v1/public/passport/challenges/<challenge-id> \
  --holder-seed-file subject-seed.txt \
  --output response.json

chio passport challenge submit \
  --input response.json \
  --submit-url https://trust.example.com/v1/public/passport/challenges/verify
```

The public holder transport is intentionally narrow:

- challenge creation and policy administration remain operator-authenticated
- public fetch is read-only over an already-stored challenge id
- public submit only verifies and consumes the stored challenge; it does not
  expose admin mutation or policy CRUD
- missing `challengeId`, stale challenges, mismatched stored challenge state,
  and replayed submissions fail closed

## Remote Verifier Surface

```text
chio trust serve \
  --listen 127.0.0.1:8090 \
  --advertise-url https://trust.example.com \
  --service-token verifier-token \
  --passport-statuses-file passport-statuses.json \
  --verifier-policies-file verifier-policies.json \
  --verifier-challenge-db verifier-challenges.sqlite3

chio \
  --control-url https://trust.example.com \
  --control-token verifier-token \
  passport policy create \
  --output verifier-policy.json \
  --policy-id rp-default \
  --verifier https://trust.example.com \
  --signing-seed-file verifier-seed.txt \
  --policy examples/policies/passport-verifier.yaml \
  --expires-at 1900000000

chio \
  --control-url https://trust.example.com \
  --control-token verifier-token \
  passport challenge create \
  --output challenge.json \
  --verifier https://trust.example.com \
  --policy-id rp-default

chio \
  --control-url https://trust.example.com \
  --control-token verifier-token \
  passport challenge verify \
  --input response.json \
  --challenge challenge.json
```

Remote verifier flows use the same policy-reference and replay-safe challenge
contract as local CLI flows. Trust-control exposes verifier policy CRUD,
passport lifecycle publish/list/get/resolve/revoke, and challenge create/verify
endpoints behind the same service token boundary.

When `--advertise-url` is configured, trust-control also exposes the bounded
holder transport plane:

- `GET /v1/public/passport/challenges/{challenge_id}`
- `POST /v1/public/passport/challenges/verify`

These are public holder routes only. They do not widen verifier admin
authority, and they remain bound to the stored challenge id plus replay-safe
challenge store semantics.

## Alpha Boundary

Shipped now:

- single-issuer reputation credentials
- single-issuer passport bundle creation with Chio-primary schema issuance
- multi-issuer passport bundle verification, evaluation, and filtered presentation
- offline verification without custom glue code
- relying-party policy evaluation over passports without custom glue code
- filtered passport presentation
- challenge-bound presentation with holder proof-of-possession
- signed reusable verifier policy artifacts with local and remote admin surfaces
- replay-safe verifier challenge persistence for local verification,
  trust-control challenge verification, federated issue, and public holder
  submit semantics
- explicit passport lifecycle publication, distribution, and verifier-side
  enforcement
- narrow OID4VP verifier interop over the projected
  `application/dc+sd-jwt` passport lane, including signed `request_uri`
  request objects, one transport-neutral wallet exchange descriptor and
  canonical transaction state, one optional verifier-scoped identity
  assertion continuity lane, one bounded hosted sender-constrained
  continuation contract over DPoP, mTLS thumbprint binding, and one
  attestation-confirmation profile, same-device and cross-device launch
  artifacts, public verifier metadata, and verifier `JWKS` trust bootstrap
- signed public issuer-discovery and verifier-discovery documents plus one
  signed transparency snapshot over those metadata surfaces, with explicit
  informational-only/manual-review import guardrails
- holder-facing challenge fetch and response submit transport over public
  trust-control routes
- conservative imported reputation reporting with provenance, attenuation, and
  fail-closed guardrails for proofless or stale remote signals

Not shipped yet:

- `did:chio` issuance and resolution
- `did:chio:update` rotation flows
- zero-knowledge selective disclosure
- generic OID4VP, DIDComm, or universal wallet qualification beyond the
  documented Chio verifier profile plus bounded public identity-profile and
  wallet-routing contract
- permissionless or auto-trusting public issuer, verifier, or wallet
  discovery networks
- mandatory identity-provider or universal login semantics for presentation
- cluster-wide verifier-state replication beyond a configured verifier store
- automatic local multi-issuer bundle authoring beyond external composition
