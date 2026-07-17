# chio-federation

`chio-federation` defines Chio's federated trust, quorum, admission, and
shared-reputation contracts: the JSON artifacts operators exchange across a
federation boundary, and the cryptographic mechanics that move and
authenticate them (and the tool-invocation receipts they gate) between two
kernels. Every contract is evidence-referential and fail-closed: an operator
can use federation data to see further, but `FederationImportControl`
requires explicit local activation and manual review before any of it
becomes runtime trust.

The crate is a pure library: no I/O, no sockets, no timers,
`#![forbid(unsafe_code)]`. Runtime artifact issuance lives in
`chio-federation-authority`; wire transport lives in
`chio-federation-transport-iroh`.

## Responsibilities

- Define five root federation contracts and their fail-closed validators:
  trust-activation exchange (`activation`), quorum reporting with
  anti-eclipse policy (`quorum`), open-admission stake requirements
  (`open_admission`), sybil-resistant reputation clearing (`reputation`), and
  a qualification matrix (`qualification`) that must cover five fixed
  `TRUSTMAX` requirement ids.
- Define the artifact reference, trust-scope, delegation-control, and
  import-control types (`artifacts`) the five contracts above share.
- Produce and verify bilateral cross-kernel co-signatures over a
  `ChioReceipt`: a detached-signature envelope (`bilateral::DualSignedReceipt`)
  and a DSSE in-toto envelope in two profiles, a signature-slice
  compatibility profile and a strict Chio bilateral invocation predicate
  (`bilateral_dsse`).
- Verify both DSSE profiles against local trust state: peer pins, a receipt
  store, a revocation oracle, a capability lease registry, a governance
  receipt store, and (for the strict profile) a bound treaty
  (`bilateral_verifier`).
- Pin a remote kernel's signing key through a signed challenge/response
  handshake that negotiates protocol capabilities and a conformance tier and
  sets an explicit rotation deadline (`trust_establishment`).
- Compute the governance-ladder action-class intersection two or more
  kernels share under a treaty scope, and evaluate a specific
  cross-boundary action request against that intersection (`treaty`).
- Carry signed revocation epoch roots (`revocation_gossip`) and pheromone
  deposits (`pheromone_gossip`) between bilateral peers: wire envelopes,
  per-peer push queues with coalescing, and (for revocation) a bounded
  catch-up protocol.
- Record federation-hop counters and a latency histogram under the workspace
  `chio-metrics-spec` registry (`metrics`).

## Public API

- `activation::{FederationActivationExchangeArtifact,
  SignedFederationActivationExchange, validate_federation_activation_exchange}`
  - cross-operator trust-activation handoff for one listing.
- `artifacts::{FederationArtifactKind, FederationArtifactReference,
  FederationTrustScope, FederationDelegationControl, FederationImportControl}`
  - shared reference, scope, and control types.
- `quorum::{FederationQuorumReport, FederationPublisherObservation,
  FederationAntiEclipsePolicy, FederationQuorumState,
  validate_federation_quorum_report}` - multi-publisher freshness quorum
  with anti-eclipse policy.
- `open_admission::{FederatedOpenAdmissionPolicyArtifact,
  FederatedStakeRequirement, validate_federated_open_admission_policy}` -
  per-admission-class stake and bond requirements.
- `reputation::{FederatedReputationClearingArtifact,
  FederatedReputationInputReference, FederatedSybilControl,
  validate_federated_reputation_clearing}` - sybil-resistant
  reputation-input clearing.
- `qualification::{FederationQualificationMatrix, FederationQualificationCase,
  validate_federation_qualification_matrix}` - scenario-based coverage
  matrix over the five `TRUSTMAX` requirements.
- `bilateral::{DualSignedReceipt, CoSigningRequest, CoSigningResponse,
  BilateralCoSigningProtocol, InProcessCoSigner, co_sign_with_origin,
  co_sign_with_origin_full, execute_local_bilateral_invocation_fixture}` -
  dual-signed-receipt co-signing and the local fixture that drives signing
  plus verification together.
- `bilateral_dsse::{DsseEnvelope, BilateralPredicate,
  BilateralPredicateExtensions, sign_dsse_envelope_full,
  sign_chio_bilateral_dsse_envelope, verify_dsse_envelope,
  verify_chio_bilateral_dsse_envelope}` - DSSE in-toto envelopes for the
  signature-slice and strict Chio bilateral invocation profiles.
- `bilateral_verifier::{PeerPinSet, VerifierConfig,
  verify_bilateral_cosign_invocation, verify_chio_bilateral_invocation,
  verify_treaty_bound_chio_bilateral_invocation, VerifierError}` - local
  verifiers for both DSSE profiles, plus the `ReceiptStore` /
  `RevocationOracle` / `CapabilityLeaseRegistry` / `GovernanceReceiptStore`
  lookup traits.
- `trust_establishment::{KernelTrustExchange, PeerHandshakeEnvelope,
  FederationPeer, ConformanceTier, QuorumPolicy}` - signed handshake that
  pins a remote kernel's key with a rotation deadline.
- `treaty::{TreatyScope, GovernanceLadderManifest, LadderIntersection,
  compute_ladder_intersection, evaluate_cross_boundary_admission}` -
  governance-ladder intersection and cross-boundary admission checks.
- `revocation_gossip::{RevocationRootGossip, RevocationGossipPushQueue,
  RevocationCatchupRequest, RevocationCatchupResponse, respond_to_catchup}`
  - signed revocation epoch-root gossip and gap-fill.
- `pheromone_gossip::{PheromoneDepositGossip, PheromoneGossipPushQueue,
  PheromoneTransitPolicy, verify_pheromone_gossip_frame,
  verify_pheromone_gossip_batch}` - pheromone-deposit gossip, direct and
  multi-hop.
- `metrics::{record_federation_hop, observe_federation_hop_latency_nanos,
  render_federation_metrics_prometheus}` - federation-hop counters and
  latency histogram.
- `error::FederationContractError` - shared error type for the five
  contract-validator modules (`activation`, `quorum`, `open_admission`,
  `reputation`, `qualification`).

Also re-exported at the crate root: `capability`, `receipt` (from
`chio-core-types`), `listing` (`chio-listing`), `open_market`
(`chio-open-market`).

## Feature flags

| Flag | Effect |
|------|--------|
| `demo` | Compiles the `demo` module (`DemoAllowAllRevocationOracle`) outside test builds. Always compiled under `cfg(test)`; not for production use. |
| `pq` | Forwards to `chio-core-types/pq`, adding post-quantum (ML-DSA-65 and hybrid) signing backends to the `PublicKey`/`Keypair` types this crate signs and verifies against. |

## Testing

`cargo test -p chio-federation`

`tests/` adds integration coverage beyond the unit tests: bilateral
co-signing round trips (`bilateral_signing.rs`), treaty ladder intersection
and cross-boundary admission (`treaty.rs`), trust-establishment handshakes
(`trust_establishment.rs`), pheromone gossip policy (`pheromone_gossip.rs`),
and an oracle-to-verifier revocation-gossip latency budget
(`oracle_gossip_e2e.rs`, the reason `chio-kernel-core` is a dev-dependency).

## See also

- `chio-federation-authority` - runtime authority-artifact issuer built on
  these contracts.
- `chio-federation-transport-iroh` - iroh transport adapter carrying this
  crate's gossip envelopes; adds no trust logic of its own.
- `chio-revocation-oracle` - owns the epoch-root state `revocation_gossip`
  transports.
- `chio-pheromone` - owns the `PheromoneDeposit` type `pheromone_gossip`
  transports.
- `chio-listing`, `chio-open-market` - re-exported as `listing` /
  `open_market`; supply the actor-kind, admission-class, and bond/fee types
  the contracts validate against.
- `chio-core-types` - supplies the receipt, capability, and crypto
  primitives the bilateral and handshake mechanics sign and verify.
