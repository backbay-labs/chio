# TEE-Backed Receipt and Runtime-Assurance Binding Memo

> **Date**: 2026-04-16
> **Status**: Explicit research track
> **Roadmap position**: Follows `docs/POST_ROADMAP_ADDENDUM.md` Phase 27 and
> remains outside the numbered product ladder and post-31 external programs.

## Scope

This memo examines how ARC could bind receipts and runtime-assurance claims to
TEE measurements, attestation evidence, freshness, and caller or workload
continuity.

This is not a prerequisite for Phases 26 through 31 or for the non-research ARC
thesis.
It is a hardware-rooted extension to the verifier-backed runtime-assurance work
already scoped in Phase 27.

## 1. Feasible Architecture Patterns

### Pattern A: Attested Session-Key Binding

**Recommendation**: best first research path.

- Run the ARC kernel or a minimal receipt-signing component inside a TEE.
- Generate an ephemeral receipt-session public key inside the TEE.
- Ask the TEE or verifier to attest a binding over:
  `kernel_measurement || receipt_session_public_key || nonce || session_anchor`.
- Mint a local ARC `VerifiedRuntimeAttestationRecord` that carries verifier
  identity, evidence digest, measurement claims, freshness, and the attested
  receipt-session key.
- Sign normal ARC receipts with the enclave-held session key, and include the
  verified-record reference plus the session key thumbprint in receipt
  metadata.

Why this fits current TEE primitives:

- AWS Nitro attestation documents can carry optional `public_key`,
  `user_data`, and `nonce`, and expose PCR measurements plus parent-instance
  identity signals.
- Azure Attestation validates that the SHA-256 of enclave-held data is present
  in SGX `reportData`, which is a natural place to bind an ARC session key or
  session anchor.
- Google attestation tokens already carry `aud`, `eat_nonce`, instance
  identity, and workload-adjacent identity signals such as
  `google_service_accounts`.
- Arm CCA tokens carry both platform and realm evidence and can expose a realm
  public key.
- Intel TDX guidance explicitly treats `report data` as the place to bind a
  public key or expected nonce.

ARC impact:

- Minimal change to receipt structure.
- One attestation can cover many receipts until expiry or key rotation.
- Receipt verification remains ordinary plus one extra verified-record lookup.

### Pattern B: Attested Checkpoint or Batch Binding

**Recommendation**: likely better than per-receipt quotes for production use.

- Keep ordinary receipt signing unchanged for each decision.
- At session start or every N receipts, have the TEE attest:
  `checkpoint_root || signer_key || nonce || validity_window`.
- Bind the checkpoint statement, Merkle root, or session anchor to the TEE
  evidence, not every individual receipt.
- Downstream verification becomes:
  receipt -> ARC signature -> checkpoint inclusion -> attested checkpoint.

Why this is attractive:

- TEE evidence is expensive and platform-specific.
- Several platforms naturally attest boot or VM state more readily than each
  individual application event.
- ARC already has checkpoint and receipt-root concepts, so this approach fits
  existing receipt-lineage and publication work better than quote-per-decision.

ARC impact:

- Stronger than Phase 27 for external verifiers who care where receipt batches
  were produced.
- Weaker immediacy than per-receipt binding, so freshness windows and replay
  rules matter more.

### Pattern C: Verifier or Key-Broker Binding

**Recommendation**: useful for partner-facing and external-proof lanes.

- Present raw TEE evidence to a trusted verifier, KMS, or attestation service.
- If measurements and policy pass, receive a short-lived signing key, signing
  certificate, or unwrap permission.
- Use that released credential to sign ARC receipts or checkpoint statements.
- Bind caller continuity with DPoP, mTLS, or another sender-constrained channel
  so the released credential and the authenticated caller stay aligned.

Why this is feasible:

- Nitro already documents KMS flows that accept enclave attestation documents.
- Google Cloud Attestation issues cryptographically verifiable claims tokens and
  supports OIDC or PKI validation paths.
- Azure Attestation is explicitly a verifier and token-issuing service.

ARC impact:

- Good fit for external reliance and partner-verifiable proof.
- Strongly depends on verifier trust-root management and on short-lived
  credential semantics.
- Does not by itself prove each receipt came from a still-live TEE unless it is
  paired with short validity windows, nonce binding, and local session
  continuity.

### Pattern D: Per-Receipt Quote Binding

**Recommendation**: strongest theory, weakest operational fit.

- Hash each canonical receipt body.
- Place that digest into the TEE report-binding field for every decision.
- Attach the quote or verifier token to each receipt.

This is feasible in principle, but it is likely the wrong first implementation:

- it is heavier on quote generation, storage, and verification
- it pushes ARC toward vendor-specific receipt shapes
- it adds little value over session-key or checkpoint binding unless the target
  market explicitly demands per-decision hardware evidence

## 2. Prerequisites and Unresolved Research Questions

### Prerequisites

- **Phase 27 first**: ARC should first make a verified attestation record the
  only strong runtime-assurance input and bind that record to caller, workload,
  or session continuity.
- **TEE family selection**: ARC needs one bounded starting set instead of a
  fake universal abstraction. The most practical first target looks like AWS
  Nitro, followed by one VM-style verifier path such as Google Confidential VM
  or Azure Confidential Computing.
- **Reference-value operations**: ARC needs a signed registry for acceptable
  measurements, collateral freshness, revocation state, and rollout windows.
- **Replay and freshness substrate**: ARC needs request nonces, session-anchor
  semantics, and one replay registry for attestation evidence or verified
  records.
- **Receipt-key lifecycle**: ARC needs rules for generating, sealing, rotating,
  revoking, and exporting receipt-signing keys inside or for a TEE-backed path.
- **Caller continuity contract**: ARC needs one explicit rule for how the
  attested runtime stays bound to the authenticated caller across admission,
  receipt emission, restart, and failover.

### Unresolved Research Questions

- Should ARC bind receipts to an attested session key, an attested checkpoint
  key, or a per-receipt digest?
- Which continuity primitive is strongest for ARC's model:
  attested public key plus DPoP, mTLS channel binding, or a verifier-issued
  short-lived workload credential?
- Can ARC define one portable TEE evidence projection without implying false
  equivalence across PCRs, SGX measurements, TDX measurements, SEV-SNP launch
  measurements, and Arm CCA realm claims?
- What is the correct migration story when a kernel restarts or moves to a new
  TEE instance?
- Does ARC need monotonic counters or a transparency witness to make replay and
  rollback claims honest, or are nonce plus short-lived session keys enough for
  the intended threat model?
- How much of the kernel must live inside the TEE:
  the full policy engine, only receipt signing, or only a verifier-bound key
  broker?

## 3. Limitations and Threat-Model Caveats

- **TEE evidence is not application-proof.** It proves measured environment
  properties and verifier policy outcomes, not that ARC policy logic is bug-free
  or that a tool result is semantically correct.
- **Availability is still out of scope.** AMD's SEV-SNP threat model still
  leaves the cloud operator trusted for availability. A host can still stop,
  delay, or restart workloads.
- **Freshness is decisive.** Without nonce or short-lived evidence rules, old
  quotes or old verifier tokens can be replayed into new receipt flows.
- **VM TEEs do not automatically prove process identity.** Google, SEV-SNP, and
  TDX evidence often say more directly that a VM or trust domain launched in an
  approved state; ARC still needs an internal chain from that state to the
  kernel process and receipt signer.
- **Trust shifts to verifier roots and collateral.** Intel TDX collateral
  expires and must be cached and refreshed. Google and Azure rely on token or
  certificate trust roots. That becomes part of ARC's trusted base.
- **Debug or degraded states must fail closed.** Nitro debug enclaves produce
  unusable attestation documents, Google exposes `dbgstat`, and Azure exposes
  policy-controlled attestation outputs. ARC has to deny rather than downgrade
  silently.
- **Cross-vendor normalization must stay conservative.** ARC should normalize
  only portable facts such as verifier family, measurement digest package,
  freshness, debug posture, and attested key binding. It should not imply that
  all vendor measurements are semantically interchangeable.

## 4. Difference From and Extension of Phase 27

Phase 27's core move is:

- make a verified runtime-attestation record the only strong runtime-assurance
  input
- bind that verified record to the caller, workload identity, or session that
  actually uses the capability

TEE-backed binding extends that in four ways:

- **From admission proof to receipt proof**:
  Phase 27 proves that ARC admitted a request based on verified attestation.
  This research track aims to prove that the receipt signer or checkpoint signer
  itself lived inside a measured TEE.
- **From verifier-backed claims to hardware-rooted receipt provenance**:
  Phase 27 can still terminate at a verifier result consumed by the kernel.
  TEE binding adds a hardware-rooted link from measurement to receipt signer,
  checkpoint, or batch root.
- **From local strong path to partner-verifiable evidence**:
  Phase 27 mainly improves ARC's own runtime boundary. TEE binding creates an
  artifact outside parties can evaluate when they care about where a receipt was
  produced.
- **From bounded runtime assurance to continuity research**:
  Phase 27 binds admission to caller or workload identity. TEE binding has to
  solve the harder problem of keeping that identity continuous across quote
  freshness, session keys, restarts, and receipt chains.

Bottom line:

- Phase 27 is a shipping-quality runtime-admission hardening phase.
- TEE-backed receipt binding is a later research extension for stronger
  external-proof and hardware-rooted provenance claims.

## 5. Doc-Ready Bullets

- Treat TEE-backed receipt and runtime-assurance binding as an explicit
  research track after Phase 27, not as hidden scope inside Phases 26 through
  31.
- Gate all TEE work on Phase 27 completing the non-research verifier-backed
  runtime-assurance path first.
- Prefer attested session-key or attested checkpoint binding before attempting
  per-receipt quotes.
- Keep vendor evidence families explicit. Do not collapse SGX, TDX, SEV-SNP,
  Nitro, Google, Azure, and Arm CCA measurements into one fake universal
  measurement claim.
- Require nonce or equivalent freshness binding plus explicit replay handling
  for any TEE evidence that can influence live receipt or runtime-assurance
  claims.
- Bind the verified TEE record to caller continuity with a sender-constrained
  mechanism such as DPoP or mTLS rather than relying on bearer-style imported
  claims.
- Start with one bounded implementation target, likely AWS Nitro or one
  verifier-token path plus a local attested session-key design, before claiming
  multi-platform TEE parity.
- Keep ship truth conservative: Phase 27 proves verifier-backed admission;
  this research track would add hardware-rooted receipt provenance only after
  extra key-management, freshness, and continuity work lands.

## Primary Sources

### ARC Context

- `docs/POST_ROADMAP_ADDENDUM.md`
- `docs/POST_31_EXTERNAL_PROGRAMS.md`
- `spec/PROTOCOL.md` (runtime attestation contract)

### Attestation and Identity Sources

- RFC 9334, Remote ATtestation procedureS (RATS) Architecture:
  [rfc-editor.org/rfc/rfc9334](https://www.rfc-editor.org/rfc/rfc9334)
- RFC 9449, OAuth 2.0 Demonstrating Proof of Possession (DPoP):
  [rfc-editor.org/rfc/rfc9449](https://www.rfc-editor.org/rfc/rfc9449)
- AWS Nitro Enclaves attestation:
  [docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html)
- AWS Nitro Enclaves root-of-trust and attestation document format:
  [docs.aws.amazon.com/enclaves/latest/user/verify-root.html](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)
- Azure Attestation overview:
  [learn.microsoft.com/azure/attestation/overview](https://learn.microsoft.com/en-us/azure/attestation/overview)
- Azure Attestation basic concepts:
  [learn.microsoft.com/azure/attestation/basic-concepts](https://learn.microsoft.com/en-us/azure/attestation/basic-concepts)
- Google Cloud Attestation:
  [cloud.google.com/confidential-computing/docs/attestation](https://cloud.google.com/confidential-computing/docs/attestation)
- Google Confidential VM token claims:
  [cloud.google.com/confidential-computing/confidential-vm/docs/token-claims](https://cloud.google.com/confidential-computing/confidential-vm/docs/token-claims)
- Intel TDX enabling guide:
  [cc-enabling.trustedservices.intel.com/intel-tdx-enabling-guide/print_page/](https://cc-enabling.trustedservices.intel.com/intel-tdx-enabling-guide/print_page/)
- Intel SGX DCAP quote library reference:
  [download.01.org/intel-sgx/sgx-dcap/1.18/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf](https://download.01.org/intel-sgx/sgx-dcap/1.18/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf)
- AMD SEV-SNP attestation overview:
  [amd.com/content/dam/amd/en/documents/developer/lss-snp-attestation.pdf](https://www.amd.com/content/dam/amd/en/documents/developer/lss-snp-attestation.pdf)
- Arm CCA attestation overview:
  [learn.arm.com/learning-paths/servers-and-cloud-computing/cca-veraison/cca-attestation/](https://learn.arm.com/learning-paths/servers-and-cloud-computing/cca-veraison/cca-attestation/)
- Arm CCA attestation token structure:
  [learn.arm.com/learning-paths/servers-and-cloud-computing/cca-veraison/attestation-token/](https://learn.arm.com/learning-paths/servers-and-cloud-computing/cca-veraison/attestation-token/)
