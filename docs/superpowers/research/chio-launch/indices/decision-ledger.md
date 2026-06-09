# Launch Research Decision Ledger

Status: second-pass decision ledger
Confidence: high for decisions recorded here; open implementation details still need owner review.

## Decisions

### D1 - Transaction Passport Is The Root

Decision: `chio.transaction-passport.v1` is the root proof artifact for launch.

Rationale: The homepage claim crosses authority, commerce, settlement, swarm, lineage, disclosure, risk, and external protocols. A public reviewer needs one signed artifact that binds all subgraphs.

Consequence: Domain reports are subordinate to the Transaction Passport verifier report.

### D2 - Hyphenated Schema IDs Are Canonical

Decision: Use dot-separated domains plus hyphenated artifact names. Do not use underscores in schema IDs.

Rationale: Existing Chio schema IDs in protocol text use names like `chio.agent-passport.v1`, and the signed-artifact registry is fail-closed.

Consequence: `indices/artifact-registry.md` is canonical for the research package.

### D3 - Raw Agent Drafts Are Evidence, Not Contract

Decision: Do not rewrite raw `agent-drafts/` files when normalizing names.

Rationale: They are research provenance from the first campaign. Canonical integrated docs supersede them.

Consequence: Consistency scans should target `INDEX.md`, `architecture/`, `plans/`, and `indices/` for canonical docs, while treating `agent-drafts/` and `agent-reviews/` as source notes.

### D4 - Proof Room UI Is Downstream Of CLI

Decision: The CLI verifier owns the verdict; Proof Room renders it.

Rationale: A proof layer needs reproducible verification. A UI-generated verdict is not credible.

Consequence: Proof Room launch cannot be complete before `chio proof verify` can reproduce the public verdict.

### D5 - Four Fixture Stages Are The Public Minimum

Decision: Public launch needs `single-call-authority`, `commerce-transaction-passport`, `recursive-runtime-swarm`, and `disclosure-and-agent-web-envelope`.

Rationale: One demo cannot prove every clause of the homepage copy.

Consequence: Homepage claims must be mapped to fixture coverage in `indices/verification-gates.md`.

### D6 - External Protocols Are Projection Subjects

Decision: Chio should project proof into external protocol contexts, not claim to replace them.

Rationale: MCP, A2A, ACP-Client, ACP-Commerce, AG-UI, OpenAPI, AP2, x402, VC, BBS, SD-JWT, Sigstore, SLSA, in-toto, and DSSE each prove different things.

Consequence: The Agent Web Proof Envelope must classify each external claim as native external proof, Chio sidecar proof, digest-bound reference, advisory observation, or unsupported.

### D7 - Insurance Copy Requires Risk Comptroller Evidence

Decision: Insurance and risk stay in the launch story only through auditable evidence.

Rationale: Risk without reconciled reserve, claim, payout, slash, and capital state is storyware. Autonomous pricing needs actuarial evidence.

Consequence: Public copy may claim auditable risk context before autonomous pricing, but not autonomous insurer pricing readiness.

### D8 - Copy Must Be Verified Like Code

Decision: Launch copy needs lint gates.

Rationale: The easiest way to overclaim is docs drift after proof work. Bare `ACP`, universal-protocol claims, unsupported "every action", and unsupported insurance claims must fail.

Consequence: A copy lint should be part of the launch gate before public homepage changes are treated as true.

### D9 - Existing Crates Are The Default Homes

Decision: Launch proof should integrate existing crates first. New crates are allowed only after owner review proves existing homes cannot carry a stable abstraction.

Rationale: The workspace already has proof package, control-plane, lineage, disclosure, runtime, federation, pheromone, market, credit, settlement, web3, anchor, and CLI substrate. Greenfield crate names would make the reorg worse and duplicate existing ownership.

Consequence: `indices/execution-slice-contract.md` defines default crate homes and shared-file ownership for implementation agents.

### D10 - Runtime Enforcement Is Separate From Proof Assembly

Decision: The minimal Transaction Passport proves the root verifier shape, but launch runtime authority needs online enforcement evidence before side effects.

Rationale: A signed proof package can be complete over what it saw while still missing live tool-server bypass, replay, stale revocation, policy reload, or advisory-laundering failures.

Consequence: Runtime execution lease, nonce, revocation freshness, sandbox attestation, tool-server acknowledgement, and receipt totality are promoted to near-term launch work.

### D11 - Third-Wave Features Are Candidate Slices, Not Product Sprawl

Decision: The third-wave debate adds verifier-backed slices for payments, crypto context, workflow preflight, enterprise export, trust-market context, and operational interop. It does not approve new product categories without verifier contracts.

Rationale: These additions strengthen the homepage claim only when they remain subordinate to Transaction Passport and `chio proof verify`.

Consequence: `indices/debate-synthesis.md` owns the accepted priority order and deferral list.

## Open Decisions For Implementation Owners

These are deliberately unresolved because they require code-owner judgment:

1. Whether Transaction Passport verifier logic lives in `chio-control-plane`, a new `chio-proof` crate, or a smaller shared crate plus CLI adapter.
2. Whether proof bundles are directories, tar archives, zip archives, or all three.
3. Whether `chio proof` should be a top-level CLI command immediately or a compatibility facade over existing `evidence`, `attest`, `runtime`, and `replay` commands first.
4. Which existing example becomes the canonical source for Stage 1 commerce fixture generation.
5. Which external protocol projection ships first after Stage 0.
