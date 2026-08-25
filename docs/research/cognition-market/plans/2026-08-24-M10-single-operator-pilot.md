# M10: Single-Operator Cognition Market Pilot

Status: candidate qualified

## Outcome

Ship a restart-safe single-operator cognition market that an operator can start
from an installed `chio` binary. Distinct seller and buyer agents can package,
admit, discover, verify, purchase, and consume real verified-fix Findings
without hand-authoring protocol JSON.

M10 is complete only after the production-composed runtime, seller workflow,
Python and TypeScript clients, coding-agent example, and measured real-task
pilot all satisfy the exit criteria below. Existing protocol tests and release
plumbing do not satisfy this milestone by themselves.

## Product contract

The installed binary exposes these operator and agent workflows:

```text
chio finding operator init
chio finding operator serve
chio finding operator tick
chio finding package verified-fix
chio finding admit
chio finding verify-bundle
```

The operator profile uses separate scoped buyer and seller credentials. Buyer
requests must bind the authenticated payer into their durable identity and
cannot omit or select another payer. Seller requests cannot mutate operator
state outside admission, and neither role receives the global control-plane
service credential.

Sealed payloads are encrypted at rest and indexed durably by Finding identity.
Purchase reservations, reveals, delivery results, and scheduled status work
survive process restarts. Exact retries replay the original outcome and do not
capture payment twice.

Operator initialization is atomic and resumable for an exact deployment
request. Initialization requires an explicit canonical repository root, and
seller submissions cannot select a repository outside it, including through a
symbolic-link escape. Repository clone, checkout, and patch generation are
deadline-bound and storage or output-bound, repository identities exclude
transport credentials, and the maximum admitted sale price cannot exceed the
collateral exposure backing the listing.

Seller-controlled tests receive the installed toolchain but never the
operator's Cargo registry or Git dependency caches. Offline dependencies must
be vendored into the submitted repository. Seller submission retention is
limited to 256 jobs and 8 GiB of package/report storage, with worst-case
headroom reserved before a new job is accepted. Challenge artifact lookup
streams one retained bundle at a time and stops at the first digest match.

Durable purchase jobs have a hard 10,000-row ceiling. A new request fails
closed at capacity while an existing exact request can still replay its
original job.

The seller workflow packages a patch, replay recipe, deterministic evidence,
commercial terms, backing, listing, and admission request from normal files.
The buyer workflow receives a proof bundle that is verified by the Rust
reference verifier before the SDK returns a verified result.
Status helpers use that same Rust boundary with the profile's status authority,
service bond, freshness policy, and a durable rollback floor. Challenge helpers
authenticate the exact purchase terminal again before deriving evidence.

## Delivery sequence

### 1. Operator runtime

- Add scoped market authentication and bind the authenticated buyer identity to
  the payer used by purchase execution.
- Add an encrypted, durable sealed-payload store with restart and tamper tests.
- Generalize the reveal server to use a fail-closed payload resolver.
- Compose a non-test `FindingPurchaseExecutor` from the durable stores, kernel
  reveal path, settlement rail, and shared mutation fence.
- Add strict operator profile parsing and `operator init`, `serve`, and `tick`.
- Make exact `operator init` retries identity-preserving and reject ephemeral
  listen ports or changed deployment arguments.

Exit: two distinct local identities can use a restarted operator process to
complete one purchase, and an exact retry returns the same terminal result with
one capture.

### 2. Verified-fix admission

- Package a Git patch, exact repository context, deterministic replay recipe,
  evidence, terms, and backing without handwritten protocol JSON.
- Admit and activate the package through the same authority stores served by
  the operator runtime.
- Publish a pre-purchase proof bundle containing the signed Finding, admission
  evidence, status proof, transaction context, and referenced artifacts.
- Persist restart-safe admission and status jobs driven by `operator tick`.

Exit: a seller can package and admit a verified fix from files, and a buyer can
verify its proof bundle before purchase using only stable CLI or SDK calls.

### 3. Agent clients

- Add Python and TypeScript buyer clients for search, proof retrieval,
  verification, purchase, status, and challenge.
- Add Python and TypeScript seller clients for package and admission workflows.
- Use `chio finding verify-bundle --input -` as the cryptographic reference
  boundary. SDK helper logic must not relabel integrity-only checks as full
  verification.
- Verify status projections through `chio finding status` and require an
  authenticated purchase wrapper for challenge filing.
- Add cross-language fixtures and black-box tests against the real operator.

Exit: both clients pass the same black-box lifecycle and reject altered signed
or referenced material.

### 4. Coding-agent pilot

- Ship a deployable local operator profile and a coding-agent seller and buyer
  example.
- Return a verified patch by default. Applying it in a sandbox is a separate,
  explicit action.
- Run at least 10 real verified-fix Findings and 5 purchases between distinct
  identities.
- Demonstrate deterministic replay, zero duplicate captures, restart during an
  active transaction, and one controlled invalid Finding that proceeds through
  challenge and retraction.
- Produce an aggregate, privacy-safe pilot report with timings, failure counts,
  replay results, and consumption outcomes.

Exit: the committed pilot evidence is reproducible from documented commands and
meets every quantity and safety condition above.

Evidence: [M10-PILOT-REPORT.md](../M10-PILOT-REPORT.md) records the qualified
ten-Finding, five-purchase run and its exact implementation candidate.

## Integration and qualification

Implementation lands as four sequential changes:

1. `feat(cognition-market): ship operator runtime`
2. `feat(cognition-market): automate verified-fix admission`
3. `feat(cognition-market): add market SDK clients`
4. `test(cognition-market): qualify real-agent pilot`

Each change receives focused tests while it is developed. The integration
boundary additionally requires formatting, clippy, affected crate tests,
`make codegen-check`, the cognition-market qualifier, the experimental CI lane,
the workspace test gate, hosted required checks, and verification from merged
`main`.

## Non-goals

M10 does not enable M7 stochastic mechanisms, metered research mechanisms,
auctions, a hosted public market, a user interface, or a background scheduler
daemon. Scheduled work remains an explicit, idempotent `operator tick` suitable
for cron or a service timer. Unrelated release-branch repair is outside this
worktree.
