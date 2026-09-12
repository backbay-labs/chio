# Megastart

Bring a local system of research, implementation, and review workers online.

```sh
cargo install --locked --path .
megastart
```

The host opens a local console. Choose the supplied mission or a directory with
`lib.rs` and `tests.rs`, select model workers or the reproducible reference, review
the authority boundary, and start. Closing the browser does not stop the host.

```sh
megastart status
megastart review
megastart resume
megastart exercise
megastart export
```

The paired Chio CLI release exposes the same commands as `chio megastart`.
The source installation provides `megastart` directly. JSON inspection is opt-in
with `status --json`. Review asks for an explicit decision bound to the candidate
shown; noninteractive automation must use the inspected candidate digest.

## Model connection and confinement

Configure `OPENAI_API_KEY`, or use `CHIO_MODEL_PROVIDER=openrouter` with
`OPENROUTER_API_KEY`. `CHIO_MODEL` selects the model. Credentials remain in the
host and are removed from compiler, test, and worker environments.

Model execution currently requires macOS with `/usr/bin/sandbox-exec`. Compilation
uses the pinned Rust toolchain, candidate-local temporary files, and bounded logs.
Generated tests cannot read host-only files, open network connections, or fork
children. The reference mode remains available on macOS and Linux. Do not treat
reference runs as model-generated repairs or as evidence for other platforms.

## Mission service

The console is a loopback service with a random session token in its launch URL
fragment. API requests require that token and the exact local host; cross-origin
writes are rejected. The service does not expose the state directory as a file
server. The browser reads retained events and receipts, never simulated activity.

Events have mission-wide monotonic sequence numbers. Reconnects retain identities.
A torn journal stops for reconciliation. Operator commands retain the existing
mission and shared invocation allowance. Protection exercises run in a separate
mission and never interrupt the user's working mission.

## Detailed reference

### Reference application

Build a system of agents around one useful mission: reproduce a Rust regression,
explore repairs in separate workspaces, independently test and review a candidate,
and publish that exact candidate after the release owner approves it.

The full walkthrough is https://chio.computer/docs/megastart .

## Run locally

Use macOS or Linux, Git, a native C toolchain, and Rust 1.94.1. Rustup selects the
included toolchain. Dependencies are pinned to the public Chio source and locked.
The first build downloads and compiles the embedded kernel; allow time for it.
The installed CLI is optional for this application. No model account is required.

```sh
cargo install --locked --path .
cargo test --locked --test mission
megastart init
megastart run
megastart status
```

One host starts three coordinator processes and six worker processes. Research
reproduces the supplied failing tests. Two implementation workers transform the
actual source differently: one fixes zero-length windows; the other also widens
the rolling accumulator. The host compiles and tests each candidate. Testing and
mechanical review then independently assess the selected candidate. These are
deterministic workers with a bounded repair vocabulary, not model-generated code.

`mission/proposal.json` names the candidate digest and original test/review receipts.
Read the candidate in `mission/candidates/` and its real compiler/test logs.
Nothing is published automatically.

## Authority and shared capacity

```sh
megastart drill authority
megastart drill allowance
megastart drill approval
```

The authority drill submits a registered write operation with a research worker's
capability, then checks that the protected file did not change. The allowance drill
requires the completed six-call mission: an additional granted inspection is
refused before its adapter records an effect. The approval drill submits the
publication request without an approval and checks that no release exists.

The mission authority directly delegates six scoped worker grants. Their shared
aggregate invocation ceiling is enforced atomically by the single SQLite admission
authority. Reopening the host preserves the family and its consumption. The pinned
kernel rejects multi-hop aggregate-family delegation, so swarm coordinators assign
work without adding a delegation hop. The separate sibling-share registry admits
each worker at 1,000 basis points; it is not the durable consumption ledger.
Read-only invocations consume the same allowance. Failed or interrupted dispatched
operations may also consume it; inspect the ledger rather than counting artifacts.

## Restart without repeating effects

```sh
megastart --state interrupted init
megastart --state interrupted run --crash-after-repair
# Expected exit code: 75. Run the next command after observing this failure.
megastart --state interrupted recover
```

The injected host termination happens after the first four effects and their
original receipts have been durably recorded. Child processes are drained before
the host exits. Recovery verifies those exact records and skips dispatch, then
performs the remaining test and review. Completed work consumes no new allowance.
The tests compare the original effect bytes and count adapter effects after restart.

Before dispatch, the host persists the exact request. If a process stops in another
window and no conclusive outcome was retained, recovery refuses to redispatch.
Inspect `requests/`, kernel receipts, and the protected resource; reconcile at the
effect owner. This example does not establish arbitrary crash-point recovery.
Ctrl-C preserves state and cancels owned subprocesses. One host can hold the mission
lease at a time. Capabilities expire after 24 hours; expired authority requires an
explicit new mission, not silent reissuance of a fresh allowance.

## Decide and verify

After inspecting `status` and the candidate, the release owner chooses its exact
digest. Replace the placeholder with `candidate_sha256` from `proposal.json`:

```sh
megastart approve --candidate CANDIDATE_SHA256
megastart key
megastart export --output evidence
megastart --state evidence verify --trusted-key TRUSTED_KERNEL_KEY
```

Approval signs a governed intent bound to the original request and exact proposal.
The publisher rechecks source bytes before atomically publishing the local `release/`
directory. Repeating an already completed approval reconciles its original receipt.
If a release exists without its outcome, the host refuses to publish again.

The exported directory contains receipts and effects, without databases, issuer
keys, worker capabilities, or pending approvals. Select the trusted public key
independently; `key` prints the local host's key for your own initial reference run.
Verification checks receipt signatures, operation identity, signed output hashes,
and the corresponding retained effects. It verifies the supplied collection;
it cannot establish that no records were omitted or that an unfamiliar signer is
trustworthy. A modified receipt or output must fail verification.

## Make it yours

Add another regression to `project/tests.rs` (for example, a complete window of one
element), then initialize a new mission with `--project project`. The chosen repair
must satisfy the modified harness. A different source layout requires adapting
`protocol::plan` and `operations::repair`; unsupported layouts fail explicitly.
To use a model planner, follow the bounded host loop in
https://chio.computer/docs/examples/agentic-os/mission-host and keep its credentials
at the execution host. Replace the mechanical review with a review suited to that
project while preserving candidate and test identity.

Each source module owns one responsibility:

| Module | Responsibility |
| --- | --- |
| `authority.rs` | Signed grants, narrowed scopes, family allowance, retained roots |
| `protocol.rs` | Bounded private IPC, coordinator/worker lifetimes and proposals |
| `operations.rs` | Protected effects, candidate workspaces, bounded compiler/tests |
| `mission.rs` | Retained assignments, admission, handoffs, recovery and publication |
| `main.rs` | Explicit operator commands and cancellation |
| `support/` | Shared host/runtime source used by the Agentic OS examples |

The host owns all resource adapters and signer keys. The local OS account is the
trust boundary: separate worker processes and directories are not security
sandboxes, and the supplied trusted test binaries run as your user. Install a real
sandboxed executor before accepting untrusted code. Moving workers to other
machines requires authenticated transport; replicating authority requires a store
and consistency model designed for that deployment. Local publication has no
external deployment or payment effect.
