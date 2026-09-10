# Consumer discovery and adoption design

## Evidence sought

The goal is to identify a repeated operational responsibility with an owner who can evaluate a replacement. A compelling interview statement is useful but weaker than access to the actual implementation, a retained failure or intervention, and a willingness to operate a pilot.

No interviews or outreach have occurred as part of this dossier. The candidate classes below guide discovery. No adoption pilot is selected. Contacting another person requires a separate explicit instruction; drafting the interview and evaluation materials does not.

The owner has separately selected six required host integrations: Claude Code,
the Codex plugin, Cursor, Hermes, Pi Agent, and OpenClaw. Their kernel testing and
completion requirements are in [19](19-priority-agent-integrations.md). They can
proceed without selecting an adoption pilot. A passing host integration still
requires actual use and retention evidence before it counts as an adopter.

## Candidate classes

| Candidate | What to inspect | Why it might fit | Why to reject it early |
|---|---|---|---|
| Existing multi-agent engineering or operations service | Worker permissions, shared-resource writes, cancellation, incident recovery | Consequential delegation and handoff may expose a reusable gap | Mature orchestration already supplies the same controls |
| Internal agent platform serving several frameworks | Duplicated tool auth, identity propagation, evidence, credentials | Cross-framework consistency may matter operationally | One existing gateway policy layer solves it adequately |
| Small team deploying a new multi-worker application | Deployment scripts, worker supervision, key distribution, storage | Integrated host may replace concrete planned work | No actual workload or operator; hypothetical need expands indefinitely |
| Buyer of agent-produced artifacts/services | Acceptance procedure and evidence required from the supplier | A real relying party can test portable evidence | Buyer trusts supplier logs and has no independent verification requirement |
| Bounded automated operations workflow | Current approval steps, allowed changes, rollback/compensation | More constrained autonomy may reduce repeated supervision | Required safety depends on human judgment the contract cannot encode |
| Existing finding-worker | Current isolation, leases, limits, cancellation, fencing | Nearby source can be inspected without inventing an application | Retained assessment already shows substantial overlap; require a new specific unmet need |

Proximity is not enough to select a consumer. An internal consumer can establish useful engineering adoption, but must be labeled internal. Independent operation means the operator can run it without the integration author driving every step; independent market demand is a further claim.

## Active-use gate

Before consumer-specific architecture, establish that the workflow is currently used or explicitly committed for imminent use, identify its accountable user, and confirm a consequential responsibility they want changed. Code presence, old deployment plans, shared ownership, and similar architecture cannot satisfy this gate.

## Interview sequence

Ask for the most recent concrete instance and its consequences.

1. What work do the agents perform today, and who is accountable when it goes wrong?
2. Show the last handoff, cancellation, authority problem, or recovery intervention. What happened and what was the actual consequence?
3. Which source files, deployment settings, credentials, and runbooks implement the current protection?
4. What guarantees must hold even if a worker is compromised? Which failures are merely inconvenient?
5. Which current components must remain, and which responsibility would you willingly hand to a maintained dependency?
6. What does installation, routine operation, incident response, and upgrading cost today? Which measurements exist?
7. What existing alternative has been tried or rejected, and why?
8. Who can approve and operate a bounded pilot, and what would make them stop it?
9. What outcome would cause them to retain the dependency after the integration author leaves?

Record concrete answers, source references, and uncertainties separately. Do not convert enthusiasm, an architecture diagram, or willingness to attend a demo into adoption evidence.

## Consumer dossier template

| Field | Required evidence |
|---|---|
| Operator and system | Named accountable role and actual deployed or imminent application |
| Recurring job | Trigger, frequency, resource, and accepted output |
| Current path | Source modules, deployment boundary, identity/auth, workflow state, resource transaction |
| Failure or maintenance burden | Retained incident, intervention record, or clearly scoped implementation responsibility |
| Existing alternative | Current implementation plus cheapest credible change that would meet the requirement |
| Proposed responsibility transfer | Exact duties Chio assumes, duties it does not assume, and who operates each |
| Non-negotiable constraints | Deployment, data access, isolation, failure budget, compatibility, latency, support |
| Measurement availability | Direct timing/counters, operator effort records, and known missing denominators |
| Pilot commitment | Owner, environment, observation window, withdrawal procedure, acceptance criteria |
| Retention decision | Decision maker, date/event for evaluation, and reason to keep or remove Chio |

Unknown fields remain unknown. They must not be populated with estimates generated from repository line counts.

## Before-and-after responsibility map

Complete this with the operator before designing its adapter:

| Responsibility | Current owner | Proposed owner | Evidence of actual removal or new cost |
|---|---|---|---|
| Identity issuance | Pending | Pending | Existing IdP/workload identity retained or migration justified |
| Task authority and delegation | Pending | Pending | Exact custom code/configuration retired |
| Worker isolation and lifecycle | Pending | Pending | Existing runner retained or complete host replacement qualified |
| Graph/model state | Pending | Pending | Framework persistence retained unless a measured reason changes it |
| Resource ownership and commit | Pending | Resource or participating transactional adapter | Atomic boundary identified; no remote precheck substituted |
| Logical operation recovery | Pending | Pending | Known/unknown outcomes and operator procedures compared |
| Receipts and evidence retention | Pending | Pending | Actual relying party and retention requirements |
| Upgrades and incident response | Pending | Pending | New on-call, storage, key, and compatibility work accounted for |

## Whole-system accounting

Use engineering and operating measures separately. Record installation elapsed time, active operator time, implementation changes, required configuration, extra services, persistent stores, secret distribution, routine interventions, incident resolution time, and upgrade effort. Record failure outcomes and latency under the same required guarantees.

A qualitative value model is:

`net value = recurring burden removed + useful capability gained - migration burden - new operating burden - regression cost`

This qualitative model requires measured inputs before numerical evaluation. Do not monetize risk reduction without frequency and consequence evidence. A one-time migration can be acceptable for frequent work; a large recurring service cost may dominate a small code reduction.

## Early rejection

Reject a proposed pilot if no operator owns it, the problem is entirely hypothetical, the baseline is deliberately weak, a required trust boundary cannot be deployed, or the system cannot produce observable evidence of the intended benefit. An operator's refusal to surrender a critical responsibility is important evidence even if an integration is technically feasible.

If no candidate qualifies, return to the hypothesis set or choose a research contribution as the explicit objective. Do not construct a new application solely to create an adopter for the current implementation.
