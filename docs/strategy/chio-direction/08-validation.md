# Validation and rejection experiments

## Experimental contract

Every experiment answers a named decision. Record the hypothesis, current alternative, required guarantees, observable result, cost envelope, and what each outcome changes before writing supporting code. Thresholds come from the consumer's operating requirements. No result may be promoted from a narrow technical check into a broader adoption or market claim.

Use existing source fixtures, package qualification, process crash tests, resource adapters and receipt verifiers wherever they match the selected contract. The [testing map](../../integrations/acceptance/planning-testing-map-20260910.md.gz) identifies these assets and their limits. An integration test and a live-model task answer different questions; neither replaces the other when both are relevant.

## Experiment catalog

| ID | Decision | Method and observable result | Reject or revise when |
|---|---|---|---|
| X00 | Is there a consumer problem to pursue? | Complete the consumer dossier using actual source, incidents and operator input | No named responsibility or willing operator; current alternative already suffices |
| X01 | Does Chio add a needed property? | Compare the existing system, its smallest competent fix, and a narrow Chio integration with the same required guarantees | Improvement only appears against a deliberately incomplete baseline |
| X02 | Can responsibility transfer cleanly? | Replace one path; account for retired code/config/runbooks and new operations | Most old machinery remains and Chio adds a second coordinator |
| X03 | Is the selected boundary enforceable? | Attempt direct resource, credential, file, network and administrative access from the worker | Protected effects remain available outside the claimed boundary |
| X04 | Does ownership survive a real handoff? | Old worker pauses, owner changes, replacement commits, old worker resumes with current resource version | Stale worker commits after the ownership transition; or the transition is merely a precheck |
| X05 | Are uncertain effects handled honestly? | Lose responses and kill worker/host at relevant cutpoints; inspect actual resource effects | Redispatch changes the resource unexpectedly, uncertainty is erased, or resolution misattributes an observation |
| X06 | Can another operator install and recover it? | Cold environment, supported artifacts and instructions, recorded assistance and interventions | Author operates the system or hidden setup is necessary |
| X07 | Does it improve routine operation? | Operator runs representative work over an agreed observation window; measure overhead, failures and interventions | Benefit disappears in normal work or new burden exceeds agreed tolerance |
| X08 | Does portable evidence change a relying party's decision? | Party verifies with its own trust policy and makes the actual acceptance decision | Evidence is ornamental, incomplete for the decision, or needs private author assistance |
| X09 | Can it be maintained and removed? | Upgrade, restart, backup/restore, credential/authority expiry, and rollback/removal drills | State becomes unsafe, operating burden is unacceptable, or exit requires a rewrite |
| X10 | Is the contract reusable beyond its first integration? | A second independent maintainer integrates a different application using the supported contract | Requires substantial new kernel/resource semantics or copies the first adapter wholesale |
| X11 | Is there a systems research contribution? | Select a precise invariant and compare against related work and competent implementations under identical assumptions | Claimed novelty is already specified, assumptions remove the hard problem, or behavior cannot be distinguished |
| X12 | Do all six required agent integrations work through the kernel? | Apply I01-I08 in [19](19-priority-agent-integrations.md) to Claude Code, the Codex plugin, Cursor, Hermes, Pi Agent, and OpenClaw; observe real host actions and resources | Any required host, action path, failure case, or delivery check fails, skips, or remains unavailable |

X00 precedes a consumer-specific adoption pilot. X03-X05 qualify mechanism properties. X06-X09 qualify the selected offering. X10 tests expansion. X11 is required if technical novelty is the chosen breakthrough objective, and can be pursued without claiming product demand. X12 is the owner's required integration program and can proceed independently of X00. Historical smokes and direct hook invocations cannot close real host acceptance.

## Baseline design

Use the real current system as baseline B0. If it lacks a required control, evaluate B1: the smallest competent change using its existing stack. Chio C1 competes with B1 for the same requirement. Keep an intentionally deficient configuration only as a clearly labeled negative control showing that the workload can expose the failure.

Match task input, resource semantics, workload bounds, relevant model/configuration, environment and failure schedule. Do not give Chio deduplication or transactional ownership while omitting it from the competent resource baseline. Account for different guarantees explicitly when equivalence is impossible.

For deterministic authority and crash questions, a controlled agent is appropriate. For questions about model adaptation, task completion and human intervention, use the actual intended application behavior. A larger live-model benchmark does not repair an unfair resource comparison.

## Fault matrix

| Interruption/change | Observable resource oracle | Expected distinction |
|---|---|---|
| Before durable intent | No protected effect | Admission failure versus lost client request |
| After intent, before delivery | Effect absent unless later delivery is possible | Safe recovery depends on actual dispatch fence |
| During tool delivery | Operation lookup and side-effect count where available | Known refusal versus possible external effect |
| After commit, before response | Actual committed state and operation record | Resource fact may be known while original receipt is unavailable |
| After response, before retained result | Effect count and host state | Unknown outcome is possible despite a successful resource |
| After result retention, before framework checkpoint | Original operation identity and receipt | Framework resumes without inventing a new intent |
| During ownership transition | Ordered assignment and mutation records | Old commit before transition differs from stale commit after it |
| During cancellation/revocation | Admission, dispatch, commit and acknowledgement order | In-flight effects are not falsely described as prevented |
| Expired credentials or capability | Actual authenticated route and authority decision | Credential rotation differs from renewed task authority |
| Store restore or key rotation | Serving fences, trusted key history, retained records | Old state or wrong signer cannot silently become valid authority |

Reuse existing cutpoint machinery only where it can observe the real effect. A proxy that invents a resource response cannot establish resource correctness. Negative controls must demonstrate that an extra dispatch or forbidden write would be detectable.

## Measurement record

| Category | Record |
|---|---|
| Provenance | Source commit, configuration digest, package/binary identities, environment, resource version |
| Execution | Logical operations, actual deliveries where observable, attempts, known/unknown outcomes, effects |
| Security | Allowed legitimate operations, denied violations, observed prohibited effects, bypass attempts, false denials |
| Utility | Accepted task outputs, corrections, manual intervention, unresolved work |
| Cost | Cold installation, active operator time, runtime overhead, storage, services, incident/upgrade effort |
| Evidence | Original receipts, verifier trust configuration, output bindings, missing data and skipped checks |
| Adoption | Responsibility removed, responsibility retained, new obligations, operator retention decision |

Report counts and denominators. Zero observed violations establish only the result for the finite tested set. Small cohorts do not establish population success rates. Do not derive wall time from summed provider durations, or evaluate the corrected verifier with predecessor-only latency.

## Acceptance and failure decisions

**Technical rejection:** an applicable required property fails. Repair the bounded defect or select an architecture that can satisfy it. Passing unrelated tests does not compensate.

**Product rejection:** the properties work but the consumer does not obtain sufficient benefit at acceptable cost. Improve the offering only if the observed cause is specific and repairable within the agreed scope; otherwise return to the hypothesis set.

**Research rejection:** the proposed contribution lacks novelty or depends on assumptions that eliminate the intended problem. Preserve useful implementation and revise the claim.

**Inconclusive:** measurements or access are insufficient. Record precisely what is missing. Do not expand the experiment until the missing evidence is available or a bounded follow-up can obtain it.

Before a follow-up, state what new observation can change the previous conclusion. Repeating the same successful demo, changing model size without a relevant question, or adding another wrapper is not a follow-up rationale.

## Planning limits

No experiments in this document have been executed by writing the plan. Existing retained qualifications remain separately cited in the evidence baseline. Customer thresholds and observation windows remain pending. Those gaps cannot be filled by a passing documentation check.
