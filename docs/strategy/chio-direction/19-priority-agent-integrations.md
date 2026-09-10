# Required agent integrations and kernel acceptance

Owner requirement, 2026-09-09: Claude Code, the Codex plugin, Cursor, Hermes,
Pi Agent, and OpenClaw are the highest-priority integration targets. All six
must work with the Chio kernel and pass real host acceptance testing.

The breakthrough condition of at least three independent agent systems remains
an intermediate dependency milestone. Completion of this integration program
requires **six of six**. A third passing integration cannot close the program
or defer the remaining targets. The owner has selected this scope; active-consumer
discovery is not a prerequisite for investigating and completing these integrations.

This document records requirements and source inspection. No acceptance run was
performed by writing it. Current end-to-end acceptance is **unverified for all six**.
Confidence in the required scope and located source paths is **high**; confidence
in complete operation on current host and kernel versions is **unknown**.

## Starting inventory

Paths below are relative to `/Users/connor/Medica/backbay`. Source was inspected
on 2026-09-09. These are discovery snapshots, not supported release pins.

| Target | Existing source | Inspected revision | Initial disposition |
|---|---|---|---|
| Claude Code | `standalone/chio-claude-code-plugin` | `db8ce99866aac612578a3378719266484fc6b6eb` | Plugin manifest, pre/post tool hooks, bridge calls, unit tests, and historical smoke present; current host acceptance pending |
| Codex plugin | `standalone/chio-codex-plugin` | `6841c72e82c982600bf5fb070181c4ab723cf6ed` | Plugin, skills, session/tool hooks, CLI wrapper, and historical smoke present; actual host enforcement pending |
| Cursor | `standalone/chio-cursor-plugin` | `2621009246ad94a4f8d42c2ca038a1027ba1f105` | Extension and hook templates present; complete kernel mediation and prevention of file edits need resolution |
| Hermes | `standalone/arc/sdks/python/chio-hermes` and `standalone/arc/docs/integrations/HERMES.md` | Top-level checkout `f5566d9a765c21cb36652a99c79de64968a656bf` | Native Python plugin and MCP configuration documented; complete host coverage and compatible kernel delivery pending |
| Pi Agent | No dedicated Chio integration located in the inspected Chio repositories | Unresolved | Confirm upstream package and extension mechanism, then locate or design the integration; absence in this search does not prove global absence |
| OpenClaw | `standalone/chio-open-claw-plugin` | `e9440c738477cc224c8c3f6257d3d5965cc15fb0` | Existing code is a hosted chat gateway; native OpenClaw agent interception and execution coverage remain unverified |

Shared TypeScript dependency: `standalone/chio-bridge`, inspected at
`f0f21945484b3e2a9ed79a5b2063bda98754ac80`. Inspect its CLI and daemon modes,
SDK versions, capability lifecycle, receipt verification, and packaged artifacts
as shared dependencies. A bridge test cannot substitute for any host's acceptance.

## Source findings that control the next work

- **Claude Code:** `hooks/hooks.json` registers pre/post tool hooks, and
  `hooks/pretooluse.mjs` calls the bridge. The historical `SMOKE.md` exercises
  a real host for an allowed call and a direct hook invocation for a denial.
  Verify host-enforced denial, missing/crashed/timed-out hooks, native and MCP
  tool routing, and delegated work against the selected host version.
- **Codex:** `.codex/hooks.json`, `src/hooks/pretooluse.ts`, and `smoke.sh`
  exist. The smoke's denial path directly invokes the hook. Loading a plugin
  and observing deny JSON do not establish that Codex suppresses the effect.
  Verify the installed host's supported plugin and hook contracts, and exercise
  real shell, file/patch, MCP, delegated, and resumed-session paths.
- **Cursor:** `templates/.cursor/hooks.json` wires edits to `afterFileEdit`.
  `hooks-src/shell.mjs` and `hooks-src/composer.mjs` contain local policy checks;
  `hooks-src/tool.mjs` calls the bridge for MCP. Establish a kernel-mediated
  path before protected writes and shell effects. An after-edit report or
  rollback cannot satisfy prevention of the original write. Test Agent,
  Composer, and inline edit/context surfaces wherever available in the selected
  release, and resolve reachable paths that evade the kernel.
- **Hermes:** `src/chio_hermes/hooks.py` returns without handling tools whose
  names lack the `chio_` prefix. `plugin.py` registers the Chio toolset;
  `handlers.py` and `executors.py` implement its operations. Prove that native
  tools, MCP servers, delegated agents, and subprocesses cannot bypass the
  protected boundary. `tests/test_against_real_sidecar.py` requires explicit
  opt-in and can skip when the binary is absent; it is not a live Hermes session.
- **Pi Agent:** pin the actual host and inventory built-in tools, extensions,
  subprocesses, custom tools, delegation where supported, and resume behavior
  before choosing interception points. Reuse the kernel contract without
  assuming another host's plugin is compatible.
- **OpenClaw:** the located `src/index.ts` starts Slack, Discord, and Telegram
  adapters plus an HTTP server. Its `SMOKE.md` explicitly omits live platform
  webhooks. Identify the actual OpenClaw agent runtime and prove its tool and
  resource boundary. Approval cards, capability issuance, and receipt fan-out
  alone cannot qualify that runtime. Test supported channel-triggered jobs,
  background work, delegation, and restart paths through the same boundary.

The public installer currently delivers the original CLI `0.1.0`. Hermes
documentation and its live-sidecar test refer to `chio start` and newer sidecar
surfaces. Select and deliver a compatible kernel/plugin/SDK combination for each
host. The installer smoke does not establish that these integrations are usable.

## Meaning of complete coverage

Create an action inventory for each pinned host version. Include filesystem
reads and writes, shell commands and descendants, network requests, git changes,
MCP/custom tools, agent delegation, background jobs, and externally visible
messages or mutations wherever the host exposes them. Sensitive reads count
because they can disclose information even without a resource mutation.

Every reachable consequential action in the supported mode must cross the
kernel's enforced boundary with the actual caller, scoped authority, and bound
request. Identify who performs the effect and how direct access is prevented.
A remote precheck followed by unrestricted local execution leaves a gap that
must be resolved. Required isolation may live in an existing host sandbox or
resource boundary; its enforcement must be tested.

Unsupported action paths must be disabled in that mode. Keeping a bypass
reachable while omitting it from the test matrix fails acceptance. Restricting
the mode must still permit the legitimate workflows this integration promises.
An agent must not be able to disable hooks, replace policy, recover unrestricted
credentials, or invoke a second ungoverned route to the same resource. Intentional
administrative changes by the trusted operator are a separate boundary.

## Acceptance gate, applied separately to all six

| Gate | Required observation |
|---|---|
| I01 Installation and versions | Install documented artifacts into an isolated profile without private sibling checkouts; record host, kernel, plugin, SDK, OS, configuration, and artifact identities; verify discovery and activation |
| I02 Useful work | A real host session completes a representative useful workflow with native and external tools as applicable; actual resource effects and correct results are observed; blanket denial cannot pass |
| I03 Denial and bypass prevention | A forbidden read/write/command/network action reaches the real host path and produces no forbidden effect; test alternate tools, shell indirection, descendants, delegation, and agent attempts to alter the enforcement configuration |
| I04 Kernel dependency | Kernel absent at startup, unavailable during a session, killed between calls, unreachable by network, and returning malformed responses all prevent new protected effects; also test plugin/hook loading failure, crash, timeout, and silent omission |
| I05 Authority | Expired/revoked capabilities, wrong principal/session/resource, scope escalation, aggregate budget exhaustion, and pending/rejected approval cannot authorize an effect; fresh valid authority restores legitimate operation |
| I06 Evidence | Trusted verification binds decisions and any claimed execution results to the actual caller and request; reject substituted request/result, wrong signer, malformed or forged evidence; keep authorization, observed effect, and final result states distinct |
| I07 Recovery | Retry, cancellation, resume, parallel calls, and kernel/host restart preserve required identity and truthful outcomes; unknown external outcomes are not silently redispatched; exercise resource fencing whenever handoff is supported |
| I08 Delivery and operation | The operator can install, configure, upgrade, recover, and remove the integration using shipped instructions; record overhead and interventions; required checks have no hidden skips and the tested version combination is published |

Use disposable files, local resource services, isolated profiles, and designated
test accounts for these checks. Observe resources independently of plugin logs:
file content, process markers, request counts, or resource transaction records.
Use negative controls to prove the observer would detect a forbidden effect.
Do not run legacy smoke scripts against the user's normal agent configuration;
the inspected Codex script includes deletion of plugin and citizen state under
the normal home directory and must be isolated or repaired before reuse.

Kernel loss cannot undo effects already committed. Tests must identify the
admission/dispatch/commit cutpoint, preserve any uncertain outcome, and verify
that subsequent authority is unavailable. Define what happens when evidence
storage or signing fails before and after an effect; never report an unrecorded
external result as a verified success.

## Execution and completion rules

1. Pin host identities, versions, and current extension contracts. Reconcile
   source with shipped bundles and existing evidence. Resolve Pi discovery and
   the OpenClaw runtime mapping during this step.
2. Define each action inventory and the actual enforcing boundary. Identify
   shared kernel/bridge compatibility work and host-specific gaps. Preserve
   existing security and release gates for the selected dependency slice.
3. Repair and qualify the existing integrations, and implement missing paths.
   Reuse bounded checks where they observe the real boundary. Keep one acceptance
   record per host with pass/fail/skipped/unavailable states and retained evidence.
4. Run I01-I08 through each real host using the proposed delivery artifacts.
   Every failed or unavailable required case remains open. A supported feature
   cannot become optional merely because its test is difficult.
5. Publish compatible artifacts and instructions after acceptance. Close this
   program only at six accepted integrations; preserve the three-system milestone
   as intermediate progress. Each record names the accepted versions and scope.

The same shared kernel contract should serve all six, with explicit versioned
extensions only when required. New demos, dashboards, frameworks, and benchmark
variants do not take priority over a failing required integration. No calendar
estimate or staffing model is inferred here.

Technical host coverage, independently operated adoption, and research novelty
retain separate acceptance. Six host integrations operated only by the project
author do not establish six independent adopters. Apply [04](04-consumers.md)
and [08](08-validation.md) when making an adoption claim.
