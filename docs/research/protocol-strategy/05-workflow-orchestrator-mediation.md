# 05 - Workflow Orchestrator Mediation

> **Erratum (wave 3):** The n8n priority-1 framing below originally cited the Cisco Talos 686% abuse spike. Per the wave-3 n8n threat-chain mapping ([11-n8n-threat-mapping.md](11-n8n-threat-mapping.md)), that spike is **Chain D** (unauthenticated webhook ingress abuse), which is **below Chio's layer and is NOT blocked by Chio**. The actually-blocked threat is **Chain C** (prompt-injection-driven agent-to-webhook exfiltration), where manifest workflow-ID allowlist + `args_schema` + `HttpEgressContract` authority pinning + loopback / link-local / ULA denial give end-to-end coverage and receipts add chain-of-custody. Keep n8n as priority-1; restrict the value-prop wording to Chain C.

## TL;DR

Chio should cover three workflow orchestrators via egress mediation, in this
order: (1) **n8n** first (active 2026 abuse surface, weakest incumbent
security story, where Chio's signed-receipt model is a genuine upgrade);
(2) **Zapier** and **Make.com** together (the largest "agent fires a
webhook" volume in production, near-identical wire shape, one adapter
covers both); (3) **GitHub Actions** as a deliberate second wave (GitHub
shipped an Agentic Workflow Firewall in 2026, but the agent-attribution
gap on `workflow_dispatch` is real and Chio's cross-platform receipt
chain is the differentiator). **Temporal**, **Airflow**, **AWS Step
Functions**, and **Argo Workflows** should be deferred: strong incumbent
controls, lower 2026 attack frequency, and Chio already has in-platform
SDKs for Temporal and Airflow that cover the realistic threat
(activity-level mediation, not trigger-level).

## Phase 1 - Existing Chio coverage (audit)

Grep over `crates/`, `sdks/`, and `docs/` surfaced the following:

- **Temporal**: `sdks/python/chio-temporal/` is shipped: an in-platform
  `ChioActivityInterceptor` that gates each Activity, not the
  signal/start-workflow trigger
  (`sdks/python/chio-temporal/README.md:1`).
- **Airflow**: `sdks/python/chio-airflow/` is shipped as a `ChioOperator`
  + `chio_task` decorator + DAG listener
  (`sdks/python/chio-airflow/README.md:1`). Same shape: it gates tasks
  inside the DAG, not the agent's REST trigger.
- **GitHub Actions**: only referenced in supply-chain contexts (Sigstore
  Fulcio OIDC identity at
  `crates/chio-attest-verify/tests/fixtures/oidc_mismatch.rs:3`, CI
  billing runbook, ClusterFuzzLite). No integration that mediates an
  agent dispatching a workflow.
- **n8n, Zapier, Make.com, Step Functions, Argo Workflows**: zero hits.
  Argo appears as a future-question annotation in the K8s Jobs doc
  (`docs/protocols/K8S-JOBS-INTEGRATION.md:429`).
- **Egress gate**: `HttpEgressContract` at
  `crates/chio-egress-contract/src/lib.rs:15`. Already pins scheme,
  authority set, redirect chain, response byte cap; fail-closes on
  missing contract via `enforce_required`
  (`crates/chio-egress-contract/src/lib.rs:84`).
- **Bridge contract**: `ToolServerConnection`
  (`crates/chio-kernel/src/runtime.rs:255`) is the primary policy gate;
  the egress contract is a second, narrower gate after the bridge has
  resolved the call. Complementary: bridge gate binds *which tool*,
  egress gate binds *which wire destination*.

Implication: Temporal and Airflow already have in-platform integration,
so egress mediation for them is additive and lower priority than
n8n/Zapier where there is nothing.

## Phase 2 - Per-platform cover/skip decisions

### n8n - COVER (priority 1)

- **Attack surface 2026**: Cisco Talos's "n8mare" report
  (<https://blog.talosintelligence.com/n8mare-n8n-abuse-spike>) documented a
  686 percent spike in n8n abuse in the first half of 2026, driven by
  publicly exposed `Webhook` and `Execute Workflow` nodes plus
  prompt-injection-laced workflow definitions imported from the community
  marketplace.
- **Mediation value**: n8n's auth model is API-key-per-instance with
  optional Basic auth on webhooks; there is no per-call signed-receipt
  story, no per-input policy. Chio's `HttpEgressContract` + policy guards
  add real coverage: pin the n8n host, pin the webhook path prefix, pin
  the workflow ID set the agent can trigger.
- **Wire shape**: agent triggers a single HTTPS POST to
  `https://<host>/webhook/<id>` or `/webhook-test/<id>`. Perfect fit for
  the egress contract.
- **Incumbent solution**: weak. Self-hosted n8n shifts security entirely
  to the operator.

### Zapier - COVER (priority 2)

- **Attack surface 2026**: Zapier is the highest-volume agent integration
  surface in production (the "Anthropic tool call -> Zapier MCP" path is
  pervasive). The threat is not prompt injection of Zapier itself but
  agent overreach: an agent firing a `Send Email`, `Create Calendar
  Event`, or `Post to Channel` Zap that was not in scope.
- **Mediation value**: Zapier's MCP and Catch Hook endpoints terminate on
  `hooks.zapier.com` with a per-hook URL secret in the path. Chio adds
  per-call policy (which Zap, which inputs, which time window) plus a
  signed receipt that survives across Zapier's opaque downstream actions.
- **Wire shape**: single HTTPS POST to
  `https://hooks.zapier.com/hooks/catch/<acct>/<hook_id>/` with a JSON
  body. Egress contract fits cleanly.
- **Incumbent solution**: Zapier provides hook-URL secrecy and per-Zap
  toggles; no policy engine, no receipts.

### Make.com - COVER (priority 2, shares Zapier adapter)

- **Attack surface 2026**: similar to Zapier but smaller volume. Make's
  Scenario webhooks (`https://hook.eu1.make.com/<token>`) are also a
  common agent target.
- **Mediation value**: identical to Zapier. Implement once, parameterize
  per provider.
- **Wire shape**: single HTTPS POST with a JSON body to a per-scenario
  URL.
- **Decision**: ship as a sibling adapter in the same release as Zapier.
  Same tool manifest schema, different `tenant_egress_namespace` and
  authority allowlist.

### GitHub Actions - COVER (priority 3, deliberate)

- **Attack surface 2026**: agents firing `workflow_dispatch` and
  `repository_dispatch` to run on-demand deploy, release-cut, and
  data-migration workflows. GitHub shipped the **Agentic Workflow
  Firewall** in 2026
  (<https://github.blog/security/agentic-workflow-firewall-2026>) which
  gates *inside* the runner: it inspects what an Actions workflow does
  during execution. It does not authenticate which agent triggered the
  dispatch, only which PAT or GitHub App did. That attribution gap is
  Chio's value.
- **Mediation value**: medium. The duplicative concern is real - GitHub
  is doing the in-runner work. Chio's contribution is the outside-in
  binding: which agent, on which user's behalf, fired which dispatch,
  with what inputs, against which (repo, ref, workflow_id) tuple, and a
  receipt that chains into the rest of the agent's session.
- **Wire shape**: single HTTPS POST to
  `https://api.github.com/repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches`.
  Egress contract fits.
- **Decision**: cover, but as priority 3. Lead with the
  agent-attribution + cross-platform-receipt narrative, not "we firewall
  Actions" (we do not; GitHub does).

### Temporal - DEFER

gRPC signal/start, not clean HTTP. Temporal's 2026 `Principal` field
(<https://docs.temporal.io/principal-2026>) closes the agent-attribution
gap at the protocol level. `chio-temporal` already handles the
inside-the-workflow story. If we revisit, egress mediation goes at the
SDK boundary (intercepting the client builder), not HTTP.

### Apache Airflow - DEFER

REST `POST /api/v1/dags/{dag_id}/dagRuns` fits the egress contract, but
`chio-airflow` already covers the in-DAG story and agents triggering
DAGs are far less common in 2026 than agents hitting Zaps or Actions.
Reuse the adapter pattern if a customer asks.

### AWS Step Functions - DEFER

`StartExecution` via AWS SDK (SigV4). IAM is strong on authorization;
the gap is which agent assumed the role, which Chio's existing IAM
role-assumption mediation is the right place to address, not a
Step-Functions-specific adapter.

### Argo Workflows - DEFER

`POST /api/v1/workflows/{namespace}` to the Argo Server, or `kubectl`
via the K8s API. K8s RBAC is reasonable but lacks agent-attribution.
Consolidate when the K8s Jobs work lands; the open question is already
flagged at `docs/protocols/K8S-JOBS-INTEGRATION.md:429`.

## Phase 3 - Mediation pattern design

For each covered platform the egress mediation lives at the
`HttpEgressContract` boundary, invoked from the adapter that the agent is
calling through (typically an MCP bridge or the Anthropic tools API
bridge). The pattern:

### Tool manifest entry

The skill manifest (`crates/chio-workflow/src/manifest.rs:13`) is a step
list; the new entry is a `SkillStep` whose `tool_name` is a
platform-specific trigger primitive. Example for GitHub Actions:

```yaml
schema: chio.skill-manifest.v1
steps:
  - server_id: chio.orchestrator-egress
    tool_name: github_actions.workflow_dispatch
    args_schema:
      repo: { type: string, pattern: "^[\\w.-]+/[\\w.-]+$" }
      workflow_id: { type: string }
      ref: { type: string, pattern: "^refs/(heads|tags)/.+$" }
      inputs: { type: object, additionalProperties: { type: string } }
```

n8n / Zapier / Make.com share a `webhook_trigger` shape:

```yaml
  - server_id: chio.orchestrator-egress
    tool_name: n8n.webhook_trigger        # or zapier.catch_hook / make.scenario_run
    args_schema:
      workflow_id: { type: string }
      payload: { type: object }
      idempotency_key: { type: string }
```

### Policy primitives

The kernel evaluates against the manifest before the egress contract is
consulted. Policy gates at the bridge layer:

- **Allowed targets**: per-tenant allowlist of (provider, account, workflow
  identifier). For GitHub Actions this is the (repo, workflow_id, ref)
  triple; for n8n/Zapier/Make it is (host, workflow_id).
- **Argument constraints**: regex/literal allow on `inputs` keys, value
  patterns on sensitive fields (no `ref: refs/heads/main` if the policy
  says staging-only).
- **Time-of-day**: existing time-window guards apply unchanged.
- **Rate / budget**: existing `budget_envelope` and rate-limit guards
  apply.

At the egress layer the `HttpEgressContract` then re-asserts the wire
target: `allowed_authority_set` pins `api.github.com`,
`hooks.zapier.com`, `hook.eu1.make.com`, or the tenant's n8n host.
`deny_loopback`, `deny_link_local`, `deny_ipv6_ula` stay on by default
to block SSRF pivots when the agent supplies a host argument.

### Receipt

The signed decision receipt embeds:

- `tool_input_hash`: SHA-256 of canonicalized tool arguments (so the
  receipt binds to the exact dispatch payload).
- `egress_target`: the `ValidatedHttpEgressTarget`
  (`crates/chio-egress-contract/src/lib.rs:42-47`) returned from
  enforcement (scheme + authority + tenant namespace).
- `provider_run_id`: the dispatch / run identifier returned by the
  platform (GitHub returns a 204 with no body for `dispatches` so we
  derive `run_id` from a follow-up `runs` query keyed by the
  client-provided `idempotency_key`; Zapier and Make return a JSON body
  with `request_id`; n8n returns the execution ID).
- `provider_run_url`: a human-navigable URL for IR
  (`https://github.com/<owner>/<repo>/actions/runs/<id>`,
  `https://<host>/workflow/<id>/executions/<exec_id>` for n8n).
- `policy_version` and `manifest_id`: already standard receipt fields.

### Failure modes

- **Agent retry / replay**: tools require an `idempotency_key` in args.
  The kernel rejects a second invocation with the same key inside the
  TTL window (existing replay-protection guard). The platform-side
  idempotency (GitHub does not honor it on dispatches; n8n/Zapier do
  partially) is best-effort.
- **Platform 5xx**: the receipt records the attempt with
  `verdict: allowed, outcome: upstream_error`. Retries are agent-driven
  and re-enter policy; the kernel does not retry on the agent's behalf.
- **Platform 2xx but downstream failure**: out of scope. The receipt
  records the dispatch, not the workflow outcome. Workflow outcome
  capture is the in-platform SDK's job (the existing `chio-temporal` and
  `chio-airflow` story).
- **DNS hijack**: `HttpEgressContract` enforces authority match before
  the DNS resolution result is trusted
  (`crates/chio-egress-contract/src/lib.rs:74-79`).

### Composition with existing bridges

When the agent calls through MCP or the Anthropic tools API, the call
already passes the `ToolServerConnection` gate. The egress contract is
the second, narrower gate that catches the case where a bridge-resolved
tool nevertheless tries to reach an out-of-scope authority. For workflow
triggers the two gates coincide most of the time, but the egress gate is
what catches the attack where a manifest-allowed tool is tricked into
hitting an attacker-controlled host via path or argument smuggling.

## Phase 4 - Phased rollout

- **Phase A (next quarter)**: ship the n8n adapter
  (`chio-orchestrator-egress` crate, `n8n.webhook_trigger` tool). Lead
  customer-facing comms with the Talos n8mare reference. Bundle a
  default `HttpEgressContract` template per tenant.
- **Phase B (one quarter behind A)**: ship Zapier and Make.com as
  sibling adapters under the same crate; same manifest shape, different
  authority lists. Zapier first by volume.
- **Phase C (opportunistic)**: GitHub Actions
  `workflow_dispatch` / `repository_dispatch`. Pair the launch with a
  cross-receipt demo (agent dispatch -> Actions run -> Sigstore release
  signature, all chained). Use the existing Sigstore identity
  infrastructure
  (`crates/chio-attest-verify/tests/fixtures/oidc_mismatch.rs:3`) as the
  trust anchor on the Actions side.
- **Defer with hooks**: Temporal, Airflow, Step Functions, Argo. Keep
  the tool-manifest schema generic enough that an adapter for any of
  them is two days of work when a customer surfaces demand. The
  in-platform `chio-temporal` and `chio-airflow` SDKs continue to be the
  primary recommendation for those platforms; egress mediation is the
  complementary outside-in gate only if the customer needs both.

## References

- Cisco Talos, n8mare report:
  <https://blog.talosintelligence.com/n8mare-n8n-abuse-spike>
- GitHub Agentic Workflow Firewall:
  <https://github.blog/security/agentic-workflow-firewall-2026>
- Temporal Principal field (2026):
  <https://docs.temporal.io/principal-2026>
- `HttpEgressContract`:
  `crates/chio-egress-contract/src/lib.rs:15`
- `ToolServerConnection`:
  `crates/chio-kernel/src/runtime.rs:255`
- `chio-temporal` Python SDK:
  `sdks/python/chio-temporal/README.md:1`
- `chio-airflow` Python SDK:
  `sdks/python/chio-airflow/README.md:1`
- Argo open question:
  `docs/protocols/K8S-JOBS-INTEGRATION.md:429`
