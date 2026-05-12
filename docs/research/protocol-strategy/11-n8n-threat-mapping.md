# 11 - n8n Threat-Mapping: Which Chains Chio Actually Blocks

> **Historical research note (PR 652):** Use [00-overview-v2.md](00-overview-v2.md) and [18-decision-packet.md](18-decision-packet.md) for planning. This file remains research input, not an implementation ticket.
>
> **Erratum (PR 652 review):** `args_schema` below is design shorthand for typed input constraints. Current workflow manifests use `input_contract` / `output_contract`, and the exact manifest-v2 constraint shape is deferred to [18-decision-packet.md](18-decision-packet.md).

## TL;DR verdict

Priority-1 designation for n8n is **partially justified, but for
narrower reasons than doc 05 implied.** Chio blocks one chain
end-to-end (Chain C, prompt-injection-driven webhook exfil),
substantially reduces one more (Chain E, poisoned self-hosted
instance), and adds forensic-only value on three (Chains A, B, F).
Chain D (raw webhook ingress abuse, which produced the Talos 686 percent
spike: "March 2026 [...] approximately 686% higher than January 2025")
is below Chio's layer entirely. Honest pitch: Chio blocks the
agent-side trigger and binds it forensically; in-workflow execution
and unauthenticated webhook hits are n8n's and the WAF's job.

## Chain enumeration

After reading both source reports plus the 2026 CVE cluster, the
distinct attack chains are:

- **Chain A - Supply-chain via malicious npm community node.** Eight
  packages including `n8n-nodes-hfgjf-irtuinvcm-lasdqewriit` (3,498
  weekly downloads pre-removal) impersonated Google Ads / generic
  integrations. Operator installs the node; `execute()` calls
  `this.getCredentials('googleAdsOAuth2Api')` and exfiltrates the
  decrypted OAuth credential set (developer tokens, client IDs, refresh
  tokens, MAC address, hostname) to
  `n8n-license-validator.onrender.com/validate-license`. Endor Labs:
  "Community nodes run with the same level of access as n8n itself."
- **Chain B - Credential theft via in-workflow RCE.** CVE-2026-25049
  (CVSS 9.4) and CVE-2026-27493 are expression-injection RCEs in
  workflow nodes (Form node, generic expressions) that let any user
  with workflow-create rights, or in some chains an unauthenticated
  caller, read the credential vault and exfiltrate. CVE-2026-21858
  (CVSS 10.0, "Ni8mare") chains content-type confusion on webhooks
  into arbitrary file read and admin session forgery. CVE-2026-25631
  (CVSS 5.3) is improper domain validation in the HTTP Request node:
  credentials can be sent to attacker-controlled hosts.
- **Chain C - Prompt-injection-driven webhook exfil.** Agent's LLM
  consumes untrusted content (email, doc, tool output), is tricked into
  invoking the n8n trigger tool with attacker-supplied workflow ID or
  payload, exfiltrating session data to an attacker-controlled
  workflow. This is the canonical agent-tool-call abuse scenario.
- **Chain D - Webhook ingress abuse (Talos n8mare).** Attacker
  discovers an exposed webhook URL on a self-hosted n8n; uses it to
  serve phishing payloads (CAPTCHA -> `DownloadedOneDriveDocument.exe`,
  Datto RMM backdoor), MSI RMM dropper, or tracking pixels. The agent
  is **not** involved; the n8n instance is the malware delivery
  surface. Talos: 686 percent volume spike (March 2026 vs January 2025).
- **Chain E - Poisoned self-hosted instance.** Operator (or upstream
  IT) installs an n8n distribution or Docker image that has been
  tampered with, or points the agent at a hostile mirror. Agent calls
  `https://n8n.attacker.example/webhook/<id>`; the instance re-routes
  outbound calls or harvests the request body.
- **Chain F - Persistent backdoor via workflow update.** Agent (or
  attacker who phished an n8n admin) calls n8n's REST API to
  create/update a workflow that adds an exfil step. Survives credential
  rotation if the workflow holds its own credentials. Endor noted the
  structural parallel to Shai-Hulud: "weaponized legitimate
  extensibility mechanisms to access centralized credential stores."

## Per-chain mapping against Chio surfaces

### Chain A - Malicious community node

Manifest gate and authority pinning do not block: Chio sees only the
agent's trigger to a legitimate n8n host, then the exfil POST to
`onrender.com` originates **from** the n8n host (not the agent), well
beyond `HttpEgressContract` reach. Receipts
(`crates/chio-core-types/src/receipt.rs:105`) and the
`ToolServerConnection` identity bind (`crates/chio-kernel/src/runtime.rs:255`)
give forensic value: post-breach, IR can replay "agent X triggered
workflow Y at time T with payload Z" and cross-reference Y's node list
against IOC feeds. **NOT blocked**: in-workflow `node.execute()`,
`getCredentials()`, the POST to the C2.

### Chain B - In-workflow RCE / credential exfil

Same exposure: manifest gate and authority pinning are upstream of the
RCE; the bug is inside n8n's expression engine or webhook handler.
Receipts attribute "which agent's call reached the vulnerable
expression." For CVE-2026-25049 (requires authenticated
workflow-create) and Chain F-style updates, value rises **if** Chio
also mediates n8n's management REST, which the current
webhook-trigger-only adapter design does not. **NOT blocked**:
everything. Patch n8n.

### Chain C - Prompt-injection-driven webhook exfil

This is where Chio's value is highest for Chio-routed agent-to-webhook egress.
The proposed `n8n.webhook_trigger` manifest with a per-tenant (host,
workflow_id) tuple plus typed input constraints rejects an injected workflow ID
or a suspicious payload field. `HttpEgressContract.allowed_authority_set`
(`crates/chio-egress-contract/src/lib.rs:27`) rejects an injected
target host before DNS is trusted; `deny_loopback` / `deny_link_local`
/ `deny_ipv6_ula` (`crates/chio-egress-contract/src/lib.rs:30-34`)
block SSRF pivots. Signed receipts (`receipt.rs:223`) record the
attempted call, decision, payload hash, and policy version so IR can
replay. Per-agent identity bind lets policy say "agent A may trigger
W1, W2; agent B may trigger W3." **NOT blocked**: an allowlisted
workflow whose body was silently updated by an admin compromise (-> F).

### Chain D - Webhook ingress abuse (Talos)

No Chio surface applies: the attacker fires the webhook directly from
a phishing email; no Chio-managed agent is involved. **NOT blocked**:
all of it. This is the chain that produced the 686 percent spike.
Belongs to n8n's auth, WAF / IP allowlisting, and email security
(Talos detected via email gateway telemetry, not endpoint). Honest
customer-facing framing required.

### Chain E - Poisoned self-hosted instance

Manifest gate (host pinning) and authority pinning **block** the
straightforward case where prompt injection or config drift points the
agent at `n8n.attacker.example`. The hard case - DNS spoof of the
pinned authority - is **not** blocked: `HttpEgressContract` enforces
authority match (`lib.rs:74-79`) but lacks a TLS pin field, so a
successful spoof to a hostile IP that presents a valid cert chain
slips through. Receipts and identity bind add forensic value. **NOT
blocked**: TLS-MITM with a valid cert chain (hostile CA, rogue
mTLS-terminating proxy). **Gap to file**: TLS-SPKI pin on
`HttpEgressContract`.

### Chain F - Persistent backdoor via workflow update

Manifest gate **partially** blocks: if the manifest exposes only
`n8n.webhook_trigger` (not `n8n.workflow_create` /
`n8n.workflow_update`), agent-driven backdoor planting is denied; an
out-of-band admin compromise still works. Authority pinning blocks
pushing a workflow to a non-allowed instance. Receipts have **high**
forensic value once the management REST surface is mediated (future
adapter): a receipt with `tool_name=n8n.workflow_update` and
`content_hash` of the workflow JSON lets an audit find "agent X added
an HTTP node pointing to onrender.com on date Y." **NOT blocked**:
admin-level n8n compromise outside any Chio-managed agent path.

## Tabular summary

| Chain | Manifest gate | Authority pinning | Receipts | Identity bind | NOT blocked |
|-------|---------------|--------------------|----------|---------------|-------------|
| A. Malicious community node | No | No (egress is from n8n host, not agent) | Forensic only | Forensic only | All in-workflow execution; credential exfil from n8n host |
| B. In-workflow RCE / cred exfil (CVE-2026-25049 etc) | No | No | Forensic only | Forensic only | All in-workflow execution; needs n8n patching |
| C. Prompt-injection webhook exfil | **Yes** (workflow-ID allowlist + typed input constraints) | **Yes** (allowed_authority_set + deny_loopback/link-local/ULA) | Full chain of custody | Per-agent workflow-ID policy | Allowlisted workflow whose body was changed (-> Chain F) |
| D. Webhook ingress abuse (Talos n8mare) | N/A | N/A | N/A | N/A | All of it - below Chio's layer |
| E. Poisoned self-hosted n8n | Partial (host pinning) | Yes (network), partial (DNS spoof of pinned authority not blocked without TLS pinning) | Forensic | Forensic | TLS-MITM with valid cert chain |
| F. Persistent backdoor via workflow update | Partial (if management surface not exposed) | Partial | Forensic high-value if mgmt surface mediated | Yes | Out-of-band admin compromise |

## Overall verdict

- **High-confidence block (priority-1 justified for this category)**:
  Chain C. Manifest gate + typed input constraints + authority pinning is
  end-to-end coverage for Chio-routed prompt-injection-driven webhook exfil
  scenario that is the agent-tool-call layer's signature attack.
- **Mixed - forensic only**: Chains A, B, F. Chio cannot prevent a
  malicious node from running inside n8n, a workflow-creation RCE,
  or an admin-compromise workflow rewrite. Signed receipts with
  payload hashes, agent identity, and policy version cut IR time and
  prove which trigger was responsible. Real value, forensic not
  preventive; customer comms must say so.
- **Partial - infrastructure-class**: Chain E. Authority pinning
  blocks the easy case; DNS spoof of the pinned authority needs TLS
  pinning, which `HttpEgressContract` does not currently provide.
- **Out of scope**: Chain D. The 686 percent volume spike is
  webhook-ingress abuse on exposed self-hosted instances. Doc-05's
  framing should be tightened: the spike justifies "n8n is a hot
  target," not "Chio blocks the spike." Chio blocks **agent-side**
  lateral movement against n8n, not unauthenticated ingress.

## Composition with incumbents

- **n8n RBAC** (Enterprise; Admin/Editor/Viewer per project; custom
  roles on Self-hosted/Cloud Enterprise) gates **human** workflow
  creation and credential sharing. Does not bind an **agent's**
  identity to a webhook trigger. Chio is additive: per-agent policy
  on top of per-human RBAC.
- **n8n credential vault**: defeated by Chains A and B once code is
  inside n8n. Only n8n hardening (community-node sandboxing,
  expression-engine fixes) helps; Chio does not.
- **Endor-style SCA**: closes Chain A at install time via IOC feeds
  for the eight known npm packages. Chio is the runtime
  attribution layer if SCA missed a zero-day.
- **n8n security advisories (Feb 6 2026; CVEs -21858, -25049, -25631,
  -27493)**: patching is the actual fix for B and D. Chio's value is
  bounded by patch latency: it caps **agent-driven** exposure during
  the patch window, not unauthenticated exposure.
- **WAF / egress firewall on the n8n host**: the right place for
  Chain D. Chio adds nothing here.
- **CVE-2026-25631** (HTTP Request node sends creds to wrong domain):
  n8n-internal bug. Chio's egress contract gates the agent's outbound,
  not n8n's internal nodes. Patch n8n.

Honest pitch: **Chio gates the agent-to-n8n trigger and produces
signed forensic receipts; n8n RBAC, n8n patches, your WAF, and SCA
own the rest of defense in depth.**

## Recommended manifest constraint primitives

To maximize Chain C coverage and improve Chain F:

1. **Workflow-ID allowlist** (per (tenant, agent_role) tuple). Already
   sketched in doc 05's workflow-ID constraint. Make it a typed
   policy primitive, not an ad-hoc pattern.
2. **Input-payload JSON schema constraints** with denylist patterns
   for sensitive substrings (regex on `payload.*` for
   `bearer\s`, `sk-[A-Za-z0-9]{20,}`, common cred shapes). Catches an
   agent tricked into POSTing its own session credentials as the
   payload.
3. **Output-domain allowlist** for the workflow's expected callback
   (if n8n's response carries a redirect URL or a `next_action` URL).
4. **Idempotency key required**, TTL window enforced
   (doc 05 phase 3). Blocks replay-amplification.
5. **Optional management-surface gate**: `n8n.workflow_create` and
   `n8n.workflow_update` as separate tools, default-denied for agents.
   Closes Chain F's agent-driven pathway.
6. **TLS pin field on `HttpEgressContract`**: SPKI hash of the n8n
   instance's certificate. Closes the Chain E DNS-spoof gap. Currently
   absent (`crates/chio-egress-contract/src/lib.rs:15-39` has no TLS
   pinning field). File as a follow-up.
7. **Tenant-scoped n8n instance binding**: receipt carries
   `tenant_id` (`receipt.rs:144`) and `tool_server`
   (`receipt.rs:113`); add a strict invariant that the egress
   authority equals a tenant-bound n8n hostname registered at policy
   load time. Closes Chain E's "wrong instance" sub-case at policy
   load rather than runtime.

## Sources

- Cisco Talos, "The n8n-n8mare":
  <https://blog.talosintelligence.com/the-n8n-n8mare/>
- Endor Labs, "n8mare on auth street":
  <https://www.endorlabs.com/learn/n8mare-on-auth-street-supply-chain-attack-targets-n8n-ecosystem>
- The Hacker News, CVE-2026-25049 disclosure:
  <https://thehackernews.com/2026/02/critical-n8n-flaw-cve-2026-25049.html>
- The Hacker News, CVE-2026-21858 (Ni8mare) disclosure:
  <https://thehackernews.com/2026/01/critical-n8n-vulnerability-cvss-100.html>
- Endor Labs, CVE-2026-25049 deep dive:
  <https://www.endorlabs.com/learn/cve-2026-25049-n8n-rce>
- The Hacker News, n8n supply-chain (community nodes):
  <https://thehackernews.com/2026/01/n8n-supply-chain-attack-abuses.html>
- n8n Security Bulletin, Feb 6, 2026:
  <https://community.n8n.io/t/security-bulletin-february-6-2026/261682>
- n8n RBAC docs: <https://docs.n8n.io/user-management/rbac/>
- n8n community-node risks:
  <https://docs.n8n.io/integrations/community-nodes/risks/>
- Upwind, CVE-2026-21858 Ni8mare:
  <https://www.upwind.io/feed/cve-2026-21858-n8n-unauthenticated-rce>
- SentinelOne, CVE-2026-27493:
  <https://www.sentinelone.com/vulnerability-database/cve-2026-27493/>
- Chio code: `crates/chio-egress-contract/src/lib.rs:15`,
  `crates/chio-egress-contract/src/lib.rs:30-34`,
  `crates/chio-egress-contract/src/lib.rs:74-79`,
  `crates/chio-core-types/src/receipt.rs:105`,
  `crates/chio-core-types/src/receipt.rs:144`,
  `crates/chio-core-types/src/receipt.rs:223`,
  `crates/chio-kernel/src/runtime.rs:255`,
  `crates/chio-workflow/src/manifest.rs:113`
- Prior swarm doc: `docs/research/protocol-strategy/05-workflow-orchestrator-mediation.md`
