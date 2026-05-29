# AGNTCY Revisited: Post-ACP Survey and Integration Recommendation

Status: draft, May 2026. **Supersedes [08-agntcy-acp-bridge-spec.md](08-agntcy-acp-bridge-spec.md)**
(factually obsolete after `agntcy/acp-spec` was archived on 2026-04-11)
and **partially supersedes** the AGNTCY section of
[02-decentralized-agent-networks.md](02-decentralized-agent-networks.md)
and the Wave-C `chio-bridge-agntcy` line in
[00-overview-v2.md](00-overview-v2.md).

## TL;DR

AGNTCY as an umbrella project is **alive and growing**, but its
Agent-Connect-Protocol surface (the one doc 08 specified a bridge for)
is **dead**: `acp-spec` and `acp-sdk` were both archived on
2026-04-11, and the function ACP served (REST tool-call surface) has
been absorbed by Linux-Foundation A2A
([linuxfoundation.org/press](https://www.linuxfoundation.org/press/a2a-protocol-surpasses-150-organizations-lands-in-major-cloud-platforms-and-sees-enterprise-production-use-in-first-year),
[zylos.ai](https://zylos.ai/research/2026-03-26-agent-interoperability-protocols-mcp-a2a-acp-convergence)).
SLIM, OASF, Identity, and Directory remain healthy, but **none of them
carry tool-call traffic** in a way that fits Chio's
`ToolServerConnection` contract
([crates/chio-kernel/src/runtime.rs:255](../../../crates/chio-kernel/src/runtime.rs)).
The only viable Chio integration point is **consume-only**: read
AGNTCY Directory + Identity records via a `DirectoryProvider` seam, in
the same shape doc 02 already proposed, to drive bridge wire-up for
A2A or MCP. **Do not build any AGNTCY-native bridge.** The
`chio-bridge-agntcy` crate proposed in doc 08 and overview-v2 should
be dropped.

## Archival Confirmation

`agntcy/acp-spec` is archived. GitHub API returns `"archived": true`,
`"updated_at": "2026-04-11T15:32:56Z"`, `"pushed_at":
"2025-05-23T13:54:01Z"` (no commits in eleven months before
archival). Companion repo `agntcy/acp-sdk` is also archived, both
flipped on 2026-04-11. `agntcy/workflow-srv` ("Run your agents and
expose them through ACP") and `agntcy/workflow-srv-mgr` are archived
too. Evidence: `gh api repos/agntcy/acp-spec`,
`gh api repos/agntcy/acp-sdk`,
[github.com/agntcy](https://github.com/agntcy). The doc-08 framing of
"frozen 2026-04-11" was wrong - that date is the archival event, not a
stable-release event.

The current `docs.agntcy.org` component list omits ACP entirely. The
six documented components are OASF, Directory, SLIM, Identity,
Observability/Evaluation, and Security
([docs.agntcy.org](https://docs.agntcy.org/)). Industry coverage
explicitly states ACP "has merged with A2A" under the LF umbrella
([zylos.ai](https://zylos.ai/research/2026-03-26-agent-interoperability-protocols-mcp-a2a-acp-convergence)).
The July 2025 A2A donation to Linux Foundation
([developers.googleblog.com](https://developers.googleblog.com/en/google-cloud-donates-a2a-to-linux-foundation/))
plus AGNTCY's own LF adoption
([linuxfoundation.org/press](https://www.linuxfoundation.org/press/linux-foundation-welcomes-the-agntcy-project-to-standardize-open-multi-agent-system-infrastructure-and-break-down-ai-agent-silos))
appear to have collapsed the two REST tool-call surfaces into one.

## Per-Component Survey

Repo metadata from `gh api orgs/agntcy/repos`. Last-push dates as of
2026-05-11. Apache-2.0 unless noted. Governance: Linux Foundation
hosted, contributed by Cisco / Outshift plus
LangChain-LlamaIndex-Galileo-Dell-Oracle-Red-Hat consortium.

### SLIM (Secure Low-Latency Interactive Messaging) - active

Repo: [github.com/agntcy/slim](https://github.com/agntcy/slim), 189
stars, pushed 2026-05-11. Spec at
[github.com/agntcy/slim-spec](https://github.com/agntcy/slim-spec).
**Description by the project itself:** "next-generation communication
framework that provides the secure, scalable transport layer for AI
agent protocols like A2A and MCP." Three-tier architecture
(data-plane in Rust, control-plane in Go, session-layer with MLS
end-to-end encryption). Active integrations: `slim-a2a-{python,
go, dotnet, java}`, `slim-mcp-{python, rust}`, `slim-otel`. Has an
IETF draft (`draft-mpsb-agntcy-slim-01`).

**Wire shape:** pub/sub + multicast RPC ("SlimRPC Multicast: One Call,
Every Agent", [blogs.agntcy.org](https://blogs.agntcy.org), Mar 31
2026). SLIM is a **substrate**, not a tool-call surface. It carries
A2A or MCP payloads; the tool-call semantic lives at the payload
layer.

**Bridge fit:** **No.** A tool-call bridge over SLIM means either (a)
re-implementing A2A and MCP on top of SLIM transport, or (b) treating
SLIM as transport for an existing bridge. (b) is plausible later as a
transport plugin to the existing MCP/A2A bridges, not a new bridge
crate. (a) violates the v2 non-goal "a replacement of MCP or A2A at
the wire-protocol ecosystem level"
([spec/PROTOCOL.md:114-115](../../../spec/PROTOCOL.md)).

**Action:** Monitor. Revisit if a Chio user demands MCP-over-SLIM.

### OASF (Open Agentic Schema Framework) - active

Repo: [github.com/agntcy/oasf](https://github.com/agntcy/oasf), 310
stars, pushed 2026-04-27. Apache-2.0. OCSF-derived JSON schema for
agent capability records (skills, domains, modules).

**Wire shape:** It is not a wire protocol; it is a schema. Records
are content addressed and stored in Directory.

**Bridge fit:** **No.** OASF is a vocabulary. If Chio ever consumes
Directory records (see below), the records carry OASF; treat OASF as
data we deserialize, not a protocol we bridge.

**Action:** Consume passively as the record schema inside Directory
results.

### Directory (`agntcy/dir`) - active

Repo: [github.com/agntcy/dir](https://github.com/agntcy/dir), 150
stars, pushed 2026-05-11. Spec at
[github.com/agntcy/dir-spec](https://github.com/agntcy/dir-spec). gRPC
API (proto in [agntcy](https://github.com/agntcy/dir/tree/main/proto)
subdir), DHT-backed distributed registry. SDKs in Go, Python, JS; an
MCP-server adapter
([github.com/agntcy/dir-mcp](https://github.com/agntcy/dir-mcp)).

**Wire shape:** request/response gRPC for publish/search/resolve. No
tool-call invocation surface.

**Bridge fit:** **Consume-only.** Directory is a service registry; it
returns OASF records that say "here is an agent at this URL with this
schema." Chio's role is not to mediate the registry; Chio uses it as
input to wire up an MCP or A2A bridge. This is exactly the
`DirectoryProvider` seam doc 02 already sketched
(02:118-126), minus the ACP coupling.

**Non-goal collision check:** v2 prohibits "permissionless public
identity or wallet discovery that widens local trust"
([spec/PROTOCOL.md:107-108](../../../spec/PROTOCOL.md)). A
`DirectoryProvider` that consults the public DHT and treats every
returned record as trusted would violate this. The seam must be
**read-only, advisory, and allowlist-gated**: returned candidates
become bridge wire-up suggestions, never capability scope. That
matches doc 02's stance and doc 08's intent.

**Action:** Build a single `DirectoryProvider` trait in
`chio-directory` with a static-config impl now, and a `dir`-backed
impl as an opt-in feature later. **Drop** the bridge crate;
**keep** the directory crate from doc 08.

### Identity (`agntcy/identity` + `agntcy/identity-service`) - active

Repos: [github.com/agntcy/identity](https://github.com/agntcy/identity)
(93 stars, pushed 2026-02-24), spec at
[identity-spec](https://github.com/agntcy/identity-spec), service at
[identity-service](https://github.com/agntcy/identity-service) (pushed
2026-04-13). Issues W3C DIDs and verifiable credentials (VCs) for
agents, MCP servers, and multi-agent systems. BYOID supported:
`did:web`, `did:jwk`, plus IdP-anchored IDs (Okta, Google A2A
agent-card IDs).

**Wire shape:** OIDC-style issuance + VC verification. Not a tool-call
surface.

**Bridge fit:** **Consume-only**, identical pattern to existing HTTP
identity inheritance
([crates/chio-http-core/src/identity.rs:44](../../../crates/chio-http-core/src/identity.rs)).
If Chio is about to call an agent that presents an AGNTCY VC in its
bridge metadata, the bridge resolves the VC and feeds the verified
DID into the receipt's actor chain. No new crate; this is a feature
on `chio-http-core` or whichever bridge sees the credential.

**Non-goal collision check:** Same as Directory: identity-resolution
output advises bridge wire-up; it does not widen capability scope or
replace the kernel's signed-truth source.

**Action:** Defer. Add only when a real consumer asks (Webex is the
likely first; see below).

### CSIT, Observe, Telemetry-Hub - active, internal

CSIT ([agntcy/csit](https://github.com/agntcy/csit)) is the internal
integration-test harness. Observe and Telemetry-Hub are
OpenTelemetry-flavored SDKs for MAS observability. None is a
tool-call surface. Ignore.

### AGP - does not exist

No `agntcy/agp` repo. Mentions of "Agent Gateway Protocol" in
industry surveys
([4sysops](https://4sysops.com/archives/comparing-ai-protocols-mcp-a2a-agp-agntcy-ibm-acp-zed-acp/))
conflate SLIM or an older internal name. Not real.

### App SDK, OIDC-Gateway, SHADI, dir-importer, others - active, internal

All active, none are bridge candidates. `dir-importer` and `dir-mcp`
hint AGNTCY itself is moving toward "consume MCP into Directory"
rather than "publish ACP from Directory."

## Identity + Directory Deep-Dive

Webex's Agent Central Service is the only documented production
consumer of AGNTCY
([developer.webex.com](https://developer.webex.com/blog/webex-leverages-agntcy-directory-and-identity-for-agentic-apps)).
The post explicitly names two components: Directory ("registration,
search, and resolution of various agentic resource records across the
Webex ecosystem") and Identity ("verifiable credential issuance,
validates signatures, and provides interoperable agentic resources'
identity resolution"). It alongside-mentions MCP and A2A as the
**tool-call protocols** Webex implements. **It does not mention ACP
or SLIM at all.** That is the production map: Identity + Directory
are the connective tissue; the call-surface is MCP or A2A. ACP was
never on the Webex path even when it was alive.

For Chio this is structural: the AGNTCY pieces Webex consumes are the
same pieces Chio should consume, in the same role (registry +
identity lookup), and the parts Webex skips (ACP, SLIM) are the parts
Chio should skip too. The doc-08 design was upside-down: it built the
dead piece and made the live pieces optional. The corrected design
builds nothing AGNTCY-specific and treats Directory + Identity as
inputs to bridges that already exist.

## Recommendation Table

| Component | Status | Bridge fit | Recommended action |
|-----------|--------|------------|--------------------|
| ACP (`acp-spec`, `acp-sdk`) | Archived 2026-04-11 | n/a | **Reject.** Subsumed by A2A under LF. No bridge. |
| SLIM | Active, healthy | No (substrate) | Monitor. Possible transport plugin to MCP/A2A bridges much later. |
| OASF | Active, healthy | No (schema) | Consume as record format inside Directory results. |
| Directory (`dir`) | Active, healthy | Consume-only | **Build** `DirectoryProvider` seam in `chio-directory` (static-config impl now, `dir`-backed impl opt-in later). |
| Identity (`identity`, `identity-service`) | Active, healthy | Consume-only | Defer. Add VC-resolution to existing HTTP identity inheritance when a consumer needs it. |
| CSIT | Internal test harness | No | Ignore. |
| Observe / Telemetry-Hub | Active, internal | No | Out of scope. |
| AGP | Does not exist | n/a | Ignore. |
| `agntcy/workflow-srv*` | Archived | n/a | Reject. |
| All other AGNTCY repos | Active, internal/reference | No | Ignore unless a specific dependency surfaces. |

## Supersedes Statement

**Doc 08
([08-agntcy-acp-bridge-spec.md](08-agntcy-acp-bridge-spec.md)) is
factually obsolete.** Every wire-level claim is for an archived spec
with no successor. Recommendation: **mark deprecated and leave as
historical context.** Add an erratum block at the very top pointing
to this doc, but do not delete: the OpenAPI mapping work captured in
sections 2-3 of doc 08 is still a useful prior art if someone later
needs an A2A REST-shape bridge (A2A inherits some ACP semantics in
its LF-merged form). The `DirectoryProvider` design fragment in doc
08 section 4 is the one piece that survives intact and should be
quoted forward into the doc-02 update below.

Suggested doc-08 erratum:

> **Erratum (May 2026):** `agntcy/acp-spec` and `acp-sdk` were
> archived on 2026-04-11. This document's "frozen" framing was wrong.
> ACP has been absorbed into Linux-Foundation A2A. See
> [17-agntcy-revisited.md](17-agntcy-revisited.md) for the current
> recommendation. The `DirectoryProvider` design in section 4 is the
> only part that carries forward.

## Cleanup Implications

**Doc 02 ([02-decentralized-agent-networks.md](02-decentralized-agent-networks.md)),
section 2 "AGNTCY (SLIM, OASF, ACP)":** rewrite to drop the ACP
bridge recommendation. The structure stays (SLIM as substrate, OASF
as schema, Directory as registry, Identity as VC layer), but the
"highest-value first build" claim must move off ACP. Replace with:
"the highest-value AGNTCY integration is consume-only:
`DirectoryProvider` reads OASF records to wire up Chio's existing
MCP and A2A bridges." Keep the Webex production data-point (it is
even more accurate now: Webex never used ACP). Delete or update
references to `chio-bridge-acp` / `chio-bridge-agntcy`.

**Doc 00-overview-v2
([00-overview-v2.md](00-overview-v2.md)), Phase C line:**

> `chio-bridge-agntcy` + `chio-directory` - DirectoryProvider trait +
> StaticAgntcyDirectoryProvider + AGNTCY ACP bridge.

Edit to:

> `chio-directory` - `DirectoryProvider` trait +
> `StaticAgntcyDirectoryProvider` (consume-only; reads OASF records
> from a static config or the live `agntcy/dir` gRPC API to wire up
> existing MCP/A2A bridges). **No AGNTCY-native bridge crate.**

Also drop or footnote the "AGNTCY zero-securitySchemes" open question
(overview-v2 line 81): it is moot once we are not building the
bridge.

**Crate-naming review (C2):** the `chio-bridge-agntcy` slot is now
free; no crate should claim it. `chio-directory` keeps its name and
its slot.

**Latency budget (doc 16):** historical AGNTCY-to-ACP hop claims
should be removed or replaced with the A2A hop, since ACP is no
longer a real target.

**Current v1 receipt semantics (doc 15):** the `tool_origin` field still
surfaces from the AGNTCY case
([00-overview-v2.md:14](00-overview-v2.md)), but the example should
move from ACP to A2A. No schema change needed.

## Bottom Line

Doc 08's bridge is for a dead spec. The live AGNTCY components are
real and worth quiet consumption, but none of them is a
`ToolServerConnection` candidate. Build one new crate
(`chio-directory`), build nothing else AGNTCY-flavored, and let the
qualified MCP and A2A bridge paths absorb whatever traffic the AGNTCY stack
ends up surfacing. The C2 naming review is partially vindicated:
`chio-bridge-agntcy` should never have been a crate.
