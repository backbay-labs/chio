# 05 - Egress, Orchestrator, and Threat-Mapping Cluster Review

Cluster: docs `01-pubsub-coverage-audit.md`, `05-workflow-orchestrator-mediation.md`,
`06-below-l7-mediation.md`, `11-n8n-threat-mapping.md`. Cross-checked against
`09-event-action-schema.md`, `00-overview.md`, `00-overview-v2.md`.

Codebase pinned to a local checkout on 2026-05-11.

## TL;DR

The three Python SDKs the cluster leans on (`chio-streaming`,
`chio-temporal`, `chio-airflow`) all exist and match their cited shapes;
the `HttpEgressContract` surface is real and richer than any single doc
shows. The most important inconsistency is the n8n priority-1 framing:
overview v1 (`00-overview.md:35`) and doc 05 Phase 2
(`05-workflow-orchestrator-mediation.md:56-72`) still anchor priority-1
on the Talos "686% spike", but doc 11 establishes that the spike is
Chain D (ingress abuse), which Chio explicitly does **not** block. Doc
06's claim that Envoy ext_authz "transparently covers" QUIC and gRPC is
load-bearing but unverified by code: the crate vendors only the
HTTP-side proto subset.

## chio-streaming SDK existence verification

Verified path: `sdks/python/chio-streaming/`. Python package
`chio_streaming` under `src/`. Doc 01's "~5000 LOC" claim matches the
source tree exactly:

`wc -l` over `sdks/python/chio-streaming/src/chio_streaming/*.py`
reports **5013 LOC** across 12 modules. With tests + examples the total
is 12,725 LOC.

Per-broker module map (verified against
`sdks/python/chio-streaming/README.md:5-13` and `src/chio_streaming/`):

- Kafka: `middleware.py` (689 LOC; `KafkaConsumerLike` /
  `KafkaProducerLike` Protocols at lines 58-80; EOS v2 transactional
  story documented at lines 1-10). The README places Kafka under the
  top-level `chio_streaming` namespace, which explains why there is no
  `kafka.py`. **Confirmed**.
- NATS / JetStream: `nats.py` (478 LOC). **Confirmed**.
- Pulsar: `pulsar.py` (454 LOC). **Confirmed**.
- AWS EventBridge: `eventbridge.py` (535 LOC). **Confirmed**.
- GCP Pub/Sub: `pubsub.py` (507 LOC). **Confirmed**.
- Redis Streams: `redis_streams.py` (588 LOC). **Confirmed**.
- Flink: `flink.py` (792 LOC) plus
  `sdks/jvm/chio-streaming-flink/` (referenced by doc 01 but I did
  not enumerate the JVM tree). **Confirmed for Python**.

Shared core: `core.py` (284 LOC), `middleware.py` (Kafka),
`receipt.py` (160 LOC), `dlq.py` (208 LOC), `errors.py` (79 LOC),
`__init__.py` (239 LOC). Tier-2/3 integration tests against
Testcontainers are present
(`tests/integration/test_kafka_middleware_integration.py`,
`test_flink_kafka_integration.py`, etc.).

Coverage gaps verified by absence: `grep -rni 'amqp\|rabbitmq\|websub'`
returns **zero hits** in `sdks/python/`, `crates/`, and the SDK READMEs.
SNS and SQS are absent as modules (`sns.py` / `sqs.py` do not exist).
Doc 01's gap list (AMQP/RabbitMQ + SNS+SQS + WebSub) is therefore
**accurate**. Doc 00-overview-v2's Phase D bullet
(`00-overview-v2.md:71`) defers these correctly.

## chio-temporal / chio-airflow existence verification

Both exist as Python SDKs (no Rust crates).

- `sdks/python/chio-temporal/` (1291 LOC across 6 source files).
  Wraps Temporal Python SDK; `interceptor.py` (572 LOC) implements
  `ChioActivityInterceptor`; `worker.py` builds `build_chio_worker`;
  `grants.py` carries `WorkflowGrant`. README confirms doc 05's
  framing: it gates Activities, not signal/start triggers
  (`sdks/python/chio-temporal/README.md:4-7`). **Confirmed**.
- `sdks/python/chio-airflow/` (1384 LOC across 6 source files).
  `operator.py` (316 LOC) is the `ChioOperator`; `task_decorator.py`
  (361 LOC) is the `chio_task` decorator; `listener.py` (360 LOC) is
  the DAG listener. README confirms it gates per-task, not the agent's
  REST trigger (`sdks/python/chio-airflow/README.md:4-10`).
  **Confirmed**.

Both are interceptor/decorator-shaped, not sidecar-shaped. Doc 05's
"activity-level mediation, not trigger-level"
(`05-workflow-orchestrator-mediation.md:16-17`) is accurate.

Note: there is no Rust mirror of either; doc 05 is correct that
Temporal/Airflow can be deferred at the orchestrator-egress layer
because the in-platform SDKs already exist.

## `HttpEgressContract` verified surface

Citations across docs 01, 05, 06, 11 collapse to one struct at
`crates/chio-egress-contract/src/lib.rs:14-39`. Per-field verification:

| Doc claim | Source line | Verdict |
|-----------|------------|---------|
| `tenant_egress_namespace` | line 18 | Correct |
| `allowed_schemes` (lowercase) | line 21 | Correct |
| `allowed_authority_set` (normalised) | line 27 | Correct |
| `deny_loopback` | line 30 | Correct |
| `deny_link_local` | line 32 | Correct |
| `deny_ipv6_ula` | line 34 | Correct |
| `max_redirect_chain` | line 36 | Correct |
| `max_response_bytes` | line 38 | Correct |
| `enforce_required` fail-closed on missing | line 84-92 | Correct |
| DNS resolution check | line 153-163 (`enforce_url_with_dns`) | Correct |
| Resolved-IP private/special-use deny | line 273-334 | Correct (richer than docs say) |

Two gaps the docs do not surface:

- The contract also blocks **`UserinfoDenied`** (line 60) and
  cross-origin POST redirects that preserve body (test at
  `lib.rs:681-724`). Worth noting in doc 11 Chain C analysis.
- `PrivateNetworkDenied` (line 72-73) covers RFC1918, CGNAT,
  benchmark, TEST-NET, AWS metadata 169.254.169.254 (line 842 test),
  and IPv6 special-use. Doc 11's "SSRF pivots" framing is accurate
  but understates the address-class list.

`ValidatedHttpEgressTarget` (line 43-47) has three public fields:
`tenant_egress_namespace`, `scheme`, `authority`. Doc 05's claim that
"the receipt embeds the validated egress target"
(`05-workflow-orchestrator-mediation.md:219-222`) is structurally
plausible but the type itself does not derive `Serialize`/`Deserialize`
(line 42-47); embedding in a receipt requires either a new derive or a
projection. **Worth a footnote in doc 05.**

## TLS pin / SPKI gap (doc 11 Chain E)

Doc 11 flags the absence of a TLS pin field
(`11-n8n-threat-mapping.md:122-123`, `216-219`). Verified: the struct
at lines 14-39 has no `pinned_spki` or `pinned_cert_chain` field. Doc
11 correctly files this as a follow-up rather than asserting Chain E
is blocked.

## n8n priority designation needs cleanup

This is the highest-confidence inconsistency in the cluster.

- `00-overview.md:35` says n8n is priority 1 "[686 percent spike per
  the Cisco Talos n8mare report]." Doc 11 attributes that exact spike
  to Chain D (ingress webhook abuse), which Chio explicitly does
  **not** block (`11-n8n-threat-mapping.md:103-110`, table row 145).
  The overview's justification claim is therefore mis-aligned with the
  threat doc.
- `05-workflow-orchestrator-mediation.md:56-72` ("n8n - COVER
  (priority 1)") cites the 686% spike under "Attack surface 2026" as
  if Chio addresses it. The "Mediation value" bullet at lines 64-68
  talks about webhook-path and workflow-ID pinning, which is Chain C,
  not D. The two sentences should be reconciled.
- `00-overview-v2.md:26` and `00-overview-v2.md:61` already explicitly
  call this out and add the Chain-C-only caveat, which is the right
  framing. **The fix is to backport that caveat into doc 05 (Phase 2,
  n8n section) and amend doc 00-overview.md line 35.**

Suggested edit for doc 05 Phase 2 n8n block: replace "Mediation value"
sentence with "Mediation value: Chio blocks the prompt-injection
agent-to-webhook chain (Chain C of doc 11). It does **not** mediate
unauthenticated ingress (Chain D, the chain that produced the Talos
686 percent spike); that surface belongs to n8n auth, WAF/IP
allowlisting, and email security."

## Other consistency findings

### chio-envoy-ext-authz QUIC/gRPC coverage (doc 06)

Doc 06 line 13 cites the crate as HTTP-only:
`crates/chio-envoy-ext-authz/src/lib.rs:1` and
`build.rs:24-25`. **Verified**: build.rs lists exactly
`external_auth.proto` and `attribute_context.proto` (plus base/status
helpers), and tool identity is derived as `http.<method>.<path>`
(`translate.rs:79-80`).

Doc 06 Phase 3 then claims "QUIC / HTTP/3 - Already covered" and
"gRPC over HTTP/2 - Already covered" (`06-below-l7-mediation.md:61-62`).
This is **transitive on Envoy** (Envoy ext_authz Check is wire-agnostic
once the HTTP framing is reconstructed). It is **not** a Chio-side
guarantee: the Chio crate's translation layer accepts whatever HTTP
request CheckRequest carries. The doc is technically right but the
phrasing reads as if Chio actively supports the protocols. Recommend
softening to "Envoy ext_authz forwards Check requests with HTTP
context regardless of the wire transport; no Chio change required."

### `SqlQueryGuard` sibling-of-`PresignedUrlGuard` claim (doc 06)

Doc 06 line 64 says `PresignedUrlGuard` should live next to
`SqlQueryGuard` in `chio-data-guards`. **Verified viable**:
`crates/chio-data-guards/src/lib.rs:40-50` already re-exports
`SqlQueryGuard`, `VectorDbGuard`, `WarehouseCostGuard`, `QueryResultGuard`.
The module layout is "one file per guard", so a `presigned_url_guard.rs`
sibling is mechanically straightforward. Doc 06's exact line citation
(`crates/chio-data-guards/src/lib.rs:50`) lands on
`pub use sql_guard::SqlQueryGuard;` which is the right anchor.

### `chio-wire-mediation` deferral (doc 06)

Doc 06 lines 5, 82 reserve `chio-wire-mediation` as a future sibling
crate that should not extend `chio-egress-contract`. The boundary is
clear: HTTP egress vs raw-TCP/wire-protocol mediation. No conflation
elsewhere in the cluster. **Consistent**.

### `chio-streaming` Rust kernel vocabulary mismatch (doc 01 / doc 09)

Doc 01 conclusion item 1 (lines 177-184): `ToolAction` lacks
`EventPublish`/`EventConsume`. Verified at
`crates/chio-guards/src/action.rs:16-46` (range cited exactly): 12
variants, none of which represent broker semantics. The closest is
`ExternalApiCall { service, endpoint }` at line 39. **Mismatch is
real.**

Doc 09's framing (additive v1->v2 manifest bump, two new variants) is
consistent with doc 01's "biggest gap" framing. **No conflict.**

### n8n manifest tool design respects existing contracts

Doc 05's sketched `chio.orchestrator-egress` server (lines 173-191)
uses `ToolServerConnection`-shaped tools (`tool_name` strings) and
double-gates via `HttpEgressContract` (lines 208-213). Verified:
`ToolServerConnection` is the trait at
`crates/chio-kernel/src/runtime.rs:255` (doc 01/05 citation is
correct). Composition story is sound: the bridge gate binds "which
tool", the egress contract binds "which authority", and the contract
is enforced *after* the bridge resolves the call. No new ergonomic
problem introduced.

### Spine/NATS doc-line claim (doc 01)

Doc 01 line 16 mentions "Spine/NATS doc-line in
`chio-kernel/src/revocation_runtime.rs:9`". Verified: the file
contains `/// distributed revocation feed via Spine/NATS.` at exactly
line 9. **Correct citation.**

### `chio-workflow/src/manifest.rs:13`

Doc 05 line 167 cites `SkillManifest` at
`crates/chio-workflow/src/manifest.rs:13`. Actual struct is at line 17
(line 13 falls inside the doc comment that precedes it). Minor citation
drift, not a substantive error. Doc 11 cites
`manifest.rs:113` for `SkillStep`, which **is** correct.

## Chain enumeration vs cited sources

Doc 11's Chain A through F enumeration:

- A: malicious community node (npm packages, Endor Labs)
- B: in-workflow RCE / cred exfil (CVE-2026-25049, -21858, -25631, -27493)
- C: prompt-injection-driven webhook exfil
- D: webhook ingress abuse (Talos n8mare; 686% spike)
- E: poisoned self-hosted instance
- F: persistent backdoor via workflow update

The doc is internally consistent: every Chain referenced in the
tabular summary (line 140-147) is defined in the enumeration section
(lines 17-60). No phantom chains. I did not re-fetch the Talos/Endor
URLs (network-fetch out of scope for this review), but the doc's
mapping of Chain D to the 686% spike is what overview v1 and doc 05
mis-attribute to "n8n is hot, therefore priority-1 blocked".

## Recommended edits

### Doc 00-overview.md

- Line 35: replace "[686% abuse spike per the Cisco Talos n8mare
  report]" with "[active 2026 abuse surface; Chio blocks the
  agent-side prompt-injection trigger chain (Chain C in doc 11), not
  the unauthenticated ingress spike (Chain D)]".

### Doc 05-workflow-orchestrator-mediation.md

- Phase 2 / "n8n - COVER (priority 1)" block (lines 56-72): split the
  "Attack surface 2026" from the "Mediation value" attribution. The
  686% spike justifies "n8n is a hot target". Chio's mediation value
  is Chain C only. Reference doc 11 explicitly.
- Phase 3 receipt block (line 219-222): note that
  `ValidatedHttpEgressTarget` does not currently derive Serialize;
  embedding in a receipt requires either a projection or a derive.
- Line 167: bump citation to `crates/chio-workflow/src/manifest.rs:17`
  (struct start) or keep line 13 if pointing at the doc comment, but
  call that out.

### Doc 06-below-l7-mediation.md

- Phase 3 QUIC/HTTP/3 + gRPC bullets (lines 61-62): soften
  "Already covered" to "Envoy ext_authz forwards Check requests
  regardless of wire transport; no Chio code change required." The
  Chio crate vendors only the HTTP-side proto subset
  (`build.rs:23-29`); the transparency is Envoy's, not the crate's.

### Doc 11-n8n-threat-mapping.md

- No content edits needed; the doc is the most rigorous in the
  cluster. Optionally add a one-line "see doc 05 Phase 2 n8n block
  for adapter design" pointer in the TL;DR for symmetry with doc 05's
  reference back.

### Doc 01-pubsub-coverage-audit.md

- Line 86: doc 01 cites
  `docs/protocols/UNIVERSAL-KERNEL-COVERAGE-MAP.md:62` for the
  unbuilt-broker list. I did not verify that file in this review;
  recommend an inline cross-check.
- Conclusion item 3 (lines 189-194): the BrokerEgressContract proposal
  is consistent with doc 09's `BrokerKind` enum + sibling
  `chio-broker-contract` crate. Reference doc 09 explicitly to keep
  them locked.

## Three-line summary

1. **chio-streaming + chio-temporal + chio-airflow all exist as
   Python SDKs at the cited paths**, with chio-streaming hitting 5013
   LOC across the seven broker modules doc 01 names; gap list (AMQP /
   SNS / SQS / WebSub) is accurate.
2. **The n8n priority-1 designation is anchored on the wrong chain in
   docs 00-overview.md:35 and 05 Phase 2**: those references cite the
   Talos 686% spike (Chain D, NOT blocked by Chio) as the
   justification, while the actual Chio value-add is Chain C
   (prompt-injection webhook exfil); overview v2 already calls this
   out but the cluster has not been backported.
3. **Output:**
   this file.
