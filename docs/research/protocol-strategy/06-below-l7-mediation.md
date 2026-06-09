# 06 - Below-L7 Mediation: Should Chio Cover Database, DNS, SOCKS, or TLS?

## TL;DR

Chio should **hard skip** TLS interception and plain DNS, **defer** SOCKS5 and direct DB wire-protocol proxying, and **cover** exactly one new below-L7-ish surface that the prior memo missed: **object-storage pre-signed URL mediation**, which is L7 packaging for what is operationally a tool call. Wire-level DB protocol mediation (Postgres / MySQL / MongoDB proxying) is the highest-pressure "below L7" candidate, but the right Chio answer is to keep DB intent at the *tool* layer (the existing `SqlQueryGuard` in `chio-data-guards`) and treat raw-credential DB egress as a substrate failure to surface, not for Chio to terminate the wire. If a future need forces wire-level coverage, it belongs in a new sibling crate (`chio-wire-mediation`) that sits next to `chio-egress-contract`, not as an extension of the existing HTTP-only contract.

## Phase 1: Existing Chio coverage audit

The bridge contract is `ToolServerConnection` at `crates/kernel/chio-kernel/src/runtime.rs:255`. Its `invoke(tool_name, arguments, ...)` (line 264) is protocol-agnostic; the kernel sees a tool name and a JSON argument object. Wire concerns are pushed to the substrate.

**Above-L7 HTTP egress** is governed by `HttpEgressContract` in `crates/protocol/chio-egress-contract/src/lib.rs:15`. The contract is explicitly HTTP-only: `allowed_schemes`, `allowed_authority_set`, `max_redirect_chain`, `max_response_bytes`, and DNS-resolution denial reasons (`HttpEgressError::DnsResolutionFailed` at line 75) all assume URL-shaped targets. There is no non-HTTP egress contract.

**Envoy ext_authz** lives in `crates/protocol/chio-envoy-ext-authz`. Per `src/lib.rs:3` it implements `envoy.service.auth.v3.Authorization/Check` only; the build vendors only HTTP-side protos (`build.rs:24-25` lists `external_auth.proto` and `attribute_context.proto`). The crate derives a tool identity `http.<method>.<path>` (`src/translate.rs:79-80`). It does *not* implement the Envoy network-filter (TCP) variant; `envoy.filters.network.ext_authz` is referenced once only in a vendored proto comment (`proto/envoy/service/auth/v3/external_auth.proto:106`). So Chio gates HTTP through Envoy, not TCP.

**`chio-data-guards`** is purely a parser-driven guard suite operating on tool arguments. `src/sql_parser.rs:20` imports `sqlparser::dialect::{PostgreSqlDialect, MySqlDialect, BigQueryDialect, ...}`; `Cargo.toml:24` pulls `sqlparser = "0.61"`. There is no DB driver, no `sqlx`, no `tokio-postgres`, no `mongodb`, no `mysql_async`, and no connection pool dependency anywhere in the workspace (verified by grep against all `crates/*/Cargo.toml`). The guard sees a SQL *string* that some tool handed it, parses, and votes. It cannot observe an agent that opens its own TCP socket to port 5432.

**No DNS, DoH, DoT, SOCKS, or TLS-interception code exists.** A workspace-wide grep against `crates/`, `docs/`, and `spec/` finds zero hits for SOCKS5, DoH, DoT, MITM CA, or interception trust anchors (the only "trust anchor" hits are checkpoint-trust-anchor publication tables in `chio-store-sqlite`, unrelated). `HttpEgressContract::enforce_url` resolves DNS but only to apply allow/deny on the resolved IP class; Chio does not police lookups themselves.

Summary of existing below-L7 footprint: **none beyond DNS-resolution-class checks bolted onto HTTP egress.** Everything Chio polices today rides the HTTP egress contract or the in-process tool-call bridge.

## Phase 2: Per-surface analysis

### Database wire protocols (Postgres / MySQL / MongoDB)

The 2026 reality is that most agent DB traffic is mediated by an MCP server (`mcp-postgres`, `supabase-mcp`, BigQuery MCP, Snowflake MCP) or a hand-rolled `run_sql(query)` tool. The query becomes an argument string, and Chio's `SqlQueryGuard` already parses it (`crates/guards/chio-data-guards/src/sql_guard.rs`). For that population, **the tool is the right policy point**, and a Postgres-protocol-level proxy would only re-derive what the JSON argument already states. PgBouncer (https://www.pgbouncer.org/) and ProxySQL (https://proxysql.com/) exist precisely because human-operated apps don't have a tool layer; agents typically do.

The real failure mode is the **raw-credential agent**: a developer hands an agent a `DATABASE_URL`, and it opens a TCP socket directly. No tool layer, no `SqlQueryGuard`, no receipt. A wire-level proxy (Chio-as-PgBouncer) would catch this; it would also parse the StartupMessage, the simple-query messages, and the extended-protocol `Parse`/`Bind`/`Execute` flow. That is real engineering: Postgres's wire protocol (https://www.postgresql.org/docs/current/protocol.html) is stable but not trivial, MySQL's is its own animal, and MongoDB's OP_MSG is yet another. The cost is roughly one new crate per dialect plus a query rewriter that reassembles statements from extended-protocol pipelining.

The 2026 ecosystem signal: Aembit (https://aembit.io/), Strata Identity Maverics (https://www.strata.io/), and Teleport's Database Access (https://goteleport.com/docs/enroll-resources/database-access/) all sit at the wire level for DB credential brokerage, and Akeyless and HashiCorp Boundary do the same. None of these are AI-agent-specific; they are generic workload-identity products. Chio competing on that axis means becoming a connection broker. Aembit's 2025 agent-identity product line (https://aembit.io/blog/) leans on workload identity rather than DB-protocol parsing.

The honest argument for Chio doing it: cryptographically signed *per-statement* receipts that survive into the audit trail and credit/settle pipelines. The honest argument against: agent platforms that ship raw DB creds to an LLM are already failing at the architecture level, and Chio's leverage there is to make tool-mediated DB access *strictly easier* than raw-cred access.

**Decision: defer.** Recommend that we wait for a customer with raw-credential agents and DB-receipt audit pressure before building this. If we ship it, it is a `chio-wire-mediation` sibling crate, *not* a generalization of `HttpEgressContract`.

### DNS (UDP/53, DoH, DoT)

DNS exfiltration is a real attack class, but DNS policy is a saturated market: Cisco Umbrella, NextDNS, Cloudflare Gateway, Quad9, and in-cluster Cilium DNS proxy and CoreDNS plugins all cover it. Cilium's L7 DNS visibility (https://docs.cilium.io/en/stable/security/dns/) is the canonical Kubernetes answer. Chio's DNS-resolution checks today (`HttpEgressContract::enforce_url`, `crates/protocol/chio-egress-contract/src/lib.rs:74-79`) are sufficient for the HTTP-target case.

For the *non-HTTP* case (an agent that does `dig` against an attacker-controlled NS), wire-level DNS policy is firmly L3/L4 substrate. Chio building a recursive resolver or DoH terminator would duplicate well-funded tooling without adding the discipline that justifies Chio: there is no "tool call" to lift, no receipt to sign that wouldn't be duplicating Umbrella's existing log stream.

**Decision: hard skip.** Consume DNS-policy decisions as ambient substrate (already implicit in `HttpEgressError::DnsResolutionFailed`). If audit requires it, accept upstream DNS logs as evidence rather than terminating queries.

### SOCKS5 forward proxy

SOCKS5 (RFC 1928) is opaque-TCP-with-an-allowlist. Putting Chio in a SOCKS5 path means demuxing arbitrary TCP streams to recover protocol context: useless without a follow-on parser. The 2026 agent-platform population using SOCKS in production is small and largely scraping-adjacent (residential-proxy aggregators like Bright Data, Oxylabs); legitimate enterprise agents talk HTTPS to APIs.

A reasonable hybrid is to accept SOCKS5 *CONNECT* targets and apply `HttpEgressContract`-style authority allowlists. That's a thin wrapper, not a mediation: no receipt content beyond "agent X connected to host:port at time T," which is L3/L4 territory Tetragon (https://tetragon.io/) and eBPF already cover with `tcp_connect` hooks.

**Decision: defer.** Add to backlog as `chio-wire-mediation::socks5_connect_gate` only if a customer wants an authority allowlist on SOCKS that mirrors HTTP. Until then, push to substrate (Cilium/Tetragon/Envoy TCP filter).

### TLS interception (MITM with corporate CA)

TLS interception is a different business: it requires custody of an interception CA, per-tenant cert minting, key-handling residency claims, and pinned-cert breakage handling. The market is Zscaler (https://www.zscaler.com/), Palo Alto Prisma, Netskope, and the open-source mitmproxy (https://mitmproxy.org/). Chio entering this space means becoming a CA operator, which is a *governance* product, not a tool-call bridge. The kernel's discipline ("lift a tool call off a wire, decide, sign") collapses when the wire is opaque TLS that Chio itself broke.

**Decision: hard skip.** Document clearly that Chio is downstream of any TLS-interception proxy: if a customer wants Chio receipts on decrypted traffic, the interception proxy decrypts, hands cleartext to Envoy/Chio-ext-authz, and Chio policies the HTTP. Chio should ship a reference recipe for "Zscaler in front of Envoy in front of Chio" rather than re-implement the front layer.

## Phase 3: Other below-L7 surfaces worth considering

The prior memo also did not address:

- **QUIC / HTTP/3.** Envoy ext_authz already runs over HTTP/3 transparently; Chio inherits coverage with zero code. No action.
- **gRPC over HTTP/2.** Same; ext_authz operates on the HTTP/2 framing. The `http.<method>.<path>` derivation in `crates/protocol/chio-envoy-ext-authz/src/translate.rs:79` works for gRPC unary calls. Streaming RPCs are policy-at-open-time only, which matches Chio's "lift the call" model. No action beyond a docs note.
- **WebSocket session inspection.** Long-lived bidirectional. Chio cannot lift "a call" off a WS stream without per-message MCP-style framing. This is the same problem MCP-over-stdio solves: define the message envelope. **Defer**: treat WS as a delivery transport for MCP frames (which Chio already supports via `chio-mcp-edge`), not as a Chio-mediated stream of its own.
- **Object-storage pre-signed URLs (S3 `PutObject`/`GetObject` and equivalents).** This is the surface the prior memo missed. A pre-signed URL is an L7 HTTP request, but it is operationally a *tool call package* with an embedded capability (signed query parameters). An agent generating or following a pre-signed URL is doing something `HttpEgressContract` covers as raw HTTP but cannot reason about semantically: who minted it, for what resource, with what lifetime. **Cover.** This belongs as a guard on top of `HttpEgressContract`, not a new transport: a small `chio-data-guards::PresignedUrlGuard` that inspects URL shape (`X-Amz-*`, `X-Goog-*`, Azure SAS query keys) and asserts pre-flight allowlists on bucket/object. It reuses every existing pipe.
- **mTLS / SPIFFE workload identity.** Already correctly characterised as substrate adoption; not a Chio bridge. No action here.

## Phase 4: Concrete recommendation

| Surface | Decision | Reasoning (2 sentences max) |
| --- | --- | --- |
| Postgres / MySQL / MongoDB wire | **Defer** | Tool-layer mediation (`SqlQueryGuard`) covers the dominant agent topology in 2026; wire proxying duplicates Aembit/Teleport without unique value. Revisit when a customer with raw-credential agents wants per-statement receipts. |
| DNS (UDP, DoH, DoT) | **Hard skip** | Cilium/Umbrella/NextDNS own this surface and Chio already denies on resolved IP class. There is no tool call to lift from a DNS query. |
| SOCKS5 forward proxy | **Defer** | Production agent traffic is overwhelmingly HTTPS; SOCKS authority allowlisting belongs in eBPF/Envoy TCP filter substrate. Reconsider only if a SOCKS-heavy customer appears. |
| TLS interception (corporate CA) | **Hard skip** | Becoming a CA operator is a different product; Chio sits downstream of Zscaler/Palo Alto and policies the decrypted HTTP. Ship a reference deployment recipe instead. |
| QUIC / HTTP/3 | **Already covered** | Envoy ext_authz operates on HTTP/3 transparently. |
| gRPC over HTTP/2 | **Already covered** | Same path as HTTP/1.1; document only. |
| WebSocket sessions | **Defer** | WS-as-MCP-transport is already covered; raw WS streams have no native "call" boundary to lift. |
| Pre-signed object-storage URLs | **Cover** | These are tool-call packages dressed as URLs; a guard on top of `HttpEgressContract` is a small, high-leverage win. Lives in `chio-data-guards`. |

**Where the only "cover" verdict lives.** A `PresignedUrlGuard` belongs in `crates/guards/chio-data-guards/src/presigned_url_guard.rs`, exported alongside `SqlQueryGuard` and `VectorDbGuard` from `crates/guards/chio-data-guards/src/lib.rs:50`. It is a guard, not a transport, and it requires no new crate. The kernel still sees a tool call; the guard inspects URL semantics before allowing.

**If wire-level mediation ever lands** (the deferred items), it should be a *new* crate `chio-wire-mediation` paralleling `chio-egress-contract`, not an extension. The HTTP egress contract's type system is URL-shaped; conflating it with `host:port` plus protocol-state pairs would invite the same kind of misuse `HttpEgressError::MissingContract` (line 53) is designed to prevent. The new crate would expose a parallel `TcpEgressContract` and a per-protocol parser shim (Postgres first, MySQL second, Mongo only on demand), each translating wire state into a `ToolCallRequest`-shaped record that the existing kernel evaluates.

**Net effect on Chio scope.** Of five candidate below-L7 surfaces, none move into the kernel today, four stay out indefinitely or until customer pull, and one (pre-signed URLs) lands as a small `chio-data-guards` guard. The prior memo's "below Chio's altitude" framing is correct for the wire-protocol surfaces; the only material miss is treating pre-signed URLs as L7-ish tool-call packages rather than raw HTTP egress.
