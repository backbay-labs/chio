# chio-agent-web-interop Design

## D9 Crate Home Decision

`chio-agent-web-interop` stays in `crates/platform` as a cross-protocol proof verifier for external Agent Web envelopes. It covers projections for Standard Webhooks, CloudEvents, GraphQL, MCP, A2A, ACP-Client, ACP-Commerce, AP2, x402, OpenAPI, AsyncAPI, browser/RPA, SaaS connectors, OAuth/OIDC, SCIM, SPIFFE/SPIRE, Kubernetes admission, OCI refs, VC/BBS/SD-JWT, Sigstore, SLSA, in-toto, and DSSE.

The default homes considered were the protocol adapter crates. Adapter crates translate live protocol traffic; this crate verifies offline evidence that external artifacts are projections under Chio authority, not authority by themselves.

## Boundary

This crate parses and verifies Agent Web evidence and emits Agent Web verifier reports. It does not run protocol clients, open network connections, or grant external authority.

## Invariants

External proof never becomes Chio authority. Receipts, sidecars, signatures, projection manifests, and subject digests must be graph-bound and verified against pinned keys or local secrets.

## Standard Webhooks Replay Modes

Agent Web verification has separate read-only and consuming operations. `verify_agent_web_interop_with_trust` validates the timestamp window, HMAC, graph, envelope, receipt, and claims without reading or writing replay state, so offline verification is idempotent. `verify_agent_web_interop_with_trust_and_consume_replays` performs the same validation and then atomically reserves every Standard Webhooks identifier. `verify_agent_web_interop_with_trust_and_consume_replays_if_report_matches` additionally requires the consuming pass to reproduce an expected read-only report before reserving identifiers. A failed bundle or report mismatch does not reserve any identifier.

The CLI uses read-only verification for `chio proof verify`. `chio proof collect` is a consuming ingestion operation, but it defers replay reservation until all proof-family, root-claim, parity, and required-claim checks pass and the final consuming report matches the first read-only report. When Standard Webhooks replay protection is configured for consuming verification, `CHIO_AGENT_WEB_REPLAY_STORE_PATH` must name a durable SQLite database; a missing or unavailable store fails closed.

Replay keys are `(replay_scope, webhook_id)`. The verifier derives the opaque scope only after the delivery HMAC succeeds, using a domain-separated HMAC over the verifier secret identity and the signed endpoint digest. Replay stores receive the derived lowercase-hex scope but never the raw verifier secret. This permits independent authenticated senders or endpoints to use the same webhook identifier without sharing replay state. During SQLite migration, legacy rows that predate scopes are assigned a reserved unscoped marker and conservatively block that identifier in every scope until the row expires.

Both in-memory and SQLite stores enforce positive global and per-scope live-entry capacities. Capacity exhaustion denies fail-closed and never evicts a live marker; expired markers are reclaimed only after all batch validation and capacity checks succeed. SQLite serializes count-and-insert with an immediate transaction, and opening an existing database with limits below its retained live rows fails instead of deleting them. The default constructors use bounded constants, while `new_with_capacity` and `open_with_capacity` let embedding hosts set explicit limits.

A shared store still has a global availability boundary. Hosts should set per-scope limits for expected sender rates, set the global limit for available memory or disk, and use separate stores when tenants require independent availability guarantees. All processes opening one SQLite replay database must use the same capacity policy.
