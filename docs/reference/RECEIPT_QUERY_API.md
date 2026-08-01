# Receipt Query API

The receipt query API provides multi-filter, cursor-paginated access to the kernel's signed tool receipt log. It is available both as an HTTP endpoint served by the trust-control server and as a CLI subcommand.

## HTTP Endpoint

```
GET /v1/receipts/query
```

All parameters are query string parameters. All filters are combined with AND semantics. The server requires a `Bearer` token in the `Authorization` header.

### Filter Parameters

All parameters are optional. Omitting a parameter disables that filter.

| Parameter | Type | Description |
|-----------|------|-------------|
| `capabilityId` | string | Exact match on capability ID |
| `toolServer` | string | Exact match on tool server name (`server_id`) |
| `toolName` | string | Exact match on tool name |
| `outcome` | string | Decision outcome: `"allow"`, `"deny"`, `"cancelled"`, or `"incomplete"` |
| `since` | u64 | Include only receipts with `timestamp >= since` (Unix seconds, inclusive) |
| `until` | u64 | Include only receipts with `timestamp <= until` (Unix seconds, inclusive) |
| `minCost` | u64 | Include only receipts with `cost_charged >= minCost` (minor units). Receipts without financial metadata are excluded when this filter is set. |
| `maxCost` | u64 | Include only receipts with `cost_charged <= maxCost` (minor units). Receipts without financial metadata are excluded when this filter is set. |
| `costCurrency` | string | Exact three-letter uppercase currency for cost filtering. Required with `minCost` or `maxCost`. |
| `agentSubject` | string | Filter by agent subject public key (hex-encoded Ed25519). Resolved from receipt attribution metadata when present and otherwise through the capability lineage table. |
| `cursor` | u64 | Pagination cursor: return only receipts with `seq > cursor` (exclusive). |
| `limit` | usize | Maximum results per page. Capped server-side at `MAX_QUERY_LIMIT` (200). Default: 50. |

The parameter names follow `camelCase` in the HTTP query string (matching the `ReceiptQueryHttpQuery` struct's `serde(rename_all = "camelCase")` attribute).

`minCost` and `maxCost` span the full unsigned 64-bit domain and are interpreted
as minor units in `costCurrency`. Supplying a bound without `costCurrency`, a
currency other than three uppercase ASCII letters, or `minCost > maxCost`
returns `400 Bad Request`.

### Response Body

```json
{
  "totalCount": 1024,
  "nextCursor": 47,
  "receipts": [ ...ChioReceipt objects... ]
}
```

`totalCount` reflects the count of all receipts matching the filters, independent of the page limit and cursor. It can be used to show "N total" in a UI without fetching all pages.

`nextCursor` is the `seq` value of the last receipt in this page. Pass it as `cursor` on the next request to get the following page. When `nextCursor` is `null` (or absent), this is the last page.

`receipts` is an array of `ChioReceipt` objects ordered by `seq ASC`.

### Cursor-Based Pagination

The cursor is the `seq` column value from the last receipt in a page. Pagination is forward-only.

```
# Page 1
GET /v1/receipts/query?toolServer=shell&limit=50

# Response includes nextCursor: 147

# Page 2
GET /v1/receipts/query?toolServer=shell&limit=50&cursor=147
```

When `nextCursor` is absent in the response, all matching receipts have been fetched.

### Example Request and Response

```
GET /v1/receipts/query?outcome=deny&since=1700000000&limit=2
Authorization: Bearer my-service-token
```

```json
{
  "totalCount": 8,
  "nextCursor": 23,
  "receipts": [
    {
      "id": "receipt-001",
      "timestamp": 1700000100,
      "capability_id": "cap-abc",
      "tool_server": "filesystem",
      "tool_name": "write_file",
      "decision": { "deny": { "reason": "path outside allowed prefix", "guard": "path_allowlist" } },
      "content_hash": "...",
      "policy_hash": "...",
      "evidence": [],
      "signature": "..."
    },
    {
      "id": "receipt-002",
      "timestamp": 1700000250,
      "capability_id": "cap-abc",
      "tool_server": "shell",
      "tool_name": "exec",
      "decision": { "deny": { "reason": "budget exhausted", "guard": "monetary_budget" } },
      "metadata": {
        "attribution": {
          "subject_key": "ed25519-subject-hex",
          "issuer_key": "ed25519-issuer-hex",
          "delegation_depth": 0,
          "grant_index": 0
        },
        "financial": {
          "grant_index": 0,
          "cost_charged": 0,
          "currency": "USD",
          "budget_remaining": 0,
          "budget_total": 10000,
          "delegation_depth": 0,
          "root_budget_holder": "agent-root",
          "settlement_status": "not_applicable",
          "attempted_cost": 500
        }
      },
      "content_hash": "...",
      "policy_hash": "...",
      "evidence": [],
      "signature": "..."
    }
  ]
}
```

### Agent-Scoped Convenience Endpoint

A shorter URL is also available for per-agent receipt lookup:

```
GET /v1/agents/{subject_key}/receipts?limit=50&cursor=0
```

This is equivalent to calling `/v1/receipts/query?agentSubject={subject_key}`. It accepts only `limit` and `cursor` query parameters.

## Receipt Analytics Endpoint

The trust-control service also exposes aggregate analytics over the same receipt corpus:

```
GET /v1/receipts/analytics
```

It uses the same authentication model as `/v1/receipts/query` and accepts these optional query parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `capabilityId` | string | Restrict analytics to one capability ID |
| `agentSubject` | string | Restrict analytics to one agent subject key |
| `toolServer` | string | Restrict analytics to one tool server |
| `toolName` | string | Restrict analytics to one tool |
| `since` | u64 | Include only receipts with `timestamp >= since` |
| `until` | u64 | Include only receipts with `timestamp <= until` |
| `groupLimit` | usize | Maximum rows returned for each grouped dimension. Default: 50, capped server-side at 200. |
| `timeBucket` | string | Time aggregation width: `hour` or `day`. Default: `day`. |

Response shape:

```json
{
  "summary": {
    "totalReceipts": 12,
    "allowCount": 9,
    "denyCount": 1,
    "cancelledCount": 1,
    "incompleteCount": 1,
    "totalCostCharged": 750,
    "totalAttemptedCost": 500,
    "reliabilityScore": 0.8181818182,
    "complianceRate": 0.9166666667,
    "budgetUtilizationRate": 0.6
  },
  "byAgent": [
    {
      "subjectKey": "ed25519-subject-hex",
      "metrics": { "...": "same metric object as summary" }
    }
  ],
  "byTool": [
    {
      "toolServer": "shell",
      "toolName": "bash",
      "metrics": { "...": "same metric object as summary" }
    }
  ],
  "byTime": [
    {
      "bucketStart": 1700000000,
      "bucketEnd": 1700086400,
      "metrics": { "...": "same metric object as summary" }
    }
  ]
}
```

The analytics API is backend-side aggregation. It complements, but is distinct from, any client-side dashboard summaries.

## Local Receipt Operations CLI

Receipt write operations are local SQLite operator commands in this release.
They require `--receipt-db <path>`. Remote `--control-url` receipt
health, flush, and checkpoint operations fail with:

```text
requires local --receipt-db; remote receipt write operations are not supported in this release
```

The JSON response is always an envelope:

```json
{
  "schema": "chio.cli.receipt.health.v1",
  "report": {}
}
```

Supported envelope schemas:

| Command | Schema |
|---------|--------|
| `chio receipt health` | `chio.cli.receipt.health.v1` |
| `chio receipt flush` | `chio.cli.receipt.flush.v1` |
| `chio receipt checkpoint status` | `chio.cli.receipt.checkpoint_status.v1` |
| `chio receipt checkpoint create` | `chio.cli.receipt.checkpoint_create.v1` |
| `chio receipt checkpoint verify` | `chio.cli.receipt.checkpoint_verify.v1` |

`chio receipt flush --timeout-ms <n>` treats the timeout as the receipt writer
flush-barrier timeout. It is not a whole-command timeout. A timeout means the
operator cannot prove all writes accepted before the barrier are committed.

`chio receipt checkpoint create --kernel-seed-file <path> --max-batch <n>`
creates the next checkpoint through the receipt store. SQLite chooses the next
contiguous `claim_receipt_log_entries.entry_seq` range, loads canonical bytes,
loads the predecessor checkpoint, builds and signs the checkpoint, inserts it,
and validates the checkpoint projections in one `IMMEDIATE` transaction.

`chio receipt checkpoint status` and `chio receipt checkpoint verify` return a
non-zero exit status when checkpoint chain or projection integrity fails.

## Operator Report Endpoint

The trust-control service also exposes a composed operator report:

```
GET /v1/reports/operator
```

It uses the same Bearer authentication model as the other receipt endpoints and accepts the same corpus filters as the analytics API, plus:

| Parameter | Type | Description |
|-----------|------|-------------|
| `attributionLimit` | usize | Maximum detailed rows returned in the nested cost-attribution slice. Default: 100. |
| `budgetLimit` | usize | Maximum budget-utilization rows returned. Default: 50, capped server-side at 200. |

Response shape:

```json
{
  "generatedAt": 1700000000,
  "filters": {
    "agentSubject": "ed25519-subject-hex",
    "toolServer": "shell",
    "toolName": "bash"
  },
  "activity": { "...": "same shape as /v1/receipts/analytics" },
  "costAttribution": { "...": "same shape as /v1/reports/cost-attribution" },
  "budgetUtilization": {
    "summary": {
      "matchingGrants": 3,
      "nearLimitCount": 1,
      "exhaustedCount": 0
    },
    "rows": [
      {
        "capabilityId": "cap-123",
        "grantIndex": 0,
        "subjectKey": "ed25519-subject-hex",
        "toolServer": "shell",
        "toolName": "bash",
        "invocationCount": 12,
        "maxInvocations": 20,
        "totalCostCharged": 850,
        "maxTotalCostUnits": 1000,
        "remainingCostUnits": 150,
        "nearLimit": true,
        "exhausted": false,
        "scopeResolved": true
      }
    ]
  },
  "compliance": {
    "matchingReceipts": 12,
    "evidenceReadyReceipts": 11,
    "uncheckpointedReceipts": 1,
    "checkpointCoverageRate": 0.9166666667,
    "lineageCoveredReceipts": 12,
    "lineageGapReceipts": 0,
    "directEvidenceExportSupported": false,
    "childReceiptScope": "omitted_no_join_path",
    "proofsComplete": false,
    "exportQuery": {
      "agentSubject": "ed25519-subject-hex"
    },
    "exportScopeNote": "tool filters narrow the operator report only; direct evidence export can scope by capability, agent, and time window."
  }
}
```

This endpoint is the stable operator workflow surface. It packages the existing analytics, cost-attribution, and evidence-export substrate into one response so dashboards and back-office tooling do not need to reconstruct the report client-side.

## Comptroller Surface Endpoint

The trust-control service exposes the unified spend and exposure surface for cross-language consumers:

```
GET /v1/reports/comptroller-surface
```

It uses the same Bearer authentication model as the other report endpoints.

The response envelope schema identifier is `chio.comptroller.surface-report.v1`. Every response carries this identifier in the top-level `schema` field so consumers can reject unknown schema versions fail-closed before parsing the body.

### Response Shape

```json
{
  "schema": "chio.comptroller.surface-report.v1",
  "generatedAt": 1700000000,
  "filters": {},
  "exposurePositions": [
    {
      "currency": "USD",
      "governedMaxExposureUnits": 10000,
      "reservedUnits": 1000,
      "settledUnits": 8500,
      "pendingUnits": 200,
      "failedUnits": 0,
      "provisionalLossUnits": 0,
      "recoveredUnits": 0,
      "quotedPremiumUnits": 0,
      "activeQuotedPremiumUnits": 0
    }
  ],
  "decisionSummary": {
    "allowCount": 38,
    "denyCount": 4,
    "cancelledCount": 0,
    "incompleteCount": 0
  },
  "settlementReconciliation": {
    "matchingReceipts": 42,
    "returnedReceipts": 0,
    "pendingReceipts": 1,
    "failedReceipts": 0,
    "actionableReceipts": 1,
    "reconciledReceipts": 37,
    "truncated": false
  },
  "budgetUtilization": {
    "matchingGrants": 5,
    "returnedGrants": 0,
    "distinctCapabilities": 2,
    "distinctSubjects": 1,
    "totalInvocations": 42,
    "totalCostCharged": 8500,
    "nearLimitCount": 1,
    "exhaustedCount": 0,
    "rowsMissingScope": 0,
    "rowsMissingLineage": 0,
    "truncated": false
  },
  "sourceRefs": {}
}
```

Note: `executionNonceRef` and `holdRef` are omitted from the JSON response when absent or null. They appear only when a specific governed invocation or pre-authorization hold context is supplied.

### Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `schema` | string | Always `chio.comptroller.surface-report.v1`. Consumers must reject unknown values fail-closed. |
| `generatedAt` | integer (Unix seconds) | Epoch timestamp when this report was produced. |
| `filters` | object | The corpus filters applied to this snapshot (mirrors the request parameters). |
| `exposurePositions` | array | Per-currency credit-exposure rows (`ExposurePosition`). Fields: `currency`, `governedMaxExposureUnits`, `reservedUnits`, `settledUnits`, `pendingUnits`, `failedUnits`, `provisionalLossUnits`, `recoveredUnits`, `quotedPremiumUnits`, `activeQuotedPremiumUnits`. Positions are never netted across currencies. |
| `decisionSummary` | object | Aggregate allow/deny/cancelled/incomplete decision counts: `allowCount`, `denyCount`, `cancelledCount`, `incompleteCount`. |
| `settlementReconciliation` | object | Settlement backlog summary: `matchingReceipts`, `returnedReceipts`, `pendingReceipts`, `failedReceipts`, `actionableReceipts`, `reconciledReceipts`, `truncated`. |
| `budgetUtilization` | object | Active grant utilization summary: `matchingGrants`, `returnedGrants`, `distinctCapabilities`, `distinctSubjects`, `totalInvocations`, `totalCostCharged`, `nearLimitCount`, `exhaustedCount`, `rowsMissingScope`, `rowsMissingLineage`, `truncated`. |
| `sourceRefs` | object | Optional provenance anchors. All sub-fields are optional strings: `operatorReportRef`, `exposureLedgerRef`, `riskComptrollerReportRef`. The object is present but may be empty `{}`. |
| `executionNonceRef` | string (optional) | Reserved. Identifies the execution nonce when this surface is attached to a specific governed invocation. Omitted when not applicable. |
| `holdRef` | string (optional) | Reserved. Identifies an open pre-authorization hold when the surface is polled mid-execution. Omitted when not applicable. |

The projection implies no fund movement. The surface report is a read-only snapshot of canonical receipt, settlement, and budget truth as of `generatedAt`.

### Schema Governance

The canonical JSON Schema for `chio.comptroller.surface-report.v1` is
`spec/schemas/chio-comptroller/v1/surface-report.schema.json` in this repository.
The TypeScript binding at `src/generated/comptroller-surface.ts` is generated
from that schema and must not be hand-edited. Any shape change requires a schema
version bump. Out-of-repo consumers must pin to the published schema SHA tracked
in `spec/schemas/chio-comptroller/v1/`.

## CLI Usage: chio receipt list

The `chio receipt list` subcommand wraps the HTTP endpoint.

```
chio receipt list [OPTIONS]

Options:
  --capability <ID>      Filter by capability ID
  --tool-server <NAME>   Filter by tool server name
  --tool-name <NAME>     Filter by tool name
  --outcome <OUTCOME>    Filter by outcome (allow/deny/cancelled/incomplete)
  --since <UNIX_SECS>    Filter by minimum timestamp (inclusive)
  --until <UNIX_SECS>    Filter by maximum timestamp (inclusive)
  --min-cost <UNITS>     Minimum cost in minor currency units
  --max-cost <UNITS>     Maximum cost in minor currency units
  --cost-currency <CODE> Three-letter uppercase currency for cost filters
  --limit <N>            Page size (default: 50)
  --cursor <SEQ>         Pagination cursor (seq value)
  --tenant <ID>          Strict tenant read boundary (local mode);
                         required for local --receipt-db reads unless
                         --admin-all is set.
  --admin-all            Explicit local-operator read across all tenants
                         (local mode); required unless --tenant is set.
  --control-url <URL>    Trust-control server URL
  --control-token <TOK>  Bearer token for the trust-control server
  --receipt-db <PATH>    Path to receipt SQLite file (local mode)
```

Local `--receipt-db` reads require an explicit read boundary. The CLI does
not silently default to admin-all reads across all tenants. Pass either
`--tenant <id>` to scope output to a single tenant or `--admin-all` to
read across tenants as a documented operator action. Remote
`--control-url` reads derive the read boundary from the control token.
`--min-cost` and `--max-cost` require `--cost-currency`.

Each matching receipt is printed as a JSON object on its own line (NDJSON). Example:

```bash
# Local mode, scoped to one tenant.
chio --receipt-db ./receipts.sqlite receipt list \
  --tenant my-tenant \
  --outcome deny \
  --since 1700000000

# Remote control plane.
chio receipt list \
  --outcome deny \
  --since 1700000000 \
  --control-url http://localhost:7391 \
  --control-token my-token
```

To paginate programmatically, capture `nextCursor` from the HTTP response and pass it as `--cursor` on the next invocation.
