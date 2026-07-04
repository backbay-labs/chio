# Data Layer Guards -- Technical Design

> **Status**: Proposed April 2026
> **Depends on**: `docs/protocols/DATA-LAYER-INTEGRATION.md` (type system
> extensions), `docs/guards/01-CURRENT-GUARD-SYSTEM.md` (guard trait and
> pipeline)

These are the first guards designed natively for Chio. Every previous guard
was ported from the prior async-guard suite, which had no database guards
because it was built for filesystem/shell/network governance. Data layer
governance is new ground.

---

## 1. Guard Catalog

Six new guards, four pre-invocation and two post-invocation:

| Guard | Phase | What it governs |
|-------|-------|-----------------|
| `SqlQueryGuard` | Pre-invocation | SQL statement structure: tables, columns, operation class, LIMIT, required predicates |
| `VectorDbGuard` | Pre-invocation | Vector database operations: collection/namespace scoping, operation class, top_k limits |
| `WarehouseCostGuard` | Pre-invocation | Warehouse query cost: bytes scanned, monetary cost via dry-run estimates |
| `GraphTraversalGuard` | Pre-invocation | Graph database traversals: depth limits, label/relationship restrictions |
| `CacheKeyGuard` | Pre-invocation | Cache/session store access: key pattern enforcement, dangerous command blocking |
| `QueryResultGuard` | Post-invocation | Result inspection: row count enforcement, column redaction, PII pattern matching |

All six implement fail-closed semantics. Errors during evaluation produce
`Verdict::Deny` (pre-invocation) or `PostInvocationVerdict::Block`
(post-invocation), consistent with every existing Chio guard.

---

## 2. `ToolAction::DatabaseQuery` -- The New Variant

### 2.1 Variant Definition

The `ToolAction` enum in `chio-guards/src/action.rs` gains a
`DatabaseQuery` variant. This is the discriminant that data layer guards
match on:

```rust
pub enum ToolAction {
    // ... existing: FileAccess, FileWrite, NetworkEgress,
    //               ShellCommand, McpTool, Patch, Unknown ...

    /// Database query execution.
    DatabaseQuery {
        /// Database engine identifier.
        engine: DatabaseEngine,
        /// Raw query text (SQL, Cypher, MQL, Redis command, etc.).
        query: String,
        /// Derived operation class from query analysis.
        operation_class: DataOperationClass,
        /// Tables or collections referenced.
        tables: Vec<String>,
        /// Columns in the SELECT projection (if parseable).
        columns: Vec<String>,
        /// Whether the query has a LIMIT/top_k bound.
        has_limit: bool,
        /// Whether the query has a WHERE/filter predicate.
        has_filter: bool,
        /// Dry-run cost estimate from the tool server, if available.
        estimated_cost: Option<MonetaryAmount>,
        /// Dry-run bytes-scanned estimate, if available.
        estimated_bytes: Option<u64>,
        /// Target database, schema, namespace, or collection path.
        target: String,
    },
}
```

`DatabaseEngine` and `DataOperationClass` are defined in
`docs/protocols/DATA-LAYER-INTEGRATION.md` section 3.2.

### 2.2 How `extract_action()` Populates It

The existing `extract_action(tool_name, arguments)` function uses
heuristic matching on tool names. The data layer extension adds a new
matching block before the MCP fallback:

```rust
// Database / query tools
if matches!(
    tool.as_str(),
    "sql_query" | "query" | "db_query" | "database_query"
        | "warehouse_query" | "bigquery_query" | "snowflake_query"
        | "nosql_query" | "mongo_query"
        | "graph_query" | "cypher_query"
        | "vector_search" | "vector_query" | "similarity_search"
        | "cache_access" | "redis" | "cache_get" | "cache_set"
        | "search" | "elasticsearch_query"
) {
    return extract_database_action(tool_name, arguments);
}
```

The `extract_database_action` helper:

1. Reads `arguments.engine` (or infers from tool name).
2. Reads `arguments.query` (the raw query text).
3. For SQL engines, parses the query with `sqlparser-rs` to extract
   tables, columns, operation class, LIMIT presence, and WHERE presence.
4. For non-SQL engines, reads structured fields (`collection`,
   `namespace`, `operation`, `top_k`, `key`, `max_depth`).
5. Reads `arguments.dry_run_estimate.bytes_scanned` and
   `arguments.dry_run_estimate.estimated_cost` if present.
6. Returns `ToolAction::DatabaseQuery { ... }`.

If extraction fails (missing fields, unsupported engine), the function
returns `ToolAction::Unknown`. Guards receiving `Unknown` for a tool
name they do not recognize return `Verdict::Allow` -- the guard does not apply. But if a guard *does* apply (the tool name matches a
database pattern and the engine is recognized) and the query cannot be
parsed, the guard itself denies. This separation keeps `extract_action`
best-effort while guards remain fail-closed.

### 2.3 Tool Name Recognition

The data layer tool name list is intentionally broad. Tool servers use
varied naming conventions:

- LangChain: `sql_db_query`, `sql_db_list_tables`
- LlamaIndex: `query_engine_query`
- Custom: `pg_query`, `run_sql`, `analytics_query`

The `extract_action` heuristic also checks for substring patterns:
`tool.contains("sql")`, `tool.contains("query") && arguments has "engine"`,
`tool.contains("vector")`, `tool.contains("redis")`, `tool.contains("cache")`.
Substring matching runs after the exact-match block and before the MCP
fallback.

---

## 3. Pre-Invocation Guards

### 3.1 `SqlQueryGuard`

**Purpose**: Parse SQL queries and enforce data layer constraints from the
matched `ToolGrant`.

**Implements**: `chio_kernel::Guard`

#### What It Checks

The guard reads the `ToolAction::DatabaseQuery` variant and evaluates:

1. **Operation class** (`Constraint::OperationClass`): The parsed
   operation class (SELECT = `ReadOnly`, INSERT = `Append`, UPDATE =
   `ReadWrite`, DELETE = `ReadWriteDelete`, DDL = `Admin`) must not
   exceed the constraint. `DataOperationClass` implements `PartialOrd`,
   so this is a `parsed <= granted` comparison.

2. **Table allowlist** (`Constraint::TableAllowlist`): Every table
   referenced in `FROM`, `JOIN`, `INSERT INTO`, `UPDATE`, `DELETE FROM`
   must match at least one allowlist entry. Entries support glob patterns
   (`analytics_*`). Tables are matched case-insensitively.

3. **Column denylist** (`Constraint::ColumnDenylist`): No column in the
   SELECT projection may appear in the denylist. `SELECT *` is denied
   when a column denylist is active because the guard cannot prove that
   the expansion excludes denied columns.

4. **Column allowlist** (`Constraint::ColumnAllowlist`): If present,
   every column in the SELECT projection must appear in the allowlist.
   `SELECT *` is denied when a column allowlist is active.

5. **Required filter predicate** (`Constraint::RequiredFilterPredicate`):
   The query must include a `WHERE` predicate on the specified column.
   If `expected_value` is set, the predicate must compare the column to
   that value (equality only). This enforces tenant isolation.

6. **Max rows returned** (`Constraint::MaxRowsReturned`): The query must
   include a `LIMIT` clause, and the limit value must not exceed the
   constraint. Queries without `LIMIT` are denied when this constraint
   is active.

7. **Destructive write safety**: `DELETE` and `UPDATE` without a `WHERE`
   clause are always denied regardless of operation class. This is a
   hardcoded safety check, not a constraint -- it cannot be overridden.

8. **DDL gating**: `CREATE`, `ALTER`, `DROP`, `TRUNCATE` require
   `DataOperationClass::Admin`. This is also hardcoded.

#### How It Reads Constraints

The guard iterates `ctx.scope.grants[ctx.matched_grant_index].constraints`
and pattern-matches on `Constraint` variants. It collects all relevant
constraints before evaluation so that multiple constraints compose
(table allowlist AND column denylist AND required predicate all apply
simultaneously).

```rust
impl Guard for SqlQueryGuard {
    fn name(&self) -> &str {
        "sql-query"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        let action = extract_action(&ctx.request.tool_name, &ctx.request.arguments);
        let db = match &action {
            ToolAction::DatabaseQuery { engine, .. }
                if engine.is_sql() => &action,
            _ => return Ok(Verdict::Allow), // Not a SQL tool call.
        };

        // Parse the SQL query. Fail-closed on parse failure.
        let parsed = self.parser.parse(query, dialect)
            .map_err(|e| KernelError::Internal(
                format!("sql-query guard: parse failed (fail-closed): {e}")
            ))?;

        // ... constraint checks (see above) ...

        Ok(Verdict::Allow)
    }
}
```

#### SQL Parsing Strategy

**Crate**: [`sqlparser`](https://crates.io/crates/sqlparser) (the Rust
crate, commonly referenced as `sqlparser-rs`).

**Dialect support**: The guard selects the `sqlparser::dialect::Dialect`
based on `DatabaseEngine`:

| Engine | Dialect |
|--------|---------|
| `Postgres` | `PostgreSqlDialect` |
| `Mysql` | `MySqlDialect` |
| `Sqlite` | `SQLiteDialect` |
| `BigQuery` | `BigQueryDialect` |
| `Snowflake` | `SnowflakeDialect` |
| `Redshift` | `RedshiftSqlDialect` |
| `Databricks` | `GenericDialect` (closest match) |
| Other SQL | `GenericDialect` |

**Fail-closed on parse failure**: If `sqlparser` cannot parse the query,
the guard returns `Err(KernelError::Internal(...))`, which the kernel
treats as deny. This matches Chio's convention (see `DataFlowGuard`,
which returns `Err` when the session journal is unavailable).

Rationale: an unparseable query is either malformed (should not execute),
uses exotic syntax the parser does not support (conservative denial is
safer than blind pass-through), or is a deliberate evasion attempt
(SQL injection via parser confusion). All three cases warrant denial.

**Multi-statement queries**: `sqlparser` returns a `Vec<Statement>`.
If the query contains multiple statements (`;`-separated), the guard
evaluates each independently. All must pass. This prevents evasion by
appending a second statement: `SELECT name FROM users; DROP TABLE users`.

**Subqueries and CTEs**: `sqlparser` produces an AST that includes
subqueries and CTEs. The guard walks the full AST to extract all
referenced tables, not just top-level `FROM` clauses.

**Prepared statement parameters**: If the query contains `$1`-style
parameters, the guard evaluates the template. Table names and column
names are structural, not parameterized, so they are still visible.
The guard cannot validate parameter values -- that is the tool server's
responsibility.

#### Concrete Deny Scenarios

```
Grant constraints:
  TableAllowlist(["users", "orders", "products"])
  OperationClass(ReadOnly)
  ColumnDenylist(["ssn", "credit_card_number"])
  RequiredFilterPredicate { column: "tenant_id", expected_value: None }
  MaxRowsReturned(1000)

DENIED: SELECT * FROM salaries LIMIT 10;
  Reason: table "salaries" not in allowlist

DENIED: DELETE FROM users WHERE id = 42;
  Reason: DELETE is ReadWriteDelete, grant permits ReadOnly

DENIED: SELECT name, ssn FROM users WHERE tenant_id = 'acme' LIMIT 10;
  Reason: column "ssn" is in the denylist

DENIED: SELECT * FROM users WHERE tenant_id = 'acme' LIMIT 10;
  Reason: SELECT * denied when column denylist is active

DENIED: SELECT name FROM users WHERE region = 'us-east' LIMIT 10;
  Reason: missing required WHERE predicate on "tenant_id"

DENIED: SELECT name FROM users WHERE tenant_id = 'acme';
  Reason: no LIMIT clause, grant requires max 1000 rows

DENIED: SELECT name FROM users WHERE tenant_id = 'acme' LIMIT 50000;
  Reason: LIMIT 50000 exceeds grant maximum of 1000

ALLOWED: SELECT name, email FROM users WHERE tenant_id = 'acme' LIMIT 100;
```

---

### 3.2 `VectorDbGuard`

**Purpose**: Enforce collection/namespace scoping and operation class
constraints on vector database tool calls.

**Implements**: `chio_kernel::Guard`

#### What It Checks

1. **Collection allowlist** (`Constraint::CollectionAllowlist`): The
   collection path (formatted as `namespace/collection`) must match at
   least one allowlist entry. Entries support glob patterns
   (`production/*`, `prod/customer-*`).

2. **Operation class** (`Constraint::OperationClass`): Vector operations
   map to classes as follows:

   | Operation | Class |
   |-----------|-------|
   | `query`, `search`, `fetch` | `ReadOnly` |
   | `upsert`, `insert` | `Append` |
   | `update` | `ReadWrite` |
   | `delete` | `ReadWriteDelete` |
   | `create_collection`, `delete_collection` | `Admin` |
   | unknown | `ReadWrite` (conservative default) |

3. **Top-k limit** (`Constraint::MaxRowsReturned`): The `top_k`
   parameter must not exceed the constraint. `MaxRowsReturned` is
   reused because it serves the same purpose -- bounding result volume.

4. **Embedding exfiltration**: When the operation class is `ReadOnly`
   and the arguments contain `"include_vectors": true`, the guard denies.
   Raw vectors enable reconstruction attacks. This is a hardcoded check.

#### How It Reads Constraints

The guard reads `arguments.collection`, `arguments.namespace`,
`arguments.operation`, and `arguments.top_k` from the tool call. It
does not require SQL parsing. The tool server is expected to submit
structured arguments per the contract in
`docs/protocols/DATA-LAYER-INTEGRATION.md` section 5.2.

If the tool call has no `collection` field and no `namespace` field,
the guard returns `Verdict::Allow` -- it does not apply to this tool
call. This follows the pattern used by `ForbiddenPathGuard`, which
allows actions without filesystem paths.

#### Concrete Deny Scenarios

```
Grant constraints:
  CollectionAllowlist(["production/product-embeddings", "production/faq-*"])
  OperationClass(ReadOnly)
  MaxRowsReturned(50)

DENIED: collection="internal-hr-embeddings", namespace="production"
  Reason: "production/internal-hr-embeddings" not in allowlist

DENIED: collection="product-embeddings", namespace="staging"
  Reason: "staging/product-embeddings" not in allowlist

DENIED: operation="upsert"
  Reason: upsert is Append, grant permits ReadOnly

DENIED: top_k=500
  Reason: top_k 500 exceeds maximum 50

DENIED: operation="query", include_vectors=true
  Reason: raw vector retrieval denied on ReadOnly grants

ALLOWED: collection="product-embeddings", namespace="production",
         operation="query", top_k=10, include_vectors=false
```

---

### 3.3 `WarehouseCostGuard`

**Purpose**: Enforce cost limits on data warehouse queries using
pre-execution dry-run estimates.

**Implements**: `chio_kernel::Guard`

#### The Dry-Run Pattern

Data warehouses (BigQuery, Snowflake, Databricks) support dry-run
queries that return estimated scan size and cost without executing. The
Chio guard does not call warehouse APIs directly. Instead:

1. The tool server receives the query from the agent.
2. The tool server runs the warehouse dry-run API itself.
3. The tool server includes the estimate in the tool call arguments:
   ```json
   {
     "query": "SELECT ...",
     "engine": "bigquery",
     "dry_run_estimate": {
       "bytes_scanned": 52428800,
       "estimated_cost": { "units": 25, "currency": "USD" }
     }
   }
   ```
4. The Chio kernel evaluates the guard using the submitted estimate.
5. If allowed, the tool server executes the actual query.

This design preserves Chio's architecture: the kernel never has direct
access to external services. The tool server is inside the sandbox; the
kernel is the trusted mediator. The kernel trusts the dry-run estimate
to the same degree it trusts any tool server argument -- it is the best
available signal, and the tool server is incentivized to report
accurately because the receipt log creates an auditable record.

**Why not call the warehouse API from the guard?** Three reasons:
(a) the guard runs synchronously in the kernel's `evaluate()` path and
cannot perform async I/O; (b) the kernel would need warehouse
credentials, violating privilege separation; (c) the kernel would become
coupled to warehouse-specific APIs.

#### What It Checks

1. **Max bytes scanned** (`Constraint::MaxBytesScanned`): The
   `dry_run_estimate.bytes_scanned` must not exceed the constraint.

2. **Max cost per query** (`Constraint::MaxCostPerQuery`): The
   `dry_run_estimate.estimated_cost.units` must not exceed the
   constraint. Currency must match.

3. **Missing dry-run estimate**: If the grant has `MaxBytesScanned` or
   `MaxCostPerQuery` constraints but the tool call does not include a
   `dry_run_estimate`, the guard denies. Fail-closed: uncosted queries
   are not allowed when cost constraints are active.

The guard also works in concert with the kernel's existing budget
checking (`max_cost_per_invocation` on `ToolGrant`). The guard provides
the pre-execution gate; the kernel's budget tracker records the actual
cost post-execution via `CostDimension::WarehouseQuery`.

#### How It Reads Constraints

The guard reads constraints from the matched grant, same as
`SqlQueryGuard`. It reads `arguments.dry_run_estimate` as a JSON object.

#### Concrete Deny Scenarios

```
Grant constraints:
  MaxBytesScanned(1_073_741_824)     # 1 GB
  MaxCostPerQuery({ units: 500, currency: "USD" })  # $5.00

DENIED: dry_run_estimate.bytes_scanned = 53_687_091_200 (50 GB)
  Reason: query would scan 50 GB, exceeding limit of 1 GB

DENIED: dry_run_estimate.estimated_cost = { units: 2500, currency: "USD" }
  Reason: estimated cost $25.00 exceeds limit $5.00

DENIED: no dry_run_estimate field present
  Reason: cost constraints require a dry-run estimate (fail-closed)

ALLOWED: dry_run_estimate = { bytes_scanned: 52428800, estimated_cost: { units: 25, currency: "USD" } }
  (50 MB scan, $0.25 cost -- within both limits)
```

---

### 3.4 `GraphTraversalGuard`

**Purpose**: Prevent unbounded graph database traversals that return
massive subgraphs.

**Implements**: `chio_kernel::Guard`

#### What It Checks

1. **Max traversal depth** (`Constraint::MaxTraversalDepth`): The
   declared or parsed traversal depth must not exceed the constraint. For
   Cypher queries, the guard inspects variable-length path patterns
   (`[*1..N]`). A pattern without an upper bound (`[*]` or `[*1..]`) is
   always denied when this constraint is active.

2. **Operation class** (`Constraint::OperationClass`): Graph operations
   map similarly to SQL. `MATCH`/`RETURN` = `ReadOnly`, `CREATE` =
   `Append`, `SET` = `ReadWrite`, `DELETE`/`DETACH DELETE` = `ReadWriteDelete`.

3. **Node label and relationship type restrictions**: The guard can
   check `arguments.node_labels` and `arguments.relationship_types`
   against `Constraint::TableAllowlist` (reused -- graph labels are
   analogous to table names).

#### Cypher Parsing

Full Cypher parsing is not attempted. The guard uses a lightweight regex
extraction for variable-length paths and relies on structured arguments
(`max_depth`, `node_labels`, `relationship_types`) from the tool server.
If the tool server provides neither structured arguments nor a parseable
Cypher pattern, the guard denies when `MaxTraversalDepth` is active
(fail-closed).

#### Concrete Deny Scenarios

```
Grant constraints:
  MaxTraversalDepth(3)
  OperationClass(ReadOnly)
  TableAllowlist(["Person", "Organization"])

DENIED: MATCH (a)-[*]->(b) RETURN b
  Reason: unbounded traversal depth, grant permits max 3

DENIED: MATCH (a)-[*1..10]->(b) RETURN b
  Reason: traversal depth 10 exceeds maximum of 3

DENIED: MATCH (a:Secret)-[:KNOWS]->(b) RETURN b
  Reason: node label "Secret" not in allowlist

DENIED: CREATE (n:Person { name: 'Eve' })
  Reason: CREATE is Append, grant permits ReadOnly

ALLOWED: MATCH (p:Person)-[:KNOWS*1..3]->(friend) RETURN friend.name
```

---

### 3.5 `CacheKeyGuard`

**Purpose**: Scope cache/session store access to specific key patterns
and block dangerous administrative commands.

**Implements**: `chio_kernel::Guard`

#### What It Checks

1. **Key pattern allowlist** (`Constraint::KeyPatternAllowlist`): The
   key (or key pattern for SCAN) must match at least one allowlist entry.
   Entries use glob syntax: `session:agent-42:*`, `cache:public:*`.

2. **Dangerous command blocking**: The following Redis commands are
   always denied unless the grant has `DataOperationClass::Admin`:
   `KEYS *`, `FLUSHDB`, `FLUSHALL`, `CONFIG SET`, `CONFIG REWRITE`,
   `DEBUG`, `SHUTDOWN`, `SLAVEOF`, `REPLICAOF`, `CLUSTER`,
   `SCRIPT FLUSH`.

3. **Operation class** (`Constraint::OperationClass`): `GET`/`MGET`/
   `EXISTS`/`TTL`/`TYPE`/`SCAN` = `ReadOnly`. `SET`/`MSET`/`SETNX`/
   `LPUSH`/`RPUSH`/`SADD`/`ZADD`/`HSET` = `Append`. `DEL`/`UNLINK`/
   `EXPIRE`/`PERSIST` = `ReadWriteDelete`.

#### How It Reads Arguments

The guard reads `arguments.key` (single key), `arguments.pattern`
(SCAN pattern), and `arguments.operation` or `arguments.command`
(the Redis command).

#### Concrete Deny Scenarios

```
Grant constraints:
  KeyPatternAllowlist(["session:agent-42:*", "cache:public:*"])
  OperationClass(ReadOnly)

DENIED: key="session:agent-99:state"
  Reason: key does not match any allowlist pattern

DENIED: key="admin:config"
  Reason: key does not match any allowlist pattern

DENIED: operation="SET", key="session:agent-42:state"
  Reason: SET is Append, grant permits ReadOnly

DENIED: command="FLUSHDB"
  Reason: FLUSHDB is always denied without Admin operation class

ALLOWED: operation="GET", key="session:agent-42:state"
```

---

## 4. Post-Invocation Guards

### 4.1 `QueryResultGuard`

**Purpose**: Inspect query results after tool execution but before
delivery to the agent. Provides defense-in-depth for constraints that
pre-invocation guards can only partially enforce.

**Implements**: `PostInvocationHook` (from `chio-guards/src/post_invocation.rs`)

#### What It Checks

1. **Row count enforcement** (`Constraint::MaxRowsReturned`): If the
   tool response metadata includes `row_count` and it exceeds the
   constraint, the guard truncates the result (returning
   `PostInvocationVerdict::Redact` with truncated rows).

   Why post-invocation? The pre-invocation `SqlQueryGuard` checks the
   LIMIT clause, but the tool server may ignore the LIMIT, or the
   database may return more rows than expected (e.g., due to a bug).
   The post-invocation guard is the last line of defense.

2. **Column redaction** (`Constraint::ColumnDenylist`): If the response
   metadata includes `columns` and any column appears in the denylist,
   the guard redacts those columns from the result payload. Returns
   `PostInvocationVerdict::Redact` with the denied columns replaced by
   `"[REDACTED]"`.

   Why post-invocation? The pre-invocation guard checks SELECT column
   names, but table structures change, aliases can mask column names,
   and the tool server might add columns to the response that were not
   in the SELECT list (e.g., `_id`, `_score`).

3. **PII pattern matching**: Scans string values in the response for
   common PII patterns:

   | Pattern | Regex |
   |---------|-------|
   | SSN | `\d{3}-\d{2}-\d{4}` |
   | Credit card | `\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}` |
   | Email | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` |
   | Phone (US) | `\+?1?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}` |

   If PII is detected and a `ColumnDenylist` or `Custom("pii_scan", "strict")`
   constraint is active, the guard replaces matched values with
   `"[PII REDACTED]"` and returns `PostInvocationVerdict::Redact`.

   If PII is detected but no PII constraint is active, the guard returns
   `PostInvocationVerdict::Escalate` with a message identifying the
   pattern. This uses the advisory pattern from `AdvisoryPipeline` --
   the response is still delivered, but an escalation signal is emitted
   for operator review.

#### Integration with `PostInvocationPipeline`

`QueryResultGuard` is registered on the `PostInvocationPipeline`
alongside the existing `ResponseSanitizationGuard`. Evaluation order
matters:

1. `ResponseSanitizationGuard` (existing) -- general PII/PHI detection
2. `QueryResultGuard` (new) -- data-layer-specific result enforcement

If `ResponseSanitizationGuard` redacts the response,
`QueryResultGuard` sees the redacted version (the pipeline chains
redactions). This is the correct behavior -- the more specific guard
operates on already-sanitized data.

#### Tool Server Response Contract

For `QueryResultGuard` to function, tool servers must include metadata
in their responses:

```json
{
  "result": [ ... rows ... ],
  "metadata": {
    "row_count": 47,
    "columns": ["name", "email", "created_at"],
    "engine": "postgres",
    "execution_ms": 120
  }
}
```

If metadata is absent, the guard falls back to inspecting the response
body directly. It counts array elements for row count and extracts
object keys for column names. This fallback is best-effort -- structured
metadata is preferred.

---

## 5. Composition with Existing Guards

The data layer guards do not replace existing guards. They compose in
the guard pipeline alongside them.

### 5.1 Composition with `VelocityGuard`

`VelocityGuard` (in `chio-guards/src/velocity.rs`) rate-limits by
`(capability_id, grant_index)`. Data layer guards run in the same
pipeline. Typical ordering:

```
VelocityGuard          -- is this agent rate-limited?
SqlQueryGuard          -- is the SQL query structurally safe?
WarehouseCostGuard     -- is the query cost within budget?
```

`VelocityGuard` runs first because it is cheap (no SQL parsing). If the
agent has exceeded its rate limit, the pipeline short-circuits before
the more expensive SQL parsing and cost estimation checks.

The existing `VelocityConfig.max_spend_per_window` can be used for
warehouse cost budgets at the velocity layer (tokens-per-window rate
limiting), while `WarehouseCostGuard` enforces per-query cost ceilings.
These are complementary: velocity limits the rate of spend,
`WarehouseCostGuard` limits the magnitude of each query.

### 5.2 Composition with `DataFlowGuard`

`DataFlowGuard` (in `chio-guards/src/data_flow.rs`) tracks cumulative
bytes read/written via the session journal. Database queries generate
data flow: a query returning 10,000 rows of 1 KB each produces ~10 MB
of bytes_read.

The tool server reports bytes in the response metadata. The kernel
records this in the session journal. `DataFlowGuard` enforces the
cumulative limit.

Data layer guards handle per-query governance (is this specific query
allowed?). `DataFlowGuard` handles session-level governance (has this
session transferred too much total data?). Both apply.

### 5.3 Composition with `EgressAllowlistGuard`

If the database tool server makes network calls (to a remote database),
`EgressAllowlistGuard` governs the network egress. But data layer
guards govern the query content. Both apply. The egress guard ensures
the tool server talks to the right host; the SQL guard ensures the
query is safe.

### 5.4 Pipeline Registration

```rust
let mut pipeline = GuardPipeline::default_pipeline();

// Add data layer guards after velocity, before MCP.
pipeline.add(Box::new(SqlQueryGuard::new(SqlParserConfig::default())));
pipeline.add(Box::new(VectorDbGuard));
pipeline.add(Box::new(WarehouseCostGuard));
pipeline.add(Box::new(GraphTraversalGuard));
pipeline.add(Box::new(CacheKeyGuard));

kernel.add_guard(Box::new(pipeline));

// Post-invocation pipeline.
let mut post_pipeline = PostInvocationPipeline::new();
post_pipeline.add(Box::new(ResponseSanitizationGuard::new(/* ... */)));
post_pipeline.add(Box::new(QueryResultGuard::new(/* ... */)));
```

---

## 6. Built-in vs. WASM Guards

### 6.1 Recommendation

**Built-in** (compiled into `chio-guards` or a new `chio-data-guards` crate):

- `SqlQueryGuard` -- SQL parsing with `sqlparser-rs` requires a full
  Rust AST library. Compiling `sqlparser` to WASM is possible but adds
  significant module size (~2 MB) and loses the type safety of matching
  on `sqlparser::ast::Statement` directly.
- `VectorDbGuard` -- Simple argument inspection, no external
  dependencies. Built-in is simpler and faster.
- `WarehouseCostGuard` -- Reads numeric fields from arguments. No
  complex logic. Built-in.
- `GraphTraversalGuard` -- Lightweight regex extraction. Built-in.
- `CacheKeyGuard` -- Glob matching on key patterns. Built-in.
- `QueryResultGuard` -- Post-invocation hook. The WASM guard interface
  is pre-invocation only (`Guard` trait). Post-invocation hooks are a
  separate pipeline. Built-in.

**WASM** (deployed as organization-specific guard modules):

- Organization-specific PII column lists (beyond the built-in patterns)
- Custom SQL deny patterns (e.g., "deny any query that joins more than
  4 tables")
- Industry-specific compliance rules (HIPAA, SOX, PCI-DSS column-level
  restrictions)
- Custom cost policies (e.g., "deny BigQuery queries on weekends",
  "require manager approval above $100")

### 6.2 Rationale

The six data layer guards are universal -- every organization with
database-accessing agents needs them. Making them built-in ensures:

1. **No deployment friction**: Guards are available out of the box.
2. **Performance**: No WASM instantiation overhead per evaluation.
   SQL parsing is latency-sensitive.
3. **Type safety**: Guards match directly on `ToolAction::DatabaseQuery`
   fields, `Constraint` variants, and `sqlparser::ast` types.
4. **Testing**: Built-in guards are tested in the Chio CI pipeline.

Organization-specific policies layer on top as WASM guards. The built-in
guards handle the structural safety checks; WASM guards handle
policy-specific logic. This mirrors the existing split: `ForbiddenPathGuard`
(built-in, universal) vs. custom path policies (WASM, org-specific).

---

## 7. Crate Structure

The data layer guards live in a new `chio-data-guards` crate to keep the
dependency on `sqlparser` isolated from the core `chio-guards` crate:

```
crates/guards/chio-data-guards/
  Cargo.toml
  src/
    lib.rs                  # Re-exports, module declarations
    sql_query.rs            # SqlQueryGuard
    vector_db.rs            # VectorDbGuard
    warehouse_cost.rs       # WarehouseCostGuard
    graph_traversal.rs      # GraphTraversalGuard
    cache_key.rs            # CacheKeyGuard
    query_result.rs         # QueryResultGuard (PostInvocationHook)
    sql_analysis.rs         # sqlparser wrapper: dialect selection,
                            #   table/column/operation extraction
    action_ext.rs           # DatabaseQuery extraction for ToolAction
```

Dependencies:

```toml
[dependencies]
chio-core-types = { path = "../chio-core-types" }
chio-kernel = { path = "../chio-kernel" }
chio-guards = { path = "../chio-guards" }
sqlparser = "0.53"
regex = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
glob-match = "0.2"
```

The `sqlparser` dependency is the only new external dependency. It is
well-maintained (1,500+ GitHub stars, used by DataFusion, GlueSQL, and
other production query engines).

---

## 8. Constraint Reading Pattern

All data layer guards follow the same pattern for reading constraints
from the matched `ToolGrant`. This is a shared utility function:

```rust
/// Find all constraints of a specific type on the matched grant.
fn find_constraints<'a>(
    ctx: &'a GuardContext,
) -> impl Iterator<Item = &'a Constraint> {
    let grant_index = ctx.matched_grant_index.unwrap_or(0);
    ctx.scope
        .grants
        .get(grant_index)
        .map(|g| g.constraints.iter())
        .unwrap_or_else(|| [].iter())
}

/// Find the first constraint matching a predicate.
fn find_constraint<F>(ctx: &GuardContext, pred: F) -> Option<&Constraint>
where
    F: Fn(&Constraint) -> bool,
{
    find_constraints(ctx).find(|c| pred(c))
}
```

Usage in a guard:

```rust
// Check table allowlist.
if let Some(Constraint::TableAllowlist(allowed)) =
    find_constraint(ctx, |c| matches!(c, Constraint::TableAllowlist(_)))
{
    // ... evaluate ...
}
```

This pattern keeps constraint access consistent across all six guards
and mirrors how `VelocityGuard` reads `max_cost_per_invocation` from
the matched grant via `ctx.matched_grant_index`.

---

## 9. Open Design Questions

1. **Multi-statement SQL**: Should the guard allow multi-statement
   queries at all, or deny them unconditionally? Multi-statement queries
   are a common SQL injection vector. Recommendation: deny by default,
   with an opt-in `Constraint::Custom("allow_multi_statement", "true")`.

2. **View and CTE resolution**: The guard sees `SELECT * FROM my_view`.
   It cannot know which underlying tables `my_view` references without
   schema metadata. Should the tool server declare view-to-table
   mappings in the manifest? Recommendation: treat views as their own
   access targets; declare them in `TableAllowlist` explicitly.

3. **Cost estimate trust**: The tool server self-reports dry-run cost.
   A malicious tool server could underreport. Mitigation: the post-
   invocation receipt records actual bytes scanned (from the warehouse
   billing API response). The receipt log makes systematic underreporting
   auditable.

4. **Cypher parsing depth**: Should the `GraphTraversalGuard` invest in
   a real Cypher parser, or is regex extraction sufficient? Cypher
   parsing libraries in Rust are immature. Recommendation: regex
   extraction for v1, with structured `max_depth` arguments as the
   primary enforcement mechanism.

5. **Cross-guard state**: Should data layer guards share parsed query
   state? Currently each guard calls `extract_action()` independently.
   The pipeline could cache the `ToolAction` from the first extraction
   and pass it to subsequent guards. This is a pipeline optimization,
   not a correctness issue.
