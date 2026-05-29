# chio-data-guards

`chio-data-guards` houses guards that inspect the semantics of data-store
accesses rather than merely the presence of a tool. It ships `SqlQueryGuard`,
which parses SQL queries submitted to database tools and enforces allowlists on
operations, tables, columns, and predicates. The module layout is designed to
absorb further data-layer guards (vector DB, warehouse cost, query-result)
without breaking the public surface.

Use this crate alongside `chio-guards` when you need data-aware enforcement for
SQL, vector-database, or warehouse tool calls.
