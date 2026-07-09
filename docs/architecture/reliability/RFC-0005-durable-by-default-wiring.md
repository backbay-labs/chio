# RFC-0005: Durable-by-default store wiring, refuse-ephemeral gates, and schema versioning

- Status: Draft (proposed, wave-3 reliability program)
- Date: 2026-07-04
- Extends: ADR-0004 (first receipt backend), ADR-0013 (async receipt durability)
- Depends on: none
- Closes findings: F60, F19, F26, F62, F64, F65 (see ./README.md and the readiness review)

## Summary

Chio's audit guarantee (durable, verifiably-signed receipts, plus revocation
that survives restart) is only delivered when an operator explicitly wires a
durable store. On the one lane the reference deployments actually ship
(`chio api protect` / `chio start`), durability is not the default: the embedded
kernel is constructed with `allow_ephemeral_receipt_log: true` hardcoded,
revocations and budgets live in RAM, and none of the three deploy manifests pass
`--receipt-store`. The result is silent total audit-log loss on every restart or
scale-in while health probes stay green. This RFC makes durability the default
and ephemerality an explicit, loud opt-in: it adds store-accepting builder
variants to `HttpAuthority` threaded through `ChioEvaluator`/`ChioLayer`, flips
`allow_ephemeral_receipt_log` to opt-in on the HTTP mediation path, adds a
matching revocation-durability gate, makes `chio api protect`/`chio start`
refuse to boot without `--receipt-store` unless `--allow-ephemeral-receipts` is
passed, repairs the three manifests and the two phantom-config docs, and adds
SQLite schema versioning plus a fail-closed migration runner for every operator
store.

## Motivation

The article lens ("overload/crashes must fail early, local, and graceful; know
the blast radius; internal accounting must be trustworthy or loudly broken;
durable recovery") is exactly inverted on the sidecar lane today: a crash loses
all audit state, the loss is silent (not loud), and recovery has nothing to
recover.

Blast radius, per finding:

- F60 (critical). Trigger: an operator copy-pastes any of the three reference
  manifests. Effect: the sidecar runs with in-memory receipt and approval
  stores, zero startup warning. Every restart, deploy, or Cloud Run scale-in
  (routine, `maxScale 100`) destroys all signed receipts and pending approvals
  on that instance. Impact: the deployment produces no durable audit evidence,
  which is the product's core security claim; discovery happens during an
  incident, when the evidence is already gone.
- F19 (high). Trigger: routine process death of any `chio-tower` middleware host
  or `api-protect` sidecar in the default configuration. Effect: the embedded
  kernel's receipt log (always ephemeral, no constructor can make it durable)
  and all pending approvals vanish. The tower middleware path has no opt-out
  whatsoever.
- F26 (high). Trigger: a kernel restarted without `--revocation-db`/
  `--control-url`. Effect: the revocation check runs against an empty in-memory
  `HashSet`, so previously revoked but unexpired capabilities validate again;
  no error, no warning, no health signal.
- F62 (medium). Trigger: a runbook rollback that skips the conditional state
  restore, or any future non-additive schema change. Effect: an old binary
  opens a newer-schema database with zero detection and no version stamp to
  diagnose the mismatch after the fact.
- F64 (medium). Trigger: an operator follows `CLOUD-SIDECAR-INTEGRATION.md`
  section 7 or 9 and sets `CHIO_RECEIPT_SINK=dynamodb://...`. Effect: the env
  var is read by nothing; receipts stay in memory. The L3 failure class:
  dashboards green, evidence absent.
- F65 (high). Trigger: an operator deploys the Azure reference. Effect: with no
  `--spec` the sidecar derives its entire route/scope table from whatever
  OpenAPI document the untrusted upstream self-publishes (trust inversion), and
  with no `--receipt-store` receipts live in RAM on all three platforms.

The unifying theme is a wiring gap: the fail-closed durability posture exists in
the kernel (`ensure_receipt_persistence_ready`) but is switched off by
construction on the exact lane that ships, and there is no matching gate for
revocation at all.

## Current behavior (verified 2026-07-04)

Re-verified against live code. Quoted signatures are current.

Kernel gate exists but is bypassed. `ensure_receipt_persistence_ready`
(`crates/kernel/chio-kernel/src/kernel/construction.rs:244`) returns `Ok` only
when `self.receipt_store.is_some() || self.config.allow_ephemeral_receipt_log`,
otherwise `Err(KernelError::Internal("durable receipt persistence unavailable ..."))`.
`ChioKernel::new` installs in-memory stores unconditionally and leaves the
receipt store unset (`construction.rs:180`, `:182`, `:190`, `:202`, `:203`):
`budget_store: Arc::new(InMemoryBudgetStore::new())`,
`revocation_store: Arc::new(InMemoryRevocationStore::new())`,
`receipt_store: None`, `execution_nonce_config: None`,
`execution_nonce_store: None`. `KernelConfig.allow_ephemeral_receipt_log` is
declared at `crates/kernel/chio-kernel/src/kernel/kernel_struct.rs:46` (doc:
"for tests and local scaffolds only"). The control-plane policy default is
fail-closed: `crates/platform/chio-control-plane/src/policy/types.rs:177` field,
`:193` default `allow_ephemeral_receipt_log: false`.

HTTP mediation path hardcodes ephemeral. `crates/platform/chio-http-core/src/authority.rs`
has a single underlying constructor
(`new_with_approval_store_and_trusted_issuers`, `:253`) that every other
`HttpAuthority` constructor funnels through. It builds the kernel with
`allow_ephemeral_receipt_log: true` hardcoded at `:279`, immediately wraps it in
`Arc::new(kernel)` at `:289`, and never calls `set_receipt_store`. The public
`HttpAuthority::new(keypair, policy_hash)` (`:229`) delegates to that constructor
with an `InMemoryApprovalStore` and no issuers. There is no receipt-store or
revocation-store parameter on any `HttpAuthority` constructor. The kernel setters
that would attach them are `crates/kernel/chio-kernel/src/kernel/construction.rs`:

```rust
// :390
pub fn set_receipt_store(&mut self, receipt_store: Box<dyn ReceiptStore>) -> Result<(), KernelError>
// :397
pub fn set_receipt_store_handle(&mut self, receipt_store: Arc<dyn ReceiptStore>) -> Result<(), KernelError>
// :444
pub fn set_revocation_store(&mut self, revocation_store: Box<dyn RevocationStore>)
// :448
pub fn set_revocation_store_handle(&mut self, revocation_store: Arc<dyn RevocationStore>)
```

They take `&mut self`; the authority Arc-wraps the kernel before any of them can
run, so a store must be attached before the `Arc::new` at `authority.rs:289`.

Tower path has no persistence hook. `crates/protocol/chio-tower/src/evaluator.rs:50`
defines `ChioEvaluator { authority, identity_extractor, route_resolver, fail_open }`;
`ChioEvaluator::new` (`:61`) calls `HttpAuthority::new(keypair, policy_hash)`
and the only builders are `with_identity_extractor`, `with_route_resolver`,
`with_fail_open`. `crates/protocol/chio-tower/src/layer.rs:21` and `ChioLayer::new`
(`:28`) mirror this. No persistence knob exists.

Sidecar uses a private, mutable, non-Merkle store. `crates/products/chio-api-protect/src/proxy/state.rs:13`
defines a `pub(crate) struct SqliteReceiptStore` that is distinct from the
Merkle-committed `chio_store_sqlite::SqliteReceiptStore`. It opens a plain
`Connection::open(path)` with no WAL/`synchronous` pragmas (`:19`) and writes
with `INSERT OR REPLACE` (mutable, not append-only) at `:86`, `:101`, `:129`.
Even in `--receipt-store` mode the sidecar loads the whole history into an
in-memory `Vec` (`ReceiptLog`, `:259-284`) and the embedded kernel's own receipt
log stays ephemeral. The signer keypair is `Keypair::generate()` fresh per boot
unless `signer_seed_hex` is set (`state.rs:228-232`), so historical receipts are
signed by an unrecoverable key.

CLI. The `api protect` subcommand is
`crates/products/chio-cli/src/cli/types/runtime.rs:830`:

```rust
pub(crate) enum ApiCommands {
    Protect {
        #[arg(long)] upstream: String,
        #[arg(long)] spec: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:9090")] listen: String,
        #[arg(long = "receipt-store")] receipt_store: Option<PathBuf>,
    },
}
```

`Commands::Start` (`crates/products/chio-cli/src/cli/types.rs:554`) carries the
same `--receipt-store` (doc: "Defaults to in-memory") plus `--listen` and
`--print-config`. `cmd_api_protect`
(`crates/products/chio-cli/src/cli/runtime.rs:147`) has signature
`(upstream: &str, spec_path: Option<&Path>, listen_addr: &str, receipt_store: Option<&Path>, authority_seed_path: Option<&Path>)`
and builds `ProtectConfig` with `receipt_db: receipt_store.map(...)` (`:177`).
It never refuses to start. `dispatch_api`
(`crates/products/chio-cli/src/cli/dispatch/api_mcp.rs:6`) forwards
`receipt_store.as_deref().or(receipt_db.as_deref())`.

Revocation. `configure_revocation_store`
(`crates/platform/chio-control-plane/src/lib.rs:419`) is a silent no-op on
`(None, None)`. The enforcement point `check_revocation`
(`crates/kernel/chio-kernel/src/kernel/validation.rs:441`) consults only the
kernel's `RevocationStore` via
`with_revocation_store(|store| Ok(store.is_revoked(&cap.id)?))`;
an empty `InMemoryRevocationStore`
(`crates/kernel/chio-kernel/src/revocation_runtime.rs:18`, `Mutex<HashSet>`,
"for development and testing") returns `is_revoked = false`, so a revoked
capability is accepted. There is no `ensure_revocation_*` gate and no
`allow_ephemeral_revocation_store` flag anywhere.

SQLite schema (F62). Every store bootstraps with `CREATE TABLE IF NOT EXISTS`
and evolves with additive `ALTER TABLE ADD COLUMN`. The shared connection setup
`crates/platform/chio-store-sqlite/src/receipt_store/bootstrap/open.rs:3`
(`configure_sqlite_connection`) sets `journal_mode = WAL`,
`synchronous = FULL`, `busy_timeout`, `foreign_keys` and asserts them
(`assert_sqlite_durability_pragmas`, `:16`), but sets neither
`PRAGMA user_version` nor `PRAGMA application_id`. The additive migration
pattern (fail-closed comment at
`crates/platform/chio-store-sqlite/src/receipt_store/support/claim_log/schema.rs:39`)
and the authority/budget schema modules use the same shape. A repository-wide
grep for `user_version`/`application_id` returns zero hits in any store crate.

Manifests. `deploy/cloud-run/service.yaml:83` args are
`api protect --upstream http://127.0.0.1:8080 --spec /etc/chio/spec/openapi.yaml
--listen 0.0.0.0:9090` (no `--receipt-store`), `minScale 1`/`maxScale 100`
(`:29`), mounting `chio-kernel-config` and `chio-openapi-spec` secret volumes
(`:105-139`). `deploy/ecs/task-definition.json:53` is equivalent (with `--spec`,
`readonlyRootFilesystem: true` at `:104`). `deploy/azure/container-app.bicep:122`
diverges: args are only `api protect --upstream ... --listen ...` (no `--spec`,
no `--receipt-store`) and the template declares zero volumes/mounts. All three
inject `CHIO_SIGNING_KEY` and `CHIO_CAPABILITY_AUTHORITY_URL` as secrets that no
code reads. `deploy/README.md:50` claims "Kernel and policy configuration is
loaded from a mounted `chio.yaml`", but `cmd_api_protect` has no config-file
parameter. `docs/protocols/CLOUD-SIDECAR-INTEGRATION.md` disclaims section 6.2
(`:321`) but sections 6.3 (`GET /health`), 7 (`CHIO_RECEIPT_SINK` sinks), and 9
(a `terraform/` module that does not exist) still assert a phantom surface.

## Design

The design has five parts. Parts A-C flip the HTTP mediation lane to
durable-by-default without breaking source compatibility; part D adds the CLI
gate and manifest/doc repair; part E adds schema versioning. Every proposed
path is fail-closed and uses `?`/typed errors (no `.unwrap()`/`.expect()`).

### A. Kernel: a revocation-durability gate mirroring receipts

Add `allow_ephemeral_revocation_store: bool` to `KernelConfig`
(`kernel_struct.rs`) and to the control-plane policy (`policy/types.rs`), both
defaulting `false`. Add a marker method to the `RevocationStore` trait
(`revocation_runtime.rs`) so the kernel can distinguish ephemeral from durable:

```rust
    /// Whether this store loses state on process restart. Default is the
    /// safe (loud) assumption; durable and remote stores override to false.
    fn is_ephemeral(&self) -> bool {
        true
    }
```

`InMemoryRevocationStore` inherits the default `true`;
`chio_store_sqlite::SqliteRevocationStore` and the remote store override to
`false`. Add the pre-dispatch gate next to `ensure_receipt_persistence_ready`
(`construction.rs`):

```rust
pub(crate) fn ensure_revocation_durability_ready(&self) -> Result<(), KernelError> {
    let ephemeral = self.with_revocation_store(|store| Ok(store.is_ephemeral()))?;
    if !ephemeral || self.config.allow_ephemeral_revocation_store {
        return Ok(());
    }
    Err(KernelError::Internal(
        "durable revocation state unavailable: no revocation store configured".to_string(),
    ))
}
```

Call it from the same pre-dispatch locations that already call
`ensure_receipt_persistence_ready`
(`kernel/evaluation/async_evaluation_core.rs:236` and
`kernel/evaluation/nested_flow_evaluation.rs:184`). Fail-closed: an empty
in-memory store with the flag unset now denies rather than silently accepting a
revoked capability. Expose the two backends in kernel health output
(`receipt_backend`, `revocation_backend`: `durable`/`remote`/`ephemeral`),
surfaced through the sidecar's fixed `GET /chio/health` route.

Landing note. `ChioKernel::new` installs `InMemoryRevocationStore`
unconditionally (`construction.rs:182`), so when this gate lands every
construction site that intends ephemerality must say so explicitly:
`mcp wrap` (which already sets `allow_ephemeral_receipt_log: true` in its
literal `KernelConfig` at `crates/products/chio-cli/src/cli/mcp/wrap.rs:314`)
and the test harnesses add `allow_ephemeral_revocation_store: true`, and the
legacy `HttpAuthority` constructors opt in via the part-B builder. The kernel
service lanes keep the policy default `false`, so `mcp serve` with
`--receipt-db` but without `--revocation-db`/`--control-url` changes from
silently accepting revoked capabilities to denying at dispatch. That behavior
change is the F26 fix and is intentional; the escape hatches are
`--revocation-db`, `--control-url`, or policy
`allow_ephemeral_revocation_store: true`.

### B. HttpAuthority: a store-accepting builder, ephemeral opt-in

Introduce a builder so stores can be attached before the kernel is Arc-wrapped,
and flip the hardcoded `allow_ephemeral_receipt_log`. Add to
`crates/platform/chio-http-core/src/authority.rs`:

```rust
#[derive(Default)]
pub struct HttpAuthorityBuilder {
    approval_store: Option<Arc<dyn ApprovalStore>>,
    receipt_store: Option<Arc<dyn ReceiptStore>>,
    revocation_store: Option<Arc<dyn RevocationStore>>,
    trusted_capability_issuers: Vec<PublicKey>,
    allow_ephemeral_receipt_log: bool,      // default false: fail-closed
    allow_ephemeral_revocation_store: bool, // default false: fail-closed
}

impl HttpAuthorityBuilder {
    // Each setter takes `mut self`, sets one field, and returns `Self` (`#[must_use]`):
    //   receipt_store(Arc<dyn ReceiptStore>), revocation_store(Arc<dyn RevocationStore>),
    //   approval_store(Arc<dyn ApprovalStore>), trusted_capability_issuers(Vec<PublicKey>),
    //   allow_ephemeral_receipt_log(bool), allow_ephemeral_revocation_store(bool).

    pub fn build(self, keypair: Keypair, policy_hash: String) -> Result<HttpAuthority, HttpAuthorityError> {
        // ... build KernelConfig with allow_ephemeral_receipt_log / _revocation
        //     from the builder (both default false) ...
        let mut kernel = ChioKernel::new(config);
        if let Some(store) = self.receipt_store {
            kernel
                .set_receipt_store_handle(store)
                .map_err(|error| HttpAuthorityError::Kernel(error.to_string()))?;
        }
        if let Some(store) = self.revocation_store {
            kernel.set_revocation_store_handle(store);
        }
        kernel.register_tool_server(Box::new(HttpAuthorizationServer));
        kernel.add_guard(Box::new(HttpProjectionGuard));
        // ... Arc-wrap AFTER stores are attached ...
    }
}
```

The single existing underlying constructor
(`new_with_approval_store_and_trusted_issuers`) is reimplemented in terms of the
builder with `allow_ephemeral_receipt_log(true)` and
`allow_ephemeral_revocation_store(true)` so that all three existing
constructors keep their current behavior under explicit, named opt-ins.
(Without the revocation opt-in, landing part A would immediately deny for
every current `HttpAuthority` embedder, since the kernel they build carries
the in-memory revocation store.) To preserve source compatibility while
flipping the runtime default, split the public surface:

- `HttpAuthority::new(keypair, policy_hash)` becomes fail-closed: it builds via
  the builder with both ephemeral flags `false` and no stores. Existing callers
  compile unchanged; at runtime the first mediated call now denies with
  "durable receipt persistence unavailable" instead of silently running
  ephemeral. This is the intended posture and matches the kernel-backed
  `mcp`/`run` lanes, which already deny-all when persistence is missing.
- `HttpAuthority::new_ephemeral(keypair, policy_hash)` is added for local
  scaffolds and tests that intend ephemerality (today's callers of
  `HttpAuthority::new` are the tower default path, `authority/tests.rs`, and
  the conformance suite). Note that `mcp wrap` is not such a caller: it never
  constructs an `HttpAuthority` and instead builds its `KernelConfig` directly
  (`wrap.rs:314`), so it is covered by the part-A flag, not by this split.

Because `build` returns `Result`, the ephemeral-vs-durable decision is explicit
at every construction site. Internally the builder splits assembly into an
infallible core (kernel config, tool server, guard, Arc-wrap) and the fallible
store-attach step (`set_receipt_store_handle`, which hydrates checkpoint
counters and can fail); `build` composes both, while the legacy `-> Self`
constructors call the infallible core with no stores attached, so they keep
their signatures without `.unwrap()`/`.expect()`.

### C. Thread the knob through ChioEvaluator / ChioLayer

`ChioEvaluator::new` eagerly constructs the authority, so add a builder that
defers authority construction until stores are known
(`crates/protocol/chio-tower/src/evaluator.rs`):

```rust
impl ChioEvaluator {
    #[must_use]
    pub fn builder(keypair: Keypair, policy_hash: String) -> ChioEvaluatorBuilder { /* ... */ }
}

impl ChioEvaluatorBuilder {
    // receipt_store(Arc<dyn ReceiptStore>), revocation_store(Arc<dyn RevocationStore>),
    // allow_ephemeral(bool) [default false], plus the existing
    // with_identity_extractor / with_route_resolver / with_fail_open.

    pub fn build(self) -> Result<ChioEvaluator, ChioTowerError> {
        let authority = HttpAuthority::builder()
            .allow_ephemeral_receipt_log(self.allow_ephemeral)
            .allow_ephemeral_revocation_store(self.allow_ephemeral)
            // .receipt_store(...) / .revocation_store(...) when present
            .build(self.keypair, self.policy_hash)
            .map_err(ChioTowerError::from)?;
        Ok(ChioEvaluator { authority, /* ... */ })
    }
}
```

`ChioEvaluator::new` and `ChioLayer::new` remain but delegate to
`builder(...).build()` with `allow_ephemeral = false` and no store, matching the
fail-closed posture in part B. `ChioLayer` gains the same
`receipt_store`/`revocation_store`/`allow_ephemeral` builder methods so a tower
embedder can wire a durable store once and clone the layer.

### D. api-protect wiring, CLI refuse-ephemeral gate, manifests, docs

Sidecar wiring. `api-protect` builds its evaluator through
`RequestEvaluator::new_with_approval_store_and_trusted_capability_issuers`
(`state.rs:251`), which reaches `HttpAuthority`. Route the durable store through
the new builder so the embedded kernel (not just the proxy-level cache) gets a
real `chio_store_sqlite::SqliteReceiptStore` and `SqliteRevocationStore`. The
private mutable `SqliteReceiptStore` in `state.rs:13` (INSERT OR REPLACE, no
WAL) is retained only as the read model for the inspection endpoints; the
system of record becomes the append-only Merkle store. When `--receipt-store` is
set, construct the durable stores and pass
`allow_ephemeral_receipt_log(false)`; the kernel's checkpoint counters hydrate
via `try_set_receipt_store_handle` (`construction.rs:404`).

CLI gate. Add a boolean flag to both entrypoints. `ApiCommands::Protect`
(`crates/products/chio-cli/src/cli/types/runtime.rs:830`):

```rust
Protect {
    #[arg(long)] upstream: String,
    #[arg(long)] spec: Option<PathBuf>,
    #[arg(long, default_value = "127.0.0.1:9090")] listen: String,
    #[arg(long = "receipt-store")] receipt_store: Option<PathBuf>,
    /// Permit in-memory receipts (audit evidence is lost on every restart).
    /// Required to boot without --receipt-store. For local dev only.
    #[arg(long, default_value_t = false)] allow_ephemeral_receipts: bool,
},
```

Add the identical flag to `Commands::Start` (`types.rs:554`), and update the
`Start` doc comment and startup banner, which currently advertise "in-memory
stores by default (no `--receipt-db`)"; the zero-config quickstart becomes
`chio start --allow-ephemeral-receipts`, one flag longer by design. Thread it
through
`dispatch_api` (`api_mcp.rs:6`) and into `cmd_api_protect`
(`runtime.rs:147`). Enforce the gate at the top of `cmd_api_protect`/`cmd_start`
before the async runtime is built:

```rust
if receipt_store.is_none() && !allow_ephemeral_receipts {
    return Err(CliError::cli_other_error(
        "refusing to start `chio api protect` without durable receipts: pass \
         --receipt-store <path> for a durable audit log, or --allow-ephemeral-receipts \
         to run with in-memory receipts that are lost on every restart"
            .to_string(),
    ));
}
```

Fail-closed: a manifest that forgets `--receipt-store` no longer boots into a
silent audit hole; it exits non-zero and the platform marks the revision
unhealthy (which is what F60 wanted). The same check covers the authority seed:
warn loudly (structured `warn!`) when `--authority-seed-file` is absent, since a
fresh signer per boot makes historical receipts unverifiable.

Manifests (F60, F65). Bring all three to parity and to durability:

- Add a persistent volume mounted read-write at `/var/lib/chio` and pass
  `--receipt-store /var/lib/chio/receipts.db`. On Cloud Run use a
  `emptyDir`-backed volume only for the ephemeral tier; for durable audit use a
  mounted GCS FUSE / Filestore volume or a managed backend. On ECS the EFS
  volume already exists (`chio-config`); add a second read-write EFS volume for
  the store (the rootfs stays read-only). On Azure add the volume the template
  currently lacks.
- Pass `--authority-seed-file` from a secret-mounted file on all three.
- Azure: add `--spec /etc/chio/spec/openapi.yaml` and the two config volume
  mounts its siblings already have, closing the trust-inversion half of F65.
- Either add a config-file flag to `api protect` that consumes the mounted
  `chio.yaml`, or delete the `chio-kernel-config` mount and the
  `deploy/README.md:50` claim. This RFC chooses deletion: the kernel policy is
  derived from the OpenAPI spec plus flags, so the `kernel.yaml` mount is
  phantom and should go.

Docs (F64, F65). Extend the section-6.2 disclaimer to the rest of
`CLOUD-SIDECAR-INTEGRATION.md`: rewrite section 7 around the real
`--receipt-store` flag and the `chio_store_sqlite` backends (delete
`CHIO_RECEIPT_SINK` and the `dynamodb://`/`bigquery://`/`s3://` examples), fix
section 6.3 from `GET /health` to the real fixed `GET /chio/health`, and delete
or mark-as-unbuilt the section-9 `terraform/` module. In `deploy/README.md`,
remove `CHIO_SIGNING_KEY`/`CHIO_CAPABILITY_AUTHORITY_URL` from the
"required secrets" list (nothing reads them) or wire them into `api protect`;
this RFC removes them and documents `--authority-seed-file` instead.

### E. Schema versioning and a fail-closed migration runner (F62)

Add a shared module `chio-store-sqlite/src/schema_version.rs` used by every
store's open path. Stamp `PRAGMA application_id` (database-wide, to distinguish a
Chio store from an unrelated SQLite file) and, in a Chio-owned
`chio_module_schema_version` table, a per-module schema revision (NOT the single
database-wide `PRAGMA user_version`, which cannot hold an independent version per
store module that shares the file), and refuse to open a database whose module
version is newer than the binary supports.

```rust
/// ASCII "CHIO" as a big-endian i32, stamped into every Chio operator store.
/// `application_id` is genuinely database-wide, so it marks the whole file as a
/// Chio store exactly once no matter how many store modules share the file.
const CHIO_SQLITE_APPLICATION_ID: i32 = 0x4348_494f;

/// Chio-owned per-module schema-version table. `PRAGMA user_version` holds ONE
/// value for the WHOLE SQLite file, so it cannot carry an independent version per
/// store module: in a shared file (an IOU store opened alongside the receipt
/// store) one module bumping `user_version` would look like a future schema to
/// another module with a lower constant and wrongly refuse the same valid Chio
/// database. Each module instead owns a row keyed by its stable module name, so a
/// bump in one module never trips the version check of another.
const MODULE_VERSION_TABLE: &str = "chio_module_schema_version";

#[derive(Debug, thiserror::Error)]
pub enum SchemaVersionError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("database application_id {found:#x} is not a Chio store (expected {expected:#x})")]
    ForeignDatabase { found: i32, expected: i32 },
    #[error("module {module} schema version {found} is newer than this binary supports ({supported}); refusing to open")]
    FutureSchema { module: String, found: i32, supported: i32 },
}

/// Read and validate the schema stamp for ONE store module sharing this file.
/// `application_id` (database-wide) proves the whole file is a Chio store;
/// `module` selects this store's own row in the Chio-owned version table so
/// modules that share a file version independently. Returns this module's on-disk
/// version so the caller can run additive migrations up to `supported_version`.
/// A zero-`application_id` file is adopted and stamped ONLY when the on-disk
/// contents prove the database is ours: either it has no user tables (fresh) or
/// it carries one of this store's `legacy_tables` (a pre-stamping Chio store).
/// `legacy_tables` is the set of table names the store has shipped since before
/// stamping existed (for the receipt store, e.g. `["chio_tool_receipts"]`).
pub fn check_schema_version(
    conn: &Connection,
    module: &str,
    supported_version: i32,
    legacy_tables: &[&str],
) -> Result<i32, SchemaVersionError> {
    let app_id: i32 = conn.query_row("PRAGMA application_id", [], |row| row.get(0))?;

    if app_id == 0 {
        // A zero application_id is ambiguous: it is shared by a fresh DB, a legacy
        // pre-stamping Chio DB, AND countless unrelated SQLite files. Adopt and
        // stamp the database-wide marker ONLY when the contents prove provenance;
        // otherwise fail closed rather than commingling Chio tables into a foreign
        // file. `user_version` is NOT part of this check: it is database-wide, so
        // it cannot certify a single module's provenance.
        if !zero_stamp_is_adoptable(conn, legacy_tables)? {
            return Err(SchemaVersionError::ForeignDatabase {
                found: app_id,
                expected: CHIO_SQLITE_APPLICATION_ID,
            });
        }
        conn.execute_batch(&format!("PRAGMA application_id = {CHIO_SQLITE_APPLICATION_ID};"))?;
        // Database-wide marker set; this module still owns no version row yet.
        return Ok(read_module_version(conn, module)?.unwrap_or(0));
    }
    if app_id != CHIO_SQLITE_APPLICATION_ID {
        return Err(SchemaVersionError::ForeignDatabase { found: app_id, expected: CHIO_SQLITE_APPLICATION_ID });
    }
    // Per-module version. An absent row means this module has never been stamped
    // in this file (e.g. a second store module opening a file the first store
    // created), which is version 0, NOT a foreign or a future schema. Only THIS
    // module's row can trip its own future-schema check.
    let found = read_module_version(conn, module)?.unwrap_or(0);
    if found > supported_version {
        return Err(SchemaVersionError::FutureSchema {
            module: module.to_string(),
            found,
            supported: supported_version,
        });
    }
    Ok(found)
}

/// Read this module's schema version, or `None` if it has no row yet. The version
/// table is created lazily so a fresh or legacy file needs no prior migration.
fn read_module_version(conn: &Connection, module: &str) -> Result<Option<i32>, SchemaVersionError> {
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {MODULE_VERSION_TABLE} \
         (module TEXT PRIMARY KEY, version INTEGER NOT NULL);"
    ))?;
    let version = conn
        .query_row(
            &format!("SELECT version FROM {MODULE_VERSION_TABLE} WHERE module = ?1"),
            [module],
            |row| row.get::<_, i32>(0),
        )
        .optional()?; // rusqlite::OptionalExtension
    Ok(version)
}

/// A zero-stamped database is adoptable only if it is empty (no user tables, so a
/// freshly created file) or carries a known legacy Chio table (so a pre-stamping
/// Chio store). This keeps an unrelated 0/0 SQLite file from being stamped and
/// written into, without falsely rejecting a legacy Chio store on upgrade.
fn zero_stamp_is_adoptable(conn: &Connection, legacy_tables: &[&str]) -> Result<bool, SchemaVersionError> {
    let user_table_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if user_table_count == 0 {
        return Ok(true); // empty file: a fresh Chio store
    }
    for table in legacy_tables {
        let present: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            [table],
            |row| row.get(0),
        )?;
        if present {
            return Ok(true); // a known legacy table proves this is our store
        }
    }
    Ok(false) // tables present but none recognizable: a foreign database
}

/// Stamp THIS module's schema revision after its migrations have run. Writes the
/// module's own row in the Chio-owned version table, leaving other modules that
/// share the file untouched (unlike `PRAGMA user_version`, which is database-wide
/// and would overwrite every module's version at once). `module`/`version` are
/// compile-time constants, not caller input, and the table name is a constant, so
/// the format string is not an injection surface.
pub fn stamp_schema_version(conn: &Connection, module: &str, version: i32) -> Result<(), SchemaVersionError> {
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {MODULE_VERSION_TABLE} \
         (module TEXT PRIMARY KEY, version INTEGER NOT NULL);"
    ))?;
    conn.execute(
        &format!(
            "INSERT INTO {MODULE_VERSION_TABLE} (module, version) VALUES (?1, ?2) \
             ON CONFLICT(module) DO UPDATE SET version = excluded.version"
        ),
        rusqlite::params![module, version],
    )?;
    Ok(())
}
```

Integration order in each store's `open` (receipt, authority, budget,
revocation, approval, execution-nonce): (1) configure durability pragmas; (2)
`check_schema_version(conn, THIS_MODULE_NAME, THIS_STORE_SUPPORTED_VERSION, LEGACY_ANCHOR_TABLES)`
and propagate its error (a module whose own version row is ahead of this binary is
refused before any write, and a zero-`application_id` file that is neither empty nor
a recognizable legacy Chio store is refused as `ForeignDatabase` before it is
stamped); (3) run the existing `CREATE TABLE IF NOT EXISTS` bootstrap and additive
`ALTER TABLE` migrations up to the supported version; (4)
`stamp_schema_version(conn, THIS_MODULE_NAME, THIS_STORE_SUPPORTED_VERSION)`.
Each store owns a `const MODULE_NAME: &str` (its stable key in the shared
`chio_module_schema_version` table), a `const SUPPORTED_SCHEMA_VERSION: i32`, bumped
on every schema-affecting change, and a `const LEGACY_ANCHOR_TABLES: &[&str]` naming
the tables it shipped before stamping existed (empty only for a store with no
pre-stamping deployments, which then adopts a zero-`application_id` file only when it
is empty). Because the version lives in a per-module row rather than the single
database-wide `PRAGMA user_version`, stores that share one SQLite file (an IOU store
opened alongside the receipt store) each carry and check their OWN schema version, so
one module bumping its version never makes another module reject the same valid Chio
database. The six stores above are the ones wired through the
kernel and CLI dispatch paths; the remaining `chio-store-sqlite` store modules
(batch approval, IOU, dead letters, memory provenance, capability lineage,
encrypted blob, evidence export) open their connections the same way and adopt
the same two calls in the same change, so the acceptance criterion covers
every store module in the crate. The existing additive `ALTER TABLE`
migrations remain the forward path; this RFC only adds the stamp and the
future-version refusal.
Because each store adds `check_schema_version` where it already asserts
durability pragmas (the receipt store at
`bootstrap/open.rs:16`), the change is localized.

Error taxonomy. All new errors are typed and fail-closed:
`SchemaVersionError` (above), `HttpAuthorityError::Kernel(String)` (existing,
reused for store-attach failures), `KernelError::Internal(String)` (existing,
reused by `ensure_revocation_durability_ready`), and the CLI gate returns
`CliError::cli_other_error(...)`. No path returns a permissive default.

### Crates/dirs, rough LOC, CI tier

- `chio-store-sqlite`: new `schema_version.rs` (~90 LOC) plus an open-path
  call site in each store module (~10 LOC each, six primary stores plus the
  auxiliary modules listed in part E). PR gate.
- `chio-kernel`: `KernelConfig` field, `RevocationStore::is_ephemeral`,
  `ensure_revocation_durability_ready`, two call sites, health fields (~70 LOC).
  PR gate.
- `chio-http-core`: `HttpAuthorityBuilder` and `new`/`new_ephemeral` split
  (~120 LOC). PR gate.
- `chio-tower`: `ChioEvaluatorBuilder`, `ChioLayer` builder methods (~110 LOC).
  PR gate.
- `chio-api-protect` + `chio-cli`: durable-store wiring, `--allow-ephemeral-receipts`
  flag, gate, dispatch threading (~90 LOC). PR gate.
- `deploy/*` and `docs/*`: manifest and doc edits (no Rust). PR gate (lint only).
- Restart-durability soak/chaos: nightly (see Test plan).

## Wire, schema, and receipt impact

No change to signed payloads, receipt kinds, or canonical-JSON (RFC 8785)
preimages. Receipts are signed and hashed exactly as today; this RFC changes
where they are stored and whether the process boots, not their bytes.

New non-wire surface:

- SQLite metadata: `PRAGMA application_id` (constant `0x4348494f`, database-wide)
  and a Chio-owned `chio_module_schema_version(module, version)` table holding one
  row per store module (each at its `SUPPORTED_SCHEMA_VERSION`, starting at 0). The
  single database-wide `PRAGMA user_version` is deliberately NOT used as the schema
  revision, so modules that share a file version independently. These are
  database-file metadata, not protocol wire.
- New `KernelConfig`/policy field `allow_ephemeral_revocation_store` (bool,
  default false). Policy files are YAML, not signed wire; the field is additive
  and defaults fail-closed.
- New CLI flag `--allow-ephemeral-receipts` on `api protect` and `start`.
- Manifest edits (volumes, `--receipt-store`, `--authority-seed-file`, Azure
  `--spec`). Doc edits in `CLOUD-SIDECAR-INTEGRATION.md` and `deploy/README.md`.

## Migration and compatibility

Source compatibility is preserved on the public constructors:
`HttpAuthority::new`, `ChioEvaluator::new`, and `ChioLayer::new` keep their
signatures; only their runtime default flips from silently-ephemeral to
fail-closed. `HttpAuthority::new_ephemeral` and the builders are additive. The
one deliberate source-level break is the new `KernelConfig` field:
`KernelConfig` has no `Default` impl and is constructed literally at every
site (`authority.rs:268`, `wrap.rs:314`, and the protocol-crate test
harnesses), so each literal construction must add
`allow_ephemeral_revocation_store`. In-tree sites are updated mechanically in
the same change; an out-of-tree embedder gets a compile error naming the
fail-closed field rather than a silent behavior change, which is the intended
failure mode.

Behavior change is staged:

1. Land the builders and `new_ephemeral` (source-compatible, no default flip);
   migrate the authority and conformance tests (today's `HttpAuthority::new`
   callers that intend ephemerality) to `new_ephemeral`. `mcp wrap` is
   unaffected here: it builds its `KernelConfig` directly and keeps its
   explicit opt-ins (part A).
2. Land the schema-version runner (F62): independent, low risk. A fresh or
   legacy unstamped DB is adopted at v0 and stamped; a future-version DB is
   refused. Old binaries (pre-runner) ignore both `application_id` and the
   `chio_module_schema_version` table and still open, so the runbook must document
   that rollback across a schema bump is unsafe and requires the state restore
   (making runbook section 7 step 3 unconditional for schema-affecting releases).
3. Wire durable stores into `api-protect` and add the CLI gate.
4. Fix manifests and docs.
5. Flip `HttpAuthority::new`/`ChioEvaluator::new`/`ChioLayer::new` to
   fail-closed in a follow-up minor, once every production entrypoint is on a
   durable store. Embedders that intentionally want ephemeral move to
   `new_ephemeral`/`allow_ephemeral(true)`.

No feature flag is needed beyond the CLI `--allow-ephemeral-receipts` and the
policy `allow_ephemeral_receipt_log`/`allow_ephemeral_revocation_store` booleans.
No receipt data migration is required; existing receipt DBs open at v0.

## Test and verification plan

Unit (PR gate, seconds):

- `HttpAuthorityBuilder::build` attaches the receipt store to the embedded
  kernel: assert a mediated allow after restart-from-same-store is retrievable;
  assert `build` with no store and `allow_ephemeral_receipt_log(false)` denies
  the first mediated call with "durable receipt persistence unavailable".
- `ensure_revocation_durability_ready`: in-memory store with the flag unset
  denies; with a `SqliteRevocationStore` (`is_ephemeral() == false`) allows;
  with the flag set allows.
- `check_schema_version`: fresh DB adopts v0 and stamps `application_id`;
  foreign `application_id` yields `ForeignDatabase`; a DB stamped at
  `supported + 1` yields `FutureSchema`; a legacy unstamped DB adopts v0.

CLI (PR gate): `chio api protect` and `chio start` with no `--receipt-store`
and no `--allow-ephemeral-receipts` exit non-zero with the gate message; with
`--allow-ephemeral-receipts` they boot ephemeral; with `--receipt-store` they
boot durable. Name: `api_protect_refuses_ephemeral_without_optin`.

Property (PR gate): schema-version monotonicity - for any
`v_disk <= v_bin`, open then reopen leaves this module's row in
`chio_module_schema_version` at `v_bin` and never downgrades, and does not disturb
any other module's row in the same file; for any `v_disk > v_bin`, open refuses and
does not mutate the file.

Soak / chaos (nightly, ties to the wave-3 load-chaos program in ./README.md):
`durable_receipts_survive_kill` - issue N mediated allows against a
`--receipt-store` sidecar, `SIGKILL` mid-stream, restart, assert all
acknowledged receipts are present and Merkle-consistent (this is the
ADR-0013 bounded-loss invariant). `revocations_survive_restart` - revoke a
capability, restart the kernel, assert the capability is still denied. Honest
runtime: ~8-12 minutes per scenario under the nightly harness.

Manifest smoke (nightly): apply each reference manifest against a local
emulator (Cloud Run emulator / LocalStack / Azure `containerapp` stub),
restart the sidecar container, and assert receipts persist across the restart;
assert Azure now derives routes from `--spec`, not the upstream.

The formal-methods plan is not on the critical path for this RFC; the
durability invariant it should eventually model is "an acknowledged mediated
allow is recoverable after crash", already stated informally in ADR-0013.

## Acceptance criteria

- `chio api protect` and `chio start` refuse to boot (non-zero exit, named
  error) when neither `--receipt-store` nor `--allow-ephemeral-receipts` is
  given.
- With `--receipt-store`, the sidecar's embedded kernel holds a durable
  `chio_store_sqlite` receipt store and a durable revocation store; receipts and
  revocations survive `SIGKILL` + restart (soak tests green).
- `HttpAuthority`, `ChioEvaluator`, and `ChioLayer` expose builder methods that
  attach a `ReceiptStore` and `RevocationStore`; their `new` constructors are
  fail-closed by default (deny when persistence is absent and ephemeral is not
  opted in).
- `ensure_revocation_durability_ready` denies on an empty in-memory revocation
  store unless `allow_ephemeral_revocation_store` is set; kernel health reports
  `receipt_backend` and `revocation_backend`.
- Every operator SQLite store stamps the database-wide `application_id` and its own
  per-module row in `chio_module_schema_version`, and refuses to open a database
  whose module version is ahead of the binary.
- All three manifests pass `--receipt-store` (durable volume) and
  `--authority-seed-file`; Azure additionally passes `--spec` and mounts config.
- `CLOUD-SIDECAR-INTEGRATION.md` sections 6.3, 7, 9 and `deploy/README.md` no
  longer document any env var or module that no code reads; a grep for
  `CHIO_RECEIPT_SINK`, `CHIO_POLICY_SOURCE`, `CHIO_HEALTH_PATH` in docs returns
  zero undisclaimed present-tense assertions.

## Risks and alternatives

Risk: flipping `new` to fail-closed denies at runtime for any embedder that
relied on the silent ephemeral default. Mitigation: the staged rollout lands the
builders and `new_ephemeral` first, the deny message names the exact missing
flag, and the flip is a separate minor. This is the correct fail-closed trade:
an audit-centric protocol should refuse to run without a place to write audit
evidence rather than run and lose it.

Risk: two audit logs on the sidecar (the private mutable `SqliteReceiptStore`
read model versus the kernel's append-only Merkle store) could diverge.
Mitigation: make the Merkle store the system of record and demote the private
store to a read cache for the inspection endpoints; a follow-up may remove it
entirely.

Risk: durable writes on the hot path (WAL `synchronous = FULL`) add fsync
latency versus in-memory. This is the ADR-0013 durable-before-allow contract and
is accepted; the async-WAL fast path in ADR-0013 remains available for
latency-sensitive surfaces and is out of scope here.

Rejected alternative: a startup warning instead of a hard refusal. Rejected
because F60/F65 show warnings are invisible in practice (probes stay green,
discovery happens during an incident). Fail-closed refusal is the only posture
that surfaces the misconfiguration before traffic flows.

Rejected alternative: infer durability from the presence of `--receipt-store`
alone without the kernel gate. Rejected because the tower middleware path has no
CLI, so the gate must live in the kernel/authority layer to cover every
embedder.

Rejected alternative: a full migration framework (versioned up/down scripts).
Rejected as over-scoped for F62; the additive `ALTER TABLE` pattern already in
the stores plus a per-module `chio_module_schema_version` stamp and a
future-version refusal closes the concrete blast radius (undetected rollback and
future non-additive change).

## Rollout and sequencing

This RFC has no RFC dependencies. Internal sequencing follows the staged
migration above: (E) schema-version runner and (A) kernel revocation gate are
independent and land first; (B) the `HttpAuthority` builder and (C) the
`ChioEvaluator`/`ChioLayer` builders land next as source-compatible additions;
(D) api-protect wiring, the CLI gate, manifest fixes, and doc reconciliation
land once the builders exist; the fail-closed default flip on the three `new`
constructors is the final step, gated on every production entrypoint being on a
durable store. Within the wave-3 reliability program, the restart-durability and
revocation-persistence soak scenarios join the load-chaos suite described in
./README.md.
