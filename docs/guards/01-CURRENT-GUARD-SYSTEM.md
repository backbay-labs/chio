# Chio Guard System -- Technical Reference

This document describes the guard system as implemented in the Chio protocol
codebase. All type signatures, field names, and behaviors are drawn from the
source code.

---

## 1. The `Guard` Trait

Defined in `crates/kernel/chio-kernel/src/kernel/mod.rs` and re-exported from
`chio_kernel`:

```rust
pub trait Guard: Send + Sync {
    /// Human-readable guard name (e.g., "forbidden-path").
    fn name(&self) -> &str;

    /// Evaluate the guard against a tool call request.
    ///
    /// Returns `Ok(Verdict::Allow)` to pass, `Ok(Verdict::Deny)` to block,
    /// or `Err` on internal failure (which the kernel treats as deny).
    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError>;
}
```

The trait requires `Send + Sync` because guards are stored in
`Vec<Box<dyn Guard>>` on the `ChioKernel` struct and may be invoked from
different contexts.

### 1.1 `Verdict` (Kernel)

The kernel's own `Verdict` is a simple two-variant enum defined in
`crates/kernel/chio-kernel/src/runtime.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The action is allowed.
    Allow,
    /// The action is denied.
    Deny,
}
```

There is **no `Abstain` variant**. Every guard must return either Allow or
Deny (or an `Err`, which is treated as Deny). This is a deliberate
fail-closed design: guards cannot "pass" on a decision.

### 1.2 `Verdict` (HTTP Layer)

A separate, richer `Verdict` exists in `crates/platform/chio-http-core/src/verdict.rs`
for the HTTP substrate:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Deny { reason: String, guard: String, http_status: u16 },
    Cancel { reason: String },
    Incomplete { reason: String },
}
```

The HTTP verdict includes denial reasons, the guard name, and HTTP status
codes (defaulting to 403). It converts to/from `chio_core_types::Decision`
for receipt signing.

The kernel-level `Verdict` (Allow/Deny) is what guards return. The richer
HTTP `Verdict` is used at the transport layer.

---

## 2. `GuardContext`

The context struct passed to every guard during evaluation, defined in
`crates/kernel/chio-kernel/src/kernel/mod.rs`:

```rust
pub struct GuardContext<'a> {
    /// The tool call request being evaluated.
    pub request: &'a ToolCallRequest,
    /// The verified capability scope.
    pub scope: &'a ChioScope,
    /// The agent making the request.
    pub agent_id: &'a AgentId,
    /// The target server.
    pub server_id: &'a ServerId,
    /// Session-scoped enforceable filesystem roots, when the request is being
    /// evaluated through the supported session-backed runtime path.
    pub session_filesystem_roots: Option<&'a [String]>,
    /// Index of the matched grant in the capability's scope, populated by
    /// check_and_increment_budget before guards run.
    pub matched_grant_index: Option<usize>,
}
```

### 2.1 Fields in Detail

**`request: &'a ToolCallRequest`** -- The full tool call request:

```rust
pub struct ToolCallRequest {
    pub request_id: String,
    pub capability: CapabilityToken,
    pub tool_name: String,
    pub server_id: ServerId,
    pub agent_id: AgentId,
    pub arguments: serde_json::Value,
    pub dpop_proof: Option<dpop::DpopProof>,
    pub governed_intent: Option<GovernedTransactionIntent>,
    pub approval_token: Option<GovernedApprovalToken>,
}
```

Guards have access to the tool name, server ID, agent ID, arguments (as
`serde_json::Value`), and the full capability token (including its scope,
delegation chain, issuer, and time bounds).

**`scope: &'a ChioScope`** -- The verified capability scope:

```rust
pub struct ChioScope {
    pub grants: Vec<ToolGrant>,
    pub resource_grants: Vec<ResourceGrant>,
    pub prompt_grants: Vec<PromptGrant>,
}
```

**`agent_id: &'a AgentId`** -- The hex-encoded public key of the calling
agent. Type alias: `pub type AgentId = String`.

**`server_id: &'a ServerId`** -- The target server identifier. Type alias:
`pub type ServerId = String`.

**`session_filesystem_roots: Option<&'a [String]>`** -- When the request is
evaluated through a session-backed path, this contains the enforceable
filesystem root paths for that session. Used by `PathAllowlistGuard` to
restrict file operations to within declared roots.

**`matched_grant_index: Option<usize>`** -- The index of the matched grant
within the capability's scope. This is populated by
`check_and_increment_budget` before guards run, allowing guards like
`VelocityGuard` to key their rate-limiting buckets on the specific grant.

---

## 3. How Guards Are Registered

### 3.1 Storage

Guards are stored as a `Vec<Box<dyn Guard>>` on `ChioKernel`:

```rust
pub struct ChioKernel {
    // ...
    guards: Vec<Box<dyn Guard>>,
    // ...
}
```

The vector is initialized empty during kernel construction:

```rust
guards: Vec::new(),
```

### 3.2 `add_guard`

```rust
/// Register a policy guard. Guards are evaluated in registration order.
/// If any guard denies, the request is denied.
pub fn add_guard(&mut self, guard: Box<dyn Guard>) {
    self.guards.push(guard);
}
```

Guards are appended to the end of the vector. **Registration order
determines evaluation order.** There is no priority field, sorting, or
reordering mechanism on `ChioKernel` itself.

> **Note:** `WasmGuardRuntime` has a `priority` field on `WasmGuardConfig`
> and its struct doc-comment claims guards are "sorted by priority," but the
> code does **not** sort -- `add_guard` and `into_guards` preserve insertion
> order. The priority field is parsed from config but unused at runtime.
> Any startup code that depends on priority ordering must sort externally
> before calling `kernel.add_guard`.

### 3.3 Composition via `GuardPipeline`

The `chio-guards` crate provides `GuardPipeline`, which itself implements
`Guard`:

```rust
pub struct GuardPipeline {
    guards: Vec<Box<dyn Guard>>,
}

impl Guard for GuardPipeline {
    fn name(&self) -> &str { "guard-pipeline" }

    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        for guard in &self.guards {
            match guard.evaluate(ctx) {
                Ok(Verdict::Allow) => continue,
                Ok(Verdict::Deny) => {
                    return Err(KernelError::GuardDenied(format!(
                        "guard \"{}\" denied the request", guard.name()
                    )));
                }
                Err(e) => {
                    return Err(KernelError::GuardDenied(format!(
                        "guard \"{}\" error (fail-closed): {e}", guard.name()
                    )));
                }
            }
        }
        Ok(Verdict::Allow)
    }
}
```

A `GuardPipeline` can be registered as a single guard on the kernel:

```rust
let pipeline = GuardPipeline::default_pipeline();
kernel.add_guard(Box::new(pipeline));
```

The `default_pipeline()` includes:
1. `ForbiddenPathGuard`
2. `ShellCommandGuard`
3. `EgressAllowlistGuard`
4. `PathAllowlistGuard`
5. `McpToolGuard`
6. `SecretLeakGuard`
7. `PatchIntegrityGuard`

---

## 4. Guard Evaluation Pipeline

### 4.1 When Guards Run

Guard evaluation occurs during `evaluate_tool_call_sync_with_session_roots`
(and the parallel `evaluate_tool_call_with_nested_flow_client`). Guards
run **after** all capability validation and **before** tool dispatch.

The full evaluation sequence in `evaluate_tool_call_sync_with_session_roots`:

1. Verify capability signature
2. Check time bounds (not before / expiry)
3. Check revocation status
4. Check subject binding (agent identity matches capability subject)
5. Resolve matching grants (scope check)
6. DPoP verification (if required by any matching grant)
7. Ensure tool target is registered
8. Record capability lineage snapshot
9. Check and increment budget
10. Validate governed transaction (if applicable)
11. **Run guards** <-- guards evaluate here
12. Authorize payment (if applicable)
13. Dispatch tool call to tool server

### 4.2 The `run_guards` Method

```rust
fn run_guards(
    &self,
    request: &ToolCallRequest,
    scope: &ChioScope,
    session_filesystem_roots: Option<&[String]>,
    matched_grant_index: Option<usize>,
) -> Result<(), KernelError> {
    let ctx = GuardContext {
        request,
        scope,
        agent_id: &request.agent_id,
        server_id: &request.server_id,
        session_filesystem_roots,
        matched_grant_index,
    };

    for guard in &self.guards {
        match guard.evaluate(&ctx) {
            Ok(Verdict::Allow) => {
                debug!(guard = guard.name(), "guard passed");
            }
            Ok(Verdict::Deny) => {
                return Err(KernelError::GuardDenied(format!(
                    "guard \"{}\" denied the request",
                    guard.name()
                )));
            }
            Err(e) => {
                // Fail closed: guard errors are treated as denials.
                return Err(KernelError::GuardDenied(format!(
                    "guard \"{}\" error (fail-closed): {e}",
                    guard.name()
                )));
            }
        }
    }

    Ok(())
}
```

### 4.3 Verdict Combination Logic

The combination logic is **strict conjunction (AND)**:

- **All guards must return `Allow`** for the request to proceed.
- **First Deny short-circuits** -- remaining guards are not evaluated.
- **First error short-circuits** -- treated identically to Deny.
- **Empty guard list** -- if no guards are registered, the request proceeds
  (vacuous truth).

There is no Abstain. There is no voting or quorum. There is no
"at least one Allow required" mode.

### 4.4 What Happens on Denial

When `run_guards` returns `Err(KernelError::GuardDenied(_))`:

1. If a monetary budget charge was made (the request had a monetary grant),
   the charge is **reversed** via `reverse_budget_charge`.
2. A denial response is built with:
   - `verdict: Verdict::Deny`
   - The denial reason string
   - A signed denial receipt
   - Financial metadata (for monetary denials)

### 4.5 Invocation from Session Path

In `evaluate_tool_call_with_nested_flow_client`, session filesystem roots
are retrieved from the session store before running guards:

```rust
let session_roots =
    self.session_enforceable_filesystem_root_paths_owned(&parent_context.session_id)?;

if let Err(e) = self.run_guards(
    request, &cap.scope,
    Some(session_roots.as_slice()),
    Some(matched_grant_index),
) { ... }
```

---

## 5. Guard Error Handling

### 5.1 Fail-Closed Semantics

The kernel's error handling follows a strict fail-closed policy:

| Guard returns | Kernel behavior |
|---|---|
| `Ok(Verdict::Allow)` | Continue to next guard |
| `Ok(Verdict::Deny)` | Short-circuit with `KernelError::GuardDenied(...)` |
| `Err(e)` | Short-circuit with `KernelError::GuardDenied("... error (fail-closed): {e}")` |

Both `Verdict::Deny` and `Err` produce a `KernelError::GuardDenied`. The
distinction is in the error message: errors include "(fail-closed)" and the
original error text.

### 5.2 `KernelError::GuardDenied`

```rust
#[error("guard denied the request: {0}")]
GuardDenied(String),
```

This variant carries the formatted reason string. It is mapped to:
- Error code `Chio-KERNEL-GUARD-DENIED` in structured error reports
- A denial response with `Verdict::Deny` in the tool call response
- A signed denial receipt in the receipt log

### 5.3 Guards That Use Mutexes

Several guards (VelocityGuard, AgentVelocityGuard, WasmGuard) use
`std::sync::Mutex` for interior mutability. If a mutex is poisoned, they
return `Err(KernelError::Internal(...))`, which the kernel treats as a
denial via the fail-closed rule.

---

## 6. Existing Guard Implementations

### 6.1 Core Guards (`chio-guards` crate)

#### `ForbiddenPathGuard` ("forbidden-path")

**File:** `crates/guards/chio-guards/src/forbidden_path.rs`

Blocks access to sensitive filesystem paths using glob patterns. Default
forbidden patterns include `.ssh/`, `.aws/`, `.env`, `.gnupg/`,
`/etc/shadow`, `/etc/passwd`, Windows credential stores, etc.

- Extracts `ToolAction` from request, checks `FileAccess`, `FileWrite`,
  and `Patch` actions.
- Normalizes paths three ways (lexical, resolved with filesystem, lexical
  absolute) to defeat symlink bypasses.
- Supports exception patterns that override forbidden patterns.
- Non-filesystem actions return `Verdict::Allow` immediately.

#### `ShellCommandGuard` ("shell-command")

**File:** `crates/guards/chio-guards/src/shell_command.rs`

Blocks dangerous shell commands using regex patterns. Default patterns
catch `rm -rf /`, `curl | bash`, reverse shells, base64 exfiltration.

- Only inspects `ToolAction::ShellCommand` actions.
- Performs best-effort shlex splitting to extract path candidates from
  command lines.
- Delegates to `ForbiddenPathGuard` for path-based checks within commands.
- Handles redirection operators (`>`, `>>`) and flag-embedded paths
  (`--output=/path`).

#### `EgressAllowlistGuard` ("egress-allowlist")

**File:** `crates/guards/chio-guards/src/egress_allowlist.rs`

Controls network egress by domain allowlist. Default allows common AI APIs
and package registries. All other egress is denied (fail-closed).

- Only inspects `ToolAction::NetworkEgress` actions.
- Block list takes precedence over allow list.
- Case-insensitive domain matching.

#### `PathAllowlistGuard` ("path-allowlist")

**File:** `crates/guards/chio-guards/src/path_allowlist.rs`

Allowlist-based path access control. **Disabled by default** (must be
explicitly configured). Supports separate allowlists for file access, file
write, and patch operations.

- When `session_filesystem_roots` is present in the `GuardContext`, denies
  any filesystem operation outside those roots. This check applies even
  when the allowlist itself is disabled.
- Empty session roots = deny all filesystem operations (fail-closed).
- Patch allowlist falls back to file write allowlist when empty.
- Resolves symlinks to prevent lexical-path allowlist bypasses.

#### `McpToolGuard` ("mcp-tool")

**File:** `crates/guards/chio-guards/src/mcp_tool.rs`

Restricts which MCP tools an agent may invoke. Supports allow/block lists,
default action, and argument size limits.

- Default blocked tools: `shell_exec`, `run_command`, `raw_file_write`,
  `raw_file_delete`.
- Default max argument size: 1 MB.
- Block list takes precedence over allow list.
- Can be disabled entirely.

#### `SecretLeakGuard` ("secret-leak")

**File:** `crates/guards/chio-guards/src/secret_leak.rs`

Detects secrets in file write content using regex patterns. Catches AWS
keys, GitHub tokens, OpenAI keys, Anthropic keys, private keys, NPM
tokens, Slack tokens, Stripe keys, GCP service accounts, GitLab PATs,
and generic API key/secret patterns.

- Only inspects `FileWrite` and `Patch` actions.
- Skips test paths by default (`**/test/**`, `**/tests/**`, etc.).
- Returns `Verdict::Deny` if any secret pattern matches.

#### `PatchIntegrityGuard` ("patch-integrity")

**File:** `crates/guards/chio-guards/src/patch_integrity.rs`

Validates patch/diff safety. Checks:
- Maximum additions (default 1000) and deletions (default 500).
- Forbidden patterns in added lines (security disablement, backdoors,
  eval/exec, reverse shells).
- Optional addition/deletion imbalance ratio checking.

#### `InternalNetworkGuard` ("internal-network")

**File:** `crates/guards/chio-guards/src/internal_network.rs`

SSRF prevention guard. Blocks network egress to:
- RFC 1918 private ranges, loopback, link-local, broadcast, 0.0.0.0/8.
- IPv6 loopback (::1), link-local (fe80::/10), unique local (fc00::/7).
- IPv4-mapped IPv6 addresses.
- Cloud metadata endpoints (169.254.169.254, metadata.google.internal,
  metadata.azure.com, kubernetes.default.svc).
- DNS rebinding suspect patterns.
- Hex/octal/decimal encoded IP addresses.

#### `VelocityGuard` ("velocity")

**File:** `crates/guards/chio-guards/src/velocity.rs`

Per-grant rate limiting using token buckets keyed by
`(capability_id, grant_index)`. Supports invocation rate limits and
spend rate limits. Uses integer milli-token arithmetic to avoid
floating-point drift.

- Uses `matched_grant_index` from `GuardContext`.
- Configurable window duration and burst factor.

#### `AgentVelocityGuard` ("agent-velocity")

**File:** `crates/guards/chio-guards/src/agent_velocity.rs`

Cross-capability rate limiting keyed by agent identity and session.

- Per-agent buckets keyed by `agent_id`.
- Per-session buckets keyed by `(agent_id, capability_id)`.
- Same token-bucket algorithm as `VelocityGuard`.

#### `DataFlowGuard` ("data-flow")

**File:** `crates/guards/chio-guards/src/data_flow.rs`

Enforces cumulative bytes-read/written limits via session journal.
Requires an `Chio<SessionJournal>`.

- Configurable max bytes read, written, and total.
- Fails closed if journal is unavailable.

#### `BehavioralSequenceGuard` ("behavioral-sequence")

**File:** `crates/guards/chio-guards/src/behavioral_sequence.rs`

Enforces tool ordering policies via session journal:
- Required predecessors (tool X requires tool Y to have run first).
- Forbidden transitions (tool X cannot follow tool Y).
- Max consecutive invocations of the same tool.
- Required first tool in session.

Fails closed if journal is unavailable.

#### `ResponseSanitizationGuard` ("response-sanitization")

**File:** `crates/guards/chio-guards/src/response_sanitization.rs`

PII/PHI pattern detection with configurable sensitivity levels. Scans for
SSNs, emails, phone numbers, credit cards, dates of birth, medical record
numbers, ICD-10 codes.

- Three sensitivity levels: Low, Medium, High.
- Two actions: Block or Redact.
- When used as a pre-invocation guard (via `Guard` trait), scans the
  request arguments.

### 6.2 Advisory Guards (`chio-guards::advisory`)

**File:** `crates/guards/chio-guards/src/advisory.rs`

Non-blocking guards that emit observations without denying requests.

#### `AdvisoryGuard` Trait

```rust
pub trait AdvisoryGuard: Send + Sync {
    fn name(&self) -> &str;
    fn evaluate(&self, ctx: &GuardContext) -> Result<Vec<AdvisorySignal>, KernelError>;
}
```

#### `AdvisoryPipeline` ("advisory-pipeline")

Wraps multiple `AdvisoryGuard` implementations and a `PromotionPolicy`.
Implements `Guard` so it can be registered on the kernel.

- Without promotion rules, always returns `Verdict::Allow`.
- With promotion rules, signals matching a `PromotionRule` (by guard name
  and minimum severity) are promoted to deterministic denials.

```rust
pub struct PromotionRule {
    pub guard_name: String,
    pub min_severity: AdvisorySeverity,
}
```

Severity levels: Info, Low, Medium, High, Critical.

#### `AnomalyAdvisoryGuard` ("anomaly-advisory")

Flags unusual invocation patterns. Emits advisory signals when:
- A tool is invoked more than a configurable threshold number of times.
- Delegation depth exceeds a threshold.

#### `DataTransferAdvisoryGuard` ("data-transfer-advisory")

Flags high cumulative data transfer volumes. Escalates severity based on
multiples of the threshold (1x = Medium, 2x = High, 3x = Critical).

### 6.3 WASM Guards (`chio-wasm-guards` crate)

**File:** `crates/guards/chio-wasm-guards/src/runtime.rs`

#### `WasmGuard`

Loads guard logic from WASM modules. Implements `Guard` by serializing the
`GuardContext` into a `GuardRequest`, passing it to the WASM ABI, and
mapping the result:

- `GuardVerdict::Allow` -> `Verdict::Allow`
- `GuardVerdict::Deny` -> `Verdict::Deny` (or `Allow` if advisory-only)
- Error -> `Verdict::Deny` (or `Allow` if advisory-only)

Advisory WASM guards log denials but always return `Verdict::Allow`.

#### `WasmGuardRuntime`

Manages a collection of loaded WASM guard modules. Guards are evaluated in
insertion order. (The struct doc-comment claims priority sorting, but the
code does not sort -- see Section 3.2 note above.)

### 6.4 `GuardPipeline` ("guard-pipeline")

**File:** `crates/guards/chio-guards/src/pipeline.rs`

Composition wrapper that itself implements `Guard`. Runs child guards in
sequence with fail-closed semantics. See Section 3.3 above.

### 6.5 Post-Invocation Hooks

**File:** `crates/guards/chio-guards/src/post_invocation.rs`

A separate pipeline for inspecting tool **responses** after invocation:

```rust
pub trait PostInvocationHook: Send + Sync {
    fn name(&self) -> &str;
    fn inspect(&self, tool_name: &str, response: &Value) -> PostInvocationVerdict;
}

pub enum PostInvocationVerdict {
    Allow,
    Block(String),
    Redact(Value),
    Escalate(String),
}
```

This is not a `Guard` implementation. It runs post-dispatch, not
pre-dispatch.

### 6.6 Test Guards (in kernel tests)

**File:** `crates/kernel/chio-kernel/src/kernel/tests/all.rs`

Several test-only guard implementations:

| Name | Behavior |
|---|---|
| `DenyAll` | Always returns `Ok(Verdict::Deny)` |
| `BrokenGuard` | Always returns `Err(KernelError::Internal(...))` |
| `TestGuard` | Configurable (used in various test scenarios) |
| `DenyOnceGuard` | Denies first invocation, allows subsequent |
| `IndexCapturingGuard` | Captures `matched_grant_index` from context |
| `CountingRateLimitGuard` | Counts invocations, denies after threshold |

---

## 7. `ToolAction` Extraction

**File:** `crates/guards/chio-guards/src/action.rs`

Guards do not directly inspect raw tool names and arguments. Instead, they
use `extract_action()` to derive a `ToolAction` enum:

```rust
pub enum ToolAction {
    FileAccess(String),
    FileWrite(String, Vec<u8>),
    NetworkEgress(String, u16),
    ShellCommand(String),
    McpTool(String, Value),
    Patch(String, String),
    Unknown,
}
```

`extract_action(tool_name, arguments)` uses heuristic matching on tool
names to categorize actions. Unknown tools fall through to
`ToolAction::McpTool`. Guards that do not apply to a given action type
return `Verdict::Allow` immediately.

---

## 8. Summary of Design Principles

1. **Fail-closed everywhere.** Errors from guards, journal lookups, mutex
   locks, and WASM execution all result in denial.

2. **No Abstain.** Guards must decide Allow or Deny. There is no neutral
   option.

3. **First-deny-wins.** Evaluation short-circuits on the first denial.
   Remaining guards are not consulted.

4. **Registration order = evaluation order.** No priority mechanism at the
   kernel level.

5. **Separation of advisory and deterministic.** Advisory guards emit
   signals without blocking. They can be promoted to denials via operator
   configuration.

6. **Budget reversal on guard denial.** If a monetary budget was charged
   before guards ran (step 9 in the pipeline), a guard denial triggers
   charge reversal.

7. **Session roots as defense-in-depth.** Even when the path allowlist is
   disabled, session filesystem roots constrain file operations.
