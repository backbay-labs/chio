# Chio Guard Taxonomy and Security Model

**Version:** 1.0
**Date:** 2026-04-14
**Status:** Normative

This document defines the complete guard taxonomy for the Chio runtime kernel,
including guard categories, configuration, fail-closed behavior, advisory
signals, WASM custom guards, and the session journal contract. It complements
[SECURITY.md](SECURITY.md) (threat model) and [HTTP-SUBSTRATE.md](HTTP-SUBSTRATE.md)
(HTTP evaluation pipeline).

The keywords **MUST**, **SHOULD**, and **MAY** are normative in this document
(per RFC 2119).

---

## 1. Guard Pipeline Overview

The Chio runtime kernel evaluates guards in a sequential pipeline before
admitting any tool invocation. The pipeline operates under a universal
**fail-closed** invariant:

- If any guard returns `Deny`, the pipeline **MUST** short-circuit and deny
  the request.
- If any guard returns an error (including internal panics, lock poisoning,
  or serialization failures), the pipeline **MUST** treat the request as
  denied.
- Only when every guard in the pipeline returns `Allow` is the request
  admitted.

Guards produce `GuardEvidence` entries that are attached to the signed receipt
for the invocation, providing an auditable record of which guards evaluated
the request and what they observed.

### 1.1 Guard Categories

Chio guards are classified into five categories based on their state
requirements and execution phase:

| Category | State | Phase | Blocking |
| --- | --- | --- | --- |
| Stateless deterministic | None | Pre-invocation | Yes |
| Session-aware deterministic | Session journal | Pre-invocation | Yes |
| Post-invocation hooks | Tool response | Post-invocation | Yes |
| Advisory signals | Session journal (optional) | Pre-invocation | No (unless promoted) |
| WASM custom guards | Sandboxed runtime | Pre-invocation | Configurable |

### 1.2 Evaluation Order

Guards **SHOULD** be evaluated in the following order within the pipeline:

1. Stateless deterministic guards (cheapest, no I/O)
2. Session-aware deterministic guards (require journal read)
3. WASM custom guards (sandboxed execution, potentially expensive)
4. Advisory pipeline (non-blocking signals, evaluated last for observability)

Post-invocation hooks run after the tool produces a response but before
delivery to the agent.

---

## 2. Stateless Deterministic Guards

Stateless deterministic guards inspect only the current request context
(tool name, arguments, agent identity, capability scope). They require no
external state, no session history, and no I/O. Their verdicts are
reproducible given the same inputs.

### 2.1 InternalNetworkGuard

**Purpose:** Prevents Server-Side Request Forgery (SSRF) by blocking network
egress to private, reserved, and cloud infrastructure addresses. This is
critical for the HTTP substrate where agents may attempt to reach internal
services through tool invocations.

**Guard name:** `internal-network`

**Blocked address classes:**

| Class | Range | Rationale |
| --- | --- | --- |
| RFC 1918 (Class A) | `10.0.0.0/8` | Private networks |
| RFC 1918 (Class B) | `172.16.0.0/12` | Private networks |
| RFC 1918 (Class C) | `192.168.0.0/16` | Private networks |
| Loopback (IPv4) | `127.0.0.0/8` | Host-local services |
| Loopback (IPv6) | `::1` | Host-local services |
| Link-local (IPv4) | `169.254.0.0/16` | Auto-configured addresses |
| Link-local (IPv6) | `fe80::/10` | Neighbor discovery scope |
| Unique local (IPv6) | `fc00::/7` | Private IPv6 ranges |
| Cloud metadata | `169.254.169.254`, `metadata.google.internal`, `metadata.azure.com` | Cloud instance credentials |
| Kubernetes | `kubernetes.default.svc`, `kubernetes.default` | Cluster-internal APIs |
| Broadcast | `255.255.255.255` | Network broadcast |
| Current network | `0.0.0.0/8` | Ambiguous origin |
| IPv4-mapped IPv6 | `::ffff:<private-v4>` | Bypass via address format |

**DNS rebinding detection:** When enabled (default), the guard blocks
hostnames that embed private IP patterns using dash or dot separators
(e.g., `evil.127-0-0-1.attacker.com`, `evil.192-168-1.attacker.com`).
This catches a common SSRF technique where an attacker-controlled DNS
server alternates between public and private addresses.

**Encoded IP detection:** The guard blocks hostnames that appear to be
obfuscated IP addresses in hexadecimal (`0x7f000001`), decimal
(`2130706433`), or octal (`0177.0.0.1`) notation.

**Configuration:**

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `extra_blocked_hosts` | `string[]` | `[]` | Additional hostnames to block beyond the built-in list |
| `dns_rebinding_detection` | `boolean` | `true` | Enable DNS rebinding heuristics |

**Fail-closed behavior:** Any IP parse error, ambiguous address, or
unexpected format **MUST** result in denial. Only addresses that are
unambiguously public are allowed.

**GuardEvidence output:** On denial, the evidence includes the blocked host
and the classification reason (e.g., "cloud metadata endpoint",
"private/reserved IP", "DNS rebinding suspect").

**Non-network actions:** Requests that do not involve network egress (file
reads, shell commands, etc.) **MUST** pass through this guard without
evaluation. The guard only activates for `NetworkEgress` actions.

### 2.2 AgentVelocityGuard

**Purpose:** Enforces per-agent and per-session rate limits using
token-bucket semantics. Unlike the grant-scoped `VelocityGuard`, this guard
rate-limits by agent identity across all capabilities, preventing a single
agent from overwhelming the system regardless of how many capabilities it
holds.

**Guard name:** `agent-velocity`

**Rate limiting model:** Token-bucket with integer milli-token arithmetic
to avoid floating-point drift. Buckets refill at a steady rate over the
configured window. The burst factor controls the initial bucket capacity
relative to the steady-state rate.

**Bucket keying:**

| Bucket | Key | Purpose |
| --- | --- | --- |
| Per-agent | `agent_id` | Cross-capability rate limit for a single agent |
| Per-session | `(agent_id, capability_id)` | Rate limit within a single session/capability context |

When both limits are configured, both **MUST** pass for the request to be
allowed. The stricter limit takes effect.

**Configuration:**

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `max_requests_per_agent` | `u32` or `null` | `null` (unlimited) | Maximum requests per agent per window |
| `max_requests_per_session` | `u32` or `null` | `null` (unlimited) | Maximum requests per session per window |
| `window_secs` | `u64` | `60` | Window duration in seconds |
| `burst_factor` | `f64` | `1.0` | Burst multiplier for bucket capacity (`1.0` = no burst above steady rate) |

**Fail-closed behavior:** If the internal mutex is poisoned, the guard
**MUST** return `KernelError::Internal` which the pipeline treats as a
denial.

**GuardEvidence output:** On denial, the evidence indicates which limit was
exceeded (per-agent or per-session) and the current token count.

---

## 3. Session-Aware Deterministic Guards

Session-aware deterministic guards consult the session journal to make
decisions based on cumulative session history. They require an
`Chio<SessionJournal>` reference and produce deterministic verdicts given
the same journal state.

DataFlowGuard and BehavioralSequenceGuard are NOT registered into the default
kernel pipeline; operators register them explicitly. The two guards depend on
a `SessionJournal` that the runtime caller supplies, and the kernel's default
guard pipeline does not assume one is present.

### 3.1 DataFlowGuard

**Purpose:** Enforces cumulative data transfer limits per session, preventing
data exfiltration through many small requests that individually appear benign
but cumulatively transfer large volumes.

**Guard name:** `data-flow`

**Accounting model:** The guard reads cumulative `bytes_read` and
`bytes_written` from the session journal's `CumulativeDataFlow` snapshot.
Limits are checked against the running totals, not per-request deltas.

**Configuration:**

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `max_bytes_read` | `u64` or `null` | `null` (unlimited) | Maximum cumulative bytes read per session |
| `max_bytes_written` | `u64` or `null` | `null` (unlimited) | Maximum cumulative bytes written per session |
| `max_bytes_total` | `u64` or `null` | `null` (unlimited) | Maximum cumulative bytes (read + written) per session |

**Fail-closed behavior:** If the session journal is unavailable (lock
poisoned, I/O error), the guard **MUST** return an error, which the pipeline
treats as a denial. The guard **MUST NOT** default to allow when journal
state is inaccessible.

**GuardEvidence output:** On denial, the evidence includes the exceeded
limit type (read, written, or total), the current cumulative value, and the
configured threshold.

### 3.2 BehavioralSequenceGuard

**Purpose:** Enforces tool ordering policies to prevent dangerous sequences
of operations. For example, an operator may require that `read_file` must
precede `write_file`, or that `bash` cannot be immediately followed by
`write_file` (preventing blind write-after-execute patterns).

**Guard name:** `behavioral-sequence`

**Policy model:** The guard reads the tool invocation sequence from the
session journal and checks four types of ordering constraints:

| Constraint | Description |
| --- | --- |
| Required predecessors | Tool X **MUST NOT** run unless tools Y and Z have been invoked earlier in the session |
| Forbidden transitions | Tool X **MUST NOT** run immediately after tool Y |
| Max consecutive | The same tool **MUST NOT** run more than N times consecutively |
| Required first tool | The first tool in a session **MUST** match a specified name |

**Configuration:**

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `required_predecessors` | `map<string, string[]>` | `{}` | Map from tool name to required predecessor tool names |
| `forbidden_transitions` | `[string, string][]` | `[]` | List of `(from_tool, to_tool)` pairs that are forbidden |
| `max_consecutive` | `u32` or `null` | `null` (unlimited) | Maximum consecutive invocations of the same tool |
| `required_first_tool` | `string` or `null` | `null` | Tool name that must be the first invocation in a session |

**Fail-closed behavior:** If the session journal is unavailable, the guard
**MUST** return an error, which the pipeline treats as a denial.

**GuardEvidence output:** On denial, the evidence includes the violated
constraint type, the current tool, and the relevant sequence context (e.g.,
the missing predecessor or the forbidden transition pair).

---

## 4. Post-Invocation Hooks

Post-invocation hooks run after a tool produces a response but before that
response is delivered to the agent. They inspect response content and can
modify, block, or escalate it.

### 4.1 PostInvocationPipeline

The `PostInvocationPipeline` evaluates hooks in registration order. Each hook
returns one of four verdicts:

| Verdict | Effect |
| --- | --- |
| `Allow` | Response passes through unmodified |
| `Block(reason)` | Response is replaced with an error message; pipeline short-circuits |
| `Redact(value)` | Response content is replaced with the redacted version; subsequent hooks see the redacted version |
| `Escalate(message)` | Response is delivered, but an escalation signal is emitted for operator review |

**Pipeline semantics:**

- A `Block` from any hook **MUST** stop the pipeline immediately. No
  subsequent hooks run.
- A `Redact` replaces the response for all subsequent hooks. Multiple
  `Redact` hooks compose sequentially.
- `Escalate` messages are collected throughout the pipeline and reported
  alongside the final verdict.
- If no hooks modify the response, the final verdict is `Allow`.

### 4.2 ResponseSanitizationGuard

**Purpose:** Scans tool responses (and request arguments when used
pre-invocation) for PII and PHI patterns, then blocks or redacts matches
before the data reaches the agent.

**Guard name:** `response-sanitization`

**Built-in patterns:**

| Pattern | Example | Sensitivity | Redaction |
| --- | --- | --- | --- |
| SSN | `123-45-6789` | High | `[SSN REDACTED]` |
| Email | `user@example.com` | Medium | `[EMAIL REDACTED]` |
| Phone | `(555) 123-4567` | Low | `[PHONE REDACTED]` |
| Credit card | `4111-1111-1111-1111` | High | `[CARD REDACTED]` |
| Date of birth | `1990-01-15` or `01/15/1990` | Low | `[DATE REDACTED]` |
| MRN | `MRN: 123456789` | High | `[MRN REDACTED]` |
| ICD-10 | `J18.9`, `E11` | Medium | `[ICD REDACTED]` |

**Sensitivity levels:**

| Level | Meaning |
| --- | --- |
| Low | May produce false positives (phone numbers, dates) |
| Medium | Likely PII (emails, medical codes) |
| High | Definite PII/PHI (SSN, credit card, MRN) |

The `min_level` configuration controls the minimum sensitivity threshold.
Only patterns at or above the threshold trigger the guard.

**Actions:**

| Action | Behavior |
| --- | --- |
| `Block` | Deny the response entirely if any pattern matches |
| `Redact` | Replace matching patterns with their redaction strings and allow the response |

**Configuration:**

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `min_level` | `SensitivityLevel` | `Low` | Minimum sensitivity level to trigger |
| `action` | `SanitizationAction` | `Block` | Action to take on match (`Block` or `Redact`) |
| `custom_patterns` | `SensitivePattern[]` | `[]` | Additional regex patterns to scan for |

Operators **MAY** define custom patterns via `build_pattern()`, specifying a
name, regex, sensitivity level, and redaction string. Invalid regexes are
silently skipped at load time.

**Dual-phase operation:**

- **Pre-invocation (Guard trait):** Scans request arguments for PII that
  should not be sent to tool servers. Denies if patterns are found.
- **Post-invocation (scan_response):** Scans tool response payloads. Returns
  `ScanResult::Clean`, `ScanResult::Blocked`, or `ScanResult::Redacted`.

**Fail-closed behavior:** If pattern compilation fails at startup, the guard
**MUST** be constructed without the failed pattern (fail-open for that
specific pattern). If a scan error occurs at runtime, the guard **MUST**
block the response.

**GuardEvidence output:** On denial or redaction, the evidence includes the
list of matched pattern names and the action taken.

---

## 5. Advisory Signal Framework

Advisory signals are non-blocking observations emitted during guard
evaluation. They provide operators with visibility into request patterns
without affecting the request verdict -- unless explicitly promoted.

### 5.1 AdvisorySignal

Each advisory signal carries:

| Field | Type | Description |
| --- | --- | --- |
| `guard_name` | `string` | Name of the advisory guard that produced the signal |
| `description` | `string` | Human-readable observation |
| `severity` | `AdvisorySeverity` | Severity classification |
| `metadata` | `object` or `null` | Structured metadata about the observation |
| `promoted` | `boolean` | Whether this signal was promoted to a deterministic denial (set by the promotion policy, not the guard) |

Advisory signals are serialized and attached to the receipt as part of the
`GuardOutput` evidence array. They **MUST** be included in the signed receipt
body so that auditors can review all observations.

### 5.2 Severity Levels

| Level | Ordinal | Meaning |
| --- | --- | --- |
| `Info` | 0 | Informational observation, no action needed |
| `Low` | 1 | Worth monitoring over time |
| `Medium` | 2 | May warrant investigation |
| `High` | 3 | Likely needs operator attention |
| `Critical` | 4 | Strong signal of abuse or anomaly |

Severity levels are ordered. A promotion rule with `min_severity: Medium`
promotes signals at Medium, High, and Critical.

### 5.3 AdvisoryPipeline

The `AdvisoryPipeline` wraps multiple `AdvisoryGuard` implementations and a
`PromotionPolicy`. It implements the kernel's `Guard` trait so it can be
registered in the standard guard pipeline.

**Guard name:** `advisory-pipeline`

**Behavior:**

1. The pipeline evaluates every registered advisory guard in order.
2. Each guard returns zero or more `AdvisorySignal` entries.
3. For each signal, the pipeline checks the promotion policy.
4. If any signal matches a promotion rule, it is marked `promoted: true` and
   the pipeline returns `Verdict::Deny`.
5. If no signals are promoted, the pipeline returns `Verdict::Allow`.
6. All collected signals (promoted or not) are stored for evidence export.

Without any promotion rules, the advisory pipeline **MUST** always return
`Verdict::Allow`.

### 5.4 PromotionPolicy

Operators configure promotion rules in `chio.yaml` to convert advisory signals
into deterministic denials:

```yaml
advisory:
  promotion_rules:
    - guard_name: anomaly-advisory
      min_severity: high
    - guard_name: data-transfer-advisory
      min_severity: critical
```

**PromotionRule fields:**

| Field | Type | Description |
| --- | --- | --- |
| `guard_name` | `string` | Exact match on the advisory guard's name |
| `min_severity` | `AdvisorySeverity` | Minimum severity to promote |

When a signal matches a promotion rule (guard name matches and signal
severity >= rule severity), the signal's `promoted` field is set to `true`
and the pipeline returns `Deny`.

**Serialization:** Both `PromotionRule` and `PromotionPolicy` are
serializable with `serde`. Severity values use `snake_case` naming
(`info`, `low`, `medium`, `high`, `critical`).

### 5.5 Built-in Advisory Guards

#### 5.5.1 AnomalyAdvisoryGuard

**Guard name:** `anomaly-advisory`

**Purpose:** Flags unusual invocation patterns and excessive delegation depth
without blocking requests.

**Signals emitted:**

| Condition | Severity | Description |
| --- | --- | --- |
| Tool invoked >= threshold times | Medium | Tool X invoked N times (threshold: T) |
| Tool invoked >= 2x threshold | High | Elevated severity for sustained repetition |
| Delegation depth >= threshold | High | Delegation depth D exceeds threshold T |

**Configuration:**

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `invocation_threshold` | `u64` | (required) | Per-tool invocation count to trigger a signal |
| `depth_threshold` | `u32` | (required) | Delegation depth to trigger a signal |

#### 5.5.2 DataTransferAdvisoryGuard

**Guard name:** `data-transfer-advisory`

**Purpose:** Flags sessions with high cumulative data transfer volumes. Useful
as an early warning before the deterministic `DataFlowGuard` limit is hit.

**Signals emitted:**

| Condition | Severity | Description |
| --- | --- | --- |
| Total bytes >= threshold | Medium | Cumulative transfer exceeds threshold |
| Total bytes >= 2x threshold | High | Elevated severity |
| Total bytes >= 3x threshold | Critical | Critical data volume |

**Configuration:**

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `bytes_threshold` | `u64` | (required) | Cumulative byte count to trigger a signal |

**Metadata:** Signals include `total_bytes`, `bytes_read`, `bytes_written`,
and `threshold` in the structured metadata field.

### 5.6 GuardOutput

The `GuardOutput` type provides a unified representation of guard results in
the evidence array:

| Variant | Tag | Fields | Description |
| --- | --- | --- | --- |
| `Deterministic` | `"deterministic"` | `guard_name`, `verdict` (bool), `details` | Result from a standard guard |
| `Advisory` | `"advisory"` | All `AdvisorySignal` fields | Non-blocking observation |

The `type` discriminator field uses `snake_case` naming in JSON serialization.

---

## 6. WASM Custom Guards

The `chio-wasm-guards` crate allows operators to author guards in any language
that compiles to WebAssembly (Rust, AssemblyScript, Go, C) and load them into
the Chio kernel at runtime.

### 6.1 Host-Guest ABI

Each `.wasm` guard module **MUST** export a single function:

```
evaluate(request_ptr: i32, request_len: i32) -> i32
```

**Invocation protocol:**

1. The host serializes a `GuardRequest` as JSON.
2. The host writes the JSON bytes into guest linear memory starting at
   offset 0.
3. The host calls `evaluate(0, json_length)`.
4. The guest reads the request from memory, evaluates it, and returns a
   verdict code.

**Return codes:**

| Code | Meaning |
| --- | --- |
| `0` | Allow |
| `1` | Deny |
| Any negative value | Error (fail-closed) |

**Deny reason protocol:** The guest **MAY** write a NUL-terminated UTF-8
string starting at offset 65536 (64 KiB) in linear memory. The host reads
up to 4096 bytes from this region. If the region is absent, empty, or
malformed, the host uses a generic denial message.

### 6.2 GuardRequest

The JSON payload written into guest memory:

| Field | Type | Description |
| --- | --- | --- |
| `tool_name` | `string` | Tool being invoked |
| `server_id` | `string` | Server hosting the tool |
| `agent_id` | `string` | Agent making the request |
| `arguments` | `object` | Tool arguments (opaque JSON) |
| `scopes` | `string[]` | Granted scope names (formatted as `"server_id:tool_name"`) |
| `session_metadata` | `object` or `null` | Optional session context for stateful guards |

### 6.3 Fuel Metering

WASM guards execute under a fuel budget that limits CPU consumption. The
runtime tracks fuel consumption per instruction and terminates the guest
when the budget is exhausted.

| Parameter | Default | Description |
| --- | --- | --- |
| `fuel_limit` | `10,000,000` | Maximum fuel units per invocation |

**Fail-closed on exhaustion:** When fuel runs out, the runtime **MUST**
terminate the guest and treat the invocation as denied. A
`WasmGuardError::FuelExhausted` error is returned, which the kernel treats
as a denial verdict.

**Fail-closed on trap:** Any WASM trap (memory access violation, stack
overflow, unreachable instruction) **MUST** result in denial.

**Fail-closed on missing export:** If the module does not export the required
`evaluate` function or `memory`, the load **MUST** fail and the guard
**MUST NOT** be registered in the pipeline.

### 6.4 Configuration

WASM guards are declared in `chio.yaml`:

```yaml
wasm_guards:
  - name: custom-pii-guard
    path: /etc/chio/guards/pii_guard.wasm
    fuel_limit: 5000000
    priority: 100
    advisory: false
```

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | `string` | (required) | Human-readable name (used in receipts and logs) |
| `path` | `string` | (required) | Filesystem path to the `.wasm` module |
| `fuel_limit` | `u64` | `10,000,000` | Maximum fuel units per invocation |
| `priority` | `u32` | `1000` | Evaluation order (lower = earlier) |
| `advisory` | `boolean` | `false` | If `true`, denial is logged but not enforced |

**Advisory WASM guards:** When `advisory: true`, the guard logs denials and
errors but returns `Verdict::Allow`. This allows operators to test new WASM
guards in production without blocking traffic.

### 6.5 Security Properties

- **Sandboxed execution:** WASM guards execute in an isolated linear memory
  space with no access to the host filesystem, network, or kernel state.
- **Deterministic termination:** Fuel metering guarantees that guards
  terminate within a bounded time.
- **No host callbacks:** The current ABI does not provide any host functions
  to the guest. The guest can only read the provided request and return a
  verdict.
- **Fail-closed on all errors:** Compilation failure, missing exports, fuel
  exhaustion, traps, and unexpected return values all result in denial (for
  non-advisory guards).

---

## 7. Session Journal Contract

The session journal (`chio-http-session` crate) is the shared state layer
that session-aware guards and advisory guards read from. It is an
append-only, hash-chained log of request records within a single session.

### 7.1 Invariants

- **Append-only:** Entries **MUST** only be added, never modified or removed.
- **Hash-chained:** Each entry **MUST** include a SHA-256 hash of the
  previous entry for tamper detection. The first entry uses the zero hash
  (`0000...0000`, 64 hex zeros) as its `prev_hash`.
- **Thread-safe:** The journal **MUST** be safe for concurrent access from
  multiple guards. The implementation uses a `Mutex` around the inner state.
- **Per-session scope:** Each session creates one journal. The journal is
  shared via `Chio<SessionJournal>` with all guards that need it.

### 7.2 Journal Entry

Each entry records a single tool invocation:

| Field | Type | Description |
| --- | --- | --- |
| `sequence` | `u64` | Monotonically increasing sequence number (0-based) |
| `prev_hash` | `string` | SHA-256 hex hash of the previous entry (zero hash for first entry) |
| `entry_hash` | `string` | SHA-256 hex hash of this entry's canonical fields |
| `timestamp_secs` | `u64` | Unix timestamp (seconds) when the entry was recorded |
| `tool_name` | `string` | Tool that was invoked |
| `server_id` | `string` | Server that hosted the tool |
| `agent_id` | `string` | Agent that made the invocation |
| `bytes_read` | `u64` | Bytes read during this invocation |
| `bytes_written` | `u64` | Bytes written during this invocation |
| `delegation_depth` | `u32` | Delegation depth at the time of invocation |
| `allowed` | `boolean` | Whether the invocation was allowed or denied |

**Entry hash computation:** The `entry_hash` is the SHA-256 digest of the
following fields concatenated in order using little-endian byte encoding for
integers and UTF-8 for strings:

1. `sequence` (8 bytes, LE)
2. `prev_hash` (UTF-8 bytes)
3. `timestamp_secs` (8 bytes, LE)
4. `tool_name` (UTF-8 bytes)
5. `server_id` (UTF-8 bytes)
6. `agent_id` (UTF-8 bytes)
7. `bytes_read` (8 bytes, LE)
8. `bytes_written` (8 bytes, LE)
9. `delegation_depth` (4 bytes, LE)
10. `allowed` (1 byte: `0x01` for true, `0x00` for false)

### 7.3 Cumulative Accounting

The journal maintains running cumulative statistics that guards read via the
`data_flow()` method:

| Statistic | Type | Description |
| --- | --- | --- |
| `total_bytes_read` | `u64` | Sum of `bytes_read` across all entries |
| `total_bytes_written` | `u64` | Sum of `bytes_written` across all entries |
| `total_invocations` | `u64` | Count of all recorded entries |
| `max_delegation_depth` | `u32` | Maximum `delegation_depth` seen in any entry |

All additions use saturating arithmetic to prevent overflow.

### 7.4 Tool Sequence Tracking

The journal maintains:

- **Tool sequence:** An ordered list of tool names in invocation order,
  available via `tool_sequence()`. Used by the `BehavioralSequenceGuard` for
  ordering checks.
- **Tool counts:** A map from tool name to invocation count, available via
  `tool_counts()`. Used by the `AnomalyAdvisoryGuard` for frequency
  detection.

Both allowed and denied invocations are recorded in the sequence and counts.

### 7.5 Integrity Verification

The `verify_integrity()` method walks the hash chain and verifies:

1. Each entry's `prev_hash` matches the preceding entry's `entry_hash`
   (or the zero hash for the first entry).
2. Each entry's `entry_hash` matches the recomputed hash of its canonical
   fields.

If either check fails, the journal returns a
`SessionJournalError::IntegrityViolation` with the index, expected hash, and
actual hash.

Operators **SHOULD** invoke integrity verification at session boundaries or
during audit. Guards **MAY** verify integrity before reading journal state,
though this adds latency and is not required for normal operation.

### 7.6 Guard Access Patterns

| Guard | Journal method | Usage |
| --- | --- | --- |
| `DataFlowGuard` | `data_flow()` | Read cumulative byte counts |
| `BehavioralSequenceGuard` | `tool_sequence()` | Read ordered tool history |
| `AnomalyAdvisoryGuard` | `tool_counts()`, `data_flow()` | Read per-tool counts and delegation depth |
| `DataTransferAdvisoryGuard` | `data_flow()` | Read cumulative byte counts |

---

## 8. Configuration Reference

### 8.1 chio.yaml Guard Section

```yaml
guards:
  # Stateless deterministic
  internal_network:
    extra_blocked_hosts:
      - "internal.corp.example.com"
    dns_rebinding_detection: true

  agent_velocity:
    max_requests_per_agent: 100
    max_requests_per_session: 20
    window_secs: 60
    burst_factor: 1.5

  # Session-aware deterministic
  data_flow:
    max_bytes_read: 10485760      # 10 MiB
    max_bytes_written: 5242880     # 5 MiB
    max_bytes_total: 15728640      # 15 MiB

  behavioral_sequence:
    required_predecessors:
      write_file:
        - read_file
    forbidden_transitions:
      - [bash, write_file]
    max_consecutive: 5
    required_first_tool: init

  # Post-invocation
  response_sanitization:
    min_level: medium
    action: redact

  # Advisory
  advisory:
    anomaly:
      invocation_threshold: 20
      depth_threshold: 5
    data_transfer:
      bytes_threshold: 5242880    # 5 MiB
    promotion_rules:
      - guard_name: anomaly-advisory
        min_severity: high
      - guard_name: data-transfer-advisory
        min_severity: critical

# WASM custom guards
wasm_guards:
  - name: custom-compliance
    path: /etc/chio/guards/compliance.wasm
    fuel_limit: 5000000
    priority: 200
    advisory: false
```

---

## 9. Implementation Status

The Implementation column reports whether the guard logic ships in the
indicated crate. The Default pipeline wiring column reports whether the
kernel's default guard pipeline registers the guard automatically or whether
operators MUST wire it themselves. Implementation status does not by itself
imply that the guard runs against incoming requests.

| Guard | Crate | Implementation | Default pipeline wiring |
| --- | --- | --- | --- |
| InternalNetworkGuard | `chio-guards` | Full | Default-wired |
| AgentVelocityGuard | `chio-guards` | Full | Default-wired |
| DataFlowGuard | `chio-guards` | Full | Operator-wired (requires `SessionJournal`) |
| BehavioralSequenceGuard | `chio-guards` | Full | Operator-wired (requires `SessionJournal`) |
| ResponseSanitizationGuard | `chio-guards` | Full | Default-wired (post-invocation) |
| PostInvocationPipeline | `chio-guards` | Full | Default-wired |
| AdvisoryPipeline | `chio-guards` | Full | Default-wired |
| AnomalyAdvisoryGuard | `chio-guards` | Full | Operator-wired (requires `SessionJournal`) |
| DataTransferAdvisoryGuard | `chio-guards` | Full | Operator-wired (requires `SessionJournal`) |
| PortableFilesystemRootsGuard | `chio-guards` | Full | Operator-wired (filesystem-scoped) |
| WasmGuard | `chio-wasm-guards` | Full | Operator-wired |
| WasmGuardRuntime | `chio-wasm-guards` | Full | Operator-wired |
| SessionJournal | `chio-http-session` | Full | Operator-wired |
