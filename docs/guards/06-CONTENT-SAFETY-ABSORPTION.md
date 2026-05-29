# Content Safety Guard Capability and Porting Plan

This document covers porting the four content safety modules from the upstream guard suite
into Chio's `chio-guards` crate. These represent the P0 gap in Chio's guard
coverage: the existing 15 guards handle filesystem, network, rate-limiting,
data-flow, and advisory signals, but nothing screens the actual content of
agent inputs for jailbreak, prompt injection, or instruction hierarchy
violations.

Source modules in the upstream guard suite:

| Module | Guard | Lines | Depends on |
|--------|-------|-------|------------|
| `guards/jailbreak.rs` | `JailbreakGuard` | 334 | `jailbreak.rs`, `text_utils.rs` |
| `guards/prompt_injection.rs` | `PromptInjectionGuard` | 265 | `hygiene.rs`, `text_utils.rs` |
| `jailbreak.rs` | `JailbreakDetector` (ML tier) | 1257 | `text_utils.rs`, `hush_core::sha256` |
| `hygiene.rs` | `detect_prompt_injection_with_limit` | 446 | `text_utils.rs`, `hush_core::sha256` |
| `spider_sense.rs` | `SpiderSenseDetector` | 720 | None (pure, WASM-compatible) |
| `instruction_hierarchy.rs` | `InstructionHierarchyEnforcer` | 1549 | `text_utils.rs` |

---

## 1. What Each Module Does

### 1.1 JailbreakGuard + JailbreakDetector

**Guard layer** (`guards/jailbreak.rs`): Wraps `JailbreakDetector` behind
The upstream async `Guard` trait. Handles `GuardAction::Custom("user_input",
...)` and `GuardAction::Custom("hushclaw.user_input", ...)`. Parses the
payload as either a raw string or `{"text": "..."}` object. Returns block,
warn, or allow based on the detector's `risk_score` against configurable
`block_threshold` (default 70) and `warn_threshold` (default 30).

**Detector layer** (`jailbreak.rs`): A tiered detection pipeline:

1. **Heuristic layer** -- Five compiled regex patterns over canonicalized text:
   - `jb_ignore_policy` (weight 0.9): `ignore|disregard|bypass|override|disable` near `policy|rules|safety|guardrails`
   - `jb_dan_unfiltered` (weight 0.9): `dan|jailbreak|unfiltered|unrestricted`
   - `jb_system_prompt_extraction` (weight 0.95): `reveal|show|tell me|repeat|print|output` near `system prompt|developer instructions|hidden prompt`
   - `jb_role_change` (weight 0.7): `you are now|act as|pretend to be|roleplay`
   - `jb_encoded_payload` (weight 0.6): `base64|rot13|url encode|decode`

2. **Statistical layer** -- Four feature detectors:
   - Punctuation ratio >= 0.35 (`stat_punctuation_ratio_high`)
   - Shannon entropy of ASCII non-whitespace chars >= 4.8 (`stat_char_entropy_high`)
   - Zero-width character stripping count > 0 (`stat_zero_width_obfuscation`)
   - Run of 12+ consecutive non-alphanumeric, non-whitespace chars (`stat_long_symbol_run`)

3. **ML layer** -- A small linear model (logistic regression via sigmoid):
   - 8 configurable weights: `bias` (-2.0), `w_ignore_policy` (2.5), `w_dan` (2.0), `w_role_change` (1.5), `w_prompt_extraction` (2.2), `w_encoded` (1.0), `w_punct` (2.0), `w_symbol_run` (1.5)
   - Features are binary indicators from the heuristic layer + continuous punctuation ratio
   - `LinearModelConfig` is serde-configurable, allowing weight replacement without code changes

4. **LLM-as-judge layer** (optional, `feature = "full"`): Trait `LlmJudge` with
   `async fn score(&self, input: &str) -> Result<f32, String>`. An
   `OpenAiLlmJudge` implementation exists behind `feature = "llm-judge-openai"`.
   Re-weights the final score: 90% baseline + 10% judge.

**Score aggregation**: Weighted combination -- heuristic (55%), statistical
(20%), ML (25%) -- producing a 0-100 `risk_score`. Severity mapping:
`>= 85 = Confirmed`, `>= 60 = Likely`, `>= 25 = Suspicious`, `< 25 = Safe`.

**Session aggregation**: Per-session state tracking with LRU eviction, TTL
(default 1h), and exponential rolling risk decay (half-life default 15min).
Session snapshots include `messages_seen`, `suspicious_count`,
`cumulative_risk`, and `rolling_risk`. Optional `SessionStore` trait for
external persistence (behind `feature = "full"`).

**Canonicalization pipeline** (`text_utils.rs`): NFKC normalization, case
folding, zero-width/formatting character stripping (18 Unicode codepoints),
and whitespace collapsing. Stats tracked for each operation.

**Caching**: LRU cache (capacity 512) keyed by SHA-256 fingerprint of raw
input. Session state is applied post-cache to avoid cross-session leakage.

**Data hygiene**: Detection results never include raw input text. Signals are
identified by stable string IDs only. Match spans are byte offsets into
canonical text, not original text.

### 1.2 PromptInjectionGuard + hygiene.rs

**Guard layer** (`guards/prompt_injection.rs`): Wraps
`detect_prompt_injection_with_limit` behind the upstream async `Guard` trait.
Handles `GuardAction::Custom("untrusted_text", ...)` -- scans external/tool
content for injection attempts. Parses `{"text": "...", "source": "..."}` or
a bare string. Configurable `warn_at_or_above` (default `Suspicious`) and
`block_at_or_above` (default `High`).

**Detection layer** (`hygiene.rs`): Regex-based signal detection over
canonicalized text, bounded by `max_scan_bytes` (default 200KB). Fingerprint
always covers full content. Six signal patterns:

| Signal ID | Weight | Pattern |
|-----------|--------|---------|
| `ignore_previous_instructions` | 3 | `ignore|disregard` near `previous|prior|above|earlier` near `instructions|directions|rules` |
| `system_prompt_mentions` | 2 | `system prompt|developer message|hidden instructions|jailbreak` |
| `prompt_extraction_request` | 4 | `reveal|show|tell me|repeat|print|output|display|copy` near `system prompt|developer instructions|hidden prompt` |
| `tool_invocation_language` | 1 | `call|invoke|run|execute` near `tool|function` |
| `security_bypass_language` | 3 | `ignore|disregard|bypass|override|disable|skip` near `guardrails|guard|policy|security|safety|filters|protections` |
| `credential_exfiltration` | 6 | `api key|secret|token|password|private key` near `send|post|upload|exfiltrate|leak|reveal|print|dump` (bidirectional) |

Plus a structural signal: `obfuscation_zero_width` (weight 1) if any
zero-width characters were stripped during canonicalization.

**Level mapping**: `weight >= 6 = Critical`, `score >= 3 = High`,
`score >= 1 = Suspicious`, `score == 0 = Safe`.

**Deduplication**: `FingerprintDeduper` -- bounded LRU cache for content
fingerprints with count tracking. Prevents log/alert spam when the same
injection payload appears across multiple sources.

### 1.3 SpiderSenseDetector

**Module** (`spider_sense.rs`): Pure synchronous embedding similarity
screening. No I/O, no feature gates, WASM-compatible.

**PatternDb**: In-memory database of pre-computed embedding vectors. Each entry
has an `id`, `category` (e.g., `"prompt_injection"`, `"data_exfiltration"`),
`stage` (perception/cognition/action/feedback), `label`, and `embedding:
Vec<f32>`. Loaded from JSON. Validates consistent dimensionality and finite
values at parse time.

**Screening**: Brute-force cosine similarity search returning top-k matches.
Cosine similarity computed in f64 precision over f32 vectors. Non-finite
values return 0.0 (fail-closed). Dimension mismatches return 0.0.

**Verdict**: Three-way decision using configurable thresholds:
- `Deny` -- top score >= `threshold + ambiguity_band` (default: >= 0.95)
- `Ambiguous` -- top score in `[threshold - band, threshold + band)` (default: [0.75, 0.95))
- `Allow` -- top score <= `threshold - ambiguity_band` (default: <= 0.75)

Dimension mismatch and non-finite embeddings produce `Deny` (fail-closed).

**Key property**: The caller is responsible for obtaining embeddings. The
detector itself does no model inference or network I/O.

### 1.4 InstructionHierarchyEnforcer

**Module** (`instruction_hierarchy.rs`): Enforces privilege ordering
`Platform > System > User > ToolOutput > External`. Processes a sequence of
`HierarchyMessage` values and detects conflicts via regex patterns.

**Conflict rules** (9 rule IDs):

| Rule | Severity | Detects | Action |
|------|----------|---------|--------|
| HIR-001 | High | Override attempts (`ignore|disregard|forget|override` near `instructions|rules|policy|guardrails|system`) | Block |
| HIR-002 | Critical | Authority impersonation (`i am|i'm|as` near `system|developer|admin|root|maintainer`) | Block |
| HIR-003 | Medium | Tool output with instruction-like language (`run|execute|invoke|call` near `tool|command|bash|shell`) | Modify |
| HIR-004 | High | External content with override language | Modify |
| HIR-005 | Medium | Context overflow (truncates low-privilege messages first) | Modify |
| HIR-006 | High | Role change (`you are now|act as|pretend to be|switch to`) | Block |
| HIR-007 | Critical | Instruction leak/extraction (`reveal|show|tell me` near `system prompt|developer instructions|hidden prompt`) | Block |
| HIR-009 | High | Fake delimiter injection (`[/SYSTEM]`, `<system>`, `<\|im_start\|>`, `<\|im_end\|>`) | Modify (replace with `[REDACTED_DELIMITER]`) |

**Enforcement actions**:
- Marker wrapping: External content wrapped in `[UNTRUSTED_CONTENT]...[/UNTRUSTED_CONTENT]`, tool output in `[TOOL_DATA]...[/TOOL_DATA]`
- Reminder injection: Periodic platform-level reminders at configurable frequency (default every 5 messages)
- Context overflow handling: Drops External first, then ToolOutput, then User, preserving System/Platform
- Trust score: Starts at 1.0, degraded per conflict severity (Critical: -0.25, High: -0.15, Medium: -0.05, Low: -0.01)

**Configuration**: `HierarchyEnforcerConfig` with `strict_mode` (any conflict
invalidates), `marker_format` (XML/JSON/Delimited/Custom), per-rule enable
flags, reminder frequency, and context byte limits.

---

## 2. Refactoring for Chio's Guard Trait

Chio's `Guard` trait (`chio_kernel::Guard`) is synchronous:

```rust
pub trait Guard: Send + Sync {
    fn name(&self) -> &str;
    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError>;
}
```

`Verdict` is `Allow | Deny`. No `Warn`, no `Abstain`. `GuardContext` provides
`request: &ToolCallRequest` (with `tool_name`, `arguments: serde_json::Value`,
`agent_id`, `server_id`), `scope: &ChioScope`, and session metadata.

### 2.1 Async removal

Upstream guards use `#[async_trait] impl Guard` with `async fn check(...)`.
The actual detection logic is already sync:

- `JailbreakDetector::detect_base_sync()` is the core pipeline. The async
  `detect()` method only adds optional `LlmJudge` calls and `SessionStore`
  load/persist. The `detect_sync()` method already exists.
- `detect_prompt_injection_with_limit()` is fully synchronous.
- `SpiderSenseDetector::screen()` is fully synchronous.
- `InstructionHierarchyEnforcer::enforce_inner()` is synchronous (both
  `enforce()` and `enforce_sync()` delegate to it).

**Action**: Use the sync codepaths directly. Drop `async_trait`, `tokio`
dependency. The LLM-as-judge layer and SessionStore persistence become
host-function extensions (see section 4).

### 2.2 Action model mapping

The upstream suite uses `GuardAction::Custom(kind, payload)` to route content to the
right guard. Chio has no `GuardAction` -- guards receive `GuardContext` with
`ToolCallRequest.arguments`.

**Mapping strategy**: Content safety guards inspect
`ctx.request.arguments` to find text to scan. The guards should define which
argument keys they look at, configurable per deployment:

```rust
pub struct JailbreakGuardConfig {
    /// Argument keys to scan for jailbreak content.
    /// Default: ["text", "content", "prompt", "message", "input"]
    pub scan_keys: Vec<String>,
    pub block_threshold: u8,     // default 70
    pub warn_threshold: u8,      // default 30
    pub max_input_bytes: usize,  // default 100_000
    pub layers: LayerConfig,
    pub linear_model: LinearModelConfig,
}
```

When a guard finds text in any of the configured `scan_keys`, it runs
detection. If no configured key is present, the guard returns `Allow` (it
does not apply to this tool call).

### 2.3 Verdict mapping

The upstream `GuardResult` has `allow`, `warn`, and `block` constructors plus
`details: Option<serde_json::Value>`. Chio's `Verdict` is binary
(Allow/Deny).

**Mapping**:
- `block` -> `Verdict::Deny`
- `warn` -> `Verdict::Allow` (emit advisory signal via `AdvisoryPipeline`)
- `allow` -> `Verdict::Allow`

This means content safety guards that want to emit warnings must either:
1. Participate in the `AdvisoryPipeline` (implement `AdvisoryGuard` for the
   warn path, and `Guard` for the block path), or
2. Be a single `Guard` implementation that returns `Deny` on block threshold
   and `Allow` otherwise, emitting detection metadata through the evidence
   system.

**Recommendation**: Option 2 for simplicity. Detection metadata (risk score,
signal IDs, fingerprint, canonicalization stats) should be attached to the
receipt's evidence field. The warn threshold becomes a separate
`ContentSafetyAdvisoryGuard` that implements `AdvisoryGuard` and emits
`AdvisorySignal` values when risk score is between warn and block thresholds.

---

## 3. What to Preserve vs. Drop

### 3.1 Preserve

| Component | Reason |
|-----------|--------|
| Heuristic regex patterns (5 jailbreak, 6 prompt injection) | Core detection logic; low-cost, interpretable |
| Statistical layer (punctuation ratio, entropy, zero-width, symbol runs) | Catches adversarial suffixes and obfuscation |
| Linear model with configurable weights | Cheap ML tier, no model files needed |
| Text canonicalization pipeline (NFKC, casefold, zero-width strip, whitespace collapse) | Critical for anti-obfuscation |
| SHA-256 fingerprinting of raw input | Deduplication and audit trail |
| Data hygiene (no raw text in signals/details) | Privacy and security requirement |
| LRU detection cache (fingerprint-keyed) | Performance |
| `SpiderSenseDetector` (cosine similarity screening) | Pure, WASM-compatible, no dependencies |
| `PatternDb` format and validation | Existing pattern databases can be reused |
| Instruction hierarchy conflict detection (regex-based) | HIR-001 through HIR-009 patterns |
| Instruction hierarchy marker wrapping | Content isolation |
| Session risk aggregation with decay | Multi-turn grooming detection |
| `FingerprintDeduper` | Alert spam prevention |

### 3.2 Drop or defer

| Component | Disposition | Reason |
|-----------|-------------|--------|
| `async_trait` + `#[async_trait] impl Guard` | **Drop** | Chio's Guard trait is sync |
| `LlmJudge` trait + `OpenAiLlmJudge` | **Defer to host function** | Requires async HTTP; should be a WASM host function or separate guard |
| `SessionStore` trait (async persistence) | **Defer** | Chio uses `SessionJournal` from `chio-http-session`; adapt to that |
| `GuardAction::Custom` dispatch | **Drop** | Replaced by `scan_keys` argument inspection |
| Upstream `GuardResult` / `Severity` types | **Drop** | Replaced by `Verdict` + `AdvisorySignal` |
| `hush_core::sha256` dependency | **Replace** | Use `chio-core`'s SHA-256 (already exists) |
| `feature = "full"` conditional compilation | **Drop** | All sync code in Chio; async extensions are separate crates |
| Instruction hierarchy `MarkerFormat::Xml` / `Json` rendering | **Defer** | Low priority; keep `Delimited` only for v1 |
| Instruction hierarchy reminder injection | **Evaluate** | May conflict with Chio's kernel-level concerns; keep the pattern detection, defer the message mutation |
| `HierarchyState.trust_score` | **Adapt** | Map to `AdvisorySignal` severity rather than a floating-point trust metric |

### 3.3 Dependencies to vendor or adapt

| Upstream dep | Chio equivalent |
|-----------------|----------------|
| `hush_core::sha256` / `hush_core::Hash` | `chio_core::crypto::sha256` (or add if missing) |
| `crate::text_utils::canonicalize_for_detection` | New `chio-guards/src/text_canonicalization.rs` module |
| `crate::text_utils::truncate_to_char_boundary` | Same new module |
| `crate::text_utils::compile_hardcoded_regex` | Same new module |
| `crate::text_utils::is_zero_width_or_formatting` | Same new module |
| `unicode-normalization` crate | Add to `chio-guards/Cargo.toml` |
| `regex` crate | Already in `chio-guards` dependency tree |

---

## 4. SpiderSense and External ML Classifiers

### 4.1 SpiderSense in Chio

SpiderSense is already WASM-compatible and sync. Two integration paths:

**Option A: Native guard in `chio-guards`**

```rust
pub struct SpiderSenseGuard {
    detector: SpiderSenseDetector,
    /// Argument key containing the pre-computed embedding vector.
    embedding_key: String,
}

impl Guard for SpiderSenseGuard {
    fn name(&self) -> &str { "spider-sense" }

    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        let embedding = extract_embedding(&ctx.request.arguments, &self.embedding_key)?;
        let result = self.detector.screen(&embedding);
        match result.verdict {
            ScreeningVerdict::Deny => Ok(Verdict::Deny),
            ScreeningVerdict::Ambiguous => Ok(Verdict::Allow), // emit advisory
            ScreeningVerdict::Allow => Ok(Verdict::Allow),
        }
    }
}
```

This requires the caller to pre-compute embeddings and include them in the
tool call arguments. The guard itself does no inference.

**Option B: WASM guard**

Compile `SpiderSenseDetector` + `PatternDb` into a `.wasm` module. The
pattern database is embedded in the WASM binary or loaded via a host
function. The WASM guard receives the embedding vector in the `GuardRequest`
and returns allow/deny.

**Recommendation**: Option A for v1 (simpler, no WASM overhead for a pure Rust
module). Option B is the long-term target for third-party pattern databases.

### 4.2 External ML classifiers

External classifiers (Lakera Guard, NVIDIA NeMo Guardrails, AWS Bedrock
Guardrails, Azure AI Content Safety) require HTTP calls and are inherently
async. They cannot implement `chio_kernel::Guard` directly.

**Architecture**: Host-function-backed WASM guards.

```
WASM guard module
  |
  +-- calls host function: classify_content(text) -> ClassificationResult
  |
  Host runtime
    |
    +-- HTTP call to external classifier API
    |
    +-- Caches result by content fingerprint
    |
    +-- Returns structured result to WASM guest
```

The WASM guard is the policy layer (interpret classifier output, apply
thresholds, map to allow/deny). The host function is the I/O layer (HTTP
client, auth, caching, retry).

**Host function signature** (defined in `chio-wasm-guards`):

```rust
/// Host function exposed to WASM guards for external content classification.
///
/// The guest passes a JSON-serialized ClassificationRequest.
/// The host returns a JSON-serialized ClassificationResponse.
fn chio_classify_content(request_ptr: i32, request_len: i32) -> i64;

pub struct ClassificationRequest {
    pub provider: String,           // "lakera" | "nemo" | "bedrock" | "azure"
    pub text: String,
    pub categories: Vec<String>,    // optional category filter
}

pub struct ClassificationResponse {
    pub flagged: bool,
    pub categories: Vec<CategoryResult>,
    pub provider_metadata: serde_json::Value,
}
```

This is a v2 feature that depends on the host function framework from
doc 05-V1-DECISION.md. The v1 content safety guards use the native heuristic
and statistical layers only.

---

## 5. Concrete Type Signatures for Chio-Native Guards

### 5.1 JailbreakGuard

```rust
// chio-guards/src/jailbreak.rs

use chio_kernel::{Guard, GuardContext, KernelError, Verdict};

pub struct JailbreakGuard {
    config: JailbreakGuardConfig,
    detector: JailbreakDetector,
}

pub struct JailbreakGuardConfig {
    pub scan_keys: Vec<String>,
    pub block_threshold: u8,
    pub max_input_bytes: usize,
    pub layers: LayerConfig,
    pub linear_model: LinearModelConfig,
}

impl Guard for JailbreakGuard {
    fn name(&self) -> &str { "jailbreak" }
    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError>;
}
```

`JailbreakDetector` is ported directly from the upstream guard suite's `jailbreak.rs` with
all async code removed. The `detect_sync()` method becomes the sole
`detect()` method. Session aggregation is retained using an internal
`Mutex<HashMap<String, SessionAgg>>` keyed by `ctx.request.agent_id` (or a
configurable session key extractor).

### 5.2 PromptInjectionGuard

```rust
// chio-guards/src/prompt_injection.rs

pub struct PromptInjectionGuard {
    config: PromptInjectionGuardConfig,
}

pub struct PromptInjectionGuardConfig {
    pub scan_keys: Vec<String>,
    pub block_at_or_above: PromptInjectionLevel,
    pub max_scan_bytes: usize,
}

impl Guard for PromptInjectionGuard {
    fn name(&self) -> &str { "prompt-injection" }
    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError>;
}
```

Detection delegates to `detect_prompt_injection_with_limit()`, ported into a
new `chio-guards/src/prompt_injection_detection.rs` module.

### 5.3 InstructionHierarchyGuard

```rust
// chio-guards/src/instruction_hierarchy.rs

pub struct InstructionHierarchyGuard {
    config: HierarchyGuardConfig,
    enforcer: Mutex<InstructionHierarchyEnforcer>,
}

pub struct HierarchyGuardConfig {
    pub scan_keys: Vec<String>,
    pub strict_mode: bool,
    pub rules: RulesConfig,
}

impl Guard for InstructionHierarchyGuard {
    fn name(&self) -> &str { "instruction-hierarchy" }
    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError>;
}
```

The enforcer is wrapped in a `Mutex` because `InstructionHierarchyEnforcer`
maintains mutable state (sequence counter, stats). The guard extracts text
from `ctx.request.arguments`, constructs a single `HierarchyMessage` at
level `External` or `User` (depending on tool type), and runs
`enforce_sync()`. If any blocking conflict is detected, returns `Deny`.

Note: The full multi-message enforcement pipeline (reminder injection,
context overflow handling) is deferred. The v1 guard uses the conflict
detection regex patterns only, applied to individual tool call arguments.

### 5.4 ContentSafetyAdvisoryGuard

```rust
// chio-guards/src/advisory.rs (extend existing module)

pub struct ContentSafetyAdvisoryGuard {
    jailbreak_detector: JailbreakDetector,
    pi_config: PromptInjectionGuardConfig,
    scan_keys: Vec<String>,
    jailbreak_warn_threshold: u8,
    pi_warn_level: PromptInjectionLevel,
}

impl AdvisoryGuard for ContentSafetyAdvisoryGuard {
    fn name(&self) -> &str { "content-safety-advisory" }
    fn evaluate(&self, ctx: &GuardContext) -> Result<Vec<AdvisorySignal>, KernelError>;
}
```

This guard emits advisory signals for content that scores between the warn
and block thresholds. It runs the same detection pipelines as the blocking
guards but produces `AdvisorySignal` values instead of `Verdict::Deny`.
Plugs into the existing `AdvisoryPipeline` and can be promoted to denial
via `PromotionPolicy`.

### 5.5 SpiderSenseGuard

```rust
// chio-guards/src/spider_sense.rs

pub struct SpiderSenseGuard {
    detector: SpiderSenseDetector,
    embedding_key: String,
}

impl Guard for SpiderSenseGuard {
    fn name(&self) -> &str { "spider-sense" }
    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError>;
}
```

---

## 6. Model Assets and Data Files

| Asset | Format | Size | Source | Required by |
|-------|--------|------|--------|-------------|
| Linear model weights | JSON (8 floats) | < 1 KB | Inline defaults in `LinearModelConfig` | `JailbreakDetector` ML layer |
| Heuristic regex patterns | Compiled at startup via `OnceLock` | N/A (code) | Inline in source | `JailbreakDetector`, `PromptInjectionGuard`, `InstructionHierarchyEnforcer` |
| SpiderSense pattern DB | JSON array of `PatternEntry` | Variable (depends on embedding dim and entry count) | User-provided file or embedded resource | `SpiderSenseDetector` |
| External classifier config | `chio.yaml` fields | N/A | Operator config | Host function for external classifiers (v2) |

**No binary model files are required for v1.** The linear model weights are
8 floating-point numbers with sensible defaults. The heuristic and
statistical layers are pure code. The only external data file is the
SpiderSense pattern database, which is optional and user-provided.

### 6.1 Text canonicalization module

A new shared module `chio-guards/src/text_canonicalization.rs` is needed,
porting these functions from the upstream `text_utils.rs`:

- `canonicalize_for_detection(text: &str) -> (String, CanonicalizationStats)` -- NFKC, casefold, zero-width strip, whitespace collapse
- `truncate_to_char_boundary(text: &str, max_bytes: usize) -> (&str, bool)`
- `is_zero_width_or_formatting(c: char) -> bool` -- 18 Unicode codepoints
- `compile_hardcoded_regex(pattern: &'static str) -> Regex`
- `CanonicalizationStats` struct

This requires adding `unicode-normalization` to `chio-guards/Cargo.toml`.

---

## 7. Priority Ordering

### Phase 1: Core content scanning (P0)

1. **Text canonicalization module** -- Foundation for all content guards.
   Port `text_utils.rs` functions into `chio-guards/src/text_canonicalization.rs`.

2. **PromptInjectionGuard** -- Simplest guard, fully sync, no internal state.
   Port `hygiene.rs` detection + wrap in `Guard` trait. Scans
   `ctx.request.arguments` for injection signals.

3. **JailbreakGuard + JailbreakDetector** -- More complex (session state,
   LRU cache, linear model) but highest-value guard. Port `jailbreak.rs`
   detector (sync path only) + guard wrapper.

### Phase 2: Hierarchy and advisory (P1)

4. **InstructionHierarchyGuard** -- Port conflict detection patterns only
   (HIR-001 through HIR-009). Defer multi-message enforcement, reminder
   injection, and context overflow to later.

5. **ContentSafetyAdvisoryGuard** -- Wire jailbreak and prompt-injection
   detectors into the `AdvisoryPipeline` for the warn tier.

### Phase 3: Embedding and external (P2)

6. **SpiderSenseGuard** -- Port `spider_sense.rs` as native guard. Already
   sync and WASM-compatible; mainly needs the `Guard` trait wrapper and
   embedding key extraction.

7. **External classifier host functions** -- Define `chio_classify_content`
   host function in `chio-wasm-guards`. Implement provider adapters for
   Lakera, NeMo, Bedrock, Azure. This is a v2 feature gated on the host
   function framework.

### Phase 4: Session and LLM judge (P3)

8. **Session aggregation adapter** -- Bridge `JailbreakDetector`'s session
   state to Chio's `SessionJournal` from `chio-http-session`.

9. **LLM-as-judge host function** -- Expose `LlmJudge` scoring as a host
   function callable from WASM guards. Provider-agnostic interface.

---

## 8. File Layout After Port

```
crates/chio-guards/src/
  lib.rs                          (add new guard exports)
  text_canonicalization.rs        (new: ported from text_utils.rs)
  jailbreak.rs                    (new: JailbreakGuard + JailbreakDetector)
  prompt_injection.rs             (new: PromptInjectionGuard + detection)
  instruction_hierarchy.rs        (new: InstructionHierarchyGuard, conflict detection only)
  spider_sense.rs                 (new: SpiderSenseGuard + SpiderSenseDetector + PatternDb)
  advisory.rs                     (extend: add ContentSafetyAdvisoryGuard)
```

Each module is self-contained with its own `#[cfg(test)] mod tests`. The
detection logic (regex patterns, statistical features, linear model) lives
in the same file as the guard, not in a separate detection crate. This avoids
The upstream guard suite pattern of splitting guard wrappers from detection engines
across multiple modules when the detection logic is small enough to inline.

---

## 9. Open Questions

1. **Session key extraction**: The upstream suite uses `GuardContext.session_id` for
   session aggregation. Chio's `GuardContext` has no explicit session ID field.
   Options: (a) derive from `agent_id`, (b) add `session_id` to
   `GuardContext`, (c) extract from `ToolCallRequest` metadata.

2. **Argument scan depth**: Should content guards recurse into nested JSON
   objects in `ctx.request.arguments`, or only scan top-level string values?
   Recursive scanning catches more injection vectors but costs more.

3. **Instruction hierarchy scope**: The full `InstructionHierarchyEnforcer`
   operates on message sequences, but Chio guards see one tool call at a time.
   Should the hierarchy guard maintain cross-request state via
   `SessionJournal`, or should it be stateless (single-message conflict
   detection only)?

4. **Pattern database distribution**: How should SpiderSense pattern databases
   be distributed? Options: embedded in the binary, loaded from a config path,
   fetched from a registry.

5. **Deduplication scope**: The `FingerprintDeduper` prevents alert spam but
   is in-memory. Should deduplication be per-guard-instance, per-session, or
   global? Should it integrate with the receipt store?
