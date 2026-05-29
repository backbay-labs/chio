# Output Sanitizer Guard Capability and Porting Plan

This document plans the full absorption of the upstream output sanitizer
into Chio's post-invocation guard system. Chio already has a partial port at
`crates/chio-guards/src/response_sanitization.rs`. The upstream implementation
is substantially richer. This doc inventories the gap, defines the refactoring
plan, and proposes type signatures for the complete Chio-native version.

---

## 1. What the Upstream Output Sanitizer Does

Source: the upstream `output_sanitizer.rs` module

### 1.1 Detection Categories

Four-variant `SensitiveCategory` enum:

| Category | Default strategy | Examples |
|----------|-----------------|----------|
| `Secret` | `Full` (replace entirely) | API keys, JWTs, private key blocks, password assignments |
| `Pii` | `Partial` (keep prefix/suffix) | Email, phone, SSN, credit cards |
| `Internal` | `TypeLabel` (category-only placeholder) | Localhost URLs, private IPs, Windows paths, sensitive file paths |
| `Custom(String)` | Caller-defined | Denylist matches, domain-specific patterns |

Categories are individually toggleable via `CategoryConfig`. Each has a
per-category default redaction strategy configurable through
`OutputSanitizerConfig.redaction_strategies`.

### 1.2 Redaction Strategies

Five-variant `RedactionStrategy` enum, ranked by strength for overlap
resolution:

| Rank | Strategy | Replacement example |
|------|----------|-------------------|
| 0 | `None` | Raw text (allowlisted/informational) |
| 1 | `Partial` | `al***om` (2-char prefix + 2-char suffix) |
| 2 | `Hash` | `[HASH:a1b2c3...]` (SHA-256 of match) |
| 3 | `TypeLabel` | `[REDACTED:internal]` |
| 4 | `Full` | `[REDACTED:openai_api_key]` |

When multiple findings overlap the same byte range, the sanitizer merges
spans and selects the strongest strategy. Replacement is applied in
reverse-offset order so byte indices remain valid.

### 1.3 Detection Pipeline

The sanitizer runs detectors in this order:

1. **Denylist patterns** -- forced-redaction regex patterns supplied by the
   operator. Each match is treated as `Secret` with `Full` strategy at 0.95
   confidence.

2. **Compiled pattern library** -- 14 static regex patterns initialized once
   via `OnceLock`. Each pattern has a stable ID (`secret_openai_api_key`,
   `pii_email`, etc.), a category, a base confidence score, and a recommended
   redaction strategy.

   Secret patterns (7):
   - `secret_openai_api_key` -- `sk-[A-Za-z0-9]{48}` (0.99)
   - `secret_anthropic_api_key` -- `sk-ant-api03-[A-Za-z0-9_-]{93}` (0.99)
   - `secret_github_token` -- `gh[ps]_[A-Za-z0-9]{36}` (0.99)
   - `secret_aws_access_key_id` -- `AKIA[0-9A-Z]{16}` (0.99)
   - `secret_private_key_block` -- PEM header (0.99)
   - `secret_jwt` -- three-segment base64url (0.8)
   - `secret_password_assignment` -- `password|passwd|pwd` followed by
     assignment operator (0.7)

   PII patterns (4):
   - `pii_email` -- RFC-like email address (0.95)
   - `pii_phone` -- US-format phone numbers with separators (0.8)
   - `pii_ssn` -- `XXX-XX-XXXX` (0.9)
   - `pii_credit_card` -- 13-19 digit sequences, **Luhn-validated** (0.7)

   Internal patterns (3):
   - `internal_localhost_url` -- `localhost` / `127.0.0.1` URLs (0.8)
   - `internal_private_ip` -- RFC 1918 ranges (0.8)
   - `internal_windows_path` -- `C:\...` style paths (0.7)
   - `internal_file_path_sensitive` -- `/etc/`, `/var/secrets/`,
     `~/.ssh/` (0.7)

3. **Entity recognizer hook** -- optional `dyn EntityRecognizer` trait object
   for external NER integration. Produces `EntityFinding` structs with
   entity type, confidence, and span. Findings are merged into the PII
   category with `Partial` redaction.

4. **Shannon entropy detector** -- for unknown secrets. Scans for tokens
   matching `[A-Za-z0-9+/=_-]{32,}`, checks they are valid base64/hex
   alphabet, computes Shannon entropy, and flags tokens above the threshold
   (default 4.5 bits). Only runs when `categories.secrets` is enabled.

### 1.4 Luhn Validation

Credit card matches are post-filtered through a Luhn checksum. The
implementation extracts digits, rejects sequences shorter than 13 or longer
than 19, rejects all-same-digit sequences, and applies the standard
double-and-sum algorithm. Only Luhn-valid matches are reported as findings.

### 1.5 Allowlist and False-Positive Reduction

`AllowlistConfig` provides three mechanisms:
- **Exact matches** -- string-equality check against a list
- **Regex patterns** -- compiled at sanitizer construction time
- **Test credential detection** -- opt-in via `allow_test_credentials`;
  recognizes obviously-placeholder tokens (repeated single character after
  known prefixes like `sk-`, `ghp_`, `AKIA`)

A match against any allowlist skips both the finding and the redaction.

### 1.6 Truncation Safety

The sanitizer bounds input to `max_input_bytes` (default 1MB). When the input
exceeds this limit, only the prefix is analyzed. The unscanned suffix is
**not appended** to the output -- the sanitizer appends
`[TRUNCATED_UNSCANNED_OUTPUT]` instead. This is a fail-closed design: content
that was not analyzed is never emitted.

### 1.7 Streaming Sanitization

`SanitizationStream` provides incremental processing for long-running tool
outputs:
- `write(chunk)` buffers input, periodically draining safe prefixes
- `flush()` emits the remaining buffer
- `end()` flushes and returns a cumulative `SanitizationResult`

The streaming mode uses a carry-bytes lookback (default 512 bytes) to avoid
cutting inside a finding span. When a cutoff would land inside a merged
redaction span, the cutoff is moved to the start of that span. Buffer size
is bounded (default 50KB). Streaming can be disabled per-config, in which
case each chunk is sanitized independently.

### 1.8 Output Structures

`SanitizationResult` contains:
- `sanitized: String` -- the redacted text
- `was_redacted: bool` -- whether any redaction was applied
- `findings: Vec<SensitiveDataFinding>` -- detected items (never raw text,
  always redacted previews)
- `redactions: Vec<Redaction>` -- applied replacements with original spans
- `stats: ProcessingStats` -- input/output length, counts, processing time

---

## 2. Upstream Watermarking System

Source: the upstream `watermarking.rs` module

The watermarking module provides content provenance via signed metadata
comments embedded in text.

### 2.1 Architecture

- `PromptWatermarker` holds an Ed25519 keypair and an atomic sequence counter
- `WatermarkPayload` contains application ID, session ID, timestamp, sequence
  number, expiration, and custom metadata
- Payloads are serialized as canonical JSON (RFC 8785 JCS) for portable
  signatures
- `EncodedWatermark` bundles the payload, its canonical bytes, the Ed25519
  signature (hex), and the public key (hex)

### 2.2 Embedding and Extraction

Encoding strategy is `Metadata` (HTML comment format):
```
<!--hushclaw.watermark:v1:<base64url(JSON)>-->
```

The embedded JSON contains the base64url-encoded canonical payload, the
signature, and the public key. `WatermarkExtractor` parses the comment,
decodes the payload, and optionally verifies against a trusted public key
list.

### 2.3 Verification Model

`WatermarkVerifierConfig` supports:
- Trusted public key list (empty means trust any valid signature)
- `allow_unverified` flag (controls whether unverified watermarks are exposed
  to callers or suppressed)

`EncodedWatermark::fingerprint()` returns SHA-256 of the canonical payload
bytes for correlation across systems.

---

## 3. Upstream Hygiene Module

Source: the upstream `hygiene.rs` module

While not directly part of output sanitization, the hygiene module is
relevant because it operates on the same text pipeline:

- **Boundary markers** -- `wrap_user_content()` inserts
  `[USER_CONTENT_START]`/`[USER_CONTENT_END]` around untrusted text
  (idempotent)
- **Prompt injection detection** -- regex-based signal detection with
  weighted scoring, canonicalization (NFKC normalization, case folding,
  zero-width character stripping, whitespace collapsing), and severity
  levels (Safe, Suspicious, High, Critical)
- **Fingerprint deduper** -- bounded LRU cache for content fingerprints to
  suppress alert spam from repeated injection payloads

The hygiene module is a pre-invocation concern (inspecting inputs), while the
output sanitizer is post-invocation (inspecting outputs). Chio already has
separate pre- and post-invocation pipelines, so these map naturally.

---

## 4. Gap Analysis: Chio vs the upstream guard suite

### 4.1 What Chio Has

`crates/chio-guards/src/response_sanitization.rs` implements:

- `SensitivityLevel` enum (Low/Medium/High) -- three tiers, no custom variant
- `SensitivePattern` struct with name, regex, level, redaction string
- `SanitizationAction` enum (Block/Redact)
- 7 default patterns: SSN, email, phone, credit card, date of birth, MRN,
  ICD-10 codes
- `ResponseSanitizationGuard` implementing the `Guard` trait for
  pre-invocation use
- `scan_response()` for post-invocation JSON scanning
- `ScanResult` enum (Clean/Blocked/Redacted)
- `build_pattern()` helper for custom patterns

`crates/chio-guards/src/post_invocation.rs` implements:

- `PostInvocationVerdict` enum (Allow/Block/Redact/Escalate)
- `PostInvocationHook` trait with `name()` and `inspect()` methods
- `PostInvocationPipeline` with ordered evaluation, short-circuit on Block,
  response threading through Redact hooks, and escalation collection

### 4.2 What Chio Is Missing

| Feature | Upstream | Chio |
|---------|------------|-----|
| Detection categories | 4 variants (`Secret`/`Pii`/`Internal`/`Custom`) with per-category toggles and strategies | 3-tier sensitivity level, no categories |
| Redaction strategies | 5 variants with strength ranking and overlap resolution | Single replacement string per pattern |
| Secret detection | 7 patterns + entropy detector | None |
| Internal infra detection | 4 patterns | None |
| Healthcare PII | None (generic PII only) | MRN + ICD-10 (Chio has this, the upstream suite does not) |
| Luhn validation | Yes, on credit card matches | No (regex-only, high false positive rate) |
| Allowlist/denylist | Exact strings, regex patterns, test credential detection | None |
| Entity recognizer hook | Trait-based extensibility for NER | None |
| Entropy-based detection | Shannon entropy scanner for unknown secrets | None |
| Streaming | Full streaming sanitizer with carry-bytes lookback | None |
| Overlap resolution | Span merging with strategy ranking | No overlap handling |
| Truncation safety | Fail-closed truncation with marker | No input size limits |
| Finding metadata | Stable IDs, confidence scores, detector type, redacted previews | Pattern name + raw match text (leaks the matched content) |
| Watermarking | Ed25519-signed content provenance | None |
| Processing stats | Input/output length, timing, counts | Redaction count only |

### 4.3 Chio-Only Features Worth Keeping

- **MRN and ICD-10 patterns** -- healthcare-specific PII not present in
  the upstream suite. These should be preserved and added to the merged pattern
  library as `Pii` category entries.
- **Date-of-birth pattern** -- useful for HIPAA compliance, keep as `Pii`.
- **`Guard` trait integration** -- the pre-invocation Guard impl that scans
  tool call arguments for PII leakage. The upstream suite does not have this
  bidirectional use.
- **`PostInvocationHook` integration** -- the pipeline model is cleaner than
  the upstream standalone sanitizer and should be the integration point.

---

## 5. Refactoring Plan

### 5.1 Phase 1: Type Unification

Replace Chio's `SensitivityLevel` with the upstream richer type model:

- Adopt `SensitiveCategory` (Secret/Pii/Internal/Custom)
- Adopt `RedactionStrategy` (None/Partial/Hash/TypeLabel/Full) with strength
  ranking
- Adopt `Span`, `DetectorType`, `SensitiveDataFinding`
- Add `CategoryConfig` with per-category enable/disable
- Keep Chio's `SanitizationAction` (Block/Redact) as the guard-level policy;
  this is orthogonal to per-finding redaction strategies

Remove `SensitivityLevel`. The old Low/Medium/High mapping becomes:
- Low -> category toggle (enable/disable Internal, which is informational)
- Medium -> PII category
- High -> Secret category

### 5.2 Phase 2: Detection Engine

Port the full detection pipeline into `response_sanitization.rs`:

1. **Static pattern library** -- merge the upstream 14 patterns with Chio's
   healthcare patterns (MRN, ICD-10, date of birth) into a single
   `OnceLock`-backed `compile_patterns()` function. Total: ~17 patterns.

2. **Luhn validator** -- port `is_luhn_valid_card_number()` as a post-filter
   on credit card regex matches.

3. **Entropy detector** -- port `shannon_entropy_ascii()` and
   `is_candidate_secret_token()`. Add `EntropyConfig` to the sanitizer
   config.

4. **Denylist/allowlist** -- port `AllowlistConfig`, `DenylistConfig`, and
   the test-credential detector. Compile regex patterns at construction time.

5. **Entity recognizer hook** -- port the `EntityRecognizer` trait. This is
   the extension point for NER integration (e.g., connecting a local
   Presidio instance or a WASM-based recognizer).

6. **Overlap resolution** -- port the span-merging algorithm with strategy
   ranking. This replaces the current naive `replace_all` approach that can
   produce garbled output when patterns overlap.

7. **Truncation** -- add `max_input_bytes` with fail-closed behavior.

### 5.3 Phase 3: Streaming

Port `SanitizationStream` for incremental tool output processing. This
matters for:
- Long-running tools (code execution, data queries) that produce streaming
  output
- MCP tool servers that return results incrementally
- Real-time agent monitoring where latency to first safe token matters

The stream integrates with `PostInvocationPipeline` by producing
`PostInvocationVerdict::Redact` values as chunks become available.

### 5.4 Phase 4: PostInvocationHook Adapter

Bridge the sanitizer into Chio's post-invocation pipeline:

```rust
pub struct SanitizationHook {
    sanitizer: OutputSanitizer,
    /// What to do when findings are present.
    on_finding: SanitizationAction,
    /// Minimum confidence threshold to act on.
    min_confidence: f32,
}

impl PostInvocationHook for SanitizationHook {
    fn name(&self) -> &str { "output-sanitizer" }

    fn inspect(&self, tool_name: &str, response: &Value)
        -> PostInvocationVerdict;
}
```

The hook extracts text content from the JSON response (recursively walking
string values), runs the sanitizer, and returns:
- `Allow` if no findings
- `Block` if `on_finding == Block`
- `Redact` with the sanitized JSON if `on_finding == Redact`
- `Escalate` for findings above a configurable confidence threshold that
  the operator wants flagged but not blocked

### 5.5 Phase 5: Guard Trait Adapter (Bidirectional)

Keep the existing `Guard` trait implementation for pre-invocation argument
scanning, but upgrade it to use the full detection engine:

```rust
impl Guard for ResponseSanitizationGuard {
    fn name(&self) -> &str { "response-sanitization" }

    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        let args_text = ctx.request.arguments.to_string();
        let result = self.sanitizer.sanitize_sync(&args_text);
        if result.was_redacted {
            Ok(Verdict::Deny)
        } else {
            Ok(Verdict::Allow)
        }
    }
}
```

This gives the same guard dual use: pre-invocation (via `Guard` trait) to
prevent PII from being sent to tools, and post-invocation (via
`PostInvocationHook`) to prevent PII from being returned to agents.

---

## 6. Data Layer Integration

### 6.1 Column-Level PII in Query Results

When Chio mediates database tool access (SQL tools, data connectors), the
output sanitizer provides a second layer of defense beyond column-level
access control:

1. **Access control** (pre-invocation guard) -- the capability scope restricts
   which tables/columns the agent can query
2. **Output sanitization** (post-invocation hook) -- catches PII that leaks
   through joins, computed columns, or free-text fields that bypass column
   restrictions

Example: an agent has access to a `patients` table but the capability scope
excludes the `ssn` column. If a free-text `notes` column contains
"SSN: 123-45-6789", the output sanitizer catches it even though column-level
ACL was satisfied.

### 6.2 Query Result Governance

The sanitizer's finding metadata integrates with Chio's receipt log:

```rust
// In the receipt, after post-invocation sanitization:
ReceiptBody {
    // ...existing fields...
    sanitization: Some(SanitizationSummary {
        findings_count: 3,
        redactions_count: 2,
        categories: vec![SensitiveCategory::Pii],
        // No raw findings -- just counts and categories.
    }),
}
```

This enables:
- Audit queries: "Which tool calls produced PII findings in the last 24h?"
- Compliance reporting: "How many SSN detections were redacted vs blocked?"
- Policy tuning: high false-positive rates on a pattern trigger allowlist
  additions

### 6.3 Structured Data Optimization

For JSON tool responses with known schemas, the sanitizer can skip
non-string fields and focus on string values. The `PostInvocationHook`
adapter should recursively walk the JSON value and sanitize only `String`
nodes, preserving the response structure:

```rust
fn sanitize_json_value(
    sanitizer: &OutputSanitizer,
    value: &Value,
) -> (Value, Vec<SensitiveDataFinding>) {
    match value {
        Value::String(s) => {
            let result = sanitizer.sanitize_sync(s);
            (Value::String(result.sanitized), result.findings)
        }
        Value::Array(arr) => { /* recurse */ }
        Value::Object(map) => { /* recurse */ }
        other => (other.clone(), vec![])
    }
}
```

---

## 7. Watermarking: Should Chio Absorb It?

### 7.1 Recommendation: Yes, as a Separate Module

The watermarking system is orthogonal to sanitization but closely related
to Chio's receipt system. Chio should absorb it into a new
`crates/chio-guards/src/watermarking.rs` module (or potentially a standalone
`chio-watermark` crate if the dependency footprint warrants it).

### 7.2 Use Case: Receipt-Linked Content Watermarks

Chio already signs receipts with Ed25519 over canonical JSON. The watermarking
system uses the same primitives. The natural integration:

1. When a tool response passes through the post-invocation pipeline, the
   sanitizer produces a `SanitizationResult`
2. The kernel signs a receipt for the tool call
3. A watermark is embedded in the sanitized output, linking to the receipt
   via the receipt ID in the watermark's metadata

This creates a chain: the watermarked content can be traced back to the
specific tool invocation, the agent that requested it, the capability that
authorized it, and the guard pipeline that sanitized it.

```rust
pub struct ReceiptLinkedWatermarkPayload {
    pub receipt_id: String,
    pub tool_name: String,
    pub sanitization_fingerprint: Option<String>,
    // Inherited from WatermarkPayload:
    pub application_id: String,
    pub session_id: String,
    pub created_at: u64,
    pub sequence_number: u32,
}
```

### 7.3 Adaptations for Chio

- Replace `hush_core` crypto with `chio_core::crypto` (same Ed25519
  primitives, different crate path)
- Replace `hush_core::canonical` with `chio_core::canonical` for JCS
  serialization
- Replace `<!--hushclaw.watermark:v1:` prefix with `<!--chio.watermark:v1:`
- Add the receipt ID to the watermark payload as a required field
- Keep the `WatermarkExtractor` and `WatermarkVerifierConfig` for downstream
  consumers that need to verify content provenance

### 7.4 When Not to Watermark

Watermarking adds bytes to every response. It should be opt-in and
configurable per tool or per capability scope:

- **Watermark** -- tool responses that will be persisted, shared, or
  rendered to end users (document generation, report tools, email drafting)
- **Do not watermark** -- ephemeral tool responses consumed only by the
  agent's reasoning loop (calculator, code execution scratch, internal
  lookups)

---

## 8. Type Signatures for the Complete Chio-Native Version

These are the target types for the fully absorbed implementation in
`crates/chio-guards/src/response_sanitization.rs`.

### 8.1 Core Types

```rust
/// Categories of sensitive data.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveCategory {
    Secret,
    Pii,
    Internal,
    Custom(String),
}

/// Redaction strategies, ranked by strength for overlap resolution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionStrategy {
    None,
    Partial,
    Hash,
    TypeLabel,
    Full,
}

impl RedactionStrategy {
    pub fn rank(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::Partial => 1,
            Self::Hash => 2,
            Self::TypeLabel => 3,
            Self::Full => 4,
        }
    }
}

/// Byte span in the input text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// How a finding was detected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorType {
    Pattern,
    Entropy,
    Entity,
    Custom(String),
}
```

### 8.2 Finding and Redaction Records

```rust
/// A detected sensitive data finding. Never contains raw matched text.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SensitiveDataFinding {
    pub id: String,
    pub category: SensitiveCategory,
    pub data_type: String,
    pub confidence: f32,
    pub span: Span,
    /// Redacted preview (e.g., "al***om"), never the raw match.
    pub preview: String,
    pub detector: DetectorType,
    pub recommended_action: RedactionStrategy,
}

/// Record of an applied redaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Redaction {
    pub finding_id: String,
    pub strategy: RedactionStrategy,
    pub original_span: Span,
    pub replacement: String,
}
```

### 8.3 Configuration

```rust
/// Per-category enable/disable toggles.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CategoryConfig {
    pub secrets: bool,    // default: true
    pub pii: bool,        // default: true
    pub internal: bool,   // default: true
}

/// Entropy-based unknown secret detection.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntropyConfig {
    pub enabled: bool,           // default: true
    pub threshold: f64,          // default: 4.5
    pub min_token_len: usize,    // default: 32
}

/// False-positive suppression.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AllowlistConfig {
    pub exact: Vec<String>,
    pub patterns: Vec<String>,
    pub allow_test_credentials: bool,
}

/// Forced-redaction patterns.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DenylistConfig {
    pub patterns: Vec<String>,
}

/// Streaming incremental sanitization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamingConfig {
    pub enabled: bool,           // default: true
    pub buffer_size: usize,      // default: 50_000
    pub carry_bytes: usize,      // default: 512
}

/// Full sanitizer configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputSanitizerConfig {
    pub categories: CategoryConfig,
    pub redaction_strategies: HashMap<SensitiveCategory, RedactionStrategy>,
    pub include_findings: bool,
    pub entropy: EntropyConfig,
    pub allowlist: AllowlistConfig,
    pub denylist: DenylistConfig,
    pub streaming: StreamingConfig,
    pub max_input_bytes: usize,   // default: 1_000_000
}
```

### 8.4 Sanitizer and Results

```rust
/// The core sanitizer. Thread-safe, cloneable.
#[derive(Clone)]
pub struct OutputSanitizer {
    config: OutputSanitizerConfig,
    allowlist_patterns: Vec<Regex>,
    denylist_patterns: Vec<(String, Regex)>,
    entity_recognizer: Option<Chio<dyn EntityRecognizer>>,
}

impl OutputSanitizer {
    pub fn new() -> Self;
    pub fn with_config(config: OutputSanitizerConfig) -> Self;
    pub fn with_entity_recognizer<R: EntityRecognizer + 'static>(
        self, recognizer: R,
    ) -> Self;
    pub fn sanitize_sync(&self, output: &str) -> SanitizationResult;
    pub fn create_stream(&self) -> SanitizationStream;
}

/// Entity recognizer extension point.
pub trait EntityRecognizer: Send + Sync {
    fn detect(&self, text: &str) -> Vec<EntityFinding>;
}

/// Sanitization output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SanitizationResult {
    pub sanitized: String,
    pub was_redacted: bool,
    pub findings: Vec<SensitiveDataFinding>,
    pub redactions: Vec<Redaction>,
    pub stats: ProcessingStats,
}

/// Processing statistics.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProcessingStats {
    pub input_length: usize,
    pub output_length: usize,
    pub findings_count: usize,
    pub redactions_count: usize,
    pub processing_time_ms: f64,
}
```

### 8.5 Post-Invocation Hook Adapter

```rust
/// Bridges OutputSanitizer into Chio's PostInvocationPipeline.
pub struct SanitizationHook {
    sanitizer: OutputSanitizer,
    on_finding: SanitizationAction,
    min_confidence: f32,
    escalate_threshold: Option<f32>,
}

impl PostInvocationHook for SanitizationHook {
    fn name(&self) -> &str { "output-sanitizer" }

    fn inspect(
        &self,
        tool_name: &str,
        response: &Value,
    ) -> PostInvocationVerdict {
        let (sanitized_value, findings) =
            sanitize_json_value(&self.sanitizer, response);

        let actionable: Vec<_> = findings.iter()
            .filter(|f| f.confidence >= self.min_confidence)
            .collect();

        if actionable.is_empty() {
            return PostInvocationVerdict::Allow;
        }

        if let Some(threshold) = self.escalate_threshold {
            let critical: Vec<_> = actionable.iter()
                .filter(|f| f.confidence >= threshold)
                .collect();
            if !critical.is_empty()
                && self.on_finding != SanitizationAction::Block
            {
                return PostInvocationVerdict::Escalate(
                    format!(
                        "{} high-confidence findings detected",
                        critical.len(),
                    ),
                );
            }
        }

        match self.on_finding {
            SanitizationAction::Block => PostInvocationVerdict::Block(
                format!(
                    "{} sensitive data findings detected",
                    actionable.len(),
                ),
            ),
            SanitizationAction::Redact => {
                PostInvocationVerdict::Redact(sanitized_value)
            }
        }
    }
}
```

### 8.6 Pre-Invocation Guard (Upgraded)

```rust
/// Guard that prevents PII/secrets from being sent to tool servers.
pub struct ResponseSanitizationGuard {
    sanitizer: OutputSanitizer,
}

impl Guard for ResponseSanitizationGuard {
    fn name(&self) -> &str { "response-sanitization" }

    fn evaluate(
        &self,
        ctx: &GuardContext,
    ) -> Result<Verdict, KernelError> {
        let args_text = ctx.request.arguments.to_string();
        let result = self.sanitizer.sanitize_sync(&args_text);
        if result.was_redacted {
            Ok(Verdict::Deny)
        } else {
            Ok(Verdict::Allow)
        }
    }
}
```

---

## 9. Migration Path

### 9.1 Backward Compatibility

The existing `ResponseSanitizationGuard` public API will change. Consumers
that construct the guard with `SensitivityLevel` and `SanitizationAction`
will need to update to `OutputSanitizerConfig`. Provide a compatibility
constructor:

```rust
impl ResponseSanitizationGuard {
    /// Compatibility constructor for existing callers.
    pub fn simple(action: SanitizationAction) -> Self {
        Self {
            sanitizer: OutputSanitizer::new(),
            action,
        }
    }
}
```

### 9.2 Pattern Library Migration

1. Start with the upstream 14 patterns as the base
2. Add Chio's MRN, ICD-10, and date-of-birth patterns with appropriate
   categories and confidence scores
3. Mark Chio-original patterns with a `healthcare_` prefix in their IDs
   for traceability
4. Remove duplicate patterns (SSN, email, phone, credit card are in both;
   prefer the upstream versions which have Luhn validation and better
   regex coverage)

### 9.3 Dependency Changes

The port requires:
- `regex` -- already a dependency of `chio-guards`
- `chio-core` crypto -- replaces `hush_core` for SHA-256 and Ed25519
- No new external dependencies needed

The `hush_core` dependency is **not** added to `chio-guards`. All crypto
goes through `chio_core::crypto` and `chio_core::canonical`.

---

## 10. Open Questions

1. **Entropy threshold tuning** -- The upstream suite defaults to 4.5 bits. Is this
   appropriate for Chio's use cases, or should it be more conservative
   (higher threshold, fewer false positives)?

2. **Entity recognizer backend** -- The trait is defined but what ships as
   the default implementation? Options: no default (callers bring their own),
   a WASM-based NER module, or a simple keyword list for common entity types.

3. **Watermark format** -- should `<!--chio.watermark:v1:` be the only
   encoding, or should Chio also support a non-HTML format for non-text
   payloads (JSON metadata field, binary trailer)?

4. **Receipt integration granularity** -- should every finding be recorded
   in the receipt, or only aggregate counts? Full findings increase receipt
   size but improve auditability.

5. **Streaming hook protocol** -- the current `PostInvocationHook::inspect`
   returns a single verdict. Streaming sanitization needs a different
   interface. Options: separate `StreamingPostInvocationHook` trait, or
   extend the existing trait with a `inspect_stream` method with a default
   implementation that falls back to `inspect`.
