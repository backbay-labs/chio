# Desktop and CUA Guard Absorption

This document specifies how the three upstream desktop/CUA guards will be
absorbed into the Chio kernel as first-class action types, native guards, and
WASM guard extension points. Chio currently has zero coverage for desktop agent,
browser extension, and computer use surfaces. The upstream suite has three guards that
cover this surface completely.

---

## 1. Upstream Guards: What They Do

### 1.1 `ComputerUseGuard`

**File:** the upstream `computer_use` guard module

The top-level gatekeeper for all CUA actions. Handles any `GuardAction::Custom`
where the custom type starts with `"remote."` or `"input."`. Operates in three
enforcement modes:

| Mode | Behavior |
|------|----------|
| `Observe` | Always allow, log every action with `Severity::Warning` |
| `Guardrail` (default) | Allow if action is in the allowlist, warn otherwise |
| `FailClosed` | Allow if action is in the allowlist, deny otherwise |

**Default allowlist** (10 action types):
- `remote.session.connect`, `remote.session.disconnect`, `remote.session.reconnect`
- `input.inject`
- `remote.clipboard`, `remote.file_transfer`
- `remote.audio`, `remote.drive_mapping`, `remote.printing`, `remote.session_share`

The guard uses a `HashSet<String>` allowlist for O(1) lookup. Configuration is
fully serializable (`ComputerUseConfig`) with `deny_unknown_fields`.

**Policy enforced:** Action-type allowlisting. If the action string is not in
the set and mode is `FailClosed`, the request is denied. This is the coarse
gate -- it decides whether a CUA action category is permitted at all before
the specialized guards below inspect the details.

### 1.2 `InputInjectionCapabilityGuard`

**File:** the upstream `input_injection_capability` guard module

Specialized guard for `input.inject` actions. Validates two things:

1. **Input type allowlisting.** The action data must contain an `input_type`
   field (accepts both `input_type` and `inputType` for cross-pipeline
   compatibility). The value must be in the allowed set. Default allowed types:
   `keyboard`, `mouse`, `touch`. Missing `input_type` is denied (fail-closed).

2. **Postcondition probe requirement.** When `require_postcondition_probe` is
   true, the action data must contain a non-empty `postcondition_probe_hash`
   (or `postconditionProbeHash`) field. This ensures that every input injection
   is paired with a verification step -- the agent must prove it checked the
   screen state after acting.

**Policy enforced:** Fine-grained input-type restrictions and mandatory
postcondition verification. An agent can be allowed to type but not click, or
required to screenshot-verify after every keystroke. The postcondition probe
hash ties input injection to the screen capture verification loop.

### 1.3 `RemoteDesktopSideChannelGuard`

**File:** the upstream `remote_desktop_side_channel` guard module

Controls six named side channels on remote desktop sessions. Each channel has
an independent enable/disable toggle:

| Channel | Config field | Action type |
|---------|-------------|-------------|
| Clipboard | `clipboard_enabled` | `remote.clipboard` |
| File transfer | `file_transfer_enabled` | `remote.file_transfer` |
| Session sharing | `session_share_enabled` | `remote.session_share` |
| Audio | `audio_enabled` | `remote.audio` |
| Drive mapping | `drive_mapping_enabled` | `remote.drive_mapping` |
| Printing | `printing_enabled` | `remote.printing` |

Additional controls:
- **`max_transfer_size_bytes`**: When set, `remote.file_transfer` actions must
  include a `transfer_size` (or `transferSize`) field as a `u64`. Missing or
  non-integer values are denied. Values exceeding the limit are denied.
- **Unknown channels are denied.** Any `remote.*` action that is not
  `remote.session.{connect,disconnect,reconnect}` and is not one of the six
  named channels is denied by the fail-closed default branch. This prevents
  new side channels from being silently allowed.

**Policy enforced:** Per-channel enable/disable, file transfer size limits,
and fail-closed handling of unknown channels.

### 1.4 Guard Interaction Model

The three guards form a layered pipeline in the upstream guard suite:

```
  ComputerUseGuard          (coarse gate: is this CUA action type permitted?)
       |
       v
  InputInjectionCapabilityGuard   (fine gate: input type + postcondition probe)
       |
       v
  RemoteDesktopSideChannelGuard   (fine gate: per-channel control + size limits)
```

The `ComputerUseGuard` uses prefix matching (`remote.*`, `input.*`) to claim
all CUA actions. The two specialized guards claim specific action subtypes.
When all three are registered, the coarse gate runs first (because
The upstream pipeline processes guards in registration order). If it denies,
the specialized guards never run. If it allows, the specialized guard for the
specific action type gets a second pass with deeper inspection.

---

## 2. New `ToolAction` Variants

Chio's `ToolAction` enum (in `chio-guards/src/action.rs`) currently has seven
variants: `FileAccess`, `FileWrite`, `NetworkEgress`, `ShellCommand`,
`McpTool`, `Patch`, `Unknown`. None of these represent desktop, browser, or
screen interaction.

### 2.1 Proposed additions

```rust
pub enum ToolAction {
    // ... existing variants ...

    /// Browser navigation or interaction (url, action_subtype).
    ///
    /// Covers: page navigation, form submission, DOM interaction,
    /// JavaScript execution, cookie/storage access.
    BrowserAction(String, BrowserActionType),

    /// Desktop automation action (action_subtype, target).
    ///
    /// Covers: input injection (keyboard, mouse, touch), window
    /// management, process launch, clipboard access, remote session
    /// lifecycle, and side channels (file transfer, audio, printing,
    /// drive mapping, session sharing).
    DesktopAction(DesktopActionType, Option<String>),

    /// Screen capture or screenshot (region, purpose).
    ///
    /// Covers: full-screen capture, region capture, OCR extraction,
    /// continuous recording. Separated from DesktopAction because
    /// screen capture has distinct privacy implications and is the
    /// primary observation channel for CUA agents.
    ScreenCapture(ScreenCaptureType),
}
```

### 2.2 Subtypes

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrowserActionType {
    /// Navigate to a URL.
    Navigate,
    /// Click an element.
    Click,
    /// Type into a form field.
    Type,
    /// Execute JavaScript.
    ExecuteScript,
    /// Read or write cookies/local storage.
    StorageAccess,
    /// Submit a form.
    FormSubmit,
    /// Download a file.
    Download,
    /// Other browser action (custom string).
    Other(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DesktopActionType {
    /// Keyboard input injection.
    KeyboardInput,
    /// Mouse input injection (click, move, drag).
    MouseInput,
    /// Touch input injection.
    TouchInput,
    /// Remote session lifecycle (connect, disconnect, reconnect).
    RemoteSession,
    /// Clipboard read/write.
    Clipboard,
    /// File transfer over remote channel.
    FileTransfer,
    /// Audio channel.
    Audio,
    /// Drive mapping.
    DriveMapping,
    /// Printing.
    Printing,
    /// Session sharing.
    SessionShare,
    /// Window management (focus, resize, move).
    WindowManagement,
    /// Process launch.
    ProcessLaunch,
    /// Other desktop action (custom string).
    Other(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScreenCaptureType {
    /// Full-screen screenshot.
    FullScreen,
    /// Region-bounded screenshot.
    Region,
    /// OCR text extraction from screen.
    OcrExtraction,
    /// Continuous screen recording.
    Recording,
}
```

### 2.3 `extract_action` changes

The `extract_action` function needs new branches to detect CUA tool names:

```rust
// Browser tools
if matches!(tool.as_str(),
    "browser" | "navigate" | "browse" | "web_browse" | "open_url"
    | "click_element" | "type_text" | "execute_js"
) { /* extract URL/target, return BrowserAction */ }

// Desktop / computer use tools
if matches!(tool.as_str(),
    "computer" | "computer_use" | "desktop" | "input_inject"
    | "keyboard" | "mouse" | "click" | "type" | "key"
    | "remote_session" | "clipboard" | "file_transfer"
) { /* extract action subtype, return DesktopAction */ }

// Screen capture tools
if matches!(tool.as_str(),
    "screenshot" | "screen_capture" | "capture_screen" | "ocr"
    | "screen_record"
) { /* extract region/type, return ScreenCapture */ }
```

These heuristics follow the same best-effort pattern as the existing
`extract_action` logic. Tools that don't match fall through to `McpTool`.

### 2.4 `filesystem_path` extension

Add a `target_url` accessor for `BrowserAction` and a `desktop_target`
accessor for `DesktopAction` to parallel `filesystem_path`:

```rust
impl ToolAction {
    pub fn target_url(&self) -> Option<&str> {
        match self {
            Self::BrowserAction(url, _) => Some(url.as_str()),
            _ => None,
        }
    }

    pub fn desktop_target(&self) -> Option<&str> {
        match self {
            Self::DesktopAction(_, Some(target)) => Some(target.as_str()),
            _ => None,
        }
    }
}
```

---

## 3. Platform Target Mapping

The three CUA guards and three new action types map to Chio's platform targets
as follows:

### 3.1 Desktop agents (Claude Desktop, Cursor, Windsurf)

These agents use computer use APIs to control the local desktop. They invoke
tools like `computer_use`, `screenshot`, `keyboard`, `mouse`.

| Guard | Action types handled | Platform behavior |
|-------|---------------------|-------------------|
| `ComputerUseGuard` | All `DesktopAction` variants | Allowlist which desktop action categories the agent can use |
| `InputInjectionGuard` | `DesktopAction(KeyboardInput\|MouseInput\|TouchInput, _)` | Restrict input modalities, require postcondition probes |
| `ScreenCaptureGuard` | `ScreenCapture(*)` | Control capture frequency, region restrictions, OCR extraction |

Desktop agents typically do NOT use remote sessions (no `remote.session.*`
actions), so the `RemoteDesktopSideChannelGuard` is not relevant in this
deployment. Instead, the clipboard/file-transfer/audio channels apply to the
local desktop context.

### 3.2 Browser extensions (agent-controlled browsers)

These agents navigate the web, fill forms, click buttons, and extract content.
They invoke tools like `navigate`, `click_element`, `type_text`, `screenshot`.

| Guard | Action types handled | Platform behavior |
|-------|---------------------|-------------------|
| `BrowserNavigationGuard` (new) | `BrowserAction(Navigate, _)` | Domain allowlist for navigation targets |
| `BrowserInputGuard` (new) | `BrowserAction(Type\|Click\|FormSubmit, _)` | Credential detection in type actions, form submission control |
| `ScreenCaptureGuard` | `ScreenCapture(*)` | Page screenshot control, OCR for sensitive content detection |

Browser agents need guards that the upstream suite does not have: domain allowlisting
for navigation (preventing the agent from visiting arbitrary sites) and
credential detection in form fields (preventing the agent from typing passwords
into phishing pages).

### 3.3 Computer use (Anthropic CUA, remote desktop control)

This is the original upstream deployment target. The agent controls a remote
desktop session via RDP/VNC/etc. All three upstream guards apply directly.

| Guard | Action types handled | Platform behavior |
|-------|---------------------|-------------------|
| `ComputerUseGuard` | All `DesktopAction` variants | Coarse gate on remote session actions |
| `InputInjectionGuard` | `DesktopAction(KeyboardInput\|MouseInput\|TouchInput, _)` | Input modality control + postcondition probes |
| `SideChannelGuard` | `DesktopAction(Clipboard\|FileTransfer\|Audio\|DriveMapping\|Printing\|SessionShare, _)` | Per-channel enable/disable, transfer size limits |
| `ScreenCaptureGuard` | `ScreenCapture(*)` | Capture rate limiting, region control |

---

## 4. Refactoring Plan for Chio's Sync Guard Trait

The upstream `Guard` trait is async (`async fn check`). Chio's kernel `Guard`
trait is synchronous (`fn evaluate`). The existing absorption path from
The upstream-to-Chio adapter (`chio-guards` crate) wraps async guards in sync
implementations. The CUA guards need the same treatment.

### 4.1 Current state

**Upstream:**
```rust
#[async_trait]
pub trait Guard: Send + Sync {
    fn name(&self) -> &str;
    fn handles(&self, action: &GuardAction<'_>) -> bool;
    async fn check(&self, action: &GuardAction<'_>, context: &GuardContext) -> GuardResult;
}
```

**Chio kernel:**
```rust
pub trait Guard: Send + Sync {
    fn name(&self) -> &str;
    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError>;
}
```

Key differences:
1. **No `handles` method in Chio.** Chio guards receive the full `GuardContext`
   and must internally decide whether they apply. They return `Allow` for
   actions they don't govern.
2. **No `GuardAction` dispatch in Chio.** Chio uses `ToolAction` (extracted by
   the host from `ToolCallRequest` fields), not a `GuardAction` enum passed
   to the guard.
3. **Sync vs async.** All three upstream CUA guards perform no I/O in their
   `check` methods -- they do pure in-memory allowlist lookups. The sync
   constraint is not a blocker.

### 4.2 Absorption strategy

Each upstream guard becomes a Chio guard that:

1. Calls `extract_action(ctx.request.tool_name, ctx.request.arguments)` to get
   a `ToolAction`.
2. Pattern-matches on the new `BrowserAction`, `DesktopAction`, or
   `ScreenCapture` variants.
3. Returns `Ok(Verdict::Allow)` for action types it does not govern.
4. Returns `Ok(Verdict::Deny)` for policy violations.

```rust
// Example: ComputerUseGuard adapted for Chio
impl Guard for ComputerUseGuard {
    fn name(&self) -> &str { "computer-use" }

    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        let action = extract_action(&ctx.request.tool_name, &ctx.request.arguments);
        match &action {
            ToolAction::DesktopAction(subtype, _) => {
                let action_key = subtype.to_action_key();
                if self.allowed_set.contains(&action_key) {
                    Ok(Verdict::Allow)
                } else {
                    Ok(Verdict::Deny)
                }
            }
            _ => Ok(Verdict::Allow), // not a CUA action, pass through
        }
    }
}
```

### 4.3 Mapping table

| upstream guard | Chio guard name | `ToolAction` variants consumed |
|------------------|----------------|-------------------------------|
| `ComputerUseGuard` | `ComputerUseGuard` | `DesktopAction(*, _)` |
| `InputInjectionCapabilityGuard` | `InputInjectionGuard` | `DesktopAction(KeyboardInput\|MouseInput\|TouchInput, _)` |
| `RemoteDesktopSideChannelGuard` | `SideChannelGuard` | `DesktopAction(Clipboard\|FileTransfer\|Audio\|DriveMapping\|Printing\|SessionShare, _)` |
| (new) | `BrowserNavigationGuard` | `BrowserAction(Navigate, _)` |
| (new) | `BrowserInputGuard` | `BrowserAction(Type\|Click\|FormSubmit, _)` |
| (new) | `ScreenCaptureGuard` | `ScreenCapture(*)` |

---

## 5. Scoping Model

### 5.1 Domain allowlists for navigation

`BrowserNavigationGuard` enforces a domain allowlist for `BrowserAction::Navigate`
actions. Configuration:

```rust
pub struct BrowserNavigationConfig {
    /// Allowed domain patterns (glob-style: "*.example.com", "docs.rs").
    pub allowed_domains: Vec<String>,
    /// Whether to allow navigation to domains not in the list.
    /// Default: false (fail-closed).
    pub allow_unlisted: bool,
    /// Blocked domain patterns (overrides allowed_domains).
    pub blocked_domains: Vec<String>,
}
```

Domain extraction from the URL uses the same `parse_host_port` logic already
in `action.rs`. The blocked list takes precedence over the allowed list
(deny-overrides-allow). Relative URLs and data URIs are denied by default.

**HushSpec mapping:** This parallels the `egress` rule type. A future HushSpec
extension could express browser navigation allowlists as:

```yaml
browser_navigation:
  allowed_domains:
    - "*.internal.corp"
    - "docs.rs"
  blocked_domains:
    - "*.malware.example"
```

### 5.2 Action-type restrictions

`ComputerUseGuard` restricts which `DesktopActionType` variants are permitted.
This is the direct port of the upstream `allowed_actions` set. Configuration:

```rust
pub struct ComputerUseConfig {
    pub enabled: bool,
    pub mode: EnforcementMode,  // Observe | Guardrail | FailClosed
    pub allowed_action_types: HashSet<DesktopActionType>,
}
```

The `EnforcementMode` enum mirrors the upstream `ComputerUseMode`:
- `Observe`: log all actions, never deny
- `Guardrail`: allow known actions, warn on unknown (default)
- `FailClosed`: allow known actions, deny on unknown

### 5.3 Credential detection in Type actions

`BrowserInputGuard` inspects `BrowserAction(Type, _)` actions for credential
patterns in the typed content. When the agent types into a form field, the
guard checks:

1. **Field name heuristics.** If the target element has a `name` or `id`
   matching password/credential patterns (`password`, `passwd`, `secret`,
   `token`, `api_key`, `ssn`, `credit_card`), the action is flagged.

2. **Content pattern matching.** The typed content is scanned for high-entropy
   strings and known secret formats (API keys, tokens, SSNs, credit card
   numbers) using the same pattern set as `SecretLeakGuard`.

3. **URL context.** If the current page URL does not match the domain
   allowlist, credential entry is denied regardless of field name.

Configuration:

```rust
pub struct BrowserInputConfig {
    /// Deny typing into fields matching these name patterns.
    pub sensitive_field_patterns: Vec<String>,
    /// Deny typing content matching these secret patterns.
    pub credential_patterns: Vec<String>,
    /// Domains where credential entry is permitted (e.g., SSO pages).
    pub credential_allowed_domains: Vec<String>,
}
```

### 5.4 Screen capture controls

`ScreenCaptureGuard` governs all `ScreenCapture` variants:

```rust
pub struct ScreenCaptureConfig {
    pub enabled: bool,
    /// Maximum captures per minute (rate limiting).
    pub max_captures_per_minute: Option<u32>,
    /// Whether OCR extraction is permitted.
    pub allow_ocr: bool,
    /// Whether continuous recording is permitted.
    pub allow_recording: bool,
    /// PII detection on captured content (reuse ResponseSanitizationGuard patterns).
    pub scan_for_pii: bool,
}
```

The rate limit is enforced via an atomic counter, similar to `AgentVelocityGuard`.
This prevents an agent from exfiltrating screen content at high frequency.

---

## 6. WASM Guard Integration

### 6.1 How CUA guards connect to the WASM system

The native guards (section 4) handle the standard 80% of CUA policy. The WASM
guard system handles the custom 20% -- the same split described in
[04-HUSHSPEC-POLICY-INTEGRATION.md](04-HUSHSPEC-POLICY-INTEGRATION.md).

Custom CUA policies as WASM guards:

| Use case | Why native guards can't do it | WASM guard approach |
|----------|------------------------------|---------------------|
| Semantic screen analysis | Native guards see action metadata, not pixels | WASM guard with host function for screen content hash comparison |
| Org-specific URL classification | Domain allowlists are static glob patterns | WASM guard with org's internal URL taxonomy |
| Workflow-aware input policies | Native guards are stateless per-request | WASM guard correlating action sequences (v2, needs persistent state) |
| ML-based anomaly detection on CUA sessions | Requires model inference | WASM guard as glue to host-side ML scorer (v2, needs host functions) |
| Compliance-specific screen redaction | Generic PII patterns miss domain-specific data | WASM guard with industry-specific PII/PHI patterns |

### 6.2 `GuardRequest` enrichment

The `GuardRequest` struct (defined in `chio-wasm-guards/src/abi.rs`) already
carries `action_type` and `extracted_path` fields (added in v1, see
[05-V1-DECISION.md](05-V1-DECISION.md)). For CUA actions, the host must
populate:

```rust
pub struct GuardRequest {
    // ... existing fields ...

    /// For BrowserAction: the target URL.
    /// For DesktopAction: the action target (window title, element ID, etc.).
    /// For ScreenCapture: the capture region descriptor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extracted_target: Option<String>,

    /// CUA-specific: the desktop action subtype.
    /// Values: "keyboard_input", "mouse_input", "touch_input",
    /// "clipboard", "file_transfer", etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_subtype: Option<String>,
}
```

The `action_type` field gains three new values: `"browser_action"`,
`"desktop_action"`, `"screen_capture"`. WASM guards that don't handle CUA
actions check `action_type` and return `Allow` immediately.

### 6.3 Custom CUA policy example

A WASM guard that blocks navigation to internal admin pages:

```rust
// Guest code (compiles to .wasm)
use chio_guard_sdk::prelude::*;

#[chio_guard]
fn evaluate(req: &GuardRequest) -> GuardVerdict {
    if req.action_type.as_deref() != Some("browser_action") {
        return GuardVerdict::Allow;
    }

    let url = match &req.extracted_target {
        Some(u) => u,
        None => return GuardVerdict::Allow,
    };

    if url.contains("/admin") || url.contains("/internal") {
        return GuardVerdict::Deny {
            reason: "Navigation to admin/internal pages is blocked by policy".into(),
        };
    }

    GuardVerdict::Allow
}
```

This follows the same pattern as the example guards in
`examples/guards/enriched-inspector/`.

---

## 7. Priority Ordering

CUA guards slot into the existing pipeline ordering defined in
[04-HUSHSPEC-POLICY-INTEGRATION.md](04-HUSHSPEC-POLICY-INTEGRATION.md):

```
1. HushSpec-compiled guards          (native Rust, fast, standard policy)
2. CUA guards -- native              (native Rust, CUA-specific policy)
3. WASM guards -- custom             (sandboxed, operator-authored)
4. Advisory pipeline                 (non-blocking, always last)
```

Within the CUA guard group (priority 2), the ordering is:

```
2a. ComputerUseGuard       (coarse gate -- deny early, save downstream work)
2b. ScreenCaptureGuard     (capture control -- before input guards)
2c. BrowserNavigationGuard (navigation gate -- before input guards)
2d. InputInjectionGuard    (fine-grained input control)
2e. BrowserInputGuard      (credential detection in browser typing)
2f. SideChannelGuard       (channel-specific controls)
```

Rationale:
- `ComputerUseGuard` runs first because it is the coarse gate. If the action
  category is not permitted, there is no reason to run the specialized guards.
- `ScreenCaptureGuard` runs before input guards because if capture is denied,
  the CUA feedback loop is broken and further input evaluation is moot.
- `BrowserNavigationGuard` runs before `BrowserInputGuard` because if the page
  itself is disallowed, there is no point checking what gets typed into it.
- `SideChannelGuard` runs last because side channels are secondary to the
  primary action flow.

---

## 8. Implementation Phases

### Phase 1: Action taxonomy (no new guards)

- Add `BrowserAction`, `DesktopAction`, `ScreenCapture` variants to `ToolAction`
- Add subtype enums (`BrowserActionType`, `DesktopActionType`, `ScreenCaptureType`)
- Extend `extract_action` with CUA tool name detection
- Add `target_url` and `desktop_target` accessors
- Unit tests for all new extraction paths

### Phase 2: Core CUA guards (direct upstream port)

- `ComputerUseGuard` -- port from the upstream guard suite, adapt to sync `Guard` trait
- `InputInjectionGuard` -- port from the upstream guard suite, map to `DesktopAction` subtypes
- `SideChannelGuard` -- port from the upstream guard suite, map to `DesktopAction` subtypes
- Integration tests with `GuardPipeline`

### Phase 3: Browser and screen guards (new)

- `BrowserNavigationGuard` -- domain allowlist enforcement
- `BrowserInputGuard` -- credential detection, field name heuristics
- `ScreenCaptureGuard` -- rate limiting, OCR control, PII scanning
- Integration tests with full CUA pipeline

### Phase 4: WASM enrichment

- Add `action_subtype` field to `GuardRequest`
- Add `"browser_action"`, `"desktop_action"`, `"screen_capture"` as
  `action_type` values
- Example WASM guard for custom CUA policy
- Documentation

---

## 9. File Changes Required

| File | Change |
|------|--------|
| `crates/chio-guards/src/action.rs` | Add `BrowserAction`, `DesktopAction`, `ScreenCapture` variants and subtype enums. Extend `extract_action`. |
| `crates/chio-guards/src/lib.rs` | Add `pub mod computer_use`, `pub mod input_injection`, `pub mod side_channel`, `pub mod browser_navigation`, `pub mod browser_input`, `pub mod screen_capture`. Re-export guard types. |
| `crates/chio-guards/src/computer_use.rs` | New file. Port of `ComputerUseGuard`. |
| `crates/chio-guards/src/input_injection.rs` | New file. Port of `InputInjectionCapabilityGuard`. |
| `crates/chio-guards/src/side_channel.rs` | New file. Port of `RemoteDesktopSideChannelGuard`. |
| `crates/chio-guards/src/browser_navigation.rs` | New file. `BrowserNavigationGuard`. |
| `crates/chio-guards/src/browser_input.rs` | New file. `BrowserInputGuard`. |
| `crates/chio-guards/src/screen_capture.rs` | New file. `ScreenCaptureGuard`. |
| `crates/chio-guards/src/pipeline.rs` | Register CUA guards in default pipeline at correct priority. |
| `crates/chio-wasm-guards/src/abi.rs` | Add `action_subtype` to `GuardRequest`. Add new `action_type` values. |
| `crates/chio-wasm-guards/src/runtime.rs` | Populate CUA fields in `build_request`. |
| `spec/GUARDS.md` | Document the six new guards. |

---

## 10. Open Questions

1. **Should `BrowserNavigationGuard` live in `chio-guards` or a separate
   `chio-browser-guards` crate?** The browser surface is distinct enough that a
   separate crate might be cleaner. Counter-argument: all guards should live
   together for a unified pipeline.

2. **Postcondition probe verification.** The upstream suite checks for the *presence*
   of a `postcondition_probe_hash` but does not verify it against anything. In
   Chio, should the kernel verify the hash against the receipt log (proving the
   agent actually captured and processed a screenshot)?

3. **Screen capture PII scanning.** If `scan_for_pii` is enabled on
   `ScreenCaptureGuard`, this is a post-invocation concern (scanning the
   captured image after the tool returns). This may belong in
   `PostInvocationPipeline` rather than the pre-dispatch guard.

4. **Rate limiting state.** `ScreenCaptureGuard` rate limiting requires
   per-session state (capture counter + timestamp). The kernel `Guard` trait
   is stateless per the v1 decision. Either use `AtomicU64` counters (like
   `AgentVelocityGuard` does) or defer rate limiting to v2.
