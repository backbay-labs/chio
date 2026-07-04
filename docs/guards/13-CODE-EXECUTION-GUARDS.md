# Code Execution and Browser Automation Guards -- Technical Design

> **Depends on**: `docs/guards/01-CURRENT-GUARD-SYSTEM.md` (guard trait and
> pipeline), `crates/guards/chio-guards/src/action.rs` (ToolAction enum)

When an agent invokes a code execution sandbox (E2B, Modal, Code Interpreter)
or controls a headless browser (Playwright, Puppeteer, Anthropic Computer
Use), the blast radius is maximal. Arbitrary code execution grants the agent
Turing-complete capability within the sandbox boundary. Browser automation
grants the agent access to any reachable web service with full interaction
capability. Chio cannot govern what happens inside these environments, but it
can govern the agent's authority to invoke them and constrain the parameters
of invocation.

This document specifies three new guards and two new `ToolAction` variants
for these surfaces.

---

## 1. Threat Model

### 1.1 Code execution surfaces

| Surface | Provider | Risk |
|---------|----------|------|
| Cloud sandbox | E2B, Modal, Replit | Agent runs arbitrary code in a remote VM. Network access, filesystem access, and resource consumption are controlled by the sandbox provider. |
| Local interpreter | Code Interpreter, ipython | Agent runs code on the host or in a lightweight container. Blast radius depends entirely on isolation quality. |
| Raw exec | `subprocess.run`, `os.system` | No sandbox boundary. Full host access. Already covered by `ShellCommandGuard`. |

The key insight: the sandbox itself is a security boundary. Chio does not
replace it. Chio governs the agent's authorization to invoke the sandbox,
constrains invocation parameters (language, network access, execution time),
and produces receipts for audit.

### 1.2 Browser automation surfaces

| Surface | Provider | Risk |
|---------|----------|------|
| Headless browser | Playwright, Puppeteer, Selenium | Agent navigates arbitrary URLs, clicks, types, and extracts content. No pixel-level interaction -- DOM-level control. |
| Browser extension agent | Custom extensions | Agent acts within a browser session, potentially with access to cookies and session state. |
| Computer Use (browser mode) | Anthropic CUA | Pixel-level browser control via screenshot + coordinate input. Covered by doc 08's `DesktopAction` and `ScreenCapture` variants. |

Headless browser automation is distinct from CUA-style browser control.
CUA operates at the pixel/coordinate level (screenshot, click at x,y). Headless
automation operates at the DOM level (navigate to URL, click selector, type
into element). Doc 08 covers CUA. This document covers headless/DOM-level
automation.

### 1.3 What Chio does NOT do

- Chio does not sandbox code. The sandbox provider does.
- Chio does not intercept network traffic inside sandboxes. The sandbox provider's
  network policy does.
- Chio does not parse or execute code. It inspects metadata about the code
  (language, hash, requested capabilities) and the invocation parameters.
- Chio does not inject itself into browser sessions. It governs the tool call
  that launches or controls the browser.

---

## 2. New `ToolAction` Variants

### 2.1 `CodeExecution`

```rust
pub enum ToolAction {
    // ... existing: FileAccess, FileWrite, NetworkEgress,
    //               ShellCommand, McpTool, Patch, Unknown ...
    // ... from doc 08: BrowserAction, DesktopAction, ScreenCapture ...
    // ... from doc 10: DatabaseQuery ...

    /// Sandboxed code execution (interpreter, cloud sandbox, notebook).
    CodeExecution {
        /// Programming language requested (e.g., "python", "javascript", "bash").
        language: String,
        /// SHA-256 hash of the code body. Guards do not see raw code by
        /// default -- they see the hash for receipt correlation. The raw
        /// code is available in the arguments for pattern detection guards
        /// that opt in.
        code_hash: String,
        /// Whether the sandbox has network access enabled.
        network_access: bool,
        /// Maximum execution time in seconds, as requested by the agent.
        max_execution_seconds: Option<u64>,
        /// Sandbox provider identifier (e.g., "e2b", "modal", "code_interpreter").
        sandbox_provider: String,
    },
}
```

### 2.2 `BrowserAction`

Doc 08 defines a `BrowserAction(String, BrowserActionType)` variant for
CUA-level browser interaction. This document uses the same variant but
extends the extraction logic to cover DOM-level automation tools. The variant
definition from doc 08 is unchanged:

```rust
pub enum ToolAction {
    // ...

    /// Browser navigation or interaction (url, action_subtype).
    BrowserAction(String, BrowserActionType),
}
```

The `BrowserActionType` enum from doc 08 already covers the action types
needed for headless automation:

```rust
pub enum BrowserActionType {
    Navigate,       // goto, navigate, open
    Click,          // click element by selector
    Type,           // type into element by selector
    ExecuteScript,  // execute JavaScript
    StorageAccess,  // read/write cookies, localStorage
    FormSubmit,     // submit a form
    Download,       // download a file
    Other(String),  // extension point
}
```

New subtypes for headless-specific actions (not in doc 08):

```rust
pub enum BrowserActionType {
    // ... existing from doc 08 ...

    /// Take a page screenshot (headless browser, not CUA screen capture).
    Screenshot,
    /// Extract page content (innerText, innerHTML, accessibility tree).
    ExtractContent,
    /// Wait for selector/condition (no side effect, but consumes time).
    WaitFor,
}
```

### 2.3 How `extract_action()` Populates These

#### Code execution extraction

Added before the MCP fallback in `extract_action`:

```rust
// Code execution tools
if matches!(
    tool.as_str(),
    "execute_code" | "run_code" | "code_interpreter" | "e2b_execute"
    | "modal_run" | "sandbox_exec" | "notebook_run" | "ipython"
    | "repl" | "eval"
) {
    let language = arguments
        .get("language")
        .or_else(|| arguments.get("lang"))
        .or_else(|| arguments.get("runtime"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_lowercase();

    let code = arguments
        .get("code")
        .or_else(|| arguments.get("source"))
        .or_else(|| arguments.get("input"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let code_hash = sha256_hex(code);

    let network_access = arguments
        .get("network_access")
        .or_else(|| arguments.get("internet"))
        .or_else(|| arguments.get("network"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let max_execution_seconds = arguments
        .get("timeout")
        .or_else(|| arguments.get("max_seconds"))
        .or_else(|| arguments.get("timeout_seconds"))
        .and_then(|v| v.as_u64());

    let sandbox_provider = arguments
        .get("sandbox")
        .or_else(|| arguments.get("provider"))
        .or_else(|| arguments.get("runtime_provider"))
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| infer_provider_from_tool_name(&tool))
        .to_string();

    return ToolAction::CodeExecution {
        language,
        code_hash,
        network_access,
        max_execution_seconds,
        sandbox_provider,
    };
}
```

The `infer_provider_from_tool_name` helper maps tool names to providers:

```rust
fn infer_provider_from_tool_name(tool: &str) -> &str {
    if tool.contains("e2b") { return "e2b"; }
    if tool.contains("modal") { return "modal"; }
    if tool.contains("code_interpreter") || tool.contains("repl") {
        return "code_interpreter";
    }
    "unknown"
}
```

The `sha256_hex` function produces the code hash. Guards that need the raw
code access it via `ctx.request.arguments` directly -- the hash in the
`ToolAction` is for receipt correlation and deduplication.

#### Browser automation extraction

Extended from doc 08's browser tool matching to cover headless automation
tools:

```rust
// Browser automation tools (headless / DOM-level)
if matches!(
    tool.as_str(),
    "browser" | "navigate" | "browse" | "web_browse" | "open_url"
    | "click_element" | "type_text" | "execute_js" | "page_screenshot"
    | "extract_content" | "get_page_content" | "playwright_navigate"
    | "playwright_click" | "playwright_type" | "puppeteer_navigate"
    | "browser_action" | "web_action"
) {
    let url = arguments
        .get("url")
        .or_else(|| arguments.get("uri"))
        .or_else(|| arguments.get("page_url"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let action_type = infer_browser_action_type(&tool, arguments);

    return ToolAction::BrowserAction(url, action_type);
}
```

The `infer_browser_action_type` function:

```rust
fn infer_browser_action_type(tool: &str, args: &Value) -> BrowserActionType {
    // Explicit action field takes precedence.
    if let Some(action) = args
        .get("action")
        .or_else(|| args.get("action_type"))
        .and_then(|v| v.as_str())
    {
        return match action.to_lowercase().as_str() {
            "navigate" | "goto" | "open" => BrowserActionType::Navigate,
            "click" => BrowserActionType::Click,
            "type" | "fill" | "input" => BrowserActionType::Type,
            "screenshot" | "capture" => BrowserActionType::Screenshot,
            "execute_script" | "eval" | "js" => BrowserActionType::ExecuteScript,
            "extract" | "content" | "text" => BrowserActionType::ExtractContent,
            "submit" => BrowserActionType::FormSubmit,
            "download" => BrowserActionType::Download,
            "wait" => BrowserActionType::WaitFor,
            other => BrowserActionType::Other(other.to_string()),
        };
    }

    // Fall back to tool name heuristics.
    if tool.contains("navigate") || tool.contains("browse") || tool.contains("open") {
        BrowserActionType::Navigate
    } else if tool.contains("click") {
        BrowserActionType::Click
    } else if tool.contains("type") || tool.contains("fill") {
        BrowserActionType::Type
    } else if tool.contains("screenshot") {
        BrowserActionType::Screenshot
    } else if tool.contains("extract") || tool.contains("content") {
        BrowserActionType::ExtractContent
    } else if tool.contains("js") || tool.contains("script") {
        BrowserActionType::ExecuteScript
    } else {
        BrowserActionType::Navigate // default for generic "browser" tool
    }
}
```

### 2.4 `ToolAction` accessor extensions

```rust
impl ToolAction {
    // ... existing: filesystem_path, target_url (doc 08), desktop_target (doc 08) ...

    /// Return the sandbox provider for code execution actions.
    pub fn sandbox_provider(&self) -> Option<&str> {
        match self {
            Self::CodeExecution { sandbox_provider, .. } => Some(sandbox_provider.as_str()),
            _ => None,
        }
    }

    /// Return the code hash for code execution actions.
    pub fn code_hash(&self) -> Option<&str> {
        match self {
            Self::CodeExecution { code_hash, .. } => Some(code_hash.as_str()),
            _ => None,
        }
    }
}
```

---

## 3. `CodeExecutionGuard`

### 3.1 Purpose

Pre-invocation guard that governs the agent's authority to execute code in a
sandbox. Enforces language restrictions, network access policy, execution
time limits, dangerous module detection, and sandbox provider scoping.

### 3.2 Configuration

```rust
pub struct CodeExecutionConfig {
    /// Allowed programming languages. If empty, all languages are denied.
    /// Default: ["python"].
    pub allowed_languages: Vec<String>,

    /// Denied programming languages (overrides allowed_languages).
    /// Default: ["bash", "sh", "zsh", "shell"].
    /// Shell execution is governed by ShellCommandGuard, not this guard.
    pub denied_languages: Vec<String>,

    /// Whether sandbox code may access the network.
    /// Default: false. Most code execution tasks do not need network access.
    pub allow_network_access: bool,

    /// Maximum execution time in seconds. If the tool call requests more,
    /// the call is denied. Default: 300 (5 minutes).
    pub max_execution_seconds: u64,

    /// Allowed sandbox providers. If empty, all providers are denied.
    /// Default: ["e2b", "modal", "code_interpreter"].
    pub allowed_providers: Vec<String>,

    /// Dangerous module/import patterns to detect in code body.
    /// Default: see section 3.4.
    pub dangerous_patterns: Vec<String>,

    /// Whether to enforce dangerous pattern detection.
    /// Default: true.
    pub enforce_dangerous_patterns: bool,
}
```

### 3.3 Guard Implementation

```rust
pub struct CodeExecutionGuard {
    config: CodeExecutionConfig,
    dangerous_regexes: Vec<Regex>,
}

impl Guard for CodeExecutionGuard {
    fn name(&self) -> &str {
        "code-execution"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        let action = extract_action(&ctx.request.tool_name, &ctx.request.arguments);

        let (language, network_access, max_seconds, provider) = match &action {
            ToolAction::CodeExecution {
                language,
                network_access,
                max_execution_seconds,
                sandbox_provider,
                ..
            } => (language, network_access, max_execution_seconds, sandbox_provider),
            _ => return Ok(Verdict::Allow), // not a code execution action
        };

        // 1. Provider scoping -- deny unknown/disallowed providers first.
        if !self.config.allowed_providers.iter().any(|p| p == provider) {
            return Ok(Verdict::Deny);
        }

        // 2. Language allowlist -- deny-list overrides allow-list.
        let lang_lower = language.to_lowercase();
        if self.config.denied_languages.iter().any(|d| d == &lang_lower) {
            return Ok(Verdict::Deny);
        }
        if !self.config.allowed_languages.iter().any(|a| a == &lang_lower) {
            return Ok(Verdict::Deny);
        }

        // 3. Network access control.
        if *network_access && !self.config.allow_network_access {
            return Ok(Verdict::Deny);
        }

        // 4. Execution time limit.
        if let Some(requested) = max_seconds {
            if *requested > self.config.max_execution_seconds {
                return Ok(Verdict::Deny);
            }
        }

        // 5. Dangerous pattern detection in code body.
        if self.config.enforce_dangerous_patterns {
            let code = ctx.request.arguments
                .get("code")
                .or_else(|| ctx.request.arguments.get("source"))
                .or_else(|| ctx.request.arguments.get("input"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            for re in &self.dangerous_regexes {
                if re.is_match(code) {
                    return Ok(Verdict::Deny);
                }
            }
        }

        Ok(Verdict::Allow)
    }
}
```

### 3.4 Dangerous Pattern Detection

Default patterns for Python code execution. These target modules and
functions that break the sandbox's intended isolation:

| Pattern | What it catches | Why it is dangerous |
|---------|-----------------|---------------------|
| `\bimport\s+os\b` | `import os` | Filesystem and process access |
| `\bimport\s+subprocess\b` | `import subprocess` | Shell command execution |
| `\bimport\s+socket\b` | `import socket` | Raw network socket access |
| `\bimport\s+shutil\b` | `import shutil` | Filesystem manipulation |
| `\bfrom\s+os\s+import\b` | `from os import ...` | Selective os module import |
| `\bfrom\s+subprocess\s+import\b` | `from subprocess import ...` | Selective subprocess import |
| `\bimport\s+ctypes\b` | `import ctypes` | C FFI, memory manipulation |
| `\bimport\s+importlib\b` | `import importlib` | Dynamic module loading (bypass static analysis) |
| `\b__import__\s*\(` | `__import__('os')` | Dynamic import bypass |
| `\bexec\s*\(` | `exec(...)` | Dynamic code execution (meta-execution inside sandbox) |
| `\beval\s*\(` | `eval(...)` | Dynamic expression evaluation |
| `\bopen\s*\([^)]*['\"]\/etc` | `open('/etc/...')` | Reading system configuration files |
| `\bimport\s+signal\b` | `import signal` | Process signal manipulation |
| `\bimport\s+sys\b.*\bsys\.exit\b` | `sys.exit()` | Process termination |

These patterns are best-effort heuristics, not a security boundary. A
determined attacker can bypass pattern matching through encoding, dynamic
construction, or aliasing. The patterns catch the common case where an LLM
naively generates dangerous code. The sandbox itself is the actual security
boundary.

### 3.5 Relationship to `ShellCommandGuard`

Shell languages (`bash`, `sh`, `zsh`, `shell`) are explicitly denied in
`CodeExecutionGuard.denied_languages`. When an agent requests shell execution
through a code sandbox, the request is denied at the language check -- it
never reaches pattern detection.

Direct shell commands (tool names like `bash`, `shell`, `exec`) are handled by
`ShellCommandGuard` via the `ToolAction::ShellCommand` variant. There is no
overlap: `extract_action` maps `bash` to `ShellCommand`, and `e2b_execute`
to `CodeExecution`. A code execution tool that receives `language: "bash"` is
caught by the language deny-list, not by `ShellCommandGuard`.

### 3.6 Relationship to `EgressAllowlistGuard`

`EgressAllowlistGuard` governs per-connection network egress from tool calls
that make HTTP requests (tool names like `http_request`, `fetch`, `curl`).
It operates on `ToolAction::NetworkEgress(host, port)`.

`CodeExecutionGuard` governs whether the sandbox environment has network
access at all. This is a coarser control: can the sandbox reach the internet?
It operates on the `network_access` boolean in `ToolAction::CodeExecution`.

These are complementary, not overlapping:

```
Agent calls http_request  -->  EgressAllowlistGuard (per-host policy)
Agent calls e2b_execute   -->  CodeExecutionGuard   (sandbox-level network toggle)
```

If the sandbox has network access enabled (and the guard allows it), traffic
inside the sandbox is governed by the sandbox provider's network policy, not
by Chio's `EgressAllowlistGuard`. Chio does not intercept sandbox-internal
traffic.

---

## 4. `BrowserAutomationGuard`

### 4.1 Purpose

Pre-invocation guard that governs headless browser automation. Enforces
domain allowlists for navigation, action-type restrictions for read-only
sessions, credential detection in type actions, and screenshot governance.

### 4.2 Configuration

```rust
pub struct BrowserAutomationConfig {
    /// Allowed domain patterns for navigation (glob-style).
    /// Default: empty (all navigation denied -- fail-closed).
    pub allowed_domains: Vec<String>,

    /// Blocked domain patterns (overrides allowed_domains).
    /// Default: empty.
    pub blocked_domains: Vec<String>,

    /// Whether to allow navigation to domains not in allowed_domains.
    /// Default: false (fail-closed).
    pub allow_unlisted_domains: bool,

    /// Allowed browser action types.
    /// Default: all types. Set to restrict sessions (e.g., read-only).
    pub allowed_action_types: Option<Vec<String>>,

    /// Whether to scan Type action content for credential patterns.
    /// Default: true.
    pub detect_credentials: bool,

    /// Patterns that match sensitive form field selectors.
    /// Default: see section 4.5.
    pub sensitive_field_patterns: Vec<String>,

    /// Maximum screenshots per minute (rate limiting).
    /// Default: None (no limit).
    pub max_screenshots_per_minute: Option<u32>,
}
```

### 4.3 Guard Implementation

```rust
pub struct BrowserAutomationGuard {
    config: BrowserAutomationConfig,
    allowed_globs: Vec<Pattern>,
    blocked_globs: Vec<Pattern>,
    sensitive_field_regexes: Vec<Regex>,
    screenshot_counter: AtomicU64, // packed: count in upper 32, epoch_minute in lower 32
}

impl Guard for BrowserAutomationGuard {
    fn name(&self) -> &str {
        "browser-automation"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        let action = extract_action(&ctx.request.tool_name, &ctx.request.arguments);

        let (url, action_type) = match &action {
            ToolAction::BrowserAction(url, at) => (url.as_str(), at),
            _ => return Ok(Verdict::Allow),
        };

        // 1. Action-type restriction.
        if let Some(ref allowed) = self.config.allowed_action_types {
            let action_key = action_type.to_key();
            if !allowed.iter().any(|a| a == &action_key) {
                return Ok(Verdict::Deny);
            }
        }

        // 2. Domain allowlist for navigation.
        if matches!(action_type, BrowserActionType::Navigate) {
            if !self.is_domain_allowed(url) {
                return Ok(Verdict::Deny);
            }
        }

        // 3. Credential detection in Type actions.
        if matches!(action_type, BrowserActionType::Type) && self.config.detect_credentials {
            if self.has_credential_risk(ctx) {
                return Ok(Verdict::Deny);
            }
        }

        // 4. Screenshot rate limiting.
        if matches!(action_type, BrowserActionType::Screenshot) {
            if let Some(limit) = self.config.max_screenshots_per_minute {
                if self.is_screenshot_rate_exceeded(limit) {
                    return Ok(Verdict::Deny);
                }
            }
        }

        Ok(Verdict::Allow)
    }
}
```

### 4.4 Domain Allowlist

Domain matching uses the same glob-based approach as `EgressAllowlistGuard`.
The blocked list takes precedence (deny-overrides-allow). Domain extraction
reuses the existing `parse_host_port` function from `action.rs`.

```rust
impl BrowserAutomationGuard {
    fn is_domain_allowed(&self, url: &str) -> bool {
        let domain = match extract_domain(url) {
            Some(d) => d.to_lowercase(),
            None => return false, // unparseable URL denied
        };

        // Block list takes precedence.
        for pattern in &self.blocked_globs {
            if pattern.matches(&domain) {
                return false;
            }
        }

        // Allow list.
        if self.config.allow_unlisted_domains {
            return true;
        }

        for pattern in &self.allowed_globs {
            if pattern.matches(&domain) {
                return true;
            }
        }

        false // fail-closed
    }
}
```

Relative URLs and `data:` URIs have no extractable domain and are denied by
default (the `None` branch returns `false`).

Example configuration for a read-only research agent:

```rust
BrowserAutomationConfig {
    allowed_domains: vec![
        "*.wikipedia.org".into(),
        "*.arxiv.org".into(),
        "docs.rs".into(),
        "*.github.com".into(),
    ],
    allowed_action_types: Some(vec![
        "navigate".into(),
        "screenshot".into(),
        "extract_content".into(),
        "wait_for".into(),
    ]),
    detect_credentials: true,
    ..Default::default()
}
```

This agent can navigate and read content on allowed domains but cannot click,
type, submit forms, or execute JavaScript.

### 4.5 Credential Detection in Type Actions

When a `BrowserAction(_, Type)` action is evaluated, the guard inspects two
things:

**Selector heuristics.** The target selector (from `arguments.selector` or
`arguments.element`) is checked against sensitive field patterns:

| Pattern | What it catches |
|---------|-----------------|
| `(?i)(type=["']?password)` | HTML password input fields |
| `(?i)(name=["']?(password\|passwd\|secret\|token\|api.?key\|ssn\|credit.?card))` | Named sensitive fields |
| `(?i)(id=["']?(password\|passwd\|secret\|token\|api.?key\|ssn\|credit.?card))` | ID-based sensitive fields |
| `(?i)(autocomplete=["']?(current-password\|new-password\|cc-number\|cc-csc))` | Autocomplete-annotated fields |
| `(?i)(\\.password\|\\.secret\|\\.token\|\\#password\|\\#secret\|\\#token)` | CSS selector patterns for sensitive fields |

**Content heuristics.** The text being typed (from `arguments.text` or
`arguments.value` or `arguments.content`) is scanned for credential-shaped
strings. This reuses the same pattern set as `SecretLeakGuard` (from doc 07):
API key prefixes (`sk-`, `ghp_`, `AKIA`), high-entropy base64 strings, SSN
format, credit card number format (Luhn check is out of scope for v1).

```rust
impl BrowserAutomationGuard {
    fn has_credential_risk(&self, ctx: &GuardContext) -> bool {
        let args = &ctx.request.arguments;

        // Check selector for sensitive field patterns.
        let selector = args
            .get("selector")
            .or_else(|| args.get("element"))
            .or_else(|| args.get("target"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        for re in &self.sensitive_field_regexes {
            if re.is_match(selector) {
                return true;
            }
        }

        // Check typed content for credential patterns.
        let text = args
            .get("text")
            .or_else(|| args.get("value"))
            .or_else(|| args.get("content"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        has_secret_pattern(text)
    }
}
```

### 4.6 Screenshot Governance

Screenshot rate limiting uses a packed `AtomicU64` counter (same pattern as
`AgentVelocityGuard`). The upper 32 bits store the count, the lower 32 bits
store the epoch minute. When the epoch minute changes, the counter resets.

```rust
impl BrowserAutomationGuard {
    fn is_screenshot_rate_exceeded(&self, limit: u32) -> bool {
        let now_minute = (epoch_seconds() / 60) as u32;
        let current = self.screenshot_counter.load(Ordering::Relaxed);
        let stored_minute = (current & 0xFFFF_FFFF) as u32;
        let stored_count = (current >> 32) as u32;

        if stored_minute != now_minute {
            // New minute -- reset counter.
            let new_val = ((1u64) << 32) | (now_minute as u64);
            self.screenshot_counter.store(new_val, Ordering::Relaxed);
            return false; // first screenshot this minute
        }

        if stored_count >= limit {
            return true; // rate exceeded
        }

        let new_val = (((stored_count + 1) as u64) << 32) | (now_minute as u64);
        self.screenshot_counter.store(new_val, Ordering::Relaxed);
        false
    }
}
```

This prevents high-frequency screenshot exfiltration. A headless browser can
capture screenshots far faster than a human can view them. Rate limiting
bounds the data extraction rate.

For PII scanning of screenshot content, this is a post-invocation concern
(the guard would need to inspect the returned image). Post-invocation
screenshot scanning is deferred to `PostInvocationPipeline` (see doc 08,
section 10, question 3).

### 4.7 Relationship to Doc 08 Guards

| Surface | Guard | `ToolAction` variant |
|---------|-------|----------------------|
| Desktop CUA (pixel-level) | `ComputerUseGuard` (doc 08) | `DesktopAction` |
| Desktop CUA input | `InputInjectionGuard` (doc 08) | `DesktopAction(KeyboardInput\|MouseInput\|TouchInput, _)` |
| Desktop CUA screenshot | `ScreenCaptureGuard` (doc 08) | `ScreenCapture` |
| Headless browser (DOM-level) | `BrowserAutomationGuard` (this doc) | `BrowserAction` |

Both `ScreenCaptureGuard` and `BrowserAutomationGuard` govern screenshots,
but at different abstraction levels. `ScreenCaptureGuard` governs pixel-level
screen captures (full screen, region, OCR). `BrowserAutomationGuard` governs
headless browser page screenshots (a `BrowserActionType::Screenshot` action).

If both guards are registered and a browser screenshot occurs, the tool name
determines which `ToolAction` variant is extracted. A tool called
`screenshot` with no URL context extracts to `ScreenCapture`. A tool called
`page_screenshot` or `browser` with `action: "screenshot"` extracts to
`BrowserAction(_, Screenshot)`.

---

## 5. `SandboxInvocationGuard`

### 5.1 Purpose

Pre-invocation guard that enforces budget and authorization constraints on
sandbox invocations. While `CodeExecutionGuard` inspects what the agent
wants to execute, `SandboxInvocationGuard` enforces how much the agent is
allowed to spend on sandbox usage.

### 5.2 What This Guard Is (and Is Not)

Chio governs the agent's ability to INVOKE the sandbox. It does not replace
the sandbox's own security boundary.

```
Agent                     Chio Kernel                    Sandbox
  |                          |                            |
  |-- tool_call: e2b_exec -->|                            |
  |                          |-- CodeExecutionGuard       |
  |                          |   (language, patterns)     |
  |                          |-- SandboxInvocationGuard   |
  |                          |   (budget, rate, auth)     |
  |                          |                            |
  |                          |-- if allowed: forward ---->|
  |                          |                            |-- sandbox runs code
  |                          |                            |-- sandbox network policy
  |                          |                            |-- sandbox filesystem isolation
  |                          |<-- result --------------------|
  |<-- receipt + result -----|                            |
```

The sandbox is already a security boundary. Chio adds three things the
sandbox does not provide:

1. **Authorization**: Is this agent permitted to invoke this sandbox at all?
   (Capability token scoping.)
2. **Budget enforcement**: Has the agent exceeded its execution time or cost
   allocation? (Cross-invocation state.)
3. **Audit**: A signed receipt recording that the invocation occurred, with
   what parameters, and the outcome. (Receipt log.)

### 5.3 Configuration

```rust
pub struct SandboxInvocationConfig {
    /// Maximum total execution seconds per session.
    /// Once exhausted, all further sandbox invocations are denied.
    /// Default: 3600 (1 hour cumulative).
    pub max_session_execution_seconds: u64,

    /// Maximum execution seconds per individual invocation.
    /// Default: 300 (5 minutes).
    pub max_per_invocation_seconds: u64,

    /// Maximum number of sandbox invocations per session.
    /// Default: 100.
    pub max_invocations_per_session: u64,

    /// Maximum estimated cost per session (in USD cents).
    /// Requires the tool server to report cost estimates.
    /// Default: None (no cost limit).
    pub max_session_cost_cents: Option<u64>,

    /// Maximum concurrent sandbox sessions.
    /// Default: 1.
    pub max_concurrent_sessions: u32,
}
```

### 5.4 Guard Implementation

```rust
pub struct SandboxInvocationGuard {
    config: SandboxInvocationConfig,
    session_seconds_used: AtomicU64,
    session_invocation_count: AtomicU64,
    session_cost_cents: AtomicU64,
    active_sessions: AtomicU32,
}

impl Guard for SandboxInvocationGuard {
    fn name(&self) -> &str {
        "sandbox-invocation"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        let action = extract_action(&ctx.request.tool_name, &ctx.request.arguments);

        let (max_seconds, _provider) = match &action {
            ToolAction::CodeExecution {
                max_execution_seconds,
                sandbox_provider,
                ..
            } => (max_execution_seconds, sandbox_provider),
            _ => return Ok(Verdict::Allow),
        };

        // 1. Invocation count limit.
        let count = self.session_invocation_count.fetch_add(1, Ordering::Relaxed);
        if count >= self.config.max_invocations_per_session {
            self.session_invocation_count.fetch_sub(1, Ordering::Relaxed);
            return Ok(Verdict::Deny);
        }

        // 2. Per-invocation time limit.
        let requested_seconds = max_seconds.unwrap_or(self.config.max_per_invocation_seconds);
        if requested_seconds > self.config.max_per_invocation_seconds {
            self.session_invocation_count.fetch_sub(1, Ordering::Relaxed);
            return Ok(Verdict::Deny);
        }

        // 3. Cumulative session time limit.
        let prev = self.session_seconds_used.fetch_add(requested_seconds, Ordering::Relaxed);
        if prev + requested_seconds > self.config.max_session_execution_seconds {
            self.session_seconds_used.fetch_sub(requested_seconds, Ordering::Relaxed);
            self.session_invocation_count.fetch_sub(1, Ordering::Relaxed);
            return Ok(Verdict::Deny);
        }

        // 4. Concurrent session limit.
        let active = self.active_sessions.fetch_add(1, Ordering::Relaxed);
        if active >= self.config.max_concurrent_sessions {
            self.active_sessions.fetch_sub(1, Ordering::Relaxed);
            self.session_seconds_used.fetch_sub(requested_seconds, Ordering::Relaxed);
            self.session_invocation_count.fetch_sub(1, Ordering::Relaxed);
            return Ok(Verdict::Deny);
        }

        Ok(Verdict::Allow)
    }
}
```

Note: The `active_sessions` counter must be decremented when the sandbox
invocation completes. This requires a post-invocation hook or a completion
callback -- the pre-invocation guard increments on allow, and a paired
post-invocation handler decrements on completion. This is the same pattern
as `AgentVelocityGuard`'s sliding window.

### 5.5 Cost Estimation

When the tool server provides cost estimates (via `arguments.estimated_cost`
or a metadata field), the guard can enforce monetary budgets:

```rust
// 5. Cost limit (when available).
if let Some(max_cost) = self.config.max_session_cost_cents {
    if let Some(cost) = ctx.request.arguments
        .get("estimated_cost_cents")
        .and_then(|v| v.as_u64())
    {
        let prev = self.session_cost_cents.fetch_add(cost, Ordering::Relaxed);
        if prev + cost > max_cost {
            self.session_cost_cents.fetch_sub(cost, Ordering::Relaxed);
            // ... rollback other counters ...
            return Ok(Verdict::Deny);
        }
    }
}
```

Cost estimation is best-effort. Not all sandbox providers report cost
upfront. When no estimate is available, the cost check is skipped (the
time-based limits still apply).

---

## 6. Pipeline Ordering

The three new guards slot into the existing pipeline after the core guards
and before WASM custom guards:

```
1. HushSpec-compiled guards              (native Rust, standard policy)
2. Core guards
   2a. ShellCommandGuard                 (shell commands)
   2b. ForbiddenPathGuard                (filesystem paths)
   2c. EgressAllowlistGuard              (network egress by domain)
   2d. SecretLeakGuard                   (content scanning)
3. Code execution + browser guards
   3a. SandboxInvocationGuard            (budget gate -- deny early if exhausted)
   3b. CodeExecutionGuard                (language, provider, patterns)
   3c. BrowserAutomationGuard            (domain, action type, credentials)
4. CUA guards (from doc 08)
   4a. ComputerUseGuard                  (coarse CUA gate)
   4b. ScreenCaptureGuard                (capture control)
   4c. BrowserNavigationGuard            (CUA browser navigation)
   4d. InputInjectionGuard               (input modality control)
   4e. BrowserInputGuard                 (CUA credential detection)
   4f. SideChannelGuard                  (channel control)
5. WASM guards                           (sandboxed, operator-authored)
6. Advisory pipeline                     (non-blocking)
```

Rationale for group 3 ordering:

- `SandboxInvocationGuard` runs first because it is the cheapest check
  (atomic counter comparisons). If the budget is exhausted, there is no
  reason to run pattern detection or domain matching.
- `CodeExecutionGuard` runs before `BrowserAutomationGuard` because code
  execution has higher blast radius -- deny it first.

---

## 7. Receipt Enrichment

Receipts for code execution and browser automation actions carry additional
fields for audit:

### 7.1 Code execution receipts

```rust
pub struct CodeExecutionReceiptData {
    /// SHA-256 hash of the executed code.
    pub code_hash: String,
    /// Language used.
    pub language: String,
    /// Sandbox provider.
    pub sandbox_provider: String,
    /// Whether network access was granted.
    pub network_access: bool,
    /// Execution time requested (seconds).
    pub requested_seconds: Option<u64>,
    /// Actual execution time (seconds), populated post-invocation.
    pub actual_seconds: Option<u64>,
    /// Guard verdicts that were applied.
    pub guard_verdicts: Vec<(String, Verdict)>,
}
```

The receipt includes the code hash, not the raw code. Audit systems that
need to correlate the hash to actual code must maintain a separate code
store. This is deliberate: receipts are append-only and potentially
replicated. Raw code in receipts creates an unbounded storage problem and
a data sensitivity concern.

### 7.2 Browser automation receipts

```rust
pub struct BrowserAutomationReceiptData {
    /// URL navigated to (for Navigate actions).
    pub url: Option<String>,
    /// Browser action type.
    pub action_type: String,
    /// Selector targeted (for Click/Type actions). Redacted if it
    /// matches sensitive field patterns.
    pub selector: Option<String>,
    /// Whether credential detection triggered (without revealing content).
    pub credential_detection_triggered: bool,
}
```

---

## 8. WASM Guard Extension Points

### 8.1 `GuardRequest` enrichment

The `GuardRequest` struct (in `chio-wasm-guards/src/abi.rs`) gains new
`action_type` values for WASM guards to match on:

| `action_type` value | When set |
|---------------------|----------|
| `"code_execution"` | `ToolAction::CodeExecution { .. }` |
| `"browser_action"` | `ToolAction::BrowserAction(_, _)` |

Additional fields populated for code execution:

```rust
pub struct GuardRequest {
    // ... existing fields ...

    /// For CodeExecution: the programming language.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_language: Option<String>,

    /// For CodeExecution: the sandbox provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_provider: Option<String>,

    /// For CodeExecution: whether network access is requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_network_access: Option<bool>,

    /// For BrowserAction: the action subtype (navigate, click, type, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_action_subtype: Option<String>,
}
```

### 8.2 Custom WASM guard example: organization code policy

```rust
// Guest code (compiles to .wasm)
use chio_guard_sdk::prelude::*;

#[chio_guard]
fn evaluate(req: &GuardRequest) -> GuardVerdict {
    if req.action_type.as_deref() != Some("code_execution") {
        return GuardVerdict::Allow;
    }

    // Organization policy: only Python 3.10+ compatible code,
    // no network access in sandbox, max 60 seconds.
    let lang = req.code_language.as_deref().unwrap_or("unknown");
    if lang != "python" {
        return GuardVerdict::Deny {
            reason: format!("Organization policy: only Python allowed, got {lang}"),
        };
    }

    if req.sandbox_network_access == Some(true) {
        return GuardVerdict::Deny {
            reason: "Organization policy: sandbox network access is prohibited".into(),
        };
    }

    GuardVerdict::Allow
}
```

### 8.3 Custom WASM guard example: browser navigation taxonomy

```rust
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

    // Organization-specific URL taxonomy: block social media,
    // allow internal tools and documentation.
    let blocked_patterns = [
        "facebook.com", "twitter.com", "x.com",
        "instagram.com", "tiktok.com", "reddit.com",
    ];

    for pattern in &blocked_patterns {
        if url.contains(pattern) {
            return GuardVerdict::Deny {
                reason: format!("Organization policy: social media ({pattern}) blocked"),
            };
        }
    }

    GuardVerdict::Allow
}
```

---

## 9. Implementation Phases

### Phase 1: Action taxonomy

- Add `CodeExecution` variant to `ToolAction` enum in `action.rs`
- Add `Screenshot`, `ExtractContent`, `WaitFor` to `BrowserActionType` (doc 08
  defines the base enum; this phase adds headless-specific subtypes)
- Extend `extract_action` with code execution and headless browser tool detection
- Add `sandbox_provider` and `code_hash` accessors to `ToolAction`
- Unit tests for all new extraction paths

### Phase 2: `CodeExecutionGuard`

- Implement `CodeExecutionGuard` with language allowlist, network control,
  time limits, and dangerous pattern detection
- Default configuration targeting Python-only, no network, 5-minute limit
- Integration tests with `GuardPipeline`

### Phase 3: `BrowserAutomationGuard`

- Implement domain allowlist (reuse `glob::Pattern` from `EgressAllowlistGuard`)
- Implement action-type restrictions for read-only sessions
- Implement credential detection (selector heuristics + content patterns)
- Implement screenshot rate limiting (atomic counter)
- Integration tests

### Phase 4: `SandboxInvocationGuard`

- Implement budget enforcement (cumulative time, invocation count, cost)
- Implement concurrent session limiting
- Post-invocation decrement hook for active session counter
- Integration tests

### Phase 5: WASM enrichment

- Add `code_language`, `sandbox_provider`, `sandbox_network_access`,
  `browser_action_subtype` fields to `GuardRequest`
- Add `"code_execution"` and `"browser_action"` as `action_type` values
- Example WASM guards for organization code policy and URL taxonomy

---

## 10. File Changes Required

| File | Change |
|------|--------|
| `crates/guards/chio-guards/src/action.rs` | Add `CodeExecution` variant. Add `Screenshot`, `ExtractContent`, `WaitFor` to `BrowserActionType`. Extend `extract_action`. Add accessors. |
| `crates/guards/chio-guards/src/lib.rs` | Add `pub mod code_execution`, `pub mod browser_automation`, `pub mod sandbox_invocation`. Re-export guard types. |
| `crates/guards/chio-guards/src/code_execution.rs` | New file. `CodeExecutionGuard`. |
| `crates/guards/chio-guards/src/browser_automation.rs` | New file. `BrowserAutomationGuard`. |
| `crates/guards/chio-guards` | New file. `SandboxInvocationGuard`. |
| `crates/guards/chio-guards/src/pipeline.rs` | Register new guards at correct priority (group 3). |
| `crates/guards/chio-wasm-guards/src/abi.rs` | Add code execution and browser fields to `GuardRequest`. |
| `crates/guards/chio-wasm-guards/src/runtime.rs` | Populate new fields in `build_request`. |

---

## 11. Open Questions

1. **Code hash verification.** Should the kernel maintain a code content
   store keyed by hash, so that receipts can be correlated to actual code
   for post-hoc audit? Or is this the responsibility of the tool server?

2. **Sandbox completion callbacks.** `SandboxInvocationGuard` needs to
   decrement `active_sessions` when a sandbox invocation completes. The
   current `Guard` trait is pre-invocation only. Either add a
   `PostInvocationGuard` trait method, use a separate post-invocation
   pipeline, or rely on the kernel to manage the counter externally.

3. **Browser session state.** Should `BrowserAutomationGuard` track which
   pages the agent has visited in the current session? This would enable
   guards like "the agent may only navigate to URLs linked from already-
   visited pages" (constrained crawling). This requires per-session state,
   which the v1 guard trait does not support.

4. **Multi-language pattern sets.** The default dangerous patterns target
   Python. JavaScript, Ruby, and other languages have different dangerous
   module names. Should `CodeExecutionGuard` maintain per-language pattern
   sets, or should this be delegated to WASM guards with language-specific
   knowledge?

5. **Browser automation vs. CUA overlap.** An agent using Playwright
   inside a CUA session (pixel-level control of a browser) would trigger
   both `BrowserAutomationGuard` (if the tool name matches) and
   `ComputerUseGuard` (if the CUA tool name matches). The `extract_action`
   heuristic determines which variant is produced. Should there be an
   explicit disambiguation rule, or is the current "tool name determines
   variant" approach sufficient?
