# ADR: Canonical Type Evolution for ToolAction and Constraint

> **Addresses**: Cross-doc type drift.
> Multiple docs independently redefine `ToolAction` and `Constraint` enums
> in incompatible shapes. This ADR establishes the canonical definitions
> and the process for evolving them.

## Problem

The documentation corpus contains 5+ incompatible definitions of new
`ToolAction` variants and `Constraint` variants:

| Doc | ToolAction proposal | Shape |
|-----|---------------------|-------|
| `13-CODE-EXECUTION-GUARDS.md` | `CodeExecution { language, code_hash, ... }` | Struct |
| `SAAS-COMMUNICATION-INTEGRATION.md:84` | `ExternalApiCall { service, action, visibility }` | Struct |
| `DATA-LAYER-INTEGRATION.md:111` | `DatabaseQuery { engine, query, ... }` | Struct |

| Doc | Constraint proposal | Shape |
|-----|---------------------|-------|
| `DATA-LAYER-INTEGRATION.md` | `MaxCostPerQuery(MonetaryAmount)` | Newtype |
| `SAAS-COMMUNICATION-INTEGRATION.md` | `ContentReviewRequired(bool)` | Newtype |
| `STRUCTURAL-SECURITY-FIXES.md` | `MemoryStoreAllowlist(Vec<String>)` | Newtype |
| `ARCHITECTURAL-EXTENSIONS.md` | `ModelConstraint { allowed_models, ... }` | Struct |

If teams execute from different docs, they will produce incompatible code.

## Decision

### 1. Source of Truth

The source of truth for `ToolAction` is `crates/guards/chio-guards/src/action.rs`.
The source of truth for `Constraint` is `crates/core/chio-core-types/src/capability`.

All doc proposals are **design sketches**. They inform the final
implementation but are not the contract. When implementing, the developer
reads the sketch, adapts it to fit the existing enum style, and updates
the canonical file.

### 2. Current State (what is in code today)

**ToolAction** (in `chio-guards/src/action.rs`):

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

Style: tuple variants with positional fields. No struct variants.

**Constraint** (in `chio-core-types/src/capability.rs`):

```rust
pub enum Constraint {
    PathPrefix(String),
    DomainExact(String),
    DomainGlob(String),
    RegexMatch(String),
    MaxLength(usize),
    GovernedIntentRequired,
    RequireApprovalAbove { threshold_units: u64 },
    SellerExact(String),
    MinimumRuntimeAssurance(RuntimeAssuranceTier),
    MinimumAutonomyTier(GovernedAutonomyTier),
    Custom(String, String),
}
```

Style: mix of newtype, unit, and struct variants. Serde-tagged as
`#[serde(tag = "type", content = "value")]`.

### 3. Planned Additions (canonical shapes)

These are the canonical shapes that resolve the cross-doc conflicts.
Implementers should use these, not the individual doc proposals.

**ToolAction additions:**

```rust
pub enum ToolAction {
    // ... existing variants unchanged ...

    /// Code execution in a sandbox (E2B, Modal, Code Interpreter).
    /// (tool_name, language, code_hash, network_access)
    CodeExecution {
        language: String,
        code_hash: String,
        network_access: bool,
    },

    /// Browser automation action (Playwright, Computer Use).
    /// (url_or_selector, action_type)
    BrowserAction {
        action_type: BrowserActionType,
        target: String,
    },

    /// Database query execution.
    /// (engine, query_text, operation_class)
    DatabaseQuery {
        engine: String,
        query: String,
        operation_class: DataOperationClass,
    },

    /// External SaaS API call (Slack, Stripe, PagerDuty, GitHub).
    /// (service_name, action_name, visibility_level)
    ExternalApiCall {
        service: String,
        action: String,
        visibility: Visibility,
    },

    /// Agent memory store write (vector DB upsert, conversation append).
    /// (store_type, key_or_collection, content_hash)
    MemoryWrite {
        store_type: String,
        target: String,
        content_hash: String,
    },
}

#[derive(Clone, Debug)]
pub enum BrowserActionType {
    Navigate,
    Click,
    Type,
    Screenshot,
    Scroll,
    DragDrop,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DataOperationClass {
    ReadOnly,
    Append,
    ReadWrite,
    ReadWriteDelete,
    Admin,
}

#[derive(Clone, Debug)]
pub enum Visibility {
    Internal,
    External,
    Financial,
}
```

Rationale for struct variants (breaking from the original tuple style):
the new action types have 3+ fields. Positional tuples with 3+ fields are
unreadable. Struct variants are self-documenting. The existing tuple
variants should remain as-is for backward compatibility.

**Constraint additions:**

```rust
pub enum Constraint {
    // ... existing variants unchanged ...

    // -- Data layer --
    TableAllowlist(Vec<String>),
    CollectionAllowlist(Vec<String>),
    OperationClass(DataOperationClass),
    MaxRowsReturned(u64),
    MaxBytesScanned(u64),
    MaxCostPerQuery(MonetaryAmount),
    ColumnAllowlist(Vec<String>),
    ColumnDenylist(Vec<String>),
    RequiredFilterPredicate { column: String, expected_value: Option<String> },
    MaxTraversalDepth(u32),
    KeyPatternAllowlist(Vec<String>),

    // -- Communication --
    RecipientAllowlist(Vec<String>),
    ContentReviewRequired,
    MaxRecipientsPerWindow(u64),

    // -- Financial --
    AllowedCurrencies(Vec<String>),

    // -- Model routing --
    ModelConstraint {
        allowed_models: Vec<String>,
        allowed_providers: Vec<String>,
        min_safety_tier: Option<ModelSafetyTier>,
    },

    // -- Memory governance --
    MemoryStoreAllowlist(Vec<String>),
    MaxRetentionTtl(u64),
    MaxMemoryEntries(u64),
}
```

Rationale: follows existing style. Simple constraints use newtype
(`MaxRowsReturned(u64)`). Compound constraints use struct variants
(`RequiredFilterPredicate { ... }`, `ModelConstraint { ... }`). The
`RequireApprovalAbove` struct variant is the precedent.

### 4. Evolution Process

When a new doc proposes a ToolAction or Constraint variant:

1. Check this ADR for the canonical shape
2. If a canonical shape exists, use it
3. If not, propose the shape in the doc AND open a PR adding it to this
   ADR for review before implementation
4. Never implement a variant that contradicts this ADR

### 5. Serde Compatibility

New `Constraint` variants must work with the existing serde tagging:
`#[serde(tag = "type", content = "value", rename_all = "snake_case")]`.

New `ToolAction` variants are internal (not serialized across the wire).
They are derived by `extract_action()` from tool call arguments. No serde
compatibility concern.

### 6. Additional Reconciliation Notes

**Config schema drift**: `UNIFIED-CONFIGURATION.md` describes a config
schema (nested `adapters.mcp/a2a/acp`, `kernel.keypair`, `chio start`)
that does not match the implemented loader in `chio-config/src/schema.rs`
(flat Vec sections, `kernel.signing_key`, no `start` command). The
UNIFIED-CONFIGURATION doc is aspirational, not current. The code in
`chio-config` is the source of truth for what works today.

**HITL approval replay (resolved)**: The kernel now has a single-use
consumption store (`approval_replay_store` on `ChioKernel`) using the
same LRU+TTL pattern as DPoP. Additionally, a lifetime cap
(`MAX_APPROVAL_TTL_SECS = 3600`) rejects tokens with lifetimes exceeding
the store's TTL, ensuring tokens expire before cache eviction can occur.
See `chio-kernel/src/kernel/mod.rs`, steps 7-8 of
`validate_governed_approval_token()`.
