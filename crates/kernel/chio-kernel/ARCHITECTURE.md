# chio-kernel Architecture Notes

## Boundary

`chio-kernel` is the hosted enforcement layer. It validates capabilities,
matches tool grants, applies budget and governed-admission checks, runs guards,
performs runtime admission, dispatches registered tools, reconciles budget
holds, signs receipts, and persists receipt evidence. Portable verifier logic
lives in `chio-kernel-core`; durable storage implementations live in storage
crates such as `chio-store-sqlite`.

## Diagram

```mermaid
flowchart TD
    subgraph agentzone["Untrusted agent"]
        agent["Agent process (no kernel PID, address, or key)"]
    end

    agent -->|"tool call"| transport["Transport (length-prefixed canonical JSON)"]

    subgraph tcb["chio-kernel trusted computing base"]
        estop["Emergency stop and RSS shed"]
        capval["Capability validation (signature, time, revocation, lineage)"]
        grant["Grant matching, DPoP, governed admission"]
        guards["Guard pipeline and runtime admission hook"]
        budget["Budget admission and execution-nonce mint"]
        dispatch["Tool dispatch (per-server budget, bounded stream)"]
        postinv["Post-invocation pipeline (allow, block, redact, escalate)"]
        signing["Receipt signing (WYSIWYS), persist, settle"]
    end

    transport --> estop
    estop -->|"tripped"| signing
    estop -->|"clear"| capval
    capval -->|"deny"| signing
    capval -->|"allow"| grant
    grant -->|"deny"| signing
    grant -->|"allow"| guards
    guards -->|"deny or error"| signing
    guards -->|"allow"| budget
    budget -->|"deny"| signing
    budget -->|"hold"| dispatch
    dispatch --> postinv
    postinv --> signing
    signing -->|"signed receipt"| transport

    subgraph traits["Consumer-supplied traits"]
        authority["CapabilityAuthority and RevocationStore"]
        budgetstore["BudgetStore and PaymentAdapter"]
        toolconn["ToolServerConnection"]
        receiptstore["ReceiptStore"]
    end

    capval -.-> authority
    budget -.-> budgetstore
    dispatch -.-> toolconn
    signing -.-> receiptstore

    capval -.->|"verifier primitives"| core["chio-kernel-core"]

    toolconn --> toolserver["Sandboxed tool servers"]
```

## Module Layout

- `kernel/validation.rs` owns capability issuance and revocation, tool-server
  event drains, portable verdict evaluation, and budget charge/reconcile
  helpers.
- `kernel/error.rs` owns `KernelError` and structured operator error reports.
- `kernel/governed_validation.rs` owns governed transaction admission:
  approval token trust checks, runtime assurance, metered billing, call-chain
  proof checks, autonomy bond checks, and governed call-chain receipt evidence.
- `kernel/dispatch.rs` owns guard evaluation, runtime admission, and tool
  dispatch.
- `budget_store.rs` owns the budget trait, request/decision records, and
  budget commit metadata. `budget_store/in_memory.rs` owns the in-memory
  backend, hold state, idempotent mutation events, and concrete `BudgetStore`
  implementation.
- `receipt_support.rs` owns receipt evidence scopes, governed receipt
  metadata, child receipt helpers, stream receipt content, and receipt
  attribution helpers. `receipt_support/signing.rs` owns the kernel crypto
  floor, hybrid receipt signing entrypoints, and signing backend construction.
- `session.rs` owns session lifecycle state, negotiated peer capabilities,
  in-flight request tracking, subscriptions, terminal request state, session
  anchors, and session-aware kernel responses. `session/tests.rs` owns the
  session unit tests.

## Security And API Constraints

- Capability validation, governed-admission checks, and budget reconciliation
  must continue to fail closed.
- Approval tokens, runtime-attestation records, call-chain proofs, autonomy
  bonds, and receipt evidence must preserve canonical bytes and verification
  semantics.
- Public kernel and receipt-store APIs must preserve explicit security
  invariants. Settlement observers install only as paired runtimes, and
  unsupported atomic projections fail closed.
