# Chio Runtime Boundaries

This document records the ownership seams introduced in phase `180` so later
runtime work has a stable place to land and the largest entrypoints do not
quietly collapse back into monolithic shells.

## Ownership Map

| Surface | Runtime shell responsibility | Extracted boundary |
| --- | --- | --- |
| `crates/protocol/chio-mcp-remote/src/remote_mcp/http_service.rs` | hosted MCP session lifecycle, auth, edge routing, and transport orchestration | `crates/protocol/chio-mcp-remote/src/remote_mcp/admin.rs` owns remote admin routes, admin-only storage access, and session trust control handlers |
| `crates/platform/chio-control-plane/src/trust_control.rs` | trust-service routing, issuance, registry operations, remote client entrypoints, and cluster coordination | `crates/platform/chio-control-plane/src/trust_control/health.rs` owns health-report composition and cluster health projection; `crates/platform/chio-control-plane/src/federation_policy.rs` owns the bounded federation-policy model; `crates/platform/chio-control-plane/src/scim_lifecycle.rs` owns the bounded SCIM lifecycle model |
| `crates/protocol/chio-mcp-edge/src/runtime.rs` | `ChioMcpEdge` state machine, task orchestration, runtime event forwarding, and inbound loop control | `crates/protocol/chio-mcp-edge/src/runtime/protocol.rs` owns JSON-RPC shaping, task/result metadata, transport glue, pagination, and capability selection helpers |
| `crates/kernel/chio-kernel/src/lib.rs` | kernel policy flow, dispatch, receipt persistence, checkpoint triggering, and public crate surface | `crates/kernel/chio-kernel/src/receipt_support/mod.rs` owns the receipt facade; `crates/kernel/chio-kernel/src/receipt_support/receipt_metadata.rs`, `receipt_content.rs`, `receipt_scopes.rs`, and `receipt_building.rs` own typed receipt helpers; `crates/kernel/chio-kernel/src/request_matching.rs` owns session request tracking plus capability and constraint matching |

## Layering Rules

- `chio-cli` stays a shell. `crates/products/chio-cli/src/main.rs` re-exports runtime
  surfaces from `chio-hosted-mcp` and `chio-control-plane` instead of inlining
  additional giant modules.
- `chio-mcp-remote` owns the remote MCP HTTP edge. `chio-hosted-mcp`
  remains a compatibility crate that re-exports the remote server entrypoint.
- `chio-control-plane` owns the trust-control service directly: the
  `trust_control` module and its submodule tree live in
  `crates/platform/chio-control-plane/src/`, and `chio-cli` re-exports them rather than
  the library reaching back into the binary crate's source.
- `chio-mcp-edge` keeps protocol glue separate from the runtime loop so JSON-RPC
  behavior can change without widening the edge state machine.
- `chio-kernel` keeps receipt construction and request matching separate from
  the main kernel flow so policy and dispatch changes do not hide low-level
  security drift.

## Implementation-Linked Verified Core Boundary

The current implementation-linked verified-core contract is defined
machine-readably in `formal/proof-manifest.toml`. It names the pure Rust
symbols, root-imported Lean modules, P1-P10 theorem coverage, audited external
assumptions, and Rust verification lanes that participate in the current
formal-evidence story.

### Covered Pure Core

| Rust surface | Why it is inside the current boundary |
| --- | --- |
| `chio_kernel_core::capability_verify::{verify_capability, verify_capability_with_trusted}` | pure issuer-trust, signature, and time-window checks over one in-memory capability |
| `chio_kernel_core::scope::{resolve_matching_grants, resolve_capability_grants}` | fail-closed portable scope matching over request arguments only |
| `chio_kernel_core::evaluate::evaluate` | pure authorization path that composes capability verification, subject binding, scope match, and sync guards |
| `chio_kernel_core::receipts::sign_receipt` | pure receipt-signing step over an already-constructed receipt body |

### Covered Shell Entry Points

| Shell surface | Covered part |
| --- | --- |
| `chio_kernel::ChioKernel::evaluate_portable_verdict` | direct delegation into `chio_kernel_core::evaluate` with trusted issuer and portable guard wiring |
| `chio_kernel::ChioKernel::build_and_sign_receipt` | direct delegation into `chio_kernel_core::sign_receipt` after the shell has assembled the receipt body |

### Audited Assumptions And Exclusions

The current verified-core boundary proves Chio's own pure protocol decisions
and treats these concrete effects as audited assumptions rather than
first-principles theorems:

- concrete Ed25519, SHA-256, canonical JSON, TLS, OS clock, SQLite, chain, and
  hosted-registry implementations
- async scheduling, network delivery, subprocess effects, and tool-server
  behavior after the verified decision core allows a call
- cluster consensus, external settlement rails, and third-party registry
  availability beyond fail-closed Chio handling
- Aeneas extraction from production `chio-kernel-core` modules until the pilot
  promotion criteria pass

Those assumptions are published in `formal/assumptions.toml`. Creusot/Kani
strict lanes are declared in `formal/rust-verification`, and the active Aeneas
pilot lives in `formal/aeneas`.

## Regression Guard

`crates/platform/chio-control-plane/tests/runtime_boundaries.rs` is the source-shape
guard for this boundary. It verifies:

- the extracted ownership files exist
- the main CLI entrypoint still re-exports hosted/control-plane crates
- the runtime shells stay below the line-count ceilings captured in phase `180`
- this document remains present as the human-readable ownership map
