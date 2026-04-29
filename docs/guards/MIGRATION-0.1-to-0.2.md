# Migrating Guard Components: `chio:guard@0.1.0` to `chio:guard@0.2.0`

This guide covers the WIT contract bump shipped in M06 Phase 1. Read it
alongside [.planning/trajectory/06-wasm-guard-platform.md](../../.planning/trajectory/06-wasm-guard-platform.md)
Phase 1 and the verbatim 0.2.0 skeleton in `wit/chio-guard/world.wit`.

## TL;DR

The 0.1 -> 0.2 bump is **purely additive**. No existing field is renamed,
removed, or retyped. Existing `evaluate` exports keep compiling; the change
is two new host-imported interfaces and two new `import` lines on the world
block. Guest SDKs only need regeneration to pick up the new host imports.

| Change | Required action |
|--------|-----------------|
| Package version `0.1.0` -> `0.2.0` | Re-pin guest SDK against new world |
| New `interface host` (4 funcs) | Optional: call `host.fetch-blob` if needed |
| New `interface policy-context` with `bundle-handle` resource | Optional: open a bundle to read content-addressed blobs |
| New `import host;` and `import policy-context;` on `world guard` | Regenerate bindings |
| `interface types` (verdict, guard-request) | Unchanged; no source edits required |

## What changed in `wit/chio-guard/world.wit`

### Package version

```wit
// before
package chio:guard@0.1.0;

// after
package chio:guard@0.2.0;
```

### `interface types` (unchanged)

The `verdict` variant and `guard-request` record are byte-for-byte identical
to 0.1.0. Field names, field order, types, optionality, and list element
types are all preserved. A guest that compiled against 0.1.0 will compile
against 0.2.0 without source edits to its `evaluate` body.

### `interface host` (new)

```wit
interface host {
    log: func(level: u32, msg: string);
    get-config: func(key: string) -> option<string>;
    get-time-unix-secs: func() -> u64;
    fetch-blob: func(handle: u32, offset: u64, len: u32) -> result<list<u8>, string>;
}
```

The first three host calls (`log`, `get-config`, `get-time-unix-secs`)
mirror the raw `Linker::func_wrap` registrations that 0.1.0 hosts wired
ad hoc through `crates/chio-wasm-guards/src/host.rs`. The 0.2.0 contract
moves those calls into the WIT-native surface so the four guest SDKs
(Rust, TypeScript via jco, Python via componentize-py, Go via wit-bindgen-go)
all consume the same generated bindings.

`fetch-blob` is new in 0.2.0. It reads bytes from a host-owned content
bundle by `(handle, offset, len)` and returns either the byte slice or a
host-side error string. It is the lower-level counterpart to the
`policy-context::bundle-handle` resource (see below); a guard typically
holds a `bundle-handle` and calls `read` on it, while `fetch-blob` is the
flat-handle form used by code generated against the host trait directly.

### `interface policy-context` (new)

```wit
interface policy-context {
    resource bundle-handle {
        constructor(id: string);
        read: func(offset: u64, len: u32) -> result<list<u8>, string>;
        close: func();
    }
}
```

`bundle-handle` is a wasmtime resource: the host owns the table, the guest
holds a reference. `constructor(id)` opens a bundle by string id (the
content-addressed digest is acceptable). `read(offset, len)` returns up to
`len` bytes starting at `offset`, or an error string. `close()` releases
the slot. The host implementation must drop the entry on `close()` and on
guest-side resource drop.

### `world guard` (additive `import` lines)

```wit
world guard {
    use types.{verdict, guard-request};
    import host;
    import policy-context;
    export evaluate: func(request: guard-request) -> verdict;
}
```

`use types.{verdict, guard-request}` and the `evaluate` export are
byte-identical to 0.1.0. The two new `import` lines are the only additions.

## Host-side migration (kernel operators)

Host wiring migration lands in **M06 P1.T2 and P1.T3**, NOT in this
ticket (P1.T1). The new host trait will be:

```rust
#[wasmtime::component::bindgen(world = "chio:guard/guard@0.2.0", async = true)]
mod bindings {}

#[async_trait::async_trait]
impl bindings::chio::guard::host::Host for GuardHost {
    async fn log(&mut self, level: u32, msg: String) -> wasmtime::Result<()> { /* ... */ }
    async fn get_config(&mut self, key: String) -> wasmtime::Result<Option<String>> { /* ... */ }
    async fn get_time_unix_secs(&mut self) -> wasmtime::Result<u64> { /* ... */ }
    async fn fetch_blob(&mut self, handle: u32, offset: u64, len: u32)
        -> wasmtime::Result<Result<Vec<u8>, String>> { /* ... */ }
}
```

P1.T2 deletes the three `Linker::func_wrap` registrations at
`crates/chio-wasm-guards/src/host.rs` lines 110, 159, and 221, plus the
JSON-serialization shim that compensated for them, and replaces them with
`bindgen!`-generated wiring. P1.T3 lands the `bundle-handle` resource
table and the `fetch-blob` host-call body. P1.T4 adds the `wit_world`
manifest field and a semver gate that rejects 0.1.x components at load
time and points operators back to this guide.

## Guest-side migration (guard authors)

The guest SDK migration train ships in **M06 P1.T5** as a single atomic
PR that bumps Rust, TypeScript, Python, and Go in lockstep:

| SDK        | Package                          | Caller-visible change                                                                   |
|------------|----------------------------------|-----------------------------------------------------------------------------------------|
| Rust       | `chio-guard-sdk` 0.1 -> 0.2      | `host::log/get_config/get_time` keep signatures; new `host::fetch_blob` and `PolicyContext` resource. Macro re-exports unchanged. |
| TypeScript | `@chio-protocol/guard-sdk`       | Regenerated via `jco transpile` against 0.2.0 WIT. `host.fetchBlob()` added; existing imports keep names. |
| Python     | `chio_guard_sdk`                 | Regenerated via `componentize-py bindings`. New `host.fetch_blob()`; everything else stable. |
| Go         | `chio-guard-sdk-go`              | Regenerated via `wit-bindgen-go` (tinygo target). New `host.FetchBlob`; package path unchanged. |

If your guard does not need `fetch-blob` or the `bundle-handle` resource,
the migration is exactly: bump the WIT pin, regenerate bindings, rebuild.
Your `evaluate` body does not change.

## Reserved namespace: `chio:guards@0.1.0`

`wit/chio-guards-redact/world.wit` is committed alongside this bump as a
**namespace placeholder** for M10's redactor host call. It declares
`package chio:guards@0.1.0;` and contains only a comment reserving the
namespace. M10 will land `interface redact { ... }` and
`world redactor { import redact; }` with the
`redact-payload: func(payload: list<u8>, classes: redact-class)`
function additively. M06 does not implement redactors; this guide does
not cover them.

## Compatibility window

The runtime accepts both 0.1.0 and 0.2.0 components during the transition.
Once P1.T4 lands the semver gate, the runtime rejects 0.1.x components
with a structured error pointing at this file. Plan to bump all in-tree
guards to 0.2.0 before P1.T4 ships.

## See also

- `wit/chio-guard/world.wit` (the canonical 0.2.0 source)
- `wit/chio-guards-redact/world.wit` (M10 namespace placeholder)
- `.planning/trajectory/06-wasm-guard-platform.md` Phase 1
- `.planning/trajectory/10-tee-attestation.md` ("Redactor host call shape")
