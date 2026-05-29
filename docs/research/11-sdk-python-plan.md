# Python SDK Plan

> Historical, pre-rename design note. Paths and names below (for example `packages/sdk/arc-py`) reflect the original ARC-era plan and are kept as a record; they are not current.
> The Python SDK shipped as `chio-sdk` (module `chio`) at `sdks/python/chio-py`.

## Goal

Build a Python SDK that is strong enough to replace the current Python conformance peer and later serve as the maintained Python client for the ARC edge.

The Python plan should optimize for:

- remote-edge usability without a Rust toolchain
- clean packaging and wheel publishing
- optional native acceleration for deterministic helpers
- good typing and project layout from the start

It should not optimize first for:

- bundling the entire Rust runtime into the Python package
- forcing native installation for ordinary remote-edge usage
- mirroring every Rust type through PyO3

## Current Repo Starting Point

Local evidence:

- the current Python peer is hand-rolled in one file and already covers session init, auth, remote HTTP, SSE-style response parsing, nested callbacks, and transcript production: [tests/conformance/peers/python/client.py](../../tests/conformance/peers/python/client.py)
- the current peer requires Python 3.11+: [tests/conformance/peers/python/pyproject.toml](../../tests/conformance/peers/python/pyproject.toml)
- the repo already plans a narrow Rust bindings core rather than a giant FFI layer: [../BINDINGS_CORE_PLAN.md](../operations/BINDINGS_CORE_PLAN.md)

Implication:

- the first Python SDK release should be a pure Python remote-edge package
- the native Rust module should be a separate concern and not block the remote-edge client

## Recommended Product Split

### `arc`

Purpose:

- pure Python remote-edge SDK
- installable anywhere Python itself is supported
- owns session, transport, auth, tasks, and nested callbacks

Should include:

- sync remote-edge client
- shared protocol models and exceptions
- auth helpers
- transcript/debug hooks
- pure Python invariant helpers where practical

### `arc-native`

Purpose:

- optional PyO3-backed accelerator and invariant helper package
- imported opportunistically by `arc`
- not required for remote-edge usage

Should include:

- canonical JSON
- hash helpers
- signature helpers
- receipt verification
- capability and manifest helpers
- optional policy compile or validation helpers if the boundary stays small

Should not include:

- full remote-edge transport
- OAuth flow logic
- callback routers
- the kernel runtime

## Why This Split

The official PyO3 and maturin docs point toward a cleaner extension-module workflow than older feature-based setups:

- PyO3 now prefers build-system configuration over the old `extension-module` feature
- `maturin` automatically handles the extension-module environment variable setup
- `abi3` can be used to ship one wheel for multiple Python versions

At the same time:

- wheel availability is never guaranteed on every platform immediately
- remote-edge clients should not fail to install just because a native wheel is missing

So the safest product model is:

- `arc` pure Python package first
- `arc-native` optional native helper package second

## Recommended Repository Layout

```text
packages/sdk/arc-py/
  pyproject.toml
  src/
    arc/
      __init__.py
      client/
      auth/
      session/
      tasks/
      nested/
      invariants/
      models.py
      errors.py
      py.typed
  tests/

packages/sdk/arc-py/arc-native/
  Cargo.toml
  pyproject.toml
  python/
    arc_native/
      __init__.py
      py.typed
  src/
    lib.rs
```

Alternative:

- publish `arc-native` as a hidden implementation detail loaded by `arc`
- or keep the import path internal as `arc._native`

The public package split still matters even if the internal import name is hidden.

## Packaging Recommendation

### Pure Python package

Use a normal Python build backend for `arc`, for example:

- Hatchling
- setuptools

Reason:

- no Rust build dependency for the main package
- easier editable installs
- easier local testing

### Native package

Use `maturin` for `arc-native`.

Reasons from the official docs:

- it automatically detects `pyo3`
- it supports wheel builds on Windows, Linux, macOS, and FreeBSD
- it supports mixed Rust/Python layouts
- it supports manylinux workflows and Zig-assisted cross-compilation

## PyO3 Recommendation

### Use `abi3`

Recommendation:

- use `abi3`
- choose one minimum Python version explicitly

Initial minimum Python recommendation:

- `abi3-py311`

Why:

- the existing repo peer already requires Python 3.11
- it simplifies the first support matrix
- it avoids claiming Python versions the repo does not currently exercise

If broader distribution becomes important later:

- reconsider `abi3-py310`

### Do not use the deprecated `extension-module` feature in new code

Official PyO3 guidance now says:

- `extension-module` is deprecated
- `maturin >= 1.9.4` sets the needed build environment automatically

Implication:

- the new native package should rely on maturin and build config, not legacy feature flags

### Module naming recommendation

Use a submodule import path to avoid mixed-package confusion:

- public Python package: `arc`
- native module import path: `arc._native`

This follows maturin's documented mixed-project guidance and makes IDEs happier.

## Transport Design

### First release target

The first Python SDK should target the remote HTTP ARC edge.

It should support:

- `initialize`
- `notifications/initialized`
- streamable HTTP response parsing
- session management
- notifications
- tasks
- auth discovery
- nested callbacks

### HTTP client recommendation

Use `httpx`.

Reason:

- modern API
- sync and async support
- better timeout and transport control than the current `urllib` peer
- clean upgrade path from sync to async

### Sync vs async recommendation

Recommendation:

- sync client first
- async client second

Why:

- the current conformance peer is sync
- sync is sufficient to migrate the existing harness behavior
- async is desirable, but not required to prove the package shape

Suggested package shape:

- `arc.client.Client`
- `arc.client.AsyncClient`

with shared models and routing logic beneath them.

## Callback and Session Design

The Python SDK needs first-class support for:

- `sampling/createMessage`
- `elicitation/create`
- `notifications/elicitation/complete`
- `roots/list`

Recommended API model:

- a `Session` object with registered handlers
- explicit callback registration rather than ad hoc monkey-patching
- fail-closed behavior if required handlers are missing

Example shape:

```python
session = client.initialize(
    on_sample=handle_sample,
    on_elicit_form=handle_form,
    on_elicit_url=handle_url,
    on_roots_list=handle_roots,
)
```

The SDK should own:

- session IDs
- protocol version propagation
- nested request routing
- orderly session teardown

## Auth Design

The current peer proves the first two auth modes:

- static bearer
- local OAuth discovery and auth-code flow

Recommended modules:

- `arc.auth.static`
- `arc.auth.protected_resource`
- `arc.auth.oauth_local`
- `arc.auth.pkce`

The auth layer should yield token providers rather than owning the transport outright.

## Invariant Helpers

### Pure Python first

The first `arc` package should have pure Python helpers where practical:

- canonical JSON
- hash helpers
- receipt verification

That is enough to:

- exercise shared vectors
- keep installation simple
- make `arc-native` optional rather than foundational

### Native helper second

The `arc-native` package should then provide:

- faster or byte-authoritative versions of the same helpers
- an import-time optional backend selected by `arc`

Selection model:

- try import `arc._native`
- if unavailable, fall back to pure Python helper implementations

For remote-edge transport:

- never require the native backend

## Type Information

The Python package should ship typing from the first release:

- `py.typed`
- `TypedDict`, `Protocol`, or dataclass-based public models
- `.pyi` files only if runtime code would otherwise become too noisy

Avoid:

- Pydantic as a hard dependency in the first pass

Reason:

- it would force a model framework choice too early
- plain typing plus dataclasses is enough for the first client

## Build and Distribution Recommendation

### Native CI and wheels

For `arc-native`:

- build wheels in CI for Linux, macOS, and Windows
- prefer manylinux-compliant builds for Linux
- use the official maturin workflow patterns

Useful official references:

- manylinux container usage
- `maturin build --release`
- `--zig` for some cross-compile flows

### Source distribution

Both packages should publish sdists.

For `arc-native`, ensure the sdist includes:

- Rust sources
- any generated vector fixtures or schema assets needed at build time
- any Python-side stubs and marker files

## Test Strategy

### Unit tests

Test:

- transport parsing
- session lifecycle
- callback routing
- auth helpers
- pure Python invariant helpers
- optional native backend import and fallback

### Vector tests

Consume the shared Rust-generated fixtures from `tests/bindings/vectors/`.

The Python package should validate:

- canonical JSON
- hash outputs
- receipt verification
- capability and manifest helper behavior if exposed

### Integration tests

Migrate the current Python conformance peer in stages:

1. keep `client.py` as a thin CLI wrapper
2. move protocol logic into `packages/sdk/arc-py`
3. import the package from the wrapper
4. then replace bespoke peer logic with package usage

## Release Strategy

### Alpha 1

Scope:

- pure Python package
- sync client
- current conformance-wave behavior
- transcript/debug support

Success condition:

- the Python conformance peer becomes a thin wrapper around the package

### Alpha 2

Scope:

- typed public API
- pure Python invariant helpers
- better auth and session ergonomics

### Alpha 3

Scope:

- `arc-native`
- optional native helper backend
- wheel CI
- vector-backed parity checks

## Risks

### Risk: native packaging delays the whole SDK

Mitigation:

- keep `arc` pure Python
- make `arc-native` optional

### Risk: mixed Rust/Python layout causes import confusion

Mitigation:

- use the documented `python-source` layout
- import the native module as `arc._native`

### Risk: choosing too old a Python minimum expands the support burden too early

Mitigation:

- start with Python 3.11
- broaden only when there is explicit demand

### Risk: sync and async APIs diverge badly later

Mitigation:

- keep shared protocol models and routing logic under both clients
- delay the async client, but design for it from the start

## Open Questions

- Should the public minimum Python version be 3.11 or 3.10?
- Should `arc-native` be a separate install extra like `arc[native]`, or an internal optional dependency?
- Do we need an async client in the first public alpha, or only after the harness migration?
- Should the native package expose raw helper functions or only a tiny internal backend interface?

## Recommended First Implementation Slice

1. Create `packages/sdk/arc-py` as a pure Python package.
2. Move the current remote HTTP logic out of [tests/conformance/peers/python/client.py](../../tests/conformance/peers/python/client.py) into `client/`, `session/`, and `auth/`.
3. Keep `client.py` as a thin wrapper importing the new package.
4. Add pure Python invariant helpers and vector tests.
5. After the package-backed peer is stable, add `packages/sdk/arc-py/arc-native` using PyO3 and maturin.

## Research Inputs

Local:

- [tests/conformance/peers/python/client.py](../../tests/conformance/peers/python/client.py)
- [tests/conformance/peers/python/pyproject.toml](../../tests/conformance/peers/python/pyproject.toml)
- [../BINDINGS_CORE_PLAN.md](../operations/BINDINGS_CORE_PLAN.md)

External:

- PyO3 building and distribution: <https://pyo3.rs/latest/building-and-distribution.html>
- PyO3 features reference: <https://pyo3.rs/latest/features>
- maturin user guide: <https://www.maturin.rs/>
- maturin bindings guide: <https://www.maturin.rs/bindings.html>
- maturin config guide: <https://www.maturin.rs/config>
- maturin distribution guide: <https://www.maturin.rs/distribution.html>
- maturin project layout guide: <https://www.maturin.rs/project_layout>
