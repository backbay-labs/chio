# chio-envoy-ext-authz

Chio adapter for Envoy's `ext_authz` gRPC filter.

## What it does

`chio-envoy-ext-authz` implements `envoy.service.auth.v3.Authorization/Check`
as a thin shim that translates each Envoy `CheckRequest` into a Chio
`ToolCallRequest`, evaluates it through a pluggable `EnvoyKernel`, and maps the
returned `Verdict` onto a compliant `CheckResponse`.

The `EnvoyKernel` trait is the extension point. Real deployments plug in
`chio-kernel` or `chio-http-core`'s `HttpAuthority`. The crate deliberately
keeps its dependency surface small so the adapter can be linked into any
Envoy-fronted service without pulling in the rest of the Chio substrate.

## Position in the system

```
Envoy proxy (ext_authz filter)
        |  gRPC CheckRequest
  [chio-envoy-ext-authz]
        |  ToolCallRequest
  EnvoyKernel (chio-kernel / HttpAuthority / custom)
        |  Verdict
  CheckResponse -> Envoy
```

## Building

```bash
cargo build -p chio-envoy-ext-authz
cargo test -p chio-envoy-ext-authz
```

## House rules

- No em dashes (U+2014) anywhere in code, comments, or documentation.
- Workspace clippy lints `unwrap_used = "deny"` and `expect_used = "deny"` apply.
- Fail-closed: evaluation errors map to a deny `CheckResponse`, not a
  pass-through.
