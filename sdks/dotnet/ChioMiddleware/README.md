# Backbay.Chio.Middleware

ASP.NET Core middleware for the [Chio protocol](../../../spec/PROTOCOL.md).
Protects any ASP.NET Core request pipeline with capability validation
and receipt-signed responses served by the Chio sidecar kernel.

## Overview

`Backbay.Chio.Middleware` is the drop-in .NET adapter for Chio. It is
aimed at ASP.NET Core service authors who want every inbound request
evaluated against a capability token and a policy verdict, without
replacing their existing routing or controllers. The middleware is
fail-closed by default: if the sidecar is unreachable, the request is
denied, and allowed requests carry an `X-Chio-Receipt-Id` response
header pointing at the signed receipt.

## Install

```bash
dotnet add package Backbay.Chio.Middleware
```

Targets `net8.0`. Requires a running Chio sidecar (defaults to
`http://127.0.0.1:9090`).

## Quickstart

```csharp
using Backbay.Chio;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddChioProtection();

var app = builder.Build();
app.UseChioProtection();

app.MapGet("/pets", () => new { pets = Array.Empty<object>() });

app.Run();
```

Denied requests receive a structured JSON error body; allowed requests
flow through the pipeline with the receipt id attached to the response.

## Configuration

`AddChioProtection(Action<ChioMiddlewareOptions>)` accepts a configure
callback. The available options are:

| Option              | Purpose                                                            |
| ------------------- | ------------------------------------------------------------------ |
| `SidecarUrl`        | Sidecar base URL; defaults to `CHIO_SIDECAR_URL` env var.          |
| `TimeoutSeconds`    | Sidecar HTTP timeout (default `5`).                                |
| `OnSidecarError`    | Reserved no-op setting. Sidecar errors always fail closed.         |
| `IdentityExtractor` | Custom caller extraction; defaults to header-based extraction.     |
| `RouteResolver`     | Map `(method, path)` to a route pattern such as `/pets/{petId}`.   |

```csharp
builder.Services.AddChioProtection(opts =>
{
    opts.SidecarUrl = "http://127.0.0.1:9090";
    opts.OnSidecarError = "deny";
    opts.RouteResolver = (method, path) =>
        path.StartsWith("/pets/") ? "/pets/{petId}" : path;
});
```

## Example

A richer end-to-end example with controllers and a custom identity
extractor lives in
[`examples/hello-dotnet`](../../../examples/hello-dotnet/). It drives
traffic through the sidecar and prints the returned receipts.

## Status

Version `0.1.0`, pre-1.0. Wire formats track the Chio `0.1.x` sidecar
contract. The API surface may evolve in minor versions before the `1.0`
stability freeze.
