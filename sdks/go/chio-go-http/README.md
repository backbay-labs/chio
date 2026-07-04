# chio-go-http

Go `net/http` middleware for the [Chio protocol](../../../spec/PROTOCOL.md).
Wraps any `http.Handler` with capability-based access control and
receipt-signed responses served by the Chio sidecar kernel.

## Overview

`chio-go-http` is the drop-in Go HTTP adapter for Chio. It is aimed at
service authors who already expose a `net/http` handler and want to gate
every request through a capability token plus a policy-evaluated
verdict, without rewriting their routing layer. The middleware is
fail-closed by default: if the sidecar is unreachable, requests are
denied, and allowed requests carry an `X-Chio-Receipt-Id` header pointing
at the signed receipt.

## Install

```bash
go get github.com/backbay-labs/chio/sdks/go/chio-go-http
```

Requires Go 1.21 or newer and a running Chio sidecar (defaults to
`http://127.0.0.1:9090`).

## Quickstart

```go
package main

import (
    "fmt"
    "net/http"

    chio "github.com/backbay-labs/chio/sdks/go/chio-go-http"
)

func handlePets(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintln(w, `{"pets":[]}`)
}

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/pets", handlePets)

    protected := chio.Protect(mux, chio.ConfigFile("chio.yaml"))
    http.ListenAndServe(":8080", protected)
}
```

Denied requests receive a structured JSON error; allowed requests flow
through to your inner handler with the receipt ID attached to the
response headers.

## Configuration

Options are passed via functional `chio.Option` values:

| Option                     | Purpose                                                             |
| -------------------------- | ------------------------------------------------------------------- |
| `ConfigFile(path)`         | Path to `chio.yaml` (routes and policies).                          |
| `WithSidecarURL(url)`      | Override sidecar base URL.                                          |
| `WithTimeout(seconds)`     | Sidecar HTTP timeout (default 5).                                   |
| `WithIdentityExtractor(f)` | Custom caller extraction; defaults to Bearer/API key/Cookie lookup. |
| `WithRouteResolver(f)`     | Map `(method, path)` to a route pattern (e.g. `/pets/{petId}`).     |

Environment variable `CHIO_SIDECAR_URL` is honoured when no explicit
sidecar URL is provided.

## Example

A slightly richer example using a custom route resolver and a shared
sidecar URL:

```go
resolver := func(method, path string) string {
    if strings.HasPrefix(path, "/pets/") {
        return "/pets/{petId}"
    }
    return path
}

protected := chio.Protect(
    mux,
    chio.ConfigFile("chio.yaml"),
    chio.WithSidecarURL("http://127.0.0.1:9090"),
    chio.WithRouteResolver(resolver),
)
```

For a full runnable flow, pair this package with the `examples/hello-tool`
tool server and drive traffic via the Chio CLI or any Chio client.

## Status

Version `0.1.0`, pre-1.0. Wire formats track the Chio `0.1.x` sidecar
contract. The API surface may evolve in minor versions before the `1.0`
stability freeze.
