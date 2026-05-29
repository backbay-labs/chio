# Releasing `chio-go`

`chio-go` is a Go module rooted at `sdks/go/chio-go`.

## Release Gate

Run both commands from the repo root:

```sh
./scripts/check-chio-go.sh
./scripts/check-chio-go-release.sh
```

The release qualification script verifies:

- `CGO_ENABLED=0` test, vet, and build coverage for the module
- the conformance peer binary installs cleanly
- a separate consumer module can import the SDK and build against it
- version constants are present and exposed through the public module surface

## Tagging

Because this module lives in a repository subdirectory, release tags must use
the subdirectory-prefixed Go module format:

```sh
git tag sdks/go/chio-go/v0.1.0
git push origin sdks/go/chio-go/v0.1.0
```

## Publication Notes

- `chio-go` is currently release-ready beta, not 1.0 stable.
- External publication depends on pushing the correct module tag and allowing
  the Go module proxy/checksum database to observe it.
