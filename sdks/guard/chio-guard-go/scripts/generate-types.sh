#!/usr/bin/env bash
set -euo pipefail

# Generate Go bindings from the Chio guard WIT contract.
#
# Prerequisites:
#   - Go 1.24+ (for `go tool` directive)
#   - wit-bindgen-go (installed via `go get -tool go.bytecodealliance.org/cmd/wit-bindgen-go`)
#   - wkg (install: cargo install wkg)
#
# The pipeline:
#   1. wkg wit build -- resolves WASI deps, produces bundled WIT package
#   2. wit-bindgen-go generate -- produces Go bindings in internal/

cd "$(dirname "$0")/.."

echo "==> Step 1: Building WIT package with wkg..."
mkdir -p dist

if command -v wkg &> /dev/null; then
    # Resolve WASI WIT dependencies and bundle into a single WIT package.
    # The -d flag points to our extended WIT directory that includes WASI
    # CLI imports required by TinyGo.
    wkg wit build -d wit/ -o dist/chio-guard-go.wasm
else
    echo "WARNING: wkg not found. Install with: cargo install wkg"
    echo "Attempting direct wit-bindgen-go generation from source WIT..."

    # Fallback: point wit-bindgen-go directly at the canonical WIT.
    # This may fail if WASI types are not resolvable, but works for
    # the core guard types.
    WIT_SOURCE="../../../wit/chio-guard"
fi

echo "==> Step 2: Generating Go bindings with wit-bindgen-go..."
rm -rf internal/

if [ -f dist/chio-guard-go.wasm ]; then
    # Generate from the bundled WIT package (preferred path).
    go tool wit-bindgen-go generate \
        --world guard \
        --out internal \
        dist/chio-guard-go.wasm
else
    # Fallback: generate directly from source WIT directory.
    go tool wit-bindgen-go generate \
        --world guard \
        --out internal \
        "${WIT_SOURCE:-../../../wit/chio-guard}"
fi

echo "==> Generated bindings in internal/:"
find internal/ -name "*.go" -type f | head -20
echo "==> Done."
