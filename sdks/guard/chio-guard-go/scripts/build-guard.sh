#!/usr/bin/env bash
set -euo pipefail

# Build a Chio guard from Go source to a WASM Component Model binary.
#
# Full pipeline: wit-bindgen-go -> TinyGo wasip2 -> wasi-virt -> component
#
# Prerequisites:
#   - Go 1.24+ with wit-bindgen-go tool dependency
#   - TinyGo 0.34+ (install: brew install tinygo)
#   - wasi-virt (install: cargo install --git https://github.com/bytecodealliance/wasi-virt)
#   - wasm-tools (install: cargo install --locked wasm-tools@1.225.0)
#   - wkg (install: cargo install wkg)
#
# Usage:
#   ./scripts/build-guard.sh                  # builds examples/tool-gate/
#   ./scripts/build-guard.sh path/to/guard/   # builds a custom guard

cd "$(dirname "$0")/.."

GUARD_DIR="${1:-./examples/tool-gate/}"
GUARD_NAME="$(basename "$GUARD_DIR")"

echo "==> Building guard: ${GUARD_NAME}"
echo "    Source: ${GUARD_DIR}"
echo ""

# ---------------------------------------------------------------
# Step 1: Generate Go bindings from WIT
# ---------------------------------------------------------------
echo "==> Step 1: Generating Go bindings from WIT..."
bash scripts/generate-types.sh

# ---------------------------------------------------------------
# Step 2: Create dist/ directory
# ---------------------------------------------------------------
echo "==> Step 2: Preparing dist/ directory..."
mkdir -p dist

# ---------------------------------------------------------------
# Step 3: Compile with TinyGo to wasip2 target
# ---------------------------------------------------------------
echo "==> Step 3: Compiling with TinyGo (target=wasip2)..."

if ! command -v tinygo &> /dev/null; then
    echo "ERROR: TinyGo not found."
    echo "Install: brew install tinygo"
    echo "    or: https://tinygo.org/getting-started/install/"
    exit 1
fi

tinygo build \
    -tags=chio_guard_generated \
    -target=wasip2 \
    -no-debug \
    --wit-package dist/chio-guard-go.wasm \
    --wit-world guard \
    -o "dist/${GUARD_NAME}-raw.wasm" \
    "${GUARD_DIR}"

echo "    Raw WASM: dist/${GUARD_NAME}-raw.wasm ($(du -h "dist/${GUARD_NAME}-raw.wasm" | cut -f1))"

# ---------------------------------------------------------------
# Step 4: Strip WASI imports with wasi-virt
# ---------------------------------------------------------------
echo "==> Step 4: Stripping WASI imports with wasi-virt..."

if ! command -v wasi-virt &> /dev/null; then
    echo "ERROR: wasi-virt not found."
    echo "Install: cargo install --git https://github.com/bytecodealliance/wasi-virt"
    exit 1
fi

wasi-virt "dist/${GUARD_NAME}-raw.wasm" -o "dist/${GUARD_NAME}.wasm"

echo "    Final WASM: dist/${GUARD_NAME}.wasm ($(du -h "dist/${GUARD_NAME}.wasm" | cut -f1))"

# ---------------------------------------------------------------
# Step 5: Verify zero imports
# ---------------------------------------------------------------
echo "==> Step 5: Verifying component imports..."

if command -v wasm-tools &> /dev/null; then
    IMPORTS=$(wasm-tools component wit "dist/${GUARD_NAME}.wasm" 2>&1 | grep "^  import" || true)
    if [ -z "$IMPORTS" ]; then
        echo "    PASS: Component has zero imports."
    else
        echo "    WARNING: Component still has imports:"
        echo "$IMPORTS"
        echo "    The Chio guard host may reject this component."
    fi
else
    echo "    SKIP: wasm-tools not found (install: cargo install --locked wasm-tools@1.225.0)"
    echo "    Cannot verify zero-import property."
fi

# ---------------------------------------------------------------
# Step 6: Print output summary
# ---------------------------------------------------------------
echo ""
echo "==> Build complete."
echo "    Output: dist/${GUARD_NAME}.wasm"
ls -lh "dist/${GUARD_NAME}.wasm"
echo ""
echo "    Load this guard into the Chio kernel with:"
echo "      chio guard install dist/${GUARD_NAME}.wasm"
