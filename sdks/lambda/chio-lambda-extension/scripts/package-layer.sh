#!/usr/bin/env bash
# Package the chio-lambda-extension binary as an AWS Lambda Extension Layer.
#
# Usage:
#   scripts/package-layer.sh [arm64|x86_64|both]
#
# Output:
#   dist/chio-extension-<arch>.zip
#
# The produced layer zip has the Lambda-required structure:
#   extensions/chio            # the extension binary (registered name = "chio")
#   bin/chio-lambda-extension  # same binary, available on PATH for debugging
#
# The binary is cross-compiled for Linux via Rust targets. This requires the
# matching target to be installed (`rustup target add ...`) and, on macOS,
# a cross-linker. The common paths are:
#
#   brew install filosottile/musl-cross/musl-cross --with-aarch64
#   # or: cargo install cross && cross build --release --target ...
#
# If the toolchain is not available we print a clear error and exit non-zero.
# On CI for Lambda deployments, prefer the `cross` container approach.

set -euo pipefail

ARCH=${1:-both}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$CRATE_DIR/dist"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$CRATE_DIR/../../../target/lambda}"

mkdir -p "$DIST_DIR"

build_for() {
    local arch="$1"
    local rust_target zip_name

    case "$arch" in
        arm64|aarch64)
            rust_target="aarch64-unknown-linux-gnu"
            zip_name="chio-extension-arm64.zip"
            ;;
        x86_64|amd64)
            rust_target="x86_64-unknown-linux-gnu"
            zip_name="chio-extension-x86_64.zip"
            ;;
        *)
            echo "error: unknown architecture '$arch' (expected arm64 or x86_64)" >&2
            return 2
            ;;
    esac

    echo "==> Building chio-lambda-extension for $rust_target"
    if ! rustup target list --installed | grep -q "^${rust_target}$"; then
        echo "error: rust target ${rust_target} is not installed." >&2
        echo "       run: rustup target add ${rust_target}" >&2
        return 3
    fi

    (
        cd "$CRATE_DIR"
        CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
            cargo build --release --target "$rust_target"
    )

    local bin_src="$CARGO_TARGET_DIR/$rust_target/release/chio-lambda-extension"
    if [[ ! -f "$bin_src" ]]; then
        echo "error: expected binary at $bin_src" >&2
        return 4
    fi

    echo "==> Assembling layer zip at $DIST_DIR/$zip_name"
    local stage
    stage="$(mktemp -d)"
    trap 'rm -rf "$stage"' RETURN
    mkdir -p "$stage/extensions" "$stage/bin"
    cp "$bin_src" "$stage/extensions/chio"
    cp "$bin_src" "$stage/bin/chio-lambda-extension"
    chmod 0755 "$stage/extensions/chio" "$stage/bin/chio-lambda-extension"
    (
        cd "$stage"
        zip -qr "$DIST_DIR/$zip_name" extensions bin
    )
    echo "==> Packaged $DIST_DIR/$zip_name"
}

case "$ARCH" in
    both)
        build_for arm64
        build_for x86_64
        ;;
    *)
        build_for "$ARCH"
        ;;
esac

echo "==> Done. Publish with:"
echo "    aws lambda publish-layer-version \\"
echo "      --layer-name chio-kernel-extension \\"
echo "      --description 'Chio protocol kernel as Lambda Extension' \\"
echo "      --zip-file fileb://\$ZIP \\"
echo "      --compatible-architectures arm64 x86_64 \\"
echo "      --compatible-runtimes python3.11 python3.12 python3.13 nodejs20.x nodejs22.x"
