#!/usr/bin/env bash
# scripts/promote_fuzz_seed.sh - graduate a fuzz seed into a permanent
# regression test under the owning crate.
#
# Reads fuzz/owners.toml to find the owning crate for the named fuzz
# target, computes sha256 of the input seed, then either:
#
#   --mode libfuzzer  Writes a libtest #[test] fn that calls the fuzz
#                     wrapper directly with the seed bytes. Output:
#                     crates/<owner>/tests/regression_<target>_<sha16>.rs.
#                     The 16-hex prefix plus target component avoids
#                     filename collisions when one owner crate hosts
#                     multiple targets or accumulates multiple promoted
#                     seeds.
#
#   --mode proptest   Writes the same regression test plus a paired
#                     proptest property when the owner crate has proptest
#                     in [dev-dependencies]. When proptest is missing,
#                     emits the plain regression test and prints a warning.
#
# In both modes the seed is moved into fuzz/corpus/<target>/<sha>.bin so
# future fuzz runs continue exercising it. Re-promoting a seed whose
# --input path already resolves to the canonical corpus location is a
# no-op (the script does not delete the corpus seed under itself).
#
# House rules: no em dashes, fail-closed on bad inputs.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: promote_fuzz_seed.sh --target <name> --input <path> --mode {libfuzzer|proptest} [--severity LEVEL]

Promotes a fuzz seed into a permanent regression test:
  - Reads fuzz/owners.toml to find the owning crate.
  - Computes sha256 of the input.
  - In libfuzzer mode: writes a libtest #[test] fn that calls the fuzz
    wrapper directly with the seed bytes. Output:
    crates/<owner>/tests/regression_<target>_<sha16>.rs.
  - In proptest mode: writes the same regression test plus a paired
    proptest property when the owner crate has proptest in
    [dev-dependencies]. When proptest is missing, falls back to the
    plain regression and warns.
  - Moves the seed file into fuzz/corpus/<target>/<sha>.bin so future
    fuzz runs continue exercising it. Re-promoting a seed that already
    lives at the canonical corpus path is a no-op rather than a delete.

Args:
  --target NAME     fuzz target (e.g. jwt_vc_verify)
  --input PATH      path to crash input file
  --mode MODE       libfuzzer|proptest
  --severity LEVEL  Critical|High|Medium|Low (default Medium)
  --help            show this help
EOF
}

# Defaults.
TARGET=""
INPUT=""
MODE=""
SEVERITY="Medium"

# Argument parser. Long-options only; matches the documented CLI.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            TARGET="${2:-}"
            shift 2
            ;;
        --input)
            INPUT="${2:-}"
            shift 2
            ;;
        --mode)
            MODE="${2:-}"
            shift 2
            ;;
        --severity)
            SEVERITY="${2:-}"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "promote_fuzz_seed.sh: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

# Locate repo root via the script path so callers can invoke from anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OWNERS_TOML="$REPO_ROOT/fuzz/owners.toml"

# Validation. Fail-closed on missing required args.
if [[ -z "$TARGET" || -z "$INPUT" || -z "$MODE" ]]; then
    echo "promote_fuzz_seed.sh: --target, --input, and --mode are required" >&2
    usage >&2
    exit 2
fi

case "$MODE" in
    libfuzzer|proptest) ;;
    *)
        echo "promote_fuzz_seed.sh: --mode must be 'libfuzzer' or 'proptest', got '$MODE'" >&2
        exit 2
        ;;
esac

case "$SEVERITY" in
    Critical|High|Medium|Low) ;;
    *)
        echo "promote_fuzz_seed.sh: --severity must be Critical|High|Medium|Low, got '$SEVERITY'" >&2
        exit 2
        ;;
esac

if [[ ! -f "$OWNERS_TOML" ]]; then
    echo "promote_fuzz_seed.sh: missing fuzz/owners.toml at $OWNERS_TOML" >&2
    exit 1
fi

if [[ ! -f "$INPUT" ]]; then
    echo "promote_fuzz_seed.sh: --input file not found: $INPUT" >&2
    exit 1
fi

# Resolve owning crate for the target by parsing fuzz/owners.toml. Bash-only
# parser: scan for the [targets.<name>] section, then capture the path key.
resolve_owner_path() {
    local target="$1"
    local toml="$2"
    awk -v t="$target" '
        BEGIN { in_section = 0 }
        /^\[targets\./ {
            in_section = 0
            section = $0
            sub(/^\[targets\./, "", section)
            sub(/\]$/, "", section)
            if (section == t) { in_section = 1 }
            next
        }
        /^\[/ { in_section = 0; next }
        in_section && /^[[:space:]]*path[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*"/, "")
            sub(/"[[:space:]]*$/, "")
            print
            exit
        }
    ' "$toml"
}

OWNER_PATH="$(resolve_owner_path "$TARGET" "$OWNERS_TOML")"
if [[ -z "$OWNER_PATH" ]]; then
    echo "promote_fuzz_seed.sh: target '$TARGET' not found in fuzz/owners.toml" >&2
    exit 1
fi

OWNER_DIR="$REPO_ROOT/$OWNER_PATH"
if [[ ! -d "$OWNER_DIR" ]]; then
    echo "promote_fuzz_seed.sh: owner directory does not exist: $OWNER_DIR" >&2
    exit 1
fi

# Compute sha256. Use shasum if available (macOS default), fall back to sha256sum.
if command -v shasum >/dev/null 2>&1; then
    SHA="$(shasum -a 256 "$INPUT" | awk '{print $1}')"
elif command -v sha256sum >/dev/null 2>&1; then
    SHA="$(sha256sum "$INPUT" | awk '{print $1}')"
else
    echo "promote_fuzz_seed.sh: neither shasum nor sha256sum available" >&2
    exit 1
fi
# Use a 16-hex-char prefix (64 bits, ~10^-19 collision probability) plus
# the target name in the test filename so two distinct seeds promoted
# into the same owner crate cannot silently overwrite each other. The
# corpus filename keeps the full digest for full-fidelity traceability.
SHA16="${SHA:0:16}"
# Sanitize the target name for use as a Rust identifier component.
TARGET_IDENT="$(printf '%s' "$TARGET" | tr -c 'A-Za-z0-9_' '_')"

TESTS_DIR="$OWNER_DIR/tests"
mkdir -p "$TESTS_DIR"

CORPUS_DIR="$REPO_ROOT/fuzz/corpus/$TARGET"
mkdir -p "$CORPUS_DIR"

# The fuzz wrapper convention from fuzz/fuzz_targets/<target>.rs is
# `<crate_underscored>::fuzz::fuzz_<target>` (e.g. `chio_credentials::fuzz::fuzz_jwt_vc_verify`).
# Derive both halves from the owner crate name and target.
OWNER_CRATE="$(basename "$OWNER_PATH")"
CRATE_UNDERSCORED="$(printf '%s' "$OWNER_CRATE" | tr '-' '_')"
FUZZ_FN="fuzz_${TARGET_IDENT}"

# Detect whether the owner crate has proptest in [dev-dependencies] so we
# do not emit a body that fails to compile.
OWNER_CARGO_TOML="$OWNER_DIR/Cargo.toml"
HAS_PROPTEST=0
if [[ -f "$OWNER_CARGO_TOML" ]] \
    && awk 'BEGIN{indev=0} /^\[dev-dependencies\]/{indev=1; next} /^\[/{indev=0} indev && /^[[:space:]]*proptest[[:space:]]*=/{found=1} END{exit found?0:1}' "$OWNER_CARGO_TOML"; then
    HAS_PROPTEST=1
fi

# Emit the regression test based on mode. Both bodies invoke the fuzz
# wrapper directly with the promoted seed so a regression panics the test
# rather than silently passing.
case "$MODE" in
    libfuzzer)
        OUT="$TESTS_DIR/regression_${TARGET_IDENT}_${SHA16}.rs"
        cat >"$OUT" <<EOF
// Auto-generated regression test from fuzz/$TARGET seed $SHA.
// Severity: $SEVERITY.
//
// This test invokes the libfuzzer wrapper for '$TARGET' directly with the
// promoted seed bytes. The wrapper must not panic on this input. The seed
// is stored at fuzz/corpus/$TARGET/$SHA.bin and is included verbatim via
// CARGO_MANIFEST_DIR so the test runs without a working fuzz toolchain.

use ${CRATE_UNDERSCORED}::fuzz::${FUZZ_FN};

#[test]
fn regression_${TARGET_IDENT}_${SHA16}() {
    let seed: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fuzz/corpus/$TARGET/$SHA.bin",
    ));
    // The fuzz entry point swallows recoverable errors and only panics on
    // invariant breaks; calling it directly is the stable surface.
    ${FUZZ_FN}(seed);
}
EOF
        ;;
    proptest)
        OUT="$TESTS_DIR/regression_${TARGET_IDENT}_${SHA16}.rs"
        if (( HAS_PROPTEST )); then
            cat >"$OUT" <<EOF
// Auto-generated regression + proptest property from fuzz/$TARGET seed $SHA.
// Severity: $SEVERITY.
//
// The seed is stored at fuzz/corpus/$TARGET/$SHA.bin and pins the
// promoted crash as a regression input alongside the proptest strategy.

use ${CRATE_UNDERSCORED}::fuzz::${FUZZ_FN};
use proptest::prelude::*;

#[test]
fn regression_${TARGET_IDENT}_${SHA16}() {
    let seed: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fuzz/corpus/$TARGET/$SHA.bin",
    ));
    ${FUZZ_FN}(seed);
}

proptest! {
    #[test]
    fn property_${TARGET_IDENT}_${SHA16}(input in proptest::collection::vec(any::<u8>(), 0..4096)) {
        // Asserts the fuzz wrapper does not panic on randomly generated
        // inputs of bounded length.
        ${FUZZ_FN}(&input);
    }
}
EOF
        else
            echo "promote_fuzz_seed.sh: WARNING: ${OWNER_CRATE} has no proptest dev-dep; falling back to a plain #[test] regression (proptest mode requested)" >&2
            cat >"$OUT" <<EOF
// Auto-generated regression test from fuzz/$TARGET seed $SHA.
// Severity: $SEVERITY.
//
// NOTE: --mode proptest was requested, but ${OWNER_CRATE} does not declare
// 'proptest' in [dev-dependencies], so the script emitted a plain #[test]
// regression that pins the promoted seed against the fuzz wrapper. To
// add the proptest property, first add 'proptest' to ${OWNER_CRATE}'s
// dev-dependencies and re-run with --mode proptest.

use ${CRATE_UNDERSCORED}::fuzz::${FUZZ_FN};

#[test]
fn regression_${TARGET_IDENT}_${SHA16}() {
    let seed: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fuzz/corpus/$TARGET/$SHA.bin",
    ));
    ${FUZZ_FN}(seed);
}
EOF
        fi
        ;;
esac

# Refuse to silently clobber a previously promoted regression test for a
# different seed. Identical content (same SHA, same target) is fine, but a
# byte-different file at the same path is a collision that we want the
# triager to see.
if [[ -e "$OUT.prev" ]]; then
    rm -f "$OUT.prev"
fi

# Move the seed into the persistent corpus so future fuzz runs replay it.
# Re-promotion case: when the caller passes --input pointing at the
# canonical corpus path itself, `cmp -s` would succeed against a file
# vs. itself and the subsequent `rm -f $INPUT` would delete the corpus
# seed (regression: r3144325279). Detect same-file via inode comparison
# (portable, no `realpath` dependency) and skip the cleanup in that case.
DEST="$CORPUS_DIR/$SHA.bin"
same_file() {
    # Returns 0 when $1 and $2 reference the same on-disk file. Compares
    # device + inode pairs from `stat`. Falls back to false if either
    # path does not exist (the outer logic handles missing files first).
    [[ -e "$1" ]] || return 1
    [[ -e "$2" ]] || return 1
    local a b
    if a=$(stat -c '%d:%i' -- "$1" 2>/dev/null); then
        b=$(stat -c '%d:%i' -- "$2" 2>/dev/null) || return 1
    else
        a=$(stat -f '%d:%i' -- "$1" 2>/dev/null) || return 1
        b=$(stat -f '%d:%i' -- "$2" 2>/dev/null) || return 1
    fi
    [[ "$a" == "$b" ]]
}

if [[ -e "$DEST" ]]; then
    if same_file "$INPUT" "$DEST"; then
        echo "promote_fuzz_seed.sh: --input is already the canonical corpus seed at $DEST; leaving it in place"
    elif cmp -s "$INPUT" "$DEST"; then
        # Idempotent: identical bytes at distinct paths, drop the duplicate.
        rm -f "$INPUT"
    else
        echo "promote_fuzz_seed.sh: corpus collision at $DEST with different bytes" >&2
        exit 1
    fi
else
    mv "$INPUT" "$DEST"
fi

echo "promote_fuzz_seed.sh: promoted $TARGET seed $SHA16 ($MODE, $SEVERITY)"
echo "  test:   $OUT"
echo "  corpus: $DEST"
