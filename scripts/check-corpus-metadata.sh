#!/usr/bin/env bash
# scripts/check-corpus-metadata.sh - assert that fuzz/corpus_metadata.toml
# indexes every seed under fuzz/corpus/.
#
# Schema (TOML) consumed by this script:
#
#   schema_version = 1
#
#   [[seed]]
#   target    = "<fuzz_target_name>"            # e.g. "wasm_guard_escape"
#   path      = "fuzz/corpus/<target>/<file>"   # repo-relative
#   sha256    = "<64 hex>"                      # sha256 of file bytes
#   source    = "<source>"                      # see SOURCES below
#   class     = "<adversarial class>"           # optional; non-empty means adversarial-tagged
#   threat_id = "<threat-model id>"             # optional; non-empty means cites a threat
#
# Sources are an enum:
#   hand_curated_coverage      libFuzzer or proptest seed shipped by hand
#   libfuzzer_crash            crash file promoted via promote_fuzz_seed.sh --mode libfuzzer
#   adversarial_curated        hand-written adversarial vector
#   adversarial_promoted       crash promoted via promote_fuzz_seed.sh --mode adversarial
#   m03_counterexample         minimised counterexample from chio-policy proptests
#   m02_verdict_divergence     promoted from cross-SDK verdict divergence
#
# The script enforces, fail-closed:
#   1. Every file under fuzz/corpus/ has exactly one [[seed]] entry.
#   2. Every [[seed]] entry's path resolves to an existing file.
#   3. Every [[seed]] entry has a recognised source.
#   4. Every [[seed]] entry tagged with a class names one of the eight
#      adversarial classes; class without threat_id is rejected and
#      threat_id without class is rejected.
#
# House rules: no em dashes, fail-closed, conventional output.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
METADATA="${REPO_ROOT}/fuzz/corpus_metadata.toml"
CORPUS_ROOT="${REPO_ROOT}/fuzz/corpus"

if [[ ! -f "${METADATA}" ]]; then
    echo "check-corpus-metadata: ${METADATA} missing" >&2
    exit 1
fi
if [[ ! -d "${CORPUS_ROOT}" ]]; then
    echo "check-corpus-metadata: ${CORPUS_ROOT} missing" >&2
    exit 1
fi

# Use python3 for TOML parsing (Python 3.11+ ships tomllib in stdlib;
# older Python falls back to a tomli pip dep. We assume a 3.11+ host).
if ! command -v python3 >/dev/null 2>&1; then
    echo "check-corpus-metadata: python3 is required to parse TOML" >&2
    exit 1
fi

python3 - "${METADATA}" "${CORPUS_ROOT}" "${REPO_ROOT}" <<'PY'
import hashlib
import os
import sys

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        sys.stderr.write(
            "check-corpus-metadata: Python 3.11+ (tomllib) or 'tomli' is required\n"
        )
        sys.exit(1)

metadata_path = sys.argv[1]
corpus_root = sys.argv[2]
repo_root = sys.argv[3]

VALID_SOURCES = {
    "hand_curated_coverage",
    "libfuzzer_crash",
    "adversarial_curated",
    "adversarial_promoted",
    "m03_counterexample",
    "m02_verdict_divergence",
}

VALID_CLASSES = {
    "clock_rewound",
    "future_dated",
    "replayed_nonce",
    "partial_signature",
    "scope_superset",
    "revocation_rollback",
    "anchor_grafted",
    "sigstore_bundle_payload_mismatch",
}

with open(metadata_path, "rb") as fh:
    doc = tomllib.load(fh)

errors: list[str] = []

if doc.get("schema_version") != 1:
    errors.append(
        f"schema_version must be 1, got {doc.get('schema_version')!r}"
    )

seeds = doc.get("seed")
if not isinstance(seeds, list):
    errors.append("[[seed]] entries are required")
    seeds = []

paths_seen: dict[str, int] = {}
for idx, entry in enumerate(seeds):
    label = f"seed[{idx}]"
    if not isinstance(entry, dict):
        errors.append(f"{label}: must be a table")
        continue

    target = entry.get("target")
    path = entry.get("path")
    sha256 = entry.get("sha256")
    source = entry.get("source")
    klass = entry.get("class")
    threat_id = entry.get("threat_id")

    for field, val in (
        ("target", target),
        ("path", path),
        ("sha256", sha256),
        ("source", source),
    ):
        if not isinstance(val, str) or not val:
            errors.append(f"{label}: '{field}' must be a non-empty string")

    if isinstance(path, str):
        if path in paths_seen:
            errors.append(
                f"{label}: duplicate path '{path}' (also at seed[{paths_seen[path]}])"
            )
        else:
            paths_seen[path] = idx

        abs_path = os.path.join(repo_root, path)
        if not os.path.isfile(abs_path):
            errors.append(f"{label}: path '{path}' does not exist on disk")
        elif isinstance(sha256, str) and len(sha256) == 64 and all(
            ch in "0123456789abcdef" for ch in sha256
        ):
            with open(abs_path, "rb") as bf:
                actual = hashlib.sha256(bf.read()).hexdigest()
            if actual != sha256:
                errors.append(
                    f"{label}: sha256 mismatch (metadata={sha256}, on-disk={actual})"
                )
        else:
            errors.append(f"{label}: sha256 must be 64 lowercase hex chars")

    if isinstance(source, str) and source not in VALID_SOURCES:
        errors.append(
            f"{label}: source '{source}' not in {sorted(VALID_SOURCES)}"
        )

    has_class = isinstance(klass, str) and klass != ""
    has_threat = isinstance(threat_id, str) and threat_id != ""
    if has_class and klass not in VALID_CLASSES:
        errors.append(
            f"{label}: class '{klass}' not in {sorted(VALID_CLASSES)}"
        )
    if has_class and not has_threat:
        errors.append(f"{label}: class without threat_id is not allowed")
    if has_threat and not has_class:
        errors.append(f"{label}: threat_id without class is not allowed")

    if has_threat and isinstance(threat_id, str):
        if not threat_id or threat_id[0] < "a" or threat_id[0] > "z":
            errors.append(
                f"{label}: threat_id '{threat_id}' must start with a lowercase letter"
            )
        elif not all(ch.islower() or ch.isdigit() or ch == "_" for ch in threat_id):
            errors.append(
                f"{label}: threat_id '{threat_id}' must use [a-z0-9_]"
            )

# Discover every actual seed file on disk and confirm metadata covers it.
on_disk: set[str] = set()
for dirpath, _dirnames, filenames in os.walk(corpus_root):
    for name in filenames:
        if name.startswith("."):
            continue
        full = os.path.join(dirpath, name)
        rel = os.path.relpath(full, repo_root)
        on_disk.add(rel.replace(os.sep, "/"))

indexed = set(paths_seen.keys())
missing = sorted(on_disk - indexed)
extra = sorted(indexed - on_disk)
for m in missing:
    errors.append(f"corpus file '{m}' has no [[seed]] entry")
for e in extra:
    errors.append(f"[[seed]] references missing file '{e}'")

if errors:
    sys.stderr.write("check-corpus-metadata: validation failed:\n")
    for err in errors:
        sys.stderr.write(f"  - {err}\n")
    sys.exit(1)

print(f"check-corpus-metadata: ok ({len(seeds)} seeds indexed across {len({s.split('/')[2] for s in indexed if s.startswith('fuzz/corpus/')})} corpora)")
PY
