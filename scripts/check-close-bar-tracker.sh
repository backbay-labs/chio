#!/usr/bin/env bash
# Trj4 close-bar tracker gate.
#
# Asserts the per-row ledger at .planning/trajectory-4/closeout/CLOSE-BAR-TRACKER.md
# is well-formed and never regresses against the committed snapshot at
# audits/evidence/close-bar-snapshot.json. Emits a structured JSON summary at
# audits/evidence/close-bar-current.json for downstream tooling.
#
# Failure modes (any one fails the gate):
#   1. tracker has fewer than 153 rows;
#   2. any row has Bucket=DONE and Wired runtime path=n (audit's "types-only" pattern);
#   3. any Bucket=DONE row has Negative conformance test=NONE;
#   4. any Bucket=DONE row points at a Negative conformance test file that is missing on disk;
#   5. any Bucket=DONE row points at a Negative conformance test path that is not in the
#      recognised test/evidence allowlist (rejects e.g. Cargo.toml, README.md);
#   6. any Theorem status=proven row points at a missing file;
#   7. any row regresses against the snapshot (DONE -> PARTIAL/NONE, PARTIAL -> NONE).
#
# Environment overrides (used by the integration tests in scripts/tests):
#   CHIO_CLOSE_BAR_TRACKER       path to the tracker markdown
#   CHIO_CLOSE_BAR_SNAPSHOT      path to the snapshot JSON
#   CHIO_CLOSE_BAR_CURRENT_OUT   path to write the current-state JSON

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

TRACKER="${CHIO_CLOSE_BAR_TRACKER:-$REPO_ROOT/.planning/trajectory-4/closeout/CLOSE-BAR-TRACKER.md}"
SNAPSHOT="${CHIO_CLOSE_BAR_SNAPSHOT:-$REPO_ROOT/audits/evidence/close-bar-snapshot.json}"
CURRENT_OUT="${CHIO_CLOSE_BAR_CURRENT_OUT:-$REPO_ROOT/audits/evidence/close-bar-current.json}"
MIN_ROWS="${CHIO_CLOSE_BAR_MIN_ROWS:-153}"

if [[ ! -f "$TRACKER" ]]; then
    echo "ERROR: tracker not found: $TRACKER" >&2
    exit 1
fi
if [[ ! -f "$SNAPSHOT" ]]; then
    echo "ERROR: snapshot not found: $SNAPSHOT" >&2
    exit 1
fi

mkdir -p "$(dirname "$CURRENT_OUT")"

python3 - "$TRACKER" "$SNAPSHOT" "$CURRENT_OUT" "$MIN_ROWS" "$REPO_ROOT" <<'PY'
import fnmatch
import json
import os
import sys

tracker_path, snapshot_path, current_out, min_rows_str, repo_root = sys.argv[1:6]
min_rows = int(min_rows_str)

ALLOWED_BUCKETS = {"DONE", "PARTIAL", "NONE"}
ALLOWED_WIRED = {"y", "n"}
ALLOWED_THEOREM = {"proven", "proposed", "assumed", "n-a"}

# Higher = closer to closure. Used for regression detection.
BUCKET_RANK = {"NONE": 0, "PARTIAL": 1, "DONE": 2}

# Recognised test/evidence path patterns for Negative conformance test cells.
# A DONE row whose path does not match any of these is rejected (rule 5).
# Patterns use fnmatch glob semantics with `**` expanded to match any depth.
ALLOWED_TEST_GLOBS = (
    "crates/*/tests/*.rs",
    "crates/*/tests/*/*.rs",
    "crates/*/tests/*/*/*.rs",
    "crates/*/tests/*/*/*/*.rs",
    "scripts/*.sh",
    "scripts/tests/*.sh",
    "scripts/tests/*.bats",
    "formal/lean4/*.lean",
    "formal/lean4/*/*.lean",
    "formal/lean4/*/*/*.lean",
    "formal/tla/*.tla",
    "formal/tla/*/*.tla",
)


def is_recognised_test_path(path: str) -> bool:
    return any(fnmatch.fnmatchcase(path, pat) for pat in ALLOWED_TEST_GLOBS)


errors = []


def parse_table(text):
    rows = []
    in_table = False
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not cells:
            continue
        # Skip header/sep rows.
        if cells[0] in ("ID",):
            in_table = True
            continue
        if all(set(c) <= set("-: ") for c in cells):
            continue
        if not in_table:
            continue
        if len(cells) < 8:
            errors.append(f"row has {len(cells)} cells, expected 8: {cells!r}")
            continue
        rows.append({
            "id": cells[0],
            "title": cells[1],
            "bucket": cells[2],
            "wired_runtime_path": cells[3],
            "negative_conformance_test": cells[4],
            "theorem_status": cells[5],
            "wave": cells[6],
            "notes": cells[7],
        })
    return rows


with open(tracker_path, "r", encoding="utf-8") as fh:
    tracker_text = fh.read()
rows = parse_table(tracker_text)

# 1. row count
if len(rows) < min_rows:
    errors.append(
        f"tracker has {len(rows)} rows, expected >= {min_rows}"
    )

# id-uniqueness invariant
seen_ids = {}
for r in rows:
    if r["id"] in seen_ids:
        errors.append(f"duplicate id: {r['id']}")
    seen_ids[r["id"]] = r

# per-row well-formedness
for r in rows:
    if r["bucket"] not in ALLOWED_BUCKETS:
        errors.append(f"{r['id']}: bucket {r['bucket']!r} not in {sorted(ALLOWED_BUCKETS)}")
    if r["wired_runtime_path"] not in ALLOWED_WIRED:
        errors.append(f"{r['id']}: wired_runtime_path {r['wired_runtime_path']!r} not in {sorted(ALLOWED_WIRED)}")
    if r["theorem_status"] not in ALLOWED_THEOREM:
        errors.append(f"{r['id']}: theorem_status {r['theorem_status']!r} not in {sorted(ALLOWED_THEOREM)}")

    # 2. DONE + wired=n is the audit's "types-only" pattern
    if r["bucket"] == "DONE" and r["wired_runtime_path"] != "y":
        errors.append(
            f"{r['id']}: Bucket=DONE but Wired runtime path={r['wired_runtime_path']!r} (audit's types-only pattern)"
        )
    # 3. DONE + neg-test=NONE
    if r["bucket"] == "DONE" and r["negative_conformance_test"] == "NONE":
        errors.append(
            f"{r['id']}: Bucket=DONE but Negative conformance test=NONE"
        )
    # 4. DONE + neg-test path missing on disk
    if r["bucket"] == "DONE" and r["negative_conformance_test"] != "NONE":
        rel_path = r["negative_conformance_test"]
        path = os.path.join(repo_root, rel_path)
        if not os.path.isfile(path):
            errors.append(
                f"{r['id']}: Bucket=DONE but Negative conformance test path missing on disk: {rel_path}"
            )
        # 5. DONE + neg-test path not in recognised test/evidence allowlist.
        # Rejects e.g. Cargo.toml, README.md, and other non-test paths so a row
        # cannot be marked DONE with arbitrary file content as the "test".
        if not is_recognised_test_path(rel_path):
            errors.append(
                f"{r['id']}: Bucket=DONE but Negative conformance test path is not a recognised test/evidence path: {rel_path}"
            )
    # 5. theorem proven + missing file
    if r["theorem_status"] == "proven":
        # Proven theorems must point at a real file in Notes (heuristic: first
        # whitespace-separated token containing a slash and ending in .lean).
        # Operators may also write the path directly into the Negative conformance
        # test column when the theorem is the conformance evidence.
        candidate_paths = []
        for col in (r["negative_conformance_test"], r["notes"]):
            for tok in col.split():
                if "/" in tok and tok.endswith(".lean"):
                    candidate_paths.append(tok)
        if not candidate_paths:
            errors.append(
                f"{r['id']}: Theorem status=proven but no .lean path found in Negative conformance test or Notes"
            )
        else:
            ok = False
            for p in candidate_paths:
                if os.path.isfile(os.path.join(repo_root, p)):
                    ok = True
                    break
            if not ok:
                errors.append(
                    f"{r['id']}: Theorem status=proven but no referenced .lean file exists on disk: {candidate_paths!r}"
                )

# 6. snapshot regression check
with open(snapshot_path, "r", encoding="utf-8") as fh:
    snap = json.load(fh)
snap_rows = {r["id"]: r for r in snap.get("rows", [])}
for r in rows:
    sr = snap_rows.get(r["id"])
    if sr is None:
        continue
    cur_rank = BUCKET_RANK.get(r["bucket"], -1)
    snap_rank = BUCKET_RANK.get(sr["bucket"], -1)
    if cur_rank < snap_rank:
        errors.append(
            f"{r['id']}: bucket regressed {sr['bucket']} -> {r['bucket']} relative to snapshot"
        )

# emit current state
out = {
    "schema": "chio.close-bar-current.v1",
    "tracker_path": os.path.relpath(tracker_path, repo_root),
    "snapshot_path": os.path.relpath(snapshot_path, repo_root),
    "row_count": len(rows),
    "bucket_counts": {
        "DONE": sum(1 for r in rows if r["bucket"] == "DONE"),
        "PARTIAL": sum(1 for r in rows if r["bucket"] == "PARTIAL"),
        "NONE": sum(1 for r in rows if r["bucket"] == "NONE"),
    },
    "rows": rows,
    "errors": errors,
}
with open(current_out, "w", encoding="utf-8") as fh:
    json.dump(out, fh, indent=2)
    fh.write("\n")

if errors:
    print("close-bar-tracker gate: FAIL", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    sys.exit(len(errors))

print("close-bar-tracker gate: PASS")
print(f"  rows: {len(rows)}")
print(f"  DONE:    {out['bucket_counts']['DONE']}")
print(f"  PARTIAL: {out['bucket_counts']['PARTIAL']}")
print(f"  NONE:    {out['bucket_counts']['NONE']}")
sys.exit(0)
PY
