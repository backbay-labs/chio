#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

case "$(uname -m)" in
  x86_64 | amd64) architecture="x86_64" ;;
  aarch64 | arm64) architecture="aarch64" ;;
  *)
    echo "Unsupported Aeneas test host architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

registry="formal/aeneas/production.toml"
proof="formal/lean4/Chio/Chio/Proofs/AeneasGeneratedEquivalence.lean"
snapshot_funs="formal/lean4/Chio/FormalAeneas/Funs.lean"
generated_funs="target/formal/aeneas-production/lean/Funs.lean"
economy_snapshot_funs="formal/lean4/Chio/FormalEconomy/Funs.lean"
economy_generated_funs="target/formal/aeneas-production/economy/lean/Funs.lean"
driver="target/formal/aeneas-toolchain/${architecture}/bin/charon-driver"
if [[ ! -x "${driver}" || -L "${driver}" ]]; then
  echo "Aeneas binding tests require the authenticated toolchain installer" >&2
  exit 1
fi
for path in "${snapshot_funs}" "${generated_funs}" \
  "${economy_snapshot_funs}" "${economy_generated_funs}"; do
  if [[ ! -f "${path}" || -L "${path}" ]]; then
    echo "Aeneas equivalence tests require current generated output: ${path}" >&2
    exit 1
  fi
done

temporary_dir="$(mktemp -d)"
restore() {
  cp -p "${temporary_dir}/production.toml" "${registry}"
  cp -p "${temporary_dir}/AeneasGeneratedEquivalence.lean" "${proof}"
  cp -p "${temporary_dir}/snapshot-Funs.lean" "${snapshot_funs}"
  cp -p "${temporary_dir}/generated-Funs.lean" "${generated_funs}"
  cp -p "${temporary_dir}/economy-snapshot-Funs.lean" "${economy_snapshot_funs}"
  cp -p "${temporary_dir}/economy-generated-Funs.lean" "${economy_generated_funs}"
  cp -p "${temporary_dir}/charon-driver" "${driver}"
  touch "${snapshot_funs}" "${generated_funs}" \
    "${economy_snapshot_funs}" "${economy_generated_funs}"
  rm -rf "${temporary_dir}"
}
trap restore EXIT

cp -p "${registry}" "${temporary_dir}/production.toml"
cp -p "${proof}" "${temporary_dir}/AeneasGeneratedEquivalence.lean"
cp -p "${snapshot_funs}" "${temporary_dir}/snapshot-Funs.lean"
cp -p "${generated_funs}" "${temporary_dir}/generated-Funs.lean"
cp -p "${economy_snapshot_funs}" "${temporary_dir}/economy-snapshot-Funs.lean"
cp -p "${economy_generated_funs}" "${temporary_dir}/economy-generated-Funs.lean"
cp -p "${driver}" "${temporary_dir}/charon-driver"

python3 - <<'PY'
import tomllib
from pathlib import Path

registry = tomllib.loads(Path("formal/aeneas/negative-tests.toml").read_text(encoding="utf-8"))
if registry.get("schema") != "chio.aeneas-negative-tests.v1":
    raise SystemExit("Aeneas negative-test registry schema mismatch")
mutations = registry.get("mutation", [])
names = [mutation.get("name") for mutation in mutations]
expected = [
    "target-status-downgrade",
    "registered-theorem-removal",
    "release-archive-substitution",
    "charon-driver-substitution",
    "generated-snapshot-drift",
    "nonce-decision-semantic-change",
    "economy-conversion-semantic-change",
]
if names != expected or any(not mutation.get("expected_evidence") for mutation in mutations):
    raise SystemExit("Aeneas negative-test registry inventory mismatch")
PY

python3 - "${registry}" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
needle = 'status = "generated_equivalence"'
if text.count(needle) < 2:
    raise SystemExit("expected at least two generated-equivalence targets")
header, marker, targets = text.partition("[[targets]]")
if not marker:
    raise SystemExit("expected an Aeneas target table")
targets = targets.replace(needle, 'status = "extraction_only"', 1)
path.write_text(header + marker + targets, encoding="utf-8")
PY
if ./scripts/check-aeneas-production.sh >"${temporary_dir}/status.out" 2>"${temporary_dir}/status.err"; then
  echo "Aeneas gate accepted a target without generated equivalence" >&2
  exit 1
fi
grep -Fq "target is not equivalence-checked" "${temporary_dir}/status.err"
cp -p "${temporary_dir}/production.toml" "${registry}"

python3 - "${proof}" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
needle = "theorem generated_ledger_apply_eq_model"
if text.count(needle) != 1:
    raise SystemExit("expected one generated ledger equivalence theorem")
path.write_text(text.replace(needle, "theorem deleted_ledger_apply_eq_model"), encoding="utf-8")
PY
if ./scripts/check-aeneas-production.sh >"${temporary_dir}/proof.out" 2>"${temporary_dir}/proof.err"; then
  echo "Aeneas gate accepted a missing registered proof" >&2
  exit 1
fi
grep -Fq "registered equivalence proofs are missing" "${temporary_dir}/proof.err"
cp -p "${temporary_dir}/AeneasGeneratedEquivalence.lean" "${proof}"

printf '%s\n' "not an Aeneas release" >"${temporary_dir}/substituted-release.tar.gz"
if ./scripts/install-aeneas-toolchain.py \
  --archive "${temporary_dir}/substituted-release.tar.gz" \
  >"${temporary_dir}/archive.out" 2>"${temporary_dir}/archive.err"; then
  echo "Aeneas installer accepted a substituted release archive" >&2
  exit 1
fi
grep -Fq "release archive hash mismatch" "${temporary_dir}/archive.err"

python3 - "${driver}" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
contents = bytearray(path.read_bytes())
contents[-1] ^= 1
path.write_bytes(contents)
PY
if ./scripts/check-aeneas-production.sh >"${temporary_dir}/driver.out" 2>"${temporary_dir}/driver.err"; then
  echo "Aeneas gate accepted a substituted Charon driver" >&2
  exit 1
fi
grep -Fq "runtime binary hash mismatch" "${temporary_dir}/driver.err"
cp -p "${temporary_dir}/charon-driver" "${driver}"

./scripts/tests/snapshot-aeneas-generated.test.sh \
  >"${temporary_dir}/snapshot.out" 2>"${temporary_dir}/snapshot.err"

python3 - "${snapshot_funs}" "${generated_funs}" <<'PY'
import sys
from pathlib import Path

needle = "ok (\N{NOT SIGN} already_live)"
replacement = "ok already_live"
for argument in sys.argv[1:]:
    path = Path(argument)
    text = path.read_text(encoding="utf-8")
    if text.count(needle) != 1:
        raise SystemExit(f"expected one nonce admission expression in {path}")
    path.write_text(text.replace(needle, replacement), encoding="utf-8")
PY
if (cd formal/lean4/Chio && lake build Chio.Proofs.AeneasGeneratedEquivalence) \
  >"${temporary_dir}/semantic.out" 2>"${temporary_dir}/semantic.err"; then
  echo "Aeneas generated proof accepted a changed nonce decision" >&2
  exit 1
fi
grep -Fq "generated_nonce_admits_eq_mirror" \
  "${temporary_dir}/semantic.out" "${temporary_dir}/semantic.err"
cp -p "${temporary_dir}/snapshot-Funs.lean" "${snapshot_funs}"
cp -p "${temporary_dir}/generated-Funs.lean" "${generated_funs}"
touch "${snapshot_funs}" "${generated_funs}"
(cd formal/lean4/Chio && lake build Chio.Proofs.AeneasGeneratedEquivalence) \
  >"${temporary_dir}/restore.out" 2>"${temporary_dir}/restore.err"

python3 - "${economy_snapshot_funs}" "${economy_generated_funs}" <<'PY'
import sys
from pathlib import Path

needle = "if rounded > i3"
replacement = "if rounded < i3"
for argument in sys.argv[1:]:
    path = Path(argument)
    text = path.read_text(encoding="utf-8")
    if text.count(needle) != 1:
        raise SystemExit(f"expected one ceil overflow comparison in {path}")
    path.write_text(text.replace(needle, replacement), encoding="utf-8")
PY
if (cd formal/lean4/Chio && lake build Chio.Proofs.AeneasGeneratedEquivalence) \
  >"${temporary_dir}/economy.out" 2>"${temporary_dir}/economy.err"; then
  echo "Aeneas generated proof accepted a changed economy conversion" >&2
  exit 1
fi
grep -Fq "generated_convert_ceil_scalar_eq_model" \
  "${temporary_dir}/economy.out" "${temporary_dir}/economy.err"
cp -p "${temporary_dir}/economy-snapshot-Funs.lean" "${economy_snapshot_funs}"
cp -p "${temporary_dir}/economy-generated-Funs.lean" "${economy_generated_funs}"
touch "${economy_snapshot_funs}" "${economy_generated_funs}"
(cd formal/lean4/Chio && lake build Chio.Proofs.AeneasGeneratedEquivalence) \
  >"${temporary_dir}/economy-restore.out" 2>"${temporary_dir}/economy-restore.err"

cmp -s "${temporary_dir}/production.toml" "${registry}"
cmp -s "${temporary_dir}/AeneasGeneratedEquivalence.lean" "${proof}"
cmp -s "${temporary_dir}/snapshot-Funs.lean" "${snapshot_funs}"
cmp -s "${temporary_dir}/generated-Funs.lean" "${generated_funs}"
cmp -s "${temporary_dir}/economy-snapshot-Funs.lean" "${economy_snapshot_funs}"
cmp -s "${temporary_dir}/economy-generated-Funs.lean" "${economy_generated_funs}"
cmp -s "${temporary_dir}/charon-driver" "${driver}"

python3 - "${temporary_dir}" <<'PY'
import hashlib
import json
import sys
import tomllib
from pathlib import Path

temporary = Path(sys.argv[1])
registry_path = Path("formal/aeneas/negative-tests.toml")
registry_bytes = registry_path.read_bytes()
registry = tomllib.loads(registry_bytes.decode("utf-8"))
logs = {
    "target-status-downgrade": ("status.out", "status.err"),
    "registered-theorem-removal": ("proof.out", "proof.err"),
    "release-archive-substitution": ("archive.out", "archive.err"),
    "charon-driver-substitution": ("driver.out", "driver.err"),
    "generated-snapshot-drift": ("snapshot.out", "snapshot.err"),
    "nonce-decision-semantic-change": ("semantic.out", "semantic.err"),
    "economy-conversion-semantic-change": ("economy.out", "economy.err"),
}
results = []
for mutation in registry["mutation"]:
    name = mutation["name"]
    output_name, error_name = logs[name]
    digest = hashlib.sha256()
    digest.update((temporary / output_name).read_bytes())
    digest.update(b"\0")
    digest.update((temporary / error_name).read_bytes())
    results.append(
        {
            "name": name,
            "status": "killed",
            "expectedGate": mutation["expected_gate"],
            "expectedEvidence": mutation["expected_evidence"],
            "logSha256": digest.hexdigest(),
        }
    )
report = Path("target/formal/aeneas-production/negative-tests.json")
report.parent.mkdir(parents=True, exist_ok=True)
report.write_text(
    json.dumps(
        {
            "schema": "chio.aeneas-negative-tests-report.v1",
            "registry": str(registry_path),
            "registrySha256": hashlib.sha256(registry_bytes).hexdigest(),
            "results": results,
        },
        indent=2,
        sort_keys=True,
    ) + "\n",
    encoding="utf-8",
)
PY

echo "Aeneas generated equivalence negative tests passed"
