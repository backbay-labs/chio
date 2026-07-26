#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/chio-loom-runner.XXXXXX")"
trap 'rm -rf "${scratch}"' EXIT

mkdir -p \
  "${scratch}/repo/.loom" \
  "${scratch}/repo/scripts" \
  "${scratch}/repo/crates/kernel/chio-kernel/tests" \
  "${scratch}/repo/fakebin"
cp "${repo_root}/scripts/run-loom-manifest.sh" "${scratch}/repo/scripts/"

write_manifest() {
  local test_name="${1:-loom_registered}"
  local lane="${2:-nightly}"
  local extra="${3:-}"
  cat > "${scratch}/repo/.loom/harnesses.toml" <<EOF
schema = "chio.loom.v1"

[[harness]]
crate = "chio-kernel"
test = "loom_concurrency::${test_name}"
max_preemptions = 3
lane = "${lane}"
scope = "bounded_abstract_model"
notes = "bounded fixture"
${extra}
EOF
}

cat > "${scratch}/repo/crates/kernel/chio-kernel/tests/loom_concurrency.rs" <<'EOF'
#[cfg(chio_kernel_loom)]
#[test]
fn loom_registered() {}
EOF

cat > "${scratch}/repo/fakebin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
if [[ "${1:-}" == "metadata" ]]; then
  cat <<JSON
{"packages":[{"id":"chio-kernel 0.0.0","name":"chio-kernel","targets":[{"name":"loom_concurrency","kind":["test"],"src_path":"${repo_root}/crates/kernel/chio-kernel/tests/loom_concurrency.rs"}]}],"workspace_members":["chio-kernel 0.0.0"]}
JSON
  exit 0
fi
if [[ "$*" == *"--list --format terse"* ]]; then
  if [[ "${FAKE_LOOM_DISCOVERY:-one}" == "zero" ]]; then
    echo "0 tests, 0 benchmarks"
  else
    echo "loom_registered: test"
  fi
  exit 0
fi
if [[ "${FAKE_LOOM_RESULT:-pass}" == "ignored" ]]; then
  echo "test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out"
else
  echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
fi
EOF
chmod +x "${scratch}/repo/fakebin/cargo" "${scratch}/repo/scripts/run-loom-manifest.sh"

export PATH="${scratch}/repo/fakebin:${PATH}"

write_manifest
list_output="$(cd "${scratch}/repo" && bash scripts/run-loom-manifest.sh --list)"
[[ "${list_output}" == "chio-kernel::loom_concurrency::loom_registered" ]]

(cd "${scratch}/repo" && bash scripts/run-loom-manifest.sh)
python3 - "${scratch}/repo/target/loom/timings.json" <<'PY'
import json
import sys

document = json.load(open(sys.argv[1], encoding="utf-8"))
assert document["schema"] == "chio.loom.timings.v1"
assert document["cfg"] == "chio_kernel_loom"
assert document["completed"] is True
assert len(document["entries"]) == 1
assert document["entries"][0]["status"] == "passed"
PY

if (cd "${scratch}/repo" && FAKE_LOOM_DISCOVERY=zero bash scripts/run-loom-manifest.sh); then
  echo "zero-test discovery unexpectedly passed" >&2
  exit 1
fi

if (cd "${scratch}/repo" && FAKE_LOOM_RESULT=ignored bash scripts/run-loom-manifest.sh); then
  echo "ignored test unexpectedly passed" >&2
  exit 1
fi

write_manifest "loom_missing"
if (cd "${scratch}/repo" && bash scripts/run-loom-manifest.sh --list); then
  echo "missing test unexpectedly passed" >&2
  exit 1
fi

write_manifest
cat >> "${scratch}/repo/.loom/harnesses.toml" <<'EOF'

[[harness]]
crate = "chio-kernel"
test = "loom_concurrency::loom_registered"
max_preemptions = 3
lane = "nightly"
scope = "bounded_abstract_model"
notes = "duplicate fixture"
EOF
if (cd "${scratch}/repo" && bash scripts/run-loom-manifest.sh --list); then
  echo "duplicate test unexpectedly passed" >&2
  exit 1
fi

write_manifest "loom_registered" "nightly" "future = true"
if (cd "${scratch}/repo" && bash scripts/run-loom-manifest.sh --list); then
  echo "unknown manifest field unexpectedly passed" >&2
  exit 1
fi

write_manifest "loom_registered" "nightly;touch_bad"
if (cd "${scratch}/repo" && bash scripts/run-loom-manifest.sh --list); then
  echo "unsafe lane unexpectedly passed" >&2
  exit 1
fi
[[ ! -e "${scratch}/repo/touch_bad" ]]

write_manifest
if (cd "${scratch}/repo" && bash scripts/run-loom-manifest.sh -- --ignored); then
  echo "unsafe pass-through arguments unexpectedly passed" >&2
  exit 1
fi

echo "run-loom-manifest tests: OK"
