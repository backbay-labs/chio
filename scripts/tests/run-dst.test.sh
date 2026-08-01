#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/chio-dst-runner.XXXXXX")"
trap 'rm -rf "${scratch}"' EXIT

mkdir -p \
  "${scratch}/repo/.dst" \
  "${scratch}/repo/scripts" \
  "${scratch}/repo/crates/kernel/chio-kernel/tests/dst" \
  "${scratch}/repo/fakebin"
cp "${repo_root}/scripts/run-dst.sh" "${scratch}/repo/scripts/"

cat > "${scratch}/repo/.dst/episodes.toml" <<'EOF'
schema = "chio.dst.v1"
package = "chio-kernel"
target = "dst_drop_injection"
scope = "single_process_single_store"
seed_corpus = "crates/kernel/chio-kernel/tests/dst/seeds.toml"
fixed_seed_count = 64
wide_episode_count = 10000

[[test]]
name = "dst_fixed_seed_corpus"
lane = "pr"
ignored = false
EOF

cat > "${scratch}/repo/.dst/harnesses.toml" <<'EOF'
schema = "chio.dst.v1"

[[harness]]
crate = "chio-kernel"
test = "dst_drop_injection::dst_fixed_seed_corpus"
EOF

{
  echo 'schema = "chio.dst.seeds.v1"'
  printf 'seeds = ['
  for seed in $(seq 0 63); do
    if [[ "${seed}" -gt 0 ]]; then printf ', '; fi
    printf '%s' "${seed}"
  done
  echo ']'
} > "${scratch}/repo/crates/kernel/chio-kernel/tests/dst/seeds.toml"

cat > "${scratch}/repo/crates/kernel/chio-kernel/tests/dst_drop_injection.rs" <<'EOF'
#[test]
fn dst_fixed_seed_corpus() {}
EOF

cat > "${scratch}/repo/fakebin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
if [[ "${1:-}" == "metadata" ]]; then
  cat <<JSON
{"packages":[{"id":"chio-kernel 0.0.0","name":"chio-kernel","targets":[{"name":"dst_drop_injection","kind":["test"],"src_path":"${root}/crates/kernel/chio-kernel/tests/dst_drop_injection.rs"}]}],"workspace_members":["chio-kernel 0.0.0"]}
JSON
  exit 0
fi
if [[ "$*" == *"--list --format terse"* ]]; then
  if [[ "${FAKE_DST_DISCOVERY:-one}" == "zero" ]]; then
    echo "0 tests, 0 benchmarks"
  else
    echo "dst_fixed_seed_corpus: test"
  fi
  exit 0
fi
echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
EOF

chmod +x "${scratch}/repo/fakebin/cargo" "${scratch}/repo/scripts/run-dst.sh"
export PATH="${scratch}/repo/fakebin:${PATH}"

list="$(cd "${scratch}/repo" && bash scripts/run-dst.sh --lane all --list)"
[[ "${list}" == "chio-kernel::dst_drop_injection::dst_fixed_seed_corpus" ]]
(cd "${scratch}/repo" && bash scripts/run-dst.sh --lane pr)

if (cd "${scratch}/repo" && FAKE_DST_DISCOVERY=zero bash scripts/run-dst.sh --lane pr); then
  echo "zero-test DST discovery unexpectedly passed" >&2
  exit 1
fi

if (cd "${scratch}/repo" && bash scripts/run-dst.sh --lane replay); then
  echo "seedless DST replay unexpectedly passed" >&2
  exit 1
fi

sed -i.bak 's/fixed_seed_count = 64/fixed_seed_count = 63/' \
  "${scratch}/repo/.dst/episodes.toml"
if (cd "${scratch}/repo" && bash scripts/run-dst.sh --lane all --list); then
  echo "wrong fixed seed count unexpectedly passed" >&2
  exit 1
fi

echo "run-dst tests: OK"
