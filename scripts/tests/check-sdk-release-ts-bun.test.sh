#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$REPO_ROOT/scripts/check-sdk-release.sh"

grep -F 'pkg.requiresBun = /\bbun\b/.test(packageScriptText);' "$SCRIPT" >/dev/null
grep -F 'pkg.requiresWasmToolchain = /\b(build:wasm|build-wasm\.sh|wasm-pack)\b/.test(packageScriptText);' "$SCRIPT" >/dev/null
grep -F 'if [[ "${ts_requires_bun}" == "1" ]] && ! command -v bun >/dev/null 2>&1; then' "$SCRIPT" >/dev/null
grep -F 'declares a Bun-backed build or test script' "$SCRIPT" >/dev/null
grep -F 'Chio TypeScript release checks require wasm-pack ${required_wasm_pack_version} on PATH because a package declares a wasm build script' "$SCRIPT" >/dev/null
grep -F 'Chio TypeScript release checks require wasm-bindgen-cli ${required_wasm_bindgen_version} on PATH because a package declares a wasm build script' "$SCRIPT" >/dev/null
grep -F 'read -r package_dir package_name has_build has_test requires_bun requires_wasm_toolchain has_import has_require bin_names local_deps' "$SCRIPT" >/dev/null
grep -F 'CHIO_REQUIRE_WASM_TOOLCHAIN="${requires_wasm_toolchain}" npm run build' "$SCRIPT" >/dev/null
grep -F 'packed_package_deps+=("${local_deps}")' "$SCRIPT" >/dev/null
grep -F 'append_packed_dependency_closure "${dep_name}"' "$SCRIPT" >/dev/null
grep -F 'TypeScript release smoke is missing packed local dependency ${requested_name}' "$SCRIPT" >/dev/null
grep -F 'append_packed_dependency_closure "${package_name}"' "$SCRIPT" >/dev/null

python3 - "$SCRIPT" <<'PYTEST'
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

source = Path(sys.argv[1]).read_text()
with tempfile.TemporaryDirectory(prefix="chio-sdk-release-driver-test-") as temporary:
    root = Path(temporary)
    repo = root / "repo"
    for directory in ("scripts", ".cargo", ".tooling", "bench", "crates", "docs/demo/passkey", "examples", "formal", "integrations", "sdks/typescript/packages/base", "sdks/typescript/packages/app", "tests", "xtask"):
        (repo / directory).mkdir(parents=True, exist_ok=True)
    for filename in ("Cargo.lock", "Cargo.toml", "rust-toolchain.toml"):
        (repo / filename).write_text("")
    sdk = repo / "sdks/typescript"
    (sdk / "package.json").write_text(json.dumps({"private": True, "workspaces": ["packages/*"]}))
    for name, dependencies in (("base", {}), ("app", {"@test/base": "0.0.0"})):
        (sdk / "packages" / name / "package.json").write_text(json.dumps({
            "name": "@test/" + name, "version": "0.0.0", "dependencies": dependencies,
        }))
    binary_dir = root / "bin"
    binary_dir.mkdir()
    npm = binary_dir / "npm"
    npm.write_text("""#!/usr/bin/env python3
import json, os, pathlib, sys
arguments = sys.argv[1:]
with open(os.environ['CHIO_TEST_NPM_LOG'], 'a') as log:
    log.write(json.dumps({'cwd': str(pathlib.Path.cwd()), 'arguments': arguments}) + '\\n')
if arguments[0] == 'install':
    if pathlib.Path.cwd().name.startswith('consumer-') and os.environ.get('CHIO_TEST_FAIL_CONSUMER') == '1':
        print('injected consumer installation failure', file=sys.stderr)
        sys.exit(37)
    sys.exit(0)
if arguments[0] == 'pack':
    name = json.loads(pathlib.Path('package.json').read_text())['name'].split('/')[-1] + '.tgz'
    destination = pathlib.Path(arguments[arguments.index('--pack-destination') + 1])
    (destination / name).write_bytes(b'test-only package placeholder')
    print(json.dumps([{'filename': name}]))
    sys.exit(0)
print('unexpected mocked npm invocation', file=sys.stderr)
sys.exit(42)
""")
    npm.chmod(0o755)
    driver = repo / "scripts/check-sdk-release.sh"
    env = os.environ.copy()
    env["PATH"] = str(binary_dir) + os.pathsep + env["PATH"]
    env.pop("CHIO_TEST_FORCED_UNSET", None)
    env.pop("CHIO_TEST_FAIL_CONSUMER", None)

    def run(name, contents, fail_consumer=False):
        driver.write_text(contents)
        log = root / (name + ".jsonl")
        case_env = dict(env, CHIO_TEST_NPM_LOG=str(log))
        if fail_consumer:
            case_env["CHIO_TEST_FAIL_CONSUMER"] = "1"
        result = subprocess.run(["bash", str(driver), "ts"], env=case_env, text=True, capture_output=True)
        return result, [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    success, calls = run("success", source)
    assert success.returncode == 0, success.stderr
    assert "Chio TypeScript release qualification passed" in success.stdout, success.stdout + success.stderr
    consumers = [call for call in calls if Path(call["cwd"]).name.startswith("consumer-")]
    assert len(consumers) == 2, consumers
    assert consumers[0]["arguments"][-1].endswith("/base.tgz"), consumers
    assert [Path(arg).name for arg in consumers[1]["arguments"][-2:]] == ["base.tgz", "app.tgz"], consumers

    failed, _ = run("consumer-failure", source, fail_consumer=True)
    assert failed.returncode == 37, (failed.returncode, failed.stdout, failed.stderr)
    assert "injected consumer installation failure" in failed.stderr, failed.stderr
    assert "release qualification passed" not in failed.stdout, failed.stdout

    marker = 'case "${lang}" in\n  cpp)'
    assert source.count(marker) == 1
    fault_source = source.replace(marker, 'printf "%s\\n" "${CHIO_TEST_FORCED_UNSET}"\n' + marker)
    failed, _ = run("nounset-failure", fault_source)
    assert failed.returncode != 0, (failed.returncode, failed.stdout, failed.stderr)
    assert "unbound variable" in failed.stderr, failed.stderr
    assert "release qualification passed" not in failed.stdout, failed.stdout

print("TS release driver executes packed dependency consumers and fails closed on consumer/nounset errors")
PYTEST

echo "check-sdk-release-ts-bun.test.sh: toolchain and behavioral consumer checks passed"
