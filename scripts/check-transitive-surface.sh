#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
install_deps="${CHIO_TRANSITIVE_INSTALL_DEPS:-0}"
tmp_root="${TMPDIR:-/tmp}"
python_bin="${CHIO_TRANSITIVE_PYTHON:-python3}"
dotnet_timeout_seconds="${CHIO_TRANSITIVE_DOTNET_TIMEOUT_SECONDS:-120}"
deferred_failures=()

export GOCACHE="${GOCACHE:-${tmp_root}/chio-go-cache}"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-${tmp_root}/chio-gradle}"
mkdir -p "${GOCACHE}" "${GRADLE_USER_HOME}"

log() {
  printf '[transitive-surface] %s\n' "$*"
}

defer_failure() {
  deferred_failures+=("$*")
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "transitive surface checks require $1 on PATH" >&2
    exit 1
  fi
}

run_in() {
  local dir="$1"
  shift
  log "${dir}: $*"
  (
    cd "${repo_root}/${dir}"
    "$@"
  )
}

npm_has_script() {
  local dir="$1"
  local script="$2"
  node -e "const p=require('./${dir}/package.json'); process.exit(p.scripts && p.scripts['${script}'] ? 0 : 1)"
}

npm_prepare() {
  local dir="$1"
  if [[ "${install_deps}" != "1" ]]; then
    return
  fi
  if [[ -f "${repo_root}/${dir}/package-lock.json" ]]; then
    run_in "${dir}" npm ci --workspaces=false --no-fund --no-audit
  else
    run_in "${dir}" npm install --workspaces=false --no-fund --no-audit
  fi
}

npm_run_if_present() {
  local dir="$1"
  local script="$2"
  if npm_has_script "${dir}" "${script}"; then
    run_in "${dir}" npm run "${script}"
  fi
}

npm_suite() {
  local dir="$1"
  npm_prepare "${dir}"
  npm_run_if_present "${dir}" build
  npm_run_if_present "${dir}" lint
  npm_run_if_present "${dir}" typecheck
  if ! npm_has_script "${dir}" test; then
    return
  fi
  if [[ "${bind_tests:-1}" == "0" ]]; then
    case "${dir}" in
      sdks/typescript/packages/node-http)
        log "${dir}: socket bind unavailable; running non-bind vitest files"
        run_in "${dir}" npm exec -- vitest run test/identity.test.ts test/types.test.ts
        ;;
      sdks/typescript/packages/express | sdks/typescript/packages/fastify)
        log "${dir}: socket bind unavailable; build and lint covered, package tests deferred to CI"
        ;;
      *)
        run_in "${dir}" npm run test
        ;;
    esac
  else
    run_in "${dir}" npm run test
  fi
}

local_bind_available() {
  "${python_bin}" - <<'PY'
import socket
import sys

for host, family in (("127.0.0.1", socket.AF_INET), ("::1", socket.AF_INET6)):
    try:
        sock = socket.socket(family)
        sock.bind((host, 0))
        sock.close()
    except OSError:
        sys.exit(1)
PY
}

pytest_in() {
  local dir="$1"
  local pythonpath="$2"
  shift 2
  log "${dir}: python -m pytest $*"
  (
    cd "${repo_root}/${dir}"
    PYTHONPATH="${pythonpath}" "${python_bin}" -m pytest "$@"
  )
}

dotnet_test_in() {
  local dir="$1"
  shift
  log "${dir}: dotnet test $*"
  local output
  if output="$(
    cd "${repo_root}/${dir}"
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
      MSBUILDDISABLENODEREUSE=1 \
      perl -e '
        my $timeout = shift @ARGV;
        my $pid = fork();
        die "fork failed: $!" unless defined $pid;
        if ($pid == 0) {
          exec @ARGV or die "exec failed: $!";
        }
        local $SIG{ALRM} = sub {
          kill 9, $pid;
          waitpid($pid, 0);
          exit 124;
        };
        alarm $timeout;
        waitpid($pid, 0);
        exit($? >> 8);
      ' "${dotnet_timeout_seconds}" \
        dotnet test "$@" --disable-build-servers -p:BuildInParallel=false 2>&1
  )"; then
    printf '%s\n' "${output}"
    return 0
  fi

  local status=$?
  printf '%s\n' "${output}" >&2
  if [[ "${install_deps}" != "1" && "${output}" == *"SocketException (13): Permission denied"* ]]; then
    defer_failure ".NET lane infrastructure unavailable: MSBuild named-pipe socket denied"
    return 0
  fi
  if [[ "${install_deps}" != "1" && "${status}" == "124" ]]; then
    defer_failure ".NET lane infrastructure unavailable: dotnet test timed out after ${dotnet_timeout_seconds}s"
    return 0
  fi
  return 1
}

python_test_deps_available() {
  "${python_bin}" - <<'PY'
import importlib.util
import sys

modules = [
    "django",
    "fastapi",
    "httpx",
    "pure25519",
    "pydantic",
    "pytest",
    "pytest_asyncio",
    "pytest_django",
    "respx",
]
missing = [module for module in modules if importlib.util.find_spec(module) is None]
if missing:
    print(", ".join(missing), file=sys.stderr)
    sys.exit(1)
PY
}

require_command cargo
require_command cmake
require_command go
require_command node
require_command npm
require_command perl
require_command "${python_bin}"
require_command dotnet
require_command bun

if [[ "${install_deps}" == "1" ]]; then
  log "installing Python test dependencies"
  "${python_bin}" -m pip install --upgrade pip
  "${python_bin}" -m pip install \
    "django>=5.2,<6" \
    "fastapi>=0.116,<1" \
    "httpx>=0.28,<1" \
    "pure25519>=0.0.1" \
    "pydantic>=2.5,<3" \
    "pytest>=8,<9" \
    "pytest-asyncio>=0.23,<1" \
    "pytest-django>=4.5,<5" \
    "respx>=0.21,<1"
fi

log "running Go SDK and example tests"
bind_tests="${CHIO_TRANSITIVE_BIND_TESTS:-auto}"
if [[ "${bind_tests}" == "auto" ]]; then
  if local_bind_available; then
    bind_tests="1"
  else
    bind_tests="0"
  fi
fi

if [[ "${bind_tests}" == "1" ]]; then
  for dir in \
    sdks/go/chio-go \
    sdks/go/chio-go-http \
    sdks/guard/chio-guard-go \
    sdks/k8s/controller \
    sdks/k8s/webhooks \
    examples/hello-chi
  do
    run_in "${dir}" go test ./...
  done
else
  log "local socket bind unavailable; running non-bind Go subsets"
  run_in sdks/go/chio-go go test ./invariants ./version ./cmd/conformance-peer
  run_in sdks/go/chio-go-http go test . -run '^(TestGenerated|TestConformance|TestIdentity)'
  run_in sdks/guard/chio-guard-go go test ./...
  run_in sdks/k8s/controller go test ./... -run '^(TestReconcile|TestBackoff|TestPodAnnotation|TestControllerOwned)'
  run_in sdks/k8s/webhooks go test ./...
  run_in examples/hello-chi go test ./...
fi

log "running TypeScript SDK and framework package suites"
for dir in \
  sdks/typescript/chio-ts \
  sdks/typescript/packages/node-http \
  sdks/typescript/packages/express \
  sdks/typescript/packages/fastify \
  sdks/typescript/packages/elysia \
  sdks/typescript/packages/ai-sdk \
  sdks/guard/chio-guard-ts
do
  npm_suite "${dir}"
done

log "running Node framework example tests"
for dir in \
  examples/hello-express \
  examples/hello-fastify \
  examples/hello-elysia
do
  npm_prepare "${dir}"
  run_in "${dir}" npm test
done

log "running web3 app typecheck"
if [[ "${install_deps}" == "1" ]]; then
  run_in examples/internet-of-agents-web3-network/app bun install --frozen-lockfile
fi
run_in examples/internet-of-agents-web3-network/app npm run typecheck

log "running Python SDK and example tests"
if ! missing_python_deps="$(python_test_deps_available 2>&1)"; then
  echo "transitive surface checks require Python lane dependencies; missing: ${missing_python_deps}" >&2
  echo "set CHIO_TRANSITIVE_INSTALL_DEPS=1 or CHIO_TRANSITIVE_PYTHON to a prepared interpreter" >&2
  if [[ "${install_deps}" == "1" ]]; then
    exit 1
  fi
  defer_failure "Python lane dependencies missing: ${missing_python_deps}"
else
  pytest_in sdks/python/chio-py src
  pytest_in sdks/python/chio-sdk-python src
  pytest_in sdks/python/chio-asgi "src:../chio-sdk-python/src"
  pytest_in sdks/python/chio-fastapi "src:../chio-asgi/src:../chio-sdk-python/src"
  pytest_in sdks/python/chio-django "src:../chio-sdk-python/src"
  pytest_in examples/hello-fastapi ".:../../sdks/python/chio-asgi/src:../../sdks/python/chio-fastapi/src:../../sdks/python/chio-sdk-python/src"
  pytest_in examples/hello-receipt-verify .
  pytest_in examples/hello-trust-control .
  log "examples/hello-django: python manage.py test"
  (
    cd "${repo_root}/examples/hello-django"
    PYTHONPATH=".:../../sdks/python/chio-django/src:../../sdks/python/chio-sdk-python/src" \
      "${python_bin}" manage.py test
  )
fi

log "running .NET SDK and example tests"
dotnet_test_in sdks/dotnet/ChioMiddleware ChioMiddleware.sln
dotnet_test_in examples/hello-dotnet tests/HelloChio.Tests.csproj

if [[ "${CHIO_TRANSITIVE_JVM_TESTS:-${install_deps}}" == "1" ]]; then
  require_command java
  log "running JVM SDK and Spring example tests"
  run_in sdks/jvm ./gradlew spotlessCheck build --no-daemon
  log "examples/hello-spring-boot: gradle test"
  (
    cd "${repo_root}"
    ./sdks/jvm/gradlew -p examples/hello-spring-boot test --no-daemon
  )
else
  log "skipping JVM tests in no-install local mode"
fi

log "running C++ SDK smoke"
CHIO_CPP_REQUIRE_CBINDGEN="${CHIO_CPP_REQUIRE_CBINDGEN:-0}" \
CHIO_CPP_BUILD_DIR="${CHIO_CPP_BUILD_DIR:-${TMPDIR:-/tmp}/chio-cpp-transitive}" \
  "${repo_root}/scripts/check-chio-cpp.sh"

if (( ${#deferred_failures[@]} > 0 )); then
  echo "transitive surface checks completed with deferred local-mode failures:" >&2
  for failure in "${deferred_failures[@]}"; do
    echo "  - ${failure}" >&2
  done
  exit 1
fi

log "ok"
