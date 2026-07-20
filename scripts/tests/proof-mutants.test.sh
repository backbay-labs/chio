#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
cd "${repo_root}"

fake_mutants="${tmp_dir}/cargo-mutants"
cat >"${fake_mutants}" <<'PY'
#!/usr/bin/env python3
import json
from pathlib import Path
import re
import sys

if sys.argv[1:] == ["--version"]:
    print("cargo-mutants 25.3.1")
    raise SystemExit(0)
arguments = sys.argv[1:]
fixtures = {
    "0/3": (
        "crates/kernel/chio-kernel-core/src/formal_core.rs",
        "false",
        "classify_time_window",
    ),
    "1/3": (
        "crates/kernel/chio-kernel-core/src/formal_aeneas.rs",
        "true",
        "classify_time_window_code",
    ),
    "2/3": (
        "crates/kernel/chio-kernel-core/src/formal_core.rs",
        "0",
        "time_window_valid",
    ),
}


def spans(path, function):
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    declaration = re.compile(rf"^\s*(?:pub\s+)?fn\s+{re.escape(function)}\s*\(")
    starts = [index for index, line in enumerate(lines) if declaration.search(line)]
    if len(starts) != 1:
        raise SystemExit(f"fixture function lookup failed for {function}")
    start = starts[0]
    depth = 0
    opening_seen = False
    end = None
    for index in range(start, len(lines)):
        for character in lines[index]:
            if character == "{":
                depth += 1
                opening_seen = True
            elif character == "}":
                depth -= 1
        if opening_seen and depth == 0:
            end = index
            break
    if end is None:
        raise SystemExit(f"fixture function body is unterminated for {function}")
    mutation_line = next(
        index for index in range(start + 1, end) if lines[index].strip()
    )
    indentation = len(lines[mutation_line]) - len(lines[mutation_line].lstrip())
    token_length = min(4, len(lines[mutation_line].strip()))
    return {
        "function_start": start + 1,
        "function_end": end + 1,
        "function_end_column": len(lines[end]) + 1,
        "mutation_line": mutation_line + 1,
        "mutation_start_column": indentation + 1,
        "mutation_end_column": indentation + token_length + 1,
    }
selected = (
    [fixtures[arguments[arguments.index("--shard") + 1]]]
    if "--shard" in arguments
    else list(fixtures.values())
)
payload = []
for path, replacement, function in selected:
    positions = spans(path, function)
    payload.append({
        "file": path,
        "function": {
            "function_name": function,
            "return_type": "-> bool",
            "span": {
                "start": {"line": positions["function_start"], "column": 1},
                "end": {
                    "line": positions["function_end"],
                    "column": positions["function_end_column"],
                },
            },
        },
        "genre": "FnValue",
        "package": "chio-kernel-core",
        "replacement": replacement,
        "span": {
            "start": {
                "line": positions["mutation_line"],
                "column": positions["mutation_start_column"],
            },
            "end": {
                "line": positions["mutation_line"],
                "column": positions["mutation_end_column"],
            },
        },
        "diff": f"--- {path}\n+++ fixture\n@@ -1 +1 @@\n-old\n+new\n",
    })
print(json.dumps(payload))
PY
chmod +x "${fake_mutants}"

CARGO_MUTANTS_BIN="${fake_mutants}" \
  python3 scripts/proof-mutants.py --list >"${tmp_dir}/list-one.json"
CARGO_MUTANTS_BIN="${fake_mutants}" \
  python3 scripts/proof-mutants.py --list >"${tmp_dir}/list-two.json"
cmp "${tmp_dir}/list-one.json" "${tmp_dir}/list-two.json"

python3 - "${tmp_dir}/list-one.json" <<'PY'
import json
from pathlib import Path
import sys

mutants = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if len(mutants) != 3:
    raise SystemExit("sharded discovery did not merge three fixtures")
if {mutant["shard"] for mutant in mutants} != {"0/3", "1/3", "2/3"}:
    raise SystemExit("sharded discovery omitted a shard")
if {mutant["file"] for mutant in mutants} != {
    "crates/kernel/chio-kernel-core/src/formal_core.rs",
    "crates/kernel/chio-kernel-core/src/formal_aeneas.rs",
}:
    raise SystemExit("discovery escaped or omitted the model files")
if len({mutant["id"] for mutant in mutants}) != 3:
    raise SystemExit("discovered mutant identifiers are not unique")
PY

python3 - "${tmp_dir}" <<'PY'
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from contextlib import redirect_stdout

script = Path("scripts/proof-mutants.py").resolve()
module_spec = importlib.util.spec_from_file_location("proof_mutants", script)
module = importlib.util.module_from_spec(module_spec)
assert module_spec.loader is not None
sys.modules[module_spec.name] = module
module_spec.loader.exec_module(module)

default_options = module.parse_arguments([])
override_options = module.parse_arguments(["--timeout-secs", "17"])
if (default_options.timeout_secs, override_options.timeout_secs) != (5400, 17):
    raise SystemExit("proof mutation timeout defaults or overrides changed")
parallel_options = module.parse_arguments(["--jobs", "3"])
if default_options.jobs != 1 or parallel_options.jobs != 3:
    raise SystemExit("proof mutation worker defaults or overrides changed")

ci_names = ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_RUN_NUMBER")
for name in ci_names:
    os.environ.pop(name, None)
if module.ci_run_evidence() is not None:
    raise SystemExit("local proof run unexpectedly has CI identity")
os.environ.update(
    GITHUB_RUN_ID="101",
    GITHUB_RUN_ATTEMPT="2",
    GITHUB_RUN_NUMBER="303",
)
if module.ci_run_evidence() != {
    "run_id": 101,
    "run_attempt": 2,
    "run_number": 303,
}:
    raise SystemExit("proof run identity was not parsed exactly")
os.environ["GITHUB_RUN_ATTEMPT"] = "invalid"
try:
    module.ci_run_evidence()
except module.ProofMutationError:
    pass
else:
    raise SystemExit("invalid proof run identity was accepted")
for name in ci_names:
    os.environ.pop(name, None)

command = module.discovery_command("cargo", "1/3")
if command.count("-f") != 2:
    raise SystemExit("discovery command did not repeat both file filters")
for path in module.FILES:
    if path.as_posix() not in command:
        raise SystemExit(f"discovery command omitted {path}")
if command[command.index("--shard") + 1] != "1/3":
    raise SystemExit("discovery command omitted the requested shard")
control = module.unsharded_discovery_command("cargo")
if "--shard" in control or control.count("-f") != 2:
    raise SystemExit("unsharded discovery control has the wrong scope")

source = "fn check() {\n    true\n}\n"
span = {
    "start": {"line": 2, "column": 5},
    "end": {"line": 2, "column": 9},
}
mutated = module.replace_span(source, span, "false")
if "false /* ~ changed by cargo-mutants ~ */" not in mutated or "true" in mutated:
    raise SystemExit("span replacement did not reproduce cargo-mutants semantics")

root = Path(sys.argv[1])
drift_root = root / "proof-drift-repo"
drift_root.mkdir()


def git(*arguments: str) -> None:
    subprocess.run(
        ["git", *arguments],
        cwd=drift_root,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


git("init", "--quiet")
git("config", "user.name", "Mutation Selftest")
git("config", "user.email", "mutation-selftest@example.invalid")
(drift_root / ".gitignore").write_text("ignored-*.txt\n", encoding="utf-8")
unrelated = drift_root / "unrelated.txt"
unrelated.write_text("stable\n", encoding="utf-8")
tracked_source = drift_root / "source.txt"
tracked_source.write_text("captured source\n", encoding="utf-8")
evidence = drift_root / "ignored-evidence.txt"
evidence.write_text("captured\n", encoding="utf-8")
extra = drift_root / "ignored-extra.txt"
extra.write_text("extra\n", encoding="utf-8")
git("add", ".gitignore", "unrelated.txt", "source.txt")
git("commit", "--quiet", "-m", "test: initialize drift fixture")

snapshot = module.capture_execution_snapshot(
    drift_root, [Path("ignored-evidence.txt")]
)
module.verify_execution_snapshot(
    drift_root, snapshot, [Path("ignored-evidence.txt")]
)
if snapshot.report_inputs()[0]["sha256"] != module.sha256_file(evidence):
    raise SystemExit("proof snapshot did not retain its starting input hash")

source_snapshot = module.capture_execution_snapshot(
    drift_root, [Path("source.txt")]
)
original_input_paths = module.proof_input_paths
original_discover = module.discover
tracked_source.write_text("transient main-tree source\n", encoding="utf-8")
module.proof_input_paths = lambda _root: [Path("source.txt")]
module.discover = lambda frozen_root, _binary: (
    [],
    [
        {
            "observed": (frozen_root / "source.txt").read_text(encoding="utf-8")
        }
    ],
)
try:
    _, frozen_commands = module.discover_at_snapshot(
        drift_root, "unused", source_snapshot
    )
finally:
    module.proof_input_paths = original_input_paths
    module.discover = original_discover
    tracked_source.write_text("captured source\n", encoding="utf-8")
if frozen_commands != [{"observed": "captured source\n"}]:
    raise SystemExit("proof discovery followed a transient main-tree edit")

evidence.write_text("drifted\n", encoding="utf-8")
try:
    module.verify_execution_snapshot(
        drift_root, snapshot, [Path("ignored-evidence.txt")]
    )
except module.ProofMutationError as error:
    if "evidence inputs drifted" not in str(error):
        raise
else:
    raise SystemExit("proof input drift was accepted")
evidence.write_text("captured\n", encoding="utf-8")

try:
    module.verify_execution_snapshot(
        drift_root,
        snapshot,
        [Path("ignored-evidence.txt"), Path("ignored-extra.txt")],
    )
except module.ProofMutationError as error:
    if "input path set drifted" not in str(error):
        raise
else:
    raise SystemExit("proof input path-set drift was accepted")

unrelated.write_text("dirty\n", encoding="utf-8")
try:
    module.verify_execution_snapshot(
        drift_root, snapshot, [Path("ignored-evidence.txt")]
    )
except module.ProofMutationError as error:
    if "worktree drifted" not in str(error):
        raise
else:
    raise SystemExit("proof worktree drift was accepted")
unrelated.write_text("stable\n", encoding="utf-8")

unrelated.write_text("committed drift\n", encoding="utf-8")
git("add", "unrelated.txt")
git("commit", "--quiet", "-m", "test: move drift fixture head")
try:
    module.verify_execution_snapshot(
        drift_root, snapshot, [Path("ignored-evidence.txt")]
    )
except module.ProofMutationError as error:
    if "Git HEAD drifted" not in str(error):
        raise
else:
    raise SystemExit("proof Git HEAD drift was accepted")

contract_source = (
    "#[cfg_attr(chio_creusot_contracts, ensures(result == true))]\n"
    "pub fn fixture() -> bool {\n"
    "    true\n"
    "}\n"
)
contract_path = root / module.FILES[0]
contract_path.parent.mkdir(parents=True, exist_ok=True)
contract_path.write_text(contract_source, encoding="utf-8")
contract_mutant = module.DiscoveredMutant(
    "f" * 20,
    "0/3",
    module.FILES[0],
    "fixture",
    "BinaryOperator",
    "false",
    {"start": {"line": 1, "column": 51}, "end": {"line": 1, "column": 55}},
    "--- fixture\n+++ fixture\n",
    {},
)
try:
    module.enforce_function_body(root, contract_mutant)
except module.ProofMutationError:
    pass
else:
    raise SystemExit("proof contract attribute was accepted as mutable model code")

qualified_source = (
    "impl From<A> for Target {\n"
    "    fn from(_: A) -> Self {\n"
    "        true\n"
    "    }\n"
    "}\n"
    "impl From<B> for Target {\n"
    "    fn from(_: B) -> Self {\n"
    "        false\n"
    "    }\n"
    "}\n"
)
qualified_path = root / module.FILES[1]
qualified_path.parent.mkdir(parents=True, exist_ok=True)
qualified_path.write_text(qualified_source, encoding="utf-8")
qualified_mutant = module.DiscoveredMutant(
    "e" * 20,
    "1/3",
    module.FILES[1],
    "<impl From<B> for Target>::from",
    "FnValue",
    "true",
    {"start": {"line": 8, "column": 9}, "end": {"line": 8, "column": 14}},
    "--- fixture\n+++ fixture\n",
    {
        "function": {
            "span": {
                "start": {"line": 7, "column": 5},
                "end": {"line": 9, "column": 6},
            }
        }
    },
)
module.enforce_function_body(root, qualified_mutant)

log = root / "kani.log"
failure_footer = (
    "harness result\nSUMMARY:\n ** 1 of 12 failed (2 unreachable)\n"
    "Failed Checks: assertion failed: fixture\n"
    " File: \"src/lib.rs\", line 4, in fixture\n\n"
    "VERIFICATION:- FAILED\nVerification Time: 0.125s\n\n"
    "Manual Harness Summary:\n"
    "Verification failed for - kani_public_harnesses::fixture\n"
    "Complete - 0 successfully verified harnesses, 1 failures, 1 total.\n"
)
log.write_text(
    failure_footer,
    encoding="utf-8",
)
if module.classify_kani(1, log) != "killed":
    raise SystemExit("exact terminal proof failure was not classified as killed")
second_failure = (
    "Checking harness second_failure...\nSUMMARY:\n ** 2 of 12 failed\n"
    "Failed Checks: assertion failed: first\n"
    " File: \"src/lib.rs\", line 8, in second_failure\n"
    "Failed Checks: assertion failed: second\n"
    " File: \"src/lib.rs\", line 9, in second_failure\n\n"
    "VERIFICATION:- FAILED\nVerification Time: 0.250s\n"
)
mixed_harness_footer = (
    failure_footer.split("Manual Harness Summary:\n", 1)[0]
    + "Checking harness successful_harness...\nSUMMARY:\n ** 0 of 4 failed\n"
    + "VERIFICATION:- SUCCESSFUL\nVerification Time: 0.050s\n"
    + second_failure
    + "\nManual Harness Summary:\n"
    + "Verification failed for - kani_public_harnesses::fixture\n"
    + "Verification failed for - kani_public_harnesses::second_failure\n"
    + "Complete - 1 successfully verified harnesses, 2 failures, 3 total.\n"
)
log.write_text(mixed_harness_footer, encoding="utf-8")
if module.classify_kani(1, log) != "killed":
    raise SystemExit("mixed multi-harness proof failures were not classified as killed")
for malformed in (
    mixed_harness_footer.replace("2 failures, 3 total", "1 failures, 2 total"),
    mixed_harness_footer.replace(
        "Verification failed for - kani_public_harnesses::second_failure\n", ""
    ),
    mixed_harness_footer.replace("** 2 of 12 failed", "** 3 of 12 failed"),
):
    log.write_text(malformed, encoding="utf-8")
    try:
        module.classify_kani(1, log)
    except module.ProofMutationError:
        pass
    else:
        raise SystemExit("inconsistent multi-harness failure evidence counted as killed")
log.write_text("error[E0308]: mismatched types\n", encoding="utf-8")
if module.classify_kani(101, log) != "unviable":
    raise SystemExit("compile failure was not classified as unviable")
wrapped_compile_failure = (
    "error[E0277]: trait bound not satisfied\n"
    "error: could not compile `chio-kernel-core` (lib) due to 1 previous error\n"
    "error: Failed to execute cargo (exit status: 101). Found 1 compilation errors.\n"
)
log.write_text(wrapped_compile_failure, encoding="utf-8")
if module.classify_kani(1, log) != "unviable":
    raise SystemExit("Kani-wrapped compile failure was not classified as unviable")
for mixed_compile_tool in (
    wrapped_compile_failure + "thread 'rustc' panicked at compiler.rs:1\n",
    wrapped_compile_failure + "error: failed to load Kani metadata\n",
    wrapped_compile_failure
    + "error: Failed to execute cargo (exit status: 101). Found 1 compilation errors.\n",
    wrapped_compile_failure.replace("exit status: 101", "exit status: 1"),
):
    log.write_text(mixed_compile_tool, encoding="utf-8")
    try:
        module.classify_kani(1, log)
    except module.ProofMutationError:
        pass
    else:
        raise SystemExit("compile failure masked independent tool-failure evidence")
log.write_text(
    "error: Failed to execute cargo (exit status: 101). Found 1 compilation errors.\n",
    encoding="utf-8",
)
try:
    module.classify_kani(1, log)
except module.ProofMutationError:
    pass
else:
    raise SystemExit("cargo wrapper without compile diagnostics was classified")
for mixed in (
    "error[E0308]: mismatched types\n" + failure_footer,
    "error: failed to run Kani compiler\n" + failure_footer,
    "SUMMARY:\n ** 1 of 12 failed\nVERIFICATION:- FAILED\n" + failure_footer,
):
    log.write_text(mixed, encoding="utf-8")
    try:
        module.classify_kani(1, log)
    except module.ProofMutationError:
        pass
    else:
        raise SystemExit("mixed Kani proof and infrastructure failure counted as killed")
log.write_text("VERIFICATION:- FAILED\n", encoding="utf-8")
try:
    module.classify_kani(1, log)
except module.ProofMutationError:
    pass
else:
    raise SystemExit("non-terminal Kani failure marker counted as a proof kill")
if module.classify_kani(0, log) != "survived":
    raise SystemExit("clean proof result was not classified as survived")
if module.classify_kani(None, log) != "timeout":
    raise SystemExit("timeout was not classified")

aggregate = module.score(
    [{"verdict": "killed"}, {"verdict": "survived"}, {"verdict": "timeout"}],
    90.0,
)
if aggregate["activation_ratio_percent"] != 33.333:
    raise SystemExit("timeout was omitted from the activation denominator")
low_viability = module.score(
    [{"verdict": "killed"}] + [{"verdict": "unviable"} for _ in range(14)],
    90.0,
)
if low_viability["activation_ratio_percent"] != 100.0 or low_viability["activation_met"]:
    raise SystemExit("compile-invalid proof sample bypassed the viability floor")

repo = Path.cwd().resolve()
sentinel = root / "sentinel"
sentinel.write_text("preserve", encoding="utf-8")
link = repo / "target/formal/proof-mutants-symlink-selftest"
link.parent.mkdir(parents=True, exist_ok=True)
link.symlink_to(root, target_is_directory=True)
try:
    try:
        module.safe_output(repo, str(link))
    except module.ProofMutationError:
        pass
    else:
        raise SystemExit("symlinked proof mutation output was accepted")
    if sentinel.read_text(encoding="utf-8") != "preserve":
        raise SystemExit("proof mutation symlink fixture was modified")
finally:
    link.unlink(missing_ok=True)

expected_inputs = set(module.FIXED_PROOF_INPUTS)
for source_root in module.PROOF_SOURCE_ROOTS:
    expected_inputs.update(
        path.relative_to(repo)
        for path in (repo / source_root).rglob("*.rs")
        if path.is_file() and not path.is_symlink()
    )
actual_inputs = module.proof_input_paths(repo)
if actual_inputs != sorted(expected_inputs, key=lambda path: path.as_posix()):
    raise SystemExit("proof report input inventory is not the exact source-complete set")

external_root = root / "proof-source-external"
guard_root = root / "proof-source-guard"
for relative in module.FILES:
    external = external_root / relative
    external.parent.mkdir(parents=True, exist_ok=True)
    external.write_text(f"preserve {relative}\n", encoding="utf-8")
oracle = guard_root / module.FIXED_PROOF_INPUTS[-1]
oracle.parent.mkdir(parents=True, exist_ok=True)
oracle.write_text("preserve oracle\n", encoding="utf-8")
(guard_root / "crates").parent.mkdir(parents=True, exist_ok=True)
(guard_root / "crates").symlink_to(external_root / "crates", target_is_directory=True)
external_before = {
    relative: (external_root / relative).read_bytes() for relative in module.FILES
}
oracle_before = oracle.read_bytes()
probe = root / "source-symlink-discovery-probe"
probe.write_text(
    "#!/usr/bin/env sh\nprintf 'changed oracle\\n' > " + repr(str(oracle)) + "\n",
    encoding="utf-8",
)
probe.chmod(0o755)
try:
    module.discover(guard_root, str(probe))
except module.ProofMutationError:
    pass
else:
    raise SystemExit("proof discovery accepted a symlinked source component")
try:
    module.write_mutable_source(guard_root, module.FILES[0], "changed\n")
except module.ProofMutationError:
    pass
else:
    raise SystemExit("proof source write followed a symlinked source component")
if oracle.read_bytes() != oracle_before:
    raise SystemExit("proof source-symlink rejection changed an oracle path")
for relative, expected in external_before.items():
    if (external_root / relative).read_bytes() != expected:
        raise SystemExit("proof source-symlink rejection changed an external source")

final_link_root = root / "proof-source-final-link"
for relative in module.FILES:
    path = final_link_root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if relative == module.FILES[0]:
        path.symlink_to(oracle)
    else:
        path.write_text("regular source\n", encoding="utf-8")
try:
    module.validate_mutable_sources(final_link_root)
except module.ProofMutationError:
    pass
else:
    raise SystemExit("proof source validation accepted a final symlink")
if oracle.read_bytes() != oracle_before:
    raise SystemExit("final proof source symlink changed its oracle target")

class InterruptedProcess:
    pid = 424242

    def __init__(self):
        self.waits = 0

    def wait(self, timeout=None):
        self.waits += 1
        if self.waits == 1:
            raise KeyboardInterrupt
        return -9


interrupted = InterruptedProcess()
kills = []
popen_options = []
original_popen = module.subprocess.Popen
original_killpg = module.os.killpg
module.subprocess.Popen = lambda *args, **kwargs: (
    popen_options.append(kwargs) or interrupted
)
module.os.killpg = lambda pid, sig: kills.append((pid, sig))
try:
    try:
        module.run_process(["unused"], root, root / "interrupt.log", 1)
    except KeyboardInterrupt:
        pass
    else:
        raise SystemExit("proof runner swallowed an interrupt")
finally:
    module.subprocess.Popen = original_popen
    module.os.killpg = original_killpg
if (
    kills != [(interrupted.pid, module.signal.SIGKILL)]
    or interrupted.waits != 2
    or len(popen_options) != 1
    or popen_options[0].get("start_new_session") is not True
):
    raise SystemExit("proof runner did not kill and reap its process group on interrupt")


class LateRegisteredProcess:
    pid = 434343

    def __init__(self):
        self.waits = 0

    def wait(self, timeout=None):
        self.waits += 1
        return -9


late_registered = LateRegisteredProcess()
late_kills = []
registry = module.ProcessRegistry()
registered = LateRegisteredProcess()
registered.pid = 434342
registry.add(registered)
module.os.killpg = lambda pid, sig: late_kills.append((pid, sig))
registry.kill_all()
registry.kill_all()
if late_kills != [(registered.pid, module.signal.SIGKILL)] or registered.waits != 1:
    raise SystemExit("proof registry cancelled a registered process more than once")
late_kills.clear()
registry.kill_all()
try:
    try:
        registry.add(late_registered)
    except module.ProofMutationError:
        pass
    else:
        raise SystemExit("proof registry accepted a process after cancellation")
finally:
    module.os.killpg = original_killpg
if late_kills != [(late_registered.pid, module.signal.SIGKILL)] or late_registered.waits != 1:
    raise SystemExit("proof registry did not kill and reap a late process after cancellation")

fixtures = [
    module.DiscoveredMutant(
        f"{index:020x}",
        "0/3",
        module.FILES[index % 2],
        f"fixture_{index}",
        "FnValue",
        str(index),
        {"start": {"line": index + 1, "column": 1}, "end": {"line": index + 1, "column": 2}},
        "--- fixture\n+++ fixture\n",
        {},
    )
    for index in range(20)
]
original_execute_mutant = module.execute_mutant
worker_lock = threading.Lock()
worker_barrier = threading.Barrier(2)
active_workers = set()
observed_workers = set()
started = 0


def fake_execute_mutant(scratch, mutant, _output, _timeout, _registry):
    global started
    with worker_lock:
        if scratch in active_workers:
            raise RuntimeError("one scratch worktree was used concurrently")
        active_workers.add(scratch)
        observed_workers.add(scratch)
        synchronize = started < 2
        started += 1
    try:
        if synchronize:
            worker_barrier.wait(timeout=5)
        time.sleep(0.001 * (int(mutant.id[-1], 16) % 3))
        return {**mutant.public(include_diff=False), "verdict": "killed", "wall_secs": 0.001}
    finally:
        with worker_lock:
            active_workers.remove(scratch)


module.execute_mutant = fake_execute_mutant
try:
    with redirect_stdout(io.StringIO()):
        parallel_results = module.execute_selected_mutants(
            [root / "worker-a", root / "worker-b"],
            fixtures,
            root / "parallel-output",
            1,
        )
finally:
    module.execute_mutant = original_execute_mutant
if [result["id"] for result in parallel_results] != [mutant.id for mutant in fixtures]:
    raise SystemExit("parallel proof results lost deterministic inventory order")
if len(observed_workers) != 2 or active_workers:
    raise SystemExit("parallel proof workers were not isolated or did not finish cleanly")

original_executor = module.ThreadPoolExecutor


class SubmitFailureExecutor:
    def __init__(self, **_kwargs):
        self.submissions = 0
        self.shutdowns = []

    def submit(self, _function, _scratch):
        self.submissions += 1
        if self.submissions == 2:
            raise RuntimeError("synthetic submit failure")
        return module.Future()

    def shutdown(self, **kwargs):
        self.shutdowns.append(kwargs)


submit_failure_executor = None


def fake_executor(**kwargs):
    global submit_failure_executor
    submit_failure_executor = SubmitFailureExecutor(**kwargs)
    return submit_failure_executor


module.ThreadPoolExecutor = fake_executor
try:
    try:
        module.execute_selected_mutants(
            [root / "submit-a", root / "submit-b"],
            fixtures,
            root / "submit-output",
            1,
        )
    except RuntimeError as error:
        if str(error) != "synthetic submit failure":
            raise
    else:
        raise SystemExit("parallel proof runner swallowed a worker submission failure")
finally:
    module.ThreadPoolExecutor = original_executor
if submit_failure_executor is None or submit_failure_executor.shutdowns != [
    {"wait": True, "cancel_futures": True}
]:
    raise SystemExit("parallel proof runner did not shut down after partial worker submission")

first, first_seed = module.select_mutants(fixtures, "a" * 40, 5, False, 1)
second, second_seed = module.select_mutants(fixtures, "a" * 40, 5, False, 2)
if first_seed != second_seed or [item.id for item in first] == [item.id for item in second]:
    raise SystemExit("proof mutation sample epochs did not rotate the sample")
for sample in (first, second):
    if {item.file for item in sample} != set(module.FILES):
        raise SystemExit("proof mutation sample omitted a model file")
cycle = {
    item.id
    for epoch in range(len(fixtures))
    for item in module.select_mutants(fixtures, "a" * 40, 5, False, epoch)[0]
}
if cycle != {item.id for item in fixtures}:
    raise SystemExit("proof mutation epochs did not cover the full inventory")
PY

if CHIO_KANI_VERSION=latest ./scripts/kani-mutant-killer.sh \
  >"${tmp_dir}/invalid-kani-version.log" 2>&1; then
  echo "invalid Kani version selector unexpectedly passed" >&2
  exit 1
fi
grep -Fq "CHIO_KANI_VERSION must remain 0.67.0" \
  "${tmp_dir}/invalid-kani-version.log"

fake_bin="${tmp_dir}/fake-bin"
mkdir -p "${fake_bin}"
cat >"${fake_bin}/cargo" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "kani" && "${2:-}" == "--version" ]]; then
  printf '%s\n' 'Kani Rust Verifier 0.67.0 (cargo plugin)'
  exit 0
fi
printf '%s\0' "$@" >>"${KANI_ARGUMENTS}"
printf '\n' >>"${KANI_ARGUMENTS}"
SH
chmod +x "${fake_bin}/cargo"
PATH="${fake_bin}:${PATH}" KANI_ARGUMENTS="${tmp_dir}/kani-arguments" \
  bash scripts/check-kani-core.sh >"${tmp_dir}/check-kani-core.log"
python3 - "${tmp_dir}/kani-arguments" <<'PY'
from pathlib import Path
import sys

arguments = Path(sys.argv[1]).read_bytes().split(b"\0")
required = {b"kani", b"-p", b"chio-kernel-core", b"--lib", b"--fail-fast"}
if not required.issubset(arguments):
    raise SystemExit(f"Kani core command omitted required arguments: {arguments}")
PY

: >"${tmp_dir}/kani-arguments"
PATH="${fake_bin}:${PATH}" KANI_ARGUMENTS="${tmp_dir}/kani-arguments" \
  bash scripts/kani-mutant-killer.sh >"${tmp_dir}/kani-mutant-killer.log"
python3 - "${tmp_dir}/kani-arguments" <<'PY'
from pathlib import Path
import sys

commands = [
    line.split(b"\0")
    for line in Path(sys.argv[1]).read_bytes().splitlines()
    if line
]
expected_execution_order = [
    b"kani_harnesses::scalar_helpers_match_reference_predicates",
    b"kani_harnesses::reservation_ledger_matches_one_step_oracle",
    b"kani_public_harnesses::verify_inclusion_step_equivalence",
    b"kani_harnesses::time_window_classifier_matches_valid_predicate",
    b"kani_harnesses::optional_caps_never_widen_parent_cap",
    b"kani_harnesses::monetary_caps_never_widen_parent_cap",
    b"kani_harnesses::dpop_required_missing_or_invalid_fails_closed",
    b"kani_harnesses::dpop_replayed_nonce_never_admits",
    b"kani_harnesses::dpop_freshness_rejects_future_beyond_skew",
    b"kani_harnesses::budget_commit_never_increases_remaining_counters",
    b"kani_harnesses::two_sequential_budget_commits_cannot_overspend",
    b"kani_harnesses::guard_deny_or_error_dominates_pipeline",
    b"kani_harnesses::revocation_snapshot_denies_presented_token_or_ancestor",
    b"kani_harnesses::receipt_coupling_requires_every_field_match",
    b"kani_harnesses::subset_helpers_preserve_parent_requirements",
    b"kani_public_harnesses::public_normalized_scope_subset_rejects_widened_child",
    b"kani_public_harnesses::public_normalized_scope_subset_rejects_value_widened_child",
    b"kani_public_harnesses::public_normalized_scope_subset_rejects_identity_mismatch",
    b"kani_public_harnesses::public_resolve_matching_grants_rejects_out_of_scope_request",
    b"kani_public_harnesses::public_resolve_matching_grants_preserves_wildcard_matching",
    b"kani_public_harnesses::verify_scope_intersection_associative",
    b"kani_public_harnesses::verify_revocation_admission_projection",
    b"kani_public_harnesses::verify_delegation_chain_step",
    b"kani_public_harnesses::verify_reservation_ledger_terminal_classification",
    b"kani_public_harnesses::verify_reservation_ledger_conservation",
    b"kani_public_harnesses::verify_budget_admission_projection",
    b"kani_public_harnesses::verify_delegate_no_widen",
    b"kani_public_harnesses::verify_oracle_inclusion_walk_parity",
]
if len(commands) != len(expected_execution_order) + 2:
    raise SystemExit(
        "expected one command per priority harness plus full and sound inclusion "
        f"commands, found: {commands}"
    )
priority_commands = commands[: len(expected_execution_order)]
full, sound_inclusion = commands[-2:]
priority_required = {
    b"kani",
    b"-p",
    b"chio-kernel-core",
    b"--lib",
    b"--exact",
    b"--fail-fast",
    b"--no-unwinding-checks",
}
for command, expected_harness in zip(
    priority_commands, expected_execution_order, strict=True
):
    selected = [
        value
        for index, value in enumerate(command)
        if index > 0 and command[index - 1] == b"--harness"
    ]
    if not priority_required.issubset(command) or selected != [expected_harness]:
        raise SystemExit(
            "priority Kani command was not isolated in fail-fast order: "
            f"{command}"
        )
full_required = {b"kani", b"-p", b"chio-kernel-core", b"--lib", b"--fail-fast"}
if not full_required.issubset(full) or b"--harness" in full:
    raise SystemExit(f"full Kani command was narrowed: {full}")
sound_required = {
    b"kani",
    b"-p",
    b"chio-kernel-core",
    b"--lib",
    b"--harness",
    b"verify_oracle_inclusion_walk_parity",
    b"--default-unwind",
    b"8",
}
if not sound_required.issubset(sound_inclusion):
    raise SystemExit(
        f"sound inclusion Kani command omitted required arguments: {sound_inclusion}"
    )
if b"--no-unwinding-checks" in sound_inclusion:
    raise SystemExit(
        f"sound inclusion Kani command disabled unwinding checks: {sound_inclusion}"
    )
PY

echo "PASS: proof mutation discovery, sharding, application, and scoring"
