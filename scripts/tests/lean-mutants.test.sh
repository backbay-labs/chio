#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
cd "${repo_root}"

python3 scripts/lean-mutants.py --list >"${tmp_dir}/one.json"
python3 scripts/lean-mutants.py --list >"${tmp_dir}/two.json"
cmp "${tmp_dir}/one.json" "${tmp_dir}/two.json"

python3 - "${tmp_dir}/one.json" <<'PY'
import json
from pathlib import Path
import tomllib
import sys

mutants = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
allowlist = tomllib.loads(
    Path("formal/lean4/lean-mutants-allowlist.toml").read_text(encoding="utf-8")
)
allowed = {(entry["path"], entry["name"]) for entry in allowlist["definition"]}
allowed_roots = (
    "formal/lean4/Chio/Chio/Core/",
    "formal/lean4/Chio/Chio/Treaty/",
)
if len(mutants) < 5:
    raise SystemExit("Lean pilot enumerated fewer than five mutants")
if len({mutant["id"] for mutant in mutants}) != len(mutants):
    raise SystemExit("Lean mutant identifiers are not unique")
for mutant in mutants:
    if (mutant["path"], mutant["definition"]) not in allowed:
        raise SystemExit(f"Lean mutant escaped its definition allowlist: {mutant}")
    if not mutant["path"].startswith(allowed_roots):
        raise SystemExit(f"Lean mutant escaped the approved model roots: {mutant}")
if not any(mutant["path"].startswith(allowed_roots[1]) for mutant in mutants):
    raise SystemExit("Lean treaty definitions produced no mutants")
PY

python3 - <<'PY'
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys

script = Path("scripts/lean-mutants.py").resolve()
module_spec = importlib.util.spec_from_file_location("lean_mutants", script)
module = importlib.util.module_from_spec(module_spec)
assert module_spec.loader is not None
sys.modules[module_spec.name] = module
module_spec.loader.exec_module(module)

if module.COMPARISON.search("def map : Bool -> Bool := fun value => value") is not None:
    raise SystemExit("Lean comparison mutator treated arrow syntax as a comparison")
comparison_tokens = [
    match.group(1)
    for match in module.COMPARISON.finditer("left > right && low ≤ high")
]
if comparison_tokens != [">", "≤"]:
    raise SystemExit(f"Lean comparison mutator missed real operators: {comparison_tokens}")

repo = Path.cwd().resolve()
input_paths = module.lean_input_paths(repo)
if any(".lake" in path.parts for path in input_paths):
    raise SystemExit("Lean evidence inputs included the materialized .lake cache")
drift_root = repo / "target/formal/lean-mutants-drift-selftest"
drift_root.mkdir(parents=True)


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
    raise SystemExit("Lean snapshot did not retain its starting input hash")

source_snapshot = module.capture_execution_snapshot(
    drift_root, [Path("source.txt")]
)
original_input_paths = module.lean_input_paths
original_load_allowlist = module.load_allowlist
original_enumerate = module.enumerate_mutations
tracked_source.write_text("transient main-tree source\n", encoding="utf-8")
module.lean_input_paths = lambda _root: [Path("source.txt")]
module.load_allowlist = lambda _root: (5, 1, [Path("source.txt")])
module.enumerate_mutations = lambda frozen_root, _definitions: [
    (frozen_root / "source.txt").read_text(encoding="utf-8")
]
try:
    frozen_sample, frozen_timeout, frozen_inventory = module.enumerate_at_snapshot(
        drift_root, source_snapshot
    )
finally:
    module.lean_input_paths = original_input_paths
    module.load_allowlist = original_load_allowlist
    module.enumerate_mutations = original_enumerate
    tracked_source.write_text("captured source\n", encoding="utf-8")
if (frozen_sample, frozen_timeout, frozen_inventory) != (
    5,
    1,
    ["captured source\n"],
):
    raise SystemExit("Lean enumeration followed a transient main-tree edit")

evidence.write_text("drifted\n", encoding="utf-8")
try:
    module.verify_execution_snapshot(
        drift_root, snapshot, [Path("ignored-evidence.txt")]
    )
except module.LeanMutationError as error:
    if "evidence inputs drifted" not in str(error):
        raise
else:
    raise SystemExit("Lean input drift was accepted")
evidence.write_text("captured\n", encoding="utf-8")

try:
    module.verify_execution_snapshot(
        drift_root,
        snapshot,
        [Path("ignored-evidence.txt"), Path("ignored-extra.txt")],
    )
except module.LeanMutationError as error:
    if "input path set drifted" not in str(error):
        raise
else:
    raise SystemExit("Lean input path-set drift was accepted")

unrelated.write_text("dirty\n", encoding="utf-8")
try:
    module.verify_execution_snapshot(
        drift_root, snapshot, [Path("ignored-evidence.txt")]
    )
except module.LeanMutationError as error:
    if "worktree drifted" not in str(error):
        raise
else:
    raise SystemExit("Lean worktree drift was accepted")
unrelated.write_text("stable\n", encoding="utf-8")

unrelated.write_text("committed drift\n", encoding="utf-8")
git("add", "unrelated.txt")
git("commit", "--quiet", "-m", "test: move drift fixture head")
try:
    module.verify_execution_snapshot(
        drift_root, snapshot, [Path("ignored-evidence.txt")]
    )
except module.LeanMutationError as error:
    if "Git HEAD drifted" not in str(error):
        raise
else:
    raise SystemExit("Lean Git HEAD drift was accepted")
shutil.rmtree(drift_root)

_, _, definitions = module.load_allowlist(repo)
inventory = module.enumerate_mutations(repo, definitions)
if module.repo_file(
    repo, "formal/lean4/Chio/Chio/Treaty/PredicateLang.lean"
) != Path("formal/lean4/Chio/Chio/Treaty/PredicateLang.lean"):
    raise SystemExit("Lean treaty source was not accepted")
for rejected in (
    "formal/lean4/Chio/Chio/Proofs/Evaluation.lean",
    "formal/lean4/Chio/Chio/TreatyNested/Fixture.lean",
):
    try:
        module.repo_file(repo, rejected)
    except module.LeanMutationError:
        pass
    else:
        raise SystemExit(f"Lean source outside approved roots was accepted: {rejected}")
first, first_seed = module.select_mutants(inventory, "a" * 40, 5, False, 1)
second, second_seed = module.select_mutants(inventory, "a" * 40, 5, False, 2)
if first_seed != second_seed or [item.id for item in first] == [item.id for item in second]:
    raise SystemExit("Lean mutation sample epochs did not rotate the sample")
cycle = {
    item.id
    for epoch in range((len(inventory) + 4) // 5)
    for item in module.select_mutants(inventory, "a" * 40, 5, False, epoch)[0]
}
if cycle != {item.id for item in inventory}:
    raise SystemExit("Lean mutation epochs did not cover the full inventory")

source = (
    "def allowed : Bool :=\n"
    "  true && false\n\n"
    "example : true || false = true := by\n"
    "  decide\n\n"
    "theorem protected : allowed = false := by\n"
    "  rfl\n"
)
lines = source.splitlines(keepends=True)
spans = module.declarations(lines)
if spans["allowed"].kind != "def" or spans["protected"].kind != "theorem":
    raise SystemExit("Lean declaration classifier lost definition kinds")
if spans["allowed"].end != 3:
    raise SystemExit("unnamed Lean example was not a declaration boundary")

mutation = module.Mutation(
    "1" * 20,
    "allowed",
    Path("fixture.lean"),
    "swap_boolean",
    2,
    3,
    2,
    6,
    "true",
    "false",
    "2" * 64,
)
root = Path("target/formal/lean-mutants-selftest")
root.mkdir(parents=True, exist_ok=True)
try:
    (root / "fixture.lean").write_text(source, encoding="utf-8")
    mutated = module.apply_mutation(root, mutation)
    if (
        "false && false" not in mutated
        or "example : true || false = true" not in mutated
        or "theorem protected" not in mutated
    ):
        raise SystemExit("Lean mutation changed the wrong source span")
finally:
    shutil.rmtree(root)

external = repo / "target/formal/lean-mutants-external-selftest"
external.mkdir(parents=True, exist_ok=True)
sentinel = external / "sentinel"
sentinel.write_text("preserve", encoding="utf-8")
original_output = module.OUTPUT
module.OUTPUT = Path("target/formal/lean-mutants-symlink-selftest")
link = repo / module.OUTPUT
link.parent.mkdir(parents=True, exist_ok=True)
link.symlink_to(external, target_is_directory=True)
try:
    try:
        module.safe_output(repo)
    except module.LeanMutationError:
        pass
    else:
        raise SystemExit("symlinked Lean mutation output was accepted")
    if sentinel.read_text(encoding="utf-8") != "preserve":
        raise SystemExit("Lean mutation symlink fixture was modified")
finally:
    link.unlink(missing_ok=True)
    module.OUTPUT = original_output
    shutil.rmtree(external)

source_external = repo / "target/formal/lean-mutants-source-external-selftest"
source_guard = repo / "target/formal/lean-mutants-source-guard-selftest"
relative_source = Path("formal/lean4/Chio/Chio/Core/Fixture.lean")
external_source = source_external / "Fixture.lean"
external_source.parent.mkdir(parents=True, exist_ok=True)
external_source.write_text("def guarded : Bool := true\n", encoding="utf-8")
core_link = source_guard / relative_source.parent
core_link.parent.mkdir(parents=True, exist_ok=True)
core_link.symlink_to(source_external, target_is_directory=True)
allowlist_path = source_guard / module.ALLOWLIST
allowlist_path.parent.mkdir(parents=True, exist_ok=True)
allowlist_path.write_text(
    'schema = "chio.lean-mutants-allowlist.v1"\n'
    "sample_size = 5\n"
    "timeout_secs = 1\n\n"
    "[[definition]]\n"
    'name = "guarded"\n'
    f'path = "{relative_source.as_posix()}"\n',
    encoding="utf-8",
)
oracle = source_guard / module.LEAN_TOOLCHAIN
oracle.parent.mkdir(parents=True, exist_ok=True)
oracle.write_text("preserve oracle\n", encoding="utf-8")
external_before = external_source.read_bytes()
oracle_before = oracle.read_bytes()
try:
    module.load_allowlist(source_guard)
except module.LeanMutationError:
    pass
else:
    raise SystemExit("Lean discovery accepted a symlinked source component")
try:
    module.write_mutable_source(source_guard, relative_source, "changed\n")
except module.LeanMutationError:
    pass
else:
    raise SystemExit("Lean source write followed a symlinked source component")
if external_source.read_bytes() != external_before:
    raise SystemExit("Lean source-symlink rejection changed an external source")
if oracle.read_bytes() != oracle_before:
    raise SystemExit("Lean source-symlink rejection changed an oracle path")

final_link_root = repo / "target/formal/lean-mutants-final-link-selftest"
final_link = final_link_root / relative_source
final_link.parent.mkdir(parents=True, exist_ok=True)
final_link.symlink_to(oracle)
try:
    module.mutable_source_path(final_link_root, relative_source)
except module.LeanMutationError:
    pass
else:
    raise SystemExit("Lean source validation accepted a final symlink")
if oracle.read_bytes() != oracle_before:
    raise SystemExit("final Lean source symlink changed its oracle target")

class InterruptedProcess:
    pid = 434343

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
interrupt_log = repo / "target/formal/lean-interrupt.log"
module.subprocess.Popen = lambda *args, **kwargs: (
    popen_options.append(kwargs) or interrupted
)
module.os.killpg = lambda pid, sig: kills.append((pid, sig))
try:
    try:
        module.run_process(["unused"], repo, interrupt_log, 1)
    except KeyboardInterrupt:
        pass
    else:
        raise SystemExit("Lean runner swallowed an interrupt")
finally:
    module.subprocess.Popen = original_popen
    module.os.killpg = original_killpg
    interrupt_log.unlink(missing_ok=True)
if (
    kills != [(interrupted.pid, module.signal.SIGKILL)]
    or interrupted.waits != 2
    or len(popen_options) != 1
    or popen_options[0].get("start_new_session") is not True
):
    raise SystemExit("Lean runner did not kill and reap its process group on interrupt")

shutil.rmtree(source_external)
shutil.rmtree(source_guard)
shutil.rmtree(final_link_root)

diagnostic = repo / "target/formal/lean-mutants-diagnostic-selftest.log"
diagnostic.write_text("Chio/Core/Fixture.lean:2:3: error: type mismatch\n", encoding="utf-8")
try:
    if module.classify_lake(1, diagnostic) != "killed":
        raise SystemExit("Lean source diagnostic was not classified as killed")
    diagnostic.write_text(
        "error: Chio/Core/Fixture.lean:2:3: Tactic `rfl` failed\n",
        encoding="utf-8",
    )
    if module.classify_lake(1, diagnostic) != "killed":
        raise SystemExit("Lake-prefixed Lean source diagnostic was not classified as killed")
    diagnostic.write_text("error: external command failed\n", encoding="utf-8")
    try:
        module.classify_lake(1, diagnostic)
    except module.LeanMutationError:
        pass
    else:
        raise SystemExit("Lean infrastructure failure was classified as killed")
finally:
    diagnostic.unlink(missing_ok=True)
PY

echo "PASS: Lean model mutation enumeration stays inside allowlisted definitions"
