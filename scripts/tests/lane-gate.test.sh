#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
mkdir -p "${tmp_dir}/bin"

config="${tmp_dir}/releases.toml"
cat >"${config}" <<'TOML'
[gates.scheduled]
workflow = "nightly.yml"
job = "target job"
event = "schedule"
posture = "advisory"
required_streak = 2
evidence_after_run_id = 100
max_age_hours = 48
activation_target = 90
scored_artifact_prefix = "scored-nightly-"
scored_artifact_schema = "chio.spec-mutants-report.v1"
scored_sample_size = 20
scored_inventory_size = 30
scored_inventory_sha256 = "SPEC_INVENTORY_SHA256"
scored_tools = ["apalache=0.50.1"]
scored_sources = [
  "SourceA=formal/SourceA.tla",
  "SourceB=formal/SourceB.tla",
]
scored_seeds = ["receipt-before-allow-guard", "revocation-transitive-cut"]

[gates.proof]
workflow = "proof-mutants.yml"
job = "proof job"
event = "schedule"
posture = "advisory"
required_streak = 1
evidence_after_run_id = 200
max_age_hours = 48
activation_target = 90
scored_artifact_prefix = "proof-mutants-report-"
scored_artifact_schema = "chio.proof-mutants-report.v1"
scored_sample_size = 10
scored_inventory_size = 20
scored_inventory_sha256 = "PROOF_INVENTORY_SHA256"
scored_files = [
  "crates/kernel/chio-kernel-core/src/formal_core.rs",
  "crates/kernel/chio-kernel-core/src/formal_aeneas.rs",
]
scored_viability_target = 80
scored_tools = [
  "cargo_mutants=25.3.1",
  "kani=0.67.0",
  "rustc=1.93.0",
]

[gates.strict]
workflow = "nightly.yml"
job = "strict job"
event = "schedule"
posture = "advisory"
required_streak = 2
evidence_after_run_id = 100
max_age_hours = 48
strict_mode_required = true
strict_artifact_prefix = "formal-proof-report-strict-"

[gates.pull-request]
workflow = "formal-pr-smoke.yml"
job = "pull request job"
event = "pull_request"
posture = "advisory"
required_streak = 2
evidence_after_run_id = 200
max_age_hours = 168
base_branch = "target"
execution_artifact_prefix = "lane-executed-pull-request-"

[gates.frozen]
workflow = "temporal.yml"
job = "temporal job"
event = "schedule"
posture = "advisory"
required_streak = 2
evidence_after_run_id = 100
max_age_hours = 48
frozen = true
frozen_reason = "property is not reliable"
TOML

fixture_dir="${tmp_dir}/artifacts"
mkdir -p "${fixture_dir}"
python3 - "${fixture_dir}" <<'PY'
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import sys
import tomllib
from types import SimpleNamespace
import zipfile

root = Path(sys.argv[1])
workspace = Path.cwd()


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, workspace / path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


spec_producer = load_module("lane_spec_mutants", "scripts/spec-mutants.py")
proof_producer = load_module("lane_proof_mutants", "scripts/proof-mutants.py")

allowlist = tomllib.loads(
    (workspace / "formal/apalache/spec-mutants-allowlist.toml").read_text(encoding="utf-8")
)
negative_registry = tomllib.loads(
    (workspace / allowlist["negative_registry"]).read_text(encoding="utf-8")
)
SEED_SPECS = {
    entry["name"]: entry["negative_spec"] for entry in allowlist["seed"]
}
SEED_NAMES = tuple(SEED_SPECS)

spec_settings = spec_producer.load_settings(
    workspace, Path("formal/apalache/spec-mutants-allowlist.toml")
)
SPEC_INPUT_PATHS = spec_producer.spec_input_paths(workspace, spec_settings)
PROOF_INPUT_PATHS = proof_producer.proof_input_paths(workspace)


def report_inputs(paths):
    return [
        {
            "path": path.as_posix(),
            "sha256": hashlib.sha256((workspace / path).read_bytes()).hexdigest(),
        }
        for path in paths
    ]


def spec_score(mutants):
    counts = {
        verdict: sum(mutant["verdict"] == verdict for mutant in mutants)
        for verdict in ("killed", "survived", "unviable", "timeout")
    }
    denominator = counts["killed"] + counts["survived"] + counts["timeout"]
    activation = round(100.0 * counts["killed"] / denominator, 3) if denominator else 0.0
    completed = counts["killed"] + counts["survived"] + counts["unviable"]
    completion = round(100.0 * completed / len(mutants), 3) if mutants else 0.0
    return {
        "sampled": len(mutants),
        **counts,
        "score_denominator": denominator,
        "timeout_policy": "timeouts count as not killed",
        "activation_ratio_percent": activation,
        "completion_ratio_percent": completion,
        "activation_target_percent": 90,
        "activation_met": activation >= 90,
    }


def spec_aggregates(mutants):
    sources = {
        source: spec_score([mutant for mutant in mutants if mutant["spec"] == source])
        for source in ("SourceA", "SourceB")
    }
    aggregate = spec_score(mutants)
    aggregate["global_activation_met"] = aggregate["activation_met"]
    aggregate["source_activation_met"] = all(
        source["activation_met"] for source in sources.values()
    )
    aggregate["activation_met"] = (
        aggregate["global_activation_met"] and aggregate["source_activation_met"]
    )
    return aggregate, sources


def select_spec(inventory, commit, sample_size, epoch):
    generator = random.Random(int(commit[:16], 16))
    permutation = list(range(len(inventory)))
    generator.shuffle(permutation)
    rank = {index: position for position, index in enumerate(permutation)}
    selected = {
        index for index, entry in enumerate(inventory) if "registered_seed" in entry
    }
    for source in sorted({entry["spec"] for entry in inventory}):
        candidates = sorted(
            (
                index
                for index, entry in enumerate(inventory)
                if entry["spec"] == source and "registered_seed" not in entry
            ),
            key=rank.__getitem__,
        )
        selected.add(candidates[epoch % len(candidates)])
    remaining = [index for index in permutation if index not in selected]
    slots = sample_size - len(selected)
    start = epoch * slots % len(remaining)
    selected.update(
        remaining[(start + offset) % len(remaining)] for offset in range(slots)
    )
    return sorted(selected)


def registered_negative():
    return [
        {
            "spec": entry["spec"],
            "cfg": entry["cfg"],
            "invariant": entry["falsifies"],
            "length": entry["length"],
            "timeout_secs": entry["timeout_secs"],
            "verdict": "killed",
            "log_sha256": hashlib.sha256(
                f"log:{entry['spec']}".encode()
            ).hexdigest(),
            "trace": (
                "target/formal/spec-mutants/registered-negative/"
                f"{Path(entry['spec']).stem}/run/violation1.itf.json"
            ),
            "trace_sha256": hashlib.sha256(
                f"trace:{entry['spec']}".encode()
            ).hexdigest(),
        }
        for entry in negative_registry["negative"]
    ]


def positive_baselines():
    return [
        {
            "spec": entry["name"],
            "path": entry["path"],
            "cfg": entry["cfg"],
            "invariant": entry["invariant"],
            "length": entry["length"],
            "verdict": "survived",
            "apalache_exit": 0,
            "wall_secs": 0.125,
            "log_sha256": hashlib.sha256(
                f"positive:{entry['name']}".encode()
            ).hexdigest(),
        }
        for entry in allowlist["spec"]
    ]


def report(commit, run_id, run_attempt, run_number):
    inventory = []
    for source_index, source in enumerate(("SourceA", "SourceB")):
        for position in range(15):
            index = source_index * 15 + position
            entry = {
                "id": f"{index:020x}",
                "spec": source,
                "path": f"formal/{source}.tla",
                **({"registered_seed": SEED_NAMES[index]} if index < len(SEED_NAMES) else {}),
            }
            inventory.append(entry)
    selected = select_spec(inventory, commit, 20, run_number)
    producer_selected, _ = spec_producer.select_mutations(
        [
            SimpleNamespace(
                id=entry["id"],
                spec=entry["spec"],
                seed=entry.get("registered_seed"),
            )
            for entry in inventory
        ],
        commit=commit,
        sample_size=20,
        full=False,
        sample_epoch=run_number,
    )
    if [inventory[index]["id"] for index in selected] != [
        entry.id for entry in producer_selected
    ]:
        raise RuntimeError("specification lane fixture selector drifted from its producer")
    mutants = [{**inventory[index], "verdict": "killed"} for index in selected]
    aggregate, source_aggregates = spec_aggregates(mutants)
    return {
        "schema": "chio.spec-mutants-report.v1",
        "commit": commit,
        "worktree": {"clean": True},
        "ci_run": {
            "run_id": run_id,
            "run_attempt": run_attempt,
            "run_number": run_number,
        },
        "sample_seed": commit[:16],
        "sample_epoch": run_number,
        "full_cycle": False,
        "enumerated": 30,
        "inventory": inventory,
        "inventory_sha256": hashlib.sha256(
            json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "sample_size_requested": 20,
        "tools": {"apalache": "0.50.1"},
        "inputs": report_inputs(SPEC_INPUT_PATHS),
        "mutants": mutants,
        "registered_seeds": [
            {
                "name": name,
                "mutant_id": f"{index:020x}",
                "negative_spec": SEED_SPECS[name],
                "status": "subsumed",
            }
            for index, name in enumerate(SEED_NAMES)
        ],
        "registered_negative": registered_negative(),
        "positive_baselines": positive_baselines(),
        "source_aggregates": source_aggregates,
        "aggregate": aggregate,
    }


PROOF_FILES = (
    "crates/kernel/chio-kernel-core/src/formal_core.rs",
    "crates/kernel/chio-kernel-core/src/formal_aeneas.rs",
)


def proof_score(mutants):
    counts = {
        verdict: sum(mutant["verdict"] == verdict for mutant in mutants)
        for verdict in ("killed", "survived", "unviable", "timeout")
    }
    denominator = counts["killed"] + counts["survived"] + counts["timeout"]
    activation = round(100.0 * counts["killed"] / denominator, 3) if denominator else 0.0
    viability = round(100.0 * denominator / len(mutants), 3) if mutants else 0.0
    completion = round(
        100.0
        * (counts["killed"] + counts["survived"] + counts["unviable"])
        / len(mutants),
        3,
    ) if mutants else 0.0
    threshold_met = activation >= 90
    viability_met = viability >= 80
    return {
        "sampled": len(mutants),
        **counts,
        "score_denominator": denominator,
        "timeout_policy": "timeouts count as not killed",
        "activation_ratio_percent": activation,
        "completion_ratio_percent": completion,
        "activation_target_percent": 90,
        "activation_threshold_met": threshold_met,
        "viability_ratio_percent": viability,
        "viability_target_percent": 80,
        "viability_met": viability_met,
        "activation_met": threshold_met and viability_met,
    }


def proof_aggregates(mutants):
    sources = {
        path: proof_score([mutant for mutant in mutants if mutant["file"] == path])
        for path in PROOF_FILES
    }
    aggregate = proof_score(mutants)
    aggregate["global_activation_met"] = aggregate["activation_met"]
    aggregate["source_activation_met"] = all(
        source["activation_met"] for source in sources.values()
    )
    aggregate["activation_met"] = (
        aggregate["global_activation_met"] and aggregate["source_activation_met"]
    )
    return aggregate, sources


def select_proof(inventory, commit, sample_size, epoch):
    cycle_epochs = len(inventory) // sample_size
    aligned_epoch = epoch % cycle_epochs
    cycle = epoch // cycle_epochs
    generator = random.Random(int(commit[:16], 16) + cycle)
    source_groups = [
        [index for index, entry in enumerate(inventory) if entry["file"] == source]
        for source in PROOF_FILES
    ]
    for group in source_groups:
        generator.shuffle(group)
    base, remainder = divmod(len(source_groups[0]), cycle_epochs)
    first_counts = [
        base + (position < remainder) for position in range(cycle_epochs)
    ]
    second_counts = [sample_size - count for count in first_counts]
    first_start = sum(first_counts[:aligned_epoch])
    second_start = sum(second_counts[:aligned_epoch])
    return sorted(
        source_groups[0][first_start : first_start + first_counts[aligned_epoch]]
        + source_groups[1][second_start : second_start + second_counts[aligned_epoch]]
    )


def proof_report(commit, run_id, run_attempt, run_number):
    inventory = []
    for file_index, path in enumerate(PROOF_FILES):
        for position in range(10):
            index = file_index * 10 + position
            entry = {
                "id": f"{index + 100:020x}",
                "file": path,
                "function": f"proof_function_{file_index}_{position}",
                "genre": "FnValue",
                "replacement": "false" if position % 2 == 0 else "true",
            }
            inventory.append(entry)
    selected = select_proof(inventory, commit, 10, run_number)
    producer_selected, _ = proof_producer.select_mutants(
        [
            SimpleNamespace(id=entry["id"], file=Path(entry["file"]))
            for entry in inventory
        ],
        commit,
        10,
        False,
        run_number,
    )
    if [inventory[index]["id"] for index in selected] != [
        entry.id for entry in producer_selected
    ]:
        raise RuntimeError("proof lane fixture selector drifted from its producer")
    mutants = [{**inventory[index], "verdict": "killed"} for index in selected]
    aggregate, source_aggregates = proof_aggregates(mutants)
    return {
        "schema": "chio.proof-mutants-report.v1",
        "commit": commit,
        "worktree": {"clean": True},
        "ci_run": {
            "run_id": run_id,
            "run_attempt": run_attempt,
            "run_number": run_number,
        },
        "sample_seed": commit[:16],
        "sample_epoch": run_number,
        "full_cycle": False,
        "enumerated": 20,
        "inventory": inventory,
        "inventory_sha256": hashlib.sha256(
            json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "sample_size_requested": 10,
        "tools": {
            "cargo_mutants": "25.3.1",
            "kani": "0.67.0",
            "rustc": "1.93.0",
        },
        "inputs": report_inputs(PROOF_INPUT_PATHS),
        "mutants": mutants,
        "source_aggregates": source_aggregates,
        "aggregate": aggregate,
    }


def archive(name, documents):
    with zipfile.ZipFile(root / name, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path, document in documents.items():
            bundle.writestr(path, json.dumps(document, sort_keys=True) + "\n")


valid_105 = report("a" * 40, 105, 2, 105)
archive("valid-105.zip", {"report.json": valid_105})
archive("valid-104.zip", {"report.json": report("b" * 40, 104, 2, 104)})
archive("valid-106.zip", {"report.json": report("f" * 40, 106, 1, 106)})

stale_commit = deepcopy(valid_105)
stale_commit["commit"] = "c" * 40
archive("stale-commit.zip", {"report.json": stale_commit})

stale_run = deepcopy(valid_105)
stale_run["ci_run"]["run_id"] = 104
archive("stale-run.zip", {"report.json": stale_run})

small_inventory = deepcopy(valid_105)
small_inventory["enumerated"] = 20
small_inventory["full_cycle"] = True
archive("small-inventory.zip", {"report.json": small_inventory})

weak_target = deepcopy(valid_105)
weak_target["aggregate"]["activation_target_percent"] = 80
archive("weak-target.zip", {"report.json": weak_target})

false_activation = deepcopy(valid_105)
false_activation["aggregate"]["activation_met"] = False
archive("false-activation.zip", {"report.json": false_activation})

bad_counts = deepcopy(valid_105)
bad_counts["aggregate"]["killed"] = 17
archive("bad-counts.zip", {"report.json": bad_counts})

weak_source = deepcopy(valid_105)
for mutant in [
    item for item in weak_source["mutants"] if item["spec"] == "SourceB"
][:2]:
    mutant["verdict"] = "survived"
weak_source["aggregate"], weak_source["source_aggregates"] = spec_aggregates(
    weak_source["mutants"]
)
archive("weak-source.zip", {"report.json": weak_source})

omitted_seed = deepcopy(valid_105)
omitted_seed["registered_seeds"].pop()
archive("omitted-seed.zip", {"report.json": omitted_seed})

mismatched_seed = deepcopy(valid_105)
mismatched_seed["registered_seeds"][0]["negative_spec"] = (
    "formal/apalache/_negative_tests/OtherBroken.tla"
)
archive("mismatched-seed.zip", {"report.json": mismatched_seed})

seed_survivor = deepcopy(valid_105)
seed_name = SEED_NAMES[0]
next(
    mutant
    for mutant in seed_survivor["mutants"]
    if mutant.get("registered_seed") == seed_name
)["verdict"] = "survived"
seed_survivor["aggregate"], seed_survivor["source_aggregates"] = spec_aggregates(
    seed_survivor["mutants"]
)
archive("seed-survivor.zip", {"report.json": seed_survivor})

omitted_negative = deepcopy(valid_105)
omitted_negative["registered_negative"].pop()
archive("omitted-negative.zip", {"report.json": omitted_negative})

mismatched_negative = deepcopy(valid_105)
mismatched_negative["registered_negative"][0]["invariant"] = "OtherInvariant"
archive("mismatched-negative.zip", {"report.json": mismatched_negative})

unsafe_negative_trace = deepcopy(valid_105)
unsafe_negative_trace["registered_negative"][0]["trace"] = (
    "target/formal/../escaped/registered-negative/"
    f"{Path(unsafe_negative_trace['registered_negative'][0]['spec']).stem}/"
    "run/violation1.itf.json"
)
archive("unsafe-negative-trace.zip", {"report.json": unsafe_negative_trace})

invalid_negative_hash = deepcopy(valid_105)
invalid_negative_hash["registered_negative"][0]["trace_sha256"] = "A" * 64
archive("invalid-negative-hash.zip", {"report.json": invalid_negative_hash})

missing_positive = deepcopy(valid_105)
missing_positive["positive_baselines"].pop()
archive("missing-positive.zip", {"report.json": missing_positive})

extra_positive = deepcopy(valid_105)
extra_positive["positive_baselines"].append(
    {
        "spec": "UnexpectedSpec",
        "path": "formal/apalache/UnexpectedSpec.tla",
        "cfg": "formal/apalache/MCUnexpectedSpec.cfg",
        "invariant": "SafetyInv",
        "length": 1,
        "verdict": "survived",
        "apalache_exit": 0,
        "wall_secs": 0.125,
        "log_sha256": "0" * 64,
    }
)
archive("extra-positive.zip", {"report.json": extra_positive})

duplicate_positive = deepcopy(valid_105)
duplicate_positive["positive_baselines"][-1] = deepcopy(
    duplicate_positive["positive_baselines"][0]
)
archive("duplicate-positive.zip", {"report.json": duplicate_positive})

wrong_positive_metadata = deepcopy(valid_105)
wrong_positive_metadata["positive_baselines"][0]["length"] += 1
archive("wrong-positive-metadata.zip", {"report.json": wrong_positive_metadata})

nonzero_positive = deepcopy(valid_105)
nonzero_positive["positive_baselines"][0]["apalache_exit"] = 12
archive("nonzero-positive.zip", {"report.json": nonzero_positive})

killed_positive = deepcopy(valid_105)
killed_positive["positive_baselines"][0]["verdict"] = "killed"
archive("killed-positive.zip", {"report.json": killed_positive})

bad_positive_hash = deepcopy(valid_105)
bad_positive_hash["positive_baselines"][0]["log_sha256"] = "A" * 64
archive("bad-positive-hash.zip", {"report.json": bad_positive_hash})

missing_input = deepcopy(valid_105)
missing_input["inputs"].pop()
archive("missing-input.zip", {"report.json": missing_input})

extra_input = deepcopy(valid_105)
extra_input["inputs"].append(
    {"path": "unexpected-input.txt", "sha256": "0" * 64}
)
archive("extra-input.zip", {"report.json": extra_input})

stale_input = deepcopy(valid_105)
stale_input["inputs"][0]["sha256"] = "0" * 64
archive("stale-input.zip", {"report.json": stale_input})

cherry_picked = deepcopy(valid_105)
selected_ids = {mutant["id"] for mutant in cherry_picked["mutants"]}
victim_index = next(
    index
    for index, mutant in enumerate(cherry_picked["mutants"])
    if "registered_seed" not in mutant
)
victim_source = cherry_picked["mutants"][victim_index]["spec"]
substitute = next(
    entry
    for entry in cherry_picked["inventory"]
    if entry["id"] not in selected_ids
    and entry["spec"] == victim_source
    and "registered_seed" not in entry
)
cherry_picked["mutants"][victim_index] = {**substitute, "verdict": "killed"}
cherry_picked["aggregate"], cherry_picked["source_aggregates"] = spec_aggregates(
    cherry_picked["mutants"]
)
archive("cherry-picked.zip", {"report.json": cherry_picked})

duplicate_id = deepcopy(valid_105)
duplicate_id["mutants"][-1]["id"] = duplicate_id["mutants"][0]["id"]
archive("duplicate-id.zip", {"report.json": duplicate_id})

archive(
    "ambiguous-report.zip",
    {"report.json": valid_105, "duplicate.json": valid_105},
)
wrong_schema = deepcopy(valid_105)
wrong_schema["schema"] = "chio.scored-test.v0"
archive("wrong-schema.zip", {"report.json": wrong_schema})

valid_proof = proof_report("d" * 40, 205, 3, 305)
archive("proof-valid.zip", {"report.json": valid_proof})

proof_dirty = deepcopy(valid_proof)
proof_dirty["worktree"] = {
    "clean": False,
    "status_sha256": "0" * 64,
    "tracked_diff_sha256": "1" * 64,
}
archive("proof-dirty.zip", {"report.json": proof_dirty})

proof_omitted_file = deepcopy(valid_proof)
proof_omitted_file["source_aggregates"].pop(PROOF_FILES[1])
archive("proof-omitted-file.zip", {"report.json": proof_omitted_file})

proof_relabeled_file = deepcopy(valid_proof)
proof_relabeled_file["source_aggregates"]["crates/kernel/chio-kernel-core/src/renamed.rs"] = (
    proof_relabeled_file["source_aggregates"].pop(PROOF_FILES[1])
)
archive("proof-relabeled-file.zip", {"report.json": proof_relabeled_file})

proof_weak_source = deepcopy(valid_proof)
next(
    mutant
    for mutant in proof_weak_source["mutants"]
    if mutant["file"] == PROOF_FILES[1]
)["verdict"] = "survived"
proof_weak_source["aggregate"], proof_weak_source["source_aggregates"] = proof_aggregates(
    proof_weak_source["mutants"]
)
proof_weak_source["aggregate"]["activation_met"] = True
proof_weak_source["aggregate"]["source_activation_met"] = True
archive("proof-weak-source.zip", {"report.json": proof_weak_source})

proof_low_viability = deepcopy(valid_proof)
seen_files = {path: 0 for path in PROOF_FILES}
for mutant in proof_low_viability["mutants"]:
    if seen_files[mutant["file"]] < 2:
        mutant["verdict"] = "unviable"
        seen_files[mutant["file"]] += 1
proof_low_viability["aggregate"], proof_low_viability["source_aggregates"] = proof_aggregates(
    proof_low_viability["mutants"]
)
proof_low_viability["aggregate"]["activation_met"] = True
proof_low_viability["aggregate"]["viability_met"] = True
proof_low_viability["aggregate"]["global_activation_met"] = True
proof_low_viability["aggregate"]["source_activation_met"] = True
archive("proof-low-viability.zip", {"report.json": proof_low_viability})

proof_tool_drift = deepcopy(valid_proof)
proof_tool_drift["tools"]["kani"] = "0.68.0"
archive("proof-tool-drift.zip", {"report.json": proof_tool_drift})

proof_inventory_digest = deepcopy(valid_proof)
proof_inventory_digest["inventory_sha256"] = "0" * 64
archive("proof-inventory-digest.zip", {"report.json": proof_inventory_digest})

proof_inventory_content = deepcopy(valid_proof)
proof_inventory_content["inventory"][-1]["function"] = "unregistered_proof_function"
proof_inventory_content["inventory_sha256"] = hashlib.sha256(
    json.dumps(
        proof_inventory_content["inventory"],
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
).hexdigest()
archive("proof-inventory-content.zip", {"report.json": proof_inventory_content})

proof_cherry_picked = deepcopy(valid_proof)
proof_selected_ids = {mutant["id"] for mutant in proof_cherry_picked["mutants"]}
proof_victim_index = 0
proof_victim_file = proof_cherry_picked["mutants"][proof_victim_index]["file"]
proof_substitute = next(
    entry
    for entry in proof_cherry_picked["inventory"]
    if entry["id"] not in proof_selected_ids and entry["file"] == proof_victim_file
)
proof_cherry_picked["mutants"][proof_victim_index] = {
    **proof_substitute,
    "verdict": "killed",
}
proof_cherry_picked["aggregate"], proof_cherry_picked["source_aggregates"] = proof_aggregates(
    proof_cherry_picked["mutants"]
)
archive("proof-cherry-picked.zip", {"report.json": proof_cherry_picked})

(root / "spec-inventory.sha256").write_text(valid_105["inventory_sha256"] + "\n")
(root / "proof-inventory.sha256").write_text(valid_proof["inventory_sha256"] + "\n")
(root / "input-paths.txt").write_text(
    "\n".join(
        sorted(
            {path.as_posix() for path in SPEC_INPUT_PATHS}
            | {path.as_posix() for path in PROOF_INPUT_PATHS}
        )
    )
    + "\n",
    encoding="utf-8",
)
PY

real_git="$(command -v git)"
input_repo="${tmp_dir}/input-repo"
git init --quiet "${input_repo}"
git -C "${input_repo}" config user.email lane-gate@example.invalid
git -C "${input_repo}" config user.name lane-gate-test
while IFS= read -r path; do
  mkdir -p "${input_repo}/$(dirname "${path}")"
  cp -p -- "${path}" "${input_repo}/${path}"
done <"${fixture_dir}/input-paths.txt"
git -C "${input_repo}" add --all
git -C "${input_repo}" commit --quiet -m "test: regular mutation inputs"
input_commit="$(git -C "${input_repo}" rev-parse HEAD)"

rm "${input_repo}/scripts/spec-mutants.py"
ln -s ../Cargo.toml "${input_repo}/scripts/spec-mutants.py"
git -C "${input_repo}" add --all
git -C "${input_repo}" commit --quiet -m "test: symlinked mutation input"
input_symlink_commit="$(git -C "${input_repo}" rev-parse HEAD)"

cat >"${tmp_dir}/bin/git" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

arguments=("$@")
selected="${MOCK_INPUT_COMMIT}"
if [[ "${MOCK_SCORED_MODE:-valid}" == "input-symlink" ]]; then
  selected="${MOCK_INPUT_SYMLINK_COMMIT}"
fi
case "${1:-}" in
  cat-file)
    if [[ "${2:-}" == "-t" && "${3:-}" =~ ^(a{40}|b{40}|c{40}|d{40}|e{40}|f{40})$ ]]; then
      arguments[2]="${selected}"
    fi
    ;;
  ls-tree)
    for index in "${!arguments[@]}"; do
      if [[ "${arguments[${index}]}" =~ ^(a{40}|b{40}|c{40}|d{40}|e{40}|f{40})$ ]]; then
        arguments[${index}]="${selected}"
      fi
    done
    ;;
esac
exec "${MOCK_REAL_GIT}" -C "${MOCK_INPUT_REPO}" "${arguments[@]}"
SH
chmod +x "${tmp_dir}/bin/git"

sed -i "s/SPEC_INVENTORY_SHA256/$(cat "${fixture_dir}/spec-inventory.sha256")/" "${config}"
sed -i "s/PROOF_INVENTORY_SHA256/$(cat "${fixture_dir}/proof-inventory.sha256")/" "${config}"
export MOCK_FIXTURE_DIR="${fixture_dir}"
export MOCK_INPUT_REPO="${input_repo}"
export MOCK_INPUT_COMMIT="${input_commit}"
export MOCK_INPUT_SYMLINK_COMMIT="${input_symlink_commit}"
export MOCK_REAL_GIT="${real_git}"
export LANE_GATE_GIT="${tmp_dir}/bin/git"

cat >"${tmp_dir}/bin/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"${MOCK_GH_LOG}"
case "${MOCK_GH_ERROR:-none}" in
  rate-limit)
    printf '%s\n' "API rate limit exceeded" >&2
    exit 1
    ;;
  transport)
    printf '%s\n' "could not resolve host api.github.com" >&2
    exit 1
    ;;
  not-found)
    printf '%s\n' "HTTP 404: Not Found" >&2
    exit 1
    ;;
  malformed)
    printf '%s\n' '{not-json'
    exit 0
    ;;
  none) ;;
  *)
    printf 'unknown MOCK_GH_ERROR: %s\n' "${MOCK_GH_ERROR}" >&2
    exit 2
    ;;
esac
endpoint="${*: -1}"
case "${endpoint}" in
  *'/actions/workflows/nightly.yml/runs?'*)
    timestamp="${MOCK_RUN_TIMESTAMP:-2026-07-10T10:00:00Z}"
    newer_success=""
    if [[ "${MOCK_NEWER_SUCCESS:-0}" == "1" ]]; then
      newer_success='{"id":106,"run_attempt":1,"run_number":106,"head_sha":"ffffffffffffffffffffffffffffffffffffffff","event":"schedule","conclusion":"success","created_at":"2026-07-10T10:30:00Z","html_url":"https://example.invalid/106"},'
    fi
    printf '%s\n' "{\"workflow_runs\":[
  ${newer_success}
  {\"id\":105,\"run_attempt\":2,\"run_number\":105,\"head_sha\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"event\":\"schedule\",\"conclusion\":\"success\",\"created_at\":\"${timestamp}\",\"html_url\":\"https://example.invalid/105\"},
  {\"id\":104,\"run_attempt\":2,\"run_number\":104,\"head_sha\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"event\":\"schedule\",\"conclusion\":\"success\",\"created_at\":\"2026-07-10T09:00:00Z\",\"html_url\":\"https://example.invalid/104\"},
  {\"id\":103,\"run_attempt\":1,\"run_number\":103,\"head_sha\":\"cccccccccccccccccccccccccccccccccccccccc\",\"event\":\"workflow_dispatch\",\"conclusion\":\"success\",\"created_at\":\"2026-07-10T08:00:00Z\",\"html_url\":\"https://example.invalid/103\"},
  {\"id\":102,\"run_attempt\":1,\"run_number\":102,\"head_sha\":\"dddddddddddddddddddddddddddddddddddddddd\",\"event\":\"schedule\",\"conclusion\":\"failure\",\"created_at\":\"2026-07-10T07:00:00Z\",\"html_url\":\"https://example.invalid/102\"},
  {\"id\":99,\"run_attempt\":1,\"run_number\":99,\"head_sha\":\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\",\"event\":\"schedule\",\"conclusion\":\"success\",\"created_at\":\"2026-07-10T06:00:00Z\",\"html_url\":\"https://example.invalid/99\"}
]}"
    ;;
  *'/actions/workflows/proof-mutants.yml/runs?'*)
    cat <<'JSON'
{"workflow_runs":[
  {"id":205,"run_attempt":3,"run_number":305,"head_sha":"dddddddddddddddddddddddddddddddddddddddd","event":"schedule","conclusion":"success","created_at":"2026-07-10T10:15:00Z","html_url":"https://example.invalid/205"}
]}
JSON
    ;;
  *'/actions/workflows/formal-pr-smoke.yml/runs?'*)
    cat <<'JSON'
{"workflow_runs":[
  {"id":203,"run_attempt":1,"event":"pull_request","conclusion":"success","created_at":"2026-07-10T10:30:00Z","html_url":"https://example.invalid/203","pull_requests":[{"base":{"ref":"other"}}]},
  {"id":202,"run_attempt":3,"event":"pull_request","conclusion":"success","created_at":"2026-07-10T10:00:00Z","html_url":"https://example.invalid/202","pull_requests":[{"base":{"ref":"target"}}]},
  {"id":201,"run_attempt":1,"event":"workflow_dispatch","conclusion":"success","created_at":"2026-07-10T09:00:00Z","html_url":"https://example.invalid/201"}
]}
JSON
    ;;
  *'/actions/workflows/temporal.yml/runs?'*)
    printf '%s\n' '{"workflow_runs":[]}'
    ;;
  *'/actions/workflows/nightly.yml')
    printf '%s\n' '{"id":77,"path":".github/workflows/nightly.yml"}'
    ;;
  *'/actions/runs/106')
    printf '%s\n' '{"id":106,"workflow_id":77,"run_attempt":1,"run_number":106,"head_sha":"ffffffffffffffffffffffffffffffffffffffff","event":"schedule","status":"completed","conclusion":"success","created_at":"2026-07-10T10:30:00Z","html_url":"https://example.invalid/106"}'
    ;;
  *'/actions/runs/105')
    printf '%s\n' '{"id":105,"workflow_id":77,"run_attempt":2,"run_number":105,"head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","event":"schedule","status":"completed","conclusion":"success","created_at":"2026-07-10T10:00:00Z","html_url":"https://example.invalid/105"}'
    ;;
  *'/actions/runs/104')
    printf '%s\n' '{"id":104,"workflow_id":77,"run_attempt":2,"run_number":104,"head_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","event":"schedule","status":"completed","conclusion":"success","created_at":"2026-07-10T09:00:00Z","html_url":"https://example.invalid/104"}'
    ;;
  *'/actions/runs/106/jobs?'*)
    printf '%s\n' '{"jobs":[{"name":"target job","run_attempt":1,"conclusion":"success"},{"name":"strict job","run_attempt":1,"conclusion":"success"}]}'
    ;;
  *'/actions/runs/105/jobs?'*)
    printf '%s\n' "{\"jobs\":[
  {\"name\":\"other job\",\"run_attempt\":2,\"conclusion\":\"failure\"},
  {\"name\":\"target job\",\"run_attempt\":${MOCK_JOB_ATTEMPT:-2},\"conclusion\":\"${MOCK_TARGET_CONCLUSION:-success}\"},
  {\"name\":\"strict job\",\"run_attempt\":2,\"conclusion\":\"success\"}
]}"
    ;;
  *'/actions/runs/104/jobs?'*)
    printf '%s\n' '{"jobs":[{"name":"target job","run_attempt":2,"conclusion":"success"},{"name":"strict job","run_attempt":2,"conclusion":"success"}]}'
    ;;
  *'/actions/runs/102/jobs?'*)
    printf '%s\n' '{"jobs":[{"name":"target job","run_attempt":1,"conclusion":"failure"},{"name":"strict job","run_attempt":1,"conclusion":"failure"}]}'
    ;;
  *'/actions/runs/202/jobs?'*)
    printf '%s\n' '{"jobs":[{"name":"pull request job","run_attempt":3,"conclusion":"success"}]}'
    ;;
  *'/actions/runs/205/jobs?'*)
    printf '%s\n' '{"jobs":[{"name":"proof job","run_attempt":3,"conclusion":"success"}]}'
    ;;
  *'/actions/runs/202/artifacts?'*)
    printf '%s\n' "{\"total_count\":1,\"artifacts\":[{\"name\":\"lane-executed-pull-request-202-${MOCK_EXECUTION_ATTEMPT:-3}\",\"expired\":false}]}"
    ;;
  *'/actions/runs/106/artifacts?'*)
    fixture="${MOCK_FIXTURE_DIR}/valid-106.zip"
    digest="$(sha256sum "${fixture}" | cut -d' ' -f1)"
    size="$(stat -c %s "${fixture}")"
    printf '%s\n' "{\"total_count\":1,\"artifacts\":[{\"id\":5106,\"name\":\"scored-nightly-106-1\",\"expired\":false,\"size_in_bytes\":${size},\"digest\":\"sha256:${digest}\",\"workflow_run\":{\"id\":106,\"head_sha\":\"ffffffffffffffffffffffffffffffffffffffff\"}}]}"
    ;;
  *'/actions/runs/105/artifacts?'*)
    fixture="${MOCK_FIXTURE_DIR}/valid-105.zip"
    case "${MOCK_SCORED_MODE:-valid}" in
      valid|prior-attempt|artifact-ambiguous|stale-artifact|digest-mismatch|input-symlink) ;;
      stale-commit|stale-run|small-inventory|weak-target|false-activation|bad-counts|weak-source|duplicate-id|omitted-seed|mismatched-seed|seed-survivor|omitted-negative|mismatched-negative|unsafe-negative-trace|invalid-negative-hash|missing-positive|extra-positive|duplicate-positive|wrong-positive-metadata|nonzero-positive|killed-positive|bad-positive-hash|missing-input|extra-input|stale-input|cherry-picked)
        fixture="${MOCK_FIXTURE_DIR}/${MOCK_SCORED_MODE}.zip"
        ;;
      report-ambiguous) fixture="${MOCK_FIXTURE_DIR}/ambiguous-report.zip" ;;
      wrong-schema) fixture="${MOCK_FIXTURE_DIR}/wrong-schema.zip" ;;
      missing)
        printf '%s\n' '{"total_count":2,"artifacts":[{"name":"formal-proof-report-strict-105-1","expired":false},{"name":"formal-proof-report-strict-105-2","expired":false}]}'
        exit 0
        ;;
      *) printf 'unknown MOCK_SCORED_MODE: %s\n' "${MOCK_SCORED_MODE}" >&2; exit 2 ;;
    esac
    digest="$(sha256sum "${fixture}" | cut -d' ' -f1)"
    size="$(stat -c %s "${fixture}")"
    artifact_name="scored-nightly-105-2"
    artifact_sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    if [[ "${MOCK_SCORED_MODE:-valid}" == "prior-attempt" ]]; then
      artifact_name="scored-nightly-105-1"
    fi
    if [[ "${MOCK_SCORED_MODE:-valid}" == "stale-artifact" ]]; then
      artifact_sha="cccccccccccccccccccccccccccccccccccccccc"
    fi
    if [[ "${MOCK_SCORED_MODE:-valid}" == "digest-mismatch" ]]; then
      digest="$(printf '0%.0s' {1..64})"
    fi
    duplicate=""
    if [[ "${MOCK_SCORED_MODE:-valid}" == "artifact-ambiguous" ]]; then
      duplicate=",{\"id\":6105,\"name\":\"scored-nightly-105-2\",\"expired\":false,\"size_in_bytes\":${size},\"digest\":\"sha256:${digest}\",\"workflow_run\":{\"id\":105,\"head_sha\":\"${artifact_sha}\"}}"
    fi
    total=3
    if [[ -n "${duplicate}" ]]; then
      total=4
    fi
    printf '%s\n' "{\"total_count\":${total},\"artifacts\":[{\"name\":\"formal-proof-report-strict-105-1\",\"expired\":false},{\"name\":\"formal-proof-report-strict-105-2\",\"expired\":false},{\"id\":5105,\"name\":\"${artifact_name}\",\"expired\":false,\"size_in_bytes\":${size},\"digest\":\"sha256:${digest}\",\"workflow_run\":{\"id\":105,\"head_sha\":\"${artifact_sha}\"}}${duplicate}]}"
    ;;
  *'/actions/runs/104/artifacts?'*)
    fixture="${MOCK_FIXTURE_DIR}/valid-104.zip"
    digest="$(sha256sum "${fixture}" | cut -d' ' -f1)"
    size="$(stat -c %s "${fixture}")"
    printf '%s\n' "{\"total_count\":3,\"artifacts\":[{\"name\":\"formal-proof-report-metadata_only-104-2\",\"expired\":false},{\"name\":\"formal-proof-report-strict-104-1\",\"expired\":false},{\"id\":5104,\"name\":\"scored-nightly-104-2\",\"expired\":false,\"size_in_bytes\":${size},\"digest\":\"sha256:${digest}\",\"workflow_run\":{\"id\":104,\"head_sha\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}}]}"
    ;;
  *'/actions/runs/205/artifacts?'*)
    fixture="${MOCK_FIXTURE_DIR}/proof-${MOCK_PROOF_MODE:-valid}.zip"
    if [[ ! -f "${fixture}" ]]; then
      printf 'unknown MOCK_PROOF_MODE: %s\n' "${MOCK_PROOF_MODE:-valid}" >&2
      exit 2
    fi
    digest="$(sha256sum "${fixture}" | cut -d' ' -f1)"
    size="$(stat -c %s "${fixture}")"
    printf '%s\n' "{\"total_count\":1,\"artifacts\":[{\"id\":5205,\"name\":\"proof-mutants-report-205-3\",\"expired\":false,\"size_in_bytes\":${size},\"digest\":\"sha256:${digest}\",\"workflow_run\":{\"id\":205,\"head_sha\":\"dddddddddddddddddddddddddddddddddddddddd\"}}]}"
    ;;
  *'/actions/artifacts/5105/zip')
    case "${MOCK_SCORED_MODE:-valid}" in
      valid|prior-attempt|artifact-ambiguous|stale-artifact|digest-mismatch|input-symlink)
        fixture="${MOCK_FIXTURE_DIR}/valid-105.zip"
        ;;
      stale-commit|stale-run|small-inventory|weak-target|false-activation|bad-counts|weak-source|duplicate-id|omitted-seed|mismatched-seed|seed-survivor|omitted-negative|mismatched-negative|unsafe-negative-trace|invalid-negative-hash|missing-positive|extra-positive|duplicate-positive|wrong-positive-metadata|nonzero-positive|killed-positive|bad-positive-hash|missing-input|extra-input|stale-input|cherry-picked)
        fixture="${MOCK_FIXTURE_DIR}/${MOCK_SCORED_MODE}.zip"
        ;;
      report-ambiguous) fixture="${MOCK_FIXTURE_DIR}/ambiguous-report.zip" ;;
      wrong-schema) fixture="${MOCK_FIXTURE_DIR}/wrong-schema.zip" ;;
      *) printf 'unexpected archive mode: %s\n' "${MOCK_SCORED_MODE}" >&2; exit 2 ;;
    esac
    cat "${fixture}"
    ;;
  *'/actions/artifacts/5106/zip')
    cat "${MOCK_FIXTURE_DIR}/valid-106.zip"
    ;;
  *'/actions/artifacts/5104/zip')
    cat "${MOCK_FIXTURE_DIR}/valid-104.zip"
    ;;
  *'/actions/artifacts/5205/zip')
    fixture="${MOCK_FIXTURE_DIR}/proof-${MOCK_PROOF_MODE:-valid}.zip"
    if [[ ! -f "${fixture}" ]]; then
      printf 'unknown MOCK_PROOF_MODE: %s\n' "${MOCK_PROOF_MODE:-valid}" >&2
      exit 2
    fi
    cat "${fixture}"
    ;;
  *)
    printf 'unexpected mocked endpoint: %s\n' "${endpoint}" >&2
    exit 2
    ;;
esac
SH
chmod +x "${tmp_dir}/bin/gh"

export PATH="${tmp_dir}/bin:${PATH}"
export MOCK_GH_LOG="${tmp_dir}/gh.log"
export LANE_GATE_CONFIG="${config}"
export LANE_GATE_REPOSITORY="owner/repo"
export LANE_GATE_NOW="2026-07-10T11:00:00Z"

scheduled="$(bash scripts/lane-gate.sh scheduled --report)"
grep -Fq 'streak=2/2' <<<"${scheduled}"
grep -Fq 'run_id=105' <<<"${scheduled}"
grep -Fq 'attempt=2' <<<"${scheduled}"
grep -Fq 'run_id=104' <<<"${scheduled}"
grep -Fq 'scored=true' <<<"${scheduled}"
if grep -Fq 'run_id=103' <<<"${scheduled}"; then
  echo "manual dispatch run was counted" >&2
  exit 1
fi
if grep -Fq 'run_id=99' <<<"${scheduled}"; then
  echo "run before the evidence reset was counted" >&2
  exit 1
fi
grep -Fq 'event=schedule' "${MOCK_GH_LOG}"
if grep -Fq '/actions/runs/102/jobs?' "${MOCK_GH_LOG}"; then
  echo "lane gate queried jobs beyond the required streak" >&2
  exit 1
fi

strict="$(bash scripts/lane-gate.sh strict --report)"
grep -Fq 'streak=1/2' <<<"${strict}"
grep -Fq 'run_id=104 attempt=2' <<<"${strict}"
grep -Fq 'reason=non_strict' <<<"${strict}"

skipped="$(MOCK_TARGET_CONCLUSION=skipped bash scripts/lane-gate.sh scheduled --report)"
grep -Fq 'conclusion=skipped reason=job_not_successful' <<<"${skipped}"

pull_request="$(bash scripts/lane-gate.sh pull-request --report)"
grep -Fq 'streak=1/2' <<<"${pull_request}"
grep -Fq 'event=pull_request' "${MOCK_GH_LOG}"
grep -Fq 'real_execution=true' <<<"${pull_request}"
if grep -Fq '/actions/runs/203/jobs?' "${MOCK_GH_LOG}"; then
  echo "lane gate queried an unrelated PR base" >&2
  exit 1
fi

no_marker="$(MOCK_EXECUTION_ATTEMPT=2 bash scripts/lane-gate.sh pull-request --report)"
grep -Fq 'reason=execution_marker_missing' <<<"${no_marker}"

if MOCK_GH_ERROR=not-found bash scripts/lane-gate.sh scheduled --report \
  >"${tmp_dir}/api-fail.out" 2>&1; then
  echo "lane gate did not fail closed on an HTTP integrity error" >&2
  exit 1
fi
grep -Fq 'HTTP 404' "${tmp_dir}/api-fail.out"

MOCK_GH_ERROR=rate-limit LANE_GATE_RATE_LIMIT_MODE=warn \
  bash scripts/lane-gate.sh scheduled --report >"${tmp_dir}/api-warn.out" 2>&1
grep -Fq 'evidence=unavailable verdict=advisory' "${tmp_dir}/api-warn.out"

MOCK_GH_ERROR=transport LANE_GATE_RATE_LIMIT_MODE=warn \
  bash scripts/lane-gate.sh scheduled --report >"${tmp_dir}/transport-warn.out" 2>&1
grep -Fq 'evidence=unavailable verdict=advisory' "${tmp_dir}/transport-warn.out"

for error_mode in malformed not-found; do
  if MOCK_GH_ERROR="${error_mode}" LANE_GATE_RATE_LIMIT_MODE=warn \
    bash scripts/lane-gate.sh scheduled --report \
      >"${tmp_dir}/${error_mode}.out" 2>&1; then
    echo "lane gate warned on evidence-integrity failure: ${error_mode}" >&2
    exit 1
  fi
done

if MOCK_RUN_TIMESTAMP=invalid LANE_GATE_RATE_LIMIT_MODE=warn \
  bash scripts/lane-gate.sh scheduled --report \
    >"${tmp_dir}/timestamp.out" 2>&1; then
  echo "lane gate warned on an invalid timestamp" >&2
  exit 1
fi
grep -Fq 'invalid run timestamp' "${tmp_dir}/timestamp.out"

if MOCK_JOB_ATTEMPT=1 LANE_GATE_RATE_LIMIT_MODE=warn \
  bash scripts/lane-gate.sh scheduled --report \
    >"${tmp_dir}/attempt.out" 2>&1; then
  echo "lane gate warned on a run-attempt mismatch" >&2
  exit 1
fi
grep -Fq 'does not match' "${tmp_dir}/attempt.out"

set +e
env -u LANE_EXIT bash scripts/lane-gate.sh scheduled \
  >"${tmp_dir}/missing-lane-exit.out" 2>&1
missing_lane_exit_status=$?
set -e
if [[ "${missing_lane_exit_status}" -ne 2 ]]; then
  echo "lane gate did not reject a missing LANE_EXIT" >&2
  exit 1
fi
grep -Fq 'LANE_EXIT is required for a job-blocking invocation' \
  "${tmp_dir}/missing-lane-exit.out"

LANE_EXIT=1 bash scripts/lane-gate.sh scheduled >/dev/null

LANE_EXIT=0 bash scripts/lane-gate.sh scheduled >"${tmp_dir}/activation-target.out"
grep -Fq 'activation_target=90' "${tmp_dir}/activation-target.out"

for scored_case in \
  'missing:scored_artifact_missing' \
  'prior-attempt:scored_artifact_missing' \
  'artifact-ambiguous:scored_artifact_ambiguous' \
  'stale-artifact:scored_artifact_stale' \
  'digest-mismatch:scored_artifact_digest_mismatch' \
  'stale-commit:scored_report_stale_commit' \
  'stale-run:scored_report_stale_run' \
  'small-inventory:scored_report_inventory_mismatch' \
  'weak-target:scored_report_target_mismatch' \
  'false-activation:scored_report_activation_not_met' \
  'bad-counts:scored_report_counts_invalid' \
  'weak-source:scored_report_activation_not_met' \
  'duplicate-id:scored_report_counts_invalid' \
  'omitted-seed:scored_report_counts_invalid' \
  'mismatched-seed:scored_report_counts_invalid' \
  'seed-survivor:scored_report_counts_invalid' \
  'omitted-negative:scored_report_counts_invalid' \
  'mismatched-negative:scored_report_counts_invalid' \
  'unsafe-negative-trace:scored_report_counts_invalid' \
  'invalid-negative-hash:scored_report_counts_invalid' \
  'missing-positive:scored_report_positive_baselines_invalid' \
  'extra-positive:scored_report_positive_baselines_invalid' \
  'duplicate-positive:scored_report_positive_baselines_invalid' \
  'wrong-positive-metadata:scored_report_positive_baselines_invalid' \
  'nonzero-positive:scored_report_positive_baselines_invalid' \
  'killed-positive:scored_report_positive_baselines_invalid' \
  'bad-positive-hash:scored_report_positive_baselines_invalid' \
  'missing-input:scored_report_inputs_invalid' \
  'extra-input:scored_report_inputs_invalid' \
  'stale-input:scored_report_inputs_invalid' \
  'input-symlink:scored_report_inputs_invalid' \
  'cherry-picked:scored_report_inventory_mismatch' \
  'report-ambiguous:scored_report_ambiguous' \
  'wrong-schema:scored_report_missing'; do
  mode="${scored_case%%:*}"
  reason="${scored_case#*:}"
  output="$(MOCK_SCORED_MODE="${mode}" bash scripts/lane-gate.sh scheduled --report)"
  grep -Fq 'streak=0/2' <<<"${output}"
  grep -Fq "reason=${reason}" <<<"${output}"
done

proof="$(bash scripts/lane-gate.sh proof --report)"
grep -Fq 'streak=1/1' <<<"${proof}"
grep -Fq 'run_id=205 attempt=3' <<<"${proof}"
grep -Fq 'scored=true' <<<"${proof}"

for proof_case in \
  'dirty:scored_report_dirty_worktree' \
  'omitted-file:scored_report_counts_invalid' \
  'relabeled-file:scored_report_counts_invalid' \
  'weak-source:scored_report_activation_not_met' \
  'low-viability:scored_report_activation_not_met' \
  'tool-drift:scored_report_tool_mismatch' \
  'inventory-digest:scored_report_inventory_mismatch' \
  'inventory-content:scored_report_inventory_mismatch' \
  'cherry-picked:scored_report_inventory_mismatch'; do
  mode="${proof_case%%:*}"
  reason="${proof_case#*:}"
  output="$(MOCK_PROOF_MODE="${mode}" bash scripts/lane-gate.sh proof --report)"
  grep -Fq 'streak=0/1' <<<"${output}"
  grep -Fq "reason=${reason}" <<<"${output}"
done

missing_scored_config="${tmp_dir}/missing-scored-config.toml"
sed '/scored_artifact_prefix/d' "${config}" >"${missing_scored_config}"
if LANE_GATE_CONFIG="${missing_scored_config}" \
  bash scripts/lane-gate.sh scheduled --report \
  >"${tmp_dir}/missing-scored-config.out" 2>&1; then
  echo "lane gate accepted a display-only activation target" >&2
  exit 1
fi
grep -Fq 'activation_target needs scored artifact prefix and schema' \
  "${tmp_dir}/missing-scored-config.out"

invalid_activation_config="${tmp_dir}/invalid-activation.toml"
sed 's/activation_target = 90/activation_target = 101/' "${config}" \
  >"${invalid_activation_config}"
if LANE_GATE_CONFIG="${invalid_activation_config}" \
  bash scripts/lane-gate.sh scheduled --report \
  >"${tmp_dir}/invalid-activation.out" 2>&1; then
  echo "lane gate accepted an activation target above 100" >&2
  exit 1
fi
grep -Fq 'activation_target must be an integer <= 100' \
  "${tmp_dir}/invalid-activation.out"

bash scripts/lane-gate.sh --fleet >"${tmp_dir}/advisory-fleet.out"
grep -Fq 'fleet required=0 verdict=pass' "${tmp_dir}/advisory-fleet.out"

python3 - "${config}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
text = text.replace(
    "[gates.scheduled]\nworkflow = \"nightly.yml\"\njob = \"target job\"\nevent = \"schedule\"\nposture = \"advisory\"",
    "[gates.scheduled]\nworkflow = \"nightly.yml\"\njob = \"target job\"\nevent = \"schedule\"\nposture = \"required\"",
)
path.write_text(text, encoding="utf-8")
PY

if LANE_EXIT=1 bash scripts/lane-gate.sh scheduled \
  >"${tmp_dir}/missing-promotion-evidence.out" 2>&1; then
  echo "required lane accepted missing promotion evidence" >&2
  exit 1
fi
grep -Fq 'required posture needs promotion_evidence' \
  "${tmp_dir}/missing-promotion-evidence.out"

python3 - "${config}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
needle = 'posture = "required"\nrequired_streak = 2'
evidence = (
    'posture = "required"\n'
    'promotion_evidence = { run_ids = [105, 104], report_sha256 = "'
    + "1da3458c2a4afafc01c96388356c169d2334ac385395001cb6fafd6dc5cd33cf"
    + '" }\nrequired_streak = 2'
)
if needle not in text:
    raise SystemExit("required scheduled lane fixture is missing")
path.write_text(text.replace(needle, evidence, 1), encoding="utf-8")
PY

invalid_promotion_config="${tmp_dir}/invalid-promotion.toml"
cp "${config}" "${invalid_promotion_config}"
sed -i 's/run_ids = \[105, 104\]/run_ids = [105]/' "${invalid_promotion_config}"
if LANE_GATE_CONFIG="${invalid_promotion_config}" \
  bash scripts/lane-gate.sh scheduled --report \
  >"${tmp_dir}/invalid-promotion.out" 2>&1; then
  echo "required lane accepted an incomplete promotion run set" >&2
  exit 1
fi
grep -Fq 'promotion_evidence.run_ids must contain exactly 2 runs' \
  "${tmp_dir}/invalid-promotion.out"

MOCK_NEWER_SUCCESS=1 LANE_EXIT=0 bash scripts/lane-gate.sh scheduled \
  >"${tmp_dir}/promotion-history-advanced.out"
grep -Fq 'current=current_job_succeeded verdict=pass' \
  "${tmp_dir}/promotion-history-advanced.out"
MOCK_NEWER_SUCCESS=1 bash scripts/lane-gate.sh --fleet \
  >"${tmp_dir}/promotion-history-advanced-fleet.out"
grep -Fq 'fleet required=1 verdict=pass' \
  "${tmp_dir}/promotion-history-advanced-fleet.out"

if LANE_EXIT=1 bash scripts/lane-gate.sh scheduled >"${tmp_dir}/required.out" 2>&1; then
  echo "required lane accepted a failed current run" >&2
  exit 1
fi
grep -Fq 'verdict=fail' "${tmp_dir}/required.out"

if MOCK_GH_ERROR=rate-limit LANE_GATE_RATE_LIMIT_MODE=warn \
  bash scripts/lane-gate.sh scheduled >"${tmp_dir}/required-api.out" 2>&1; then
  echo "required lane downgraded an API failure to a warning" >&2
  exit 1
fi
grep -Fq 'API rate limit exceeded' "${tmp_dir}/required-api.out"

python3 - "${config}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
text = text.replace(
    "[gates.frozen]\nworkflow = \"temporal.yml\"\njob = \"temporal job\"\nevent = \"schedule\"\nposture = \"advisory\"",
    "[gates.frozen]\nworkflow = \"temporal.yml\"\njob = \"temporal job\"\nevent = \"schedule\"\nposture = \"required\"",
)
path.write_text(text, encoding="utf-8")
PY

if bash scripts/lane-gate.sh frozen >"${tmp_dir}/frozen.out" 2>&1; then
  echo "frozen lane accepted required posture" >&2
  exit 1
fi
grep -Fq 'frozen lane cannot use required posture' "${tmp_dir}/frozen.out"

python3 - "${config}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
text = text.replace(
    "[gates.frozen]\nworkflow = \"temporal.yml\"\njob = \"temporal job\"\nevent = \"schedule\"\nposture = \"required\"",
    "[gates.frozen]\nworkflow = \"temporal.yml\"\njob = \"temporal job\"\nevent = \"schedule\"\nposture = \"advisory\"",
)
text = text.replace(
    "max_age_hours = 48\nactivation_target = 90",
    "max_age_hours = 1\nactivation_target = 90",
    1,
)
path.write_text(text, encoding="utf-8")
PY

if LANE_GATE_NOW="2026-07-10T12:01:00Z" \
  bash scripts/lane-gate.sh --fleet >"${tmp_dir}/fleet.out" 2>&1; then
  echo "fleet accepted stale evidence for a required lane" >&2
  exit 1
fi
grep -Fq 'freshness=stale' "${tmp_dir}/fleet.out"

python3 - "${config}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8").replace(
    "max_age_hours = 1\nactivation_target = 90",
    "max_age_hours = 48\nactivation_target = 90",
    1,
)
path.write_text(text, encoding="utf-8")
PY
LANE_GATE_NOW="2026-07-10T11:00:00Z" bash scripts/lane-gate.sh --fleet \
  >"${tmp_dir}/fleet-pass.out"
grep -Fq 'fleet required=1 verdict=pass' "${tmp_dir}/fleet-pass.out"

if MOCK_TARGET_CONCLUSION=failure LANE_GATE_NOW="2026-07-10T11:00:00Z" \
  bash scripts/lane-gate.sh --fleet >"${tmp_dir}/fleet-failure.out" 2>&1; then
  echo "fleet accepted a failed latest job" >&2
  exit 1
fi
grep -Fq 'reason=job_not_successful' "${tmp_dir}/fleet-failure.out"

python3 - <<'PY'
from pathlib import Path
import re
import tomllib

expected = {
    "apalache-negative",
    "apalache-safety",
    "apalache-temporal",
    "formal-qualification",
    "fuzz-corpus-smoke-nightly",
    "fuzz-corpus-smoke-pr",
    "kani-manifest-pr",
    "kani-public-nightly",
    "kani-public-pr",
    "lean-build",
    "rust-verification-metadata",
    "proof-mutants",
    "spec-mutants",
}
document = tomllib.loads(Path("releases.toml").read_text(encoding="utf-8"))
gates = document.get("gates", {})
missing_baseline = expected - set(gates)
if missing_baseline:
    raise SystemExit(f"lane registry lacks baseline lanes: {sorted(missing_baseline)}")
for name, lane in gates.items():
    posture = lane.get("posture")
    if posture not in {"advisory", "required"}:
        raise SystemExit(f"lane {name} has invalid posture")
    promotion = lane.get("promotion_evidence")
    if posture == "advisory" and promotion is not None:
        raise SystemExit(f"advisory lane {name} claims promotion evidence")
    if posture == "required":
        if not isinstance(promotion, dict) or set(promotion) != {
            "run_ids",
            "report_sha256",
        }:
            raise SystemExit(f"required lane {name} lacks structured promotion evidence")
        run_ids = promotion.get("run_ids")
        if (
            not isinstance(run_ids, list)
            or len(run_ids) != lane.get("required_streak")
            or len(run_ids) != len(set(run_ids))
            or any(
                isinstance(run_id, bool)
                or not isinstance(run_id, int)
                or run_id <= lane.get("evidence_after_run_id", 0)
                for run_id in run_ids
            )
        ):
            raise SystemExit(f"required lane {name} has invalid promotion run IDs")
        if not re.fullmatch(r"[0-9a-f]{64}", promotion.get("report_sha256", "")):
            raise SystemExit(f"required lane {name} has invalid promotion report binding")
    if not lane.get("workflow") or not lane.get("job"):
        raise SystemExit(f"lane {name} lacks workflow or job identity")
    if lane.get("event") not in {"schedule", "pull_request"}:
        raise SystemExit(f"lane {name} has invalid event")
    if "evidence_after_run_id" not in lane or "max_age_hours" not in lane:
        raise SystemExit(f"lane {name} lacks reset or freshness policy")
    scored_fields = (
        lane.get("scored_artifact_prefix"),
        lane.get("scored_artifact_schema"),
        lane.get("scored_sample_size"),
        lane.get("scored_inventory_size"),
        lane.get("scored_inventory_sha256"),
        lane.get("scored_tools"),
    )
    if lane.get("activation_target") is None and any(scored_fields):
        raise SystemExit(f"unscored lane {name} has scored artifact configuration")
    if lane.get("activation_target") is not None and not all(scored_fields):
        raise SystemExit(f"scored lane {name} lacks artifact or inventory binding")
    if lane.get("scored_artifact_schema") == "chio.spec-mutants-report.v1":
        if not lane.get("scored_sources") or not lane.get("scored_seeds"):
            raise SystemExit(f"specification lane {name} lacks source or seed bindings")
    if lane.get("scored_artifact_schema") == "chio.proof-mutants-report.v1":
        if not lane.get("scored_files") or not lane.get("scored_viability_target"):
            raise SystemExit(f"proof lane {name} lacks file or viability bindings")
    if lane.get("event") == "pull_request":
        if not lane.get("base_branch") or not lane.get("execution_artifact_prefix"):
            raise SystemExit(f"pull-request lane {name} lacks base or execution marker")
        if posture == "advisory" and lane.get("frozen") is not True:
            raise SystemExit(f"advisory pull-request lane {name} is not frozen")
        if posture == "required" and lane.get("frozen") is True:
            raise SystemExit(f"required pull-request lane {name} remains frozen")

def workflow_jobs(path):
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    try:
        jobs_index = lines.index("jobs:")
    except ValueError as exc:
        raise SystemExit(f"workflow lacks jobs mapping: {path}") from exc
    header = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
    starts = [
        (index, match.group(1))
        for index, line in enumerate(lines[jobs_index + 1 :], start=jobs_index + 1)
        if (match := header.match(line)) is not None
    ]
    jobs = []
    for position, (start, job_id) in enumerate(starts):
        end = starts[position + 1][0] if position + 1 < len(starts) else len(lines)
        block = lines[start:end]
        names = [line.split(":", 1)[1].strip().strip("\"'") for line in block if line.startswith("    name:")]
        if len(names) != 1:
            raise SystemExit(f"workflow job {path}:{job_id} must have one static display name")
        jobs.append({"id": job_id, "name": names[0], "lines": block})
    return text, lines[:jobs_index], jobs


def steps(job, workflow_path):
    lines = job["lines"]
    try:
        start = next(index for index, line in enumerate(lines) if line == "    steps:") + 1
    except StopIteration as exc:
        raise SystemExit(f"workflow job {workflow_path}:{job['id']} lacks steps") from exc
    step_starts = [
        index for index in range(start, len(lines)) if lines[index].startswith("      - ")
    ]
    blocks = []
    for position, step_start in enumerate(step_starts):
        step_end = (
            step_starts[position + 1] if position + 1 < len(step_starts) else len(lines)
        )
        blocks.append(lines[step_start:step_end])
    return blocks


workflow_cache = {}
for name, lane in gates.items():
    workflow_path = Path(".github/workflows") / lane["workflow"]
    if not workflow_path.is_file():
        raise SystemExit(f"lane {name} references missing workflow {workflow_path}")
    if workflow_path not in workflow_cache:
        workflow_cache[workflow_path] = workflow_jobs(workflow_path)
    workflow, preamble, jobs = workflow_cache[workflow_path]
    command = f"bash scripts/lane-gate.sh {name}"
    matching_jobs = [job for job in jobs if job["name"] == lane["job"]]
    calls = []
    for job in jobs:
        for index, step in enumerate(steps(job, workflow_path)):
            if any(line.strip() in {f"run: {command}", command} for line in step):
                calls.append((job, index, step, len(steps(job, workflow_path))))

    if len(matching_jobs) != 1:
        raise SystemExit(f"lane {name} does not resolve to one static workflow job")
    if len(calls) != 1 or calls[0][0]["id"] != matching_jobs[0]["id"]:
        raise SystemExit(f"lane {name} gate call is missing or in the wrong job block")
    job, step_index, step, step_count = calls[0]
    if step_index != step_count - 1:
        raise SystemExit(f"lane {name} gate call is not the terminal job step")
    required_step_lines = {
        "if: always()",
        "GH_TOKEN: ${{ github.token }}",
        "LANE_EXIT: ${{ job.status == 'success' && '0' || '1' }}",
        "LANE_GATE_RATE_LIMIT_MODE: warn",
    }
    actual_step_lines = {line.strip() for line in step}
    if not ({f"run: {command}", command} & actual_step_lines):
        required_step_lines.add(command)
    missing_step_lines = required_step_lines - actual_step_lines
    if missing_step_lines:
        raise SystemExit(
            f"lane {name} terminal gate step lacks {sorted(missing_step_lines)}"
        )
    try:
        steps_index = job["lines"].index("    steps:")
    except ValueError as exc:
        raise SystemExit(f"lane {name} job lacks steps") from exc
    permission_lines = preamble + job["lines"][:steps_index]
    if not any(line.strip() == "actions: read" for line in permission_lines):
        raise SystemExit(f"lane {name} workflow or job lacks actions read permission")
    if lane.get("activation_target") is not None:
        for required_line in ("set -euo pipefail", command, 'exit "${LANE_EXIT}"'):
            if required_line not in actual_step_lines:
                raise SystemExit(
                    f"scored lane {name} terminal gate does not preserve failures"
                )
        artifact_name = (
            f'{lane["scored_artifact_prefix"]}'
            "${{ github.run_id }}-${{ github.run_attempt }}"
        )
        upload_steps = [
            candidate
            for candidate in steps(job, workflow_path)
            if any(line.strip() == f"name: {artifact_name}" for line in candidate)
        ]
        if len(upload_steps) != 1:
            raise SystemExit(
                f"scored lane {name} lacks one exact per-attempt report artifact"
            )
        upload_lines = {line.strip() for line in upload_steps[0]}
        if "if: always()" not in upload_lines or "if-no-files-found: error" not in upload_lines:
            raise SystemExit(f"scored lane {name} report upload is not fail-closed")
        report_paths = [
            line.split(":", 1)[1].strip()
            for line in upload_lines
            if line.startswith("path:")
        ]
        if len(report_paths) != 1 or not report_paths[0].endswith(".json"):
            raise SystemExit(f"scored lane {name} artifact is not report-only JSON")

nightly = workflow_cache[Path(".github/workflows/nightly.yml")][0]
if "formal-proof-report-${{ steps.proof_report.outputs.mode }}-${{ github.run_id }}-${{ github.run_attempt }}" not in nightly:
    raise SystemExit("nightly proof artifact name does not expose mode, run id, and attempt")
if "Mode: \\`" not in nightly:
    raise SystemExit("nightly job summary does not expose proof mode")
if "target/formal/coverage.json" not in nightly or "if-no-files-found: error" not in nightly:
    raise SystemExit("nightly does not retain proof report and coverage fail-closed")

formal_smoke = workflow_cache[Path(".github/workflows/formal-pr-smoke.yml")][0]
for required in (
    '- "scripts/lean-assumption-audit.lean"',
    '- "scripts/tests/lean-assumption-audit.test.sh"',
    "lean-assumption-audit\\.lean",
    "scripts/tests/lean-assumption-audit\\.test\\.sh",
):
    if required not in formal_smoke:
        raise SystemExit(f"formal PR smoke path filter lacks {required}")

qualification = Path("scripts/qualify-release.sh").read_text(encoding="utf-8")
if "./scripts/lane-gate.sh --fleet" not in qualification:
    raise SystemExit("release qualification does not enforce the lane fleet")
for required in (
    "target/formal/proof-report.json",
    "target/formal/coverage.json",
    'formal_root="${output_root}/formal"',
):
    if required not in qualification:
        raise SystemExit(f"release qualification does not retain {required}")
release_workflow = Path(".github/workflows/release-qualification.yml").read_text(
    encoding="utf-8"
)
if "actions: read" not in release_workflow or "GH_TOKEN: ${{ github.token }}" not in release_workflow:
    raise SystemExit("release qualification lacks GitHub Actions read credentials")
for required in (
    "Retain formal proof evidence",
    "target/release-qualification/formal/proof-report.json",
    "target/release-qualification/formal/coverage.json",
    "if-no-files-found: error",
):
    if required not in release_workflow:
        raise SystemExit(f"release workflow does not retain formal evidence: {required}")

codeowners = {}
for line in Path(".github/CODEOWNERS").read_text(encoding="utf-8").splitlines():
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        continue
    pattern, *owners = stripped.split()
    codeowners[pattern] = owners
for protected in (
    "formal/**",
    "formal/proof-manifest.toml",
    "formal/apalache/**",
    "xtask/src/**",
    "crates/kernel/chio-kernel-core/src/**",
    "crates/core/chio-core-types/**",
    "crates/kernel/chio-kernel-core/**",
    "docs/formal/COVERAGE.md",
    "docs/reference/CLAIM_REGISTRY.md",
    "docs/release/RISK_REGISTER.md",
    "docs/start-here/VISION.md",
    "spec/PROTOCOL.md",
    "scripts/check-*.sh",
    "scripts/ci-workspace.sh",
    "scripts/lane-gate.sh",
    "scripts/spec-mutants.py",
    "scripts/proof-mutants.py",
    "scripts/proof-mutants.sh",
    "scripts/kani-mutant-killer.sh",
    "scripts/lean-mutants.py",
    "scripts/lean-assumption-audit.lean",
    "scripts/file-mutation-survivors.py",
    "scripts/lib/apalache_evidence.py",
    "tools/install-apalache.sh",
    "scripts/generate-proof-report.sh",
    "scripts/check-proof-report.sh",
    "scripts/qualify-release.sh",
    "scripts/tests/**",
    "scripts/tests/check-proof-report.test.sh",
    "scripts/tests/lane-gate.test.sh",
    "xtask/src/proof_coverage.rs",
    ".github/workflows/formal-pr-smoke.yml",
    ".github/workflows/nightly.yml",
    ".github/workflows/apalache-safety.yml",
    ".github/workflows/apalache-temporal.yml",
    ".github/workflows/proof-mutants.yml",
    ".github/workflows/release-qualification.yml",
    "releases.toml",
):
    if codeowners.get(protected) != ["@backbay-labs/chio-maintainers"]:
        raise SystemExit(f"evidence TCB lacks CODEOWNERS protection: {protected}")
PY

echo "Lane gate contract passed"
