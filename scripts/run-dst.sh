#!/usr/bin/env bash
# Validate and run the registered deterministic simulation tests.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

exec python3 - "${repo_root}" "$@" <<'PY'
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

try:
    import tomllib
except ModuleNotFoundError as error:
    raise SystemExit("run-dst: Python 3.11 or newer is required") from error


SCHEMA = "chio.dst.v1"
SCOPE = "single_process_single_store"
ROOT_KEYS = {
    "schema",
    "package",
    "target",
    "scope",
    "seed_corpus",
    "fixed_seed_count",
    "wide_episode_count",
    "test",
}
TEST_KEYS = {"name", "lane", "ignored"}
LANES = {"pr", "nightly", "replay"}
IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
PACKAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
DECLARATION = re.compile(
    r"(?m)((?:^[ \t]*#\[[^\n]+\][ \t]*\n)+)"
    r"[ \t]*(?:pub(?:\([^\n)]*\))?[ \t]+)?fn[ \t]+"
    r"([A-Za-z_][A-Za-z0-9_]*)[ \t]*\("
)
SUMMARY = re.compile(r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;")


class RunnerError(Exception):
    pass


def fail(message):
    raise RunnerError(message)


def arguments(argv):
    parser = argparse.ArgumentParser(prog="run-dst.sh", allow_abbrev=False)
    parser.add_argument("--lane", choices=["pr", "nightly", "replay", "all"], default="pr")
    parser.add_argument("--seed", type=int)
    parser.add_argument("--list", action="store_true")
    parsed = parser.parse_args(argv)
    if parsed.seed is not None and not 0 <= parsed.seed <= (2**64 - 1):
        fail("--seed must be a u64")
    if parsed.lane == "replay" and not parsed.list and parsed.seed is None:
        fail("--lane replay requires --seed")
    if parsed.lane == "all" and not parsed.list:
        fail("--lane all is validation-only and requires --list")
    if parsed.seed is not None and parsed.lane != "replay":
        fail("--seed is only valid with --lane replay")
    return parsed


def manifest(path):
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot load {path}: {error}")
    unknown = set(data) - ROOT_KEYS
    missing = ROOT_KEYS - set(data)
    if unknown or missing:
        fail(f"manifest root mismatch: missing={sorted(missing)} unknown={sorted(unknown)}")
    if data["schema"] != SCHEMA or data["scope"] != SCOPE:
        fail("manifest schema or scope is not admitted")
    if not isinstance(data["package"], str) or PACKAGE.fullmatch(data["package"]) is None:
        fail("manifest package is unsafe")
    if not isinstance(data["target"], str) or IDENTIFIER.fullmatch(data["target"]) is None:
        fail("manifest target is unsafe")
    if type(data["fixed_seed_count"]) is not int or data["fixed_seed_count"] != 64:
        fail("fixed_seed_count must be exactly 64")
    if type(data["wide_episode_count"]) is not int or data["wide_episode_count"] != 10000:
        fail("wide_episode_count must be exactly 10000")
    if not isinstance(data["seed_corpus"], str) or not data["seed_corpus"]:
        fail("seed_corpus must be a non-empty string")
    corpus = Path(data["seed_corpus"])
    if corpus.is_absolute() or ".." in corpus.parts:
        fail("seed_corpus must be a repository-relative path")
    tests = data["test"]
    if not isinstance(tests, list) or not tests:
        fail("manifest has no [[test]] entries")
    seen = set()
    for index, entry in enumerate(tests):
        if not isinstance(entry, dict) or set(entry) != TEST_KEYS:
            fail(f"test[{index}] keys must be exactly {sorted(TEST_KEYS)}")
        if not isinstance(entry["name"], str) or IDENTIFIER.fullmatch(entry["name"]) is None:
            fail(f"test[{index}].name is unsafe")
        if entry["lane"] not in LANES or type(entry["ignored"]) is not bool:
            fail(f"test[{index}] lane or ignored value is invalid")
        if entry["name"] in seen:
            fail(f"duplicate test {entry['name']}")
        seen.add(entry["name"])
    return data


def cargo_target(root, package, target):
    result = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=root,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        fail(f"cargo metadata failed: {result.stderr.strip()}")
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        fail(f"cargo metadata returned invalid JSON: {error}")
    members = set(data.get("workspace_members", []))
    for item in data.get("packages", []):
        if item.get("id") not in members or item.get("name") != package:
            continue
        for cargo_target in item.get("targets", []):
            if cargo_target.get("name") == target and "test" in cargo_target.get("kind", []):
                return Path(cargo_target["src_path"])
    fail(f"missing integration target {package}::{target}")


def validate_source(path, expected):
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"cannot read {path}: {error}")
    discovered = {
        name
        for attributes, name in DECLARATION.findall(source)
        if re.search(r"#\[\s*test\s*\]", attributes)
    }
    if discovered != expected:
        fail(f"registry/source mismatch: expected={sorted(expected)} discovered={sorted(discovered)}")


def validate_seed_corpus(path, expected_count):
    try:
        corpus = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot load seed corpus {path}: {error}")
    if set(corpus) != {"schema", "seeds"} or corpus.get("schema") != "chio.dst.seeds.v1":
        fail("seed corpus schema is not admitted")
    seeds = corpus.get("seeds")
    if not isinstance(seeds, list) or len(seeds) != expected_count:
        fail(f"seed corpus must contain exactly {expected_count} seeds")
    if any(type(seed) is not int or not 0 <= seed <= (2**64 - 1) for seed in seeds):
        fail("seed corpus contains a non-u64 value")
    if len(set(seeds)) != len(seeds):
        fail("seed corpus contains duplicates")


def validate_coverage_registry(path, package, target, tests):
    try:
        registry = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot load DST coverage registry {path}: {error}")
    if set(registry) != {"schema", "harness"} or registry.get("schema") != SCHEMA:
        fail("DST coverage registry schema is not admitted")
    harnesses = registry.get("harness")
    if not isinstance(harnesses, list) or not harnesses:
        fail("DST coverage registry has no harnesses")
    actual = set()
    for index, harness in enumerate(harnesses):
        if not isinstance(harness, dict) or set(harness) != {"crate", "test"}:
            fail(f"DST coverage harness[{index}] has invalid keys")
        actual.add(f"{harness['crate']}::{harness['test']}")
    expected = {f"{package}::{target}::{entry['name']}" for entry in tests}
    if len(actual) != len(harnesses) or actual != expected:
        fail(f"DST runner/coverage registry mismatch: expected={sorted(expected)} actual={sorted(actual)}")


def run(command, root, environment, log):
    log.parent.mkdir(parents=True, exist_ok=True)
    process = subprocess.run(
        command,
        cwd=root,
        env=environment,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    log.write_text(process.stdout, encoding="utf-8")
    print(process.stdout, end="")
    return process.returncode, process.stdout


def main(argv):
    root = Path(argv[0]).resolve()
    args = arguments(argv[1:])
    data = manifest(root / ".dst" / "episodes.toml")
    tests = data["test"]
    expected = {entry["name"] for entry in tests}
    source = cargo_target(root, data["package"], data["target"])
    validate_source(source, expected)
    validate_seed_corpus(root / data["seed_corpus"], data["fixed_seed_count"])
    validate_coverage_registry(
        root / ".dst" / "harnesses.toml", data["package"], data["target"], tests
    )
    selected = [entry for entry in tests if args.lane == "all" or entry["lane"] == args.lane]
    if not selected:
        fail(f"no tests matched lane={args.lane}")
    if args.list:
        for entry in selected:
            print(f"{data['package']}::{data['target']}::{entry['name']}")
        return

    output = root / "target" / "dst"
    environment = os.environ.copy()
    if args.lane == "nightly":
        environment["CHIO_DST_EPISODES"] = str(data["wide_episode_count"])
    if args.lane == "replay":
        environment["CHIO_DST_SEED"] = str(args.seed)

    discovery = [
        "cargo", "test", "-p", data["package"], "--test", data["target"],
        "--", "--list", "--format", "terse",
    ]
    code, text = run(discovery, root, environment, output / "discovery.log")
    if code != 0:
        fail(f"compiled discovery failed with exit code {code}")
    compiled = {line.removesuffix(": test") for line in text.splitlines() if line.endswith(": test")}
    if not compiled:
        fail("compiled discovery returned zero tests")
    if compiled != expected:
        fail(f"registry/compiled mismatch: expected={sorted(expected)} compiled={sorted(compiled)}")

    results = []
    for entry in selected:
        command = [
            "cargo", "test", "-p", data["package"], "--test", data["target"],
            entry["name"], "--", "--exact", "--nocapture",
        ]
        if entry["ignored"]:
            command.append("--ignored")
        started = time.monotonic()
        code, text = run(command, root, environment, output / "logs" / f"{entry['name']}.log")
        elapsed = round(time.monotonic() - started, 6)
        summaries = SUMMARY.findall(text)
        passed = any(item == ("1", "0", "0") for item in summaries)
        if code != 0 or not passed:
            if args.lane == "replay":
                print(f"run-dst: replay seed={args.seed}", file=sys.stderr)
            fail(f"{entry['name']} did not produce exactly one passing test")
        results.append({"name": entry["name"], "durationSeconds": elapsed, "status": "passed"})
    document = {
        "schema": "chio.dst.results.v1",
        "lane": args.lane,
        "scope": data["scope"],
        "seed": args.seed,
        "results": results,
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "results.json").write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


try:
    main(sys.argv[1:])
except RunnerError as error:
    print(f"run-dst: {error}", file=sys.stderr)
    raise SystemExit(1)
PY
