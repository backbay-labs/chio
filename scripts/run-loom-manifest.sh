#!/usr/bin/env bash
# Run the registered bounded Loom models with a fixed crate-local cfg.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

exec python3 - "${repo_root}" "$@" <<'PY'
import argparse
import datetime as dt
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
    raise SystemExit("run-loom-manifest: Python 3.11 or newer is required") from error


SCHEMA = "chio.loom.v1"
TIMING_SCHEMA = "chio.loom.timings.v1"
CFG_FLAG = "--cfg chio_kernel_loom"
VALID_LANES = {"pr", "nightly"}
VALID_SCOPE = "bounded_abstract_model"
ENTRY_KEYS = {
    "crate",
    "test",
    "max_preemptions",
    "lane",
    "scope",
    "notes",
}
IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
PACKAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
TEST_DECLARATION = re.compile(
    r"(?m)((?:^[ \t]*#\[[^\n]+\][ \t]*\n)+)"
    r"[ \t]*(?:pub(?:\([^\n)]*\))?[ \t]+)?fn[ \t]+"
    r"([A-Za-z_][A-Za-z0-9_]*)[ \t]*\("
)
TEST_SUMMARY = re.compile(
    r"test result: (?:ok|FAILED)\. "
    r"(\d+) passed; (\d+) failed; (\d+) ignored;"
)


class RunnerError(Exception):
    pass


def fail(message):
    raise RunnerError(message)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="run-loom-manifest.sh",
        description="Run registered bounded Loom models.",
        allow_abbrev=False,
    )
    parser.add_argument("--lane", choices=["pr", "nightly", "all"], default="nightly")
    parser.add_argument(
        "--list",
        action="store_true",
        help="validate the registry and list matching entries without compiling tests",
    )
    return parser.parse_args(argv)


def load_manifest(path):
    try:
        raw = path.read_bytes()
    except OSError as error:
        fail(f"cannot read {path}: {error}")
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot parse {path}: {error}")
    if not isinstance(data, dict):
        fail("manifest root must be a table")
    unknown_root = set(data) - {"schema", "harness"}
    if unknown_root:
        fail(f"manifest has unknown root keys: {sorted(unknown_root)}")
    if data.get("schema") != SCHEMA:
        fail(f"unexpected schema {data.get('schema')!r}; expected {SCHEMA!r}")
    entries = data.get("harness")
    if not isinstance(entries, list) or not entries:
        fail("manifest must contain at least one [[harness]] entry")

    normalized = []
    seen = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            fail(f"harness[{index}] must be a table")
        missing = ENTRY_KEYS - set(entry)
        unknown = set(entry) - ENTRY_KEYS
        if missing:
            fail(f"harness[{index}] is missing keys: {sorted(missing)}")
        if unknown:
            fail(f"harness[{index}] has unknown keys: {sorted(unknown)}")

        crate = entry["crate"]
        test = entry["test"]
        bound = entry["max_preemptions"]
        lane = entry["lane"]
        scope = entry["scope"]
        notes = entry["notes"]
        if not isinstance(crate, str) or PACKAGE.fullmatch(crate) is None:
            fail(f"harness[{index}].crate is not a safe package name")
        if not isinstance(test, str):
            fail(f"harness[{index}].test must be a string")
        components = test.split("::")
        if len(components) != 2 or any(IDENTIFIER.fullmatch(value) is None for value in components):
            fail(f"harness[{index}].test must be <integration-target>::<test-name>")
        if type(bound) is not int or not 1 <= bound <= 64:
            fail(f"harness[{index}].max_preemptions must be an integer in 1..=64")
        if not isinstance(lane, str) or lane not in VALID_LANES:
            fail(f"harness[{index}].lane must be one of {sorted(VALID_LANES)}")
        if not isinstance(scope, str) or scope != VALID_SCOPE:
            fail(f"harness[{index}].scope must be {VALID_SCOPE!r}")
        if not isinstance(notes, str) or not notes.strip() or any(ord(char) < 32 for char in notes):
            fail(f"harness[{index}].notes must be a non-empty single-line string")
        key = (crate, test)
        if key in seen:
            fail(f"duplicate harness entry: {crate}::{test}")
        seen.add(key)
        normalized.append(entry)
    return normalized


def cargo_metadata(root):
    command = ["cargo", "metadata", "--no-deps", "--format-version", "1"]
    try:
        result = subprocess.run(
            command,
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as error:
        fail(f"cannot run cargo metadata: {error}")
    if result.returncode != 0:
        fail(f"cargo metadata failed: {result.stderr.strip()}")
    try:
        metadata = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        fail(f"cargo metadata returned invalid JSON: {error}")
    members = set(metadata.get("workspace_members", []))
    packages = {}
    for package in metadata.get("packages", []):
        if package.get("id") not in members:
            continue
        targets = {}
        for target in package.get("targets", []):
            if "test" in target.get("kind", []):
                targets[target.get("name")] = Path(target.get("src_path", ""))
        packages[package.get("name")] = targets
    return packages


def source_tests(path):
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"cannot read integration-test target {path}: {error}")
    tests = set()
    for attributes, name in TEST_DECLARATION.findall(raw):
        if re.search(r"#\[\s*test\s*\]", attributes):
            tests.add(name)
    return tests


def validate_sources(root, entries, packages):
    expected_by_target = {}
    source_by_target = {}
    for entry in entries:
        crate = entry["crate"]
        target, test_name = entry["test"].split("::")
        if crate not in packages:
            fail(f"manifest names non-workspace package: {crate}")
        if target not in packages[crate]:
            fail(f"manifest names missing integration-test target: {crate}::{target}")
        source = packages[crate][target]
        try:
            source.relative_to(root)
        except ValueError:
            fail(f"integration-test source is outside the repository: {source}")
        key = (crate, target)
        expected_by_target.setdefault(key, set()).add(test_name)
        source_by_target[key] = source

    for key, expected in expected_by_target.items():
        discovered = source_tests(source_by_target[key])
        if expected != discovered:
            missing = sorted(discovered - expected)
            stale = sorted(expected - discovered)
            details = []
            if missing:
                details.append(f"unregistered tests={missing}")
            if stale:
                details.append(f"missing tests={stale}")
            fail(f"registry/source mismatch for {key[0]}::{key[1]}: {'; '.join(details)}")
    return expected_by_target


def run_stream(command, root, environment, log_path):
    log_path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    try:
        process = subprocess.Popen(
            command,
            cwd=root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except OSError as error:
        fail(f"cannot run {command[0]}: {error}")
    if process.stdout is None:
        fail("cargo output pipe was not created")
    with log_path.open("w", encoding="utf-8") as log:
        for line in process.stdout:
            print(line, end="", flush=True)
            log.write(line)
            lines.append(line)
    return process.wait(), "".join(lines)


def write_timings(path, root, lane, commit, entries, completed):
    document = {
        "schema": TIMING_SCHEMA,
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "gitCommit": commit,
        "lane": lane,
        "cfg": "chio_kernel_loom",
        "completed": completed,
        "entries": entries,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def replay_help(entry):
    crate = entry["crate"]
    target, test_name = entry["test"].split("::")
    bound = entry["max_preemptions"]
    checkpoint = f"target/loom/checkpoints/{crate}--{target}--{test_name}.json"
    command = (
        f'RUSTFLAGS="{CFG_FLAG}" LOOM_MAX_PREEMPTIONS={bound} '
        f"LOOM_CHECKPOINT_FILE={checkpoint} cargo test -p {crate} --release "
        f"--test {target} {test_name} -- --exact --nocapture"
    )
    print("run-loom-manifest: capture the failing schedule with:", file=sys.stderr)
    print(f"  {command}", file=sys.stderr)
    print("run-loom-manifest: replay the next schedule with:", file=sys.stderr)
    print(f"  LOOM_CHECKPOINT_INTERVAL=1 {command}", file=sys.stderr)
    print(
        "run-loom-manifest: add LOOM_LOG=trace LOOM_LOCATION=1 for a synchronization trace",
        file=sys.stderr,
    )


def main(argv):
    if not argv:
        fail("repository root argument is missing")
    root = Path(argv[0]).resolve()
    args = parse_args(argv[1:])
    manifest = root / ".loom" / "harnesses.toml"
    entries = load_manifest(manifest)
    packages = cargo_metadata(root)
    expected_by_target = validate_sources(root, entries, packages)
    selected = [entry for entry in entries if args.lane == "all" or entry["lane"] == args.lane]
    if not selected:
        fail(f"no harnesses matched lane={args.lane}")
    if args.list:
        for entry in selected:
            print(f"{entry['crate']}::{entry['test']}")
        return

    output_root = root / "target" / "loom"
    timings_path = output_root / "timings.json"
    logs_root = output_root / "logs"
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        commit = "unknown"
    timing_entries = []
    write_timings(timings_path, root, args.lane, commit, timing_entries, False)

    base_environment = os.environ.copy()
    rustflags = base_environment.get("RUSTFLAGS", "").strip()
    base_environment["RUSTFLAGS"] = f"{rustflags} {CFG_FLAG}".strip()

    selected_targets = sorted(
        {(entry["crate"], entry["test"].split("::")[0]) for entry in selected}
    )
    for crate, target in selected_targets:
        command = [
            "cargo",
            "test",
            "-p",
            crate,
            "--release",
            "--test",
            target,
            "--",
            "--list",
            "--format",
            "terse",
        ]
        log_path = logs_root / f"{crate}--{target}--list.log"
        print(f"::group::loom discovery {crate}::{target}")
        returncode, output = run_stream(command, root, base_environment, log_path)
        print("::endgroup::")
        if returncode != 0:
            fail(f"test discovery failed for {crate}::{target} with exit code {returncode}")
        discovered = {
            line.removesuffix(": test")
            for line in output.splitlines()
            if line.endswith(": test")
        }
        expected = expected_by_target[(crate, target)]
        if not discovered:
            fail(f"test discovery executed zero tests for {crate}::{target}")
        if discovered != expected:
            fail(
                f"compiled test list mismatch for {crate}::{target}: "
                f"expected={sorted(expected)} discovered={sorted(discovered)}"
            )

    for entry in selected:
        crate = entry["crate"]
        target, test_name = entry["test"].split("::")
        bound = entry["max_preemptions"]
        environment = base_environment.copy()
        environment["LOOM_MAX_PREEMPTIONS"] = str(bound)
        command = [
            "cargo",
            "test",
            "-p",
            crate,
            "--release",
            "--test",
            target,
            test_name,
            "--",
            "--exact",
            "--nocapture",
        ]
        log_path = logs_root / f"{crate}--{target}--{test_name}.log"
        print(f"::group::loom {crate}::{target}::{test_name} (max_preemptions={bound})")
        started = time.monotonic_ns()
        returncode, output = run_stream(command, root, environment, log_path)
        duration_ms = (time.monotonic_ns() - started) // 1_000_000
        print("::endgroup::")
        summaries = TEST_SUMMARY.findall(output)
        passed = returncode == 0 and summaries == [("1", "0", "0")]
        timing_entries.append(
            {
                "crate": crate,
                "test": entry["test"],
                "maxPreemptions": bound,
                "durationMs": duration_ms,
                "status": "passed" if passed else "failed",
                "log": str(log_path.relative_to(root)),
            }
        )
        write_timings(timings_path, root, args.lane, commit, timing_entries, False)
        if not passed:
            replay_help(entry)
            if returncode != 0:
                fail(f"{crate}::{entry['test']} exited with code {returncode}")
            fail(
                f"{crate}::{entry['test']} did not execute exactly one non-ignored test; "
                f"summaries={summaries}"
            )
        print(
            f"run-loom-manifest: passed {crate}::{entry['test']} in {duration_ms} ms"
        )

    write_timings(timings_path, root, args.lane, commit, timing_entries, True)
    print(
        f"run-loom-manifest: {len(timing_entries)} harnesses passed; "
        f"timings={timings_path.relative_to(root)}"
    )


try:
    main(sys.argv[1:])
except RunnerError as error:
    print(f"run-loom-manifest: FAIL: {error}", file=sys.stderr)
    raise SystemExit(1) from error
PY
