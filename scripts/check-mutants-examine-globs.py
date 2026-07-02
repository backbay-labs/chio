#!/usr/bin/env python3
"""Fail closed when cargo-mutants examine globs go dark."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import fnmatch
from pathlib import Path
import sys
import tomllib


@dataclass(frozen=True)
class GlobFailure:
    config: Path
    pattern: str
    reason: str


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_configs(root: Path) -> list[Path]:
    configs: list[Path] = []
    for rel in [".cargo/mutants.toml"]:
        path = root / rel
        if path.is_file():
            configs.append(path)
    configs.extend(sorted((root / "audits/mutation/per-crate-configs").glob("*.toml")))
    configs.extend(sorted((root / "crates").glob("**/mutants.toml")))
    return configs


def as_string_list(value: object, label: str, config: Path) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{config}: {label} must be an array of strings")
    return value


def is_excluded(path: Path, root: Path, exclude_globs: list[str]) -> bool:
    rel = path.relative_to(root).as_posix()
    return any(fnmatch.fnmatch(rel, pattern) for pattern in exclude_globs)


def active_matches(root: Path, pattern: str, exclude_globs: list[str]) -> tuple[list[Path], list[Path]]:
    matches = sorted(path for path in root.glob(pattern) if path.exists())
    active = [path for path in matches if not is_excluded(path, root, exclude_globs)]
    return matches, active


def check_config(root: Path, config: Path) -> list[GlobFailure]:
    try:
        data = tomllib.loads(config.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"{config}: invalid TOML: {exc}") from exc

    examine_globs = as_string_list(data.get("examine_globs"), "examine_globs", config)
    exclude_globs = as_string_list(data.get("exclude_globs"), "exclude_globs", config)

    failures: list[GlobFailure] = []
    for pattern in examine_globs:
        matches, active = active_matches(root, pattern, exclude_globs)
        if not matches:
            failures.append(GlobFailure(config, pattern, "matches no paths"))
        elif not active:
            failures.append(GlobFailure(config, pattern, "matches only excluded paths"))
    return failures


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate that cargo-mutants examine_globs match active files."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=repo_root(),
        help="Repository root to scan.",
    )
    parser.add_argument(
        "--config",
        action="append",
        type=Path,
        default=None,
        help="Specific config path relative to root. May be repeated.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    if args.config:
        configs = [(root / config).resolve() for config in args.config]
    else:
        configs = default_configs(root)

    failures: list[GlobFailure] = []
    try:
        for config in configs:
            if not config.is_file():
                failures.append(GlobFailure(config, "<config>", "config file is missing"))
                continue
            failures.extend(check_config(root, config))
    except ValueError as exc:
        print(f"check-mutants-examine-globs: {exc}", file=sys.stderr)
        return 2

    if failures:
        print("cargo-mutants examine glob failures:", file=sys.stderr)
        for failure in failures:
            config = failure.config
            try:
                config = config.relative_to(root)
            except ValueError:
                pass
            print(
                f"- {config}: {failure.pattern}: {failure.reason}",
                file=sys.stderr,
            )
        return 1

    print(
        f"check-mutants-examine-globs: OK ({len(configs)} config file(s) scanned)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
