#!/usr/bin/env python3
"""Fail closed when cargo-mutants examine globs go dark."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import fnmatch
from pathlib import Path
import re
import sys
import tomllib


GLOB_META = frozenset("*?[")
RUST_FN_RE = re.compile(
    r"^(?:pub(?:\([^)]*\))?\s+)?"
    r"(?:(?:async|const|unsafe|extern(?:\s+\"[^\"]+\")?)\s+)*"
    r"fn\s+[A-Za-z_][A-Za-z0-9_]*\b"
)
RUST_MOD_DECL_RE = re.compile(
    r"^(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*;"
)


@dataclass(frozen=True)
class GlobFailure:
    config: Path
    pattern: str
    reason: str


@dataclass(frozen=True)
class RustSurfaceStats:
    fn_items: int
    logic_lines: int
    mod_declarations: int


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_configs(root: Path) -> list[Path]:
    configs: list[Path] = [root / ".cargo/mutants.toml"]
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


def has_glob_meta(pattern: str) -> bool:
    return any(char in pattern for char in GLOB_META)


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def production_rust_lines(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    production: list[str] = []
    skip_cfg_test_item = False
    skip_brace_depth = 0

    for line in lines:
        stripped = line.strip()
        if skip_brace_depth:
            skip_brace_depth += line.count("{") - line.count("}")
            if skip_brace_depth <= 0:
                skip_brace_depth = 0
            continue

        if skip_cfg_test_item:
            if not stripped or stripped.startswith("#["):
                continue
            depth = line.count("{") - line.count("}")
            skip_cfg_test_item = False
            if depth > 0:
                skip_brace_depth = depth
            continue

        if stripped.startswith("#[cfg(test)]"):
            skip_cfg_test_item = True
            continue

        production.append(line)

    return production


def rust_surface_stats(path: Path) -> RustSurfaceStats:
    fn_items = 0
    logic_lines = 0
    mod_declarations = 0

    for line in production_rust_lines(path):
        stripped = line.strip()
        if RUST_FN_RE.match(stripped):
            fn_items += 1
        if RUST_MOD_DECL_RE.match(stripped):
            mod_declarations += 1
            continue
        if (
            not stripped
            or stripped.startswith("//")
            or stripped.startswith("#[")
            or stripped in {"{", "}", "};"}
            or stripped.startswith("use ")
            or stripped.startswith("pub use ")
            or stripped.startswith("crate::")
        ):
            continue
        logic_lines += 1

    return RustSurfaceStats(
        fn_items=fn_items,
        logic_lines=logic_lines,
        mod_declarations=mod_declarations,
    )


def active_rust_files_under(root: Path, directory: Path, exclude_globs: list[str]) -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(
        path
        for path in directory.rglob("*.rs")
        if path.is_file() and not is_excluded(path, root, exclude_globs)
    )


def sibling_directory_examined(
    root: Path,
    directory: Path,
    examine_globs: list[str],
    exclude_globs: list[str],
) -> bool:
    for pattern in examine_globs:
        _matches, active = active_matches(root, pattern, exclude_globs)
        if any(is_relative_to(path, directory) for path in active):
            return True
    return False


def shim_directory_failure(
    root: Path,
    pattern: str,
    file_path: Path,
    examine_globs: list[str],
    exclude_globs: list[str],
) -> str | None:
    if has_glob_meta(pattern) or not pattern.endswith(".rs"):
        return None

    sibling_dir = file_path.with_suffix("")
    sibling_files = active_rust_files_under(root, sibling_dir, exclude_globs)
    if not sibling_files:
        return None
    if sibling_directory_examined(root, sibling_dir, examine_globs, exclude_globs):
        return None

    file_stats = rust_surface_stats(file_path)
    if file_stats.mod_declarations == 0:
        return None

    sibling_logic_lines = sum(rust_surface_stats(path).logic_lines for path in sibling_files)
    is_hollow = file_stats.fn_items == 0
    is_thin_umbrella = (
        file_stats.fn_items <= 8
        and file_stats.logic_lines <= 120
        and sibling_logic_lines >= max(80, file_stats.logic_lines * 2)
    )
    if not is_hollow and not is_thin_umbrella:
        return None

    try:
        sibling_pattern = f"{sibling_dir.relative_to(root).as_posix()}/*.rs"
    except ValueError:
        sibling_pattern = f"{sibling_dir.as_posix()}/*.rs"
    return f"matches shim file but sibling module directory is not examined: {sibling_pattern}"


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
        elif len(active) == 1 and active[0].is_file() and active[0].suffix == ".rs":
            reason = shim_directory_failure(
                root,
                pattern,
                active[0],
                examine_globs,
                exclude_globs,
            )
            if reason is not None:
                failures.append(GlobFailure(config, pattern, reason))
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
