#!/usr/bin/env python3
"""Phase 6 crate-folder migration (deterministic, source-of-truth).

Move every top-level `crates/chio-*` directory into one of 11 functional
subfolders (`crates/<group>/chio-*`) and rewrite every path literal that
references the old locations, in lockstep, so no fail-closed gate or path
filter silently goes dark.

The move map below is authoritative. The script runs in explicit phases
driven by flags so each step is verifiable in isolation:

  --check-sum-only           Validate the 11-group map sums to 107 and prints OK.
  --moves                    `git mv` the 107 crate dirs (nested crates ride along)
                             and rename chio-openai -> chio-openai-adapter.
  --rewrite-relative-deps    Fix sibling `../chio-x` / `../../chio-x` deps inside
                             moved manifests using both-endpoint group math.
  --rewrite-root-and-standalones
                             Rewrite root Cargo.toml + the 4 standalone workspaces.
  --rewrite-configs          Sweep .github, scripts, out-of-band configs, runtime
                             literals, examples, tests, sdks, tools, formal, spec.
  --all                      Run moves, then all rewrites, in order.
  --dry-run                  With any rewrite phase, print planned edits, write nothing.

Two literal forms are handled:
  Mechanism A (directory-rooted): `crates/chio-x` -> `crates/<group>/chio-x`
    applied everywhere, boundary-anchored, longest-first. Covers root manifest,
    every config, every `../crates/`/`../../crates/`/`../../../crates/` external
    dep (they spell `crates/` explicitly), and the openai rename.
  Mechanism B (in-crates sibling deps): `../chio-x` and `../../chio-x` (which do
    NOT contain the `crates/` token) rewritten with both-endpoint group lookup.
  Mechanism C (mid-string wildcards): the handful of `crates/chio-*-suffix/**`
    and `crates/chio-prefix*/**` glob patterns in path filters and review slices,
    hand-mapped to their (single) group.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

# --- The 11-folder move map. ------------------------------------------------
# Group totals: core 5, kernel 7, guards 6, protocol 27, economy 13, trust 20,
# observability 5, platform 7, products 6, sdk 6, tooling 5. Sum = 107, which
# is the invariant build_crate_to_group asserts at import time. Each group
# below maps 1:1 onto the 107 real crate directories.
GROUPS: dict[str, list[str]] = {
    "core": [
        "chio-core",
        "chio-core-types",
        "chio-errors",
        "chio-adversarial-suite",
        "chio-arena",
    ],
    "kernel": [
        "chio-kernel",
        "chio-kernel-core",
        "chio-kernel-browser",
        "chio-kernel-mobile",
        "chio-runtime",
        "chio-runtime-core",
        "chio-runtime-harness",
    ],
    "guards": [
        "chio-data-guards",
        "chio-external-guards",
        "chio-guard-registry",
        "chio-guards",
        "chio-policy",
        "chio-wasm-guards",
    ],
    "protocol": [
        "chio-a2a-adapter",
        "chio-a2a-edge",
        "chio-acp-edge",
        "chio-acp-proxy",
        "chio-ag-ui-proxy",
        "chio-anthropic-tools-adapter",
        "chio-bedrock-converse-adapter",
        "chio-cohere-tools-adapter",
        "chio-cross-protocol",
        "chio-edge-metrics",
        "chio-egress-contract",
        "chio-envoy-ext-authz",
        "chio-gemini-tools-adapter",
        "chio-groq-tools-adapter",
        "chio-mcp-adapter",
        "chio-mcp-edge",
        "chio-mcp-remote",
        "chio-mistral-tools-adapter",
        "chio-ollama-tools-adapter",
        "chio-openai",
        "chio-openapi",
        "chio-openapi-mcp-bridge",
        "chio-provider-adapter-core",
        "chio-provider-conformance",
        "chio-tool-call-fabric",
        "chio-tower",
        "chio-hosted-mcp",
    ],
    "economy": [
        "chio-anchor",
        "chio-appraisal",
        "chio-autonomy",
        "chio-credit",
        "chio-link",
        "chio-listing",
        "chio-market",
        "chio-open-market",
        "chio-settle",
        "chio-underwriting",
        "chio-web3",
        "chio-web3-bindings",
        "chio-metering",
    ],
    "trust": [
        "chio-replay-corpus",
        "chio-attest-buyer",
        "chio-attest-buyer-core",
        "chio-attest-verify",
        "chio-attest-loopback",
        "chio-custody-hw",
        "chio-weights",
        "chio-tee",
        "chio-tee-frame",
        "chio-credentials",
        "chio-did",
        "chio-federation",
        "chio-federation-authority",
        "chio-governance",
        "chio-pheromone",
        "chio-pheromone-relay",
        "chio-pheromone-runtime",
        "chio-revocation-oracle",
        "chio-reputation",
        "chio-selective-disclosure",
    ],
    "observability": [
        "chio-lineage",
        "chio-log-redact",
        "chio-metrics-spec",
        "chio-otel-receipt-exporter",
        "chio-siem",
    ],
    "platform": [
        "chio-config",
        "chio-control-plane",
        "chio-manifest",
        "chio-store-sqlite",
        "chio-workflow",
        "chio-http-core",
        "chio-http-session",
    ],
    "products": [
        "chio-api-protect",
        "chio-cli",
        "chio-mercury",
        "chio-mercury-core",
        "chio-wall",
        "chio-wall-core",
    ],
    "sdk": [
        "chio-binding-helpers",
        "chio-bindings-ffi",
        "chio-cpp-kernel-ffi",
        "chio-eval-receipt",
        "chio-guard-sdk",
        "chio-guard-sdk-macros",
    ],
    "tooling": [
        "chio-lsp",
        "chio-conformance",
        "chio-spec-codegen",
        "chio-spec-validate",
        "chio-test-support",
    ],
}

GROUP_NAMES = list(GROUPS.keys())

# The one directory whose new basename differs from its old basename: the dir
# rename folds into its move so the dir matches its package name.
DIR_RENAME = {"chio-openai": "chio-openai-adapter"}

# Trees that deliberately quote old paths as historical/evidence, plus build
# output and nested worktrees. The walk skips anything under these prefixes.
EXCLUDE_PREFIXES = (
    "docs/superpowers/",
    "audits/evidence/",
    ".codex/pr-cleanup/",
    "target/",
    ".git/",
    ".worktrees/",
    ".claude/worktrees/",
)

# The guard's own resolver-test fixtures intentionally embed synthetic crate
# names (chio-ghost, chio-foo) and pre-move literals; the blind sweep must
# never rewrite them.
SKIP_FILES = ("xtask/src/crate_paths.rs",)

# This migration script itself embeds the old-form crate names in its map; it
# must never rewrite itself.
SCRIPT_REL = "scripts/migrate-phase6-crate-folders.py"

# File extensions the config sweep rewrites (the union of every place a
# directory-rooted literal can live across the repo). Includes the live-path
# build/test surfaces beyond the manifest set: CMake (.cmake / CMakeLists.txt),
# TypeScript (verdict-matrix driver imports and source-path references), and
# ignore globs (a stale ignore would let generated output land at the new
# crate path uncommitted-or-committed wrongly). Prose-only types (.md, .tex,
# .tla, .lean, .csv) are deliberately NOT swept: their crate-path mentions are
# cosmetic and out of the fail-closed gate's include set.
SWEEP_EXTS = {
    ".toml",
    ".yml",
    ".yaml",
    ".json",
    ".py",
    ".sh",
    ".bats",
    ".rs",
    ".go",
    ".cmake",
    ".ts",
}
# Files with no extension (or fixed basenames) that still carry live literals.
SWEEP_BASENAMES = {"Dockerfile", "CODEOWNERS", "CMakeLists.txt", ".gitignore"}


def build_crate_to_group() -> dict[str, str]:
    total = sum(len(v) for v in GROUPS.values())
    if total != 107:
        sys.exit(f"FATAL: group map sums to {total}, expected 107")
    crate_to_group: dict[str, str] = {}
    for group, crates in GROUPS.items():
        for crate in crates:
            if crate in crate_to_group:
                sys.exit(f"FATAL: {crate} assigned to two groups")
            crate_to_group[crate] = group
    return crate_to_group


CRATE_TO_GROUP = build_crate_to_group()


def new_dir_basename(crate: str) -> str:
    return DIR_RENAME.get(crate, crate)


def new_rel_under_crates(crate: str) -> str:
    """`chio-x` -> `<group>/chio-x` (with the openai dir rename applied)."""
    return f"{CRATE_TO_GROUP[crate]}/{new_dir_basename(crate)}"


# --- Mechanism A: boundary-anchored directory-literal map. ------------------
# Ordered longest-first so `crates/chio-core` cannot partially match inside
# `crates/chio-core-types`. The match must be followed by a path-boundary char
# (`/`, `"`, whitespace, `:`, `*`, `,`, `)`, backtick, `'`) or end-of-string.
def _build_dir_literal_pattern() -> tuple[re.Pattern[str], dict[str, str]]:
    mapping: dict[str, str] = {}
    for crate in CRATE_TO_GROUP:
        old = f"crates/{crate}"
        new = f"crates/{new_rel_under_crates(crate)}"
        mapping[old] = new
    olds = sorted(mapping.keys(), key=len, reverse=True)
    alternation = "|".join(re.escape(o) for o in olds)
    # The match must START at a non-crate-name char (so `foochio-core` is not
    # touched) and END where the crate-name segment ends: the next char must
    # NOT continue a crate name (`[A-Za-z0-9_-]`). That boundary admits a path
    # separator `/`, a quote, whitespace, a glob `*`, a comma/paren/backtick,
    # and a trailing sentence period, while still keeping `crates/chio-core`
    # distinct from `crates/chio-core-types` (a following `-` blocks the short
    # match, and longest-first ordering matches the long name first anyway).
    pattern = re.compile(rf"(?<![A-Za-z0-9_])({alternation})(?![A-Za-z0-9_-])")
    return pattern, mapping


DIR_LITERAL_RE, DIR_LITERAL_MAP = _build_dir_literal_pattern()


def rewrite_directory_literals(text: str) -> str:
    return DIR_LITERAL_RE.sub(lambda m: DIR_LITERAL_MAP[m.group(1)], text)


# --- Mechanism C: mid-string wildcard glob patterns. ------------------------
# Each maps to exactly one group because every crate matching the wildcard
# lives in that group. Longest-first so a short wildcard cannot shadow a
# longer crate name (e.g. `chio-*-edge` vs `chio-edge-metrics`).
# `chio-replay-gate` matches no real crate dir; carrying its prefix keeps it
# harmlessly non-matching.
WILDCARD_MAP: list[tuple[str, str]] = [
    ("crates/chio-*-adapter/", "crates/protocol/chio-*-adapter/"),
    ("crates/chio-*-edge/", "crates/protocol/chio-*-edge/"),
    ("crates/chio-*-proxy/", "crates/protocol/chio-*-proxy/"),
    ("crates/chio-attest-*/", "crates/trust/chio-attest-*/"),
    ("crates/chio-federation*/", "crates/trust/chio-federation*/"),
    ("crates/chio-kernel*/", "crates/kernel/chio-kernel*/"),
    ("crates/chio-replay-gate/", "crates/trust/chio-replay-gate/"),
]


def rewrite_wildcards(text: str) -> str:
    for old, new in WILDCARD_MAP:
        text = text.replace(old, new)
    return text


# --- Mechanism B: sibling relative deps inside moved manifests. -------------
# For an in-crates manifest whose source crate is S, a dep written as
# `../chio-x` (single level) or `../../chio-x` (verdict_matrix, depth 2 under
# crates/) must be recomputed from BOTH endpoints' new locations:
#   single-level source S at crates/<gS>/S, dep chio-x at crates/<gX>/<dirX>:
#     same group   -> ../<dirX>            (one up to the shared group dir)
#     cross group   -> ../../<gX>/<dirX>   (two up: out of S, out of gS)
#   verdict_matrix source at crates/tooling/chio-conformance/verdict_matrix
#   (depth 3 under crates/), dep chio-x at crates/<gX>/<dirX>:
#     always cross  -> ../../../<gX>/<dirX>
_SIBLING_RE = re.compile(r'path\s*=\s*"((?:\.\./)+)(chio-[a-z0-9-]+)"')


def rewrite_relative_deps(source_crate: str, depth_under_crates: int, text: str) -> str:
    """Rewrite `../chio-x` style sibling deps. `depth_under_crates` is how many
    path segments the manifest's directory sits below `crates/` BEFORE the move
    (1 for a top-level crate dir, 2 for verdict_matrix)."""
    source_group = CRATE_TO_GROUP[source_crate]

    def repl(m: re.Match[str]) -> str:
        dep = m.group(2)
        if dep not in CRATE_TO_GROUP:
            return m.group(0)
        dep_group = CRATE_TO_GROUP[dep]
        dep_dir = new_dir_basename(dep)
        if depth_under_crates == 1:
            # Top-level source crate, now at crates/<source_group>/<crate>.
            if dep_group == source_group:
                new_path = f"../{dep_dir}"
            else:
                new_path = f"../../{dep_group}/{dep_dir}"
        else:
            # verdict_matrix: was crates/chio-conformance/verdict_matrix
            # (depth 2), now crates/tooling/chio-conformance/verdict_matrix
            # (depth 3). Its deps always cross out to a sibling group.
            new_path = f"../../../{dep_group}/{dep_dir}"
        return f'path = "{new_path}"'

    return _SIBLING_RE.sub(repl, text)


# --- Mechanism D: cross-crate source includes inside `.rs` test files. ------
# Two distinct relative-path bases appear in `.rs` files, with different math:
#
# 1. Compile-time `#[path = "../../chio-x/..."]` / `include_str!` /
#    `include_bytes!` / `include!`: the path is relative to the SOURCE FILE,
#    which sits at crates/<gS>/<S>/tests/<f>.rs. Before the move `../../chio-x`
#    climbed tests -> S -> crates and landed on the (then top-level) `chio-x`.
#    The file is now one directory deeper, so `../../chio-x/...` becomes
#    `../../../<gX>/chio-x/...` (one extra `../`, then the dest group). This is
#    independent of the source group because the base climbs all the way to
#    `crates/`.
#
# 2. Runtime `CARGO_MANIFEST_DIR`-relative joins (`manifest_dir.join("../chio-x")`
#    or `PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../chio-x/...")`): the
#    base is the CRATE directory crates/<gS>/<S>. `../chio-x` previously reached
#    crates/chio-x; now `..` is the group dir, so this is the same both-endpoint
#    math as a Cargo sibling dep (Mechanism B, depth 1): same group keeps
#    `../chio-x`, cross group becomes `../../<gX>/chio-x`.
#
# Form 1 is detected by requiring two-or-more `../` levels; form 2 by exactly
# one. Both skip non-crate names (so `../chio-py-peer`, a binary probe, is
# untouched). Idempotent: a rewritten path no longer has `chio-` directly after
# the dots.
_RS_INCLUDE_RE = re.compile(r'"((?:\.\./){2,})(chio-[a-z0-9-]+)((?:/[^"]*)?)"')
_RS_MANIFEST_JOIN_RE = re.compile(r'"\.\./(chio-[a-z0-9-]+)((?:/[^"]*)?)"')


def rewrite_rs_cross_crate_includes(text: str) -> str:
    def repl(m: re.Match[str]) -> str:
        dots, dep, tail = m.group(1), m.group(2), m.group(3)
        if dep not in CRATE_TO_GROUP:
            return m.group(0)
        new_dots = dots + "../"
        dep_dir = new_dir_basename(dep)
        dep_group = CRATE_TO_GROUP[dep]
        return f'"{new_dots}{dep_group}/{dep_dir}{tail}"'

    return _RS_INCLUDE_RE.sub(repl, text)


def rewrite_rs_manifest_dir_joins(source_crate: str, text: str) -> str:
    source_group = CRATE_TO_GROUP[source_crate]

    def repl(m: re.Match[str]) -> str:
        dep, tail = m.group(1), m.group(2)
        if dep not in CRATE_TO_GROUP:
            return m.group(0)
        dep_dir = new_dir_basename(dep)
        dep_group = CRATE_TO_GROUP[dep]
        if dep_group == source_group:
            return f'"../{dep_dir}{tail}"'
        return f'"../../{dep_group}/{dep_dir}{tail}"'

    return _RS_MANIFEST_JOIN_RE.sub(repl, text)


# --- Mechanism E: crate-relative paths that escape to a repo-root directory. -
# A moved crate now sits one directory deeper (crates/<group>/<crate> instead
# of crates/<crate>). EVERY relative path inside that crate that climbs out to
# a repo-root sibling directory (docs/, contracts/, spec/, tests/, examples/,
# scripts/, deploy/, sdks/, fuzz/, formal/, integrations/, bench/, compliance/,
# wit/, arena-at-root, audits/, packaging/, ci-gates/, tools/, coverage/) is now
# off by exactly one `../`, regardless of which subdirectory the file lives in
# (the inserted `<group>` segment is always between `crates/` and the crate).
# These are live `include_str!` / `include_bytes!` / `sol!` / `.join` / fs
# reads; the compiler reads the compile-time ones, so a missed `../` is a hard
# build break (verified: chio-web3-bindings `sol!` macros read
# `/../../contracts/...`).
#
# The first path segment after the leading `../` run selects the target. Only
# real repo-root directories are shifted; a first segment that is a crate group
# (already handled by Mechanisms B/D) or a within-crate directory (src, cases,
# fixtures, ...) is left untouched. Group names and repo-root names are
# disjoint (verified), so keying on the repo-root set is unambiguous.
REPO_ROOT_DIRS = frozenset(
    {
        "docs",
        "contracts",
        "spec",
        "tests",
        "examples",
        "scripts",
        "deploy",
        "sdks",
        "fuzz",
        "formal",
        "integrations",
        "bench",
        "compliance",
        "wit",
        "arena",
        "audits",
        "packaging",
        "ci-gates",
        "tools",
        "coverage",
        ".github",
    }
)
_RS_REPO_ESCAPE_RE = re.compile(
    r'"(/?)((?:\.\./)+)([A-Za-z0-9_.-]+)(/[^"]*)?"'
)


def rewrite_rs_repo_root_escapes(text: str) -> str:
    def repl(m: re.Match[str]) -> str:
        lead_slash, dots, first, tail = (
            m.group(1),
            m.group(2),
            m.group(3),
            m.group(4) or "",
        )
        if first not in REPO_ROOT_DIRS:
            return m.group(0)
        return f'"{lead_slash}../{dots}{first}{tail}"'

    return _RS_REPO_ESCAPE_RE.sub(repl, text)


# --- File I/O helpers. ------------------------------------------------------
def repo_root() -> Path:
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    )
    return Path(out.stdout.strip())


ROOT = repo_root()


def is_excluded(rel: str) -> bool:
    return any(rel.startswith(p) for p in EXCLUDE_PREFIXES)


def should_sweep(rel: str) -> bool:
    if is_excluded(rel):
        return False
    if rel in SKIP_FILES or rel == SCRIPT_REL:
        return False
    base = os.path.basename(rel)
    if base in SWEEP_BASENAMES or base.startswith("Dockerfile"):
        return True
    return os.path.splitext(rel)[1] in SWEEP_EXTS


def iter_sweep_files() -> list[str]:
    """All tracked + untracked-but-not-ignored files eligible for the sweep."""
    out = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        capture_output=True,
        text=True,
        check=True,
    )
    rels = sorted(set(out.stdout.splitlines()))
    return [r for r in rels if should_sweep(r)]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    (ROOT / rel).write_text(text, encoding="utf-8")


# --- Phase: directory moves. ------------------------------------------------
def git_moves(dry_run: bool) -> None:
    for group in GROUP_NAMES:
        (ROOT / "crates" / group).mkdir(parents=True, exist_ok=True)
    moved = 0
    for crate, group in CRATE_TO_GROUP.items():
        src = ROOT / "crates" / crate
        dst = ROOT / "crates" / group / new_dir_basename(crate)
        if not src.exists() and dst.exists():
            continue  # idempotent: already moved
        if not src.exists():
            sys.exit(f"FATAL: source crate dir missing: {src}")
        if dry_run:
            print(f"git mv crates/{crate} crates/{group}/{new_dir_basename(crate)}")
            moved += 1
            continue
        subprocess.run(
            ["git", "mv", str(src), str(dst)],
            cwd=ROOT,
            check=True,
        )
        moved += 1
    print(f"moves: {moved} crate directories")


# --- Phase: rewrite sibling relative deps inside moved manifests. -----------
def manifest_source_info(rel: str) -> tuple[str, int] | None:
    """Return (source_crate, depth_under_crates) for an in-crates Cargo.toml
    whose directory's sibling deps need recomputation, else None.

    After --moves the manifests live at crates/<group>/<crate>/Cargo.toml and
    crates/<group>/chio-conformance/verdict_matrix/Cargo.toml. We map back to
    the owning crate and its ORIGINAL depth under crates/ (1 top-level, 2 for
    verdict_matrix) so the dep math matches the pre-move relative form."""
    parts = rel.split("/")
    if parts[0] != "crates" or parts[-1] != "Cargo.toml":
        return None
    # crates/<group>/<crate>/Cargo.toml -> top-level crate (depth 1)
    if len(parts) == 4 and parts[1] in GROUPS:
        crate_dir = parts[2]
        # map renamed dir back to its crate key
        for c in CRATE_TO_GROUP:
            if new_dir_basename(c) == crate_dir:
                return (c, 1)
        return None
    # crates/<group>/chio-conformance/verdict_matrix/Cargo.toml -> depth 2
    if (
        len(parts) == 5
        and parts[1] in GROUPS
        and parts[2] == "chio-conformance"
        and parts[3] == "verdict_matrix"
    ):
        return ("chio-conformance", 2)
    return None


def rs_source_crate(rel: str) -> str | None:
    """For a `.rs` file at crates/<group>/<crate>/..., return its owning crate
    key (mapping the openai rename back), else None."""
    parts = rel.split("/")
    if len(parts) < 3 or parts[0] != "crates" or parts[1] not in GROUPS:
        return None
    crate_dir = parts[2]
    for c in CRATE_TO_GROUP:
        if new_dir_basename(c) == crate_dir:
            return c
    return None


def rewrite_relative_deps_phase(dry_run: bool) -> None:
    out = subprocess.run(
        ["git", "ls-files", "crates"],
        capture_output=True,
        text=True,
        check=True,
    )
    manifests = 0
    includes = 0
    for rel in out.stdout.splitlines():
        if rel.endswith("Cargo.toml"):
            info = manifest_source_info(rel)
            if info is None:
                continue
            source_crate, depth = info
            before = read(rel)
            after = rewrite_relative_deps(source_crate, depth, before)
            if after != before:
                if dry_run:
                    print(f"[rel-deps] {rel}")
                else:
                    write(rel, after)
                manifests += 1
        elif rel.endswith(".rs"):
            # Cross-crate source references that climb out of the crate to a
            # sibling crate (Mechanism D): compile-time `#[path]`/`include*!`
            # (base = source file) and runtime CARGO_MANIFEST_DIR `.join`
            # (base = crate dir). Skip the guard's own fixtures.
            if rel in SKIP_FILES:
                continue
            raw = read(rel)
            # `"../` covers source-file-relative literals; `"/..` covers the
            # `concat!(env!("CARGO_MANIFEST_DIR"), "/../../...")` form.
            if '"../' not in raw and '"/..' not in raw:
                continue
            after = rewrite_rs_cross_crate_includes(raw)
            after = rewrite_rs_repo_root_escapes(after)
            source_crate = rs_source_crate(rel)
            if source_crate is not None:
                after = rewrite_rs_manifest_dir_joins(source_crate, after)
            if after != raw:
                if dry_run:
                    print(f"[rs-include] {rel}")
                else:
                    write(rel, after)
                includes += 1
    print(
        f"rewrite-relative-deps: {manifests} manifests + "
        f"{includes} .rs cross-crate includes updated"
    )


# --- Phase: root Cargo.toml + standalone workspaces. ------------------------
# The root manifest and the standalone external deps all spell `crates/` so
# Mechanism A handles them directly. The standalone manifests are not in-crates
# (their sibling form is `../crates/...` which contains the token).
STANDALONE_FILES = [
    "Cargo.toml",
    "fuzz/Cargo.toml",
    "fuzz/owners.toml",
    "fuzz/target-map.toml",
    "sdks/rust/chio-guard-sdk-compat/Cargo.toml",
    "sdks/lambda/chio-lambda-extension/Cargo.toml",
]


def rewrite_root_and_standalones(dry_run: bool) -> None:
    changed = 0
    for rel in STANDALONE_FILES:
        if not (ROOT / rel).exists():
            sys.exit(f"FATAL: expected standalone file missing: {rel}")
        before = read(rel)
        after = rewrite_wildcards(rewrite_directory_literals(before))
        if after != before:
            if dry_run:
                print(f"[root/standalone] {rel}")
            else:
                write(rel, after)
            changed += 1
    print(f"rewrite-root-and-standalones: {changed} files updated")


# --- Phase: blind config sweep over everything else. ------------------------
def rewrite_configs(dry_run: bool) -> None:
    changed = 0
    # Files already handled by the root/standalone phase: do not double-process
    # (idempotent anyway, but keep the accounting clean).
    handled = set(STANDALONE_FILES)
    for rel in iter_sweep_files():
        if rel in handled:
            continue
        before = read(rel)
        if "crates/chio-" not in before:
            continue
        after = rewrite_wildcards(rewrite_directory_literals(before))
        if after != before:
            if dry_run:
                print(f"[config] {rel}")
            else:
                write(rel, after)
            changed += 1
    print(f"rewrite-configs: {changed} files updated")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check-sum-only", action="store_true")
    ap.add_argument("--moves", action="store_true")
    ap.add_argument("--rewrite-relative-deps", action="store_true")
    ap.add_argument("--rewrite-root-and-standalones", action="store_true")
    ap.add_argument("--rewrite-configs", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.check_sum_only:
        total = sum(len(v) for v in GROUPS.values())
        print(f"{total} crates across {len(GROUPS)} groups; sum OK")
        return

    ran = False
    if args.all or args.moves:
        git_moves(args.dry_run)
        ran = True
    if args.all or args.rewrite_relative_deps:
        rewrite_relative_deps_phase(args.dry_run)
        ran = True
    if args.all or args.rewrite_root_and_standalones:
        rewrite_root_and_standalones(args.dry_run)
        ran = True
    if args.all or args.rewrite_configs:
        rewrite_configs(args.dry_run)
        ran = True
    if not ran:
        ap.print_help()


if __name__ == "__main__":
    main()
