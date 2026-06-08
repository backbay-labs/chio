#!/usr/bin/env python3
"""Phase 2 helper: flip internal chio path deps to `{ workspace = true }`.

For each Cargo.toml passed on argv, rewrite every line of the form
    <key> = { [package = "P",] [version = "V",] path = "<...chio-...>" [, ...] }
to
    <key> = { [package = "P",] workspace = true [, ...] }
preserving package / default-features / features / optional and dropping any
version. Only lines whose `path` points at an internal chio crate are touched;
any other dependency line is left byte-for-byte unchanged. Idempotent: a line
already using `workspace = true` is skipped.

RENAMED-DEP GUARD: cargo inherits a workspace dependency by the dependency KEY,
not by `package = "..."`. A line `chio-core = { package = "chio-core-types",
workspace = true }` would resolve to the table entry keyed `chio-core` (the real
chio-core crate), NOT chio-core-types, silently mis-resolving the graph; and
`chio-openai = { package = "chio-openai-adapter", workspace = true }` would fail
to parse (`dependency.chio-openai was not found in workspace.dependencies`,
because the table key is chio-openai-adapter, not chio-openai). So any line whose
`package = "P"` differs from its dependency key CANNOT be centralized via a
member-side package= + workspace=true and is left path-based, unchanged. Lines
whose package equals the key (self-named, redundant) stay flippable. Fail-closed:
a path-dep line that matches the chio prefix but cannot be parsed into the known
shape aborts with a nonzero exit and an error naming the file and line.
"""
import pathlib
import re
import sys

# An internal chio path dep target: ../chio-x, ../../chio-x, ../../crates/chio-x,
# ../../../crates/chio-x, etc. The package name resolves elsewhere; here we only
# need to recognize that the path ends in a chio-* crate dir.
PATH_RE = re.compile(r'path\s*=\s*"((?:\.\./)+(?:crates/)?chio-[a-z0-9/-]+?)"')
# A single inline-table dep line: `key = { ... }`.
LINE_RE = re.compile(r'^(?P<indent>\s*)(?P<key>chio-[a-z0-9-]+)\s*=\s*\{(?P<body>.*)\}\s*$')


def attrs(body: str) -> dict:
    """Parse the inline-table body into an ordered attr map (string values kept raw)."""
    out = {}
    # Split on top-level commas (no nested brackets except features = [...]).
    depth = 0
    cur = ""
    parts = []
    for ch in body:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    for p in parts:
        if "=" not in p:
            continue
        k, v = p.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def flip_line(line: str, filename: str, lineno: int) -> str:
    m = LINE_RE.match(line)
    if not m:
        return line
    body = m.group("body")
    if "workspace = true" in body or "workspace=true" in body:
        return line  # already flipped; idempotent
    if not PATH_RE.search(body):
        return line  # not an internal chio path dep
    a = attrs(body)
    if "path" not in a:
        sys.stderr.write(f"{filename}:{lineno}: chio path-dep with no parseable path\n")
        raise SystemExit(2)
    # Renamed-dep guard: cargo inherits by KEY, not by package=. If package=
    # differs from the dependency key, member-side package=+workspace=true would
    # resolve to (or fail to find) the wrong table entry, so leave the line
    # path-based and unchanged. Self-named lines (package == key) are flippable.
    if "package" in a:
        pkg = a["package"].strip().strip('"').strip("'")
        if pkg != m.group("key"):
            return line  # renamed dep cannot be centralized; stays path-based
    # Rebuild in canonical order: package, workspace=true, default-features,
    # features, optional. Drop version and path.
    rebuilt = []
    if "package" in a:
        rebuilt.append(f'package = {a["package"]}')
    rebuilt.append("workspace = true")
    if "default-features" in a:
        rebuilt.append(f'default-features = {a["default-features"]}')
    if "features" in a:
        rebuilt.append(f'features = {a["features"]}')
    if "optional" in a:
        rebuilt.append(f'optional = {a["optional"]}')
    known = {"package", "version", "path", "default-features", "features", "optional"}
    unknown = set(a) - known
    if unknown:
        sys.stderr.write(f"{filename}:{lineno}: unexpected attrs {unknown}\n")
        raise SystemExit(2)
    return f'{m.group("indent")}{m.group("key")} = {{ ' + ", ".join(rebuilt) + " }\n"


def main(argv) -> int:
    changed = 0
    for fn in argv:
        path = pathlib.Path(fn)
        lines = path.read_text().splitlines(keepends=True)
        out = []
        for i, line in enumerate(lines, start=1):
            new = flip_line(line, fn, i)
            if new != line:
                changed += 1
            out.append(new)
        path.write_text("".join(out))
    print(f"flipped {changed} dependency line(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
