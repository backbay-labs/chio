"""Bundled default policy for coding agents.

This module exposes the zero-config policy shipped with
``chio-code-agent``. Two representations are provided:

* :data:`DEFAULT_POLICY_YAML` -- the raw YAML string. The Rust
  ``chio-cli`` crate embeds a byte-identical copy of this file so that
  ``chio mcp serve --preset code-agent`` runs the same policy.
* :data:`DEFAULT_POLICY` -- a parsed :class:`CodeAgentPolicy` dataclass
  used by the Python pre-flight checks (``FileTool``, ``ShellTool``,
  ``GitTool``). The pre-flight rejects calls locally for cases such as
  ``.env`` writes, absolute paths outside cwd, and ``git push --force``
  so the SDK works even without a running sidecar.

The policy is fail-closed: anything not explicitly allowed is denied.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from chio_code_agent.errors import ChioCodeAgentPolicyError

# ---------------------------------------------------------------------------
# Bundled YAML
# ---------------------------------------------------------------------------

_POLICY_YAML_PATH = Path(__file__).parent / "default_policy.yaml"


def _load_default_yaml() -> str:
    """Read the bundled default policy YAML from disk."""
    try:
        return _POLICY_YAML_PATH.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - packaging bug
        raise ChioCodeAgentPolicyError(
            f"failed to load bundled default policy: {exc}"
        ) from exc


DEFAULT_POLICY_YAML: str = _load_default_yaml()
"""Raw YAML string of the bundled default policy.

Kept in sync with ``crates/chio-cli/src/policies/code_agent.yaml`` so the
Python SDK and the ``chio mcp serve --preset code-agent`` flag evaluate
the same rules.
"""


# ---------------------------------------------------------------------------
# Parsed policy model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AllowedTool:
    """A single tool the default policy permits."""

    server: str
    tool: str


@dataclass
class CodeAgentPolicy:
    """Parsed, validated default policy used by local pre-flight checks.

    Attributes
    ----------
    allowed_tools:
        Tools explicitly allowed by the bundled policy. Anything not
        present here is denied.
    forbidden_path_patterns:
        Glob patterns (``fnmatch``/``**`` style) that are always denied
        for file operations. Matched against the absolute or relative
        path, with ``**`` treated as ``*`` per glob segment.
    writable_roots:
        Roots under which write operations are allowed. All writes
        must be strictly inside one of these roots. Defaults to
        ``{"src", "tests", "docs"}`` under the cwd.
    readable_from_cwd:
        When True (the default), read operations are confined to the
        current working directory subtree.
    shell_forbidden_patterns:
        Compiled regular expressions; if any matches the full shell
        command, the call is denied.
    shell_approval_required_patterns:
        Compiled regular expressions; if any matches, the call needs
        explicit human approval (the caller decides how to surface the
        prompt). The default set flags ``rm -rf`` of user-owned paths
        and other mutating operations.
    git_deny_patterns:
        Compiled regular expressions denied for git tool calls
        regardless of the agent context (covers force-push, etc.).
    raw:
        The parsed YAML as a dict, preserved for debugging / hashing.
    """

    allowed_tools: set[AllowedTool] = field(default_factory=set)
    forbidden_path_patterns: list[str] = field(default_factory=list)
    writable_roots: list[str] = field(default_factory=list)
    readable_from_cwd: bool = True
    shell_forbidden_patterns: list[re.Pattern[str]] = field(default_factory=list)
    shell_approval_required_patterns: list[re.Pattern[str]] = field(
        default_factory=list
    )
    git_deny_patterns: list[re.Pattern[str]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Tool-level checks
    # ------------------------------------------------------------------

    def is_tool_allowed(self, server: str, tool: str) -> bool:
        """Return True if ``(server, tool)`` is in the allow list."""
        return AllowedTool(server=server, tool=tool) in self.allowed_tools

    # ------------------------------------------------------------------
    # Filesystem checks
    # ------------------------------------------------------------------

    def check_read(self, path: str, *, cwd: Path | None = None) -> None:
        """Raise :class:`ChioCodeAgentDeniedError` if reads are forbidden.

        Enforces three rules:
        1. The path does not match ``forbidden_path_patterns``.
        2. If ``readable_from_cwd`` is True, the resolved path is under
           ``cwd``.
        3. Absolute paths outside ``cwd`` are denied.
        """
        from chio_code_agent.errors import ChioCodeAgentDeniedError

        cwd_resolved = (cwd or Path.cwd()).resolve()
        resolved = self._resolve(path, cwd_resolved)

        if self._matches_forbidden(path, resolved, cwd_resolved):
            raise ChioCodeAgentDeniedError(
                f"read of {path!r} denied by forbidden_path policy",
                tool_name="read_file",
                reason="forbidden_path",
                guard="forbidden_path",
            )

        if self.readable_from_cwd and not self._is_under(resolved, cwd_resolved):
            raise ChioCodeAgentDeniedError(
                f"read of {path!r} denied: path is outside the working directory",
                tool_name="read_file",
                reason="outside_cwd",
                guard="path_allowlist",
            )

    def check_write(self, path: str, *, cwd: Path | None = None) -> None:
        """Raise :class:`ChioCodeAgentDeniedError` if writes are forbidden.

        Enforces:
        1. Forbidden path patterns.
        2. The resolved path is inside ``cwd``.
        3. The resolved path is inside one of ``writable_roots`` under
           ``cwd`` (default: ``src/``, ``tests/``, ``docs/``).
        """
        from chio_code_agent.errors import ChioCodeAgentDeniedError

        cwd_resolved = (cwd or Path.cwd()).resolve()
        resolved = self._resolve(path, cwd_resolved)

        if self._matches_forbidden(path, resolved, cwd_resolved):
            raise ChioCodeAgentDeniedError(
                f"write to {path!r} denied by forbidden_path policy",
                tool_name="write_file",
                reason="forbidden_path",
                guard="forbidden_path",
            )

        if not self._is_under(resolved, cwd_resolved):
            raise ChioCodeAgentDeniedError(
                f"write to {path!r} denied: path is outside the working directory",
                tool_name="write_file",
                reason="outside_cwd",
                guard="path_allowlist",
            )

        if self.writable_roots and not self._is_in_writable_root(
            resolved, cwd_resolved
        ):
            roots = ", ".join(sorted(self.writable_roots))
            raise ChioCodeAgentDeniedError(
                f"write to {path!r} denied: writes are only allowed under {{{roots}}}",
                tool_name="write_file",
                reason="not_in_writable_root",
                guard="path_allowlist",
            )

    # ------------------------------------------------------------------
    # Shell checks
    # ------------------------------------------------------------------

    def check_shell(self, command: str) -> bool:
        """Return True if the command should require explicit approval.

        Raises :class:`ChioCodeAgentDeniedError` for outright-denied
        commands (e.g. ``git push --force``). Returns ``True`` when the
        caller should prompt a human before running the command, and
        ``False`` when the command is considered safe.
        """
        from chio_code_agent.errors import ChioCodeAgentDeniedError

        for pat in self.shell_forbidden_patterns:
            if pat.search(command):
                raise ChioCodeAgentDeniedError(
                    f"shell command {command!r} denied by policy",
                    tool_name="run_command",
                    reason=f"matches forbidden pattern {pat.pattern!r}",
                    guard="shell_command",
                )
        for pat in self.shell_approval_required_patterns:
            if pat.search(command):
                return True
        return False

    # ------------------------------------------------------------------
    # Git checks
    # ------------------------------------------------------------------

    def check_git(self, command: str) -> None:
        """Raise :class:`ChioCodeAgentDeniedError` for disallowed git ops."""
        from chio_code_agent.errors import ChioCodeAgentDeniedError

        for pat in self.git_deny_patterns:
            if pat.search(command):
                raise ChioCodeAgentDeniedError(
                    f"git command {command!r} denied by policy",
                    tool_name="git",
                    reason=f"matches forbidden pattern {pat.pattern!r}",
                    guard="shell_command",
                )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve(path: str, cwd: Path) -> Path:
        p = Path(path)
        if not p.is_absolute():
            p = cwd / p
        try:
            return p.resolve()
        except OSError:
            # Target may not exist yet (e.g. new file). Fall back to a
            # lexical resolve that still handles ``..`` safely.
            return Path(os.path.normpath(str(p)))

    @staticmethod
    def _is_under(candidate: Path, root: Path) -> bool:
        try:
            candidate.relative_to(root)
            return True
        except ValueError:
            return False

    def _is_in_writable_root(self, candidate: Path, cwd: Path) -> bool:
        for root in self.writable_roots:
            root_abs = (cwd / root).resolve()
            if self._is_under(candidate, root_abs):
                return True
        return False

    def _matches_forbidden(
        self, original: str, resolved: Path, cwd: Path
    ) -> bool:
        haystacks = {original, str(resolved)}
        try:
            rel = resolved.relative_to(cwd)
            haystacks.add(str(rel))
            haystacks.add(str(PurePosixPath(*rel.parts)))
        except ValueError:
            pass

        for pattern in self.forbidden_path_patterns:
            for h in haystacks:
                if _glob_match(pattern, h):
                    return True
        return False


def _glob_match(pattern: str, path: str) -> bool:
    """Match ``path`` against a ``**``-aware glob pattern.

    Implements gitignore-style ``**`` segments on top of ``fnmatch``.
    We convert the pattern into a regular expression where:

    * ``**`` matches any sequence of characters (including ``/``);
    * ``*`` matches any sequence of non-slash characters;
    * ``?`` matches a single non-slash character.

    The pattern matches anchored at the start of ``path`` and at the
    end, but a leading ``**/`` is treated as optional so that
    ``**/.env`` matches both ``.env`` at the top level and any nested
    ``.env``. The pattern is also tried against the basename for
    leaf-only matches.
    """
    normalized_path = path.replace(os.sep, "/").lstrip("/")
    patterns = [pattern]
    if pattern.startswith("**/"):
        patterns.append(pattern[3:])
    for pat in patterns:
        regex = _compile_glob(pat)
        if regex.match(normalized_path):
            return True
    # Only try a leaf match for patterns whose final segment is a
    # concrete filename (no ``**``, no embedded slash). This prevents
    # a pattern like ``**/.git/**`` (basename ``**``) from matching
    # every file.
    pattern_basename = os.path.basename(pattern)
    if pattern_basename and "**" not in pattern_basename:
        basename = os.path.basename(normalized_path)
        leaf_regex = _compile_glob(pattern_basename)
        if leaf_regex.match(basename):
            return True
    return False


def _compile_glob(pattern: str) -> re.Pattern[str]:
    """Compile a ``**``-aware glob to an anchored regex."""
    out: list[str] = ["^"]
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                # `**` -- match anything including path separators.
                out.append(".*")
                i += 2
                if i < len(pattern) and pattern[i] == "/":
                    i += 1
            else:
                out.append("[^/]*")
                i += 1
        elif ch == "?":
            out.append("[^/]")
            i += 1
        elif ch in ".+()^$|\\{}[]":
            out.append(re.escape(ch))
            i += 1
        else:
            out.append(ch)
            i += 1
    out.append("$")
    return re.compile("".join(out))


# ---------------------------------------------------------------------------
# Compilation from YAML
# ---------------------------------------------------------------------------


_DEFAULT_WRITABLE_ROOTS = ("src", "tests", "docs")

# Approval-required patterns surface explicit destructive intent but
# stop short of the outright-denied patterns in the YAML. The SDK does
# not execute the command; callers decide whether to prompt the user.
_DEFAULT_APPROVAL_REQUIRED = (
    r"(?i)^\s*rm\s+-rf?\s+",
    r"(?i)^\s*rm\s+",
    r"(?i)git\s+reset\s+--hard",
    r"(?i)git\s+clean\s+-[fd]+",
    r"(?i)\bmv\s+",
    r"(?i)\bcp\s+-r",
)

_DEFAULT_GIT_DENY = (
    r"(?i)git\s+push\s+.*--force",
    r"(?i)git\s+push\s+.*-f(\s|$)",
    r"(?i)git\s+push\s+.*--force-with-lease",
    r"(?i)git\s+reset\s+--hard\s+origin",
)


def compile_policy(yaml_text: str) -> CodeAgentPolicy:
    """Compile a policy YAML string into a :class:`CodeAgentPolicy`.

    Parameters
    ----------
    yaml_text:
        YAML document in the format produced by
        :data:`DEFAULT_POLICY_YAML`.

    Raises
    ------
    ChioCodeAgentPolicyError
        If the YAML is malformed or missing required sections.
    """
    try:
        parsed = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        raise ChioCodeAgentPolicyError(
            f"invalid policy YAML: {exc}"
        ) from exc

    if not isinstance(parsed, dict):
        raise ChioCodeAgentPolicyError(
            "policy YAML must be a mapping at the top level"
        )

    guards = parsed.get("guards") or {}
    capabilities = parsed.get("capabilities") or {}
    default_caps = (capabilities.get("default") or {}).get("tools") or []

    allowed: set[AllowedTool] = set()
    for entry in default_caps:
        if not isinstance(entry, dict):
            continue
        server = entry.get("server")
        tool = entry.get("tool")
        if not isinstance(server, str) or not isinstance(tool, str):
            continue
        allowed.add(AllowedTool(server=server, tool=tool))

    forbidden_cfg = guards.get("forbidden_path") or {}
    forbidden_patterns: list[str] = []
    if isinstance(forbidden_cfg, dict):
        extra = forbidden_cfg.get("additional_patterns") or []
        if isinstance(extra, list):
            forbidden_patterns.extend(str(p) for p in extra)
        explicit = forbidden_cfg.get("patterns")
        if isinstance(explicit, list):
            forbidden_patterns.extend(str(p) for p in explicit)

    shell_cfg = guards.get("shell_command") or {}
    shell_forbidden: list[re.Pattern[str]] = []
    if isinstance(shell_cfg, dict):
        patterns = shell_cfg.get("forbidden_patterns") or []
        if isinstance(patterns, list):
            for raw in patterns:
                try:
                    shell_forbidden.append(re.compile(str(raw)))
                except re.error as exc:
                    raise ChioCodeAgentPolicyError(
                        f"invalid shell_command pattern {raw!r}: {exc}"
                    ) from exc

    git_deny = [re.compile(p) for p in _DEFAULT_GIT_DENY]
    approval_required = [re.compile(p) for p in _DEFAULT_APPROVAL_REQUIRED]

    return CodeAgentPolicy(
        allowed_tools=allowed,
        forbidden_path_patterns=forbidden_patterns,
        writable_roots=list(_DEFAULT_WRITABLE_ROOTS),
        readable_from_cwd=True,
        shell_forbidden_patterns=shell_forbidden,
        shell_approval_required_patterns=approval_required,
        git_deny_patterns=git_deny,
        raw=parsed,
    )


DEFAULT_POLICY: CodeAgentPolicy = compile_policy(DEFAULT_POLICY_YAML)
"""The parsed bundled default policy, ready for pre-flight checks."""


__all__ = [
    "AllowedTool",
    "CodeAgentPolicy",
    "DEFAULT_POLICY",
    "DEFAULT_POLICY_YAML",
    "compile_policy",
]
