"""JSON Schema definitions for the chio-hermes tool surface.

Schemas live here so tests can assert that parameter names line up with
`chio_code_agent.tools` method signatures without dragging in the full
plugin stack. Every schema sets `additionalProperties: false` so
Hermes's validator rejects unknown keys at parse time. Tool names match
`provides_tools` in `plugin.yaml`; parameter keys mirror the kwargs of
the corresponding `CodeAgent` method.
"""

from __future__ import annotations

from typing import Any

# Reusable property fragments: defined once so manifest tests can
# assert they are referenced by name rather than copy-pasted.
_PATH_PROPERTY: dict[str, Any] = {
    "type": "string",
    "minLength": 1,
    "description": "Filesystem path; resolved relative to the workspace root.",
}

_OPTIONAL_PATH_PROPERTY: dict[str, Any] = {
    "type": "string",
    "description": "Filesystem path; resolved relative to the workspace root.",
}


CHIO_FILE_READ: dict[str, Any] = {
    "type": "object",
    "title": "chio_file_read",
    "description": "Read a file inside the workspace root.",
    "properties": {"path": _PATH_PROPERTY},
    "required": ["path"],
    "additionalProperties": False,
}

CHIO_FILE_WRITE: dict[str, Any] = {
    "type": "object",
    "title": "chio_file_write",
    "description": "Write text content to a file inside the workspace root.",
    "properties": {
        "path": _PATH_PROPERTY,
        "content": {
            "type": "string",
            "description": "File contents as a UTF-8 string.",
        },
    },
    "required": ["path", "content"],
    "additionalProperties": False,
}

CHIO_FILE_EDIT: dict[str, Any] = {
    "type": "object",
    "title": "chio_file_edit",
    "description": "Apply a unified diff to a file inside the workspace root.",
    "properties": {
        "path": _PATH_PROPERTY,
        "patch": {
            "type": "string",
            "minLength": 1,
            "description": "Unified-diff patch text fed to `patch -p0` on stdin.",
        },
    },
    "required": ["path", "patch"],
    "additionalProperties": False,
}

CHIO_FILE_LIST: dict[str, Any] = {
    "type": "object",
    "title": "chio_file_list",
    "description": "List entries in a directory inside the workspace root.",
    "properties": {"path": _PATH_PROPERTY},
    "required": ["path"],
    "additionalProperties": False,
}

CHIO_FILE_SEARCH: dict[str, Any] = {
    "type": "object",
    "title": "chio_file_search",
    "description": "Search files by name (glob) inside the workspace root.",
    "properties": {
        "query": {
            "type": "string",
            "minLength": 1,
            "description": "Glob query passed to Path.rglob.",
        },
        "path": _OPTIONAL_PATH_PROPERTY,
    },
    "required": ["query"],
    "additionalProperties": False,
}

CHIO_SHELL_RUN: dict[str, Any] = {
    "type": "object",
    "title": "chio_shell_run",
    "description": (
        "Run a shell command via argv-tokenized exec (NEVER shell=True). "
        "Subject to the bundled CodeAgentPolicy approval list. "
        "Approval-required commands (e.g. `rm -rf <subdir>`, `mv`, "
        "`git reset --hard`) are denied; there is no model-supplied "
        "approval channel today."
    ),
    "properties": {
        "command": {
            "type": "string",
            "minLength": 1,
            "description": "Shell command line; tokenized via shlex before exec.",
        },
    },
    "required": ["command"],
    "additionalProperties": False,
}

CHIO_GIT_STATUS: dict[str, Any] = {
    "type": "object",
    "title": "chio_git_status",
    "description": "Run `git status --porcelain` inside the workspace root.",
    "properties": {},
    "required": [],
    "additionalProperties": False,
}

CHIO_GIT_DIFF: dict[str, Any] = {
    "type": "object",
    "title": "chio_git_diff",
    "description": "Run `git diff` (optionally constrained to paths).",
    "properties": {
        "paths": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Optional list of paths to include in the diff.",
        },
    },
    "required": [],
    "additionalProperties": False,
}

CHIO_GIT_LOG: dict[str, Any] = {
    "type": "object",
    "title": "chio_git_log",
    "description": "Run `git log` with a configurable entry limit.",
    "properties": {
        "limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": 1000,
            "description": "Maximum number of log entries to return.",
        },
    },
    "required": [],
    "additionalProperties": False,
}

CHIO_GIT_ADD: dict[str, Any] = {
    "type": "object",
    "title": "chio_git_add",
    "description": "Stage paths for commit (`git add ...`).",
    "properties": {
        "paths": {
            "type": "array",
            "items": {"type": "string", "minLength": 1},
            "minItems": 1,
            "description": "Paths to stage.",
        },
    },
    "required": ["paths"],
    "additionalProperties": False,
}

CHIO_GIT_COMMIT: dict[str, Any] = {
    "type": "object",
    "title": "chio_git_commit",
    "description": "Create a git commit with the provided message.",
    "properties": {
        "message": {
            "type": "string",
            "minLength": 1,
            "description": "Commit message body.",
        },
    },
    "required": ["message"],
    "additionalProperties": False,
}

CHIO_GIT_RUN: dict[str, Any] = {
    "type": "object",
    "title": "chio_git_run",
    "description": (
        "Run an arbitrary `git ...` command. Subject to the bundled "
        "CodeAgentPolicy git deny list (e.g. push --force)."
    ),
    "properties": {
        "command": {
            "type": "string",
            "minLength": 1,
            "description": (
                "Git arguments after the leading `git` "
                "(e.g. `status --porcelain`); a leading `git` token is "
                "tolerated and stripped."
            ),
        },
    },
    "required": ["command"],
    "additionalProperties": False,
}


SCHEMAS: dict[str, dict[str, Any]] = {
    "chio_file_read": CHIO_FILE_READ,
    "chio_file_write": CHIO_FILE_WRITE,
    "chio_file_edit": CHIO_FILE_EDIT,
    "chio_file_list": CHIO_FILE_LIST,
    "chio_file_search": CHIO_FILE_SEARCH,
    "chio_shell_run": CHIO_SHELL_RUN,
    "chio_git_status": CHIO_GIT_STATUS,
    "chio_git_diff": CHIO_GIT_DIFF,
    "chio_git_log": CHIO_GIT_LOG,
    "chio_git_add": CHIO_GIT_ADD,
    "chio_git_commit": CHIO_GIT_COMMIT,
    "chio_git_run": CHIO_GIT_RUN,
}


__all__ = [
    "SCHEMAS",
    "CHIO_FILE_READ",
    "CHIO_FILE_WRITE",
    "CHIO_FILE_EDIT",
    "CHIO_FILE_LIST",
    "CHIO_FILE_SEARCH",
    "CHIO_SHELL_RUN",
    "CHIO_GIT_STATUS",
    "CHIO_GIT_DIFF",
    "CHIO_GIT_LOG",
    "CHIO_GIT_ADD",
    "CHIO_GIT_COMMIT",
    "CHIO_GIT_RUN",
]
