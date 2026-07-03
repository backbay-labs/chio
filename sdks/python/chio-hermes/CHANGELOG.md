# Changelog

All notable changes to `chio-hermes` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1]

### Changed

- chore: migrate seven security primitives (`redact_args`,
  `sanitised_env`, `harden_git_argv`, `BoundedSubprocess`,
  `ReceiptBuffer`, `forbidden_path` filters,
  `reject_shell_argv_escape`) to `chio-adapter-base`. The chio-hermes
  inline copies are now thin deprecation re-exports; consumers should
  import from `chio_adapter_base` directly. The inline copies will be
  superseded by the canonical executor exports.
- (no behavior change; all 165 existing tests continue to pass)

### Security

- `chio_shell_run` no longer exposes a model-supplied `approved`
  parameter. The JSON Schema dropped the property and the handler
  passes `approved=False` unconditionally; approval-required commands
  surface as a `denied` envelope.

### Fixed

- `ReceiptBuffer.denial_count()` now reflects denied tool calls. The
  post-hook hoists `status` / `error` from the handler's JSON envelope
  onto the receipt record so the deny counter (and `/chio status`)
  increments.
- `append_jsonl` writes the canonical-JSON record and trailing newline
  in one `fh.write` call. POSIX append-mode is atomic per write up to
  `PIPE_BUF`, so a SIGTERM/OOM mid-record no longer leaves a torn line.

### Removed

- `CHIO_FAIL_OPEN` env var. Documented as an escape hatch but never
  consumed; a real fail-open with sidecar-mediated semantics may
  return in a future release.

## [0.1.0]

### Added

- Initial release. Hermes Agent plugin wrapping `chio_code_agent.CodeAgent`
  for file/shell/git tools. Registers 12 capability-scoped tools under
  the `chio` toolset, captures signed Chio receipts in `post_tool_call`,
  and enforces local policy in `pre_tool_call`.
- Session-lifecycle hooks: `on_session_start` clears stale pending,
  `on_session_end` drains the in-memory pending buffer through the
  JSONL writer.
- `hermes chio` CLI subcommand (`issue`, `list`, `revoke`).
- `/chio` in-session slash command (`status`, `receipts`, `policy`).
- Hatchling build with `plugin.yaml` force-included into the wheel.

### Notes

- All four registered hooks are plain `def` callables; Hermes's
  `PluginManager.invoke_hook` (`hermes_cli/plugins.py:1218-1232`)
  dispatches synchronously and would drop async-hook bodies. See
  `docs/integrations/HERMES.md` "Known issues" for upstream gaps in
  `hermes plugins list`, `hermes plugins enable`, and `hermes setup`
  for entry-point plugins.
