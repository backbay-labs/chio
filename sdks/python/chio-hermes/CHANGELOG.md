# Changelog

All notable changes to `chio-hermes` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

### Added

- Initial release. Hermes Agent plugin wrapping `chio_code_agent.CodeAgent`
  for file/shell/git tools. Registers 12 capability-scoped tools under the
  `chio` toolset, captures signed Chio receipts in `post_tool_call`, and
  enforces local policy in `pre_tool_call`.
- Session-lifecycle hooks: `on_session_start` clears stale pending entries,
  `on_session_end` drains the in-memory pending buffer through the JSONL
  writer.
- `hermes chio` CLI subcommand for capability lifecycle (`issue`, `list`,
  `revoke`).
- `/chio` in-session slash command for status and recent receipts.
- Hatchling build with `plugin.yaml` force-included into the wheel for
  directory-mode discovery.

### Notes

- All four registered hooks are plain `def` callables. Hermes's
  `PluginManager.invoke_hook` dispatches synchronously
  (`hermes_cli/plugins.py:1218-1232` does `ret = cb(**kwargs)` with no
  await), so async hooks would silently drop their bodies. See
  `docs/integrations/HERMES.md` "Known issues" for upstream-Hermes
  caveats around `hermes plugins list`, `hermes plugins enable`, and
  `hermes setup` for entry-point plugins.
- `register(ctx)` requires a Hermes plugin context whose `register_tool`
  accepts `check_fn`, `requires_env`, and `description` keyword
  arguments.
