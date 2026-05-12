# Changelog

All notable changes to `chio-iac` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- chore: bump `chio-adapter-base` dependency to `>=0.1.1,<0.2` so the
  centralised `bind_and_redact` helper and
  `DEFAULT_TOOL_POSITIONAL_NAMES` registry (added in chio-adapter-base
  0.1.1, PR #675) are available downstream. No source change is needed
  here because `chio-iac` builds the redacted parameters dict in the
  CLI / SDK wrappers (`terraform.py`, `pulumi.py`) without any
  positional-binding helper to consolidate.
- feat: redact tool argument bodies via `chio_adapter_base.redact.redact_args`
  before forwarding them to the sidecar. Override via the new
  `redaction_policy` keyword arg on `run_terraform` and `chio_pulumi`.
- design note: redact_args runs BEFORE evaluate_tool_call as defense-in-depth;
  sidecar receives only metadata for redacted fields. Tradeoff: parameter_hash
  for chio_file_write/chio_file_edit is uniform across calls. Underlying tool
  execution still receives original args.
- v0.2 follow-up (deferred primitives): `chio-adapter-base` is also missing
  `sanitised_env`, `bounded_subprocess`, and `shell_argv_escape_check` per the
  cross-adapter audit. Once those land, `run_terraform`'s subprocess invocation
  and the Pulumi shim should adopt them.

## [0.1.0]

- Initial release: `run_terraform` CLI wrapper and `chio_pulumi`
  decorator with two-phase Chio capability enforcement
  (`infra:plan` / `infra:apply`) plus `PlanReviewGuard`.
