# Changelog

All notable changes to `chio-iac` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- note: `chio-adapter-base` 0.1.1 ships `bind_and_redact` and the
  `DEFAULT_TOOL_POSITIONAL_NAMES` registry, but `chio-iac` does not use
  them today (the CLI / SDK wrappers in `terraform.py` and `pulumi.py`
  build the redacted parameters dict directly). The dependency floor
  stays at `chio-adapter-base>=0.1.0` until a concrete consumer needs
  the helper.
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
