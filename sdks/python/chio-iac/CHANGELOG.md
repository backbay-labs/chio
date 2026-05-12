# Changelog

All notable changes to `chio-iac` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- feat: redact tool argument bodies before writing them to receipts. Uses
  `chio_adapter_base.redact.redact_args` with the chio-default policy
  (`{"chio_file_write": ("content",), "chio_file_edit": ("patch",)}`).
  Pass a custom `RedactionPolicy` via the new `redaction_policy`
  constructor / keyword arg on `run_terraform` and `chio_pulumi` to
  redact terraform / pulumi tool-name fields (for example, the `args`
  list under `terraform:apply` when callers pass `-var=password=...`).
- note: chio-iac also lacks `sanitised_env`, `bounded_subprocess`, and
  `shell_argv_escape_check` primitives per the chio-adapter-base audit.
  Those land in a follow-up PR.

## [0.1.0]

- Initial release: `run_terraform` CLI wrapper and `chio_pulumi`
  decorator with two-phase Chio capability enforcement
  (`infra:plan` / `infra:apply`) plus `PlanReviewGuard`.
