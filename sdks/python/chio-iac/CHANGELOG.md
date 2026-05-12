# Changelog

All notable changes to `chio-iac` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- feat: redact tool argument bodies via `chio_adapter_base.redact.redact_args`
  before forwarding them to the sidecar. Override via the new
  `redaction_policy` keyword arg on `run_terraform` and `chio_pulumi`.

## [0.1.0]

- Initial release: `run_terraform` CLI wrapper and `chio_pulumi`
  decorator with two-phase Chio capability enforcement
  (`infra:plan` / `infra:apply`) plus `PlanReviewGuard`.
