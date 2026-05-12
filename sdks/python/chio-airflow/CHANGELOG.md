# Changelog

All notable changes to `chio-airflow` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- feat: redact tool argument bodies before forwarding them to the Chio
  sidecar (and therefore the receipt log). The TaskFlow `@chio_task`
  decorator now passes its `{"args": [...], "kwargs": {...}}` payload
  through `chio_adapter_base.redact.redact_args` with the chio-default
  policy (`{"chio_file_write": ("content",), "chio_file_edit": ("patch",)}`).
  Pass a custom `RedactionPolicy` via the new `redaction_policy`
  argument on `@chio_task(...)` to extend with adapter-specific tool
  names. The user function still receives the original (unredacted)
  arguments; only the parameters forwarded to the sidecar are redacted.
- note: `ChioOperator` records Airflow context fields (`dag_id`,
  `run_id`, `execution_date`, `logical_date`) rather than per-tool
  arguments, so the redaction wiring lives on the TaskFlow path. The
  remaining chio-adapter-base primitives (`sanitised_env`,
  `harden_git_argv`, `bounded_subprocess`, `shell_argv_escape_check`)
  are deferred to a v0.2.x follow-up.

## [0.1.0]

- Initial release: `ChioOperator` wrapper, TaskFlow `@chio_task`
  decorator, and DAG listener that push receipt ids into XCom.
