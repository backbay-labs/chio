# Changelog

All notable changes to `chio-airflow` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- feat: `@chio_task` redacts kwarg bodies via
  `chio_adapter_base.redact.redact_args` before forwarding to the
  sidecar. Override via the new `redaction_policy` arg.

## [0.1.0]

- Initial release: `ChioOperator` wrapper, TaskFlow `@chio_task`
  decorator, and DAG listener that push receipt ids into XCom.
