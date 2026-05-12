# Changelog

All notable changes to `chio-ray` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- feat: redact kwargs via `chio_adapter_base.redact.redact_args`
  before forwarding to the sidecar. Override via the new
  `redaction_policy` keyword on `chio_remote(...)` and
  `ChioActor.__init__(...)`. Note: this only governs receipt-log
  parameters; Ray's object store still holds the pickled originals.

## [0.1.0]

- Initial release: `@chio_remote` decorator and `ChioActor` base class
  with standing capability grants.
