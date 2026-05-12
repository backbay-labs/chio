# Changelog

All notable changes to `chio-autogen` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

- feat: redact tool argument bodies via `chio_adapter_base.redact.redact_args`
  before forwarding them to the sidecar. Override via the new
  `redaction_policy` ctor arg on `ChioFunctionRegistry`.

## [0.1.0]

- Initial release: `ChioFunctionRegistry`, `ChioGroupChat` /
  `ChioGroupChatManager`, and `register_nested_chats_with_attenuation`
  for capability-scoped AutoGen integration.
