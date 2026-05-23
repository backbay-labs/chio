# Changelog

All notable changes to `chio-streaming` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1]

- chore: depend on `chio-adapter-base>=0.1.0,<0.2` so `chio-streaming`
  joins the cross-adapter redaction lineage. No runtime wiring is added
  in this release: every broker middleware's `_parameters_for` already
  returns metadata only (`subject`/`topic`, normalised headers,
  `body_length`, `body_hash`, plus broker-specific identifiers) and
  never forwards the message body. The Chio sidecar therefore never
  receives a `chio_file_write.content` / `chio_file_edit.patch` payload
  through the streaming surface, so `redact_args` would be a no-op
  today. Declaring the dependency makes the secret-leak audit table
  uniform across adapters and lets a future broker that does forward
  bodies wire `chio_adapter_base.redact.redact_args` in one line.

## [0.2.0]

- Prior release: full broker matrix (Kafka EOS v2 transactions, NATS
  JetStream, Apache Pulsar, AWS EventBridge, Google Cloud Pub/Sub,
  Redis Streams, Apache Flink) with shared `ReceiptEnvelope`,
  `DLQRouter`, and `BaseProcessingOutcome`.
