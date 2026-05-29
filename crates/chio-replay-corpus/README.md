# chio-replay-corpus

`chio-replay-corpus` provides replay-corpus helpers for Chio TEE captures. The
bless pipeline records redacted frames, deduplicates them by the canonical JSON
hash of their `invocation`, then re-redacts payload bytes under the current
default redactor set before writing fixtures.

Use this crate to graduate captured TEE frames into a deterministic replay
corpus. The capture source is `chio-tee`; the frame format is `chio-tee-frame`.
