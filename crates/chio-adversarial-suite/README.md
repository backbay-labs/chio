# chio-adversarial-suite

`chio-adversarial-suite` is the shared loader for Chio's curated adversarial
trust-boundary corpus. It fixes the case envelope and validation rules for
malicious-but-well-formed cases; the concrete vectors live under `cases/`.

Use this crate to load and validate adversarial test cases against the Chio
trust boundary. The scenario runner that exercises them is `chio-arena`.
