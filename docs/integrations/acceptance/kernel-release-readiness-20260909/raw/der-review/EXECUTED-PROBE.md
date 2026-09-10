# Executed der 0.8.2 parser probe

This addendum follows the read-only source review in REVIEW.md. The isolated probe was compiled and executed after that report. It does not use or alter any Chio owner, host, credentials, protected volume, kernel binary, or repository dependency selection.

Source: the complete checksum-verified published der 0.8.2 archive retained in this directory. Expected archive SHA256: a878c850e9e421b20262e9b41f9c860e4785fa07541c266b62ff9d1ef998a80a. The probe selects only its alloc feature and uses its own Cargo target directory.

Command: `cargo run --manifest-path /tmp/chio-kernel-release-audit-20260909/der-review/probe/Cargo.toml`. Exit status 0. Exact source, Cargo lockfile, command/times, stdout and stderr are in probe/.

Observed output:

```text
valid_integer: accepted len=1 count=1 first=Some(1) reencoded=Ok([49, 3, 2, 1, 1])
wrong_type_null: accepted len=1 count=0 first=None reencoded=Ok([49, 0])
```

The valid control is SET OF INTEGER containing 1 (`31 03 02 01 01`). The invalid input is SET OF containing NULL (`31 02 05 00`), decoded as `SetOfRef<u8>`. The latter succeeds despite the wrong element type, reports one element, iterates zero elements, and serializes to an empty set. This confirms the review's typed-error suppression finding on the published source.

No application exploitability is claimed. Source review found no SetOfRef calls in Chio or the inspected Iroh/Ed25519/PKCS8/SPKI parent crates. Default CLI dependency graphs do not select der 0.8. This probe does not certify the full dependency, and no safe-to-deploy audit or gate waiver was added.
