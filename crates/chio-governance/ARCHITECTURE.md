# chio-governance Architecture

## Boundary

`chio-governance` owns Chio capability leases, destructive-action governance receipts, generic governance charters, and governance case evaluation. It sits below verifier crates and must fail closed before signed authorization artifacts are accepted by higher-level proof or runtime paths.

The crate defines and verifies governance artifacts. It does not mint capability tokens, evaluate kernel guard pipelines, write receipt logs, settle payments, or resolve registry data from the network. Callers provide signed artifacts and the current evaluation time.

## Lease Authorization

Capability leases bind issuer, subject, scope digest, action class, and validity window. Verification checks schema, signature, scope digest, expiry, and issuance time so a future-dated lease cannot authorize a present action.

Destructive authorization adds a signed governance receipt. The receipt must bind the lease id, workflow id, step hash, issuing kernel, and validity window before a destructive step can proceed.

## Governance Cases

Generic governance cases evaluate listing identity, charter scope, activation binding, appeal or supersession targets, and effective admission impact. Failures return structured findings instead of panicking so callers can report why a listing is disputed, frozen, sanctioned, or clear.

## Invariants

- Unsupported schemas fail closed.
- Signatures are checked before artifact contents authorize anything.
- Scope digests and step hashes are exact SHA-256 hex bindings.
- Future-dated and expired leases or receipts are rejected.
- Evaluation errors are structured findings, not implicit allow decisions.
