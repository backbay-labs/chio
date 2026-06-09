# chio-control-plane

`chio-control-plane` packages Chio's trust-control service, client helpers, and
shared runtime wiring for clustered authority, receipt, revocation, and budget
state.

Use this crate when you need the trust-control layer behind `chio trust serve`
or you are wiring a distributed Chio deployment instead of a single local
sidecar.
