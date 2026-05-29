# chio-did

`chio-did` implements self-certifying `did:chio` identifiers and DID Document
resolution. The method is intentionally narrow: the method-specific identifier
is the lowercase hex form of an Ed25519 public key already used by Chio agents
and operators, so basic resolution is self-certifying and needs no registry
lookup. The resolving environment may optionally attach receipt-log service
endpoints.

Use this crate to derive, parse, or resolve the DIDs that name Chio agents and
operators.
