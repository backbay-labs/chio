# chio-federation-authority

`chio-federation-authority` is the runtime issuer for Chio federation authority
artifacts. It produces the signed authority documents that the federation
contracts in `chio-federation` consume when establishing cross-operator trust.

Use this crate when you operate a federation authority and need to mint its
artifacts; use `chio-federation` for the admission and reputation-clearing
contract types those artifacts feed.
