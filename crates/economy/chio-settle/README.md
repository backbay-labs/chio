# chio-settle

`chio-settle` is the settlement runtime over Chio's official web3 contract
family. It turns approved Chio capital instructions into real contract calls,
projects on-chain state back into the frozen web3 receipt family, and exposes
the bounded Solana-native settlement model used for Ed25519-first parity
checks.

Use this crate to execute escrow and bond settlement on chain and reconcile the
result into Chio receipts. The contract types and bindings live in `chio-web3`
and `chio-web3-bindings`.
