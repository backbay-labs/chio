# chio-web3

`chio-web3` defines Chio's web3 settlement, anchoring, and official-chain
contract types. These types freeze the first official web3 execution surface on
top of the Chio extension substrate: the trust profile, contract package, chain
configuration, anchoring proof bundle, oracle evidence envelope, and web3
settlement lifecycle artifacts that later live-money work must honor.

Use this crate as the source of truth for Chio's on-chain artifact shapes. The
Alloy bindings and compiled artifacts live in `chio-web3-bindings`; execution
lives in `chio-settle` and `chio-anchor`.
