# chio-autonomy

`chio-autonomy` defines Chio's bounded autonomy contracts: autonomous pricing,
capital optimization, and fail-safe automation types, including execution and
rollback contracts. These extend the delegated underwriting, market, capital,
and web3 surfaces into one bounded automation layer. The layer stays
evidence-referential: it carries explicit references back to prior signed Chio
truth rather than replacing those artifacts.

Use this crate to model bounded autonomous execution with explicit pricing and
rollback guarantees.
