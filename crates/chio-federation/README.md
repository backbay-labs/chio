# chio-federation

`chio-federation` defines Chio's federated trust, quorum, admission, and
shared-reputation contracts. These contracts extend Chio's local listing,
governance, and open-market surfaces into one bounded cross-operator
federation lane. Federation stays evidence-referential and fail-closed:
visibility may flow across operators, but runtime trust still requires explicit
local activation and review.

Use this crate to model multi-operator admission and reputation clearing on top
of locally signed Chio artifacts.
