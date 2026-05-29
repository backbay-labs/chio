# chio-credit

`chio-credit` defines Chio's credit, capital, and bonded-execution contracts.
It provides the credit-evaluator hook and IOU envelope types, a local credit
account, an exposure ledger, and an IOU envelope store binding. It composes the
appraisal and underwriting surfaces so credit decisions reference prior signed
Chio truth rather than restating it.

Use this crate to model credit limits, IOUs, and bonded execution for metered
tool access.
