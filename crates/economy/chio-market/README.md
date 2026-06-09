# chio-market

`chio-market` defines Chio's liability-market provider, quote, and claims
contracts. It provides the insurance flow (`quote_and_bind`, bound policies,
coverage limits, premium sources) and the claim-settlement path (claim
evidence, decisions, denial reasons, and settlement requests) with receipt
fingerprints linking claims to signed receipt evidence. It builds on the
appraisal, credit, and underwriting surfaces.

Use this crate to model liability coverage for metered tool access: quoting,
binding policies, and settling claims against receipt evidence.
