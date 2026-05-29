# chio-underwriting

`chio-underwriting` defines Chio's underwriting decision, simulation, and appeal
artifacts. It provides the risk taxonomy and reason codes, evidence references
(receipt, reputation, certification), the premium pricing model
(`price_premium`, risk multipliers, decline reasons), and marketplace credit
limits by tier. It builds on the appraisal surface.

Use this crate to compute underwriting decisions and premiums from signed Chio
evidence; `chio-market` and `chio-credit` consume these outputs.
