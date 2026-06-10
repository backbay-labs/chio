# chio-selective-disclosure

`chio-selective-disclosure` provides BBS selective-disclosure projections and
proof packages for Chio receipts. It lets a holder reveal a subset of a
receipt's fields while producing a verifiable proof over the disclosed
projection.

Use this crate when a receipt must be shared with a verifier who should see
only part of its contents.
