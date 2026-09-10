# Engineering recovery procedure

Keep the admission database, signed receipts, operation IDs, and report artifacts when a host restarts. The report adapter reconciles an operation against its published artifact before deciding whether more work is needed.

A missing response is not proof that an operation failed. If the report exists and its input digest matches, return the existing report. If the adapter cannot establish the result, leave the operation unresolved for inspection.

Engineering incident artifacts are retained for 90 days under policy ENG-17. Customer material must be redacted before it crosses the support boundary.
