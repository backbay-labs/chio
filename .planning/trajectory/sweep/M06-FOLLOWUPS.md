# M06 Followups

## P2: real dispatch/canonicalization allocation evidence

Carried forward from `.planning/audits/M06-perf-hardening.md`.

Original blocker: the audit's P5.T1 evidence entry says the dhat harness still
uses a placeholder `dispatch_allow` probe and does not measure the real
dispatch/canonicalization path.

New owning artifact: future performance-evidence work should replace the
placeholder probe, capture allocation-count reduction attributable to reduced
reserialization, and update `.planning/audits/M06-perf-hardening.md` with the
resulting evidence.
