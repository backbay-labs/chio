# HITRUST Encryption-at-Rest Evidence Pointer

> **Status: internal readiness / gap.** No assessor is engaged and no
> provider evidence has been collected for this repository. This records
> WHERE encryption-at-rest and provider-inheritance evidence would come
> from, and marks it as an open gap until collected.

**Scope:** Chio healthcare design-partner deployment (this assessed release)
**Cloud provider:** AWS (intended deployment)

## Provider inheritance

A future assessed deployment would inherit physical, environmental, and
baseline storage controls from AWS for the design-partner environment.
This repository records only non-secret pointers. The private
environment evidence and any AWS artifact downloads required by a future
MyCSF object are out-of-tree and have not been collected.

## Evidence pointers (intended, not collected)

| Control area | Provider evidence pointer | Repository handling |
|--------------|---------------------------|---------------------|
| Physical and environmental security | AWS Artifact SOC 2 and ISO 27001 reports for the deployment region | out-of-tree; not collected |
| Encryption at rest | AWS KMS configuration and storage encryption inventory | out-of-tree; not collected |
| Key management | AWS KMS key policy export plus Chio key-rotation policy | policy is in-repo (`compliance/hitrust/policies/key-rotation.md`); export is out-of-tree |
| Transmission protection | TLS certificate inventory plus `spec/SECURITY.md` transport posture | spec is in-repo; inventory is out-of-tree |
| Access logging | CloudTrail or equivalent tenant activity export | out-of-tree; not collected |

## Chio evidence linkage (in-repo)

- `compliance/hitrust/policies/key-rotation.md`
- `compliance/hitrust/scope-boundary.md`
- `spec/SECURITY.md`

## Fail-closed rule

Until AWS provider evidence is exported and verified for the assessed
tenant, the physical, environmental, and encryption rows remain a gap
and cannot be represented as evidenced.
