# HITRUST Encryption-at-Rest Evidence Pointer

**Milestone:** M09.P2.T5
**Scope:** Chio v3.18 healthcare design-partner deployment
**Cloud provider:** AWS
**Status:** provider-inheritance pointer recorded for assessor bundle

## Provider inheritance

The assessed deployment inherits physical, environmental, and baseline
storage controls from AWS for the design-partner environment. This
repository records only non-secret pointers. The assessor evidence
channel must receive the private environment evidence and any current
AWS artifact downloads required by the MyCSF object.

## Evidence pointers

| Control area | Provider evidence pointer | Repository handling |
|--------------|---------------------------|---------------------|
| Physical and environmental security | AWS Artifact SOC 2 and ISO 27001 reports for the deployment region | private assessor upload only |
| Encryption at rest | AWS KMS configuration and storage encryption inventory for the tenant environment | private assessor upload only |
| Key management | AWS KMS key policy export and Chio key-rotation policy | redacted hash in P3 bundle |
| Transmission protection | TLS certificate inventory plus `spec/SECURITY.md` transport posture | P3 bundle index |
| Access logging | CloudTrail or equivalent tenant activity export | private assessor upload only |

## Chio evidence linkage

- `compliance/hitrust/policies/key-rotation.md`
- `compliance/hitrust/scope-boundary.md`
- `.planning/trajectory-3/audits/M01-healthcare-pilot.md`
- `.planning/trajectory-3/audits/M03-ci-restoration.md`

## Fail-closed rule

If the AWS provider evidence cannot be exported or verified for the
assessed tenant, the affected physical, environmental, and encryption
rows remain accepted-risk and cannot be represented as evidenced.
