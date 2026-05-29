# HITRUST De-identification and Minimum-Necessary Policy

**Scope:** Chio healthcare design-partner deployment (this assessed release)
**HIPAA reference:** 45 CFR 164.514
**Default posture:** no PHI in Chio kernel telemetry

## Telemetry boundary

Chio kernel telemetry for the assessed deployment must not contain PHI.
Operational telemetry records protocol decisions, receipt ids, control
ids, hashes, error classes, and timing metadata. Payload content,
patient identifiers, free-text clinical content, and design-partner
user identifiers are excluded unless the BAA-approved evidence channel
explicitly requests a redacted sample.

## De-identification posture

If any analytics or evidence sample could cross the PHI boundary, the
evidence owner must use one of the HIPAA 45 CFR 164.514 de-identification
paths before upload:

- Safe Harbor removal of direct identifiers.
- Expert Determination by an approved privacy reviewer.
- Hash-only evidence when the assessor needs integrity without content.

## Minimum necessary rule

Evidence exports include only the smallest field set needed for the
assessor control row. For routine HITRUST rows, that means schema,
hashes, control ids, receipt ids, timestamps, and redacted operator
metadata. PHI-bearing samples require private BAA channel approval and
must not be committed to this public repository.

## Assessor upload rule

The public repo may store redacted evidence paths and hashes. It must
not store PHI, unredacted patient samples, BAA contract text, or
tenant-private identity records.
