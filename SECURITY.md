# Security Policy

Chio is security-critical infrastructure: it mediates tool access for AI systems
and signs receipts over governed decisions. We take vulnerabilities seriously and
appreciate the work of researchers who report them responsibly.

This document is the coordinated vulnerability disclosure policy: it explains how
to report a vulnerability and what to expect afterward. For the normative threat
model and trust-boundary analysis, see [spec/SECURITY.md](spec/SECURITY.md).

## Reporting a vulnerability

Please report security vulnerabilities privately. Do not open a public issue,
pull request, or discussion for a suspected vulnerability.

Email **[security@backbay.io](mailto:security@backbay.io)** with the details. If you
would like to encrypt your report, say so in an initial message and we will
arrange a secure channel.

Please include as much of the following as you can:

- A description of the vulnerability and its impact.
- The affected component, crate, or surface (for example a specific kernel,
  guard, adapter, or SDK).
- Step-by-step reproduction instructions, including a minimal proof of concept
  where possible.
- The version, commit, or release you tested against, and your environment
  (operating system and toolchain).
- Any suggested mitigation or fix, if you have one.

Clear, reproducible reports let us triage and fix issues faster.

## What to expect

- **Acknowledgement:** we aim to acknowledge your report within 3 business days.
- **Triage:** we aim to provide an initial assessment, including a severity
  estimate and whether we accept the report, within 10 business days.
- **Progress:** we will keep you informed as we work on a fix and will coordinate
  a disclosure timeline with you.
- **Credit:** with your permission, we are happy to credit you in the release
  notes or advisory for the fix. Let us know how you would like to be named, or
  if you prefer to remain anonymous.

We ask that you give us a reasonable opportunity to remediate an issue before any
public disclosure, and that you avoid privacy violations, data destruction, and
service degradation while researching.

## Supported versions

Chio is pre-release and the current Chio-owned protocol, schema, SDK, and runtime
surfaces are v1-only. Security fixes are made against the latest released version
and the `main` branch. We recommend tracking the latest release; we cannot
guarantee backported fixes for older pre-release builds. Once Chio reaches a
stable release line, this section will be updated with a concrete support window.

## Safe harbor

We will not pursue or support legal action against researchers who, in good
faith:

- make a reasonable effort to follow this policy,
- report through the private channel above,
- avoid privacy violations, data destruction, and interruption or degradation of
  services beyond what is necessary to demonstrate a vulnerability, and
- give us a reasonable time to remediate before any public disclosure.

Activity conducted consistent with this policy is considered authorized, and we
will work with you to understand and resolve the issue quickly. If in doubt about
whether a specific test is acceptable, contact us first at
[security@backbay.io](mailto:security@backbay.io).
