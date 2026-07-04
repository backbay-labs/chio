---
date: 2026-04-16
framework: PCI DSS v4.0 (March 2022, effective March 2025)
maintainer: Chio Protocol Team
---

# PCI DSS v4.0 Compliance Mapping

## Metadata

| Field | Value |
|-------|-------|
| Framework | Payment Card Industry Data Security Standard v4.0 |
| Published | March 2022, fully effective March 31, 2025 |
| Scope | All 12 requirement groups |
| Chio Profile | Current v1-only pre-release profile |
| Document Date | 2026-04-16 |

---

## Executive Summary

PCI DSS v4.0 protects cardholder data (CHD) and sensitive authentication data (SAD) across people, processes, and technology. Chio does not itself process, store, or transmit cardholder data. However, agent systems governed by Chio frequently call payment gateways, CRMs that hold card data, or internal financial tool servers. Chio's role is to reduce the PCI DSS scope of the agent layer by enforcing that agents can only reach specific tools, under specific conditions, with tamper-evident attribution for every call.

Chio's strongest PCI DSS contributions are to Requirements 7, 8, and 10 (access by business need, user identification and authentication, logging and monitoring). Every tool invocation produces a signed `ChioReceipt`; batches are Merkle-committed via `KernelCheckpoint`; capability tokens carry scope, expiry, and delegation chains that map to role-based access; DPoP proof-of-possession binds each call to an agent keypair. Requirements 1, 5, 9, and 12 are organizational or network-layer concerns and are out of scope for Chio as a protocol. Requirements 3, 4, 6, and 11 have partial coverage with customer follow-through needed (for example, enforcing minimum TLS version and redacting guard evidence before persistence).

This mapping covers all 12 requirement groups with coverage level, gaps, and customer responsibility. It is intended as an input to a PCI DSS Report on Compliance (RoC) or Self-Assessment Questionnaire (SAQ) scoping exercise for an agent-layer deployment built on Chio.

---

## Coverage Legend

| Level | Meaning |
|-------|---------|
| strong | Chio's shipped controls directly satisfy the requirement at the agent tool-governance layer |
| partial | Chio supplies part of the control; configuration or additional components are required |
| customer-responsibility | The requirement is organizational, physical, or network-layer; Chio does not implement it |
| out-of-scope | The requirement does not apply to the tool-governance layer |

---

## Requirement Mapping

| Req ID | Requirement Summary | Chio Controls | Coverage | Gaps | Customer Responsibility |
|--------|---------------------|--------------|----------|------|-------------------------|
| **Req 1** | Install and maintain network security controls | Application layer; Chio runs as sidecar to tool servers. No network segmentation enforcement. | out-of-scope | Chio does not enforce firewall rules or segmentation | Firewall rules, network segmentation, CDE isolation |
| 1.2 | Configuration standards for NSCs | N/A | out-of-scope | N/A | Network device standards |
| 1.3 | Restrict inbound and outbound traffic | `crates/guards/chio-guards/src/egress_allowlist.rs` limits which egress targets agents can reach | partial | Chio enforces at application layer, not network | Network ACLs |
| 1.4 | NSCs installed between trusted and untrusted networks | N/A | out-of-scope | N/A | Network perimeter |
| 1.5 | Control risks from computing devices | N/A | out-of-scope | N/A | Endpoint management |
| **Req 2** | Apply secure configurations to all system components | Unified config (`docs/protocols/UNIFIED-CONFIGURATION.md`); fail-closed defaults | partial | No PCI-specific baseline document | PCI secure-baseline for org |
| 2.2 | System components are configured securely | `KernelConfig` defaults (deny unless allowed); guard pipeline defaults | partial | No hardening benchmark shipped | Secure baseline doc |
| 2.2.7 | Non-console admin access uses strong crypto | HTTP endpoints support TLS; mTLS documented for tool-server transport | partial | `min_tls_version` config option is planned, not yet enforced | TLS configuration |
| 2.3 | Wireless environments secured | N/A | out-of-scope | N/A | Wireless policy |
| **Req 3** | Protect stored account data | Chio does not store CHD. Receipt content hashes are SHA-256 of arguments (not raw CHD) | partial | Guard evidence (e.g., `response_sanitization` output snippets) may contain sensitive substrings before redaction | Encryption at rest for data stores |
| 3.2 | Account data storage minimized | Receipts store hashes, not raw arguments; see `crates/core/chio-core-types` | strong | None in receipt payload | PAN minimization in tool servers |
| 3.3 | SAD is not stored after authorization | N/A | out-of-scope | N/A | SAD handling in tool servers |
| 3.4 | PAN is rendered unreadable | PAN redaction in guard outputs is configurable via `secret_leak.rs` / `response_sanitization.rs` patterns | partial | No shipped PAN-specific pattern library | PAN pattern set for `response_sanitization` |
| 3.5 | Cryptographic keys used to protect PAN are secured | Chio signing keys are not PAN-encryption keys; FIPS/HSM path planned (`docs/protocols/COMPLIANCE-ROADMAP.md` section 2) | partial | HSM backends (Vault/KMS) not yet shipped | Key management for PAN |
| 3.6 | Cryptographic keys are managed | Kernel signing key rotation documented at `docs/protocols/TRUST-MODEL-AND-KEY-MANAGEMENT.md` | partial | Automated rotation tooling incomplete | Key rotation SOPs |
| 3.7 | Key-management policies and procedures | Documented in trust-model draft | partial | No formal signed SOP artifact | Customer policy docs |
| **Req 4** | Protect cardholder data with strong cryptography during transmission | TLS on HTTP endpoints; mTLS documented | partial | No enforced `min_tls_version` yet (planned) | TLS termination config |
| 4.2 | PAN is secured in transit over open/public networks | TLS between kernel and tool server | partial | Minimum version not enforced | Deployment TLS config |
| 4.2.1 | Strong cryptography and security protocols are used | Ed25519 signing for Chio artifacts; TLS configured by deployer | partial | FIPS signing path behind feature flag (planned) | FIPS crypto selection |
| **Req 5** | Protect all systems and networks from malicious software | Not endpoint protection | out-of-scope | N/A | AV/EDR on hosts |
| 5.2 | Anti-malware solutions are deployed | N/A | out-of-scope | N/A | Endpoint security |
| 5.3 | Anti-malware mechanisms are active | N/A | out-of-scope | N/A | Endpoint security |
| 5.4 | Anti-phishing mechanisms | Indirectly: `egress_allowlist.rs`, `forbidden_path.rs`, prompt-injection guards reduce phishing blast radius | partial | No dedicated phishing detector | Email/phishing controls |
| **Req 6** | Develop and maintain secure systems and software | `unwrap_used = "deny"`, `expect_used = "deny"`, `clippy -D warnings` in workspace | partial | No formal SDLC document | Customer SDLC |
| 6.2 | Bespoke and custom software is developed securely | `cargo test --workspace`, `cargo fmt --check`, canonical JSON (RFC 8785) for all signed payloads | strong | None at protocol layer | SDLC evidence |
| 6.3 | Security vulnerabilities are identified and addressed | GitHub issue tracker; dependency review | partial | No formal vuln disclosure policy | Vuln disclosure policy |
| 6.4 | Public-facing web applications are protected | Chio is not public-facing by default; `chio trust serve` requires Bearer auth (`docs/RECEIPT_QUERY_API.md`) | partial | No WAF integration | WAF for public endpoints |
| 6.5 | Changes to systems and software are managed | Policy hash in every receipt (`crates/core/chio-core-types`) ties call to policy version | strong | No change-management workflow shipped | Change-management process |
| **Req 7** | Restrict access to system components and cardholder data by business need to know | Capability tokens (`crates/core/chio-core-types/src/capability`) scope access to specific tools and servers | strong | None at tool-access layer | Role/permission design |
| 7.2 | Access is defined and assigned appropriately | `ToolGrant` with `scope`, `constraints`, expiry; delegation attenuation in `capability.rs` | strong | None | Role definitions |
| 7.2.5 | Application and system accounts least-privilege | Capability-based least-privilege is the default | strong | None | Grant design per agent |
| 7.3 | Access is managed through access-control systems | Capability issuance via `chio-governance` / `chio-control-plane`; revocation via `revocation_runtime.rs` | strong | None | Access-control ownership |
| **Req 8** | Identify users and authenticate access | DPoP proof-of-possession (`crates/kernel/chio-kernel/src/dpop.rs`) binds Ed25519 keypair to every call | strong | Agent identity is not a human user; mapping needed | Mapping agent-to-operator identity |
| 8.2 | User identification and related accounts are managed | `CapabilityToken.subject` uniquely identifies each agent; `WorkloadIdentity` captures metadata | strong | Account lifecycle docs are deployment-specific | Lifecycle procedures |
| 8.3 | Strong authentication for users is established | Ed25519 keypair per agent; DPoP replay-safe via `action_hash` + nonce | strong | None at agent layer | MFA for human operators |
| 8.4 | MFA is implemented into the CDE | N/A for agents | customer-responsibility | Agents use cryptographic authentication, not MFA | MFA for humans |
| 8.5 | MFA systems are configured | N/A for agents | customer-responsibility | N/A | MFA config |
| 8.6 | Application and system account use is managed | Capability expiry (`not_after`), revocation, and delegation-chain validation | strong | None | Governance cadence |
| **Req 9** | Restrict physical access to cardholder data | Physical controls | out-of-scope | N/A | Data center, clean desk |
| 9.2-9.5 | Physical access controls | N/A | out-of-scope | N/A | Physical security |
| **Req 10** | Log and monitor all access to system components and cardholder data | Every tool invocation produces a signed `ChioReceipt`; batches Merkle-committed via `KernelCheckpoint` | strong | None at tool-call layer | Log aggregation |
| 10.2 | Audit logs are implemented | Receipt store (`crates/kernel/chio-kernel/src/receipt_store.rs`); append-only, sequential | strong | None | Log destination |
| 10.3 | Audit logs are protected from destruction and unauthorized modification | Merkle commitments in `crates/kernel/chio-kernel/src/checkpoint.rs`; inclusion proofs via `build_inclusion_proof` | strong | None | Archive storage |
| 10.4 | Audit logs are reviewed | `chio trust serve` dashboard; receipt query API (`crates/kernel/chio-kernel/src/receipt_query.rs`) | partial | No alerting engine in Chio itself (SIEM export covers this) | Review rota |
| 10.5 | Audit-log history is retained | `RetentionConfig.retention_days` and `max_size_bytes`; archival preserves checkpoint rows | strong | 1-year minimum (PCI) must be set explicitly | Retention configuration |
| 10.6 | Time-synchronization mechanisms are used | Receipts carry Unix timestamps from kernel clock; operator must ensure NTP on host | partial | No NTP enforcement inside Chio | Host time-sync |
| 10.7 | Failures of critical security control systems are detected | Fail-closed pipeline produces deny receipts on error; SIEM adapter (`crates/observability/chio-siem/src/exporter.rs`) streams events | partial | No automatic alert escalation inside Chio | Alert routing |
| **Req 11** | Test security of systems and networks regularly | `cargo test --workspace`, guard integration tests under `crates/kernel/chio-kernel/tests/` | partial | No automated pen-test pipeline | Pen-testing, vuln scanning |
| 11.2 | Wireless access points are identified | N/A | out-of-scope | N/A | Wireless scan |
| 11.3 | External and internal vulnerabilities are identified and addressed | Dependency scanning is deployer-managed | customer-responsibility | N/A | Vuln scanning |
| 11.4 | External and internal penetration testing | Not automated in Chio | customer-responsibility | N/A | Pen-test program |
| 11.5 | Network intrusions and unexpected file changes are detected | Merkle checkpoint verification detects tamper in receipt log; not a NIDS | partial | Not a network IDS | NIDS/FIM |
| 11.6 | Unauthorized changes on payment pages are detected | N/A | out-of-scope | N/A | Page integrity |
| **Req 12** | Support information security with organizational policies and programs | Organizational | out-of-scope | N/A | Infosec policy, training, incident response |
| 12.3 | Risks to the CDE are formally identified | `chio-underwriting` risk tiering can contribute | partial | Not a PCI-specific risk assessment | Risk assessment |
| 12.5 | PCI scope is documented and validated | Chio compliance certificate (`crates/products/chio-cli/src/cert.rs`) supports scope evidence | partial | No PCI-specific scope template | Scope documentation |
| 12.6 | Security awareness education is ongoing | N/A | customer-responsibility | N/A | Training |
| 12.8 | Third-party service providers are managed | Capability scoping restricts which third-party tool servers an agent can reach | partial | Chio does not audit TPSPs | TPSP due diligence |
| 12.10 | Suspected and confirmed security incidents are responded to | Evidence export bundles usable for investigation; revocation for containment | partial | No IR playbook in Chio | IR plan |

---

## Gaps Summary

Items that require additional Chio work or customer effort:

1. **Req 3.4 PAN redaction patterns.** `response_sanitization.rs` supports pattern rules but ships no PAN-specific library. Customer must load a PAN regex set.
2. **Req 3.5 / 3.6 / 4.2.1 FIPS and key management.** The FIPS signing path and HSM backends (Vault Transit, AWS KMS) are tracked in `docs/protocols/COMPLIANCE-ROADMAP.md` section 2 but not yet shipped.
3. **Req 4.2 `min_tls_version`.** The option is planned but not currently enforced inside `KernelConfig`. HTTP termination layer must enforce TLS 1.2 minimum.
4. **Req 6.3 Vulnerability disclosure policy.** Not published in-tree.
5. **Req 10.6 NTP.** Host-level concern; kernel relies on system clock.
6. **Req 11.4 Pen-testing.** Not automated.
7. **Guard evidence redaction.** Listed P1 in the compliance roadmap; the store may persist post-invocation guard snippets that could contain PAN if not configured.

Customer-responsibility items that implementers must not assume Chio provides:

- Req 1 (network security), Req 5 (anti-malware), Req 9 (physical access), Req 12 (policy/training/IR program) in full.

---

## Cross-References

- Capability tokens, grants, delegation: `crates/core/chio-core-types/src/capability`
- Receipt structure and signing: `crates/core/chio-core-types`, `crates/kernel/chio-kernel/src/receipt_support`
- Receipt store and retention: `crates/kernel/chio-kernel/src/receipt_store.rs`, `crates/platform/chio-store-sqlite/src/receipt_store/evidence_retention.rs`
- Checkpoints: `crates/kernel/chio-kernel/src/checkpoint.rs`
- DPoP: `crates/kernel/chio-kernel/src/dpop.rs`
- Revocation: `crates/kernel/chio-kernel/src/revocation_runtime.rs`, `crates/kernel/chio-kernel/src/revocation_store.rs`
- Budgets: `crates/kernel/chio-kernel/src/budget_store.rs`, `crates/economy/chio-metering/src/budget.rs`
- Guards (egress/path/secret-leak/response-sanitization): `crates/guards/chio-guards/src/`
- SIEM export: `crates/observability/chio-siem/src/exporter.rs`
- Compliance certificate: `crates/products/chio-cli/src/cert.rs`
- Receipt query API: `crates/kernel/chio-kernel/src/receipt_query.rs` and `docs/RECEIPT_QUERY_API.md`
- Trust model and key management: `docs/protocols/TRUST-MODEL-AND-KEY-MANAGEMENT.md`
- Unified configuration: `docs/protocols/UNIFIED-CONFIGURATION.md`
