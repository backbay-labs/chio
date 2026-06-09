# Agent 20 Enterprise Compliance Debate

Role: enterprise observability, compliance, and governance buyer
Status: debate output
Confidence: high for enterprise buyer requirements, high for launch-scope critique, moderate for final schema boundaries until implementation owners size the work.

## Buyer Verdict

Chio is not enterprise-ready if the launch proof cannot be exported, retained, held, classified, mapped to controls, reviewed by approvers, investigated after failure, and handed to auditors or regulators as digest-bound evidence.

The strongest counterargument to adding enterprise features is correct: a full GRC suite, SIEM, IAM layer, ticketing product, data catalog, retention engine, or regulator portal would be enterprise bloat and would dilute the launch. Chio should not try to replace Splunk, Datadog, OpenTelemetry collectors, ServiceNow, Jira, Okta, Entra ID, Vanta, Drata, OneTrust, BigID, or a customer's document retention system.

That counterargument does not remove the enterprise requirement. It clarifies it. Chio must produce verifier-grade enterprise evidence projections. Enterprise systems can consume those projections, but the proof semantics stay inside the Transaction Passport, verifier report, evidence graph, risk comptroller report, disclosure profile, and receipt log.

The missing launch capability is therefore an enterprise control evidence overlay:

- SIEM and OTel exports are projections over signed receipts and verifier reports.
- Audit retention and legal hold are signed governance constraints over evidence bundles.
- Policy packs are curated verifier and Chio policy manifests, not a marketplace of vague templates.
- Approval workflows and RBAC are signed authorization evidence that can gate capability issuance and policy elevation.
- Evidence export is a deterministic, redacted, digest-bound bundle.
- SOC 2-style control mapping is a control evidence map, not a certification claim.
- Incident response is a signed incident case over failed gates, affected passports, containment decisions, and remediation evidence.
- Regulator review is a redacted export view with retained provenance and policy justification.
- Data residency and PII classification are verifier inputs, not documentation claims.

## Why The Current Package Is Not Enough

The current launch package is strong on cryptographic proof and risk reconciliation. It is weaker on enterprise operating evidence.

Existing contracts say the Transaction Passport owns the launch verdict, the evidence graph uses typed predicates, external protocols are projections, privacy profiles are semantic gates, the Proof Room renders verifier output, and unsupported copy must be rejected. That is the right foundation.

The enterprise buyer still asks a different set of questions:

1. Can my SOC see every governed action as normalized telemetry without trusting a UI screenshot?
2. Can I prove an audit record was retained for the required period?
3. Can I freeze a transaction, incident, claim, export, or evidence bundle under legal hold?
4. Can my compliance team see which control each verifier gate satisfies?
5. Can high-risk policy changes require approval and separation of duties?
6. Can RBAC be proven as a source of capability issuance, not just asserted in admin UI state?
7. Can I export evidence for an auditor without leaking forbidden PII?
8. Can an incident responder reconstruct a timeline from signed receipts and failed gates?
9. Can a regulator review a redacted bundle and verify that redaction did not alter the underlying evidence?
10. Can I enforce data residency and PII classification before evidence crosses trust boundaries?

If the answer is "the customer can build that from logs," the enterprise story is weak. Plain logs are not proof. They are operational exhaust unless they bind back to Chio receipts, verifier reports, schema IDs, policy hashes, evidence graph nodes, redaction profiles, retention classes, and export manifests.

## Enterprise Additions That Should Ship

### 1. SIEM And OTel Projection

Add `chio.enterprise.telemetry-projection.v1`.

Purpose: produce normalized telemetry events from signed Chio evidence without making the telemetry system authoritative.

Minimum fields:

- `projection_id`
- `transaction_passport_ref`
- `verifier_report_ref`
- `receipt_refs`
- `risk_comptroller_report_ref`
- `commerce_order_ref`
- `actor_ref`
- `subject_ref`
- `tool_ref`
- `decision`
- `policy_id`
- `policy_hash`
- `guard_refs`
- `capability_ref`
- `schema_ids`
- `evidence_graph_node_refs`
- `evidence_graph_edge_refs`
- `risk_verdict`
- `data_classification_ref`
- `residency_ref`
- `retention_class`
- `legal_hold_ref`
- `incident_case_ref`
- `export_format`
- `destination_class`
- `event_digest`
- `signature`

Verifier rule: a telemetry projection passes only if every event digest recomputes from referenced signed artifacts. A SIEM event with no receipt ref, no verifier report ref, or mismatched digest is advisory at best and cannot support launch copy or audit evidence.

This can project to OTel logs, metrics, and traces, and to SIEM-friendly JSON. The schema should avoid promising first-class support for every vendor parser. Chio should guarantee stable evidence fields and digests, not every customer dashboard.

### 2. Audit Retention, Legal Hold, Data Residency, And PII Classification

Add `chio.enterprise.data-governance-report.v1`.

Purpose: bind evidence handling rules to the proof bundle before data leaves Chio custody or a customer's controlled environment.

Minimum fields:

- `report_id`
- `transaction_passport_ref`
- `evidence_bundle_ref`
- `classification_policy_id`
- `pii_classification_summary`
- `field_classification_refs`
- `residency_policy_id`
- `allowed_regions`
- `observed_storage_regions`
- `retention_policy_id`
- `retention_class`
- `retain_until`
- `legal_hold_refs`
- `deletion_blocked`
- `redaction_profile_ref`
- `disclosure_capsule_ref`
- `leakage_ledger_ref`
- `residency_verdict`
- `classification_verdict`
- `retention_verdict`
- `signature`

Verifier rule: export fails if the data governance report is absent for enterprise export, if a field lacks required classification, if observed region falls outside allowed regions, if retention is shorter than policy, or if deletion/export conflicts with legal hold.

This report should bind to the disclosure system. PII classification without selective disclosure and leakage accounting is not enough. A regulator or auditor must see which fields were disclosed, which fields were hidden, which predicates were used, and which policy allowed the result.

### 3. Policy Packs

Add `chio.enterprise.policy-pack-manifest.v1`.

Purpose: package known-good policy combinations for enterprise review and repeatable launch demos.

Minimum fields:

- `policy_pack_id`
- `version`
- `intended_profile`
- `transaction_verifier_policy_ref`
- `chio_policy_refs`
- `risk_policy_refs`
- `privacy_profile_ref`
- `data_governance_policy_ref`
- `approval_workflow_ref`
- `rbac_binding_ref`
- `control_map_ref`
- `required_negative_fixture_refs`
- `claim_allowlist`
- `claim_blocklist`
- `signature`

Initial policy packs should be boring and explicit:

- regulated commerce observer;
- enterprise procurement with human approval;
- marketplace provider admission with risk context;
- low-data developer sandbox;
- incident investigation export.

Policy packs should never imply regulatory compliance by themselves. They are launchable only if the verifier can show which claims they enable, which claims they block, and which negative fixtures prove they fail closed.

### 4. Approval Workflows And RBAC

Add `chio.enterprise.approval-case.v1`.

Purpose: prove that a high-risk action, policy elevation, coverage binding, reserve release, legal hold release, evidence export, or incident closure had the required approval.

Minimum fields:

- `approval_case_id`
- `requested_action`
- `transaction_passport_ref`
- `commerce_order_ref`
- `risk_comptroller_report_ref`
- `policy_pack_ref`
- `required_roles`
- `required_quorum`
- `separation_of_duties_rules`
- `approver_identity_refs`
- `rbac_binding_refs`
- `approval_receipt_refs`
- `denial_receipt_refs`
- `expiry`
- `revocation_epoch`
- `decision`
- `signature`

Add `chio.enterprise.access-decision-report.v1`.

Purpose: bind enterprise roles, groups, or identity-provider assertions to Chio capability issuance without turning Chio into an identity provider.

Minimum fields:

- `access_decision_id`
- `subject_ref`
- `issuer_ref`
- `role_claim_refs`
- `group_claim_refs`
- `capability_issuance_ref`
- `policy_id`
- `allowed_actions`
- `denied_actions`
- `freshness`
- `revocation_epoch`
- `decision`
- `signature`

Verifier rule: approval fails if the approver lacks a fresh role binding, if quorum is not met, if the same person requests and approves an action barred by separation of duties, if the approval expired before execution, or if capability issuance cannot be traced to an access decision.

This is enough for enterprise buyers. A full workflow builder is bloat.

### 5. Evidence Export

Add `chio.enterprise.evidence-export-bundle.v1`.

Purpose: make auditor, regulator, SOC, legal, and customer-review exports deterministic and replayable.

Minimum fields:

- `export_id`
- `purpose`
- `requester_ref`
- `approval_case_ref`
- `transaction_passport_ref`
- `verifier_report_ref`
- `risk_comptroller_report_ref`
- `disclosure_capsule_ref`
- `data_governance_report_ref`
- `control_evidence_map_ref`
- `incident_case_ref`
- `artifact_manifest`
- `redaction_profile_ref`
- `leakage_ledger_ref`
- `legal_hold_refs`
- `retention_class`
- `destination_class`
- `expires_at`
- `bundle_digest`
- `signature`

Verifier rule: an export is valid only if the bundle digest covers exactly the listed artifacts after redaction, redaction follows the privacy profile, retained provenance remains verifiable, and the export purpose is allowed by policy.

This should feed auditors and regulators without exposing raw internal databases or relying on a Proof Room screenshot.

### 6. SOC 2-Style Control Mapping

Add `chio.enterprise.control-evidence-map.v1`.

Purpose: map verifier gates and signed artifacts to control assertions.

Minimum fields:

- `control_map_id`
- `framework_profile`
- `control_refs`
- `claim_refs`
- `verifier_gate_refs`
- `artifact_refs`
- `test_procedure_refs`
- `negative_fixture_refs`
- `coverage_status`
- `unsupported_control_refs`
- `generated_at`
- `signature`

Verifier rule: a control map fails if it references a verifier gate that did not run, an artifact that is missing from the evidence graph, a negative fixture that is absent, or a control assertion outside the policy pack allowlist.

Launch copy can say Chio exports control evidence. It should not say Chio is SOC 2 compliant or replaces an audit.

### 7. Incident Response And Regulator Review

Add `chio.enterprise.incident-review-case.v1`.

Purpose: reconstruct failed gates, affected artifacts, containment actions, approvals, notifications, remediation evidence, and closure conditions.

Minimum fields:

- `incident_case_id`
- `triggering_event_ref`
- `failed_gate_refs`
- `affected_transaction_passport_refs`
- `affected_receipt_refs`
- `affected_subject_refs`
- `data_governance_report_refs`
- `risk_comptroller_report_refs`
- `containment_action_refs`
- `approval_case_refs`
- `notification_refs`
- `regulator_review_bundle_refs`
- `remediation_evidence_refs`
- `closure_verdict`
- `signature`

Add `chio.enterprise.regulator-review-bundle.v1` only as a restricted export profile over `chio.enterprise.evidence-export-bundle.v1`.

Verifier rule: a regulator review bundle fails if redaction cannot be tied to the disclosure profile, if provenance is broken, if legal hold is missing where required, if incident chronology has gaps, or if unsupported claims are included in the review summary.

Regulator review should be a proof package. It should not become a hosted portal in the launch slice.

## Rejected Enterprise Bloat

Reject a native SIEM. Chio should emit digest-bound telemetry projections and stable fields. Customers already have SIEM infrastructure.

Reject a full OTel collector or vendor agent. Chio can emit OTLP-compatible payloads or files, but should not own deployment topology, sampling policy, or customer observability pipelines.

Reject an IAM replacement. Chio should verify identity assertions and bind them to capability issuance. It should not become Okta or Entra ID.

Reject a full RBAC administration console. Role bindings matter only when they affect capability issuance, approval, export, or policy elevation. The launch surface should prove those decisions, not manage every org chart.

Reject a general workflow engine. Chio needs signed approval cases with quorum, freshness, expiry, and separation of duties. It does not need custom form builders, escalations, reminders, and inboxes.

Reject a broad policy-pack marketplace. Enterprise launch needs a few curated policy packs with verifier coverage and negative fixtures. A marketplace adds naming drift and unsupported claims.

Reject a compliance dashboard as proof root. The verifier report remains the source of truth. Dashboards can render, filter, and export.

Reject automatic SOC 2 claims. Chio can map evidence to controls. It cannot certify a customer environment.

Reject a regulator portal. A regulator review bundle is enough for launch. Portals create authentication, retention, access, and uptime obligations that are not core to proving Chio.

Reject a data catalog and DLP suite. Chio needs PII classification refs, data residency verdicts, disclosure policies, and leakage ledgers for Chio evidence. It should not scan an entire enterprise estate.

Reject automatic legal conclusions. Chio can enforce a signed legal hold and export policy. It should not decide legal privilege, statutory adequacy, or regulator sufficiency.

Reject incident case management as a product. Chio should create signed incident review cases and export evidence. Customers will use their own incident tools for assignments and communications.

## Artifact And Schema Implications

All enterprise artifacts that carry public launch claims must follow the existing registry-before-verifier contract:

1. Add schema files under `spec/schemas/enterprise/`.
2. Add schema IDs to `spec/schemas/registry.json`.
3. Refresh `spec/schemas/MANIFEST.sha256`.
4. Extend `scripts/check-chio-schema-registry.sh` for the enterprise schema root.
5. Expose accepted IDs through `KNOWN_SIGNED_ARTIFACT_SCHEMAS` or its generated successor.
6. Add fail-closed unknown-schema tests.
7. Add claim and proof-manifest rows when an artifact supports public copy.
8. Add positive fixtures.
9. Add negative unknown-schema fixtures.
10. Reject unknown schema IDs before reading artifact bodies.

Proposed schema IDs:

| Schema ID | Launch role |
| --- | --- |
| `chio.enterprise.telemetry-projection.v1` | SIEM and OTel projection over receipts and verifier reports. |
| `chio.enterprise.data-governance-report.v1` | PII classification, data residency, retention, legal hold, and redaction verdict. |
| `chio.enterprise.policy-pack-manifest.v1` | Curated enterprise verifier and Chio policy pack. |
| `chio.enterprise.approval-case.v1` | Signed approval workflow evidence. |
| `chio.enterprise.access-decision-report.v1` | RBAC and identity assertion binding to Chio capability issuance. |
| `chio.enterprise.evidence-export-bundle.v1` | Deterministic redacted evidence export. |
| `chio.enterprise.control-evidence-map.v1` | SOC 2-style control evidence mapping. |
| `chio.enterprise.incident-review-case.v1` | Failed gate, containment, remediation, and closure evidence. |
| `chio.enterprise.regulator-review-bundle.v1` | Restricted regulator review export view. |

Transaction Passport should not be displaced. It should gain optional enterprise evidence nodes:

- `enterprise.telemetry_projection`
- `enterprise.data_governance_report`
- `enterprise.policy_pack`
- `enterprise.approval_case`
- `enterprise.access_decision`
- `enterprise.evidence_export_bundle`
- `enterprise.control_evidence_map`
- `enterprise.incident_review_case`
- `enterprise.regulator_review_bundle`

First slice should avoid new evidence graph predicates. Use existing predicates:

- `binds` for approval, access, data governance, retention, and legal hold refs;
- `projects-to` for SIEM, OTel, regulator, and control-map projections;
- `reconciles` for control evidence and incident closure;
- `discloses` and `redacts` for export and regulator review;
- `authorizes` for RBAC-driven capability issuance and approval cases.

If later slices add `classifies`, `retains`, `exports`, `approves`, or `controls`, those predicates must be registry-backed and fail closed when unknown.

## First Slice

Build one enterprise evidence path for one risk-backed autonomous commerce fixture.

Scope:

1. Start from a valid Transaction Passport that binds commerce order context and `chio.risk.comptroller-report.v1`.
2. Add `chio.enterprise.data-governance-report.v1` with PII classification, allowed region, observed region, retention class, legal hold status, redaction profile, disclosure capsule ref, and leakage ledger ref.
3. Add `chio.enterprise.evidence-export-bundle.v1` that exports the passport, verifier report, risk report, disclosure capsule, leakage ledger, and data governance report with a recomputable bundle digest.
4. Add `chio.enterprise.telemetry-projection.v1` for the same fixture with one allow event, one denied guard event, and one risk verifier event, each digest-bound to signed artifacts.
5. Add `chio.enterprise.control-evidence-map.v1` that maps launch gates to a small internal control profile:
   - governed action authorization;
   - policy enforcement;
   - audit evidence retention;
   - data minimization;
   - access approval for sensitive export;
   - incident reconstruction for failed verification.
6. Add `chio.enterprise.approval-case.v1` only for the evidence export decision in the first slice. Broader policy elevation and reserve release approvals can follow after the base export path verifies.
7. Wire CLI verification so `chio proof verify` emits enterprise sections but still makes `chio.transaction.verifier-report.v1` the root launch verdict.
8. Make the Proof Room render the enterprise sections from verifier output only.

Pass condition:

- a skeptical enterprise reviewer can run one verifier command and see that the exported evidence, telemetry projection, data governance verdict, approval case, and control map all bind back to the same Transaction Passport and risk comptroller report.

Non-goal for first slice:

- no SIEM product;
- no workflow builder;
- no IAM admin UI;
- no regulator portal;
- no SOC 2 claim;
- no broad policy-pack marketplace;
- no enterprise data catalog.

## Negative Fixtures

Add these as launch-grade negative controls:

| Fixture | Failure proved |
| --- | --- |
| `enterprise_siem_event_without_receipt_fails` | Telemetry cannot support proof without signed receipt refs. |
| `enterprise_otel_digest_mismatch_fails` | Projected telemetry digest must recompute from source artifacts. |
| `enterprise_telemetry_wrong_passport_fails` | Event tied to one passport cannot be projected under another passport. |
| `enterprise_audit_retention_shorter_than_policy_fails` | Export cannot claim audit retention below policy. |
| `enterprise_legal_hold_deletion_fails` | Legal hold blocks deletion, destructive export, or closure actions. |
| `enterprise_legal_hold_missing_for_incident_fails` | Incident evidence that requires hold cannot be exported as disposable evidence. |
| `enterprise_policy_pack_unknown_schema_fails` | Policy pack cannot reference unregistered signed artifacts. |
| `enterprise_policy_pack_claim_blocklist_fails` | Policy pack cannot enable a blocked public claim. |
| `enterprise_approval_missing_quorum_fails` | Sensitive action cannot proceed without required approver quorum. |
| `enterprise_approval_expired_before_action_fails` | Approval freshness must cover execution time. |
| `enterprise_approval_separation_of_duties_fails` | Same identity cannot request and approve when policy bars it. |
| `enterprise_rbac_stale_role_claim_fails` | Capability issuance cannot depend on stale role evidence. |
| `enterprise_rbac_wrong_issuer_fails` | Untrusted role issuer cannot authorize capability issuance. |
| `enterprise_export_overdiscloses_pii_fails` | Evidence export must obey privacy profile and leakage ledger. |
| `enterprise_export_bundle_digest_mismatch_fails` | Export manifest must exactly match redacted artifact bytes. |
| `enterprise_export_without_approval_fails` | Sensitive export requires a signed approval case. |
| `enterprise_control_map_missing_gate_fails` | Control evidence cannot cite a verifier gate that did not run. |
| `enterprise_control_map_unsupported_claim_fails` | Control map cannot turn unsupported verifier claims into control coverage. |
| `enterprise_incident_timeline_gap_fails` | Incident case must reconstruct failed gate chronology. |
| `enterprise_incident_closure_without_remediation_fails` | Closure requires remediation evidence and verifier-compatible closure verdict. |
| `enterprise_regulator_bundle_provenance_gap_fails` | Regulator bundle must preserve source artifact provenance after redaction. |
| `enterprise_regulator_bundle_unredacted_pii_fails` | Regulator review cannot disclose forbidden PII fields. |
| `enterprise_data_residency_region_mismatch_fails` | Export or storage region outside policy must fail. |
| `enterprise_pii_classification_missing_field_fails` | Required evidence fields cannot be exported without classification. |
| `enterprise_retention_and_disclosure_policy_conflict_fails` | Export cannot proceed when retention, legal hold, and disclosure policies conflict without an explicit signed override. |

## Debate Close

Enterprise compliance is not a side quest. It is the difference between "cool cryptographic demo" and "deployable control plane evidence." The launch package can stay lean if Chio treats enterprise features as signed projections and verifier gates.

The enterprise buyer does not need Chio to become a compliance platform. The buyer needs Chio to make every governed action exportable, retainable, reviewable, classifiable, approvable, investigable, and mappable to controls without breaking the core proof model.

The minimum defensible launch claim is:

Chio can produce digest-bound enterprise evidence for governed autonomous commerce, including telemetry projection, redacted export, retention and legal hold status, PII classification, data residency verdict, approval evidence, access-decision evidence, control mapping, and incident-review evidence, all rooted in the Transaction Passport verifier report.

Anything stronger needs more artifacts and more negative fixtures.
