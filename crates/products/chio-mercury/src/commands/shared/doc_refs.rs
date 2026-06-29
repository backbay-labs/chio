use super::super::MercuryAssuranceReviewerPopulation;
use super::types::*;

pub(crate) fn reviewer_doc_refs() -> MercuryQualificationDocRefs {
    MercuryQualificationDocRefs {
        bridge_file: "docs/mercury/SUPERVISED_LIVE_BRIDGE.md".to_string(),
        operating_model_file: "docs/mercury/SUPERVISED_LIVE_OPERATING_MODEL.md".to_string(),
        operations_runbook_file: "docs/mercury/SUPERVISED_LIVE_OPERATIONS_RUNBOOK.md".to_string(),
        qualification_package_file: "docs/mercury/SUPERVISED_LIVE_QUALIFICATION_PACKAGE.md"
            .to_string(),
        decision_record_file: "docs/mercury/SUPERVISED_LIVE_DECISION_RECORD.md".to_string(),
    }
}

pub(crate) fn downstream_review_doc_refs() -> MercuryDownstreamReviewDocRefs {
    MercuryDownstreamReviewDocRefs {
        distribution_file: "docs/mercury/DOWNSTREAM_REVIEW_DISTRIBUTION.md".to_string(),
        operations_file: "docs/mercury/DOWNSTREAM_REVIEW_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/DOWNSTREAM_REVIEW_VALIDATION_PACKAGE.md".to_string(),
        decision_record_file: "docs/mercury/DOWNSTREAM_REVIEW_DECISION_RECORD.md".to_string(),
    }
}

pub(crate) fn governance_workbench_doc_refs() -> MercuryGovernanceWorkbenchDocRefs {
    MercuryGovernanceWorkbenchDocRefs {
        workbench_file: "docs/mercury/GOVERNANCE_WORKBENCH.md".to_string(),
        operations_file: "docs/mercury/GOVERNANCE_WORKBENCH_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/GOVERNANCE_WORKBENCH_VALIDATION_PACKAGE.md"
            .to_string(),
        decision_record_file: "docs/mercury/GOVERNANCE_WORKBENCH_DECISION_RECORD.md".to_string(),
    }
}

pub(crate) fn assurance_suite_doc_refs() -> MercuryAssuranceSuiteDocRefs {
    MercuryAssuranceSuiteDocRefs {
        suite_file: "docs/mercury/ASSURANCE_SUITE.md".to_string(),
        operations_file: "docs/mercury/ASSURANCE_SUITE_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/ASSURANCE_SUITE_VALIDATION_PACKAGE.md".to_string(),
        decision_record_file: "docs/mercury/ASSURANCE_SUITE_DECISION_RECORD.md".to_string(),
    }
}

pub(crate) fn embedded_oem_doc_refs() -> MercuryEmbeddedOemDocRefs {
    MercuryEmbeddedOemDocRefs {
        oem_file: "docs/mercury/EMBEDDED_OEM.md".to_string(),
        operations_file: "docs/mercury/EMBEDDED_OEM_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/EMBEDDED_OEM_VALIDATION_PACKAGE.md".to_string(),
        decision_record_file: "docs/mercury/EMBEDDED_OEM_DECISION_RECORD.md".to_string(),
    }
}

pub(crate) fn trust_network_doc_refs() -> MercuryTrustNetworkDocRefs {
    MercuryTrustNetworkDocRefs {
        trust_network_file: "docs/mercury/TRUST_NETWORK.md".to_string(),
        operations_file: "docs/mercury/TRUST_NETWORK_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/TRUST_NETWORK_VALIDATION_PACKAGE.md".to_string(),
        decision_record_file: "docs/mercury/TRUST_NETWORK_DECISION_RECORD.md".to_string(),
    }
}

pub(crate) fn release_readiness_doc_refs() -> MercuryReleaseReadinessDocRefs {
    MercuryReleaseReadinessDocRefs {
        release_readiness_file: "docs/mercury/RELEASE_READINESS.md".to_string(),
        operations_file: "docs/mercury/RELEASE_READINESS_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/RELEASE_READINESS_VALIDATION_PACKAGE.md".to_string(),
        decision_record_file: "docs/mercury/RELEASE_READINESS_DECISION_RECORD.md".to_string(),
    }
}

pub(crate) fn controlled_adoption_doc_refs() -> MercuryControlledAdoptionDocRefs {
    MercuryControlledAdoptionDocRefs {
        controlled_adoption_file: "docs/mercury/CONTROLLED_ADOPTION.md".to_string(),
        operations_file: "docs/mercury/CONTROLLED_ADOPTION_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/CONTROLLED_ADOPTION_VALIDATION_PACKAGE.md"
            .to_string(),
        decision_record_file: "docs/mercury/CONTROLLED_ADOPTION_DECISION_RECORD.md".to_string(),
    }
}

pub(crate) fn reference_distribution_doc_refs() -> MercuryReferenceDistributionDocRefs {
    MercuryReferenceDistributionDocRefs {
        reference_distribution_file: "docs/mercury/REFERENCE_DISTRIBUTION.md".to_string(),
        operations_file: "docs/mercury/REFERENCE_DISTRIBUTION_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/REFERENCE_DISTRIBUTION_VALIDATION_PACKAGE.md"
            .to_string(),
        decision_record_file: "docs/mercury/REFERENCE_DISTRIBUTION_DECISION_RECORD.md".to_string(),
    }
}

pub(crate) fn broader_distribution_doc_refs() -> MercuryBroaderDistributionDocRefs {
    MercuryBroaderDistributionDocRefs {
        broader_distribution_file: "docs/mercury/BROADER_DISTRIBUTION.md".to_string(),
        operations_file: "docs/mercury/BROADER_DISTRIBUTION_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/BROADER_DISTRIBUTION_VALIDATION_PACKAGE.md"
            .to_string(),
        decision_record_file: "docs/mercury/BROADER_DISTRIBUTION_DECISION_RECORD.md".to_string(),
    }
}

pub(crate) fn assurance_suite_population_configs() -> [MercuryAssurancePopulationConfig<'static>; 3]
{
    [
        MercuryAssurancePopulationConfig {
            reviewer_population: MercuryAssuranceReviewerPopulation::InternalReview,
            dir_name: "internal-review",
            audience: "internal-review",
            redaction_profile: "internal-review-default",
            retained_artifact_policy: "retain-all-qualified-review-artifacts",
            intended_use:
                "Internal review over the same qualified workflow evidence without lossy redaction.",
            verifier_equivalent: true,
            investigation_focus: &[
                "release approval continuity",
                "rollback readiness and supervisory coverage",
            ],
        },
        MercuryAssurancePopulationConfig {
            reviewer_population: MercuryAssuranceReviewerPopulation::AuditorReview,
            dir_name: "auditor-review",
            audience: "auditor-review",
            redaction_profile: "auditor-review-default",
            retained_artifact_policy: "retain-qualified-audit-artifacts-and-source-links",
            intended_use:
                "Auditor review over the same governed workflow with retained provenance and checkpoint continuity.",
            verifier_equivalent: true,
            investigation_focus: &[
                "checkpoint and retained-artifact continuity",
                "control-state and exception routing evidence",
            ],
        },
        MercuryAssurancePopulationConfig {
            reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview,
            dir_name: "counterparty-review",
            audience: "counterparty-review",
            redaction_profile: "counterparty-review-default",
            retained_artifact_policy: "retain-bounded-redacted-review-artifacts",
            intended_use:
                "Counterparty review over a bounded redacted export without widening into a generic portal.",
            verifier_equivalent: false,
            investigation_focus: &[
                "bounded disclosure and inquiry continuity",
                "release and rollback reconstruction from redacted evidence",
            ],
        },
    ]
}
