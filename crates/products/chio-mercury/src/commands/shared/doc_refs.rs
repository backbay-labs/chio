use super::super::MercuryAssuranceReviewerPopulation;
use super::types::*;

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
