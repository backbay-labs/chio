//! Trust-boundary fuzz target for `chio-underwriting` policy and decision inputs.

#![no_main]

use chio_fuzz::canonical_json::canonical_json_mutate;
use chio_underwriting::{
    build_underwriting_decision_artifact, compute_marketplace_credit_limit,
    evaluate_underwriting_policy_input, price_premium, LookbackWindow,
    MarketplaceCreditLimitRequest, PremiumInputs, UnderwritingAppealCreateRequest,
    UnderwritingAppealResolveRequest, UnderwritingDecisionArtifact, UnderwritingDecisionListReport,
    UnderwritingDecisionPolicy, UnderwritingDecisionQuery, UnderwritingPolicyInput,
    UnderwritingPolicyInputQuery, UnderwritingSimulationReport, UnderwritingSimulationRequest,
};
use libfuzzer_sys::{fuzz_mutator, fuzz_target};

fuzz_target!(|data: &[u8]| {
    if let Ok(query) = serde_json::from_slice::<UnderwritingPolicyInputQuery>(data) {
        let normalized = query.normalized();
        let _ = normalized.validate();
    }

    if let Ok(query) = serde_json::from_slice::<UnderwritingDecisionQuery>(data) {
        let _ = query.normalized();
    }

    if let Ok(policy) = serde_json::from_slice::<UnderwritingDecisionPolicy>(data) {
        let _ = policy.validate();
    }

    if let Ok(request) = serde_json::from_slice::<UnderwritingSimulationRequest>(data) {
        let _ = request.query.normalized().validate();
        let _ = request.policy.validate();
    }

    if let Ok(input) = serde_json::from_slice::<UnderwritingPolicyInput>(data) {
        let policy = match serde_json::from_slice::<UnderwritingDecisionPolicy>(data) {
            Ok(policy) if policy.validate().is_ok() => policy,
            _ => UnderwritingDecisionPolicy::default(),
        };

        if let Ok(report) = evaluate_underwriting_policy_input(input, &policy) {
            let issued_at = report.generated_at;
            let _ = serde_json::to_vec(&report);
            let _ = build_underwriting_decision_artifact(report, issued_at, None, None);
        }
    }

    if let Ok(artifact) = serde_json::from_slice::<UnderwritingDecisionArtifact>(data) {
        let _ = serde_json::to_vec(&artifact);
    }

    if let Ok(report) = serde_json::from_slice::<UnderwritingDecisionListReport>(data) {
        let _ = serde_json::to_vec(&report);
    }

    if let Ok(report) = serde_json::from_slice::<UnderwritingSimulationReport>(data) {
        let _ = serde_json::to_vec(&report);
    }

    if let Ok(request) = serde_json::from_slice::<UnderwritingAppealCreateRequest>(data) {
        let _ = serde_json::to_vec(&request);
    }

    if let Ok(request) = serde_json::from_slice::<UnderwritingAppealResolveRequest>(data) {
        let _ = serde_json::to_vec(&request);
    }

    if let Ok(request) = serde_json::from_slice::<MarketplaceCreditLimitRequest>(data) {
        let _ = compute_marketplace_credit_limit(&request);
    }

    if let Ok(inputs) = serde_json::from_slice::<PremiumInputs>(data) {
        let _ = inputs.validate();
        let window = LookbackWindow { since: 0, until: 0 };
        let _ = price_premium("fuzz-agent", "fuzz-scope", window, &inputs);
    }
});

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    canonical_json_mutate(data, size, max_size, seed)
});
