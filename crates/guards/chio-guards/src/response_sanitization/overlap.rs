use std::collections::HashMap;

use super::formatting::preview_redacted;
use super::types::{Redaction, RedactionStrategy, SensitiveCategory, SensitiveDataFinding, Span};

// ---------------------------------------------------------------------------
// Overlap resolution: longest-match-wins, with strategy-rank tiebreaker.
// ---------------------------------------------------------------------------

fn strategy_rank(s: &RedactionStrategy) -> u8 {
    match s {
        RedactionStrategy::Keep => 0,
        RedactionStrategy::Partial => 1,
        RedactionStrategy::TypeLabel => 2,
        RedactionStrategy::Fingerprint => 3,
        RedactionStrategy::Tokenize => 4,
        RedactionStrategy::Mask => 5,
        RedactionStrategy::Drop => 6,
    }
}

pub(super) type ResolvedSpan = (Span, RedactionStrategy, SensitiveCategory, String, String);

fn redaction_strategy_for_finding(
    finding: &SensitiveDataFinding,
    defaults: &HashMap<SensitiveCategory, RedactionStrategy>,
) -> RedactionStrategy {
    if is_mandatory_redaction_finding(finding) {
        return non_keep_redaction_strategy(&finding.recommended_action);
    }

    match &finding.recommended_action {
        RedactionStrategy::Keep => RedactionStrategy::Keep,
        RedactionStrategy::Drop | RedactionStrategy::Fingerprint | RedactionStrategy::Tokenize => {
            finding.recommended_action.clone()
        }
        _ => defaults
            .get(&finding.category)
            .cloned()
            .unwrap_or_else(|| finding.recommended_action.clone()),
    }
}

fn is_mandatory_redaction_finding(finding: &SensitiveDataFinding) -> bool {
    finding.detector == "denylist"
        || finding.detector == "fail_closed"
        || finding.id.starts_with("denylist_")
        || finding.id == "redaction_unavailable_fail_closed"
}

fn non_keep_redaction_strategy(strategy: &RedactionStrategy) -> RedactionStrategy {
    match strategy {
        RedactionStrategy::Keep => RedactionStrategy::Mask,
        _ => strategy.clone(),
    }
}

pub(super) fn resolve_overlaps(
    findings: &[SensitiveDataFinding],
    defaults: &HashMap<SensitiveCategory, RedactionStrategy>,
) -> Vec<ResolvedSpan> {
    let mut spans: Vec<ResolvedSpan> = Vec::with_capacity(findings.len());
    for f in findings {
        let strategy = redaction_strategy_for_finding(f, defaults);
        spans.push((
            f.span,
            strategy,
            f.category.clone(),
            f.data_type.clone(),
            f.id.clone(),
        ));
    }

    spans.sort_by(|a, b| {
        a.0.start
            .cmp(&b.0.start)
            .then_with(|| b.0.end.cmp(&a.0.end))
    });

    let mut merged: Vec<ResolvedSpan> = Vec::new();
    for current in spans {
        if let Some(last) = merged.last_mut() {
            if current.0.start < last.0.end {
                let new_end = last.0.end.max(current.0.end);
                last.0.end = new_end;
                if strategy_rank(&current.1) > strategy_rank(&last.1) {
                    last.1 = current.1;
                    last.2 = current.2;
                    last.3 = current.3;
                    last.4 = current.4;
                }
                continue;
            }
        }
        merged.push(current);
    }
    merged
}

pub(super) fn detect_service_account_object(
    map: &serde_json::Map<String, serde_json::Value>,
) -> Option<(SensitiveDataFinding, Redaction)> {
    let value = map.get("type")?.as_str()?;
    if !value.eq_ignore_ascii_case("service_account") {
        return None;
    }

    let span = Span { start: 0, end: 0 };
    let finding = SensitiveDataFinding {
        id: "secret_gcp_service_account".to_string(),
        category: SensitiveCategory::Secret,
        data_type: "gcp_service_account_json".to_string(),
        confidence: 0.97,
        span,
        preview: preview_redacted(value),
        detector: "object".to_string(),
        recommended_action: RedactionStrategy::Drop,
    };
    let redaction = Redaction {
        finding_id: finding.id.clone(),
        strategy: RedactionStrategy::Drop,
        original_span: span,
        replacement: String::new(),
    };
    Some((finding, redaction))
}
