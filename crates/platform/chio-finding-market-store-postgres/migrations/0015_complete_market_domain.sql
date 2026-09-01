INSERT INTO chio_finding_market_domain_event_contracts (
    aggregate_kind, event_kind, artifact_schema, signed_artifact
) VALUES
    (
        'participation', 'participation.admitted',
        'chio.finding.claim-allocation.v1', TRUE
    ),
    (
        'reveal', 'reveal.committed',
        'chio.finding.purchase-result.v1', TRUE
    ),
    (
        'purchase_terminal', 'purchase.settled',
        'chio.finding.purchase-result.v1', TRUE
    ),
    (
        'verified_fix', 'verified_fix.submitted',
        'chio.finding.verified-fix-submission.v1', TRUE
    ),
    (
        'retraction', 'retraction.voluntary',
        'chio.finding.voluntary-retraction.v1', TRUE
    ),
    (
        'liability', 'liability.assessed',
        'chio.finding.liability.v1', TRUE
    ),
    (
        'penalty', 'penalty.assessed',
        'chio.registry.market-penalty.v1', TRUE
    ),
    (
        'settlement', 'settlement.terminal',
        'chio.commerce.settlement-packet.v1', FALSE
    );
