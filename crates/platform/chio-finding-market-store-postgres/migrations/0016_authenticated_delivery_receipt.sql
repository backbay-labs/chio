DO $migration$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM (
            SELECT aggregate_kind, event_kind, 'chio.finding.delivery.v1'::TEXT AS artifact_schema
            FROM chio_finding_market_aggregate_events
            UNION ALL
            SELECT aggregate_kind, event_kind, artifact_schema
            FROM chio_finding_market_domain_projections
            UNION ALL
            SELECT aggregate_kind, event_kind, artifact_schema
            FROM chio_finding_market_replication_events
            UNION ALL
            SELECT aggregate_kind, event_kind, artifact_schema
            FROM chio_finding_market_replication_outbox
        ) AS retained_delivery
        WHERE retained_delivery.aggregate_kind = 'delivery'
          AND retained_delivery.event_kind = 'delivery.accepted'
          AND retained_delivery.artifact_schema = 'chio.finding.delivery.v1'
    ) THEN
        RAISE EXCEPTION 'unauthenticated hosted delivery state requires manual quarantine';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM chio_finding_market_domain_event_contracts
        WHERE aggregate_kind = 'delivery'
          AND event_kind = 'delivery.accepted'
          AND artifact_schema = 'chio.finding.delivery.v1'
          AND signed_artifact = FALSE
    ) THEN
        RAISE EXCEPTION 'hosted delivery event contract is missing or drifted';
    END IF;
END
$migration$;

ALTER TABLE chio_finding_market_domain_event_contracts
    DISABLE TRIGGER chio_finding_market_domain_event_contracts_immutable;

DELETE FROM chio_finding_market_domain_event_contracts
WHERE aggregate_kind = 'delivery'
  AND event_kind = 'delivery.accepted'
  AND artifact_schema = 'chio.finding.delivery.v1'
  AND signed_artifact = FALSE;

INSERT INTO chio_finding_market_domain_event_contracts (
    aggregate_kind, event_kind, artifact_schema, signed_artifact
) VALUES (
    'delivery', 'delivery.accepted',
    'chio.finding.hosted-authenticated-delivery.v1', TRUE
);

ALTER TABLE chio_finding_market_domain_event_contracts
    ENABLE TRIGGER chio_finding_market_domain_event_contracts_immutable;
