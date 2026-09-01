ALTER TABLE chio_finding_market_domain_projections
    ADD COLUMN subject_finding_id TEXT;

DROP TRIGGER chio_finding_market_domain_projections_immutable
    ON chio_finding_market_domain_projections;

UPDATE chio_finding_market_domain_projections
SET subject_finding_id = convert_from(payload_json, 'UTF8')::jsonb
    #>> '{body,finding_id}'
WHERE aggregate_kind IN ('retraction', 'enforcement');

ALTER TABLE chio_finding_market_domain_projections
    ADD CONSTRAINT chio_finding_market_domain_projection_status_subject_v1 CHECK (
        (
            aggregate_kind IN ('retraction', 'enforcement')
            AND octet_length(subject_finding_id) = 64
            AND subject_finding_id !~ '[^0-9a-f]'
        )
        OR (
            aggregate_kind NOT IN ('retraction', 'enforcement')
            AND subject_finding_id IS NULL
        )
    );

CREATE FUNCTION chio_finding_market_derive_status_subject()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $function$
BEGIN
    IF NEW.aggregate_kind IN ('retraction', 'enforcement') THEN
        NEW.subject_finding_id := convert_from(NEW.payload_json, 'UTF8')::jsonb
            #>> '{body,finding_id}';
    ELSE
        NEW.subject_finding_id := NULL;
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER chio_finding_market_domain_projections_derive_status_subject
BEFORE INSERT OR UPDATE ON chio_finding_market_domain_projections
FOR EACH ROW EXECUTE FUNCTION chio_finding_market_derive_status_subject();

CREATE TRIGGER chio_finding_market_domain_projections_immutable
BEFORE UPDATE OR DELETE ON chio_finding_market_domain_projections
FOR EACH ROW EXECUTE FUNCTION chio_finding_market_guard_domain_projection_mutation();

CREATE INDEX chio_finding_market_domain_projection_status_subject_v1
ON chio_finding_market_domain_projections (
    tenant_id, subject_finding_id, aggregate_kind, aggregate_id
)
WHERE subject_finding_id IS NOT NULL;

REVOKE ALL ON FUNCTION chio_finding_market_derive_status_subject() FROM PUBLIC;
