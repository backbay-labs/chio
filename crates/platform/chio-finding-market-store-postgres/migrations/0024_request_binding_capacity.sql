-- Bound the request admissions one tenant retains. A binding outlives the
-- proof that created it so an interrupted mutation can be retried with a
-- fresh one, which means the live-proof ceiling does not bound it. Without a
-- ceiling of its own, a credential holder rotates idempotency keys as nonce
-- slots expire and retains a row per admitted request until its capability
-- expires, which no admission path refuses.

ALTER TABLE chio_finding_market_dpop_admission_state
    ADD COLUMN IF NOT EXISTS live_request_bindings BIGINT NOT NULL DEFAULT 0
        CHECK (live_request_bindings >= 0);

CREATE FUNCTION chio_finding_market_maintain_request_bindings()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    subject TEXT;
    delta BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        subject := NEW.tenant_id;
        delta := 1;
    ELSE
        subject := OLD.tenant_id;
        delta := -1;
    END IF;
    INSERT INTO public.chio_finding_market_dpop_admission_state
        (tenant_id, live_nonces, last_swept_at)
    VALUES (subject, 0, 0)
    ON CONFLICT (tenant_id) DO NOTHING;
    -- Clamped for the same reason as the nonce counter: the expiry sweep
    -- re-derives it from an exact count, and raising here would fail the
    -- statement that repairs the skew.
    UPDATE public.chio_finding_market_dpop_admission_state
    SET live_request_bindings = GREATEST(live_request_bindings + delta, 0)
    WHERE tenant_id = subject;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END
$function$;

REVOKE ALL ON FUNCTION chio_finding_market_maintain_request_bindings() FROM PUBLIC;

CREATE TRIGGER chio_finding_market_request_binding_accounting
AFTER INSERT OR DELETE ON chio_finding_market_capability_request_admissions
FOR EACH ROW
EXECUTE FUNCTION chio_finding_market_maintain_request_bindings();

-- Derive the counter from the bindings that already exist.
INSERT INTO chio_finding_market_dpop_admission_state (tenant_id, live_nonces, last_swept_at)
SELECT DISTINCT tenant_id, 0, 0
FROM chio_finding_market_capability_request_admissions
ON CONFLICT (tenant_id) DO NOTHING;

UPDATE chio_finding_market_dpop_admission_state AS state
SET live_request_bindings = (
    SELECT COUNT(*)
    FROM chio_finding_market_capability_request_admissions AS admissions
    WHERE admissions.tenant_id = state.tenant_id
);
