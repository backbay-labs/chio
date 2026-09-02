-- Maintain the spend and nonce accumulators inside the database so every
-- writer keeps them correct, including a replica still running the previous
-- release during a rolling update. The deployment applies migrations before
-- the new ReplicaSet replaces the old one, so an accumulator that only the
-- new binary maintained would miss the old binary's reservations and nonce
-- writes for the length of that window.

CREATE FUNCTION chio_finding_market_maintain_spend_period()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    charged BIGINT := 0;
    consumed BIGINT;
    maximum BIGINT;
    period public.chio_finding_market_spend_reservations%ROWTYPE;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IN ('reserved', 'committed') THEN
            charged := NEW.units;
        END IF;
    ELSIF TG_OP = 'DELETE' THEN
        IF OLD.state IN ('reserved', 'committed') THEN
            charged := -OLD.units;
        END IF;
    ELSE
        -- A reservation records what it charged, so only its state moves
        -- after it is written. Allowing its units to change would let a
        -- writer enlarge a reservation that is already charged without any
        -- state transition to account for, leaving the accumulator, and the
        -- ceiling enforced against it, holding the original amount.
        IF NEW.tenant_id <> OLD.tenant_id
           OR NEW.reservation_id <> OLD.reservation_id
           OR NEW.billing_period <> OLD.billing_period
           OR NEW.units <> OLD.units THEN
            RAISE EXCEPTION 'spend reservation identity and units are immutable'
                USING ERRCODE = '23000';
        END IF;
        IF OLD.state IN ('reserved', 'committed') AND NEW.state = 'released' THEN
            charged := -OLD.units;
        ELSIF OLD.state = 'released' AND NEW.state IN ('reserved', 'committed') THEN
            charged := NEW.units;
        END IF;
    END IF;
    IF charged = 0 THEN
        RETURN COALESCE(NEW, OLD);
    END IF;
    period := COALESCE(NEW, OLD);
    INSERT INTO public.chio_finding_market_spend_periods
        (tenant_id, billing_period, consumed_units, updated_at)
    VALUES (period.tenant_id, period.billing_period, 0, period.updated_at)
    ON CONFLICT (tenant_id, billing_period) DO NOTHING;
    SELECT consumed_units INTO consumed
    FROM public.chio_finding_market_spend_periods
    WHERE tenant_id = period.tenant_id
      AND billing_period = period.billing_period
    FOR UPDATE;
    IF consumed IS NULL THEN
        RAISE EXCEPTION 'spend period accumulator is not readable in this tenant context'
            USING ERRCODE = '42501';
    END IF;
    consumed := consumed + charged;
    -- Clamping a negative result at zero would discard the skew that
    -- produced it: the accumulator would then undercount the reservations
    -- still charged, and a later insert would pass a ceiling that actual
    -- reserved and committed spend already exceeds. Nothing re-derives this
    -- accumulator at runtime, so an underflow is unrecoverable accounting
    -- and denies rather than becoming authoritative.
    IF consumed < 0 THEN
        RAISE EXCEPTION 'spend period accumulator underflowed for tenant %', period.tenant_id
            USING ERRCODE = '23000';
    END IF;
    UPDATE public.chio_finding_market_spend_periods
    SET consumed_units = consumed,
        updated_at = period.updated_at
    WHERE tenant_id = period.tenant_id
      AND billing_period = period.billing_period;
    IF charged > 0 THEN
        SELECT max_monthly_spend_units INTO maximum
        FROM public.chio_finding_market_tenants
        WHERE tenant_id = period.tenant_id;
        IF maximum IS NULL OR consumed > maximum THEN
            RAISE EXCEPTION 'tenant monthly spend ceiling exceeded'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'chio_finding_market_spend_period_ceiling_v1';
        END IF;
    END IF;
    RETURN COALESCE(NEW, OLD);
END
$function$;

REVOKE ALL ON FUNCTION chio_finding_market_maintain_spend_period() FROM PUBLIC;

CREATE TRIGGER chio_finding_market_spend_period_accounting
AFTER INSERT OR UPDATE OR DELETE ON chio_finding_market_spend_reservations
FOR EACH ROW
EXECUTE FUNCTION chio_finding_market_maintain_spend_period();

CREATE FUNCTION chio_finding_market_maintain_dpop_live_nonces()
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
    -- This counter clamps where the spend accumulator denies, because the
    -- expiry sweep deletes a tenant's stale nonces and then resets this
    -- counter from an exact count. Raising here would fail the statement
    -- that repairs the skew; an undercount survives only until that sweep.
    UPDATE public.chio_finding_market_dpop_admission_state
    SET live_nonces = GREATEST(live_nonces + delta, 0)
    WHERE tenant_id = subject;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END
$function$;

REVOKE ALL ON FUNCTION chio_finding_market_maintain_dpop_live_nonces() FROM PUBLIC;

CREATE TRIGGER chio_finding_market_dpop_nonce_accounting
AFTER INSERT OR DELETE ON chio_finding_market_dpop_nonces
FOR EACH ROW
EXECUTE FUNCTION chio_finding_market_maintain_dpop_live_nonces();

-- Re-derive both accumulators from their source tables. Any skew a writer
-- introduced between the accumulator's introduction and this trigger is
-- corrected here, and both are trigger-maintained from this point on.
INSERT INTO chio_finding_market_spend_periods (tenant_id, billing_period, consumed_units, updated_at)
SELECT
    tenant_id,
    billing_period,
    SUM(units),
    FLOOR(EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::BIGINT
FROM chio_finding_market_spend_reservations
WHERE state IN ('reserved', 'committed')
GROUP BY tenant_id, billing_period
ON CONFLICT (tenant_id, billing_period) DO UPDATE
SET consumed_units = EXCLUDED.consumed_units,
    updated_at = EXCLUDED.updated_at;

UPDATE chio_finding_market_spend_periods AS periods
SET consumed_units = 0
WHERE NOT EXISTS (
    SELECT 1
    FROM chio_finding_market_spend_reservations AS reservations
    WHERE reservations.tenant_id = periods.tenant_id
      AND reservations.billing_period = periods.billing_period
      AND reservations.state IN ('reserved', 'committed')
);

INSERT INTO chio_finding_market_dpop_admission_state (tenant_id, live_nonces, last_swept_at)
SELECT tenant_id, COUNT(*), 0
FROM chio_finding_market_dpop_nonces
GROUP BY tenant_id
ON CONFLICT (tenant_id) DO UPDATE
SET live_nonces = EXCLUDED.live_nonces;

UPDATE chio_finding_market_dpop_admission_state AS state
SET live_nonces = 0
WHERE NOT EXISTS (
    SELECT 1
    FROM chio_finding_market_dpop_nonces AS nonces
    WHERE nonces.tenant_id = state.tenant_id
);
