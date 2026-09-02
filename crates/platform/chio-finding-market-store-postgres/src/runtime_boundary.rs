use sqlx::{PgPool, Row as _};

use crate::HostedMarketStoreError;

const TENANT_SCOPED_TABLES: [&str; 31] = [
    "chio_finding_market_tenants",
    "chio_finding_market_jobs",
    "chio_finding_market_principals",
    "chio_finding_market_api_keys",
    "chio_finding_market_dpop_nonces",
    "chio_finding_market_dpop_admission_state",
    "chio_finding_market_capability_uses",
    "chio_finding_market_capability_request_admissions",
    "chio_finding_market_security_events",
    "chio_finding_market_aggregate_events",
    "chio_finding_market_aggregate_heads",
    "chio_finding_market_aggregate_checkpoints",
    "chio_finding_market_spend_reservations",
    "chio_finding_market_spend_periods",
    "chio_finding_market_journal_checkpoints",
    "chio_finding_market_journal_checkpoint_members",
    "chio_finding_market_archive_manifests",
    "chio_finding_market_legal_hold_events",
    "chio_finding_market_restore_verifications",
    "chio_finding_market_quota_alerts",
    "chio_finding_market_gc_receipts",
    "chio_finding_market_domain_projections",
    "chio_finding_market_principal_events",
    "chio_finding_market_principal_key_overlaps",
    "chio_finding_market_authority_state",
    "chio_finding_market_replication_events",
    "chio_finding_market_principal_replication_events",
    "chio_finding_market_replication_checks",
    "chio_finding_market_replication_outbox",
    "chio_finding_market_principal_replication_outbox",
    "chio_finding_market_authority_transitions",
];
const TENANT_POLICY_EXPRESSION: &str =
    "(tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))";
const APPEND_AGGREGATE_EVENT_FUNCTION: &str = concat!(
    "chio_finding_market_append_aggregate_event(",
    "text,text,text,bigint,text,text,text,text,bytea,text,bigint)"
);
const GC_RETAINED_RESOURCE_FUNCTION: &str = concat!(
    "chio_finding_market_gc_retained_resource(",
    "text,text,text,text,text,bigint,text,text,text,bytea,bigint)"
);
const APPEND_JOURNAL_CHECKPOINT_FUNCTION: &str = concat!(
    "chio_finding_market_append_journal_checkpoint(",
    "text,text,text,text,text,bigint,text,text,bytea,bigint,jsonb)"
);
const APPEND_ARCHIVE_MANIFEST_FUNCTION: &str = concat!(
    "chio_finding_market_append_archive_manifest(",
    "text,text,text,text,text,bigint,text,text,text,text,bigint,text,text,text,bytea,bigint)"
);
const APPEND_LEGAL_HOLD_EVENT_FUNCTION: &str = concat!(
    "chio_finding_market_append_legal_hold_event(",
    "text,text,text,text,text,text,text,text,text,bytea,bigint)"
);
const APPEND_RESTORE_VERIFICATION_FUNCTION: &str = concat!(
    "chio_finding_market_append_restore_verification(",
    "text,text,text,text,text,bytea,bigint)"
);
const APPEND_QUOTA_ALERT_FUNCTION: &str = concat!(
    "chio_finding_market_append_quota_alert(",
    "text,text,text,bigint,bigint,text,bytea,bigint)"
);
const RETENTION_APPEND_FUNCTIONS: [&str; 5] = [
    APPEND_JOURNAL_CHECKPOINT_FUNCTION,
    APPEND_ARCHIVE_MANIFEST_FUNCTION,
    APPEND_LEGAL_HOLD_EVENT_FUNCTION,
    APPEND_RESTORE_VERIFICATION_FUNCTION,
    APPEND_QUOTA_ALERT_FUNCTION,
];
const APPEND_DOMAIN_EVENT_FUNCTION: &str = concat!(
    "chio_finding_market_append_domain_event(",
    "text,text,text,bigint,text,text,text,text,text,bytea,text,bigint)"
);
const APPLY_PRINCIPAL_EVENT_FUNCTION: &str = concat!(
    "chio_finding_market_apply_principal_event(",
    "text,text,text,text,text,text,bigint,text,text,bytea,bigint)"
);
const APPLY_REPLICATION_EVENT_FUNCTION: &str = concat!(
    "chio_finding_market_apply_replication_event(",
    "text,text,text,bigint,bigint,text,text,bigint,text,text,text,text,text,bytea,text,text,bytea,bigint)"
);
const APPLY_PRINCIPAL_REPLICATION_EVENT_FUNCTION: &str = concat!(
    "chio_finding_market_apply_principal_replication_event(",
    "text,text,text,bigint,bigint,text,text,text,text,text,bigint,text,text,bytea,text,bytea,bigint)"
);
const APPEND_REPLICATION_CHECK_FUNCTION: &str = concat!(
    "chio_finding_market_append_replication_check(",
    "text,text,text,bigint,bigint,text,text,bigint,bigint,bigint,text,bytea,bigint)"
);
const APPLY_AUTHORITY_TRANSITION_FUNCTION: &str = concat!(
    "chio_finding_market_apply_authority_transition(",
    "text,text,text,text,text,bigint,bigint,bigint,text,text,text,bigint,text,bytea,bigint)"
);
const WORKER_JOB_FUNCTIONS: [&str; 6] = [
    "chio_finding_market_claim_jobs(text,text,bigint,bigint)",
    "chio_finding_market_renew_job_lease(text,text,text,bigint,bigint)",
    "chio_finding_market_complete_job(text,text,text,bigint,text,bytea)",
    "chio_finding_market_fail_job(text,text,text,bigint,text,bigint)",
    "chio_finding_market_relinquish_job_lease(text,text,text,bigint)",
    "chio_finding_market_exhaust_job(text,text,text,bigint,text)",
];

struct RuntimeTablePrivileges {
    name: &'static str,
    select: bool,
    insert: bool,
    update: bool,
    delete: bool,
}

const RUNTIME_TABLE_PRIVILEGES: [RuntimeTablePrivileges; 33] = [
    RuntimeTablePrivileges {
        name: "_sqlx_migrations",
        select: true,
        insert: false,
        update: false,
        delete: false,
    },
    RuntimeTablePrivileges {
        name: "chio_finding_market_tenants",
        select: true,
        insert: true,
        update: true,
        delete: false,
    },
    RuntimeTablePrivileges {
        name: "chio_finding_market_jobs",
        select: true,
        insert: true,
        update: true,
        delete: false,
    },
    RuntimeTablePrivileges {
        name: "chio_finding_market_principals",
        select: true,
        insert: false,
        update: false,
        delete: false,
    },
    RuntimeTablePrivileges {
        name: "chio_finding_market_api_keys",
        select: true,
        insert: true,
        update: true,
        delete: false,
    },
    RuntimeTablePrivileges {
        name: "chio_finding_market_dpop_nonces",
        select: true,
        insert: true,
        update: false,
        delete: true,
    },
    RuntimeTablePrivileges {
        name: "chio_finding_market_dpop_admission_state",
        select: true,
        insert: true,
        update: true,
        delete: false,
    },
    RuntimeTablePrivileges {
        name: "chio_finding_market_capability_uses",
        select: true,
        insert: true,
        update: true,
        delete: true,
    },
    RuntimeTablePrivileges {
        name: "chio_finding_market_capability_request_admissions",
        select: true,
        insert: true,
        update: false,
        delete: true,
    },
    RuntimeTablePrivileges {
        name: "chio_finding_market_security_events",
        select: true,
        insert: true,
        update: false,
        delete: false,
    },
    RuntimeTablePrivileges {
        name: "chio_finding_market_aggregate_events",
        select: true,
        insert: false,
        update: false,
        delete: false,
    },
    RuntimeTablePrivileges {
        name: "chio_finding_market_aggregate_heads",
        select: true,
        insert: false,
        update: false,
        delete: false,
    },
    RuntimeTablePrivileges {
        name: "chio_finding_market_aggregate_checkpoints",
        select: true,
        insert: true,
        update: false,
        delete: false,
    },
    RuntimeTablePrivileges {
        name: "chio_finding_market_spend_reservations",
        select: true,
        insert: true,
        update: true,
        delete: false,
    },
    // The accumulator is maintained only by the security-definer trigger on
    // the reservation table, so the runtime never writes it. Leaving those
    // writes granted would let a compromised runtime role forge a low total
    // for its own tenant and pass the ceiling the trigger enforces.
    RuntimeTablePrivileges {
        name: "chio_finding_market_spend_periods",
        select: true,
        insert: false,
        update: false,
        delete: false,
    },
    no_runtime_privilege("chio_finding_market_journal_checkpoints"),
    no_runtime_privilege("chio_finding_market_journal_checkpoint_members"),
    no_runtime_privilege("chio_finding_market_archive_manifests"),
    no_runtime_privilege("chio_finding_market_legal_hold_events"),
    no_runtime_privilege("chio_finding_market_restore_verifications"),
    no_runtime_privilege("chio_finding_market_quota_alerts"),
    no_runtime_privilege("chio_finding_market_gc_receipts"),
    RuntimeTablePrivileges {
        name: "chio_finding_market_domain_event_contracts",
        select: true,
        insert: false,
        update: false,
        delete: false,
    },
    RuntimeTablePrivileges {
        name: "chio_finding_market_domain_projections",
        select: true,
        insert: false,
        update: false,
        delete: false,
    },
    RuntimeTablePrivileges {
        name: "chio_finding_market_principal_events",
        select: true,
        insert: false,
        update: false,
        delete: false,
    },
    RuntimeTablePrivileges {
        name: "chio_finding_market_principal_key_overlaps",
        select: true,
        insert: false,
        update: false,
        delete: false,
    },
    RuntimeTablePrivileges {
        name: "chio_finding_market_authority_state",
        select: true,
        insert: false,
        update: false,
        delete: false,
    },
    no_runtime_privilege("chio_finding_market_replication_events"),
    no_runtime_privilege("chio_finding_market_principal_replication_events"),
    no_runtime_privilege("chio_finding_market_replication_checks"),
    no_runtime_privilege("chio_finding_market_replication_outbox"),
    no_runtime_privilege("chio_finding_market_principal_replication_outbox"),
    no_runtime_privilege("chio_finding_market_authority_transitions"),
];

const fn no_runtime_privilege(name: &'static str) -> RuntimeTablePrivileges {
    RuntimeTablePrivileges {
        name,
        select: false,
        insert: false,
        update: false,
        delete: false,
    }
}

pub(crate) async fn verify_runtime_role(pool: &PgPool) -> Result<(), HostedMarketStoreError> {
    let row = sqlx::query(
        "SELECT role_catalog.rolsuper, role_catalog.rolbypassrls, role_catalog.rolcreaterole, role_catalog.rolcreatedb, role_catalog.rolreplication, role_catalog.rolinherit, EXISTS (SELECT 1 FROM pg_auth_members WHERE member = role_catalog.oid) FROM pg_roles AS role_catalog WHERE role_catalog.rolname = current_user",
    )
    .fetch_optional(pool)
    .await
    .map_err(unavailable)?
    .ok_or(HostedMarketStoreError::Configuration)?;
    let is_superuser: bool = row.try_get(0).map_err(unavailable)?;
    let bypasses_rls: bool = row.try_get(1).map_err(unavailable)?;
    let can_create_role: bool = row.try_get(2).map_err(unavailable)?;
    let can_create_database: bool = row.try_get(3).map_err(unavailable)?;
    let can_replicate: bool = row.try_get(4).map_err(unavailable)?;
    let inherits_roles: bool = row.try_get(5).map_err(unavailable)?;
    let has_role_memberships: bool = row.try_get(6).map_err(unavailable)?;
    if is_superuser
        || bypasses_rls
        || can_create_role
        || can_create_database
        || can_replicate
        || inherits_roles
        || has_role_memberships
    {
        return Err(HostedMarketStoreError::Configuration);
    }
    verify_runtime_database_privileges(pool).await?;
    verify_runtime_table_privileges(pool).await?;
    verify_function_privileges(pool, &WORKER_JOB_FUNCTIONS, true).await?;
    verify_runtime_rls_surface(pool).await?;
    Ok(())
}

pub(crate) async fn verify_migrator_role(pool: &PgPool) -> Result<(), HostedMarketStoreError> {
    let row = sqlx::query(
        "SELECT role_catalog.rolsuper, role_catalog.rolbypassrls, role_catalog.rolcreaterole, role_catalog.rolcreatedb, role_catalog.rolreplication, role_catalog.rolinherit, EXISTS (SELECT 1 FROM pg_auth_members WHERE member = role_catalog.oid), has_database_privilege(current_user, current_database(), 'CREATE'), has_database_privilege(current_user, current_database(), 'TEMPORARY'), has_schema_privilege(current_user, current_schema(), 'CREATE') FROM pg_roles AS role_catalog WHERE role_catalog.rolname = current_user",
    )
    .fetch_optional(pool)
    .await
    .map_err(unavailable)?
    .ok_or(HostedMarketStoreError::Configuration)?;
    for index in [0_usize, 2, 3, 4, 5, 6, 7, 8] {
        let forbidden: bool = row.try_get(index).map_err(unavailable)?;
        if forbidden {
            return Err(HostedMarketStoreError::Configuration);
        }
    }
    let bypasses_rls: bool = row.try_get(1).map_err(unavailable)?;
    let can_create_schema_objects: bool = row.try_get(9).map_err(unavailable)?;
    let schemas: Vec<String> = sqlx::query_scalar("SELECT current_schemas(FALSE)")
        .fetch_one(pool)
        .await
        .map_err(unavailable)?;
    if !bypasses_rls
        || !can_create_schema_objects
        || schemas.len() != 1
        || schemas.first().map(String::as_str) != Some("public")
    {
        return Err(HostedMarketStoreError::Configuration);
    }
    Ok(())
}

pub(crate) async fn verify_retention_role(pool: &PgPool) -> Result<(), HostedMarketStoreError> {
    verify_unprivileged_login_role(pool).await?;
    verify_runtime_database_privileges(pool).await?;
    for expected in retention_table_privileges() {
        verify_one_table_privilege(pool, &expected).await?;
    }
    let can_gc: bool =
        sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
            .bind(GC_RETAINED_RESOURCE_FUNCTION)
            .fetch_one(pool)
            .await
            .map_err(unavailable)?;
    for function in RETENTION_APPEND_FUNCTIONS {
        let can_append: bool =
            sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
                .bind(function)
                .fetch_one(pool)
                .await
                .map_err(unavailable)?;
        if !can_append {
            return Err(HostedMarketStoreError::Configuration);
        }
    }
    let can_append_raw: bool =
        sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
            .bind(APPEND_AGGREGATE_EVENT_FUNCTION)
            .fetch_one(pool)
            .await
            .map_err(unavailable)?;
    let can_append_domain: bool =
        sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
            .bind(APPEND_DOMAIN_EVENT_FUNCTION)
            .fetch_one(pool)
            .await
            .map_err(unavailable)?;
    let can_apply_principal: bool =
        sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
            .bind(APPLY_PRINCIPAL_EVENT_FUNCTION)
            .fetch_one(pool)
            .await
            .map_err(unavailable)?;
    let can_replicate: bool =
        sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
            .bind(APPLY_REPLICATION_EVENT_FUNCTION)
            .fetch_one(pool)
            .await
            .map_err(unavailable)?;
    let can_replicate_principal: bool =
        sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
            .bind(APPLY_PRINCIPAL_REPLICATION_EVENT_FUNCTION)
            .fetch_one(pool)
            .await
            .map_err(unavailable)?;
    let can_append_replication_check: bool =
        sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
            .bind(APPEND_REPLICATION_CHECK_FUNCTION)
            .fetch_one(pool)
            .await
            .map_err(unavailable)?;
    let can_transition: bool =
        sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
            .bind(APPLY_AUTHORITY_TRANSITION_FUNCTION)
            .fetch_one(pool)
            .await
            .map_err(unavailable)?;
    if !can_gc
        || can_append_raw
        || can_append_domain
        || can_apply_principal
        || can_replicate
        || can_replicate_principal
        || can_append_replication_check
        || can_transition
    {
        return Err(HostedMarketStoreError::Configuration);
    }
    verify_function_privileges(pool, &WORKER_JOB_FUNCTIONS, false).await?;
    verify_runtime_rls_surface(pool).await
}

pub(crate) async fn verify_worker_role(pool: &PgPool) -> Result<(), HostedMarketStoreError> {
    verify_unprivileged_login_role(pool).await?;
    verify_runtime_database_privileges(pool).await?;
    for runtime in RUNTIME_TABLE_PRIVILEGES {
        let expected = match runtime.name {
            "_sqlx_migrations" | "chio_finding_market_tenants" => RuntimeTablePrivileges {
                name: runtime.name,
                select: true,
                insert: false,
                update: false,
                delete: false,
            },
            "chio_finding_market_jobs" => RuntimeTablePrivileges {
                name: runtime.name,
                select: true,
                insert: false,
                update: false,
                delete: false,
            },
            _ => no_runtime_privilege(runtime.name),
        };
        verify_one_table_privilege(pool, &expected).await?;
    }
    for function in [
        APPEND_AGGREGATE_EVENT_FUNCTION,
        APPEND_DOMAIN_EVENT_FUNCTION,
        APPLY_PRINCIPAL_EVENT_FUNCTION,
        GC_RETAINED_RESOURCE_FUNCTION,
        APPLY_REPLICATION_EVENT_FUNCTION,
        APPLY_PRINCIPAL_REPLICATION_EVENT_FUNCTION,
        APPEND_REPLICATION_CHECK_FUNCTION,
        APPLY_AUTHORITY_TRANSITION_FUNCTION,
    ] {
        let can_execute: bool =
            sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
                .bind(function)
                .fetch_one(pool)
                .await
                .map_err(unavailable)?;
        if can_execute {
            return Err(HostedMarketStoreError::Configuration);
        }
    }
    for function in RETENTION_APPEND_FUNCTIONS {
        let can_execute: bool =
            sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
                .bind(function)
                .fetch_one(pool)
                .await
                .map_err(unavailable)?;
        if can_execute {
            return Err(HostedMarketStoreError::Configuration);
        }
    }
    verify_function_privileges(pool, &WORKER_JOB_FUNCTIONS, true).await?;
    verify_runtime_rls_surface(pool).await
}

pub(crate) async fn verify_replicator_role(pool: &PgPool) -> Result<(), HostedMarketStoreError> {
    verify_unprivileged_login_role(pool).await?;
    verify_runtime_database_privileges(pool).await?;
    for runtime in RUNTIME_TABLE_PRIVILEGES {
        let (select, insert) = match runtime.name {
            "_sqlx_migrations"
            | "chio_finding_market_tenants"
            | "chio_finding_market_aggregate_events"
            | "chio_finding_market_aggregate_heads"
            | "chio_finding_market_domain_event_contracts"
            | "chio_finding_market_domain_projections"
            | "chio_finding_market_principals"
            | "chio_finding_market_principal_events"
            | "chio_finding_market_principal_key_overlaps"
            | "chio_finding_market_authority_state"
            | "chio_finding_market_replication_events"
            | "chio_finding_market_principal_replication_events"
            | "chio_finding_market_replication_outbox"
            | "chio_finding_market_principal_replication_outbox"
            | "chio_finding_market_authority_transitions" => (true, false),
            "chio_finding_market_replication_checks" => (true, false),
            _ => (false, false),
        };
        verify_one_table_privilege(
            pool,
            &RuntimeTablePrivileges {
                name: runtime.name,
                select,
                insert,
                update: false,
                delete: false,
            },
        )
        .await?;
    }
    for (function, expected) in [
        (APPEND_AGGREGATE_EVENT_FUNCTION, false),
        (APPEND_DOMAIN_EVENT_FUNCTION, false),
        (APPLY_PRINCIPAL_EVENT_FUNCTION, false),
        (GC_RETAINED_RESOURCE_FUNCTION, false),
        (APPLY_REPLICATION_EVENT_FUNCTION, true),
        (APPLY_PRINCIPAL_REPLICATION_EVENT_FUNCTION, true),
        (APPEND_REPLICATION_CHECK_FUNCTION, true),
        (APPLY_AUTHORITY_TRANSITION_FUNCTION, true),
    ] {
        let can_execute: bool =
            sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
                .bind(function)
                .fetch_one(pool)
                .await
                .map_err(unavailable)?;
        if can_execute != expected {
            return Err(HostedMarketStoreError::Configuration);
        }
    }
    for function in RETENTION_APPEND_FUNCTIONS {
        let can_execute: bool =
            sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
                .bind(function)
                .fetch_one(pool)
                .await
                .map_err(unavailable)?;
        if can_execute {
            return Err(HostedMarketStoreError::Configuration);
        }
    }
    verify_function_privileges(pool, &WORKER_JOB_FUNCTIONS, false).await?;
    verify_runtime_rls_surface(pool).await
}

async fn verify_function_privileges(
    pool: &PgPool,
    functions: &[&str],
    expected: bool,
) -> Result<(), HostedMarketStoreError> {
    for function in functions {
        let actual: bool =
            sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
                .bind(function)
                .fetch_one(pool)
                .await
                .map_err(unavailable)?;
        if actual != expected {
            return Err(HostedMarketStoreError::Configuration);
        }
    }
    Ok(())
}

async fn verify_unprivileged_login_role(pool: &PgPool) -> Result<(), HostedMarketStoreError> {
    let row = sqlx::query(
        "SELECT role_catalog.rolsuper, role_catalog.rolbypassrls, role_catalog.rolcreaterole, role_catalog.rolcreatedb, role_catalog.rolreplication, role_catalog.rolinherit, EXISTS (SELECT 1 FROM pg_auth_members WHERE member = role_catalog.oid) FROM pg_roles AS role_catalog WHERE role_catalog.rolname = current_user",
    )
    .fetch_optional(pool)
    .await
    .map_err(unavailable)?
    .ok_or(HostedMarketStoreError::Configuration)?;
    for index in 0..7 {
        if row.try_get::<bool, _>(index).map_err(unavailable)? {
            return Err(HostedMarketStoreError::Configuration);
        }
    }
    Ok(())
}

fn retention_table_privileges() -> Vec<RuntimeTablePrivileges> {
    RUNTIME_TABLE_PRIVILEGES
        .iter()
        .map(|runtime| {
            let select = matches!(
                runtime.name,
                "_sqlx_migrations"
                    | "chio_finding_market_tenants"
                    | "chio_finding_market_jobs"
                    | "chio_finding_market_aggregate_events"
                    | "chio_finding_market_aggregate_heads"
                    | "chio_finding_market_aggregate_checkpoints"
                    | "chio_finding_market_gc_receipts"
                    | "chio_finding_market_journal_checkpoints"
                    | "chio_finding_market_journal_checkpoint_members"
                    | "chio_finding_market_archive_manifests"
                    | "chio_finding_market_legal_hold_events"
                    | "chio_finding_market_restore_verifications"
                    | "chio_finding_market_quota_alerts"
            );
            RuntimeTablePrivileges {
                name: runtime.name,
                select,
                insert: false,
                update: false,
                delete: false,
            }
        })
        .collect()
}

async fn verify_runtime_database_privileges(pool: &PgPool) -> Result<(), HostedMarketStoreError> {
    let row = sqlx::query(
        "SELECT has_database_privilege(current_user, current_database(), 'CREATE'), has_database_privilege(current_user, current_database(), 'TEMPORARY'), has_schema_privilege(current_user, current_schema(), 'CREATE'), current_setting('row_security')",
    )
    .fetch_one(pool)
    .await
    .map_err(unavailable)?;
    let can_create_database_objects: bool = row.try_get(0).map_err(unavailable)?;
    let can_create_temporary_objects: bool = row.try_get(1).map_err(unavailable)?;
    let can_create_schema_objects: bool = row.try_get(2).map_err(unavailable)?;
    let row_security: String = row.try_get(3).map_err(unavailable)?;
    if can_create_database_objects
        || can_create_temporary_objects
        || can_create_schema_objects
        || row_security != "on"
    {
        return Err(HostedMarketStoreError::Configuration);
    }
    let schemas: Vec<String> = sqlx::query_scalar("SELECT current_schemas(FALSE)")
        .fetch_one(pool)
        .await
        .map_err(unavailable)?;
    if schemas.len() != 1 || schemas.first().map(String::as_str) != Some("public") {
        return Err(HostedMarketStoreError::Configuration);
    }
    Ok(())
}

async fn verify_runtime_table_privileges(pool: &PgPool) -> Result<(), HostedMarketStoreError> {
    for expected in RUNTIME_TABLE_PRIVILEGES {
        verify_one_table_privilege(pool, &expected).await?;
    }
    let can_append_raw: bool =
        sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
            .bind(APPEND_AGGREGATE_EVENT_FUNCTION)
            .fetch_one(pool)
            .await
            .map_err(unavailable)?;
    let can_append_domain: bool =
        sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
            .bind(APPEND_DOMAIN_EVENT_FUNCTION)
            .fetch_one(pool)
            .await
            .map_err(unavailable)?;
    let can_apply_principal: bool =
        sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
            .bind(APPLY_PRINCIPAL_EVENT_FUNCTION)
            .fetch_one(pool)
            .await
            .map_err(unavailable)?;
    let can_gc: bool =
        sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
            .bind(GC_RETAINED_RESOURCE_FUNCTION)
            .fetch_one(pool)
            .await
            .map_err(unavailable)?;
    let can_replicate: bool =
        sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
            .bind(APPLY_REPLICATION_EVENT_FUNCTION)
            .fetch_one(pool)
            .await
            .map_err(unavailable)?;
    let can_replicate_principal: bool =
        sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
            .bind(APPLY_PRINCIPAL_REPLICATION_EVENT_FUNCTION)
            .fetch_one(pool)
            .await
            .map_err(unavailable)?;
    let can_append_replication_check: bool =
        sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
            .bind(APPEND_REPLICATION_CHECK_FUNCTION)
            .fetch_one(pool)
            .await
            .map_err(unavailable)?;
    let can_transition: bool =
        sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
            .bind(APPLY_AUTHORITY_TRANSITION_FUNCTION)
            .fetch_one(pool)
            .await
            .map_err(unavailable)?;
    for function in RETENTION_APPEND_FUNCTIONS {
        let can_execute: bool =
            sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
                .bind(function)
                .fetch_one(pool)
                .await
                .map_err(unavailable)?;
        if can_execute {
            return Err(HostedMarketStoreError::Configuration);
        }
    }
    if can_append_raw
        || !can_append_domain
        || !can_apply_principal
        || can_gc
        || can_replicate
        || can_replicate_principal
        || can_append_replication_check
        || can_transition
    {
        return Err(HostedMarketStoreError::Configuration);
    }
    Ok(())
}

async fn verify_one_table_privilege(
    pool: &PgPool,
    expected: &RuntimeTablePrivileges,
) -> Result<(), HostedMarketStoreError> {
    let row = sqlx::query(
        r#"
            SELECT
                has_table_privilege(current_user, $1, 'SELECT'),
                has_table_privilege(current_user, $1, 'INSERT'),
                has_table_privilege(current_user, $1, 'UPDATE'),
                has_table_privilege(current_user, $1, 'DELETE'),
                has_table_privilege(current_user, $1, 'TRUNCATE'),
                has_table_privilege(current_user, $1, 'REFERENCES'),
                has_table_privilege(current_user, $1, 'TRIGGER')
            "#,
    )
    .bind(expected.name)
    .fetch_one(pool)
    .await
    .map_err(unavailable)?;
    let select: bool = row.try_get(0).map_err(unavailable)?;
    let insert: bool = row.try_get(1).map_err(unavailable)?;
    let update: bool = row.try_get(2).map_err(unavailable)?;
    let delete: bool = row.try_get(3).map_err(unavailable)?;
    let truncate: bool = row.try_get(4).map_err(unavailable)?;
    let references: bool = row.try_get(5).map_err(unavailable)?;
    let trigger: bool = row.try_get(6).map_err(unavailable)?;
    if select != expected.select
        || insert != expected.insert
        || update != expected.update
        || delete != expected.delete
        || truncate
        || references
        || trigger
    {
        return Err(HostedMarketStoreError::Configuration);
    }
    Ok(())
}

async fn verify_runtime_rls_surface(pool: &PgPool) -> Result<(), HostedMarketStoreError> {
    let table_names = TENANT_SCOPED_TABLES.to_vec();
    let rows = sqlx::query(
        r#"
        SELECT
            table_catalog.relname,
            table_catalog.relrowsecurity,
            table_catalog.relforcerowsecurity,
            pg_get_userbyid(table_catalog.relowner) = current_user AS owned_by_runtime,
            policy_catalog.polname,
            policy_catalog.polcmd = '*' AS applies_to_all_commands,
            policy_catalog.polpermissive,
            policy_catalog.polroles = ARRAY[0::oid] AS applies_to_public,
            pg_get_expr(policy_catalog.polqual, policy_catalog.polrelid) = $2
                AS using_is_exact,
            pg_get_expr(policy_catalog.polwithcheck, policy_catalog.polrelid) = $2
                AS check_is_exact
        FROM pg_class AS table_catalog
        JOIN pg_namespace AS namespace_catalog
          ON namespace_catalog.oid = table_catalog.relnamespace
        JOIN pg_policy AS policy_catalog
          ON policy_catalog.polrelid = table_catalog.oid
        WHERE namespace_catalog.nspname = current_schema()
          AND table_catalog.relkind = 'r'
          AND table_catalog.relname = ANY($1)
        ORDER BY table_catalog.relname
        "#,
    )
    .bind(&table_names)
    .bind(TENANT_POLICY_EXPRESSION)
    .fetch_all(pool)
    .await
    .map_err(unavailable)?;
    if rows.len() != TENANT_SCOPED_TABLES.len() {
        return Err(HostedMarketStoreError::Configuration);
    }
    for row in rows {
        let name: String = row.try_get(0).map_err(unavailable)?;
        let enabled: bool = row.try_get(1).map_err(unavailable)?;
        let forced: bool = row.try_get(2).map_err(unavailable)?;
        let owned_by_runtime: bool = row.try_get(3).map_err(unavailable)?;
        let policy_name: String = row.try_get(4).map_err(unavailable)?;
        let applies_to_all_commands: bool = row.try_get(5).map_err(unavailable)?;
        let permissive: bool = row.try_get(6).map_err(unavailable)?;
        let applies_to_public: bool = row.try_get(7).map_err(unavailable)?;
        let using_is_exact: bool = row.try_get(8).map_err(unavailable)?;
        let check_is_exact: bool = row.try_get(9).map_err(unavailable)?;
        if !TENANT_SCOPED_TABLES.contains(&name.as_str())
            || !enabled
            || !forced
            || owned_by_runtime
            || policy_name != tenant_policy_name(&name)
            || !applies_to_all_commands
            || !permissive
            || !applies_to_public
            || !using_is_exact
            || !check_is_exact
        {
            return Err(HostedMarketStoreError::Configuration);
        }
    }
    Ok(())
}

fn tenant_policy_name(table_name: &str) -> String {
    let mut name = format!("{table_name}_tenant_isolation");
    name.truncate(63);
    name
}

fn unavailable(_: sqlx::Error) -> HostedMarketStoreError {
    HostedMarketStoreError::Unavailable
}
