use sqlx::{PgPool, Row as _};

use crate::HostedMarketStoreError;

const TENANT_SCOPED_TABLES: [&str; 9] = [
    "chio_finding_market_tenants",
    "chio_finding_market_jobs",
    "chio_finding_market_principals",
    "chio_finding_market_api_keys",
    "chio_finding_market_dpop_nonces",
    "chio_finding_market_capability_uses",
    "chio_finding_market_security_events",
    "chio_finding_market_aggregate_events",
    "chio_finding_market_aggregate_heads",
];

pub(crate) async fn verify_runtime_role(pool: &PgPool) -> Result<(), HostedMarketStoreError> {
    let row = sqlx::query(
        "SELECT role_catalog.rolsuper, role_catalog.rolbypassrls, role_catalog.rolcreaterole, role_catalog.rolcreatedb, role_catalog.rolreplication, role_catalog.rolinherit, EXISTS (SELECT 1 FROM pg_auth_members WHERE member = role_catalog.oid) FROM pg_roles AS role_catalog WHERE role_catalog.rolname = current_user",
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| HostedMarketStoreError::Unavailable)?
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
    verify_runtime_rls_surface(pool).await?;
    Ok(())
}

async fn verify_runtime_database_privileges(pool: &PgPool) -> Result<(), HostedMarketStoreError> {
    let row = sqlx::query(
        "SELECT has_database_privilege(current_user, current_database(), 'CREATE'), has_database_privilege(current_user, current_database(), 'TEMPORARY'), has_schema_privilege(current_user, current_schema(), 'CREATE'), current_setting('row_security')",
    )
    .fetch_one(pool)
    .await
    .map_err(|_| HostedMarketStoreError::Unavailable)?;
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
        .map_err(|_| HostedMarketStoreError::Unavailable)?;
    if schemas.len() != 1 {
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
            COUNT(policy_catalog.oid) AS policy_count,
            BOOL_AND(
                policy_catalog.polname = table_catalog.relname || '_tenant_isolation'
                AND POSITION('chio.tenant_id' IN pg_get_expr(policy_catalog.polqual, policy_catalog.polrelid)) > 0
                AND POSITION('tenant_id' IN pg_get_expr(policy_catalog.polqual, policy_catalog.polrelid)) > 0
                AND POSITION('chio.tenant_id' IN pg_get_expr(policy_catalog.polwithcheck, policy_catalog.polrelid)) > 0
                AND POSITION('tenant_id' IN pg_get_expr(policy_catalog.polwithcheck, policy_catalog.polrelid)) > 0
            ) AS policy_is_bound
        FROM pg_class AS table_catalog
        JOIN pg_namespace AS namespace_catalog
          ON namespace_catalog.oid = table_catalog.relnamespace
        LEFT JOIN pg_policy AS policy_catalog
          ON policy_catalog.polrelid = table_catalog.oid
        WHERE namespace_catalog.nspname = current_schema()
          AND table_catalog.relkind = 'r'
          AND table_catalog.relname = ANY($1)
        GROUP BY table_catalog.oid, table_catalog.relname,
                 table_catalog.relrowsecurity, table_catalog.relforcerowsecurity,
                 table_catalog.relowner
        ORDER BY table_catalog.relname
        "#,
    )
    .bind(&table_names)
    .fetch_all(pool)
    .await
    .map_err(|_| HostedMarketStoreError::Unavailable)?;
    if rows.len() != TENANT_SCOPED_TABLES.len() {
        return Err(HostedMarketStoreError::Configuration);
    }
    for row in rows {
        let name: String = row.try_get(0).map_err(unavailable)?;
        let enabled: bool = row.try_get(1).map_err(unavailable)?;
        let forced: bool = row.try_get(2).map_err(unavailable)?;
        let owned_by_runtime: bool = row.try_get(3).map_err(unavailable)?;
        let policy_count: i64 = row.try_get(4).map_err(unavailable)?;
        let policy_is_bound: bool = row.try_get(5).map_err(unavailable)?;
        if !TENANT_SCOPED_TABLES.contains(&name.as_str())
            || !enabled
            || !forced
            || owned_by_runtime
            || policy_count != 1
            || !policy_is_bound
        {
            return Err(HostedMarketStoreError::Configuration);
        }
    }
    Ok(())
}

fn unavailable(_: sqlx::Error) -> HostedMarketStoreError {
    HostedMarketStoreError::Unavailable
}
