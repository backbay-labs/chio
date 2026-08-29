use sqlx::{PgPool, Row as _};

use crate::HostedMarketStoreError;

const TENANT_SCOPED_TABLES: [&str; 11] = [
    "chio_finding_market_tenants",
    "chio_finding_market_jobs",
    "chio_finding_market_principals",
    "chio_finding_market_api_keys",
    "chio_finding_market_dpop_nonces",
    "chio_finding_market_capability_uses",
    "chio_finding_market_security_events",
    "chio_finding_market_aggregate_events",
    "chio_finding_market_aggregate_heads",
    "chio_finding_market_aggregate_checkpoints",
    "chio_finding_market_spend_reservations",
];
const TENANT_POLICY_EXPRESSION: &str =
    "(tenant_id = NULLIF(current_setting('chio.tenant_id'::text, true), ''::text))";
const APPEND_AGGREGATE_EVENT_FUNCTION: &str = concat!(
    "chio_finding_market_append_aggregate_event(",
    "text,text,text,bigint,text,text,text,text,bytea,text,bigint)"
);

struct RuntimeTablePrivileges {
    name: &'static str,
    select: bool,
    insert: bool,
    update: bool,
    delete: bool,
}

const RUNTIME_TABLE_PRIVILEGES: [RuntimeTablePrivileges; 12] = [
    RuntimeTablePrivileges {
        name: "chio_finding_market_schema_migrations",
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
        insert: true,
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
        name: "chio_finding_market_capability_uses",
        select: true,
        insert: true,
        update: true,
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
    verify_runtime_table_privileges(pool).await?;
    verify_runtime_rls_surface(pool).await?;
    Ok(())
}

pub(crate) async fn verify_migrator_role(pool: &PgPool) -> Result<(), HostedMarketStoreError> {
    let row = sqlx::query(
        "SELECT role_catalog.rolsuper, role_catalog.rolbypassrls, role_catalog.rolcreaterole, role_catalog.rolcreatedb, role_catalog.rolreplication, role_catalog.rolinherit, EXISTS (SELECT 1 FROM pg_auth_members WHERE member = role_catalog.oid), has_database_privilege(current_user, current_database(), 'CREATE'), has_database_privilege(current_user, current_database(), 'TEMPORARY'), has_schema_privilege(current_user, current_schema(), 'CREATE') FROM pg_roles AS role_catalog WHERE role_catalog.rolname = current_user",
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| HostedMarketStoreError::Unavailable)?
    .ok_or(HostedMarketStoreError::Configuration)?;
    for index in 0..9 {
        let forbidden: bool = row.try_get(index).map_err(unavailable)?;
        if forbidden {
            return Err(HostedMarketStoreError::Configuration);
        }
    }
    let can_create_schema_objects: bool = row.try_get(9).map_err(unavailable)?;
    let schemas: Vec<String> = sqlx::query_scalar("SELECT current_schemas(FALSE)")
        .fetch_one(pool)
        .await
        .map_err(|_| HostedMarketStoreError::Unavailable)?;
    if !can_create_schema_objects
        || schemas.len() != 1
        || schemas.first().map(String::as_str) != Some("public")
    {
        return Err(HostedMarketStoreError::Configuration);
    }
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
    if schemas.len() != 1 || schemas.first().map(String::as_str) != Some("public") {
        return Err(HostedMarketStoreError::Configuration);
    }
    Ok(())
}

async fn verify_runtime_table_privileges(pool: &PgPool) -> Result<(), HostedMarketStoreError> {
    for expected in RUNTIME_TABLE_PRIVILEGES {
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
        .map_err(|_| HostedMarketStoreError::Unavailable)?;
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
    }
    let can_append: bool =
        sqlx::query_scalar("SELECT has_function_privilege(current_user, $1, 'EXECUTE')")
            .bind(APPEND_AGGREGATE_EVENT_FUNCTION)
            .fetch_one(pool)
            .await
            .map_err(|_| HostedMarketStoreError::Unavailable)?;
    if !can_append {
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
    .map_err(|_| HostedMarketStoreError::Unavailable)?;
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
            || policy_name != format!("{name}_tenant_isolation")
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

fn unavailable(_: sqlx::Error) -> HostedMarketStoreError {
    HostedMarketStoreError::Unavailable
}
