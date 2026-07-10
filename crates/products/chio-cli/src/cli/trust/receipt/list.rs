use super::*;

pub(crate) struct ReceiptListArgs<'a> {
    pub(crate) capability: Option<&'a str>,
    pub(crate) tool_server: Option<&'a str>,
    pub(crate) tool_name: Option<&'a str>,
    pub(crate) outcome: Option<&'a str>,
    pub(crate) since: Option<u64>,
    pub(crate) until: Option<u64>,
    pub(crate) min_cost: Option<u64>,
    pub(crate) max_cost: Option<u64>,
    pub(crate) limit: usize,
    pub(crate) cursor: Option<u64>,
    pub(crate) tenant: Option<&'a str>,
    pub(crate) admin_all: bool,
}

pub(crate) fn cmd_receipt_list(
    args: ReceiptListArgs<'_>,
    backend: QueryBackend<'_>,
) -> Result<(), CliError> {
    if let Some(url) = backend.control_url {
        if args.tenant.is_some() || args.admin_all {
            return Err(CliError::cli_other_error(
                "receipt list read-boundary flags apply to local --receipt-db; remote reads derive scope from the control token"
                    .to_string(),
            ));
        }
        let token = require_control_token(backend.control_token)?;
        let client = trust_control::service_runtime::client::build_client(url, token)?;
        let query = trust_control::ReceiptQueryHttpQuery {
            capability_id: args.capability.map(ToOwned::to_owned),
            tool_server: args.tool_server.map(ToOwned::to_owned),
            tool_name: args.tool_name.map(ToOwned::to_owned),
            outcome: args.outcome.map(ToOwned::to_owned),
            since: args.since,
            until: args.until,
            min_cost: args.min_cost,
            max_cost: args.max_cost,
            cursor: args.cursor,
            limit: Some(args.limit),
            agent_subject: None,
        };
        let response = client.query_receipts(&query)?;
        for receipt in &response.receipts {
            println!("{}", serde_json::to_string(receipt)?);
        }
        if let Some(next_cursor) = response.next_cursor {
            eprintln!(
                "next_cursor={next_cursor} total_count={}",
                response.total_count
            );
        }
    } else {
        let path = backend.receipt_db_path.ok_or_else(|| {
            CliError::cli_other_error(
                "receipt commands require --receipt-db <path> or --control-url".to_string(),
            )
        })?;
        if !path.is_file() {
            return Err(CliError::cli_other_error(format!(
                "receipt list requires an existing --receipt-db <path>: {}",
                path.display()
            )));
        }
        let read_context = local_receipt_read_context(args.tenant, args.admin_all)?;
        let store = chio_store_sqlite::SqliteReceiptStore::open_existing(path)?;
        let kernel_query = chio_kernel::ReceiptQuery {
            capability_id: args.capability.map(ToOwned::to_owned),
            tool_server: args.tool_server.map(ToOwned::to_owned),
            tool_name: args.tool_name.map(ToOwned::to_owned),
            outcome: args.outcome.map(ToOwned::to_owned),
            since: args.since,
            until: args.until,
            min_cost: args.min_cost,
            max_cost: args.max_cost,
            cursor: args.cursor,
            limit: args.limit,
            agent_subject: None,
            tenant_filter: args.tenant.map(ToOwned::to_owned),
            read_context: Some(read_context),
        };
        let result = store.query_receipts(&kernel_query)?;
        for stored in &result.receipts {
            println!("{}", serde_json::to_string(&stored.receipt)?);
        }
        if let Some(next_cursor) = result.next_cursor {
            eprintln!(
                "next_cursor={next_cursor} total_count={}",
                result.total_count
            );
        }
    }
    Ok(())
}

/// Resolve the local-CLI receipt read context from explicit operator
/// flags. The local CLI does NOT silently default to admin-all reads
/// across all tenants. Exactly one of `--tenant <id>` or `--admin-all`
/// must be specified by the operator for any local --receipt-db
/// listing or lookup; otherwise this function fails closed.
///
/// Note: clap is configured with `conflicts_with = "admin_all"` on the
/// `--tenant` flag, so the both-set case is rejected at parse time.
/// This function still defends against the both-set state in case any
/// caller bypasses the clap surface.
pub(crate) fn local_receipt_read_context(
    tenant: Option<&str>,
    admin_all: bool,
) -> Result<chio_kernel::ReceiptReadContext, CliError> {
    match (tenant, admin_all) {
        (Some(_), true) => Err(CliError::cli_other_error(
            "--tenant <id> and --admin-all are mutually exclusive".to_string(),
        )),
        (Some(tenant), false) => Ok(chio_kernel::ReceiptReadContext::authenticated_tenant(
            tenant.to_string(),
        )),
        (None, true) => Ok(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
        (None, false) => Err(CliError::cli_other_error(
            "--tenant <id> or --admin-all is required for local receipt reads".to_string(),
        )),
    }
}
