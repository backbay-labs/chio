use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::budget_store::{
    AuthorizedBudgetHold, BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest,
    BudgetEventAuthority, BudgetMutationKind, BudgetMutationRecord, DeniedBudgetHold,
};
use chio_kernel::{BudgetStore, BudgetStoreError, BudgetUsageRecord};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

mod model;
mod replication;
mod rows;
mod schema;
mod store;
mod trait_impl;

#[cfg(test)]
#[path = "budget_store/tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;

use model::{HoldDisposition, SqliteBudgetHold};
use replication::*;
use rows::*;
use schema::*;

pub struct SqliteBudgetStore {
    connection: Mutex<Connection>,
}
