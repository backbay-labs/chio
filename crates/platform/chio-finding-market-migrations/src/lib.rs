//! Compile-time embedded SQLx migrations for the hosted cognition market.
//!
//! This crate depends on `sqlx-core` directly so migration support cannot
//! pull SQLx's optional SQLite driver into the workspace's independent
//! `rusqlite` native-library graph.

#![forbid(unsafe_code)]

pub static MIGRATOR: sqlx::migrate::Migrator =
    sqlx_macros::migrate!("../chio-finding-market-store-postgres/migrations");
