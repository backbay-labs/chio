#![allow(unused_imports)]

use std::path::Path;

use chio_core::capability::{
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_kernel::ReceiptStore;
use chio_store_sqlite::SqliteReceiptStore;

pub(crate) fn make_capability_token(
    id: &str,
    subject_keypair: &Keypair,
    issuer_keypair: &Keypair,
) -> CapabilityToken {
    let body = CapabilityTokenBody {
        id: id.to_string(),
        issuer: issuer_keypair.public_key(),
        subject: subject_keypair.public_key(),
        scope: ChioScope::default(),
        issued_at: 1000,
        expires_at: 9999999999,
        delegation_chain: vec![],
    };
    CapabilityToken::sign(body, issuer_keypair).expect("sign capability token")
}

pub(crate) fn prepopulate_lineage(db_path: &Path, entries: &[(&CapabilityToken, Option<&str>)]) {
    let store = SqliteReceiptStore::open(db_path).expect("open receipt store for lineage");
    for (token, parent_id) in entries {
        store
            .record_capability_snapshot(token, *parent_id)
            .expect("record_capability_snapshot");
    }
}

pub(crate) fn run_large_stack_test(name: &str, test_fn: fn()) {
    std::thread::Builder::new()
        .name(name.to_string())
        .stack_size(16 * 1024 * 1024)
        .spawn(test_fn)
        .expect("spawn large-stack test thread")
        .join()
        .expect("join large-stack test thread");
}
