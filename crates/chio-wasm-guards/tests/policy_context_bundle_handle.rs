//! Tests for policy-context bundle handles and blob lookup.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use sha2::{Digest, Sha256};

use chio_wasm_guards::bundle_store::{BundleStore, InMemoryBundleStore};

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[test]
fn in_memory_bundle_store_fetches_blob_by_sha256() {
    let blob = b"bundle payload".to_vec();
    let sha256 = digest(&blob);
    let store = InMemoryBundleStore::new().with_blob(sha256, blob.clone());

    let fetched = store.fetch_blob(&sha256).expect("blob should exist");

    assert_eq!(fetched, blob);
}

#[test]
fn in_memory_bundle_store_missing_blob_fails_closed() {
    let store = InMemoryBundleStore::new();
    let sha256 = digest(b"missing payload");

    let err = store
        .fetch_blob(&sha256)
        .expect_err("missing blob should fail closed");

    assert!(err.to_string().contains("bundle blob not found"));
}

#[cfg(feature = "wasmtime-runtime")]
mod host_resource_tests {
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    use wasmtime::component::Resource;

    use chio_wasm_guards::host::bindings::chio::guard::host::Host;
    use chio_wasm_guards::host::bindings::chio::guard::policy_context::HostBundleHandle;
    use chio_wasm_guards::host::{BundleHandle, WasmHostState};

    use super::{digest, InMemoryBundleStore};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn block_on_ready<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(NoopWaker));
        let mut cx = Context::from_waker(&waker);
        let mut future = pin!(future);

        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("host future should complete without suspension"),
        }
    }

    #[test]
    fn policy_context_bundle_handle_reads_blob_slice() {
        let blob = b"policy bundle bytes".to_vec();
        let sha256 = digest(&blob);
        let store = InMemoryBundleStore::new().with_blob(sha256, blob);
        let mut state = WasmHostState::with_bundle_store(HashMap::new(), Arc::new(store));

        let handle = block_on_ready(HostBundleHandle::new(
            &mut state,
            format!("sha256:{}", hex::encode(sha256)),
        ))
        .expect("bundle handle should open");
        let rep = handle.rep();

        let read = block_on_ready(HostBundleHandle::read(
            &mut state,
            Resource::<BundleHandle>::new_borrow(rep),
            7,
            6,
        ))
        .expect("read should not trap")
        .expect("blob should exist");

        assert_eq!(read, b"bundle");

        let flat_read = block_on_ready(Host::fetch_blob(&mut state, rep, 0, 6))
            .expect("fetch-blob should not trap")
            .expect("blob should exist");

        assert_eq!(flat_read, b"policy");

        block_on_ready(HostBundleHandle::close(
            &mut state,
            Resource::<BundleHandle>::new_borrow(rep),
        ))
        .expect("close should release the bundle handle");

        let after_close = block_on_ready(HostBundleHandle::read(
            &mut state,
            Resource::<BundleHandle>::new_borrow(rep),
            0,
            1,
        ))
        .expect("closed handle read should return an error result");

        assert!(after_close.is_err());
    }

    #[test]
    fn policy_context_bundle_handle_missing_blob_fails_closed() {
        let sha256 = digest(b"not inserted");
        let mut state =
            WasmHostState::with_bundle_store(HashMap::new(), Arc::new(InMemoryBundleStore::new()));

        let handle = block_on_ready(HostBundleHandle::new(&mut state, hex::encode(sha256)))
            .expect("digest id should open a handle");
        let rep = handle.rep();

        let read = block_on_ready(HostBundleHandle::read(
            &mut state,
            Resource::<BundleHandle>::new_borrow(rep),
            0,
            32,
        ))
        .expect("missing blob should not trap");

        let err = match read {
            Ok(bytes) => panic!("missing blob returned bytes: {bytes:?}"),
            Err(err) => err,
        };
        assert!(err.contains("bundle blob not found"));
    }
}
