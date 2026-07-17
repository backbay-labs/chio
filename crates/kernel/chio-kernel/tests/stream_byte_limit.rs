//! The kernel enforces max_stream_total_bytes at the invoke seam.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_kernel::runtime::{
    enforce_stream_byte_limit, push_chunk_bounded, ToolCallChunk, ToolCallStream,
};
use chio_kernel::KernelError;

fn chunk(payload: &str) -> ToolCallChunk {
    ToolCallChunk {
        data: serde_json::json!({ "text": payload }),
    }
}

#[test]
fn oversized_stream_is_denied_with_overloaded_streambytes() {
    let stream = ToolCallStream {
        chunks: vec![chunk("aaaa"), chunk("bbbb"), chunk("cccc")],
    };
    // A tiny budget forces a breach.
    let err = enforce_stream_byte_limit(&stream, 8).unwrap_err();
    assert!(
        matches!(
            err,
            KernelError::Overloaded {
                resource: chio_kernel::OverloadResource::StreamBytes
            }
        ),
        "expected Overloaded {{ StreamBytes }}, got {err:?}"
    );
}

#[test]
fn within_budget_stream_is_allowed() {
    let stream = ToolCallStream {
        chunks: vec![chunk("x")],
    };
    assert!(
        enforce_stream_byte_limit(&stream, 0).is_ok(),
        "0 = unlimited"
    );
    assert!(enforce_stream_byte_limit(&stream, 1_000_000).is_ok());
}

#[test]
fn push_chunk_bounded_sheds_on_chunk_count_even_under_byte_cap() {
    // A byte-only bound lets a flood of tiny chunks that never trips
    // `max_total_bytes` grow the accumulator without bound. With a generous byte cap
    // but a chunk cap of 2, the 3rd tiny chunk must shed with
    // Overloaded { StreamChunks } rather than being retained.
    let mut acc: Vec<ToolCallChunk> = Vec::new();
    let mut running_bytes = 0u64;
    let byte_cap = 1_000_000u64; // never reached by tiny chunks
    let chunk_cap = 2u64;

    // First two tiny chunks fit within both caps.
    push_chunk_bounded(
        &mut acc,
        &mut running_bytes,
        chunk("a"),
        byte_cap,
        chunk_cap,
    )
    .unwrap();
    push_chunk_bounded(
        &mut acc,
        &mut running_bytes,
        chunk("b"),
        byte_cap,
        chunk_cap,
    )
    .unwrap();
    assert_eq!(acc.len(), 2);

    // The third chunk trips the chunk-count cap (bytes still far under the byte cap).
    let err = push_chunk_bounded(
        &mut acc,
        &mut running_bytes,
        chunk("c"),
        byte_cap,
        chunk_cap,
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            KernelError::Overloaded {
                resource: chio_kernel::OverloadResource::StreamChunks
            }
        ),
        "expected Overloaded {{ StreamChunks }}, got {err:?}"
    );
    // The accumulator stayed bounded at the cap: the rejected chunk was not retained.
    assert_eq!(acc.len(), 2, "rejected chunk must not grow the accumulator");
}

#[test]
fn push_chunk_bounded_chunk_cap_zero_is_unlimited() {
    // `0 = unlimited` for the chunk cap, mirroring the byte cap convention.
    let mut acc: Vec<ToolCallChunk> = Vec::new();
    let mut running_bytes = 0u64;
    for i in 0..1000 {
        push_chunk_bounded(&mut acc, &mut running_bytes, chunk(&format!("c{i}")), 0, 0).unwrap();
    }
    assert_eq!(acc.len(), 1000);
}
