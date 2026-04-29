//! Integration tests for the streaming state machine transitions:
//!
//! - Idle -> Buffering on `StartBlock`
//! - Buffering -> Buffering on `AppendBytes`
//! - Buffering -> Emitting on `FinishBlock`
//! - Emitting -> Closed on `Close`
//! - Invalid transitions return errors (e.g., `AppendBytes` in `Idle`)
//! - Multiple blocks in sequence: Idle -> Buffering -> Emitting -> Buffering
//!   -> Emitting -> Closed

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_tool_call_fabric::stream::{
    BlockKind, BufferedBlock, StreamError, StreamEvent, StreamPhase,
};

#[test]
fn idle_to_buffering_on_start_block() {
    let phase = StreamPhase::Idle;
    let next = phase
        .transition(StreamEvent::StartBlock {
            block_id: "tool_call_1".to_string(),
            kind: BlockKind::ToolCall,
        })
        .unwrap();
    match next {
        StreamPhase::Buffering(block) => {
            assert_eq!(block.block_id, "tool_call_1");
            assert_eq!(block.kind, BlockKind::ToolCall);
            assert!(block.bytes.is_empty());
        }
        other => panic!("expected Buffering, got {other}"),
    }
}

#[test]
fn buffering_to_buffering_on_append_bytes() {
    let phase = StreamPhase::Buffering(BufferedBlock::new("blk", BlockKind::ToolCall));
    let next = phase
        .transition(StreamEvent::AppendBytes {
            chunk: b"hello".to_vec(),
        })
        .unwrap();
    let buf = next.buffered().expect("still buffering");
    assert_eq!(buf.bytes, b"hello");
}

#[test]
fn buffering_accumulates_across_multiple_append_bytes() {
    let phase = StreamPhase::Buffering(BufferedBlock::new("blk", BlockKind::ToolCall));
    let after_first = phase
        .transition(StreamEvent::AppendBytes {
            chunk: b"hello ".to_vec(),
        })
        .unwrap();
    let after_second = after_first
        .transition(StreamEvent::AppendBytes {
            chunk: b"world".to_vec(),
        })
        .unwrap();
    let buf = after_second.buffered().unwrap();
    assert_eq!(buf.bytes, b"hello world");
    assert_eq!(buf.block_id, "blk");
}

#[test]
fn buffering_to_emitting_on_finish_block() {
    let phase = StreamPhase::Buffering(BufferedBlock::new("blk", BlockKind::ToolCall));
    let next = phase.transition(StreamEvent::FinishBlock).unwrap();
    assert_eq!(next, StreamPhase::Emitting);
}

#[test]
fn emitting_to_closed_on_close() {
    let phase = StreamPhase::Emitting;
    let next = phase.transition(StreamEvent::Close).unwrap();
    assert_eq!(next, StreamPhase::Closed);
    assert!(next.is_closed());
}

#[test]
fn idle_to_closed_on_close() {
    let phase = StreamPhase::Idle;
    let next = phase.transition(StreamEvent::Close).unwrap();
    assert_eq!(next, StreamPhase::Closed);
}

#[test]
fn buffering_to_closed_on_close_drops_buffer() {
    let phase = StreamPhase::Buffering(BufferedBlock {
        block_id: "blk".to_string(),
        bytes: b"unflushed".to_vec(),
        kind: BlockKind::ToolCall,
    });
    let next = phase.transition(StreamEvent::Close).unwrap();
    assert_eq!(next, StreamPhase::Closed);
}

#[test]
fn append_bytes_in_idle_is_invalid() {
    let phase = StreamPhase::Idle;
    let err = phase
        .transition(StreamEvent::AppendBytes {
            chunk: b"x".to_vec(),
        })
        .unwrap_err();
    match err {
        StreamError::NoBlockInFlight { phase, event } => {
            assert_eq!(phase, "Idle");
            assert_eq!(event, "AppendBytes");
        }
        other => panic!("expected NoBlockInFlight, got {other:?}"),
    }
}

#[test]
fn finish_block_in_idle_is_invalid() {
    let phase = StreamPhase::Idle;
    let err = phase.transition(StreamEvent::FinishBlock).unwrap_err();
    assert!(matches!(err, StreamError::NoBlockInFlight { .. }));
}

#[test]
fn append_bytes_in_emitting_is_invalid() {
    let phase = StreamPhase::Emitting;
    let err = phase
        .transition(StreamEvent::AppendBytes {
            chunk: b"x".to_vec(),
        })
        .unwrap_err();
    assert!(matches!(err, StreamError::NoBlockInFlight { .. }));
}

#[test]
fn finish_block_in_emitting_is_invalid() {
    let phase = StreamPhase::Emitting;
    let err = phase.transition(StreamEvent::FinishBlock).unwrap_err();
    assert!(matches!(err, StreamError::NoBlockInFlight { .. }));
}

#[test]
fn start_block_while_buffering_is_invalid() {
    let phase = StreamPhase::Buffering(BufferedBlock::new("first", BlockKind::ToolCall));
    let err = phase
        .transition(StreamEvent::StartBlock {
            block_id: "second".to_string(),
            kind: BlockKind::ToolCall,
        })
        .unwrap_err();
    match err {
        StreamError::BlockAlreadyOpen { previous } => assert_eq!(previous, "first"),
        other => panic!("expected BlockAlreadyOpen, got {other:?}"),
    }
}

#[test]
fn closed_is_terminal_for_every_event() {
    let closed = StreamPhase::Closed;
    let events = vec![
        StreamEvent::StartBlock {
            block_id: "x".to_string(),
            kind: BlockKind::Text,
        },
        StreamEvent::AppendBytes {
            chunk: b"x".to_vec(),
        },
        StreamEvent::FinishBlock,
        StreamEvent::Close,
    ];
    for ev in events {
        let err = closed.transition(ev).unwrap_err();
        assert!(matches!(err, StreamError::AlreadyClosed { .. }));
    }
}

#[test]
fn multiple_blocks_full_lifecycle() {
    // Idle -> Buffering -> Emitting -> Buffering -> Emitting -> Closed
    let phase = StreamPhase::Idle;

    // First block: tool_call
    let phase = phase
        .transition(StreamEvent::StartBlock {
            block_id: "call_1".to_string(),
            kind: BlockKind::ToolCall,
        })
        .unwrap();
    assert!(matches!(phase, StreamPhase::Buffering(_)));

    let phase = phase
        .transition(StreamEvent::AppendBytes {
            chunk: br#"{"q":"a"}"#.to_vec(),
        })
        .unwrap();
    assert_eq!(phase.buffered().unwrap().bytes, br#"{"q":"a"}"#);

    let phase = phase.transition(StreamEvent::FinishBlock).unwrap();
    assert_eq!(phase, StreamPhase::Emitting);

    // Second block: text
    let phase = phase
        .transition(StreamEvent::StartBlock {
            block_id: "txt_1".to_string(),
            kind: BlockKind::Text,
        })
        .unwrap();
    match &phase {
        StreamPhase::Buffering(b) => {
            assert_eq!(b.block_id, "txt_1");
            assert_eq!(b.kind, BlockKind::Text);
        }
        other => panic!("expected Buffering, got {other}"),
    }

    let phase = phase.transition(StreamEvent::FinishBlock).unwrap();
    assert_eq!(phase, StreamPhase::Emitting);

    let phase = phase.transition(StreamEvent::Close).unwrap();
    assert_eq!(phase, StreamPhase::Closed);
    assert!(phase.is_closed());
}

#[test]
fn block_kinds_are_distinct() {
    // Sanity check that BlockKind variants are not collapsed by clone/PartialEq.
    let kinds = [
        BlockKind::ToolCall,
        BlockKind::ToolResult,
        BlockKind::Text,
        BlockKind::Other,
    ];
    for (i, a) in kinds.iter().enumerate() {
        for (j, b) in kinds.iter().enumerate() {
            if i == j {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b);
            }
        }
    }
}
