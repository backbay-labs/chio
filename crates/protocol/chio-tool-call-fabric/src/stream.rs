//! Streaming state machine for the tool-call fabric.
//!
//! Mediates provider streams (OpenAI SSE, Anthropic event-stream, Bedrock
//! `ConverseStream`) at the tool-use block boundary: events are buffered while
//! the kernel resolves a verdict, then flushed on allow or dropped on deny.
//!
//! - [`StreamPhase`] is the finite-state enum every adapter drives.
//! - [`BufferedBlock`] is the per-block buffer carried while the phase is
//!   [`StreamPhase::Buffering`].
//! - [`BlockKind`] tags whether the block represents a tool call, a tool
//!   result, plain text, or some other provider construct.
//! - [`StreamEvent`] enumerates the inputs that drive transitions.
//! - [`StreamError`] reports invalid transitions.

use std::fmt;

/// Default upper bound on bytes accumulated in a single [`BufferedBlock`].
///
/// Streams hold tool-call arguments in memory while the kernel resolves a
/// verdict. Without an upper bound, a malicious or runaway upstream could
/// pin unbounded heap until the verdict resolves. The default of 1 MiB is
/// generous for tool-call argument JSON; callers that expect larger blocks
/// can opt into [`StreamPhase::transition_with_limit`].
pub const DEFAULT_MAX_BUFFERED_BLOCK_BYTES: usize = 1024 * 1024;

/// Default upper bound on raw provider frames retained for one buffered block.
///
/// Argument-byte limits alone do not cap zero-length deltas or large provider
/// metadata frames that must remain withheld until a verdict resolves.
pub const DEFAULT_MAX_BUFFERED_RAW_FRAMES: usize = 4096;

/// Kind of a buffered block.
///
/// Each provider exposes a small handful of block kinds that the fabric needs
/// to distinguish at the state-machine level:
///
/// - `ToolCall` covers OpenAI `tool_call` items, Anthropic `tool_use` blocks,
///   and Bedrock `toolUse` blocks. These are the verdict-bearing blocks.
/// - `ToolResult` covers the lowered side: OpenAI `tool_call_output`,
///   Anthropic `tool_result` blocks, Bedrock `toolResult` blocks.
/// - `Text` covers plain text content blocks that pass through verbatim.
/// - `Other` is the open variant for thinking blocks, citations, and any
///   future provider construct that does not need verdict mediation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockKind {
    ToolCall,
    ToolResult,
    Text,
    Other,
}

/// A single buffered block, identified by the upstream block id, tagged by
/// kind, and carrying the bytes accumulated so far.
///
/// The fabric never inspects `bytes` at this layer; it stores them so the
/// adapter can either flush them downstream on Allow or discard them on Deny
/// without re-running its parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferedBlock {
    /// Provider block identifier (OpenAI `call_id`, Anthropic block `id`,
    /// Bedrock `toolUseId`). Adapters preserve the upstream value verbatim.
    pub block_id: String,
    /// Raw bytes accumulated for this block. Encoding is provider-specific;
    /// the fabric does not interpret them.
    pub bytes: Vec<u8>,
    /// Kind of the buffered block.
    pub kind: BlockKind,
}

impl BufferedBlock {
    /// Construct a new empty buffer for `block_id` of `kind`.
    pub fn new(block_id: impl Into<String>, kind: BlockKind) -> Self {
        Self {
            block_id: block_id.into(),
            bytes: Vec::new(),
            kind,
        }
    }

    /// Append `chunk` to the buffer.
    pub fn append(&mut self, chunk: &[u8]) {
        self.bytes.extend_from_slice(chunk);
    }
}

/// Phase of the streaming state machine.
///
/// The contract follows the doc's "Streaming verdict semantics" diagram, but
/// collapses the provider-specific verdict-resolution sub-states (`ToolUseSeen`,
/// `AwaitingVerdict`, `Allowed`, `Denied`, `Streaming`) into a single
/// adapter-driven transition: each adapter calls into the kernel between
/// `Buffering` and `Emitting`, and only once a verdict resolves does the
/// fabric move to `Emitting`. The fabric intentionally does not represent
/// in-flight verdict requests at this layer; that lives one layer up.
///
/// Transitions:
///
/// - `Idle` + `StartBlock { .. }` -> `Buffering(block)`
/// - `Buffering(block)` + `AppendBytes { .. }` -> `Buffering(block')`
/// - `Buffering(block)` + `FinishBlock { .. }` -> `Emitting`
/// - `Emitting` + `StartBlock { .. }` -> `Buffering(block)` (next block)
/// - `Emitting` + `Close` -> `Closed`
/// - `Idle` + `Close` -> `Closed`
/// - `Buffering(_)` + `Close` -> `Closed` (drops the in-flight buffer)
/// - any other event in any state returns [`StreamError`].
///
/// `Closed` is terminal: any further event yields
/// [`StreamError::AlreadyClosed`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum StreamPhase {
    /// No block in flight. The adapter is idle between blocks (or before the
    /// first block) and forwards non-tool deltas verbatim downstream.
    #[default]
    Idle,
    /// A block has started and the adapter is buffering its bytes pending the
    /// verdict resolution at `FinishBlock` time.
    Buffering(BufferedBlock),
    /// The verdict resolved and buffered bytes are being emitted downstream.
    /// Subsequent blocks transition back through `Buffering`; closing the
    /// stream transitions to `Closed`.
    Emitting,
    /// Terminal phase. The upstream stream is finished or was torn down.
    Closed,
}

/// Input that drives [`StreamPhase`] transitions.
///
/// Adapters surface upstream stream events as `StreamEvent`s and feed them
/// into [`StreamPhase::transition`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    /// A new block started (OpenAI `response.output_item.added`, Anthropic
    /// `content_block_start`, Bedrock `contentBlockStart`).
    StartBlock { block_id: String, kind: BlockKind },
    /// A delta chunk for the current block (OpenAI
    /// `response.function_call_arguments.delta`, Anthropic `input_json_delta`,
    /// Bedrock `contentBlockDelta`).
    AppendBytes { chunk: Vec<u8> },
    /// The current block ended (OpenAI `response.output_item.done`, Anthropic
    /// `content_block_stop`, Bedrock `contentBlockStop`).
    FinishBlock,
    /// The upstream stream was closed (`response.completed` /
    /// `message_stop` / `messageStop`, or the transport tore down).
    Close,
}

/// Error returned by [`StreamPhase::transition`] for an invalid transition.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StreamError {
    /// The phase had no current block but an event that requires one
    /// (`AppendBytes`, `FinishBlock`) arrived.
    #[error("event {event} is invalid in phase {phase}: no block is buffering")]
    NoBlockInFlight {
        phase: &'static str,
        event: &'static str,
    },
    /// A new block started while the previous block was still buffering.
    /// Adapters must finish or close the previous block first.
    #[error(
        "StartBlock arrived while a block is already buffering (previous block_id {previous})"
    )]
    BlockAlreadyOpen { previous: String },
    /// The stream is already closed; no further events are accepted.
    #[error("stream is closed; event {event} ignored")]
    AlreadyClosed { event: &'static str },
    /// Buffering this chunk would push the in-flight block past its
    /// configured byte cap. Adapters should fail the upstream stream
    /// rather than continue buffering.
    #[error(
        "AppendBytes would grow buffered block {block_id} from {buffered} to {projected} bytes, exceeding limit {limit}"
    )]
    BufferOverflow {
        block_id: String,
        buffered: usize,
        projected: usize,
        limit: usize,
    },
}

impl StreamPhase {
    /// Apply `event` to this phase and return the next phase.
    ///
    /// Errors leave the caller's previous phase untouched (the function takes
    /// `&self` and returns a fresh `StreamPhase`), so an adapter that wants to
    /// stay in its current state on an invalid event can discard the
    /// error.
    ///
    /// Buffered blocks are capped at [`DEFAULT_MAX_BUFFERED_BLOCK_BYTES`].
    /// Adapters that need a different cap (or none) should call
    /// [`StreamPhase::transition_with_limit`] directly.
    pub fn transition(&self, event: StreamEvent) -> Result<StreamPhase, StreamError> {
        self.transition_with_limit(event, DEFAULT_MAX_BUFFERED_BLOCK_BYTES)
    }

    /// Apply `event` to this phase, enforcing `max_buffered_bytes` on
    /// `AppendBytes`. See [`StreamPhase::transition`] for general semantics.
    ///
    /// `max_buffered_bytes` of 0 disables buffering entirely (any
    /// non-empty chunk overflows). `usize::MAX` effectively disables the
    /// cap for callers that have an upstream limit.
    pub fn transition_with_limit(
        &self,
        event: StreamEvent,
        max_buffered_bytes: usize,
    ) -> Result<StreamPhase, StreamError> {
        match (self, event) {
            // Closed is terminal; any event is a hard error.
            (StreamPhase::Closed, ev) => Err(StreamError::AlreadyClosed {
                event: event_label(&ev),
            }),

            // Close transitions any non-Closed state to Closed.
            (_, StreamEvent::Close) => Ok(StreamPhase::Closed),

            // Idle: only StartBlock is valid (besides Close, handled above).
            (StreamPhase::Idle, StreamEvent::StartBlock { block_id, kind }) => {
                Ok(StreamPhase::Buffering(BufferedBlock::new(block_id, kind)))
            }
            (StreamPhase::Idle, StreamEvent::AppendBytes { .. }) => {
                Err(StreamError::NoBlockInFlight {
                    phase: "Idle",
                    event: "AppendBytes",
                })
            }
            (StreamPhase::Idle, StreamEvent::FinishBlock) => Err(StreamError::NoBlockInFlight {
                phase: "Idle",
                event: "FinishBlock",
            }),

            // Buffering: AppendBytes extends, FinishBlock advances to Emitting,
            // StartBlock is a protocol error (previous block must finish first).
            (StreamPhase::Buffering(block), StreamEvent::AppendBytes { chunk }) => {
                let Some(projected) = projected_buffer_len(block.bytes.len(), chunk.len()) else {
                    return Err(StreamError::BufferOverflow {
                        block_id: block.block_id.clone(),
                        buffered: block.bytes.len(),
                        projected: usize::MAX,
                        limit: max_buffered_bytes,
                    });
                };
                if projected > max_buffered_bytes {
                    return Err(StreamError::BufferOverflow {
                        block_id: block.block_id.clone(),
                        buffered: block.bytes.len(),
                        projected,
                        limit: max_buffered_bytes,
                    });
                }
                let mut next = block.clone();
                next.append(&chunk);
                Ok(StreamPhase::Buffering(next))
            }
            (StreamPhase::Buffering(_), StreamEvent::FinishBlock) => Ok(StreamPhase::Emitting),
            (StreamPhase::Buffering(block), StreamEvent::StartBlock { .. }) => {
                Err(StreamError::BlockAlreadyOpen {
                    previous: block.block_id.clone(),
                })
            }

            // Emitting: StartBlock begins the next block; AppendBytes /
            // FinishBlock without an open block are protocol errors.
            (StreamPhase::Emitting, StreamEvent::StartBlock { block_id, kind }) => {
                Ok(StreamPhase::Buffering(BufferedBlock::new(block_id, kind)))
            }
            (StreamPhase::Emitting, StreamEvent::AppendBytes { .. }) => {
                Err(StreamError::NoBlockInFlight {
                    phase: "Emitting",
                    event: "AppendBytes",
                })
            }
            (StreamPhase::Emitting, StreamEvent::FinishBlock) => {
                Err(StreamError::NoBlockInFlight {
                    phase: "Emitting",
                    event: "FinishBlock",
                })
            }
        }
    }

    /// Borrow the buffered block, if the phase is [`StreamPhase::Buffering`].
    pub fn buffered(&self) -> Option<&BufferedBlock> {
        match self {
            StreamPhase::Buffering(b) => Some(b),
            _ => None,
        }
    }

    /// Whether this phase is terminal.
    pub fn is_closed(&self) -> bool {
        matches!(self, StreamPhase::Closed)
    }
}

impl fmt::Display for StreamPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamPhase::Idle => f.write_str("Idle"),
            StreamPhase::Buffering(_) => f.write_str("Buffering"),
            StreamPhase::Emitting => f.write_str("Emitting"),
            StreamPhase::Closed => f.write_str("Closed"),
        }
    }
}

fn projected_buffer_len(buffered: usize, chunk_len: usize) -> Option<usize> {
    buffered.checked_add(chunk_len)
}

fn event_label(ev: &StreamEvent) -> &'static str {
    match ev {
        StreamEvent::StartBlock { .. } => "StartBlock",
        StreamEvent::AppendBytes { .. } => "AppendBytes",
        StreamEvent::FinishBlock => "FinishBlock",
        StreamEvent::Close => "Close",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn default_phase_is_idle() {
        assert_eq!(StreamPhase::default(), StreamPhase::Idle);
    }

    #[test]
    fn idle_to_buffering_on_start_block() {
        let phase = StreamPhase::Idle;
        let next = phase
            .transition(StreamEvent::StartBlock {
                block_id: "blk_1".to_string(),
                kind: BlockKind::ToolCall,
            })
            .unwrap();
        let buf = next.buffered().unwrap();
        assert_eq!(buf.block_id, "blk_1");
        assert_eq!(buf.kind, BlockKind::ToolCall);
        assert!(buf.bytes.is_empty());
    }

    #[test]
    fn buffering_append_bytes_accumulates() {
        let phase = StreamPhase::Buffering(BufferedBlock::new("blk", BlockKind::ToolCall));
        let next = phase
            .transition(StreamEvent::AppendBytes {
                chunk: b"abc".to_vec(),
            })
            .unwrap();
        let buf = next.buffered().unwrap();
        assert_eq!(buf.bytes, b"abc");
    }

    #[test]
    fn projected_buffer_len_rejects_overflow() {
        assert_eq!(projected_buffer_len(8, 4), Some(12));
        assert_eq!(projected_buffer_len(usize::MAX - 1, 4), None);
    }

    #[test]
    fn buffering_finish_block_emits() {
        let phase = StreamPhase::Buffering(BufferedBlock::new("blk", BlockKind::ToolCall));
        let next = phase.transition(StreamEvent::FinishBlock).unwrap();
        assert_eq!(next, StreamPhase::Emitting);
    }

    #[test]
    fn close_is_terminal() {
        let closed = StreamPhase::Closed;
        let err = closed
            .transition(StreamEvent::AppendBytes {
                chunk: b"x".to_vec(),
            })
            .unwrap_err();
        assert!(matches!(err, StreamError::AlreadyClosed { .. }));
    }
    #[test]
    fn buffering_append_overflow_is_rejected() {
        let phase = StreamPhase::Buffering(BufferedBlock::new("blk_cap", BlockKind::ToolCall));
        let next = phase
            .transition_with_limit(
                StreamEvent::AppendBytes {
                    chunk: b"abcde".to_vec(),
                },
                4,
            )
            .unwrap_err();
        match next {
            StreamError::BufferOverflow {
                block_id,
                buffered,
                projected,
                limit,
            } => {
                assert_eq!(block_id, "blk_cap");
                assert_eq!(buffered, 0);
                assert_eq!(projected, 5);
                assert_eq!(limit, 4);
            }
            other => panic!("expected BufferOverflow, got {other:?}"),
        }
    }

    #[test]
    fn buffering_append_at_exact_limit_is_allowed() {
        let phase = StreamPhase::Buffering(BufferedBlock::new("blk_eq", BlockKind::ToolCall));
        let next = phase
            .transition_with_limit(
                StreamEvent::AppendBytes {
                    chunk: b"abcd".to_vec(),
                },
                4,
            )
            .unwrap();
        let buf = next.buffered().unwrap();
        assert_eq!(buf.bytes, b"abcd");
    }

    #[test]
    fn default_transition_caps_at_one_mib() {
        let phase = StreamPhase::Buffering(BufferedBlock::new("blk_huge", BlockKind::ToolCall));
        let oversized = vec![b'x'; DEFAULT_MAX_BUFFERED_BLOCK_BYTES + 1];
        let err = phase
            .transition(StreamEvent::AppendBytes { chunk: oversized })
            .unwrap_err();
        assert!(matches!(err, StreamError::BufferOverflow { .. }));
    }
}
