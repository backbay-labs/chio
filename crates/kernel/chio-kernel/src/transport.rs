//! Length-prefixed canonical JSON transport.
//!
//! Wire format: `[4-byte big-endian length][canonical JSON bytes]`
//!
//! The transport is generic over `Read` and `Write` so it works with pipes,
//! TCP, Unix domain sockets, or in-memory buffers for testing.

use std::io::{BufReader, BufWriter, Read, Write};

use chio_core::canonical::canonical_json_bytes;
use chio_core::message::{AgentMessage, KernelMessage};

/// Errors produced by the transport layer.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("message too large: {size} bytes (max {max})")]
    MessageTooLarge { size: u32, max: u32 },

    #[error("json deserialization error: {0}")]
    Deserialize(#[from] serde_json::Error),

    #[error("canonical json serialization error: {0}")]
    Serialize(String),

    #[error("connection closed")]
    ConnectionClosed,
}

/// Maximum message size: 16 MiB.
const MAX_MESSAGE_SIZE: u32 = 16 * 1024 * 1024;

/// Length-prefixed canonical JSON transport.
///
/// Reads `AgentMessage` frames from the reader and writes `KernelMessage`
/// frames to the writer. Each frame is a 4-byte big-endian length prefix
/// followed by that many bytes of canonical JSON.
pub struct ChioTransport<R: Read, W: Write> {
    reader: BufReader<R>,
    writer: BufWriter<W>,
}

impl<R: Read, W: Write> ChioTransport<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer: BufWriter::new(writer),
        }
    }

    /// Read one `AgentMessage` from the transport.
    ///
    /// Blocks until a complete frame is available. Returns
    /// `TransportError::ConnectionClosed` if the reader reaches EOF before
    /// a complete frame is read.
    pub fn recv(&mut self) -> Result<AgentMessage, TransportError> {
        let bytes = read_frame(&mut self.reader)?;
        let msg: AgentMessage = serde_json::from_slice(&bytes)?;
        Ok(msg)
    }

    /// Send one `KernelMessage` over the transport.
    ///
    /// The message is serialized to canonical JSON (RFC 8785) and written
    /// as a length-prefixed frame. The writer is flushed after each send.
    pub fn send(&mut self, msg: &KernelMessage) -> Result<(), TransportError> {
        let bytes =
            canonical_json_bytes(msg).map_err(|e| TransportError::Serialize(e.to_string()))?;
        write_frame(&mut self.writer, &bytes)?;
        self.writer.flush()?;
        Ok(())
    }
}

/// Read a single length-prefixed frame from a reader.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>, TransportError> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(TransportError::ConnectionClosed);
        }
        Err(e) => return Err(TransportError::Io(e)),
    }

    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MESSAGE_SIZE {
        return Err(TransportError::MessageTooLarge {
            size: len,
            max: MAX_MESSAGE_SIZE,
        });
    }

    let mut buf = vec![0u8; len as usize];
    match reader.read_exact(&mut buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(TransportError::ConnectionClosed);
        }
        Err(e) => return Err(TransportError::Io(e)),
    }
    Ok(buf)
}

/// Write a single length-prefixed frame to a writer.
pub fn write_frame<W: Write>(writer: &mut W, data: &[u8]) -> Result<(), TransportError> {
    let len = u32::try_from(data.len()).map_err(|_| TransportError::MessageTooLarge {
        size: u32::MAX,
        max: MAX_MESSAGE_SIZE,
    })?;
    if len > MAX_MESSAGE_SIZE {
        return Err(TransportError::MessageTooLarge {
            size: len,
            max: MAX_MESSAGE_SIZE,
        });
    }
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(data)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_core::capability::{
        scope::{ChioScope, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    };
    use chio_core::crypto::Keypair;
    use chio_core::receipt::{
        body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
        metadata::GuardEvidence,
    };
    use std::io::Cursor;

    fn make_token(kp: &Keypair) -> CapabilityToken {
        let body = CapabilityTokenBody {
            id: "cap-transport-001".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "srv".to_string(),
                    tool_name: "echo".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            issued_at: 1000,
            expires_at: 2000,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        };
        CapabilityToken::sign(body, kp).unwrap()
    }

    fn make_receipt(kp: &Keypair) -> ChioReceipt {
        let body = ChioReceiptBody {
            id: "rcpt-transport-001".to_string(),
            timestamp: 1500,
            capability_id: "cap-transport-001".to_string(),
            tool_server: "srv".to_string(),
            tool_name: "echo".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"text": "hello"})).unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: chio_core::sha256_hex(br#"{"output":"world"}"#),
            policy_hash: "deadbeef".to_string(),
            evidence: vec![GuardEvidence {
                guard_name: "ShellCommandGuard".to_string(),
                verdict: true,
                details: None,
            }],
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: kp.public_key(),
            bbs_projection_version: None,
        };
        ChioReceipt::sign(body, kp).unwrap()
    }

    #[test]
    fn frame_roundtrip() {
        let data = b"hello, world";
        let mut buf = Vec::new();
        write_frame(&mut buf, data).unwrap();

        let mut cursor = Cursor::new(buf);
        let recovered = read_frame(&mut cursor).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn length_prefix_encoding() {
        let data = vec![0xAA; 256];
        let mut buf = Vec::new();
        write_frame(&mut buf, &data).unwrap();

        // First 4 bytes should be big-endian 256.
        assert_eq!(&buf[..4], &[0, 0, 1, 0]);
        assert_eq!(buf.len(), 4 + 256);
    }

    #[test]
    fn transport_agent_message_roundtrip() {
        let kp = Keypair::generate();
        let msg = AgentMessage::ToolCallRequest {
            id: "req-001".to_string(),
            capability_token: Box::new(make_token(&kp)),
            server_id: "srv".to_string(),
            tool: "echo".to_string(),
            params: Box::new(serde_json::json!({"text": "hello"})),
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: None,
        };

        // Serialize to a buffer (using canonical JSON, same as KernelMessage path).
        let bytes = canonical_json_bytes(&msg).expect("canonical serialization");
        let mut wire = Vec::new();
        write_frame(&mut wire, &bytes).unwrap();

        // Read it back.
        let mut cursor = Cursor::new(wire);
        let frame = read_frame(&mut cursor).unwrap();
        let recovered: AgentMessage = serde_json::from_slice(&frame).unwrap();

        let (id, server_id, tool) = match recovered {
            AgentMessage::ToolCallRequest {
                id,
                server_id,
                tool,
                ..
            } => Some((id, server_id, tool)),
            _ => None,
        }
        .expect("wrong variant");
        assert_eq!(id, "req-001");
        assert_eq!(server_id, "srv");
        assert_eq!(tool, "echo");
    }

    #[test]
    fn transport_kernel_message_roundtrip() {
        let kp = Keypair::generate();
        let receipt = make_receipt(&kp);
        let kernel_msg = KernelMessage::ToolCallResponse {
            id: "req-001".to_string(),
            result: chio_core::message::ToolCallResult::Ok {
                value: serde_json::json!({"output": "world"}),
            },
            receipt: Box::new(receipt),
            execution_nonce: None,
        };

        // Use a shared buffer as the "pipe".
        let mut wire = Vec::new();
        {
            let bytes = canonical_json_bytes(&kernel_msg).expect("canonical serialization");
            write_frame(&mut wire, &bytes).unwrap();
        }

        let mut cursor = Cursor::new(wire);
        let frame = read_frame(&mut cursor).unwrap();
        let recovered: KernelMessage = serde_json::from_slice(&frame).unwrap();

        let (id, result, receipt) = match recovered {
            KernelMessage::ToolCallResponse {
                id,
                result,
                receipt,
                ..
            } => Some((id, result, receipt)),
            _ => None,
        }
        .expect("wrong variant");
        assert_eq!(id, "req-001");
        assert!(matches!(
            result,
            chio_core::message::ToolCallResult::Ok { .. }
        ));
        assert!(receipt.verify_signature().unwrap());
    }

    #[test]
    fn transport_kernel_chunk_roundtrip() {
        let kernel_msg = KernelMessage::ToolCallChunk {
            id: "req-stream-1".to_string(),
            chunk_index: 1,
            data: serde_json::json!({"delta": "world"}),
        };

        let mut wire = Vec::new();
        {
            let bytes = canonical_json_bytes(&kernel_msg).expect("canonical serialization");
            write_frame(&mut wire, &bytes).unwrap();
        }

        let mut cursor = Cursor::new(wire);
        let frame = read_frame(&mut cursor).unwrap();
        let recovered: KernelMessage = serde_json::from_slice(&frame).unwrap();

        let (id, chunk_index, data) = match recovered {
            KernelMessage::ToolCallChunk {
                id,
                chunk_index,
                data,
            } => Some((id, chunk_index, data)),
            _ => None,
        }
        .expect("wrong variant");
        assert_eq!(id, "req-stream-1");
        assert_eq!(chunk_index, 1);
        assert_eq!(data["delta"], "world");
    }

    #[test]
    fn transport_send_recv_roundtrip() {
        let agent_msg = AgentMessage::Heartbeat;
        let agent_bytes = canonical_json_bytes(&agent_msg).expect("canonical");
        let mut agent_wire = Vec::new();
        write_frame(&mut agent_wire, &agent_bytes).unwrap();

        let kernel_msg = KernelMessage::Heartbeat;

        // agent_wire is what the "agent" wrote, kernel_buf is where the
        // kernel writes its response.
        let kernel_buf: Vec<u8> = Vec::new();
        let mut transport = ChioTransport::new(Cursor::new(agent_wire), kernel_buf);

        let received = transport.recv().unwrap();
        assert!(matches!(received, AgentMessage::Heartbeat));

        transport.send(&kernel_msg).unwrap();
    }

    #[test]
    fn connection_closed_on_empty_read() {
        let empty: Vec<u8> = Vec::new();
        let mut cursor = Cursor::new(empty);
        let err = read_frame(&mut cursor).unwrap_err();
        assert!(matches!(err, TransportError::ConnectionClosed));
    }

    #[test]
    fn rejects_oversized_frame() {
        // Craft a length prefix claiming 20 MiB.
        let len: u32 = 20 * 1024 * 1024;
        let mut buf = Vec::new();
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&[0u8; 16]); // some trailing data

        let mut cursor = Cursor::new(buf);
        let err = read_frame(&mut cursor).unwrap_err();
        assert!(matches!(err, TransportError::MessageTooLarge { .. }));
    }

    #[test]
    fn multiple_frames_in_sequence() {
        let mut wire = Vec::new();
        write_frame(&mut wire, b"first").unwrap();
        write_frame(&mut wire, b"second").unwrap();
        write_frame(&mut wire, b"third").unwrap();

        let mut cursor = Cursor::new(wire);
        assert_eq!(read_frame(&mut cursor).unwrap(), b"first");
        assert_eq!(read_frame(&mut cursor).unwrap(), b"second");
        assert_eq!(read_frame(&mut cursor).unwrap(), b"third");

        // Next read should get ConnectionClosed.
        assert!(matches!(
            read_frame(&mut cursor).unwrap_err(),
            TransportError::ConnectionClosed
        ));
    }
}
