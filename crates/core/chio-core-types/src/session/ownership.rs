use serde::{Deserialize, Serialize};

/// Transport family that owns a logical runtime session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionTransport {
    InProcess,
    Stdio,
    StreamableHttp,
}

/// Canonical owner for work and terminal state within a session.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkOwner {
    Request,
    Task,
}

/// Canonical owner for a stream surface within a session.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StreamOwner {
    RequestStream,
    SessionNotificationStream,
}

/// Ownership model for request-scoped work.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RequestOwnershipSnapshot {
    pub work_owner: WorkOwner,
    pub result_stream_owner: StreamOwner,
    pub terminal_state_owner: WorkOwner,
}

impl RequestOwnershipSnapshot {
    pub fn request_owned() -> Self {
        Self {
            work_owner: WorkOwner::Request,
            result_stream_owner: StreamOwner::RequestStream,
            terminal_state_owner: WorkOwner::Request,
        }
    }
}

/// Ownership model for task-scoped work.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TaskOwnershipSnapshot {
    pub work_owner: WorkOwner,
    pub result_stream_owner: StreamOwner,
    pub status_notification_owner: StreamOwner,
    pub terminal_state_owner: WorkOwner,
}

impl TaskOwnershipSnapshot {
    pub fn task_owned() -> Self {
        Self {
            work_owner: WorkOwner::Task,
            result_stream_owner: StreamOwner::RequestStream,
            status_notification_owner: StreamOwner::SessionNotificationStream,
            terminal_state_owner: WorkOwner::Task,
        }
    }
}
