//! Agent-to-UI event types and classification.
//!
//! Events flowing from an agent to a UI client are classified by type,
//! target component, and action for policy enforcement and receipting.

use serde::{Deserialize, Serialize};

/// An event in the agent-to-UI stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgUiEvent {
    /// Unique event identifier.
    pub event_id: String,
    /// Unix timestamp (seconds) when the event was produced.
    pub timestamp: u64,
    /// Agent that produced this event.
    pub agent_id: String,
    /// Session this event belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// The type of event.
    pub event_type: EventType,
    /// Target UI component, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetComponent>,
    /// Action classification for policy matching.
    pub classification: EventClassification,
    /// Event payload (opaque JSON).
    pub payload: serde_json::Value,
}

/// Types of agent-to-UI events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Text content being streamed to the UI.
    TextStream,
    /// A state update to a UI component.
    StateUpdate,
    /// A navigation or routing event.
    Navigation,
    /// A UI component lifecycle event (create, destroy).
    Lifecycle,
    /// A form submission or input request.
    FormAction,
    /// A notification or alert.
    Notification,
    /// An error displayed to the user.
    Error,
    /// Custom event type for extensibility.
    Custom(String),
}

/// Target UI component for an event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetComponent {
    /// Component type (e.g. "chat-window", "sidebar", "modal").
    pub component_type: String,
    /// Optional component instance ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component_id: Option<String>,
}

/// Action classification for policy enforcement.
///
/// This categorizes what the event is doing from a security perspective,
/// allowing guards to enforce policies like "agents cannot navigate
/// away from the current page" or "agents cannot modify form fields".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventClassification {
    /// Read-only display of information.
    Display,
    /// Modification of UI state.
    Mutate,
    /// Navigation to a different view or URL.
    Navigate,
    /// Creation of a new UI element.
    Create,
    /// Destruction of a UI element.
    Destroy,
    /// Submission of data (forms, inputs).
    Submit,
    /// Request for user attention (alerts, modals).
    Alert,
}

impl AgUiEvent {
    pub(crate) fn validate_boundary(&self) -> Result<(), String> {
        validate_identity_field("event_id", &self.event_id)?;
        validate_identity_field("agent_id", &self.agent_id)?;
        if let Some(session_id) = &self.session_id {
            validate_identity_field("session_id", session_id)?;
        }
        if let Some(target) = &self.target {
            validate_identity_field("target.component_type", &target.component_type)?;
            if let Some(component_id) = &target.component_id {
                validate_identity_field("target.component_id", component_id)?;
            }
        }
        Ok(())
    }

    /// Returns `true` if this event modifies UI state.
    #[must_use]
    pub fn is_mutating(&self) -> bool {
        matches!(
            self.classification,
            EventClassification::Mutate
                | EventClassification::Navigate
                | EventClassification::Create
                | EventClassification::Destroy
                | EventClassification::Submit
        )
    }

    /// Returns `true` if this event is read-only.
    #[must_use]
    pub fn is_display_only(&self) -> bool {
        matches!(self.classification, EventClassification::Display)
    }
}

fn validate_identity_field(field_name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{field_name} must be a non-empty string"));
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(format!(
            "{field_name} must be unpadded and contain no control characters"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_roundtrip() {
        let event = AgUiEvent {
            event_id: "evt-1".to_string(),
            timestamp: 1700000000,
            agent_id: "agent-1".to_string(),
            session_id: Some("sess-1".to_string()),
            event_type: EventType::TextStream,
            target: Some(TargetComponent {
                component_type: "chat-window".to_string(),
                component_id: Some("main".to_string()),
            }),
            classification: EventClassification::Display,
            payload: serde_json::json!({"text": "Hello"}),
        };

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: AgUiEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.event_id, "evt-1");
        assert!(deserialized.is_display_only());
        assert!(!deserialized.is_mutating());
    }

    #[test]
    fn mutating_events() {
        let event = AgUiEvent {
            event_id: "evt-2".to_string(),
            timestamp: 0,
            agent_id: "a".to_string(),
            session_id: None,
            event_type: EventType::StateUpdate,
            target: None,
            classification: EventClassification::Mutate,
            payload: serde_json::Value::Null,
        };
        assert!(event.is_mutating());
        assert!(!event.is_display_only());
    }

    #[test]
    fn navigation_events_are_mutating() {
        let event = AgUiEvent {
            event_id: "evt-nav".to_string(),
            timestamp: 0,
            agent_id: "a".to_string(),
            session_id: None,
            event_type: EventType::Navigation,
            target: None,
            classification: EventClassification::Navigate,
            payload: serde_json::Value::Null,
        };
        assert!(event.is_mutating());
        assert!(!event.is_display_only());
    }

    #[test]
    fn custom_event_type() {
        let event = AgUiEvent {
            event_id: "evt-3".to_string(),
            timestamp: 0,
            agent_id: "a".to_string(),
            session_id: None,
            event_type: EventType::Custom("clipboard-copy".to_string()),
            target: None,
            classification: EventClassification::Submit,
            payload: serde_json::Value::Null,
        };
        assert!(event.is_mutating());
        assert_eq!(
            event.event_type,
            EventType::Custom("clipboard-copy".to_string())
        );
    }
}
