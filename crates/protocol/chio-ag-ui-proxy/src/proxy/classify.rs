use crate::event::{AgUiEvent, EventClassification, EventType};

pub(super) fn derive_server_classification(
    event: &AgUiEvent,
) -> Result<EventClassification, String> {
    match &event.event_type {
        EventType::TextStream => Ok(EventClassification::Display),
        EventType::StateUpdate => Ok(EventClassification::Mutate),
        EventType::Navigation => Ok(EventClassification::Navigate),
        EventType::Lifecycle => derive_lifecycle_classification(&event.payload),
        EventType::FormAction => Ok(EventClassification::Submit),
        EventType::Notification | EventType::Error => Ok(EventClassification::Alert),
        EventType::Custom(name) => Err(format!(
            "custom AG-UI event type cannot be server-classified: {name}"
        )),
    }
}

fn derive_lifecycle_classification(
    payload: &serde_json::Value,
) -> Result<EventClassification, String> {
    let action = payload
        .get("action")
        .or_else(|| payload.get("lifecycle"))
        .or_else(|| payload.get("event"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_ascii_lowercase);

    match action.as_deref() {
        Some("create" | "created" | "mount" | "mounted" | "open" | "opened") => {
            Ok(EventClassification::Create)
        }
        Some("destroy" | "destroyed" | "unmount" | "unmounted" | "close" | "closed") => {
            Ok(EventClassification::Destroy)
        }
        Some("update" | "updated" | "change" | "changed") => Ok(EventClassification::Mutate),
        Some(other) => Err(format!(
            "lifecycle AG-UI event action is not classifiable: {other}"
        )),
        None => Err("lifecycle AG-UI event missing classifiable action".to_string()),
    }
}
