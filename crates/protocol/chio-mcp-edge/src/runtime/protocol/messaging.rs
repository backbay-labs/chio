use super::*;

pub(in crate::runtime) fn cancellation_matches_request(message: &Value, request_id: &str) -> bool {
    message.get("method").and_then(Value::as_str) == Some("notifications/cancelled")
        && message
            .get("params")
            .and_then(|params| params.get("requestId"))
            == Some(&Value::String(request_id.to_string()))
}

pub(in crate::runtime) fn cancellation_matches_client_request(
    message: &Value,
    request_id: &Value,
) -> bool {
    message.get("method").and_then(Value::as_str) == Some("notifications/cancelled")
        && message
            .get("params")
            .and_then(|params| params.get("requestId"))
            == Some(request_id)
}

pub(in crate::runtime) fn task_cancel_matches_related_task(
    message: &Value,
    related_task_id: Option<&str>,
) -> bool {
    let Some(related_task_id) = related_task_id else {
        return false;
    };

    has_jsonrpc_request_id(message)
        && message.get("method").and_then(Value::as_str) == Some("tasks/cancel")
        && message
            .get("params")
            .and_then(|params| params.get("taskId"))
            .and_then(Value::as_str)
            == Some(related_task_id)
}

pub(in crate::runtime) fn is_cancellation_side_channel_signal(message: &Value) -> bool {
    match message.get("method").and_then(Value::as_str) {
        Some("notifications/cancelled") => message.get("params").is_some_and(Value::is_object),
        Some("tasks/cancel") => has_jsonrpc_request_id(message),
        _ => false,
    }
}

fn has_jsonrpc_request_id(message: &Value) -> bool {
    message
        .get("id")
        .is_some_and(|id| id.is_string() || id.is_number() || id.is_null())
}

pub(in crate::runtime) fn explicit_task_cancel_reason() -> &'static str {
    "task cancelled by client"
}

pub(in crate::runtime) fn cancellation_reason(message: &Value) -> String {
    let reason = message
        .get("params")
        .and_then(|params| params.get("reason"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|reason| !reason.is_empty());

    match reason {
        Some(reason) => format!("cancelled by client: {reason}"),
        None => "cancelled by client".to_string(),
    }
}

pub(in crate::runtime) fn next_client_message(
    client_rx: &mpsc::Receiver<ClientInbound>,
) -> Result<Value, AdapterError> {
    match client_rx.recv() {
        Ok(ClientInbound::Message(message)) => Ok(message),
        Ok(ClientInbound::ParseError(error)) => Err(AdapterError::ParseError(format!(
            "failed to parse MCP edge message: {error}"
        ))),
        Ok(ClientInbound::ReadError(error)) => Err(AdapterError::ConnectionFailed(format!(
            "failed to read MCP edge request: {error}"
        ))),
        Ok(ClientInbound::Closed) | Err(mpsc::RecvError) => Err(AdapterError::ConnectionFailed(
            "MCP client closed connection while request was in flight".into(),
        )),
    }
}

pub(in crate::runtime) fn pump_client_messages<R: BufRead>(
    mut reader: R,
    sender: mpsc::Sender<ClientInbound>,
    cancel_sender: mpsc::Sender<Value>,
) {
    loop {
        match read_jsonrpc_frame(&mut reader) {
            Ok(None) => {
                let _ = sender.send(ClientInbound::Closed);
                return;
            }
            Err(error) => {
                let stop_after_send = matches!(error, AdapterError::ConnectionFailed(_));
                let inbound = match error {
                    AdapterError::ConnectionFailed(message) => ClientInbound::ReadError(message),
                    AdapterError::ParseError(message) => ClientInbound::ParseError(message),
                    other => ClientInbound::ParseError(other.to_string()),
                };
                if sender.send(inbound).is_err() || stop_after_send {
                    return;
                }
            }
            Ok(Some(message)) => {
                let is_cancel_signal = is_cancellation_side_channel_signal(&message);
                if sender
                    .send(ClientInbound::Message(message.clone()))
                    .is_err()
                {
                    return;
                }
                // Queue the JSON-RPC request before the side-channel signal so a
                // nested-flow cancellation can still defer and answer tasks/cancel.
                if is_cancel_signal {
                    let _ = cancel_sender.send(message);
                }
            }
        }
    }
}

pub(in crate::runtime) fn pump_channel_messages(
    receiver: mpsc::Receiver<Value>,
    sender: mpsc::Sender<ClientInbound>,
    cancel_sender: mpsc::Sender<Value>,
) {
    while let Ok(message) = receiver.recv() {
        let is_cancel_signal = is_cancellation_side_channel_signal(&message);
        if sender
            .send(ClientInbound::Message(message.clone()))
            .is_err()
        {
            return;
        }
        if is_cancel_signal {
            let _ = cancel_sender.send(message);
        }
    }

    let _ = sender.send(ClientInbound::Closed);
}
