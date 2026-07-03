use std::collections::BTreeMap;
use std::io::Write;

use chio_core::session::{
    CreateElicitationOperation, CreateMessageOperation, TaskOwnershipSnapshot,
};
use chio_kernel::NestedFlowBridge;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::edge::AdapterError;

use super::utils::{
    attach_related_task_meta_to_result, build_related_task_meta, iso8601_now, json_rpc_error,
    json_rpc_result, map_nested_flow_error_code, send_line, MAX_BACKGROUND_TASKS_PER_TICK,
    TASK_POLL_INTERVAL_MILLIS,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RequestedTask {
    #[serde(default)]
    pub(super) ttl: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum NestedFlowTaskStatus {
    Working,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone)]
enum NestedFlowTaskOperation {
    CreateMessage(CreateMessageOperation),
    CreateElicitation(CreateElicitationOperation),
}

#[derive(Debug, Clone)]
enum NestedFlowTaskFinalOutcome {
    Result(serde_json::Value),
    Error { code: i64, message: String },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct NestedFlowTask {
    task_id: String,
    status: NestedFlowTaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_message: Option<String>,
    created_at: String,
    last_updated_at: String,
    pub(super) ttl: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    poll_interval: Option<u64>,
    ownership: TaskOwnershipSnapshot,
    owner_request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_request_id: Option<String>,
    #[serde(skip)]
    operation: NestedFlowTaskOperation,
    #[serde(skip)]
    final_outcome: Option<NestedFlowTaskFinalOutcome>,
}

impl NestedFlowTask {
    fn new_create_message(
        task_id: String,
        owner_request_id: String,
        parent_request_id: Option<String>,
        operation: CreateMessageOperation,
        ttl: Option<u64>,
    ) -> Self {
        let now = iso8601_now();
        Self {
            task_id,
            status: NestedFlowTaskStatus::Working,
            status_message: Some("The operation is now in progress.".to_string()),
            created_at: now.clone(),
            last_updated_at: now,
            ttl,
            poll_interval: Some(TASK_POLL_INTERVAL_MILLIS),
            ownership: TaskOwnershipSnapshot::task_owned(),
            owner_request_id,
            parent_request_id,
            operation: NestedFlowTaskOperation::CreateMessage(operation),
            final_outcome: None,
        }
    }

    fn new_create_elicitation(
        task_id: String,
        owner_request_id: String,
        parent_request_id: Option<String>,
        operation: CreateElicitationOperation,
        ttl: Option<u64>,
    ) -> Self {
        let now = iso8601_now();
        Self {
            task_id,
            status: NestedFlowTaskStatus::Working,
            status_message: Some("The operation is now in progress.".to_string()),
            created_at: now.clone(),
            last_updated_at: now,
            ttl,
            poll_interval: Some(TASK_POLL_INTERVAL_MILLIS),
            ownership: TaskOwnershipSnapshot::task_owned(),
            owner_request_id,
            parent_request_id,
            operation: NestedFlowTaskOperation::CreateElicitation(operation),
            final_outcome: None,
        }
    }

    pub(super) fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            NestedFlowTaskStatus::Completed
                | NestedFlowTaskStatus::Failed
                | NestedFlowTaskStatus::Cancelled
        )
    }

    fn touch(&mut self) {
        self.last_updated_at = iso8601_now();
    }

    fn mark_completed(&mut self, result: serde_json::Value) {
        self.status = NestedFlowTaskStatus::Completed;
        self.status_message = Some("The operation completed successfully.".to_string());
        self.final_outcome = Some(NestedFlowTaskFinalOutcome::Result(result));
        self.touch();
    }

    fn mark_failed(&mut self, code: i64, message: String) {
        self.status = NestedFlowTaskStatus::Failed;
        self.status_message = Some(message.clone());
        self.final_outcome = Some(NestedFlowTaskFinalOutcome::Error { code, message });
        self.touch();
    }

    fn mark_cancelled(&mut self, reason: &str) {
        self.status = NestedFlowTaskStatus::Cancelled;
        self.status_message = Some(reason.to_string());
        self.final_outcome = Some(NestedFlowTaskFinalOutcome::Error {
            code: -32800,
            message: reason.to_string(),
        });
        self.touch();
    }
}

#[derive(Debug, Default)]
pub(super) struct NestedFlowTaskRuntime {
    task_counter: u64,
    pub(super) tasks: BTreeMap<String, NestedFlowTask>,
    pending_background_tasks: Vec<String>,
}

impl NestedFlowTaskRuntime {
    fn next_task_id(&mut self) -> String {
        self.task_counter += 1;
        format!("nested-client-task-{}", self.task_counter)
    }

    pub(super) fn create_message_task(
        &mut self,
        owner_request_id: String,
        parent_request_id: String,
        operation: CreateMessageOperation,
        requested_task: RequestedTask,
    ) -> serde_json::Value {
        let task_id = self.next_task_id();
        let task = NestedFlowTask::new_create_message(
            task_id.clone(),
            owner_request_id,
            Some(parent_request_id),
            operation,
            requested_task.ttl,
        );
        let task_view = task.clone();
        self.tasks.insert(task_id.clone(), task);
        self.pending_background_tasks.push(task_id);
        json!({ "task": task_view })
    }

    pub(super) fn create_elicitation_task(
        &mut self,
        owner_request_id: String,
        parent_request_id: String,
        operation: CreateElicitationOperation,
        requested_task: RequestedTask,
    ) -> serde_json::Value {
        let task_id = self.next_task_id();
        let task = NestedFlowTask::new_create_elicitation(
            task_id.clone(),
            owner_request_id,
            Some(parent_request_id),
            operation,
            requested_task.ttl,
        );
        let task_view = task.clone();
        self.tasks.insert(task_id.clone(), task);
        self.pending_background_tasks.push(task_id);
        json!({ "task": task_view })
    }

    pub(super) fn handle_tasks_list(
        &self,
        id: serde_json::Value,
        params: &serde_json::Value,
    ) -> serde_json::Value {
        let start = match parse_cursor(params) {
            Ok(start) => start,
            Err(message) => return json_rpc_error(id, -32602, &message),
        };

        let tasks = self.tasks.values().cloned().collect::<Vec<_>>();
        if start > tasks.len() {
            return json_rpc_error(id, -32602, "cursor is out of range");
        }

        let end = (start + 50).min(tasks.len());
        let next_cursor = (end < tasks.len()).then(|| end.to_string());
        let page = tasks[start..end]
            .iter()
            .map(|task| serde_json::to_value(task).unwrap_or_else(|_| json!({})))
            .collect::<Vec<_>>();

        json_rpc_result(
            id,
            json!({
                "tasks": page,
                "nextCursor": next_cursor,
            }),
        )
    }

    pub(super) fn handle_tasks_get(
        &self,
        id: serde_json::Value,
        params: &serde_json::Value,
    ) -> serde_json::Value {
        let task_id = match parse_task_id(params) {
            Ok(task_id) => task_id,
            Err(message) => return json_rpc_error(id, -32602, &message),
        };

        let Some(task) = self.tasks.get(&task_id) else {
            return json_rpc_error(id, -32602, "Failed to retrieve task: Task not found");
        };

        json_rpc_result(id, serde_json::to_value(task).unwrap_or_else(|_| json!({})))
    }

    pub(super) fn handle_tasks_cancel(
        &mut self,
        id: serde_json::Value,
        params: &serde_json::Value,
    ) -> serde_json::Value {
        let task_id = match parse_task_id(params) {
            Ok(task_id) => task_id,
            Err(message) => return json_rpc_error(id, -32602, &message),
        };

        let Some(task) = self.tasks.get_mut(&task_id) else {
            return json_rpc_error(id, -32602, "Failed to retrieve task: Task not found");
        };
        if task.is_terminal() {
            return json_rpc_error(
                id,
                -32602,
                &format!(
                    "Cannot cancel task: already in terminal status '{}'",
                    nested_flow_task_status_label(task.status)
                ),
            );
        }

        task.mark_cancelled("The task was cancelled by request.");
        self.pending_background_tasks
            .retain(|pending| pending != &task_id);
        json_rpc_result(id, serde_json::to_value(task).unwrap_or_else(|_| json!({})))
    }

    pub(super) fn handle_tasks_result(
        &mut self,
        id: serde_json::Value,
        params: &serde_json::Value,
        nested_flow_bridge: &mut dyn NestedFlowBridge,
        writer: &mut impl Write,
    ) -> Result<serde_json::Value, AdapterError> {
        let task_id = match parse_task_id(params) {
            Ok(task_id) => task_id,
            Err(message) => return Ok(json_rpc_error(id, -32602, &message)),
        };

        self.pending_background_tasks
            .retain(|pending| pending != &task_id);

        if !self.tasks.contains_key(&task_id) {
            return Ok(json_rpc_error(
                id,
                -32602,
                "Failed to retrieve task: Task not found",
            ));
        }

        if !self
            .tasks
            .get(&task_id)
            .is_some_and(NestedFlowTask::is_terminal)
        {
            self.execute_task(&task_id, nested_flow_bridge, writer)?;
        }

        let Some(task) = self.tasks.get(&task_id) else {
            return Ok(json_rpc_error(
                id,
                -32602,
                "Failed to retrieve task: Task not found",
            ));
        };

        let response = match task.final_outcome.clone() {
            Some(NestedFlowTaskFinalOutcome::Result(result)) => json_rpc_result(
                id,
                attach_related_task_meta_to_result(
                    result,
                    build_related_task_meta(
                        &task.task_id,
                        Some(&task.owner_request_id),
                        task.parent_request_id.as_deref(),
                    ),
                ),
            ),
            Some(NestedFlowTaskFinalOutcome::Error { code, message }) => {
                json_rpc_error(id, code, &message)
            }
            None => json_rpc_error(id, -32603, "task result unavailable"),
        };

        Ok(response)
    }

    pub(super) fn process_background_tasks(
        &mut self,
        nested_flow_bridge: &mut dyn NestedFlowBridge,
        writer: &mut impl Write,
    ) -> Result<(), AdapterError> {
        for _ in 0..MAX_BACKGROUND_TASKS_PER_TICK {
            let Some(task_id) = self.pending_background_tasks.first().cloned() else {
                break;
            };
            self.pending_background_tasks.remove(0);

            if !self.tasks.contains_key(&task_id) {
                continue;
            }

            if self
                .tasks
                .get(&task_id)
                .is_some_and(NestedFlowTask::is_terminal)
            {
                continue;
            }

            self.execute_task(&task_id, nested_flow_bridge, writer)?;
            if let Some(task) = self.tasks.get(&task_id) {
                send_line(
                    writer,
                    &json!({
                        "jsonrpc": "2.0",
                        "method": "notifications/tasks/status",
                        "params": serde_json::to_value(task).unwrap_or_else(|_| json!({})),
                    }),
                )?;
            }
        }
        Ok(())
    }

    fn execute_task(
        &mut self,
        task_id: &str,
        nested_flow_bridge: &mut dyn NestedFlowBridge,
        _writer: &mut impl Write,
    ) -> Result<(), AdapterError> {
        let Some(mut task) = self.tasks.remove(task_id) else {
            return Ok(());
        };

        if !task.is_terminal() {
            match task.operation.clone() {
                NestedFlowTaskOperation::CreateMessage(operation) => {
                    match nested_flow_bridge.create_message(operation) {
                        Ok(result) => {
                            let result = serde_json::to_value(result).map_err(|error| {
                                AdapterError::ParseError(format!(
                                    "failed to serialize sampling/createMessage result: {error}"
                                ))
                            })?;
                            task.mark_completed(result);
                        }
                        Err(error) => {
                            task.mark_failed(map_nested_flow_error_code(&error), error.to_string());
                        }
                    }
                }
                NestedFlowTaskOperation::CreateElicitation(operation) => {
                    match nested_flow_bridge.create_elicitation(operation) {
                        Ok(result) => {
                            let result = serde_json::to_value(result).map_err(|error| {
                                AdapterError::ParseError(format!(
                                    "failed to serialize elicitation/create result: {error}"
                                ))
                            })?;
                            task.mark_completed(result);
                        }
                        Err(error) => {
                            task.mark_failed(map_nested_flow_error_code(&error), error.to_string());
                        }
                    }
                }
            }
        }

        self.tasks.insert(task_id.to_string(), task);
        Ok(())
    }
}

pub(super) fn parse_requested_task(
    params: &serde_json::Value,
) -> Result<Option<RequestedTask>, AdapterError> {
    let Some(task) = params.get("task").cloned() else {
        return Ok(None);
    };
    serde_json::from_value(task).map(Some).map_err(|_| {
        AdapterError::ParseError("task must be an object with an optional numeric ttl".into())
    })
}

fn parse_cursor(params: &serde_json::Value) -> Result<usize, String> {
    let cursor = match params.get("cursor") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(cursor)) => Some(cursor.clone()),
        Some(_) => return Err("cursor must be a string".to_string()),
    };

    match cursor.as_deref() {
        None => Ok(0),
        Some(cursor) => cursor
            .parse::<usize>()
            .map_err(|_| "cursor must be numeric".to_string()),
    }
}

fn parse_task_id(params: &serde_json::Value) -> Result<String, String> {
    params
        .get("taskId")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| "taskId must be a string".to_string())
}

fn nested_flow_task_status_label(status: NestedFlowTaskStatus) -> &'static str {
    match status {
        NestedFlowTaskStatus::Working => "working",
        NestedFlowTaskStatus::Completed => "completed",
        NestedFlowTaskStatus::Failed => "failed",
        NestedFlowTaskStatus::Cancelled => "cancelled",
    }
}
