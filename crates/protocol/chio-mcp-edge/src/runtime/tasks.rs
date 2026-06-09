use super::tool_calls::ToolCallRequestContext;
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum EdgeTaskStatus {
    Working,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct EdgeTask {
    pub(super) task_id: String,
    pub(super) status: EdgeTaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) status_message: Option<String>,
    pub(super) created_at: String,
    pub(super) last_updated_at: String,
    pub(super) ttl: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) poll_interval: Option<u64>,
    pub(super) ownership: TaskOwnershipSnapshot,
    pub(super) owner_session_id: String,
    pub(super) owner_request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) parent_request_id: Option<String>,
    #[serde(skip)]
    pub(super) session_id: SessionId,
    #[serde(skip)]
    pub(super) context: OperationContext,
    #[serde(skip)]
    pub(super) operation: ToolCallOperation,
    #[serde(skip)]
    pub(super) final_outcome: Option<EdgeTaskFinalOutcome>,
    #[serde(skip)]
    pub(super) background_ready_at_ms: u64,
    #[serde(skip)]
    pub(super) expires_at_ms: u64,
}

#[derive(Debug, Clone)]
pub(super) enum EdgeTaskFinalOutcome {
    Result(Value),
    JsonRpcError {
        code: i64,
        message: String,
        data: Option<Value>,
    },
}

pub(super) enum ToolCallEdgeOutcome {
    Result(Value),
    Cancelled {
        reason: String,
    },
    JsonRpcError {
        code: i64,
        message: String,
        data: Option<Value>,
    },
}

impl EdgeTask {
    pub(super) fn new(
        task_id: String,
        session_id: SessionId,
        context: OperationContext,
        operation: ToolCallOperation,
        ttl: Option<u64>,
        background_start_delay_millis: u64,
    ) -> Self {
        let now = iso8601_now();
        let now_ms = unix_now_millis();
        let ttl_millis = ttl.unwrap_or(DEFAULT_MCP_TASK_TTL_MILLIS);
        Self {
            task_id,
            status: EdgeTaskStatus::Working,
            status_message: Some("The operation is now in progress.".to_string()),
            created_at: now.clone(),
            last_updated_at: now,
            ttl,
            poll_interval: Some(TASK_POLL_INTERVAL_MILLIS),
            ownership: TaskOwnershipSnapshot::task_owned(),
            owner_session_id: session_id.to_string(),
            owner_request_id: context.request_id.to_string(),
            parent_request_id: context.parent_request_id.clone().map(|id| id.to_string()),
            session_id,
            context,
            operation,
            final_outcome: None,
            background_ready_at_ms: now_ms.saturating_add(background_start_delay_millis),
            expires_at_ms: now_ms.saturating_add(ttl_millis),
        }
    }

    pub(super) fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            EdgeTaskStatus::Completed | EdgeTaskStatus::Failed | EdgeTaskStatus::Cancelled
        )
    }

    pub(super) fn touch(&mut self) {
        self.last_updated_at = iso8601_now();
    }

    pub(super) fn mark_completed(&mut self, result: Value) {
        self.status = if tool_result_is_error(&result) {
            EdgeTaskStatus::Failed
        } else {
            EdgeTaskStatus::Completed
        };
        self.status_message = task_status_message(&self.status, &result);
        self.final_outcome = Some(EdgeTaskFinalOutcome::Result(result));
        self.touch();
    }

    pub(super) fn mark_cancelled(&mut self, reason: &str) {
        self.status = EdgeTaskStatus::Cancelled;
        self.status_message = Some(reason.to_string());
        self.final_outcome = Some(EdgeTaskFinalOutcome::Result(tool_error_result(reason)));
        self.touch();
    }

    pub(super) fn mark_jsonrpc_error(&mut self, code: i64, message: String, data: Option<Value>) {
        self.status = EdgeTaskStatus::Failed;
        self.status_message = Some(message.clone());
        self.final_outcome = Some(EdgeTaskFinalOutcome::JsonRpcError {
            code,
            message,
            data,
        });
        self.touch();
    }

    pub(super) fn record_outcome(&mut self, outcome: ToolCallEdgeOutcome) {
        match outcome {
            ToolCallEdgeOutcome::Result(result) => self.mark_completed(result),
            ToolCallEdgeOutcome::Cancelled { reason } => self.mark_cancelled(&reason),
            ToolCallEdgeOutcome::JsonRpcError {
                code,
                message,
                data,
            } => self.mark_jsonrpc_error(code, message, data),
        }
    }

    pub(super) fn background_ready(&self) -> bool {
        unix_now_millis() >= self.background_ready_at_ms
    }

    pub(super) fn is_expired_at(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms
    }
}

impl ChioMcpEdge {
    pub(super) fn next_task_id(&mut self) -> String {
        self.task_counter += 1;
        format!("mcp-edge-task-{}", self.task_counter)
    }

    pub(super) fn create_tool_call_task(
        &mut self,
        id: Value,
        session_id: SessionId,
        context: OperationContext,
        operation: ToolCallOperation,
        requested_task: RequestedTask,
        queue_background: bool,
    ) -> Value {
        if let Err(response) = self.ensure_deferred_task_capacity(&id) {
            return response;
        }
        let task_id = self.next_task_id();
        let task = EdgeTask::new(
            task_id.clone(),
            session_id,
            context,
            operation,
            requested_task.ttl,
            self.background_task_start_delay_millis(),
        );
        let task_view = task.clone();
        self.tasks.insert(task_id, task);
        if queue_background {
            self.pending_background_tasks
                .push(task_view.task_id.clone());
        }
        jsonrpc_result(id, json!({ "task": task_view }))
    }

    pub(super) fn background_task_start_delay_millis(&self) -> u64 {
        match self.session_auth_context.transport {
            SessionTransport::StreamableHttp => TASK_POLL_INTERVAL_MILLIS,
            SessionTransport::InProcess | SessionTransport::Stdio => 0,
        }
    }

    pub(super) fn ensure_deferred_task_capacity(&mut self, id: &Value) -> Result<(), Value> {
        self.prune_expired_tasks();
        if self.tasks.len() >= MAX_DEFERRED_MCP_TASKS {
            self.prune_terminal_tasks();
        }
        if self.tasks.len() >= MAX_DEFERRED_MCP_TASKS {
            return Err(jsonrpc_error(
                id.clone(),
                JSONRPC_INVALID_PARAMS,
                "too many deferred tasks are pending",
            ));
        }
        Ok(())
    }

    pub(super) fn prune_expired_tasks(&mut self) {
        let now_ms = unix_now_millis();
        self.tasks.retain(|_, task| !task.is_expired_at(now_ms));
        self.retain_live_background_tasks();
    }

    pub(super) fn prune_terminal_tasks(&mut self) {
        self.tasks.retain(|_, task| !task.is_terminal());
        self.retain_live_background_tasks();
    }

    pub(super) fn retain_live_background_tasks(&mut self) {
        self.pending_background_tasks
            .retain(|task_id| self.tasks.contains_key(task_id));
    }

    pub(super) fn handle_tasks_list(&mut self, id: Value, params: Value) -> Value {
        self.prune_expired_tasks();
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let start = match parse_cursor(&id, &params) {
            Ok(start) => start,
            Err(response) => return response,
        };

        let tasks = self
            .tasks
            .values()
            .filter(|task| task.session_id == session_id)
            .cloned()
            .collect::<Vec<_>>();
        if start > tasks.len() {
            return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "cursor is out of range");
        }

        let page_size = self.config.page_size.max(1);
        let end = (start + page_size).min(tasks.len());
        let next_cursor = (end < tasks.len()).then(|| end.to_string());
        let page = tasks[start..end]
            .iter()
            .map(|task| serde_json::to_value(task).unwrap_or_else(|_| json!({})))
            .collect::<Vec<_>>();

        jsonrpc_result(
            id,
            json!({
                "tasks": page,
                "nextCursor": next_cursor,
                "total": tasks.len(),
            }),
        )
    }

    pub(super) fn handle_tasks_get(&mut self, id: Value, params: Value) -> Value {
        self.prune_expired_tasks();
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let task_id = match parse_task_id(&id, &params) {
            Ok(task_id) => task_id,
            Err(response) => return response,
        };

        let Some(task) = self.tasks.get(&task_id) else {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "failed to retrieve task: task not found",
            );
        };
        if task.session_id != session_id {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "failed to retrieve task: task not found",
            );
        }

        jsonrpc_result(id, serde_json::to_value(task).unwrap_or_else(|_| json!({})))
    }

    pub(super) fn handle_tasks_cancel(&mut self, id: Value, params: Value) -> Value {
        self.prune_expired_tasks();
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let task_id = match parse_task_id(&id, &params) {
            Ok(task_id) => task_id,
            Err(response) => return response,
        };

        let Some(mut task) = self.tasks.remove(&task_id) else {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "failed to retrieve task: task not found",
            );
        };
        if task.session_id != session_id {
            self.tasks.insert(task_id, task);
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "failed to retrieve task: task not found",
            );
        }
        if task.is_terminal() {
            let status = task.status;
            let task_view = task.clone();
            self.tasks.insert(task_id, task);
            return match status {
                EdgeTaskStatus::Cancelled => jsonrpc_result(
                    id,
                    serde_json::to_value(task_view).unwrap_or_else(|_| json!({})),
                ),
                _ => jsonrpc_error(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    &format!(
                        "cannot cancel task: already in terminal status '{}'",
                        edge_task_status_label(status)
                    ),
                ),
            };
        }

        task.mark_cancelled("task cancelled by client");
        self.dequeue_background_task(&task_id);
        let task_view = task.clone();
        self.queue_task_status_notification(&task_view);
        self.tasks.insert(task_id, task);
        jsonrpc_result(
            id,
            serde_json::to_value(task_view).unwrap_or_else(|_| json!({})),
        )
    }

    pub(super) fn handle_tasks_result(&mut self, id: Value, params: Value) -> Value {
        self.prune_expired_tasks();
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let task_id = match parse_task_id(&id, &params) {
            Ok(task_id) => task_id,
            Err(response) => return response,
        };

        let task = match self.tasks.get(&task_id).cloned() {
            Some(task) => task,
            None => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    "failed to retrieve task: task not found",
                )
            }
        };
        if task.session_id != session_id {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "failed to retrieve task: task not found",
            );
        }

        self.dequeue_background_task(&task_id);
        if !task.is_terminal() {
            let result = self.evaluate_tool_call_operation(
                &id,
                &session_id,
                &task.context,
                &task.operation,
                Some(task_id.as_str()),
            );
            let mut task_view = None;
            if let Some(task) = self.tasks.get_mut(&task_id) {
                if !task.is_terminal() {
                    task.record_outcome(result);
                    task_view = Some(task.clone());
                }
            }
            if let Some(task_view) = task_view.as_ref() {
                self.queue_task_status_notification(task_view);
            }
        }

        let task = self.tasks.get(&task_id).cloned();
        task_outcome_to_jsonrpc(task, &id, &task_id)
    }

    pub(super) fn handle_tasks_result_with_transport<R: BufRead + Send, W: Write + Send>(
        &mut self,
        id: Value,
        params: Value,
        reader: &mut R,
        writer: &mut W,
    ) -> Value {
        self.prune_expired_tasks();
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let task_id = match parse_task_id(&id, &params) {
            Ok(task_id) => task_id,
            Err(response) => return response,
        };

        let task = match self.tasks.get(&task_id).cloned() {
            Some(task) => task,
            None => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    "failed to retrieve task: task not found",
                )
            }
        };
        if task.session_id != session_id {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "failed to retrieve task: task not found",
            );
        }

        self.dequeue_background_task(&task_id);
        if !task.is_terminal() {
            let result = self.evaluate_tool_call_operation_with_transport(
                ToolCallRequestContext {
                    id: &id,
                    session_id: &session_id,
                    context: &task.context,
                    operation: &task.operation,
                    related_task_id: Some(task_id.as_str()),
                },
                reader,
                writer,
            );
            let mut task_view = None;
            if let Some(task) = self.tasks.get_mut(&task_id) {
                if !task.is_terminal() {
                    task.record_outcome(result);
                    task_view = Some(task.clone());
                }
            }
            if let Some(task_view) = task_view.as_ref() {
                self.queue_task_status_notification(task_view);
            }
        }

        let task = self.tasks.get(&task_id).cloned();
        task_outcome_to_jsonrpc(task, &id, &task_id)
    }

    pub(super) fn handle_tasks_result_with_transport_channel<W: Write>(
        &mut self,
        id: Value,
        params: Value,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
    ) -> Value {
        self.prune_expired_tasks();
        let session_id = match self.ready_session_id(&id) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };
        let task_id = match parse_task_id(&id, &params) {
            Ok(task_id) => task_id,
            Err(response) => return response,
        };

        let task = match self.tasks.get(&task_id).cloned() {
            Some(task) => task,
            None => {
                return jsonrpc_error(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    "failed to retrieve task: task not found",
                )
            }
        };
        if task.session_id != session_id {
            return jsonrpc_error(
                id,
                JSONRPC_INVALID_PARAMS,
                "failed to retrieve task: task not found",
            );
        }

        self.dequeue_background_task(&task_id);
        if !task.is_terminal() {
            let result = self.evaluate_tool_call_operation_with_transport_channel(
                ToolCallRequestContext {
                    id: &id,
                    session_id: &session_id,
                    context: &task.context,
                    operation: &task.operation,
                    related_task_id: Some(task_id.as_str()),
                },
                client_rx,
                cancel_rx,
                writer,
            );
            let mut task_view = None;
            if let Some(task) = self.tasks.get_mut(&task_id) {
                if !task.is_terminal() {
                    task.record_outcome(result);
                    task_view = Some(task.clone());
                }
            }
            if let Some(task_view) = task_view.as_ref() {
                self.queue_task_status_notification(task_view);
            }
        }

        let task = self.tasks.get(&task_id).cloned();
        task_outcome_to_jsonrpc(task, &id, &task_id)
    }

    pub(super) fn queue_task_status_notification(&mut self, task: &EdgeTask) {
        self.pending_notifications.push(json!({
            "jsonrpc": "2.0",
            "method": "notifications/tasks/status",
            "params": serde_json::to_value(task).unwrap_or_else(|_| json!({})),
        }));
    }
    pub(super) fn dequeue_background_task(&mut self, task_id: &str) {
        self.pending_background_tasks
            .retain(|pending| pending != task_id);
    }

    pub(super) fn process_background_tasks_with_channel<W: Write>(
        &mut self,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
    ) -> Result<bool, AdapterError> {
        let mut processed_any = false;

        for _ in 0..MAX_BACKGROUND_TASKS_PER_TICK {
            let Some(task_id) = self.pending_background_tasks.first().cloned() else {
                break;
            };
            self.pending_background_tasks.remove(0);

            let Some(task) = self.tasks.get(&task_id).cloned() else {
                continue;
            };

            if task.is_terminal() {
                continue;
            }

            if !task.background_ready() {
                self.pending_background_tasks.push(task_id);
                continue;
            }

            let result = self.evaluate_tool_call_operation_with_transport_channel(
                ToolCallRequestContext {
                    id: &Value::String(task.task_id.clone()),
                    session_id: &task.session_id,
                    context: &task.context,
                    operation: &task.operation,
                    related_task_id: Some(task.task_id.as_str()),
                },
                client_rx,
                cancel_rx,
                writer,
            );
            let mut task_view = None;
            if let Some(task) = self.tasks.get_mut(&task_id) {
                if !task.is_terminal() {
                    task.record_outcome(result);
                    task_view = Some(task.clone());
                }
            }
            if let Some(task_view) = task_view.as_ref() {
                self.queue_task_status_notification(task_view);
            }
            processed_any = true;
        }

        Ok(processed_any)
    }

    pub(super) fn process_background_tasks(&mut self) -> Result<bool, AdapterError> {
        let mut processed_any = false;

        for _ in 0..MAX_BACKGROUND_TASKS_PER_TICK {
            let Some(task_id) = self.pending_background_tasks.first().cloned() else {
                break;
            };
            self.pending_background_tasks.remove(0);

            let Some(task) = self.tasks.get(&task_id).cloned() else {
                continue;
            };

            if task.is_terminal() {
                continue;
            }

            if !task.background_ready() {
                self.pending_background_tasks.push(task_id);
                continue;
            }

            let result = self.evaluate_tool_call_operation(
                &Value::String(task.task_id.clone()),
                &task.session_id,
                &task.context,
                &task.operation,
                Some(task.task_id.as_str()),
            );
            let mut task_view = None;
            if let Some(task) = self.tasks.get_mut(&task_id) {
                if !task.is_terminal() {
                    task.record_outcome(result);
                    task_view = Some(task.clone());
                }
            }
            if let Some(task_view) = task_view.as_ref() {
                self.queue_task_status_notification(task_view);
            }
            processed_any = true;
        }

        Ok(processed_any)
    }

    pub(super) fn service_background_runtime_with_channel<W: Write>(
        &mut self,
        client_rx: &mpsc::Receiver<ClientInbound>,
        cancel_rx: &mpsc::Receiver<Value>,
        writer: &mut W,
    ) -> Result<(), AdapterError> {
        let _ = self.process_background_tasks_with_channel(client_rx, cancel_rx, writer)?;
        self.process_pending_actions_with_channel(client_rx, writer)?;
        self.forward_runtime_events();
        self.flush_pending_notifications(writer)?;
        Ok(())
    }
}
