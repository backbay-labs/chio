#[derive(Debug)]
struct A2aTaskRegistry {
    path: PathBuf,
    lock: Mutex<()>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct A2aPersistedTaskRegistry {
    version: String,
    #[serde(default)]
    tasks: BTreeMap<String, A2aTaskRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct A2aTaskRecord {
    task_id: String,
    tool_name: String,
    server_id: String,
    interface_url: String,
    protocol_binding: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant: Option<String>,
    partner: String,
    first_seen_at: u64,
    last_seen_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_state: Option<String>,
    last_source: String,
}

impl Default for A2aPersistedTaskRegistry {
    fn default() -> Self {
        Self {
            version: TASK_REGISTRY_VERSION.to_string(),
            tasks: BTreeMap::new(),
        }
    }
}

struct A2aTaskRecordContext<'a> {
    source: &'a str,
    tool_name: &'a str,
    server_id: &'a str,
    selected_interface: &'a A2aAgentInterface,
    selected_binding: &'a A2aProtocolBinding,
    partner: &'a str,
}

struct A2aTaskFollowUpContext<'a> {
    operation: &'a str,
    tool_name: &'a str,
    server_id: &'a str,
    selected_interface: &'a A2aAgentInterface,
    selected_binding: &'a A2aProtocolBinding,
    partner: &'a str,
}

#[derive(Debug, Clone)]
struct A2aTaskObservation {
    task_id: String,
    state: Option<String>,
}

#[derive(Debug)]
enum A2aTaskRegistryRecordError {
    Fatal(AdapterError),
    RebindConflict(AdapterError),
}

impl A2aTaskRegistryRecordError {
    #[cfg(test)]
    fn into_adapter_error(self) -> AdapterError {
        match self {
            Self::Fatal(error) | Self::RebindConflict(error) => error,
        }
    }
}

impl A2aTaskRegistry {
    fn open(path: &std::path::Path) -> Result<Self, AdapterError> {
        let registry = Self {
            path: path.to_path_buf(),
            lock: Mutex::new(()),
        };
        let _ = registry.load()?;
        Ok(registry)
    }

    fn load(&self) -> Result<A2aPersistedTaskRegistry, AdapterError> {
        match fs::read(&self.path) {
            Ok(bytes) => {
                let registry: A2aPersistedTaskRegistry = serde_json::from_slice(&bytes)
                    .map_err(|error| AdapterError::Lifecycle(format!(
                        "failed to parse A2A task registry {}: {error}",
                        self.path.display()
                    )))?;
                if registry.version != TASK_REGISTRY_VERSION {
                    return Err(AdapterError::Lifecycle(format!(
                        "unsupported A2A task registry version `{}` in {}",
                        registry.version,
                        self.path.display()
                    )));
                }
                Ok(registry)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(A2aPersistedTaskRegistry::default())
            }
            Err(error) => Err(AdapterError::Lifecycle(format!(
                "failed to read A2A task registry {}: {error}",
                self.path.display()
            ))),
        }
    }

    fn save(&self, registry: &A2aPersistedTaskRegistry) -> Result<(), AdapterError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                AdapterError::Lifecycle(format!(
                    "failed to create A2A task registry directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
        fs::write(
            &self.path,
            serde_json::to_vec_pretty(registry).map_err(|error| {
                AdapterError::Lifecycle(format!(
                    "failed to encode A2A task registry {}: {error}",
                    self.path.display()
                ))
            })?,
        )
        .map_err(|error| {
            AdapterError::Lifecycle(format!(
                "failed to write A2A task registry {}: {error}",
                self.path.display()
            ))
        })
    }

    fn validate_follow_up(
        &self,
        task_id: &str,
        context: &A2aTaskFollowUpContext<'_>,
    ) -> Result<(), AdapterError> {
        let operation = context.operation;
        let _guard = self
            .lock
            .lock()
            .map_err(|_| AdapterError::Lifecycle("A2A task registry lock poisoned".to_string()))?;
        let registry = self.load()?;
        let Some(record) = registry.tasks.get(task_id) else {
            return Err(AdapterError::Lifecycle(format!(
                "{operation} requires a previously recorded A2A task `{task_id}` in {}",
                self.path.display()
            )));
        };
        if record.tool_name != context.tool_name {
            return Err(AdapterError::Lifecycle(format!(
                "{operation} attempted to use task `{task_id}` from tool `{}` through `{tool_name}`",
                record.tool_name,
                tool_name = context.tool_name
            )));
        }
        if record.server_id != context.server_id {
            return Err(AdapterError::Lifecycle(format!(
                "{operation} attempted to use task `{task_id}` from server `{}` through `{server_id}`",
                record.server_id,
                server_id = context.server_id
            )));
        }
        if record.interface_url != context.selected_interface.url {
            return Err(AdapterError::Lifecycle(format!(
                "{operation} attempted to use task `{task_id}` against interface `{}` instead of `{}`",
                context.selected_interface.url, record.interface_url
            )));
        }
        if record.protocol_binding != binding_label(context.selected_binding) {
            return Err(AdapterError::Lifecycle(format!(
                "{operation} attempted to use task `{task_id}` over binding `{}` instead of `{}`",
                binding_label(context.selected_binding),
                record.protocol_binding
            )));
        }
        if record.tenant.as_deref() != context.selected_interface.tenant.as_deref() {
            return Err(AdapterError::Lifecycle(format!(
                "{operation} attempted to use task `{task_id}` with tenant `{}` instead of `{}`",
                context
                    .selected_interface
                    .tenant
                    .as_deref()
                    .unwrap_or("none"),
                record.tenant.as_deref().unwrap_or("none")
            )));
        }
        if record.partner != context.partner {
            return Err(AdapterError::Lifecycle(format!(
                "{operation} attempted to use task `{task_id}` from partner `{}` through `{partner}`",
                record.partner,
                partner = context.partner
            )));
        }
        Ok(())
    }

    #[cfg(test)]
    fn record_from_value(
        &self,
        value: &Value,
        context: &A2aTaskRecordContext<'_>,
    ) -> Result<(), AdapterError> {
        self.record_from_value_classified(value, context)
            .map_err(A2aTaskRegistryRecordError::into_adapter_error)
    }

    fn record_from_value_classified(
        &self,
        value: &Value,
        context: &A2aTaskRecordContext<'_>,
    ) -> Result<(), A2aTaskRegistryRecordError> {
        let seen =
            task_observations_from_value(value).map_err(A2aTaskRegistryRecordError::Fatal)?;
        if seen.is_empty() {
            return Ok(());
        }

        let _guard = self.lock.lock().map_err(|_| {
            A2aTaskRegistryRecordError::Fatal(AdapterError::Lifecycle(
                "A2A task registry lock poisoned".to_string(),
            ))
        })?;
        let mut registry = self.load().map_err(A2aTaskRegistryRecordError::Fatal)?;
        let now = unix_timestamp_now();
        let mut first_rebind_conflict = None;
        let mut changed = false;
        for observation in seen {
            let entry = registry
                .tasks
                .entry(observation.task_id.clone())
                .or_insert_with(|| A2aTaskRecord {
                    task_id: observation.task_id.clone(),
                    tool_name: context.tool_name.to_string(),
                    server_id: context.server_id.to_string(),
                    interface_url: context.selected_interface.url.clone(),
                    protocol_binding: binding_label(context.selected_binding).to_string(),
                    tenant: context.selected_interface.tenant.clone(),
                    partner: context.partner.to_string(),
                    first_seen_at: now,
                    last_seen_at: now,
                    last_state: None,
                    last_source: context.source.to_string(),
                });
            if let Err(error) = validate_task_record_binding(entry, context) {
                if first_rebind_conflict.is_none() {
                    first_rebind_conflict = Some(error);
                }
                continue;
            }
            entry.last_seen_at = now;
            entry.last_source = context.source.to_string();
            entry.last_state = observation.state.or_else(|| entry.last_state.clone());
            changed = true;
        }
        if changed {
            self.save(&registry)
                .map_err(A2aTaskRegistryRecordError::Fatal)?;
        }
        if let Some(error) = first_rebind_conflict {
            return Err(A2aTaskRegistryRecordError::RebindConflict(error));
        }
        Ok(())
    }
}

fn task_observations_from_value(value: &Value) -> Result<Vec<A2aTaskObservation>, AdapterError> {
    let mut observations = Vec::new();
    if let Some(task) = value.get("task") {
        validate_task_value(task)?;
        let task_id = task.get("id").and_then(Value::as_str).ok_or_else(|| {
            AdapterError::Protocol("A2A task response must contain string `id`".to_string())
        })?;
        let state = task
            .get("status")
            .and_then(|status| status.get("state"))
            .and_then(Value::as_str)
            .map(str::to_string);
        observations.push(A2aTaskObservation {
            task_id: observed_task_id(task_id),
            state,
        });
    }
    if let Some(update) = value.get("statusUpdate") {
        validate_status_update(update)?;
        let task_id = update.get("taskId").and_then(Value::as_str).ok_or_else(|| {
            AdapterError::Protocol("A2A status update must contain string `taskId`".to_string())
        })?;
        let state = update
            .get("status")
            .and_then(|status| status.get("state"))
            .and_then(Value::as_str)
            .map(str::to_string);
        observations.push(A2aTaskObservation {
            task_id: observed_task_id(task_id),
            state,
        });
    }
    if let Some(update) = value.get("artifactUpdate") {
        validate_artifact_update(update)?;
        let task_id = update.get("taskId").and_then(Value::as_str).ok_or_else(|| {
            AdapterError::Protocol("A2A artifact update must contain string `taskId`".to_string())
        })?;
        observations.push(A2aTaskObservation {
            task_id: observed_task_id(task_id),
            state: None,
        });
    }
    Ok(observations)
}

fn observed_task_id(task_id: &str) -> String {
    task_id.to_string()
}

fn validate_task_record_binding(
    record: &A2aTaskRecord,
    context: &A2aTaskRecordContext<'_>,
) -> Result<(), AdapterError> {
    if record.tool_name != context.tool_name {
        return Err(AdapterError::Lifecycle(format!(
            "A2A task `{}` attempted to rebind from tool `{}` to `{}`",
            record.task_id, record.tool_name, context.tool_name
        )));
    }
    if record.server_id != context.server_id {
        return Err(AdapterError::Lifecycle(format!(
            "A2A task `{}` attempted to rebind from server `{}` to `{}`",
            record.task_id, record.server_id, context.server_id
        )));
    }
    if record.interface_url != context.selected_interface.url {
        return Err(AdapterError::Lifecycle(format!(
            "A2A task `{}` attempted to rebind from interface `{}` to `{}`",
            record.task_id, record.interface_url, context.selected_interface.url
        )));
    }
    let context_binding = binding_label(context.selected_binding);
    if record.protocol_binding != context_binding {
        return Err(AdapterError::Lifecycle(format!(
            "A2A task `{}` attempted to rebind from binding `{}` to `{}`",
            record.task_id, record.protocol_binding, context_binding
        )));
    }
    if record.tenant.as_deref() != context.selected_interface.tenant.as_deref() {
        return Err(AdapterError::Lifecycle(format!(
            "A2A task `{}` attempted to rebind from tenant `{}` to `{}`",
            record.task_id,
            record.tenant.as_deref().unwrap_or("none"),
            context.selected_interface.tenant.as_deref().unwrap_or("none")
        )));
    }
    if record.partner != context.partner {
        return Err(AdapterError::Lifecycle(format!(
            "A2A task `{}` attempted to rebind from partner `{}` to `{}`",
            record.task_id, record.partner, context.partner
        )));
    }
    Ok(())
}
