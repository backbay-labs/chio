impl SharedUpstreamToolServer {
    fn new(upstream: Arc<AdaptedMcpServer>) -> Self {
        let manifest = upstream.manifest_clone();
        Self {
            server_id: manifest.server_id,
            tool_names: manifest
                .tools
                .into_iter()
                .map(|tool| tool.name)
                .collect::<Vec<_>>(),
            upstream,
        }
    }
}
#[async_trait::async_trait]
impl ToolServerConnection for SharedUpstreamToolServer {
    fn server_id(&self) -> &str {
        &self.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tool_names.clone()
    }

    /// Delegate to the wrapped upstream so its manifest-derived read-only
    /// annotations (from the MCP `readOnlyHint`) survive the shared-upstream
    /// wrapping instead of falling back to the side-effecting default.
    fn tool_is_read_only(&self, tool_name: &str) -> bool {
        self.upstream.tool_is_read_only(tool_name)
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: Value,
        nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        ToolServerConnection::invoke(
            self.upstream.as_ref(),
            tool_name,
            arguments,
            nested_flow_bridge,
        )
        .await
    }
}

impl SharedUpstreamOwner {
    fn new(config: &RemoteServeHttpConfig) -> Result<Self, CliError> {
        let wrapped_arg_refs = config
            .wrapped_args
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let manifest_public_key = config
            .manifest_public_key
            .clone()
            .unwrap_or_else(|| Keypair::generate().public_key().to_hex());
        let notification_source: Arc<dyn McpTransport> = Arc::new(StdioMcpTransport::spawn(
            &config.wrapped_command,
            &wrapped_arg_refs,
        )?);
        let adapter = McpAdapter::new(
            McpAdapterConfig {
                server_id: config.server_id.clone(),
                server_name: config.server_name.clone(),
                server_version: config.server_version.clone(),
                public_key: manifest_public_key,
            },
            Box::new(SerializedMcpTransport::from_arc(
                notification_source.clone(),
            )),
        );
        let upstream_server = Arc::new(AdaptedMcpServer::new(adapter)?);
        let notification_subscribers =
            Arc::new(StdMutex::new(Vec::<Weak<StdMutex<VecDeque<Value>>>>::new()));
        let notification_stats = Arc::new(SharedUpstreamNotificationStats::default());
        let notification_source_for_thread = notification_source.clone();
        let notification_subscribers_for_thread = notification_subscribers.clone();
        let notification_stats_for_thread = notification_stats.clone();
        thread::spawn(move || loop {
            let notifications = notification_source_for_thread.drain_notifications();
            fan_out_shared_upstream_notifications(
                &notification_subscribers_for_thread,
                notification_stats_for_thread.as_ref(),
                notifications,
            );
            thread::sleep(Duration::from_millis(
                DEFAULT_SHARED_NOTIFICATION_POLL_MILLIS,
            ));
        });

        Ok(Self {
            upstream_server,
            notification_subscribers,
            notification_stats,
        })
    }

    fn upstream_server(&self) -> Arc<AdaptedMcpServer> {
        self.upstream_server.clone()
    }

    fn notification_tap(&self) -> Arc<dyn McpTransport> {
        let queue = Arc::new(StdMutex::new(VecDeque::new()));
        if let Ok(mut subscribers) = self.notification_subscribers.lock() {
            subscribers.push(Arc::downgrade(&queue));
        }
        Arc::new(SharedUpstreamNotificationTap { queue })
    }

    fn notification_stats_snapshot(&self) -> SharedUpstreamNotificationStatsSnapshot {
        SharedUpstreamNotificationStatsSnapshot {
            fanout_batches: self.notification_stats.fanout_batches.load(Ordering::Relaxed),
            fanout_notifications: self
                .notification_stats
                .fanout_notifications
                .load(Ordering::Relaxed),
            fanout_targets: self
                .notification_stats
                .fanout_targets
                .load(Ordering::Relaxed),
            pruned_subscribers: self
                .notification_stats
                .pruned_subscribers
                .load(Ordering::Relaxed),
            queue_lock_skips: self
                .notification_stats
                .queue_lock_skips
                .load(Ordering::Relaxed),
            subscriber_lock_failures: self
                .notification_stats
                .subscriber_lock_failures
                .load(Ordering::Relaxed),
        }
    }
}

impl McpTransport for SharedUpstreamNotificationTap {
    fn list_tools(&self) -> Result<Vec<chio_mcp_adapter::edge::McpToolInfo>, AdapterError> {
        Err(AdapterError::ConnectionFailed(
            "shared upstream notification tap does not support direct tool calls".to_string(),
        ))
    }

    fn call_tool(
        &self,
        _tool_name: &str,
        _arguments: Value,
    ) -> Result<chio_mcp_adapter::edge::McpToolResult, AdapterError> {
        Err(AdapterError::ConnectionFailed(
            "shared upstream notification tap does not support direct tool calls".to_string(),
        ))
    }

    fn drain_notifications(&self) -> Vec<Value> {
        let Ok(mut queue) = self.queue.lock() else {
            return vec![];
        };
        queue.drain(..).collect()
    }
}

fn fan_out_shared_upstream_notifications(
    subscribers: &NotificationSubscriberList,
    stats: &SharedUpstreamNotificationStats,
    notifications: Vec<Value>,
) {
    if notifications.is_empty() {
        return;
    }
    stats.fanout_batches.fetch_add(1, Ordering::Relaxed);
    stats
        .fanout_notifications
        .fetch_add(notifications.len() as u64, Ordering::Relaxed);
    let Ok(mut subscribers) = subscribers.lock() else {
        stats
            .subscriber_lock_failures
            .fetch_add(1, Ordering::Relaxed);
        warn!("failed to lock shared hosted-owner notification subscribers");
        return;
    };
    let before_prune = subscribers.len();
    subscribers.retain(|subscriber| subscriber.strong_count() > 0);
    let pruned = before_prune.saturating_sub(subscribers.len());
    if pruned > 0 {
        stats
            .pruned_subscribers
            .fetch_add(pruned as u64, Ordering::Relaxed);
    }
    // Shared hosted-owner mode multiplexes one upstream subprocess across many
    // sessions. Each session-local ChioMcpEdge still applies its own resource
    // subscription and elicitation filtering before surfacing client-visible
    // notifications, so the shared tap can safely replay raw upstream
    // notifications into every live session queue.
    for subscriber in subscribers.iter() {
        let Some(queue) = subscriber.upgrade() else {
            continue;
        };
        let Ok(mut queue) = queue.lock() else {
            stats
                .queue_lock_skips
                .fetch_add(notifications.len() as u64, Ordering::Relaxed);
            warn!("failed to lock shared hosted-owner notification tap queue");
            continue;
        };
        stats.fanout_targets.fetch_add(1, Ordering::Relaxed);
        queue.extend(notifications.iter().cloned());
    }
}
