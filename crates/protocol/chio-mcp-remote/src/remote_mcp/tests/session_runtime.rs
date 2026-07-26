use super::*;

fn private_remote_admission_directory(label: &str) -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "chio-remote-admission-{label}-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("create remote admission directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("secure remote admission directory");
    }
    directory
}

#[test]
fn mcp_rate_limiter_caps_session_window() {
    let limiter = McpRateLimiter::new();
    for _ in 0..MCP_RATE_LIMIT_MAX_REQUESTS {
        assert!(limiter.check("session:test".to_string(), 120).is_ok());
    }

    let retry_after = limiter
        .check("session:test".to_string(), 120)
        .expect_err("session should be rate limited after the window budget is exhausted");
    assert_eq!(retry_after, 60);
    assert!(limiter.check("session:test".to_string(), 180).is_ok());
}

#[test]
fn mcp_rate_limiter_caps_tracked_keys() {
    let limiter = McpRateLimiter::new();
    for idx in 0..MCP_RATE_LIMIT_MAX_KEYS {
        assert!(limiter.check(format!("session:{idx}"), 120).is_ok());
    }

    let retry_after = limiter
        .check("session:overflow".to_string(), 120)
        .expect_err("new rate-limit keys should be capped within a window");
    assert_eq!(retry_after, 60);
    assert!(limiter.check("session:0".to_string(), 120).is_ok());
}

#[test]
fn remote_session_factory_holds_one_durable_admission_sidecar() {
    let directory = private_remote_admission_directory("owner");
    let policy_path = directory.join("policy.yaml");
    std::fs::write(
        &policy_path,
        "capabilities:\n  default:\n    tools: []\n",
    )
    .expect("write remote admission policy");
    let session_database = directory.join("sessions.sqlite3");
    let mut config = test_remote_config();
    config.policy_path = policy_path;
    config.session_db_path = Some(session_database.clone());

    let factory =
        RemoteSessionFactory::new(config.clone()).expect("claim remote durable admission owner");
    assert!(factory.durable_admission.is_some());
    assert_ne!(
        durable_admission_sidecar_path(&session_database)
            .expect("derive remote admission sidecar"),
        session_database
    );
    assert!(RemoteSessionFactory::new(config.clone()).is_err());

    drop(factory);
    RemoteSessionFactory::new(config).expect("reclaim remote admission owner after shutdown");
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn remote_session_factory_rejects_admission_sidecar_aliases() {
    let directory = private_remote_admission_directory("alias");
    let policy_path = directory.join("policy.yaml");
    std::fs::write(
        &policy_path,
        "capabilities:\n  default:\n    tools: []\n",
    )
    .expect("write remote admission policy");
    let session_database = directory.join("sessions.sqlite3");
    let admission_database =
        durable_admission_sidecar_path(&session_database).expect("derive admission sidecar");
    let mut config = test_remote_config();
    config.policy_path = policy_path;
    config.session_db_path = Some(session_database);
    config.receipt_db_path = Some(admission_database);

    let error = RemoteSessionFactory::new(config)
        .err()
        .expect("admission sidecar alias must be rejected");
    assert!(error
        .to_string()
        .contains("durable admission database must not alias receipt database"));
    let _ = std::fs::remove_dir_all(directory);
}
