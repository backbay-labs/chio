use super::*;

#[test]
fn tenant_ids_are_closed_and_bounded() {
    assert!(HostedTenantId::new("tenant:acme-1").is_ok());
    assert!(HostedTenantId::new("").is_err());
    assert!(HostedTenantId::new("tenant with spaces").is_err());
    assert!(HostedTenantId::new("x".repeat(MAX_TENANT_ID_BYTES + 1)).is_err());
}

#[test]
fn tenant_limits_are_closed_and_bounded() {
    assert!(HostedTenantLimits::new(1, 1, 1, "revision-1").is_ok());
    assert!(HostedTenantLimits::new(0, 1, 1, "revision-1").is_err());
    assert!(HostedTenantLimits::new(1, 0, 1, "revision-1").is_err());
    assert!(HostedTenantLimits::new(1, 1, 0, "revision-1").is_err());
    assert!(HostedTenantLimits::new(1, 1, 1, "revision with spaces").is_err());
}

#[test]
fn postgres_dsn_is_redacted_and_tls_is_forced() {
    let config = HostedPostgresConfig::new("postgres://market-user:super-secret@db.example/chio")
        .unwrap_or_else(|error| panic!("valid PostgreSQL config: {error}"));
    let debug = format!("{config:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("super-secret"));
    let options = config
        .connect_options()
        .unwrap_or_else(|error| panic!("connect options: {error}"));
    assert!(matches!(options.get_ssl_mode(), PgSslMode::VerifyFull));
}

#[test]
fn postgres_pool_bounds_reject_operational_extremes() {
    let config = || HostedPostgresConfig::new("postgres://market-user@db.example/chio");
    assert!(config()
        .and_then(|value| value.with_acquire_timeout(Duration::from_millis(100)))
        .is_ok());
    assert!(config()
        .and_then(|value| value.with_acquire_timeout(Duration::from_millis(99)))
        .is_err());
    assert!(config()
        .and_then(|value| value.with_acquire_timeout(Duration::from_secs(31)))
        .is_err());
}

#[test]
fn canonical_payload_validation_fails_closed() {
    assert!(validate_canonical_json(br#"{"a":1,"b":2}"#, "payload").is_ok());
    assert!(validate_canonical_json(br#"{ "b": 2, "a": 1 }"#, "payload").is_err());
    assert!(validate_canonical_json(&[], "payload").is_err());
}
