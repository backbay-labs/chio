use super::*;

#[test]
fn build_cluster_state_seeds_persisted_authority_fence_term() {
    let authority_db_path = unique_temp_path("cluster-authority-fence", "sqlite3");
    let authority = SqliteCapabilityAuthority::open(&authority_db_path).test_unwrap();
    authority
        .seed_cluster_fence(Some("http://node-b"), 7)
        .test_unwrap();

    let mut config = base_config();
    config.advertise_url = Some("http://node-a".to_string());
    config.peer_urls = vec!["http://node-b".to_string()];
    config.authority_db_path = Some(authority_db_path.clone());

    let cluster = build_cluster_state(&config, config.listen)
        .test_unwrap()
        .test_unwrap();
    let guard = cluster.lock().test_unwrap();
    assert_eq!(guard.election_term, 7);
    assert_eq!(guard.last_leader_url.as_deref(), Some("http://node-b"));

    let _ = std::fs::remove_file(authority_db_path);
}

#[test]
fn build_cluster_state_discards_persisted_authority_fence_for_unknown_leader() {
    let authority_db_path = unique_temp_path("cluster-authority-fence-unknown-leader", "sqlite3");
    let authority = SqliteCapabilityAuthority::open(&authority_db_path).test_unwrap();
    authority
        .seed_cluster_fence(Some("http://node-z"), 7)
        .test_unwrap();

    let mut config = base_config();
    config.advertise_url = Some("http://node-a".to_string());
    config.peer_urls = vec!["http://node-b".to_string()];
    config.authority_db_path = Some(authority_db_path.clone());

    let cluster = build_cluster_state(&config, config.listen)
        .test_unwrap()
        .test_unwrap();
    let guard = cluster.lock().test_unwrap();
    assert_eq!(guard.election_term, 7);
    assert!(
        guard.last_leader_url.is_none(),
        "unknown persisted leader should be cleared"
    );

    let _ = std::fs::remove_file(authority_db_path);
}

#[test]
fn build_cluster_state_discards_persisted_authority_fence_after_rotation() {
    let authority_db_path = unique_temp_path("cluster-authority-fence-stale-generation", "sqlite3");
    let authority = SqliteCapabilityAuthority::open(&authority_db_path).test_unwrap();
    authority
        .seed_cluster_fence(Some("http://node-b"), 7)
        .test_unwrap();
    authority.rotate().test_unwrap();

    let mut config = base_config();
    config.advertise_url = Some("http://node-a".to_string());
    config.peer_urls = vec!["http://node-b".to_string()];
    config.authority_db_path = Some(authority_db_path.clone());

    let cluster = build_cluster_state(&config, config.listen)
        .test_unwrap()
        .test_unwrap();
    let guard = cluster.lock().test_unwrap();
    assert_eq!(guard.election_term, 0);
    assert!(guard.last_leader_url.is_none());

    let _ = std::fs::remove_file(authority_db_path);
}
