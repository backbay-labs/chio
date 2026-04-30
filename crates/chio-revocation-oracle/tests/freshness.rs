use chio_revocation_oracle::{
    verify_fresh_epoch_root, EpochNonce, FreshnessConfig, InMemoryRevocationOracle, RevocationKey,
    RevocationOracle, SubjectId,
};

#[test]
fn fail_closed_default_denies_stale_root() -> chio_revocation_oracle::Result<()> {
    let mut oracle = InMemoryRevocationOracle::new();
    let key = RevocationKey::new(SubjectId::from("subject-a"), EpochNonce::new(1));
    let root = oracle.insert(key, 1_000)?;

    assert!(verify_fresh_epoch_root(&root, 1_000, FreshnessConfig::default()).is_ok());
    assert!(verify_fresh_epoch_root(&root, 1_001, FreshnessConfig::default()).is_err());
    Ok(())
}

#[test]
fn offline_grace_accepts_bounded_staleness() -> chio_revocation_oracle::Result<()> {
    let mut oracle = InMemoryRevocationOracle::new();
    let key = RevocationKey::new(SubjectId::from("subject-a"), EpochNonce::new(1));
    let root = oracle.insert(key, 1_000)?;
    let config = FreshnessConfig::with_offline_grace(100, 900);

    assert!(verify_fresh_epoch_root(&root, 2_000, config).is_ok());
    assert!(verify_fresh_epoch_root(&root, 2_001, config).is_err());
    Ok(())
}
