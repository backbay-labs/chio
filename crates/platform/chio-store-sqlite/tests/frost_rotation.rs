use std::fs;
use std::path::{Path, PathBuf};

use chio_core::Keypair;
use chio_federation_authority::{
    advance_frost_ceremony, begin_frost_ceremony, FrostCeremonyConfig, FrostCeremonyParticipant,
};
use chio_store_sqlite::{
    FrostCeremonyState, FrostCustodyKey, SqliteAuthorityStore, SqliteFrostStore,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tempfile::TempDir;

struct StoreFixture {
    _temp: TempDir,
    database: PathBuf,
    lock_root: PathBuf,
}

impl StoreFixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let database = temp.path().join("authority.db");
        let lock_root = temp.path().join("locks");
        fs::create_dir(&lock_root).unwrap_or_else(|error| panic!("create lock root: {error}"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|error| panic!("secure database parent: {error}"));
            fs::set_permissions(&lock_root, fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|error| panic!("secure lock root: {error}"));
        }
        SqliteAuthorityStore::provision(&database, &lock_root)
            .unwrap_or_else(|error| panic!("provision authority: {error}"));
        Self {
            _temp: temp,
            database,
            lock_root,
        }
    }

    fn open(&self) -> (SqliteAuthorityStore, SqliteFrostStore) {
        let authority = SqliteAuthorityStore::open_serving(&self.database, &self.lock_root)
            .unwrap_or_else(|error| panic!("open authority: {error}"));
        let frost = authority.frost_store();
        (authority, frost)
    }
}

struct ParticipantFixture {
    config: FrostCeremonyConfig,
    transport_key: Keypair,
}

fn participants() -> Vec<ParticipantFixture> {
    let keys = [
        Keypair::from_seed(&[0x51; 32]),
        Keypair::from_seed(&[0x52; 32]),
        Keypair::from_seed(&[0x53; 32]),
    ];
    let participants = keys
        .iter()
        .enumerate()
        .map(|(index, key)| FrostCeremonyParticipant {
            participant_id: format!("operator-{}", index + 1),
            transport_key_id: format!("operator-{}.dkg.v1", index + 1),
            transport_public_key: key.public_key(),
        })
        .collect::<Vec<_>>();
    keys.into_iter()
        .enumerate()
        .map(|(index, transport_key)| ParticipantFixture {
            config: FrostCeremonyConfig {
                scope_id: "treaty.atlantic.v1".to_string(),
                key_epoch: 2,
                threshold: 2,
                predecessor_roster_digest: Some("64".repeat(32)),
                participants: participants.clone(),
                local_participant_id: format!("operator-{}", index + 1),
            },
            transport_key,
        })
        .collect()
}

fn custody() -> FrostCustodyKey {
    FrostCustodyKey::new("custody-generation-7", [0xa5; 32])
        .unwrap_or_else(|error| panic!("custody key: {error}"))
}

fn reopen(
    fixture: &StoreFixture,
    authority: SqliteAuthorityStore,
    frost: SqliteFrostStore,
) -> (SqliteAuthorityStore, SqliteFrostStore) {
    drop(frost);
    drop(authority);
    fixture.open()
}

#[test]
fn frost_rotation_ceremony_commits_each_round_before_replay_after_restart() {
    let fixture = StoreFixture::new();
    let participants = participants();
    let (mut authority, mut frost) = fixture.open();

    let mut rng = ChaCha20Rng::from_seed([1; 32]);
    let first = frost
        .begin_ceremony(
            &participants[0].config,
            &participants[0].transport_key,
            &custody(),
            &mut rng,
            &authority.mutation_fence(),
            1_000,
        )
        .unwrap_or_else(|error| panic!("persist round one: {error}"));
    assert_eq!(first.state, FrostCeremonyState::Round1Ready);

    (authority, frost) = reopen(&fixture, authority, frost);
    let mut retry_rng = ChaCha20Rng::from_seed([99; 32]);
    let replayed_first = frost
        .begin_ceremony(
            &participants[0].config,
            &participants[0].transport_key,
            &custody(),
            &mut retry_rng,
            &authority.mutation_fence(),
            1_001,
        )
        .unwrap_or_else(|error| panic!("replay round one: {error}"));
    assert_eq!(replayed_first.package, first.package);
    assert_eq!(replayed_first.state_version, first.state_version);

    let mut round1 = vec![replayed_first.package.clone()];
    let mut peer_round1_secrets = Vec::new();
    for (index, participant) in participants.iter().enumerate().skip(1) {
        let mut rng = ChaCha20Rng::from_seed([index as u8 + 1; 32]);
        let transition =
            begin_frost_ceremony(&participant.config, &participant.transport_key, &mut rng)
                .unwrap_or_else(|error| panic!("peer round one: {error}"));
        round1.push(transition.package);
        peer_round1_secrets.push(transition.secret);
    }

    let second = frost
        .advance_ceremony(
            &participants[0].config,
            &participants[0].transport_key,
            &custody(),
            &round1,
            &authority.mutation_fence(),
            2_000,
        )
        .unwrap_or_else(|error| panic!("persist round two: {error}"));
    assert_eq!(second.state, FrostCeremonyState::Round2Ready);

    (authority, frost) = reopen(&fixture, authority, frost);
    let replayed_second = frost
        .advance_ceremony(
            &participants[0].config,
            &participants[0].transport_key,
            &custody(),
            &round1,
            &authority.mutation_fence(),
            2_001,
        )
        .unwrap_or_else(|error| panic!("replay round two: {error}"));
    assert_eq!(replayed_second.packages, second.packages);
    assert_eq!(replayed_second.state_version, second.state_version);

    let mut round2 = replayed_second.packages.clone();
    for ((participant, secret), index) in participants
        .iter()
        .skip(1)
        .zip(peer_round1_secrets)
        .zip(0_u8..)
    {
        let transition = advance_frost_ceremony(
            &participant.config,
            &participant.transport_key,
            secret,
            &round1,
        )
        .unwrap_or_else(|error| panic!("peer round two {index}: {error}"));
        round2.extend(transition.packages);
    }

    let completed = frost
        .complete_ceremony(
            &participants[0].config,
            &custody(),
            &round1,
            &round2,
            &authority.mutation_fence(),
            3_000,
        )
        .unwrap_or_else(|error| panic!("persist completion: {error}"));
    assert_eq!(completed.state, FrostCeremonyState::Completed);

    (authority, frost) = reopen(&fixture, authority, frost);
    let replayed_completion = frost
        .complete_ceremony(
            &participants[0].config,
            &custody(),
            &round1,
            &round2,
            &authority.mutation_fence(),
            3_001,
        )
        .unwrap_or_else(|error| panic!("replay completion: {error}"));
    assert_eq!(replayed_completion, completed);
    let key_package = frost
        .load_completed_key_package(
            &completed.ceremony_id,
            &custody(),
            &authority.mutation_fence(),
        )
        .unwrap_or_else(|error| panic!("load completed key: {error}"));
    assert_eq!(
        key_package.kind(),
        chio_federation_authority::FrostCeremonySecretKind::KeyPackage
    );
}

#[test]
fn frost_rotation_ceremony_rejects_changed_config_and_wrong_custody_generation() {
    let fixture = StoreFixture::new();
    let participants = participants();
    let (authority, frost) = fixture.open();
    let mut rng = ChaCha20Rng::from_seed([4; 32]);
    let first = frost
        .begin_ceremony(
            &participants[0].config,
            &participants[0].transport_key,
            &custody(),
            &mut rng,
            &authority.mutation_fence(),
            1_000,
        )
        .unwrap_or_else(|error| panic!("persist round one: {error}"));

    let wrong_custody = FrostCustodyKey::new("custody-generation-8", [0xa5; 32])
        .unwrap_or_else(|error| panic!("wrong custody fixture: {error}"));
    assert!(frost
        .load_ceremony(&first.ceremony_id, &wrong_custody)
        .is_err());

    let mut changed = participants[0].config.clone();
    changed.threshold = 3;
    let mut retry_rng = ChaCha20Rng::from_seed([5; 32]);
    assert!(frost
        .begin_ceremony(
            &changed,
            &participants[0].transport_key,
            &custody(),
            &mut retry_rng,
            &authority.mutation_fence(),
            1_001,
        )
        .is_err());
}

#[test]
fn frost_rotation_ceremony_never_persists_round_material_in_plaintext() {
    let fixture = StoreFixture::new();
    let participants = participants();
    let (authority, frost) = fixture.open();
    let mut rng = ChaCha20Rng::from_seed([6; 32]);
    let first = frost
        .begin_ceremony(
            &participants[0].config,
            &participants[0].transport_key,
            &custody(),
            &mut rng,
            &authority.mutation_fence(),
            1_000,
        )
        .unwrap_or_else(|error| panic!("persist round one: {error}"));
    let package_bytes = serde_json::to_vec(&first.package)
        .unwrap_or_else(|error| panic!("serialize package: {error}"));
    drop(frost);
    drop(authority);

    assert_database_files_exclude(&fixture.database, &package_bytes);
}

fn assert_database_files_exclude(database: &Path, needle: &[u8]) {
    for path in [
        database.to_path_buf(),
        PathBuf::from(format!("{}-wal", database.display())),
    ] {
        if let Ok(bytes) = fs::read(&path) {
            assert!(
                !bytes.windows(needle.len()).any(|window| window == needle),
                "{} contains plaintext ceremony output",
                path.display()
            );
        }
    }
}
