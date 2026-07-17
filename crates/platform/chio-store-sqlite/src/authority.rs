use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chio_core::capability::{
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::{Keypair, PublicKey};
use chio_kernel::{
    AuthoritySnapshot, AuthorityStatus, AuthorityStoreError, AuthorityTrustedKeySnapshot,
    CapabilityAuthority, KernelError,
};
use rusqlite::{params, Connection};
use uuid::Uuid;

pub struct SqliteCapabilityAuthority {
    path: PathBuf,
    cached_public_key: Mutex<PublicKey>,
    cached_trusted_public_keys: Mutex<Vec<PublicKey>>,
}

/// Authority-store schema revision. Bump on every schema-affecting change.
const AUTHORITY_STORE_SUPPORTED_SCHEMA_VERSION: i32 = 0;
/// Stable key under which this store records its schema revision in the shared
/// keyed metadata table, distinct from any co-located store's key.
const AUTHORITY_STORE_SCHEMA_KEY: &str = "authority";
/// Tables shipped before schema stamping existed, used to adopt a pre-stamping
/// authority database rather than reject it as foreign.
const AUTHORITY_STORE_LEGACY_ANCHOR_TABLES: &[&str] = &["authority_state"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityClusterFence {
    pub leader_url: Option<String>,
    pub election_term: u64,
    pub updated_at: u64,
    pub authority_generation: u64,
    pub authority_rotated_at: u64,
}

impl SqliteCapabilityAuthority {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuthorityStoreError> {
        let path = path.as_ref().to_path_buf();
        // Resolve any `file:` URI to its on-disk parent before creating it, so a
        // URI-configured store creates the real backing directory rather than a
        // bogus scheme-prefixed one.
        if let Some(parent) = crate::sqlite_parent_dir_to_create(&path) {
            fs::create_dir_all(&parent)?;
        }

        let bootstrap = Keypair::generate();
        let connection = Self::open_connection(&path)?;
        connection.execute(
            r#"
            INSERT INTO authority_state (singleton_id, seed_hex, public_key_hex, generation, rotated_at)
            VALUES (1, ?1, ?2, 1, ?3)
            ON CONFLICT(singleton_id) DO NOTHING
            "#,
            params![
                bootstrap.seed_hex(),
                bootstrap.public_key().to_hex(),
                unix_now() as i64
            ],
        )?;
        let current_public_key = connection
            .query_row(
                r#"
                SELECT seed_hex
                FROM authority_state
                WHERE singleton_id = 1
                "#,
                [],
                |row| row.get::<_, String>(0),
            )
            .map(|seed_hex| Keypair::from_seed_hex(seed_hex.trim()))
            .map_err(AuthorityStoreError::from)??;
        connection.execute(
            r#"
            UPDATE authority_state
            SET public_key_hex = COALESCE(NULLIF(public_key_hex, ''), ?1)
            WHERE singleton_id = 1
            "#,
            params![current_public_key.public_key().to_hex()],
        )?;
        connection.execute(
            r#"
            INSERT INTO authority_trusted_keys (public_key_hex, generation, activated_at)
            VALUES (?1, 1, ?2)
            ON CONFLICT(public_key_hex) DO NOTHING
            "#,
            params![current_public_key.public_key().to_hex(), unix_now() as i64],
        )?;
        let status = Self::read_status_from_connection(&connection)?;
        Ok(Self {
            path,
            cached_public_key: Mutex::new(status.public_key),
            cached_trusted_public_keys: Mutex::new(status.trusted_public_keys),
        })
    }

    pub fn status(&self) -> Result<AuthorityStatus, AuthorityStoreError> {
        let connection = Self::open_connection(&self.path)?;
        let status = Self::read_status_from_connection(&connection)?;
        self.update_cached_public_key(status.public_key.clone());
        self.update_cached_trusted_public_keys(status.trusted_public_keys.clone());
        Ok(status)
    }

    pub fn rotate(&self) -> Result<AuthorityStatus, AuthorityStoreError> {
        let connection = Self::open_connection(&self.path)?;
        let status_before = Self::read_status_from_connection(&connection)?;
        let keypair = Keypair::generate();
        let rotated_at = unix_now();
        let next_generation = status_before.generation.saturating_add(1);

        connection.execute(
            r#"
            UPDATE authority_state
            SET seed_hex = ?1, public_key_hex = ?2, generation = ?3, rotated_at = ?4
            WHERE singleton_id = 1
            "#,
            params![
                keypair.seed_hex(),
                keypair.public_key().to_hex(),
                next_generation as i64,
                rotated_at as i64,
            ],
        )?;
        connection.execute(
            r#"
            INSERT INTO authority_trusted_keys (public_key_hex, generation, activated_at)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(public_key_hex) DO NOTHING
            "#,
            params![
                keypair.public_key().to_hex(),
                next_generation as i64,
                rotated_at as i64
            ],
        )?;

        let status = Self::read_status_from_connection(&connection)?;
        self.update_cached_public_key(status.public_key.clone());
        self.update_cached_trusted_public_keys(status.trusted_public_keys.clone());
        Ok(status)
    }

    pub fn snapshot(&self) -> Result<AuthoritySnapshot, AuthorityStoreError> {
        let connection = Self::open_connection(&self.path)?;
        let status = Self::read_status_from_connection(&connection)?;
        Ok(AuthoritySnapshot {
            public_key_hex: status.public_key.to_hex(),
            generation: status.generation,
            rotated_at: status.rotated_at,
            trusted_keys: Self::read_trusted_key_snapshots(&connection)?,
        })
    }

    pub fn apply_snapshot(
        &self,
        snapshot: &AuthoritySnapshot,
    ) -> Result<bool, AuthorityStoreError> {
        let connection = Self::open_connection(&self.path)?;
        let local_snapshot = self.snapshot()?;
        let remote_public_key = PublicKey::from_hex(snapshot.public_key_hex.trim())?;

        // Cluster snapshots replicate verification history, not signing custody.
        connection.execute(
            r#"
            INSERT INTO authority_trusted_keys (public_key_hex, generation, activated_at)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(public_key_hex) DO UPDATE SET
                generation = MAX(generation, excluded.generation),
                activated_at = MIN(activated_at, excluded.activated_at)
            "#,
            params![
                remote_public_key.to_hex(),
                snapshot.generation as i64,
                snapshot.rotated_at as i64
            ],
        )?;
        for trusted_key in &snapshot.trusted_keys {
            connection.execute(
                r#"
                INSERT INTO authority_trusted_keys (public_key_hex, generation, activated_at)
                VALUES (?1, ?2, ?3)
                ON CONFLICT(public_key_hex) DO UPDATE SET
                    generation = MAX(generation, excluded.generation),
                    activated_at = MIN(activated_at, excluded.activated_at)
                "#,
                params![
                    trusted_key.public_key_hex,
                    trusted_key.generation as i64,
                    trusted_key.activated_at as i64
                ],
            )?;
        }

        let should_replace = snapshot.generation > local_snapshot.generation
            || (snapshot.generation == local_snapshot.generation
                && (snapshot.rotated_at, snapshot.public_key_hex.as_str())
                    > (
                        local_snapshot.rotated_at,
                        local_snapshot.public_key_hex.as_str(),
                    ));
        if should_replace {
            connection.execute(
                r#"
                UPDATE authority_state
                SET public_key_hex = ?1, generation = ?2, rotated_at = ?3
                WHERE singleton_id = 1
                "#,
                params![
                    remote_public_key.to_hex(),
                    snapshot.generation as i64,
                    snapshot.rotated_at as i64,
                ],
            )?;
        }

        let status = Self::read_status_from_connection(&connection)?;
        self.update_cached_public_key(status.public_key);
        self.update_cached_trusted_public_keys(status.trusted_public_keys);
        Ok(should_replace)
    }

    pub fn current_keypair(&self) -> Result<Keypair, AuthorityStoreError> {
        self.read_current_keypair()
    }

    pub fn local_keypair(&self) -> Result<Keypair, AuthorityStoreError> {
        let connection = Self::open_connection(&self.path)?;
        Self::read_keypair_from_connection(&connection)
    }

    pub fn cluster_fence(&self) -> Result<AuthorityClusterFence, AuthorityStoreError> {
        let connection = Self::open_connection(&self.path)?;
        Self::read_cluster_fence_from_connection(&connection)
    }

    pub fn seed_cluster_fence(
        &self,
        leader_url: Option<&str>,
        election_term: u64,
    ) -> Result<bool, AuthorityStoreError> {
        let connection = Self::open_connection(&self.path)?;
        let current = Self::read_cluster_fence_from_connection(&connection)?;
        let (_, authority_generation, authority_rotated_at) =
            Self::read_public_state_from_connection(&connection)?;
        let next_leader = leader_url.map(ToOwned::to_owned);
        let same_term_same_leader = election_term == current.election_term
            && current.leader_url.as_deref() == next_leader.as_deref();
        let fence_authority_state_is_stale = (current.election_term > 0
            || current.leader_url.is_some())
            && (current.authority_generation != authority_generation
                || current.authority_rotated_at != authority_rotated_at);
        let should_update = election_term > current.election_term
            || (election_term == current.election_term
                && current.leader_url.is_none()
                && next_leader.is_some())
            || (same_term_same_leader && fence_authority_state_is_stale);
        if should_update {
            Self::write_cluster_fence_to_connection(&connection, next_leader, election_term)?;
        }
        Ok(should_update)
    }

    pub fn enforce_cluster_fence(
        &self,
        leader_url: &str,
        election_term: u64,
    ) -> Result<(), AuthorityStoreError> {
        let connection = Self::open_connection(&self.path)?;
        let current = Self::read_cluster_fence_from_connection(&connection)?;
        let (_, authority_generation, authority_rotated_at) =
            Self::read_public_state_from_connection(&connection)?;
        if (current.election_term > 0 || current.leader_url.is_some())
            && (current.authority_generation != authority_generation
                || current.authority_rotated_at != authority_rotated_at)
        {
            return Err(AuthorityStoreError::Fence(format!(
                "persisted authority fence generation `{}` rotated_at `{}` does not match current authority generation `{authority_generation}` rotated_at `{authority_rotated_at}`",
                current.authority_generation, current.authority_rotated_at
            )));
        }
        if election_term < current.election_term {
            return Err(AuthorityStoreError::Fence(format!(
                "stale authority term `{election_term}` is below persisted term `{}`",
                current.election_term
            )));
        }
        if election_term == current.election_term
            && current
                .leader_url
                .as_deref()
                .is_some_and(|current_leader| current_leader != leader_url)
        {
            return Err(AuthorityStoreError::Fence(format!(
                "authority term `{election_term}` is already fenced to leader `{}`",
                current.leader_url.unwrap_or_default()
            )));
        }
        Self::write_cluster_fence_to_connection(
            &connection,
            Some(leader_url.to_string()),
            election_term,
        )
    }

    fn open_connection(path: &Path) -> Result<Connection, AuthorityStoreError> {
        let connection = Connection::open(path)?;
        crate::check_schema_version(
            &connection,
            AUTHORITY_STORE_SCHEMA_KEY,
            AUTHORITY_STORE_SUPPORTED_SCHEMA_VERSION,
            AUTHORITY_STORE_LEGACY_ANCHOR_TABLES,
        )
        .map_err(|error| AuthorityStoreError::Schema(error.to_string()))?;
        connection.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS authority_state (
                singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                seed_hex TEXT NOT NULL,
                public_key_hex TEXT,
                generation INTEGER NOT NULL,
                rotated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS authority_trusted_keys (
                public_key_hex TEXT PRIMARY KEY,
                generation INTEGER NOT NULL,
                activated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS authority_cluster_fence (
                singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                leader_url TEXT,
                election_term INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                authority_generation INTEGER NOT NULL DEFAULT 0,
                authority_rotated_at INTEGER NOT NULL DEFAULT 0
            );

            INSERT INTO authority_cluster_fence (singleton_id, leader_url, election_term, updated_at)
            VALUES (1, NULL, 0, 0)
            ON CONFLICT(singleton_id) DO NOTHING;
            "#,
        )?;
        if !Self::table_has_column(&connection, "authority_state", "public_key_hex")? {
            connection.execute(
                "ALTER TABLE authority_state ADD COLUMN public_key_hex TEXT",
                [],
            )?;
        }
        if !Self::table_has_column(
            &connection,
            "authority_cluster_fence",
            "authority_generation",
        )? {
            connection.execute(
                "ALTER TABLE authority_cluster_fence ADD COLUMN authority_generation INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        if !Self::table_has_column(
            &connection,
            "authority_cluster_fence",
            "authority_rotated_at",
        )? {
            connection.execute(
                "ALTER TABLE authority_cluster_fence ADD COLUMN authority_rotated_at INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        crate::stamp_schema_version(
            &connection,
            AUTHORITY_STORE_SCHEMA_KEY,
            AUTHORITY_STORE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| AuthorityStoreError::Schema(error.to_string()))?;
        Ok(connection)
    }

    fn read_status_from_connection(
        connection: &Connection,
    ) -> Result<AuthorityStatus, AuthorityStoreError> {
        let (public_key, generation, rotated_at) =
            Self::read_public_state_from_connection(connection)?;
        Ok(AuthorityStatus {
            public_key,
            generation,
            rotated_at,
            trusted_public_keys: Self::read_trusted_public_keys(connection)?,
        })
    }

    fn read_keypair_from_connection(
        connection: &Connection,
    ) -> Result<Keypair, AuthorityStoreError> {
        let seed_hex = connection.query_row(
            r#"
            SELECT seed_hex
            FROM authority_state
            WHERE singleton_id = 1
            "#,
            [],
            |row| row.get::<_, String>(0),
        )?;
        Keypair::from_seed_hex(seed_hex.trim()).map_err(Into::into)
    }

    fn read_public_state_from_connection(
        connection: &Connection,
    ) -> Result<(PublicKey, u64, u64), AuthorityStoreError> {
        let (seed_hex, public_key_hex, generation, rotated_at) = connection.query_row(
            r#"
            SELECT seed_hex, public_key_hex, generation, rotated_at
            FROM authority_state
            WHERE singleton_id = 1
            "#,
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )?;
        let public_key = match public_key_hex
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(public_key_hex) => PublicKey::from_hex(public_key_hex)?,
            None => Keypair::from_seed_hex(seed_hex.trim())?.public_key(),
        };
        Ok((
            public_key,
            generation.max(0) as u64,
            rotated_at.max(0) as u64,
        ))
    }

    fn read_current_keypair(&self) -> Result<Keypair, AuthorityStoreError> {
        let connection = Self::open_connection(&self.path)?;
        let keypair = Self::read_keypair_from_connection(&connection)?;
        let status = Self::read_status_from_connection(&connection)?;
        self.update_cached_public_key(status.public_key.clone());
        self.update_cached_trusted_public_keys(status.trusted_public_keys.clone());
        if keypair.public_key() != status.public_key {
            return Err(AuthorityStoreError::Fence(format!(
                "local signing seed public key {} does not match replicated authority public key {}",
                keypair.public_key().to_hex(),
                status.public_key.to_hex(),
            )));
        }
        Ok(keypair)
    }

    fn table_has_column(
        connection: &Connection,
        table: &str,
        column: &str,
    ) -> Result<bool, AuthorityStoreError> {
        let pragma = format!("PRAGMA table_info({table})");
        let mut statement = connection.prepare(&pragma)?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            if row.get::<_, String>(1)? == column {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn update_cached_public_key(&self, public_key: PublicKey) {
        match self.cached_public_key.lock() {
            Ok(mut guard) => *guard = public_key,
            Err(poisoned) => {
                tracing::error!(
                    "cached_public_key mutex is poisoned - recovering possibly-stale key material"
                );
                *poisoned.into_inner() = public_key;
            }
        }
    }

    fn update_cached_trusted_public_keys(&self, public_keys: Vec<PublicKey>) {
        match self.cached_trusted_public_keys.lock() {
            Ok(mut guard) => *guard = public_keys,
            Err(poisoned) => {
                tracing::error!(
                    "cached_trusted_public_keys mutex is poisoned - recovering possibly-stale key material"
                );
                *poisoned.into_inner() = public_keys;
            }
        }
    }

    fn cached_public_key(&self) -> PublicKey {
        match self.cached_public_key.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => {
                tracing::error!(
                    "cached_public_key mutex is poisoned - reading possibly-stale key material"
                );
                poisoned.into_inner().clone()
            }
        }
    }

    fn cached_trusted_public_keys(&self) -> Vec<PublicKey> {
        match self.cached_trusted_public_keys.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => {
                tracing::error!(
                    "cached_trusted_public_keys mutex is poisoned - reading possibly-stale key material"
                );
                poisoned.into_inner().clone()
            }
        }
    }

    fn read_trusted_public_keys(
        connection: &Connection,
    ) -> Result<Vec<PublicKey>, AuthorityStoreError> {
        let mut statement = connection.prepare(
            r#"
            SELECT public_key_hex
            FROM authority_trusted_keys
            ORDER BY generation ASC, activated_at ASC
            "#,
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|row| {
            let public_key_hex = row?;
            PublicKey::from_hex(public_key_hex.trim()).map_err(AuthorityStoreError::from)
        })
        .collect()
    }

    fn read_trusted_key_snapshots(
        connection: &Connection,
    ) -> Result<Vec<AuthorityTrustedKeySnapshot>, AuthorityStoreError> {
        let mut statement = connection.prepare(
            r#"
            SELECT public_key_hex, generation, activated_at
            FROM authority_trusted_keys
            ORDER BY generation ASC, activated_at ASC, public_key_hex ASC
            "#,
        )?;
        let rows = statement.query_map([], |row| {
            Ok(AuthorityTrustedKeySnapshot {
                public_key_hex: row.get(0)?,
                generation: row.get::<_, i64>(1)?.max(0) as u64,
                activated_at: row.get::<_, i64>(2)?.max(0) as u64,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn read_cluster_fence_from_connection(
        connection: &Connection,
    ) -> Result<AuthorityClusterFence, AuthorityStoreError> {
        let (leader_url, election_term, updated_at, authority_generation, authority_rotated_at) =
            connection.query_row(
                r#"
            SELECT leader_url, election_term, updated_at, authority_generation, authority_rotated_at
            FROM authority_cluster_fence
            WHERE singleton_id = 1
            "#,
                [],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )?;
        Ok(AuthorityClusterFence {
            leader_url,
            election_term: election_term.max(0) as u64,
            updated_at: updated_at.max(0) as u64,
            authority_generation: authority_generation.max(0) as u64,
            authority_rotated_at: authority_rotated_at.max(0) as u64,
        })
    }

    fn write_cluster_fence_to_connection(
        connection: &Connection,
        leader_url: Option<String>,
        election_term: u64,
    ) -> Result<(), AuthorityStoreError> {
        let (_, authority_generation, authority_rotated_at) =
            Self::read_public_state_from_connection(connection)?;
        connection.execute(
            r#"
            UPDATE authority_cluster_fence
            SET
                leader_url = ?1,
                election_term = ?2,
                updated_at = ?3,
                authority_generation = ?4,
                authority_rotated_at = ?5
            WHERE singleton_id = 1
            "#,
            params![
                leader_url,
                election_term as i64,
                unix_now() as i64,
                authority_generation as i64,
                authority_rotated_at as i64,
            ],
        )?;
        Ok(())
    }
}

impl CapabilityAuthority for SqliteCapabilityAuthority {
    fn authority_public_key(&self) -> PublicKey {
        self.status()
            .map(|status| status.public_key)
            .unwrap_or_else(|_| self.cached_public_key())
    }

    fn trusted_public_keys(&self) -> Vec<PublicKey> {
        self.status()
            .map(|status| status.trusted_public_keys)
            .unwrap_or_else(|_| self.cached_trusted_public_keys())
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError> {
        let keypair = self
            .read_current_keypair()
            .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
        let now = unix_now();
        let body = CapabilityTokenBody {
            id: format!("cap-{}", Uuid::now_v7()),
            issuer: keypair.public_key(),
            subject: subject.clone(),
            scope,
            issued_at: now,
            expires_at: now.saturating_add(ttl_seconds),
            delegation_chain: vec![],
        };

        CapabilityToken::sign(body, &keypair)
            .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use chio_core::capability::scope::{Operation, ToolGrant};
    use chio_kernel::LocalCapabilityAuthority;

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    #[test]
    fn local_capability_authority_signs_capabilities() {
        let authority = LocalCapabilityAuthority::new(Keypair::generate());
        let subject = Keypair::generate().public_key();
        let capability = authority
            .issue_capability(
                &subject,
                ChioScope {
                    grants: vec![ToolGrant {
                        server_id: "srv-a".to_string(),
                        tool_name: "read_file".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    resource_grants: vec![],
                    prompt_grants: vec![],
                },
                300,
            )
            .unwrap();

        assert_eq!(capability.subject, subject);
        assert_eq!(capability.issuer, authority.authority_public_key());
        assert!(capability.id.starts_with("cap-"));
        assert!(capability.verify_signature().unwrap());
    }

    #[test]
    fn sqlite_capability_authority_persists_and_rotates_across_handles() {
        let path = unique_db_path("chio-authority");
        let authority_a = SqliteCapabilityAuthority::open(&path).unwrap();
        let authority_b = SqliteCapabilityAuthority::open(&path).unwrap();

        let before = authority_a.status().unwrap();
        assert_eq!(before.generation, 1);
        assert_eq!(authority_b.status().unwrap().public_key, before.public_key);

        let rotated = authority_a.rotate().unwrap();
        assert_eq!(rotated.generation, 2);
        assert_ne!(rotated.public_key, before.public_key);

        let observed = authority_b.status().unwrap();
        assert_eq!(observed.public_key, rotated.public_key);
        assert_eq!(observed.generation, rotated.generation);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_capability_authority_issues_with_current_rotated_key() {
        let path = unique_db_path("chio-authority-issue");
        let authority = SqliteCapabilityAuthority::open(&path).unwrap();
        let subject = Keypair::generate().public_key();
        let first = authority
            .issue_capability(
                &subject,
                ChioScope {
                    grants: vec![ToolGrant {
                        server_id: "srv-a".to_string(),
                        tool_name: "read_file".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    resource_grants: vec![],
                    prompt_grants: vec![],
                },
                300,
            )
            .unwrap();
        let rotated = authority.rotate().unwrap();
        let second = authority
            .issue_capability(
                &subject,
                ChioScope {
                    grants: vec![ToolGrant {
                        server_id: "srv-a".to_string(),
                        tool_name: "read_file".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    resource_grants: vec![],
                    prompt_grants: vec![],
                },
                300,
            )
            .unwrap();

        assert_ne!(first.issuer, second.issuer);
        assert_eq!(second.issuer, rotated.public_key);
        assert!(second.verify_signature().unwrap());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_capability_authority_snapshot_updates_public_view_without_copying_seed() {
        let source_path = unique_db_path("chio-authority-source");
        let follower_path = unique_db_path("chio-authority-follower");
        let source = SqliteCapabilityAuthority::open(&source_path).unwrap();
        let follower = SqliteCapabilityAuthority::open(&follower_path).unwrap();

        let follower_local_key = follower.current_keypair().unwrap().public_key();
        let rotated = source.rotate().unwrap();
        let snapshot = source.snapshot().unwrap();

        assert!(follower.apply_snapshot(&snapshot).unwrap());

        let follower_status = follower.status().unwrap();
        assert_eq!(follower_status.public_key, rotated.public_key);
        assert_eq!(follower_status.generation, rotated.generation);
        let error = match follower.current_keypair() {
            Ok(_) => panic!("mismatched follower keypair should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("does not match replicated authority public key"));
        assert!(error.contains(&follower_local_key.to_hex()));

        let _ = fs::remove_file(source_path);
        let _ = fs::remove_file(follower_path);
    }

    #[test]
    fn sqlite_capability_authority_same_term_snapshot_does_not_clear_fenced_leader() {
        let path = unique_db_path("chio-authority-fence");
        let authority = SqliteCapabilityAuthority::open(&path).unwrap();

        assert!(authority
            .seed_cluster_fence(Some("http://leader-a"), 7)
            .unwrap());
        assert!(!authority.seed_cluster_fence(None, 7).unwrap());

        let fence = authority.cluster_fence().unwrap();
        let status = authority.status().unwrap();
        assert_eq!(fence.election_term, 7);
        assert_eq!(fence.leader_url.as_deref(), Some("http://leader-a"));
        assert_eq!(fence.authority_generation, status.generation);
        assert_eq!(fence.authority_rotated_at, status.rotated_at);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_capability_authority_enforce_cluster_fence_rejects_stale_rotation() {
        let path = unique_db_path("chio-authority-fence-stale-rotation");
        let authority = SqliteCapabilityAuthority::open(&path).unwrap();

        assert!(authority
            .seed_cluster_fence(Some("http://leader-a"), 7)
            .unwrap());
        let fence = authority.cluster_fence().unwrap();
        authority.rotate().unwrap();

        let error = authority
            .enforce_cluster_fence("http://leader-a", 7)
            .expect_err("stale persisted fence should fail closed")
            .to_string();
        assert!(error.contains("persisted authority fence generation"));
        assert!(error.contains(&fence.authority_generation.to_string()));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn sqlite_capability_authority_seed_cluster_fence_refreshes_same_term_authority_state() {
        let path = unique_db_path("chio-authority-fence-same-term-refresh");
        let authority = SqliteCapabilityAuthority::open(&path).unwrap();

        assert!(authority
            .seed_cluster_fence(Some("http://leader-a"), 7)
            .unwrap());
        authority.rotate().unwrap();

        assert!(authority
            .seed_cluster_fence(Some("http://leader-a"), 7)
            .unwrap());
        authority
            .enforce_cluster_fence("http://leader-a", 7)
            .expect("same-term reseed should refresh authority generation");

        let fence = authority.cluster_fence().unwrap();
        let status = authority.status().unwrap();
        assert_eq!(fence.election_term, 7);
        assert_eq!(fence.leader_url.as_deref(), Some("http://leader-a"));
        assert_eq!(fence.authority_generation, status.generation);
        assert_eq!(fence.authority_rotated_at, status.rotated_at);

        let _ = fs::remove_file(path);
    }
}
