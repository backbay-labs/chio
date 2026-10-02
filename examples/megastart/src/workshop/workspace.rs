use super::setup::{Setup, Workers};
use crate::{digest, read};
use anyhow::{ensure, Context, Result};
use chio_agent_os_shared::runtime::files;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub const REGRESSION: &str = "#[test]\nfn singleton_window_preserves_value() {\n    assert_eq!(moving_average(&[u64::MAX], 1), Ok(vec![u64::MAX]));\n}\n";
pub const SOURCE: &str = include_str!("../../project/lib.rs");
pub const HARNESS: &str = include_str!("../../project/tests.rs");
pub const RECIPE: &str = "singleton-window-v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub id: Uuid,
    pub label: String,
    pub parent_id: Option<Uuid>,
    pub recipe: Option<String>,
    pub revision_id: Uuid,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub id: Uuid,
    pub setup: Setup,
    pub selected_mission_id: Option<Uuid>,
    pub missions: Vec<Entry>,
    pub pending: Option<Entry>,
    pub example_identity: String,
}

pub fn example_identity() -> Result<String> {
    digest(&(SOURCE, HARNESS, REGRESSION))
}

pub fn private(path: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "Workspace directory must not be a symlink"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        ensure!(
            meta.permissions().mode() & 0o077 == 0 && meta.uid() == unsafe { libc::geteuid() },
            "Workspace directory must be owned by this user and private (0700)"
        );
    }
    Ok(())
}

pub fn writable(root: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::iter::once(root.to_path_buf())
        .chain(["missions", "revisions", "commands", "connections"].map(|name| root.join(name)))
        .all(|path| {
            std::fs::metadata(path)
                .is_ok_and(|metadata| metadata.permissions().mode() & 0o300 == 0o300)
        })
}

pub fn lock(root: &Path, name: &str) -> Result<File> {
    private(root)?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(root.join(name))?;
    ensure!(file.metadata()?.is_file(), "Lock must be a regular file");
    fs2::FileExt::try_lock_exclusive(&file).context("Another operation owns this workspace")?;
    Ok(file)
}

pub fn load(root: &Path) -> Result<Manifest> {
    private(root)?;
    for directory in ["missions", "revisions", "commands", "connections"] {
        private(&root.join(directory))?;
    }
    let m: Manifest =
        serde_json::from_str(&files::read_text(&root.join("workspace.json"), 64_000)?)?;
    m.setup.validate()?;
    ensure!(
        m.schema_version == 1 && m.example_identity == example_identity()?,
        "Unsupported workspace or bundled example; use the matching operator release"
    );
    ensure!(
        m.missions.len() <= 32,
        "Workspace history capacity exceeded"
    );
    let ids: std::collections::HashSet<_> = m.missions.iter().map(|e| e.id).collect();
    ensure!(
        ids.len() == m.missions.len(),
        "Workspace contains duplicate mission IDs"
    );
    ensure!(
        m.selected_mission_id.is_none_or(|id| ids.contains(&id)),
        "Selected mission is outside this workspace"
    );
    ensure!(
        m.pending
            .as_ref()
            .is_none_or(|pending| !ids.contains(&pending.id)),
        "Pending mission is already committed"
    );
    for e in m.missions.iter().chain(m.pending.iter()) {
        ensure!(
            e.label.len() <= 160 && e.recipe.as_deref().is_none_or(|r| r == RECIPE),
            "Unsupported mission metadata"
        );
        ensure!(
            e.parent_id.is_none_or(|id| ids.contains(&id) && id != e.id),
            "Invalid mission parent"
        );
        ensure!(
            e.parent_id.is_some() == e.recipe.is_some(),
            "Invalid revision lineage"
        );
    }
    Ok(m)
}

fn save(root: &Path, m: &Manifest) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(m)?;
    ensure!(
        bytes.len() <= 64_000 && m.missions.len() <= 32,
        "Workspace history is full; create a new workspace"
    );
    files::replace(&root.join("workspace.json"), &bytes)?;
    Ok(())
}

pub fn create(root: &Path, setup: Setup) -> Result<Manifest> {
    setup.validate()?;
    ensure!(!root.exists(), "Workspace already exists");
    files::private_directory(root)?;
    private(root)?;
    for name in ["missions", "revisions", "commands", "connections"] {
        files::private_directory(&root.join(name))?;
    }
    let m = Manifest {
        schema_version: 1,
        id: Uuid::new_v4(),
        setup,
        selected_mission_id: None,
        missions: vec![],
        pending: None,
        example_identity: example_identity()?,
    };
    save(root, &m)?;
    Ok(m)
}

pub fn launch(setup: Option<Setup>, existing: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = existing {
        ensure!(setup.is_none(), "Choose --setup or --workspace");
        load(path)?;
        return Ok(path.canonicalize()?);
    }
    let setup = setup.unwrap_or_else(Setup::reference);
    let base = if let Some(path) = std::env::var_os("CHIO_WORKSHOPS") {
        PathBuf::from(path)
    } else {
        PathBuf::from(std::env::var_os("HOME").context("HOME is unavailable")?)
            .join(".local/share/chio/megastart/workshops")
    };
    files::private_directory(&base)?;
    let _lock = lock(&base, "index.lock")?;
    let pointer = base.join(format!("setup-{}.json", digest(&setup)?));
    if pointer.exists() {
        let id: Uuid = read(&pointer)?;
        let root = base.join(id.to_string());
        let manifest = load(&root)?;
        ensure!(
            manifest.id == id && manifest.setup == setup,
            "Retained workspace does not match this setup"
        );
        return Ok(root.canonicalize()?);
    }
    let id = Uuid::new_v4();
    let root = base.join(id.to_string());
    let mut manifest = create(&root, setup)?;
    manifest.id = id;
    save(&root, &manifest)?;
    crate::retain(&pointer, &id)?;
    Ok(root.canonicalize()?)
}

pub fn entry(m: &Manifest, id: Uuid) -> Result<&Entry> {
    m.missions
        .iter()
        .find(|e| e.id == id)
        .context("Mission is outside this workspace")
}
pub fn mission_path(root: &Path, m: &Manifest, id: Uuid) -> Result<PathBuf> {
    entry(m, id)?;
    let path = root.join("missions").join(id.to_string());
    private(&path)?;
    Ok(path)
}

pub fn initialize(root: &Path, requested: &Setup) -> Result<Uuid> {
    let _lock = lock(root, "workspace.lock")?;
    let mut m = load(root)?;
    ensure!(
        &m.setup == requested,
        "Setup differs from the retained draft; open the intended setup first"
    );
    if let Some(entry) = m.missions.iter().find(|e| e.parent_id.is_none()) {
        return Ok(entry.id);
    }
    prepare(root, &mut m, None)
}

pub fn create_revision(root: &Path, parent: Uuid) -> Result<Uuid> {
    let _lock = lock(root, "workspace.lock")?;
    let mut m = load(root)?;
    ensure!(
        entry(&m, parent)?.recipe.is_none(),
        "This recipe applies only to the baseline"
    );
    if let Some(entry) = m
        .missions
        .iter()
        .find(|e| e.parent_id == Some(parent) && e.recipe.as_deref() == Some(RECIPE))
    {
        return Ok(entry.id);
    }
    let parent_root = mission_path(root, &m, parent)?;
    let _parent_lease = lock(&parent_root, "host.lock")?;
    let state = super::projection::mission(&parent_root, entry(&m, parent)?)?;
    ensure!(
        ["awaiting_review", "published"].contains(&state["phase"].as_str().unwrap_or(""))
            && state["tests"]["status"] == "passed"
            && state["tests"]["complete"] == true,
        "Complete the baseline before adding its regression"
    );
    ensure!(
        state["source_digest"] == digest(&SOURCE)? && state["harness_digest"] == digest(&HARNESS)?,
        "Recipe does not match this baseline"
    );
    prepare(root, &mut m, Some(parent))
}

// Persist IDs before preparation. An explicit retry finishes those same IDs;
// it never creates a second mission or replenishes an existing allowance.
fn prepare(root: &Path, m: &mut Manifest, parent: Option<Uuid>) -> Result<Uuid> {
    ensure!(m.missions.len() < 32, "Workspace history is full");
    let pending = if let Some(pending) = &m.pending {
        ensure!(
            pending.parent_id == parent,
            "A different revision preparation needs reconciliation first"
        );
        pending.clone()
    } else {
        let pending = Entry {
            id: Uuid::new_v4(),
            label: if parent.is_some() {
                "Moving average · added regression"
            } else {
                "Moving average"
            }
            .into(),
            parent_id: parent,
            recipe: parent.map(|_| RECIPE.into()),
            revision_id: Uuid::new_v4(),
        };
        m.pending = Some(pending.clone());
        save(root, m)?;
        pending
    };
    let harness = if parent.is_some() {
        format!("{HARNESS}\n{REGRESSION}")
    } else {
        HARNESS.to_string()
    };
    let revision = root.join("revisions").join(pending.revision_id.to_string());
    if !revision.exists() {
        let stage = files::StagedDirectory::new(&root.join("revisions"))?;
        files::create(&stage.path().join("lib.rs"), SOURCE.as_bytes())?;
        files::create(&stage.path().join("tests.rs"), harness.as_bytes())?;
        crate::retain(
            &stage.path().join("revision.json"),
            &serde_json::json!({"id":pending.revision_id,"parent_mission_id":parent,"recipe":pending.recipe,"source_digest":digest(&SOURCE)?,"harness_digest":digest(&harness)?}),
        )?;
        stage.publish(&revision)?;
    }
    private(&revision)?;
    ensure!(
        files::read_text(&revision.join("lib.rs"), 64_000)? == SOURCE
            && files::read_text(&revision.join("tests.rs"), 64_000)? == harness,
        "Prepared revision changed"
    );
    let destination = root.join("missions").join(pending.id.to_string());
    if !destination.exists() {
        let stage = files::StagedDirectory::new(&root.join("missions"))?;
        let mission = stage.path().join("mission");
        match &m.setup.workers {
            Workers::Reference => crate::operator::initialize(&mission, Some(&revision), false)?,
            Workers::Native { roles } => {
                #[cfg(feature = "native-agents")]
                {
                    let selection = serde_json::from_value(serde_json::to_value(roles)?)?;
                    crate::operator::initialize_native(&mission, Some(&revision), selection)?;
                }
                #[cfg(not(feature = "native-agents"))]
                {
                    let _ = roles;
                    anyhow::bail!("This operator has no native agent support");
                }
            }
        }
        // Mission initialization creates no running processes or authority lease.
        // Destination is unobservable until the manifest reference is committed.
        std::fs::rename(&mission, &destination)?;
        files::sync_directory(&root.join("missions"))?;
    }
    private(&destination)?;
    let config: serde_json::Value = read(&destination.join("mission.json"))?;
    ensure!(
        config["source_sha256"] == digest(&SOURCE)? && config["tests_sha256"] == digest(&harness)?,
        "Prepared mission input identity changed"
    );
    match &m.setup.workers {
        Workers::Reference => ensure!(
            config["native"].is_null(),
            "Prepared mission has a different execution mode"
        ),
        Workers::Native { roles } => {
            for (role, agent) in [
                ("research", roles.research),
                ("implementation", roles.implementation),
                ("review", roles.review),
            ] {
                ensure!(
                    config["native"]["swarms"][role]["agent"] == agent.name(),
                    "Prepared mission has a different native worker"
                );
            }
        }
    }
    m.missions.push(pending.clone());
    m.selected_mission_id = Some(pending.id);
    m.pending = None;
    save(root, m)?;
    Ok(pending.id)
}
