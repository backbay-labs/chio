use anyhow::{Context, Result};
use chio_agent_os_shared::{host::private_directory, json, Value};
use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
};
use tokio::process::Command;

pub struct Repository {
    pub directory: PathBuf,
    pub baseline: PathBuf,
    pub editable: Vec<String>,
    pub test_file: String,
    pub gate: Mutex<()>,
    pub writes: std::sync::atomic::AtomicUsize,
}
pub struct RepositoryServer(pub Arc<Repository>);
impl Repository {
    pub fn create(root: &Path) -> Result<Self> {
        let directory = root.join("candidate");
        let baseline = root.join("baseline");
        private_directory(&directory)?;
        private_directory(&baseline)?;
        let (editable, test_file) = if let Ok(source) = std::env::var("CHIO_FACTORY_WORKSPACE") {
            let source = Path::new(&source).canonicalize()?;
            let config: Value =
                serde_json::from_slice(&std::fs::read(source.join("chio-factory.json"))?)?;
            let editable: Vec<String> = serde_json::from_value(config["editable_files"].clone())?;
            let test_file = config["test_file"]
                .as_str()
                .context("Configuration needs test_file")?
                .to_owned();
            anyhow::ensure!(
                !editable.is_empty() && editable.len() <= 8,
                "Choose 1 to 8 editable files"
            );
            let mut files = editable.clone();
            files.push(test_file.clone());
            for name in &files {
                simple_path(name)?;
                let file = source.join(name);
                anyhow::ensure!(
                    !file.symlink_metadata()?.file_type().is_symlink()
                        && file.is_file()
                        && file.metadata()?.len() <= 32_000,
                    "Workspace files must be regular files of at most 32000 bytes"
                );
                let bytes = std::fs::read(file)?;
                std::fs::write(directory.join(name), &bytes)?;
                std::fs::write(baseline.join(name), bytes)?;
            }
            anyhow::ensure!(
                !editable.contains(&test_file),
                "The test file must not be editable by the repair worker"
            );
            (editable, test_file)
        } else {
            for (name, contents) in [
                ("analysis.py", include_str!("../project/analysis.py")),
                (
                    "test_analysis.py",
                    include_str!("../project/test_analysis.py"),
                ),
            ] {
                std::fs::write(directory.join(name), contents)?;
                std::fs::write(baseline.join(name), contents)?;
            }
            (vec!["analysis.py".into()], "test_analysis.py".into())
        };
        Ok(Self {
            directory,
            baseline,
            editable,
            test_file,
            gate: Mutex::new(()),
            writes: std::sync::atomic::AtomicUsize::new(0),
        })
    }
    pub fn digest(&self) -> Result<String> {
        let _lock = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("Repository lock failed"))?;
        self.digest_unlocked()
    }
    fn digest_unlocked(&self) -> Result<String> {
        let mut files = self.editable.clone();
        files.push(self.test_file.clone());
        files.sort();
        let mut contents = std::collections::BTreeMap::new();
        for file in files {
            contents.insert(
                file.clone(),
                std::fs::read_to_string(self.directory.join(file))?,
            );
        }
        Ok(chio_core::sha256_hex(&chio_core::canonical_json_bytes(
            &contents,
        )?))
    }
    fn read(&self, path: &str) -> Result<Value> {
        simple_path(path)?;
        anyhow::ensure!(
            self.editable.iter().any(|p| p == path) || self.test_file == path,
            "File is outside this workspace's read set"
        );
        Ok(json!({
            "path":path,
            "content":std::fs::read_to_string(self.directory.join(path))?,
            "candidate_sha256":self.digest_unlocked()?
        }))
    }
    fn write(&self, path: &str, content: &str) -> Result<Value> {
        simple_path(path)?;
        anyhow::ensure!(
            self.editable.iter().any(|p| p == path),
            "File is outside the worker's editable set"
        );
        anyhow::ensure!(content.len() <= 32_000, "File exceeds 32000 bytes");
        let destination = self.directory.join(path);
        anyhow::ensure!(
            !destination.symlink_metadata()?.file_type().is_symlink(),
            "Refusing to replace a symlink"
        );
        let temporary = self.directory.join(format!("{}.tmp", uuid::Uuid::new_v4()));
        std::fs::write(&temporary, content)?;
        std::fs::rename(temporary, destination)?;
        self.writes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(json!({"path":path,"candidate_sha256":self.digest_unlocked()?}))
    }
    pub fn diff(&self) -> Result<String> {
        let mut diff = String::new();
        for name in &self.editable {
            let before = std::fs::read_to_string(self.baseline.join(name))?;
            let after = std::fs::read_to_string(self.directory.join(name))?;
            if before != after {
                diff.push_str(&format!(
                    "--- a/{name}\n+++ b/{name}\n@@ -1,{} +1,{} @@\n",
                    before.lines().count(),
                    after.lines().count()
                ));
                for line in before.lines() {
                    diff.push_str(&format!("-{line}\n"));
                }
                for line in after.lines() {
                    diff.push_str(&format!("+{line}\n"));
                }
            }
        }
        Ok(diff)
    }
    pub async fn test(&self, baseline: bool) -> Result<Value> {
        let directory = if baseline {
            &self.baseline
        } else {
            &self.directory
        };
        let candidate = if baseline {
            "baseline".into()
        } else {
            self.digest()?
        };
        let output = isolated_python(directory, &self.test_file).await?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        let summary = stderr.lines().rev().find_map(|line| line.strip_prefix("CHIO_TEST_RESULT="))
            .context("The isolated test runner did not complete. Inspect its runtime configuration before requesting a repair")?;
        let summary: Value = serde_json::from_str(summary)?;
        anyhow::ensure!(
            summary["tests_run"].as_u64().is_some_and(|n| n > 0),
            "The focused test file contains no discovered unittest tests"
        );
        anyhow::ensure!(
            output.status.success() == (summary["failures"] == 0 && summary["errors"] == 0),
            "Test runner exit status does not match its result"
        );
        if !baseline {
            anyhow::ensure!(
                candidate == self.digest()?,
                "Candidate changed during testing; run the tests again"
            );
        }
        Ok(json!({
            "candidate_sha256":candidate,
            "passed":output.status.success(),
            "exit_code":output.status.code(),
            "stdout":String::from_utf8_lossy(&output.stdout),
            "stderr":String::from_utf8_lossy(&output.stderr),
            "test_file":self.test_file,
            "summary":summary,
            "isolation":if cfg!(target_os="linux"){
                "bubblewrap: no network; read-only project and system runtime"
            }else{
                "macOS sandbox profile: no network; project read access"
            }
        }))
    }
}
fn simple_path(path: &str) -> Result<()> {
    anyhow::ensure!(
        !path.is_empty()
            && path.len() <= 128
            && !path.starts_with('.')
            && std::path::Path::new(path).components().count() == 1
            && path.ends_with(".py"),
        "Use a top-level Python file in the configured workspace"
    );
    Ok(())
}
fn error(e: anyhow::Error) -> KernelError {
    KernelError::ToolServerError(e.to_string())
}
#[async_trait::async_trait]
impl ToolServerConnection for RepositoryServer {
    fn server_id(&self) -> &str {
        "repository"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["list_files".into(), "read_file".into(), "write_file".into()]
    }
    fn tool_is_read_only(&self, tool: &str) -> bool {
        matches!(tool, "list_files" | "read_file")
    }
    async fn invoke(
        &self,
        tool: &str,
        args: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        let _lock = self
            .0
            .gate
            .lock()
            .map_err(|_| KernelError::ToolServerError("Repository lock failed".into()))?;
        match tool {
            "list_files" => {
                Ok(json!({"editable":self.0.editable,"read_only_tests":self.0.test_file}))
            }
            "read_file" => self
                .0
                .read(args["path"].as_str().unwrap_or(""))
                .map_err(error),
            "write_file" => self
                .0
                .write(
                    args["path"].as_str().unwrap_or(""),
                    args["content"].as_str().ok_or_else(|| {
                        KernelError::ToolServerError("Provide file content".into())
                    })?,
                )
                .map_err(error),
            _ => Err(KernelError::ToolServerError(
                "Unknown repository tool".into(),
            )),
        }
    }
}

const TEST_RUNNER: &str = r#"import sys, os, importlib.util, unittest, json
path = sys.argv[1]
sys.path.insert(0, os.path.dirname(path))
spec = importlib.util.spec_from_file_location("chio_focused_tests", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
suite = unittest.defaultTestLoader.loadTestsFromModule(module)
result = unittest.TextTestRunner(verbosity=2).run(suite)
print("CHIO_TEST_RESULT=" + json.dumps({"tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors)}), file=sys.stderr)
sys.exit(0 if result.wasSuccessful() and result.testsRun else 1)
"#;

pub async fn isolated_python(directory: &Path, test_file: &str) -> Result<std::process::Output> {
    let directory = directory.canonicalize()?;
    let mut command;
    #[cfg(target_os = "linux")]
    {
        // Some managed Linux hosts start processes with ambient capabilities.
        // Drop them before entering an unprivileged user namespace.
        if std::env::var("CHIO_SANDBOX_DROP_CAPS").as_deref() == Ok("1") {
            command = Command::new("sudo");
            command.args([
                "setpriv",
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                "--reuid=1000",
                "--regid=1000",
                "--clear-groups",
                "bwrap",
            ]);
        } else {
            command = Command::new("bwrap");
        }
        command
            .args([
                "--unshare-all",
                "--die-with-parent",
                "--new-session",
                "--uid",
                "0",
                "--gid",
                "0",
                "--ro-bind",
                "/usr",
                "/usr",
                "--ro-bind",
                "/lib",
                "/lib",
                "--ro-bind",
                "/lib64",
                "/lib64",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "--ro-bind",
            ])
            .arg(&directory)
            .args([
                "/workspace",
                "--chdir",
                "/workspace",
                "/usr/bin/python3",
                "-I",
                "-B",
                "-c",
                TEST_RUNNER,
            ])
            .arg(format!("/workspace/{test_file}"));
    }
    #[cfg(target_os = "macos")]
    {
        command = Command::new("/usr/bin/sandbox-exec");
        let quoted =
            serde_json::to_string(directory.to_str().context("Workspace path is not UTF-8")?)?;
        let profile=format!("(version 1)(deny default)(allow process*)(allow sysctl-read)(allow mach-lookup)(allow file-read* (subpath \"/System\") (subpath \"/usr\") (subpath \"/Library\") (subpath \"/private/var/db\") (subpath {quoted}))(allow file-write* (literal \"/dev/null\"))");
        command
            .args([
                "-p",
                &profile,
                "/usr/bin/python3",
                "-I",
                "-B",
                "-c",
                TEST_RUNNER,
            ])
            .arg(directory.join(test_file));
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        anyhow::bail!("This project requires the qualified Linux or macOS test runner");
    }
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .context("Install the documented isolated Python runner")?;
    let stdout = child.stdout.take().context("Test runner has no stdout")?;
    let stderr = child.stderr.take().context("Test runner has no stderr")?;
    async fn bounded(stream: impl tokio::io::AsyncRead + Unpin) -> Result<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        let mut bytes = Vec::new();
        stream.take(32_001).read_to_end(&mut bytes).await?;
        anyhow::ensure!(
            bytes.len() <= 32_000,
            "Test output exceeded 32000 bytes on one stream"
        );
        Ok(bytes)
    }
    let execution = async {
        tokio::try_join!(
            async { Ok::<_, anyhow::Error>(child.wait().await?) },
            bounded(stdout),
            bounded(stderr)
        )
    };
    let (status, stdout, stderr) =
        tokio::time::timeout(std::time::Duration::from_secs(15), execution)
            .await
            .context("Tests exceeded their 15-second deadline")??;
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}
