use anyhow::{Context, Result};
use chio_agent_os_shared::{
    async_trait,
    host::{private_directory, write_json},
    json, Application, Run, Value,
};
use chio_software_factory::{repository::Repository, Factory};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
};
use tokio::process::Command;

pub struct Marketplace;
#[async_trait]
impl Application for Marketplace {
    fn name(&self) -> &'static str {
        "cognition-marketplace"
    }
    fn title(&self) -> &'static str {
        "Acquire a repair that the venue has replayed"
    }
    fn description(&self) -> &'static str {
        "A seller produces a patch, a native Chio venue verifies it, and a buyer applies the purchased delivery to a separate broken project."
    }
    fn sample(&self) -> Value {
        json!({"issue":Factory.sample()["issue"],"mode":"supplied","price":300,"max_price":300,"exercise_denials":true})
    }
    async fn execute(&self, input: Value, run: Run) -> Result<Value> {
        anyhow::ensure!(cfg!(target_os="linux"),"The venue requires Linux with Bubblewrap and delegated cgroup v2; use the documented Linux profile");
        let price = input["price"].as_u64().context("Choose an offer price")?;
        let bid = input["max_price"]
            .as_u64()
            .context("Choose a maximum purchase price")?;
        anyhow::ensure!(
            price >= 2 && price <= 450 && bid <= 450,
            "Choose an offer price from 2 to 450 local credit units and a bid of at most 450"
        );
        let mode = input["mode"].as_str().unwrap_or("supplied");
        anyhow::ensure!(
            ["supplied", "model"].contains(&mode),
            "Choose supplied or model seller mode"
        );
        let root = run.directory()?.canonicalize()?;
        let seller_input = json!({"issue":input["issue"],"mode":if mode=="model" {"model"}else{"deterministic"},"exercise_denials":true});
        let seller_run = Run::create(&root.join("seller-runs"), Factory.name(), &seller_input)?;
        let repair = Factory.execute(seller_input, seller_run.clone()).await;
        seller_run.finish(&repair)?;
        let repair = repair?;
        anyhow::ensure!(
            repair["tests"]["passed"] == true,
            "Seller has no passing candidate to offer"
        );
        run.emit(
            "market.seller",
            "seller",
            "Produced and tested the candidate using the factory",
            seller_run.snapshot()?,
        )?;
        let project = seller_run.directory()?.join("project");
        let repo = root.join("offered-repository");
        private_directory(&repo)?;
        copy_files(&project.join("baseline"), &repo)?;
        git(&repo, &["init", "--initial-branch=baseline"]).await?;
        git(&repo, &["add", "."]).await?;
        git(
            &repo,
            &[
                "commit",
                "-m",
                "Starting project with immutable regression tests",
            ],
        )
        .await?;
        let base = git(&repo, &["rev-parse", "HEAD"]).await?.trim().to_owned();
        git(&repo, &["checkout", "-b", "candidate"]).await?;
        copy_files(&project.join("candidate"), &repo)?;
        git(&repo, &["add", "."]).await?;
        git(
            &repo,
            &["commit", "-m", "Candidate produced by the repair worker"],
        )
        .await?;
        let candidate = git(&repo, &["rev-parse", "HEAD"]).await?.trim().to_owned();
        git(&repo, &["checkout", "-b", "non-fixing", &base]).await?;
        std::fs::write(
            repo.join("NOTES.md"),
            "This documentation-only proposal does not repair moving_average.\n",
        )?;
        git(&repo, &["add", "NOTES.md"]).await?;
        git(
            &repo,
            &[
                "commit",
                "-m",
                "Non-fixing proposal for venue refusal check",
            ],
        )
        .await?;
        let nonfix = git(&repo, &["rev-parse", "HEAD"]).await?.trim().to_owned();
        git(&repo, &["checkout", "candidate"]).await?;
        let chio = chio_binary()?;
        let venue = root.join("venue");
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        drop(listener);
        checked(
            Command::new(&chio)
                .args(["finding", "operator", "init", "--directory"])
                .arg(&venue)
                .arg("--repository-root")
                .arg(&repo)
                .arg("--listen")
                .arg(address.to_string()),
            60,
        )
        .await?;
        let log = std::fs::File::create(root.join("operator.log"))?;
        let mut command = operator_command(&chio);
        command
            .args(["finding", "operator", "serve", "--profile"])
            .arg(venue.join("operator-profile.json"));
        let mut operator = command
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .kill_on_drop(true)
            .spawn()?;
        let mut ready = false;
        for _ in 0..100 {
            if operator.try_wait()?.is_some() {
                anyhow::bail!("The venue stopped during startup; inspect operator.log")
            }
            if tokio::net::TcpStream::connect(address).await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        anyhow::ensure!(ready, "The venue did not become ready within ten seconds");
        let python = python().await?;
        let script = root.join("market-client.py");
        std::fs::write(&script, include_str!("../client.py"))?;
        let common = json!({
            "venue":venue,
            "repository":repo,
            "base":base,
            "candidate":candidate,
            "price":price,
            "chio":chio,
            "max_price":bid,
            "patch":root.join("purchased.patch")
        });
        let offered = client(&python, &script, &root, &common, "offer", None).await?;
        let finding = offered["offer"]["findingId"]
            .as_str()
            .context("Venue did not admit a finding")?;
        run.emit(
            "market.admitted",
            "venue",
            "The isolated venue replayed the failure and candidate",
            offered.clone(),
        )?;
        let mut denials = json!({});
        if input["exercise_denials"] == true {
            let mut nonfix_input = common.clone();
            nonfix_input["candidate"] = json!(nonfix);
            denials["nonfixing_candidate"] =
                client(&python, &script, &root, &nonfix_input, "nonfix", None).await?;
            denials["tampered_proof"] =
                client(&python, &script, &root, &common, "tamper", Some(finding)).await?;
            let mut insufficient = common.clone();
            insufficient["max_price"] = json!(price - 1);
            let refused = client(
                &python,
                &script,
                &root,
                &insufficient,
                "purchase",
                Some(finding),
            )
            .await?;
            anyhow::ensure!(
                refused["status"] == "refused" && !root.join("purchased.patch").exists(),
                "Insufficient bid advanced to a delivered patch"
            );
            anyhow::ensure!(refused["reason"].as_str().unwrap_or("").contains("bid_ceiling_too_low"),
                "Venue did not return the actionable bid-ceiling error; use this application's tested Chio revision");
            denials["insufficient_bid"] = refused;
        }
        let purchased = client(&python, &script, &root, &common, "purchase", Some(finding)).await?;
        if purchased["status"] != "delivered" {
            run.emit(
                "market.refused",
                "buyer",
                "Purchase did not deliver a patch",
                purchased.clone(),
            )?;
            return Ok(json!({
                "status":"refused",
                "offer":offered,
                "purchase":purchased,
                "denials":denials,
                "accounting":"Local credits denominated in USD minor units; no external payment"
            }));
        }
        let customer = Repository::create(&root.join("customer"))?;
        git(&customer.directory, &["init", "--initial-branch=customer"]).await?;
        let before = customer.test(true).await?;
        anyhow::ensure!(
            before["passed"] == false,
            "Customer copy did not reproduce the defect"
        );
        let patch = root.join("purchased.patch");
        git(
            &customer.directory,
            &[
                "apply",
                "--check",
                patch.to_str().context("Invalid patch path")?,
            ],
        )
        .await?;
        git(
            &customer.directory,
            &["apply", patch.to_str().context("Invalid patch path")?],
        )
        .await?;
        let after = customer.test(false).await?;
        run.emit(
            "market.customer-tested",
            "customer",
            "Test the purchased delivery in the customer repository",
            json!({"before":before,"after":after}),
        )?;
        anyhow::ensure!(
            after["passed"] == true,
            "Delivered patch did not repair the separate customer project"
        );
        run.emit(
            "market.repaired",
            "customer",
            "The purchased patch repairs a separate customer copy",
            json!({"before":before,"after":after,"finding_id":finding}),
        )?;
        operator.kill().await?;
        let _ = operator.wait().await?;
        Ok(json!({
            "status":"completed",
            "seller_mode":mode,
            "offer":offered,
            "purchase":purchased,
            "customer":{
                "before":before,
                "after":after
            },
            "denials":denials,
            "accounting":"Local credits denominated in USD minor units; no external payment"
        }))
    }
}
fn copy_files(from: &Path, to: &Path) -> Result<()> {
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let metadata = entry.file_type()?;
        anyhow::ensure!(
            metadata.is_file() && !metadata.is_symlink(),
            "Project contains a non-regular source file"
        );
        std::fs::copy(entry.path(), to.join(entry.file_name()))?;
    }
    Ok(())
}
async fn checked(command: &mut Command, seconds: u64) -> Result<String> {
    command.kill_on_drop(true);
    let output = tokio::time::timeout(std::time::Duration::from_secs(seconds), command.output())
        .await
        .context("Operation timed out; inspect retained venue state before retrying")??;
    anyhow::ensure!(
        output.stdout.len() + output.stderr.len() <= 32_000_000,
        "Operation output exceeded 32 MB"
    );
    anyhow::ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}
async fn git(root: &Path, args: &[&str]) -> Result<String> {
    checked(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args([
                "-c",
                "user.name=Chio example",
                "-c",
                "user.email=examples@chio.computer",
            ])
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null"),
        30,
    )
    .await
}
fn chio_binary() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("CHIO_BINARY") {
        return Ok(PathBuf::from(path));
    }
    let executable = std::env::current_exe()?;
    // Cargo places integration tests in debug/deps and application binaries in debug.
    for directory in executable.ancestors().skip(1).take(2) {
        let binary = directory.join("chio");
        if binary.is_file() {
            return Ok(binary);
        }
    }
    Ok(PathBuf::from("chio"))
}
fn operator_command(chio: &Path) -> Command {
    if std::env::var("CHIO_SANDBOX_DROP_CAPS").as_deref() == Ok("1") {
        let mut command = Command::new("sudo");
        command.args([
            "setpriv",
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--reuid=1000",
            "--regid=1000",
            "--clear-groups",
            "--",
            "env",
        ]);
        for name in ["CHIO_SANDBOX_PROC", "CHIO_SANDBOX_CGROUP_PARENT"] {
            if let Ok(value) = std::env::var(name) {
                command.arg(format!("{name}={value}"));
            }
        }
        command.arg(chio);
        command
    } else {
        Command::new(chio)
    }
}
async fn python() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("CHIO_MARKET_PYTHON") {
        return Ok(PathBuf::from(path));
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let executable = root.join(".venv/bin/python");
    if !executable.is_file() {
        checked(
            Command::new("uv")
                .args(["sync", "--locked", "--directory"])
                .arg(root),
            120,
        )
        .await
        .context("Install uv to create the locked SDK environment")?;
    }
    Ok(executable)
}
async fn client(
    python: &Path,
    script: &Path,
    root: &Path,
    common: &Value,
    action: &str,
    finding: Option<&str>,
) -> Result<Value> {
    let mut input = common.clone();
    input["action"] = json!(action);
    if let Some(finding) = finding {
        input["finding_id"] = json!(finding)
    };
    let file = root.join("client-input.json");
    write_json(&file, &input)?;
    let output = checked(Command::new(python).arg(script).arg(file), 600).await?;
    Ok(serde_json::from_str(&output)?)
}
