use chio_megastart::{journal, operator};
use serde_json::json;
use std::path::PathBuf;

fn root() -> PathBuf {
    std::env::temp_dir().join(format!("megastart-operator-test-{}", uuid::Uuid::new_v4()))
}

#[test]
fn mission_events_survive_reopening_with_stable_sequences() -> anyhow::Result<()> {
    let directory = root();
    operator::initialize(&directory, None, false)?;
    journal::emit(
        &directory,
        "worker.assigned",
        "research-0",
        json!({"id":"first"}),
    )?;
    let before = journal::events(&directory)?;
    journal::emit(
        &directory,
        "operation.completed",
        "research-0",
        json!({"id":"first"}),
    )?;
    let after = journal::events(&directory)?;
    assert_eq!(&after[..before.len()], before.as_slice());
    assert_eq!(after.last().unwrap()["sequence"], 3);
    assert!(operator::initialize(&directory, None, false).is_err());
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[test]
fn interrupted_journal_is_never_silently_truncated() -> anyhow::Result<()> {
    use std::io::Write;
    let directory = root();
    operator::initialize(&directory, None, false)?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.join("events.ndjson"))?
        .write_all(b"{\"sequence\":2")?;
    assert!(journal::events(&directory).is_err());
    assert!(journal::emit(&directory, "retry", "host", json!({})).is_err());
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[tokio::test]
async fn generated_code_cannot_read_host_files_or_open_network() -> anyhow::Result<()> {
    if !chio_megastart::sandbox::available() {
        return Ok(());
    }
    let directory = root();
    std::fs::create_dir_all(directory.join("candidate"))?;
    let secret = directory.join("host-secret");
    std::fs::write(&secret, "host-only")?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?.to_string();
    let source = format!(
        r#"#[test] fn host_is_outside_the_boundary() {{
        assert!(std::fs::read_to_string({secret:?}).is_err());
        assert!(std::net::TcpStream::connect({address:?}).is_err());
        assert!(std::process::Command::new("/usr/bin/true").status().is_err());
        assert!(std::env::var("OPENAI_API_KEY").is_err());
        assert!(std::env::var("OPENROUTER_API_KEY").is_err());
        std::fs::write("allowed-output", "local").unwrap();
    }}"#
    );
    std::fs::write(directory.join("candidate/tests.rs"), source)?;
    let result = chio_megastart::operations::tests(&directory.join("candidate"), true).await?;
    assert_eq!(result["passed"], true, "{result}");
    assert_eq!(std::fs::read_to_string(secret)?, "host-only");
    assert_eq!(
        std::fs::read_to_string(directory.join("candidate/allowed-output"))?,
        "local"
    );
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[tokio::test]
async fn console_requires_session_and_same_origin_before_mutation() -> anyhow::Result<()> {
    use std::process::Stdio;
    let directory = root();
    let log = directory.with_extension("log");
    let output = std::fs::File::create(&log)?;
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_megastart"))
        .arg("--state")
        .arg(&directory)
        .args(["console", "--port", "0", "--no-open"])
        .stdout(output)
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let url = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            if let Some(url) = std::fs::read_to_string(&log)?
                .lines()
                .find(|line| line.starts_with("http://"))
            {
                return Ok::<_, anyhow::Error>(url.to_owned());
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await??;
    let (base, token) = url.split_once('#').unwrap();
    let client = reqwest::Client::new();
    let action = format!("{base}api/action");
    let setup = json!({"action":"initialize","model":false,"project":null});
    assert!(!client
        .post(&action)
        .json(&setup)
        .send()
        .await?
        .status()
        .is_success());
    assert!(!client
        .post(&action)
        .bearer_auth(token)
        .header("Origin", "https://untrusted.invalid")
        .json(&setup)
        .send()
        .await?
        .status()
        .is_success());
    assert!(!directory.exists());
    assert!(client
        .post(&action)
        .bearer_auth(token)
        .json(&setup)
        .send()
        .await?
        .status()
        .is_success());
    let one: serde_json::Value = client
        .get(format!("{base}api/events?after=0"))
        .bearer_auth(token)
        .send()
        .await?
        .json()
        .await?;
    let none: serde_json::Value = client
        .get(format!("{base}api/events?after=1"))
        .bearer_auth(token)
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(one["events"].as_array().unwrap().len(), 1);
    assert_eq!(none["events"].as_array().unwrap().len(), 0);
    child.kill().await?;
    child.wait().await?;
    assert_eq!(
        journal::events(&directory)?,
        one["events"].as_array().unwrap().clone()
    );
    std::fs::remove_dir_all(directory)?;
    std::fs::remove_file(log)?;
    Ok(())
}
