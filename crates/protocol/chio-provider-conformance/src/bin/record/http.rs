use std::env;
use std::fs;
use std::process::Command;

use serde_json::Value;

use crate::util::{now_ts, sanitize_id};
use crate::RecordError;

pub(crate) fn curl_json_post(
    provider: &'static str,
    url: &str,
    headers: &[(&str, String)],
    body: &Value,
) -> Result<String, RecordError> {
    let input_path =
        env::temp_dir().join(format!("chio-{provider}-{}.json", sanitize_id(&now_ts())));
    fs::write(&input_path, serde_json::to_vec(body)?).map_err(|source| {
        RecordError::WriteFixture {
            path: input_path.clone(),
            source,
        }
    })?;

    let mut command = Command::new("curl");
    command.args([
        "--silent",
        "--show-error",
        "--fail-with-body",
        "--location",
        "--request",
        "POST",
        "--header",
        "Content-Type: application/json",
    ]);
    for (name, value) in headers {
        command.args(["--header", &format!("{name}: {value}")]);
    }
    command.args(["--data-binary", &format!("@{}", input_path.display()), url]);

    let output = command.output().map_err(|source| RecordError::Curl {
        provider,
        message: format!("failed to run curl: {source}"),
    })?;
    let _ = fs::remove_file(&input_path);
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let message = if stdout.is_empty() {
            stderr
        } else if stderr.is_empty() {
            stdout
        } else {
            format!("{stderr}\n{stdout}")
        };
        return Err(RecordError::Curl { provider, message });
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
