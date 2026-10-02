//! Authenticated operator client. Actions are never automatically retried.
use anyhow::{bail, ensure, Context, Result};
use reqwest::{blocking::Client, redirect::Policy, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    io::Read,
    net::IpAddr,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};

const LIMIT: u64 = 16 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Connection {
    pub protocol_version: u32,
    pub endpoint: String,
    pub token: String,
    pub mission_root: PathBuf,
    pub pid: u32,
}

#[derive(Deserialize, Clone)]
pub struct Snapshot {
    pub protocol_version: u32,
    pub state: Value,
    pub busy: bool,
    pub connections: Value,
}

#[derive(Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    Run,
    Resume,
    Exercise,
    Approve { candidate: String },
    Initialize { native: Selection },
    Connect { agent: String },
}

#[derive(Clone, Serialize)]
pub struct Selection {
    pub research: String,
    pub implementation: String,
    pub review: String,
}

pub struct Operator {
    client: Client,
    pub connection: Connection,
}

impl Operator {
    pub fn connect(path: &Path) -> Result<Self> {
        let metadata =
            fs::symlink_metadata(path).context("Open the mission host before connecting")?;
        ensure!(
            metadata.is_file() && metadata.mode() & 0o077 == 0,
            "Connection descriptor must be an owner-only regular file"
        );
        ensure!(metadata.len() <= 8192, "Connection descriptor is too large");
        let connection: Connection = serde_json::from_slice(&fs::read(path)?)?;
        validate(&connection)?;
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build()?;
        Ok(Self { client, connection })
    }

    fn request(&self, route: &str, action: Option<&Action>) -> Result<Value> {
        let url = format!("{}{route}", self.connection.endpoint);
        let request = match action {
            Some(action) => self
                .client
                .post(url)
                .json(action)
                .timeout(Duration::from_secs(900)),
            None => self.client.get(url),
        };
        let response = request
            .bearer_auth(&self.connection.token)
            .send()
            .context("Host disconnected. Reconnect before issuing another action")?;
        let status = response.status();
        let mut bytes = Vec::new();
        response.take(LIMIT + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= LIMIT,
            "Operator response exceeds the supported limit"
        );
        let value: Value = serde_json::from_slice(&bytes).context("Invalid operator response")?;
        if !status.is_success() {
            bail!(
                "{}",
                value["error"]
                    .as_str()
                    .unwrap_or("Operator refused this request")
            );
        }
        Ok(value)
    }

    pub fn snapshot(&self) -> Result<Snapshot> {
        let snapshot: Snapshot = serde_json::from_value(self.request("/api/state", None)?)?;
        ensure!(
            snapshot.protocol_version == 1,
            "Unsupported operator protocol"
        );
        Ok(snapshot)
    }

    pub fn action(&self, action: &Action) -> Result<()> {
        self.request("/api/action", Some(action))
            .context("Action was not confirmed. Inspect retained state before retrying")?;
        Ok(())
    }

    pub fn events(&self, cursor: &mut Cursor) -> Result<()> {
        let value = self.request(&format!("/api/events?after={}", cursor.sequence), None)?;
        ensure!(value["protocol_version"] == 1, "Unsupported event protocol");
        cursor.advance(value["events"].as_array().context("Missing events")?)
    }
}

fn validate(connection: &Connection) -> Result<()> {
    ensure!(
        connection.protocol_version == 1,
        "Unsupported connection protocol"
    );
    let url = Url::parse(&connection.endpoint)?;
    let ip: IpAddr = url
        .host_str()
        .context("Missing host")?
        .parse()
        .context("Operator host must be an IP literal")?;
    ensure!(
        url.scheme() == "http"
            && ip.is_loopback()
            && url.port().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "Operator must use a plain loopback endpoint without credentials or redirects"
    );
    ensure!(
        connection.token.len() == 64 && connection.token.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid operator credential"
    );
    ensure!(
        connection.mission_root.is_absolute() && connection.pid > 0,
        "Invalid host identity"
    );
    Ok(())
}

#[derive(Default)]
pub struct Cursor {
    pub sequence: u64,
}
impl Cursor {
    pub fn advance(&mut self, events: &[Value]) -> Result<()> {
        let mut next = self.sequence;
        for event in events {
            let sequence = event["sequence"]
                .as_u64()
                .context("Invalid event sequence")?;
            ensure!(
                sequence == next + 1,
                "Event gap: refresh the retained snapshot before continuing"
            );
            next = sequence;
        }
        self.sequence = next;
        Ok(())
    }
}

/// Native text is untrusted terminal content. Preserve newlines, never escapes.
pub fn text(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn rejects_remote_and_credential_endpoints() {
        for endpoint in [
            "http://example.com:12",
            "http://127.0.0.1:12/?token=x",
            "http://a@127.0.0.1:12",
            "https://127.0.0.1:12",
        ] {
            let c = Connection {
                protocol_version: 1,
                endpoint: endpoint.into(),
                token: "a".repeat(64),
                mission_root: "/tmp/mission".into(),
                pid: 1,
            };
            assert!(validate(&c).is_err());
        }
    }
    #[test]
    fn event_gap_does_not_partially_advance_cursor() {
        let mut cursor = Cursor::default();
        assert!(cursor
            .advance(&[json!({"sequence":1}), json!({"sequence":3})])
            .is_err());
        assert_eq!(cursor.sequence, 0);
        cursor
            .advance(&[json!({"sequence":1}), json!({"sequence":2})])
            .unwrap();
        assert_eq!(cursor.sequence, 2);
        assert!(cursor.advance(&[json!({"sequence":2})]).is_err());
    }
    #[test]
    fn terminal_content_cannot_emit_control_sequences() {
        assert!(!text("\x1b]52;c;secret\x07\nhello").contains('\x1b'));
        assert_eq!(text("a\nb\tc"), "a\nb\tc");
    }
}
