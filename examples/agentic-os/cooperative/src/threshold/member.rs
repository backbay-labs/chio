use super::{action, body, now, Settlement};
use anyhow::{Context, Result};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use chio_agent_os_shared::{
    host::{private_directory, write_json},
    json, Value,
};
use chio_core::crypto::PublicKey;
use chio_federation::frost::FrostRosterV1;
use chio_federation_authority::*;
use chio_personal_network::directory::key;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    pub root: PathBuf,
    pub id: String,
    pub admin: String,
    pub budget: u64,
    pub accept: bool,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Peer {
    pub id: String,
    pub url: String,
    pub transport_key: PublicKey,
    pub pid: u32,
}
struct Ceremony {
    config: FrostCeremonyConfig,
    peers: Vec<Peer>,
    round1: Vec<FrostAuthenticatedDkgPackage>,
    secret: Option<FrostCeremonySecret>,
    inbound: Vec<FrostAuthenticatedDkgPackage>,
    key: Option<FrostCeremonySecret>,
    public: Option<Value>,
    roster: Option<FrostRosterV1>,
    nonces: BTreeMap<String, (FrostSignerNonceSecret, Vec<u8>, String)>,
}
struct Node {
    config: Config,
    transport: chio_core::crypto::Keypair,
    ceremony: Mutex<Option<Ceremony>>,
}
type Api = std::result::Result<Json<Value>, (StatusCode, String)>;
fn error(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, e.to_string())
}
fn admin(node: &Node, h: &HeaderMap) -> Result<()> {
    anyhow::ensure!(
        h.get("authorization").and_then(|v| v.to_str().ok())
            == Some(&format!("Bearer {}", node.config.admin)),
        "Member administration requires authentication"
    );
    Ok(())
}
fn private_bytes(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
async fn begin(State(node): State<Arc<Node>>, h: HeaderMap, Json(peers): Json<Vec<Peer>>) -> Api {
    admin(&node, &h).map_err(error)?;
    if peers.len() != 3 {
        return Err(error("The registered settlement roster has three members"));
    }
    let mut state = node.ceremony.lock().map_err(error)?;
    if state.is_some() {
        return Err(error(
            "A ceremony already exists; reuse its result or start a new run",
        ));
    }
    let mut participants = peers
        .iter()
        .map(|p| FrostCeremonyParticipant {
            participant_id: p.id.clone(),
            transport_key_id: format!("{}.transport", p.id),
            transport_public_key: p.transport_key.clone(),
        })
        .collect::<Vec<_>>();
    participants.sort_by(|a, b| a.participant_id.cmp(&b.participant_id));
    let config = FrostCeremonyConfig {
        scope_id: super::SCOPE.into(),
        key_epoch: 1,
        threshold: 2,
        predecessor_roster_digest: None,
        participants,
        local_participant_id: node.config.id.clone(),
    };
    let first =
        begin_frost_ceremony(&config, &node.transport, &mut rand_core::OsRng).map_err(error)?;
    private_bytes(
        &node.config.root.join("round1.custody"),
        first.secret.custody_bytes(),
    )
    .map_err(error)?;
    let value = json!(first.package);
    *state = Some(Ceremony {
        config,
        peers,
        round1: vec![],
        secret: Some(first.secret),
        inbound: vec![],
        key: None,
        public: None,
        roster: None,
        nonces: BTreeMap::new(),
    });
    Ok(Json(value))
}
async fn receive(
    State(node): State<Arc<Node>>,
    Json(package): Json<FrostAuthenticatedDkgPackage>,
) -> Api {
    let mut guard = node.ceremony.lock().map_err(error)?;
    let state = guard
        .as_mut()
        .ok_or_else(|| error("Member has not joined a ceremony"))?;
    if package.round() != FrostDkgRound::Round2
        || package.recipient_participant_id() != Some(&node.config.id)
        || !state
            .peers
            .iter()
            .any(|p| p.id == package.sender_participant_id())
    {
        return Err(error("Private package is not addressed to this member"));
    }
    package.verify_for_recipient(&state.config).map_err(error)?;
    if state.inbound.len() >= 2
        || state
            .inbound
            .iter()
            .any(|p| p.sender_participant_id() == package.sender_participant_id())
    {
        return Err(error("Duplicate or excess inbound package"));
    }
    // Completion authenticates every package against its signed public receipt.
    state.inbound.push(package);
    Ok(Json(json!({"received":true})))
}
async fn advance(
    State(node): State<Arc<Node>>,
    h: HeaderMap,
    Json(round1): Json<Vec<FrostAuthenticatedDkgPackage>>,
) -> Api {
    admin(&node, &h).map_err(error)?;
    let (packages, peers) = {
        let mut guard = node.ceremony.lock().map_err(error)?;
        let state = guard.as_mut().ok_or_else(|| error("No ceremony"))?;
        let secret = state
            .secret
            .take()
            .ok_or_else(|| error("Round one has already been consumed"))?;
        let second = advance_frost_ceremony(&state.config, &node.transport, secret, &round1)
            .map_err(error)?;
        private_bytes(
            &node.config.root.join("round2.custody"),
            second.secret.custody_bytes(),
        )
        .map_err(error)?;
        state.secret = Some(second.secret);
        state.round1 = round1;
        (second.packages, state.peers.clone())
    };
    let mut receipts = Vec::new();
    for package in packages {
        let peer = peers
            .iter()
            .find(|p| Some(p.id.as_str()) == package.recipient_participant_id())
            .ok_or_else(|| error("Recipient not enrolled"))?;
        reqwest::Client::new()
            .post(format!("{}/receive", peer.url))
            .json(&package)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(error)?
            .error_for_status()
            .map_err(error)?;
        receipts.push(package.public_receipt());
    }
    Ok(Json(json!(receipts)))
}
async fn complete(
    State(node): State<Arc<Node>>,
    h: HeaderMap,
    Json(receipts): Json<Vec<FrostDkgPackageReceipt>>,
) -> Api {
    admin(&node, &h).map_err(error)?;
    let mut guard = node.ceremony.lock().map_err(error)?;
    let state = guard.as_mut().ok_or_else(|| error("No ceremony"))?;
    let complete = complete_frost_ceremony_scoped(
        &state.config,
        state
            .secret
            .take()
            .ok_or_else(|| error("Round two already consumed"))?,
        &state.round1,
        &state.inbound,
        &receipts,
    )
    .map_err(error)?;
    private_bytes(
        &node.config.root.join("key-package.custody"),
        complete.key_package.custody_bytes(),
    )
    .map_err(error)?;
    let value = json!({
        "group_public_key":complete.group_public_key,
        "verification_shares":complete.verification_shares,
        "transcript_digest":complete.transcript_digest,
        "received_private_packages":state.inbound.len()
    });
    state.key = Some(complete.key_package);
    state.public = Some(value.clone());
    state.inbound.clear();
    Ok(Json(value))
}
async fn roster(
    State(node): State<Arc<Node>>,
    h: HeaderMap,
    Json(roster): Json<FrostRosterV1>,
) -> Api {
    admin(&node, &h).map_err(error)?;
    roster.validate_for_active_resolution().map_err(error)?;
    let mut guard = node.ceremony.lock().map_err(error)?;
    let state = guard.as_mut().ok_or_else(|| error("No ceremony"))?;
    let public = state
        .public
        .as_ref()
        .ok_or_else(|| error("Ceremony incomplete"))?;
    if json!(roster.group_public_key) != public["group_public_key"]
        || json!(roster.ceremony_transcript_digest) != public["transcript_digest"]
        || roster.participants.iter().any(|p| {
            json!(p.verification_share) != public["verification_shares"][&p.participant_id]
        })
        || roster.key_epoch != 1
        || roster.scope_id != super::SCOPE
    {
        return Err(error("Roster differs from this member's completed DKG"));
    }
    if state.roster.is_some() {
        return Err(error("Roster already installed"));
    }
    state.roster = Some(roster);
    Ok(Json(json!({"installed":true})))
}
fn check(
    node: &Node,
    state: &Ceremony,
    input: &Value,
) -> Result<(Settlement, chio_federation::frost::FrostAuthorizationBodyV1)> {
    let settlement: Settlement = serde_json::from_value(input["settlement"].clone())?;
    settlement.validate()?;
    anyhow::ensure!(
        node.config.accept && settlement.units <= node.config.budget,
        "Member policy refuses this computation or its cost"
    );
    let supplied: chio_federation::frost::FrostAuthorizationBodyV1 =
        serde_json::from_value(input["body"].clone())?;
    let roster = state
        .roster
        .as_ref()
        .context("Member has no approved roster")?;
    let expected = body(
        roster,
        &action(&settlement)?,
        supplied.issued_at,
        supplied.expires_at,
    )?;
    anyhow::ensure!(
        supplied == expected
            && now() >= supplied.issued_at
            && now() < supplied.expires_at
            && supplied.expires_at - supplied.issued_at <= 120,
        "Proposal is outside the exact action, roster, or validity interval"
    );
    Ok((settlement, supplied))
}
async fn prepare(State(node): State<Arc<Node>>, h: HeaderMap, Json(input): Json<Value>) -> Api {
    admin(&node, &h).map_err(error)?;
    let mut guard = node.ceremony.lock().map_err(error)?;
    let state = guard.as_mut().ok_or_else(|| error("No ceremony"))?;
    let (_, body) = check(&node, state, &input).map_err(error)?;
    let id = body.authorization_id.clone();
    if state.nonces.contains_key(&id) || node.config.root.join(format!("{id}.prepared")).exists() {
        return Err(error(
            "This authorization already has a nonce; start a new proposal",
        ));
    }
    let preparation = prepare_frost_signer(
        state.key.as_ref().ok_or_else(|| error("No member key"))?,
        &mut rand_core::OsRng,
    )
    .map_err(error)?;
    let commitment = preparation.commitment_bytes().to_vec();
    let message_digest = chio_core::sha256_hex(&body.signing_bytes().map_err(error)?);
    // Retain the nonce only in this process. The durable marker prevents reuse after restart.
    write_json(
        &node.config.root.join(format!("{id}.prepared")),
        &json!({"body":body,"commitment":hex::encode(&commitment)}),
    )
    .map_err(error)?;
    state.nonces.insert(
        id,
        (
            preparation.into_nonce_secret(),
            commitment.clone(),
            message_digest,
        ),
    );
    Ok(Json(
        json!({"participant_id":node.config.id,"commitment":hex::encode(commitment)}),
    ))
}
async fn sign(State(node): State<Arc<Node>>, h: HeaderMap, Json(input): Json<Value>) -> Api {
    admin(&node, &h).map_err(error)?;
    let mut guard = node.ceremony.lock().map_err(error)?;
    let state = guard.as_mut().ok_or_else(|| error("No ceremony"))?;
    let (_, body) = check(&node, state, &input).map_err(error)?;
    let (nonce, commitment, message) = state
        .nonces
        .remove(&body.authorization_id)
        .ok_or_else(|| error("Signing nonce absent or already consumed"))?;
    let package = hex::decode(
        input["signing_package"]
            .as_str()
            .ok_or_else(|| error("No signing package"))?,
    )
    .map_err(error)?;
    let share = create_frost_signature_share(
        state.key.as_ref().ok_or_else(|| error("No member key"))?,
        nonce,
        &package,
        &message,
        &commitment,
    )
    .map_err(error)?;
    Ok(Json(
        json!({"participant_id":node.config.id,"share":hex::encode(share.share_bytes())}),
    ))
}
pub async fn serve(config: Config) -> Result<()> {
    private_directory(&config.root)?;
    let transport = key(&config.root.join("transport.key"))?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let peer = Peer {
        id: config.id.clone(),
        url: format!("http://{}", listener.local_addr()?),
        transport_key: transport.public_key(),
        pid: std::process::id(),
    };
    let node = Arc::new(Node {
        config,
        transport,
        ceremony: Mutex::new(None),
    });
    let router = Router::new()
        .route("/begin", post(begin))
        .route("/receive", post(receive))
        .route("/advance", post(advance))
        .route("/complete", post(complete))
        .route("/roster", post(roster))
        .route("/prepare", post(prepare))
        .route("/sign", post(sign))
        .layer(DefaultBodyLimit::max(512_000))
        .with_state(node);
    println!("{}", serde_json::to_string(&peer)?);
    axum::serve(listener, router).await?;
    Ok(())
}
