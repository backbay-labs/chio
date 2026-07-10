//! DEPLOYABILITY: mount the iroh federation-transport lanes on the pheromone
//! relay serve binary so the transport is actually runnable.
//!
//! # Safety invariant (DUAL, opt-in, default OFF)
//!
//! This module is only ever reached when the operator passes `--iroh-enable`
//! (which defaults to `false`). With the flag off, [`load_iroh_serve_inputs`]
//! returns `Ok(None)` BEFORE touching any file or constructing anything iroh, so
//! the serve path is byte-for-byte unchanged and the HTTP relay behaves exactly as
//! today. With the flag on, the iroh endpoint runs ALONGSIDE the axum HTTP relay
//! (DUAL migration): the HTTP relay always keeps running and stays authoritative;
//! iroh is a second ingress/egress behind the same trust logic.
//!
//! # What is wired here
//!
//! The pheromone directed-batch lane is the lane that genuinely reuses the
//! shipped relay seam: [`build_iroh_router`] mounts
//! [`chio_federation_transport_iroh::lanes::pheromone::mount_pheromone_lane`]
//! with the SAME `Arc<dyn RelayBatchReceiver>` and `Arc<SqlitePheromoneRelayStore>`
//! the HTTP `PheromoneRelayService` holds (one receiver, one store, two
//! transports). The per-frame verifier runs ABOVE both transports, unchanged.
//!
//! The revocation and bilateral lanes are NOT wired on this hook: the current
//! crate constructors need collaborators the relay-serve process does not host
//! (`RevocationHandler::new` requires a `RevocationRootSink` backed by a live
//! revocation-view cache plus a `RevocationCatchupHistory`;
//! `BilateralCoSignHandler::new` requires a dedicated DSSE co-sign `Keypair` and a
//! pinned-passport-key map). Stubbing those with no-op collaborators would be
//! fail-OPEN for revocation (a no-op sink silently discards verified revocation
//! roots), which the house rules forbid, so requesting them fails closed at load
//! time (see [`parse_iroh_lanes`]).
//!
//! # Fail-closed
//!
//! Every load/verify step ([`load_iroh_serve_inputs`]) and every endpoint-build
//! step ([`build_iroh_router`]) returns `Err` on any problem, and the caller
//! aborts serve startup. `--iroh-enable` never silently continues without the
//! transport.
//!
//! # Relay/discovery default
//!
//! With no `--iroh-relay-url`, the endpoint uses `RelayMode::Disabled` (direct
//! addressing). The n0 free relays end 2026-12-31, so this NEVER defaults to n0.

use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chio_federation_transport_iroh::admission::DirectoryGate;
use chio_federation_transport_iroh::identity::TransportDirectoryBundleDocument;
use chio_federation_transport_iroh::identity::TransportDirectoryBundleTrust;
use chio_federation_transport_iroh::identity::TrustedTransportDirectoryIssuer;
use chio_federation_transport_iroh::identity::VerifiedDirectory;
use chio_federation_transport_iroh::lanes::limits::RECOMMENDED_MAX_IDLE_TIMEOUT;
use chio_federation_transport_iroh::lanes::pheromone::mount_pheromone_lane;
use chio_federation_transport_iroh::lanes::pheromone::InboundBatchScopeCheck;
use chio_federation_transport_iroh::lanes::pheromone::PheromoneBatchHandler;
use chio_pheromone_relay::enforce_peer_batch_directory_scope;
use chio_pheromone_relay::PeerDirectory;
use chio_pheromone_relay::RelayBatchReceiver;
use chio_pheromone_relay::SqlitePheromoneRelayStore;
use iroh::endpoint::presets;
use iroh::endpoint::IdleTimeout;
use iroh::endpoint::QuicTransportConfig;
use iroh::endpoint::VarInt;
use iroh::protocol::Router;
use iroh::Endpoint;
use iroh::EndpointId;
use iroh::RelayMode;
use iroh::RelayUrl;
use iroh::SecretKey;

use super::read_utf8_json_file;
use super::unix_now_ms;
use super::RelayTrustedIssuersDocument;
use crate::CliError;

/// A dedicated, rotatable ed25519 transport key file (Option B), SEPARATE from the
/// long-term passport / relay signing key. `seedHex` is the 32-byte ed25519 seed as
/// hex. Kept minimal on purpose: the passport key (loaded elsewhere) endorses this
/// transport `EndpointId` inside the issuer-signed directory bundle.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IrohTransportKeyDocument {
    pub(crate) seed_hex: String,
}

/// Optional rotation-state input for the transport-directory bundle, mirroring the
/// relay's signed peer-directory state. It pins the rollback FLOOR and the expected
/// predecessor bundle hash a ROTATED successor bundle must chain onto, so a
/// post-genesis bundle (version > 1 carrying a `previousVersionSha256`) is accepted
/// at startup. Without it the wiring can only promote a GENESIS bundle (floor 0, no
/// predecessor). The bundle it pins is itself issuer-signed and verified against
/// `--trusted-issuers`; this document only carries the operator's local rollback pin.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IrohTransportDirectoryStateDocument {
    /// Rollback floor: the loaded bundle's `version` MUST be strictly greater.
    pub(crate) version_floor: u64,
    /// The expected predecessor bundle hash the successor must chain onto (its
    /// `previousVersionSha256`); `None` only when pinning a genesis bundle.
    pub(crate) expected_previous_version_sha256: Option<String>,
}

/// The iroh federation-transport lanes an operator may request via `--iroh-lanes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IrohLane {
    /// Directed pheromone batches (lane a). Reuses the relay receiver + store.
    Pheromone,
    /// Revocation epoch roots (lane b). Needs a sink + history not hosted here.
    Revocation,
    /// Bilateral DSSE co-sign (lane d). Needs a co-sign key + passport-key map.
    Bilateral,
}

impl IrohLane {
    fn label(self) -> &'static str {
        match self {
            IrohLane::Pheromone => "pheromone",
            IrohLane::Revocation => "revocation",
            IrohLane::Bilateral => "bilateral",
        }
    }
}

/// Endpoint + router construction knobs, derived from the CLI flags.
#[derive(Debug, Clone)]
pub(crate) struct IrohMountConfig {
    /// Relay mode. `Disabled` by default (never n0).
    pub(crate) relay_mode: RelayMode,
    /// Socket address the iroh endpoint binds.
    pub(crate) bind_addr: SocketAddr,
    /// The lanes to mount (pheromone only, on this hook).
    pub(crate) lanes: Vec<IrohLane>,
    /// QUIC transport idle-timeout backstop.
    pub(crate) max_idle_timeout: Duration,
}

/// Everything needed to build the iroh router, produced by
/// [`load_iroh_serve_inputs`] (all fail-closed file loads + the load-time bundle
/// verification), and consumed by [`build_iroh_router`] (the async endpoint bind).
/// Deliberately does NOT hold the relay receiver/store: those are attached at build
/// time so the loading + verification is unit-testable without them.
pub(crate) struct IrohServeInputs {
    /// The load-time-verified transport directory the admission gate is built from.
    pub(crate) directory: Arc<VerifiedDirectory>,
    /// The rotatable ed25519 transport key this endpoint authenticates as.
    pub(crate) transport_key: SecretKey,
    /// The transport directory's own `localKernelId` (the issuer-signed, body-hash-pinned
    /// identity this node authenticates AS over the transport). Captured at load time
    /// from the verified bundle so [`build_iroh_router`] can fail closed when it does NOT
    /// match the relay's configured local identity (`peer_directory.local_kernel_id()`):
    /// otherwise the endpoint would authenticate as a DIFFERENT kernel than the relay's
    /// receiver verifies inbound batches as, and valid deliveries would be
    /// rejected/dead-lettered. `VerifiedDirectory` does not surface this id, so it is
    /// carried here rather than re-derived.
    pub(crate) transport_local_kernel_id: String,
    /// Endpoint + router construction knobs.
    pub(crate) config: IrohMountConfig,
}

/// A live iroh mount: the spawned router (kept alive for the process lifetime) plus
/// startup metadata for the log line.
pub(crate) struct IrohMount {
    /// The spawned protocol router. Call [`Router::shutdown`] on teardown.
    pub(crate) router: Router,
    /// This endpoint's authenticated id (for the startup log line).
    pub(crate) endpoint_id: EndpointId,
    /// The socket address(es) the endpoint actually bound. With the default
    /// `--iroh-bind-addr 0.0.0.0:0` the OS assigns an ephemeral port, so this is
    /// the ONLY place the operator can learn the reachable port; it is logged at
    /// startup and returned here so it is observable + assertable in tests.
    pub(crate) bound_sockets: Vec<SocketAddr>,
    /// The lane labels actually mounted (for the startup log line).
    pub(crate) enabled_lanes: Vec<&'static str>,
    /// The admission gate installed on the endpoint (shares one Arc<ArcSwap> with
    /// the installed hook), so the directory reloader can publish re-verified
    /// directories that every lane observes immediately.
    pub(crate) gate: DirectoryGate,
    /// This node's `localKernelId` (the identity the bound endpoint authenticates AS).
    /// Threaded into the reloader's `DirectoryReloadConfig` so the live binding recheck
    /// mirrors the startup check EXACTLY (`resolve_transport_endpoint(local_kernel_id)
    /// == endpoint_id`) rather than merely confirming the endpoint resolves to some
    /// kernel.
    pub(crate) transport_local_kernel_id: String,
}

/// Render the iroh federation-transport Prometheus metric families.
///
/// The relay's own `/metrics` route lives in `chio-pheromone-relay`
/// (`service.rs`), a separate crate this `-p chio-cli` change does not touch. The
/// clean hook is a one-line concatenation of this string onto that exporter's
/// body; this accessor makes the render reachable from the serving binary in the
/// meantime. All families are process-global statics, so any `/metrics` handler
/// that calls this observes the live counters.
#[must_use]
pub(crate) fn iroh_transport_metrics_prometheus() -> String {
    chio_federation_transport_iroh::metrics::render_iroh_transport_metrics_prometheus()
}

/// Parse the comma-separated `--iroh-lanes` value.
///
/// Fail-closed: an empty set, an unknown token, or a lane that is not wireable on
/// the relay-serve hook (revocation / bilateral, see the module docs) is rejected
/// rather than silently dropped.
pub(crate) fn parse_iroh_lanes(raw: &str) -> Result<Vec<IrohLane>, CliError> {
    let mut lanes = Vec::new();
    for token in raw.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let lane = match token {
            "pheromone" => IrohLane::Pheromone,
            "revocation" => IrohLane::Revocation,
            "bilateral" => IrohLane::Bilateral,
            other => {
                return Err(CliError::cli_other_error(format!(
                    "Chio iroh transport: unknown lane '{other}' (expected pheromone, revocation, or bilateral)"
                )));
            }
        };
        if !matches!(lane, IrohLane::Pheromone) {
            return Err(CliError::cli_other_error(format!(
                "Chio iroh transport: lane '{}' is not yet wired on the pheromone relay serve hook \
                 (it needs collaborators the relay does not host); only 'pheromone' is supported here",
                lane.label()
            )));
        }
        if !lanes.contains(&lane) {
            lanes.push(lane);
        }
    }
    if lanes.is_empty() {
        return Err(CliError::cli_other_error(
            "Chio iroh transport: --iroh-lanes selected no lanes".to_string(),
        ));
    }
    Ok(lanes)
}

/// Build `RelayMode` from the repeated `--iroh-relay-url` flag.
///
/// No URLs -> `RelayMode::Disabled` (direct addressing). This NEVER returns the n0
/// default map (free relays end 2026-12-31); a self-hosted relay is opt-in.
fn relay_mode_from_urls(urls: &[String]) -> Result<RelayMode, CliError> {
    if urls.is_empty() {
        return Ok(RelayMode::Disabled);
    }
    let mut parsed = Vec::with_capacity(urls.len());
    for url in urls {
        let relay_url: RelayUrl = url.parse().map_err(|error| {
            CliError::cli_other_error(format!("Chio iroh transport relay url '{url}': {error}"))
        })?;
        parsed.push(relay_url);
    }
    Ok(RelayMode::custom(parsed))
}

/// Load the transport ed25519 secret key from a `{ "seedHex": ".." }` file.
fn load_transport_secret_key(path: &Path) -> Result<SecretKey, CliError> {
    let json = read_utf8_json_file(path, "Chio iroh transport key")?;
    let document: IrohTransportKeyDocument = serde_json::from_str(&json).map_err(|error| {
        CliError::cli_other_error(format!("Chio iroh transport key: {error}"))
    })?;
    let bytes = hex::decode(document.seed_hex.trim()).map_err(|error| {
        CliError::cli_other_error(format!("Chio iroh transport key seedHex: {error}"))
    })?;
    let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        CliError::cli_other_error(
            "Chio iroh transport key seedHex: must decode to exactly 32 bytes".to_string(),
        )
    })?;
    Ok(SecretKey::from_bytes(&seed))
}

/// Build the load-time trust for the transport-directory bundle from the SAME
/// `--trusted-issuers` config the HTTP peer directory uses. The validity window is
/// checked against `now`.
///
/// Rollback pin: the trusted-issuer file's `minVersion` (the SAME field the HTTP
/// peer-directory loader reads as its trusted floor) is the rollback floor when no
/// explicit `transport_directory_state` pin is supplied, so a bundle below the
/// issuer-configured minimum is rejected fail-closed even without a state file
/// (defaulting to `0` only when `minVersion` is absent). Without a state pin the
/// expected predecessor is `None`, so a ROTATED successor bundle (carrying a
/// `previousVersionSha256`) still needs the state input to pin the predecessor hash;
/// a supplied state floor can never sit BELOW the issuer `minVersion` (a local pin
/// must not silently lower the issuer-configured floor). See
/// [`IrohTransportDirectoryStateDocument`].
fn transport_bundle_trust(
    trusted_issuers: Option<&Path>,
    transport_directory_state: Option<&Path>,
    now_unix_ms: u64,
) -> Result<TransportDirectoryBundleTrust, CliError> {
    let path = trusted_issuers.ok_or_else(|| {
        CliError::cli_other_error(
            "Chio iroh transport: --trusted-issuers is required with --iroh-enable".to_string(),
        )
    })?;
    let json = read_utf8_json_file(path, "Chio iroh transport trusted issuers")?;
    let document: RelayTrustedIssuersDocument = serde_json::from_str(&json).map_err(|error| {
        CliError::cli_other_error(format!("Chio iroh transport trusted issuers: {error}"))
    })?;
    // The SAME minVersion the HTTP peer-directory loader enforces as its trusted
    // rollback floor (absent -> 0). Read before `issuers` is consumed below.
    let trusted_min_version = document.min_version.unwrap_or(0);
    let issuers = document
        .issuers
        .into_iter()
        .map(|issuer| TrustedTransportDirectoryIssuer {
            issuer: issuer.issuer,
            key_id: issuer.key_id,
            public_key: issuer.public_key,
        })
        .collect::<Vec<_>>();
    if issuers.is_empty() {
        return Err(CliError::cli_other_error(
            "Chio iroh transport trusted issuers: no issuers configured".to_string(),
        ));
    }
    // Honor the trusted-issuer minVersion as the rollback floor. Without a rotation
    // state the expected predecessor is None (genesis chaining); with one, the
    // explicit floor takes precedence but can never fall below the issuer minVersion.
    //
    // minVersion is INCLUSIVE (the HTTP peer-directory loader accepts version ==
    // minVersion via `version < min_version`), but `verify_bundle` treats
    // `version_floor` as EXCLUSIVE (`version <= version_floor` rejects). Map the
    // inclusive minimum onto the exclusive floor with `saturating_sub(1)` so a
    // bundle exactly AT minVersion is accepted and one below it is rejected, in
    // lockstep with the HTTP loader.
    let inclusive_min_as_floor = trusted_min_version.saturating_sub(1);
    let (version_floor, expected_previous_version_sha256) = match transport_directory_state {
        Some(state_path) => {
            let state_json =
                read_utf8_json_file(state_path, "Chio iroh transport directory state")?;
            let state: IrohTransportDirectoryStateDocument = serde_json::from_str(&state_json)
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "Chio iroh transport directory state: {error}"
                    ))
                })?;
            (
                state.version_floor.max(inclusive_min_as_floor),
                state.expected_previous_version_sha256,
            )
        }
        None => (inclusive_min_as_floor, None),
    };
    Ok(TransportDirectoryBundleTrust {
        issuers,
        version_floor,
        expected_previous_version_sha256,
        now_unix_ms,
    })
}

/// Load + verify all iroh serve inputs, fail-closed.
///
/// Returns `Ok(None)` immediately (touching NO files, constructing NOTHING) when
/// `iroh_enable` is false: this is the opt-in-default-off / byte-unchanged
/// guarantee. When enabled, every missing/invalid input aborts with `Err`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn load_iroh_serve_inputs(
    iroh_enable: bool,
    iroh_transport_directory: Option<&Path>,
    iroh_transport_directory_state: Option<&Path>,
    trusted_issuers: Option<&Path>,
    iroh_transport_key: Option<&Path>,
    iroh_bind_addr: &str,
    iroh_relay_url: &[String],
    iroh_lanes: &str,
    now_unix_ms: u64,
) -> Result<Option<IrohServeInputs>, CliError> {
    if !iroh_enable {
        return Ok(None);
    }

    let lanes = parse_iroh_lanes(iroh_lanes)?;

    let directory_path = iroh_transport_directory.ok_or_else(|| {
        CliError::cli_other_error(
            "Chio iroh transport: --iroh-transport-directory is required with --iroh-enable"
                .to_string(),
        )
    })?;
    let directory_json =
        read_utf8_json_file(directory_path, "Chio iroh transport directory bundle")?;
    let bundle: TransportDirectoryBundleDocument = serde_json::from_str(&directory_json)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio iroh transport directory bundle: {error}"))
        })?;
    let trust = transport_bundle_trust(
        trusted_issuers,
        iroh_transport_directory_state,
        now_unix_ms,
    )?;
    let directory = bundle.verify_bundle(&trust).map_err(|error| {
        CliError::cli_other_error(format!(
            "Chio iroh transport directory bundle verification: {error}"
        ))
    })?;

    let key_path = iroh_transport_key.ok_or_else(|| {
        CliError::cli_other_error(
            "Chio iroh transport: --iroh-transport-key is required with --iroh-enable".to_string(),
        )
    })?;
    let transport_key = load_transport_secret_key(key_path)?;

    // Validate the LOCAL transport-key binding (fail-closed). The key this node
    // authenticates as MUST be exactly the transport `EndpointId` the verified
    // directory endorses for THIS node's `localKernelId`. Otherwise the endpoint
    // binds under an `EndpointId` no peer endorses: peers enforcing the same transport
    // directory would dial a DIFFERENT endpoint, or reject this one at the
    // `DirectoryGate` (`after_handshake`), so the opt-in iroh transport is silently
    // unusable. The `localKernelId` is carried by the body-hash-pinned directory
    // document, so it is trusted once `verify_bundle` succeeds; `resolve_transport_endpoint`
    // returns the non-removed binding (or `None` for an unknown/removed local entry).
    let local_kernel_id = bundle.directory.local_kernel_id.as_str();
    let endorsed_endpoint = directory
        .resolve_transport_endpoint(local_kernel_id)
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "Chio iroh transport: the verified directory binds no non-removed transport \
                 endpoint for this node's local kernel id '{local_kernel_id}', so the \
                 --iroh-transport-key cannot be a directory-endorsed endpoint"
            ))
        })?;
    let bound_endpoint = transport_key.public();
    if bound_endpoint != endorsed_endpoint {
        return Err(CliError::cli_other_error(format!(
            "Chio iroh transport: --iroh-transport-key public endpoint {} does not match the \
             directory-endorsed transport endpoint {} for local kernel id '{local_kernel_id}'; \
             peers enforcing this directory would reject or bypass this node",
            bound_endpoint.fmt_short(),
            endorsed_endpoint.fmt_short()
        )));
    }

    let bind_addr = iroh_bind_addr.parse::<SocketAddr>().map_err(|error| {
        CliError::cli_other_error(format!("Chio iroh transport bind address: {error}"))
    })?;
    let relay_mode = relay_mode_from_urls(iroh_relay_url)?;

    Ok(Some(IrohServeInputs {
        directory: Arc::new(directory),
        transport_key,
        // The issuer-signed, body-hash-pinned local identity this node authenticates
        // AS over the transport. Compared against the relay's configured local identity
        // at build time (fail-closed) so the endpoint can never authenticate as a
        // different kernel than the relay's receiver verifies inbound batches as.
        transport_local_kernel_id: bundle.directory.local_kernel_id.clone(),
        config: IrohMountConfig {
            relay_mode,
            bind_addr,
            lanes,
            max_idle_timeout: RECOMMENDED_MAX_IDLE_TIMEOUT,
        },
    }))
}

// -- Live directory reload ---------------------------------------------------

/// A directory-reload failure. Never crosses the trust boundary as an admit: the
/// reloader keeps last-good on a transient error and fails closed on expiry.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DirectoryReloadError {
    #[error("directory reload read error: {0}")]
    Read(String),
    #[error("directory reload verify error: {0}")]
    Verify(String),
    #[error("directory reload rollback: on-disk version {found} is not above current {current}")]
    Rollback { found: u64, current: u64 },
}

/// The outcome of one reload evaluation.
#[derive(Debug)]
pub(crate) enum ReloadOutcome {
    /// A strictly-newer, in-window bundle re-verified; swap it in.
    Updated(VerifiedDirectory),
    /// The on-disk bundle is unchanged and still in-window; no swap.
    Unchanged,
    /// The running bundle expired with no valid successor; swap to deny-all.
    ExpiredWhileRunning,
    /// A strictly-newer, in-window successor re-verified but no longer binds THIS
    /// node's local transport endpoint (it tombstoned or rotated this node). The
    /// already-bound endpoint would keep serving with the old key, so the swap must
    /// NOT proceed as an admit; fail closed to deny-all (local-binding recheck,
    /// mirroring the startup binding check). Carries the (validly-signed,
    /// in-window, monotone) revoking directory so the reloader ADVANCES its last-good
    /// chain onto it: the revoker is now the federation's canonical directory, so a
    /// later successor that rebinds this node chains onto THIS revoker (not the
    /// pre-revoke version) and must be able to self-heal admission.
    LocalBindingRevoked(VerifiedDirectory),
    /// The directory is below a trusted `minVersion` operators raised above it, so it can
    /// never be admitted (a restart would reject it via `transport_bundle_trust`); fail
    /// closed to deny-all. `Some(successor)` is a strictly-newer, validly-signed, in-window
    /// successor that is itself below the raised floor: it cannot admit, but the reloader
    /// ADVANCES its last-good chain onto it (like [`ReloadOutcome::LocalBindingRevoked`]) so
    /// a later at-or-above-floor bundle - which chains onto THIS successor - self-heals
    /// rather than being stranded against a dropped chain. `None` is the running directory
    /// itself below the floor (the unchanged fast path, or a below-floor running directory
    /// whose on-disk successor did not verify): deny-all, chain KEPT.
    BelowMinVersionFloor(Option<VerifiedDirectory>),
    /// The on-disk bundle is UNCHANGED and still in-window, but it no longer verifies
    /// against the CURRENT trusted-issuer set: operators rotated or removed the issuer
    /// that signed it (or rotated its key) since the last verification. A restart would
    /// reject it via `transport_bundle_trust` (unknown issuer / invalid signature); the
    /// unchanged fast path must fail closed to deny-all identically rather than keep
    /// admitting under a signer the federation no longer trusts until expiry.
    TrustRootsChanged,
    /// The on-disk bundle carries the running version but a DIFFERENT canonical body: the
    /// file was replaced without a version bump (a tampered or out-of-band rotated body).
    /// It cannot be a monotone successor at the same version, and treating it as Unchanged
    /// would keep the loaded directory admitting peers the replacement dropped. Fail closed
    /// to deny-all; a proper versioned successor chained onto last-good self-heals.
    CurrentBodyReplaced,
    /// The trusted-issuers file parsed but pins NO issuer (operators removed every issuer).
    /// Trusting no signer must admit nothing, and startup rejects the same empty
    /// configuration; the reload must fail closed to deny-all rather than fold it into the
    /// transient keep-last-good read-error path (which would keep the previous signer active
    /// until expiry). Chain is KEPT so a successor under a restored issuer self-heals.
    TrustRootsEmpty,
}

/// Inputs for the bounded poll reloader. The reloader deliberately advances its
/// version floor + previous-hash chain from the LIVE directory (current_version /
/// current_body_sha256), not from a rotation-state file, so a downgrade can never
/// be re-accepted; hence no state-file path is carried here.
pub(crate) struct DirectoryReloadConfig {
    pub interval: Duration,
    pub bundle_path: PathBuf,
    pub trusted_issuers_path: PathBuf,
    /// This node's LOCAL transport binding: the `EndpointId` the running endpoint is
    /// actually bound to (the public half of the configured `--iroh-transport-key`).
    /// Rechecked against every re-verified successor BEFORE the swap:
    /// the startup path rejects a directory that does not endorse this binding, and a
    /// live successor that tombstones or rotates this node must not be swapped in while
    /// the endpoint keeps serving with the old key. The recheck fails closed to deny-all.
    pub local_transport_endpoint: EndpointId,
    /// This node's `localKernelId` (the identity the running endpoint authenticates AS,
    /// carried by the body-hash-pinned directory document and matched at startup). The
    /// binding recheck mirrors the startup check EXACTLY: it requires the successor to
    /// bind THIS kernel id to THIS endpoint (`resolve_transport_endpoint(local_kernel_id)
    /// == local_transport_endpoint`). Checking only that the endpoint resolves to SOME
    /// kernel is insufficient: a successor that reassigns this endpoint to a DIFFERENT
    /// kernel id would still `authorize` it, yet the relay would keep serving under the
    /// old secret for an identity the directory no longer binds to this node.
    pub local_kernel_id: String,
}

/// Read + parse the on-disk transport directory bundle (no verification).
fn read_bundle_document(path: &Path) -> Result<TransportDirectoryBundleDocument, String> {
    let json = read_utf8_json_file(path, "Chio iroh transport directory bundle")
        .map_err(|error| error.to_string())?;
    serde_json::from_str(&json).map_err(|error| error.to_string())
}

/// The canonical sha256 of a parsed bundle document. This matches the value the gate
/// reports as `current_body_sha256` and that a successor pins as `previousVersionSha256`
/// (`VerifiedDirectory::body_sha256` hashes the same whole document), so the reloader can
/// tell a byte-unchanged bundle from a same-version replacement without re-verifying.
fn bundle_body_sha256(bundle: &TransportDirectoryBundleDocument) -> Result<String, String> {
    let bytes =
        chio_core_types::canonical_json_bytes(bundle).map_err(|error| error.to_string())?;
    Ok(chio_core_types::sha256_hex(&bytes))
}

/// A trusted-issuers reload failure. `Empty` is a DISTINCT fail-closed condition (the
/// file parsed but pins no issuer, so no signer is trusted) kept apart from a transient
/// `Read`/parse error that keeps last-good.
enum TrustedIssuersReloadError {
    /// The file could not be read or parsed (transient); keep last-good.
    Read(String),
    /// The file parsed but pins NO issuer. Trusting no signer must admit nothing, so this
    /// fails closed to deny-all rather than keeping the previous signer active until expiry.
    Empty,
}

/// Read + parse the trusted-issuers file into the verifier's issuer list PLUS the
/// trusted `minVersion` (absent -> 0). The reload path honors this floor identically
/// to the startup loader: operators that raise `minVersion` on a running relay
/// must have it enforced on the NEXT reload, not only at restart. An empty issuer set is
/// surfaced as [`TrustedIssuersReloadError::Empty`] so callers fail closed rather than
/// folding it into the transient keep-last-good read-error path.
fn read_trusted_issuers(
    path: &Path,
) -> Result<(Vec<TrustedTransportDirectoryIssuer>, u64), TrustedIssuersReloadError> {
    let json = read_utf8_json_file(path, "Chio iroh transport trusted issuers")
        .map_err(|error| TrustedIssuersReloadError::Read(error.to_string()))?;
    let document: super::relay::RelayTrustedIssuersDocument = serde_json::from_str(&json)
        .map_err(|error| TrustedIssuersReloadError::Read(error.to_string()))?;
    let trusted_min_version = document.min_version.unwrap_or(0);
    let issuers: Vec<TrustedTransportDirectoryIssuer> = document
        .issuers
        .into_iter()
        .map(|issuer| TrustedTransportDirectoryIssuer {
            issuer: issuer.issuer,
            key_id: issuer.key_id,
            public_key: issuer.public_key,
        })
        .collect();
    if issuers.is_empty() {
        return Err(TrustedIssuersReloadError::Empty);
    }
    Ok((issuers, trusted_min_version))
}

/// Re-verify the directory bundle, fail-closed. EXPIRY IS CHECKED BEFORE THE
/// UNCHANGED FAST PATH: an unchanged-but-expired bundle must not be treated as
/// valid; with no strictly-newer in-window successor it fails closed as
/// `ExpiredWhileRunning`.
pub(crate) fn reload_verified_directory(
    config: &DirectoryReloadConfig,
    now: u64,
    current_version: u64,
    current_expires_at_unix_ms: u64,
    current_body_sha256: &str,
) -> Result<ReloadOutcome, DirectoryReloadError> {
    let expired = current_expires_at_unix_ms <= now;

    // Read the on-disk bundle. If it cannot be read and the running bundle is
    // expired, we cannot keep serving it -> fail closed; else keep last-good.
    let bundle = match read_bundle_document(&config.bundle_path) {
        Ok(bundle) => bundle,
        Err(error) => {
            if expired {
                return Ok(ReloadOutcome::ExpiredWhileRunning);
            }
            return Err(DirectoryReloadError::Read(error));
        }
    };

    // Fast path ONLY when still in-window: a genuinely unchanged, still-valid
    // bundle needs no re-verify. Guarded by `!expired` so an expired bundle can
    // never be short-circuited as Unchanged.
    if !expired && bundle.body.version == current_version {
        // The unchanged fast path is only sound when the on-disk body is BYTE-identical to
        // the loaded one. A same-version file whose canonical body differs (a tampered or
        // out-of-band rotated body, possibly re-signed by rotated trust roots) is a
        // substitution, not the running directory: it cannot be a monotone successor at the
        // same version, and reporting it Unchanged would keep the loaded directory admitting
        // peers the replacement dropped. Fail closed to deny-all instead; a proper versioned
        // successor chained onto last-good self-heals. Compare hashes BEFORE the fast path.
        match bundle_body_sha256(&bundle) {
            Ok(on_disk) if on_disk != current_body_sha256 => {
                return Ok(ReloadOutcome::CurrentBodyReplaced);
            }
            Ok(_) => {}
            Err(error) => return Err(DirectoryReloadError::Verify(error)),
        }
        // The unchanged fast path must be exactly as strict as a restart: an operator can
        // change the trusted-issuer set (raise `minVersion`, or rotate/remove the signing
        // issuer) while the on-disk bundle is byte-unchanged. Re-read the current trust so
        // the fast path enforces it rather than serving a stale-but-now-untrusted directory
        // until expiry. A transient read error must NOT tear down a still-in-window
        // directory, so keep last-good (`Err(Read)`) exactly as the strictly-newer path.
        let (issuers, trusted_min_version) =
            match read_trusted_issuers(&config.trusted_issuers_path) {
                Ok(parsed) => parsed,
                Err(TrustedIssuersReloadError::Empty) => {
                    return Ok(ReloadOutcome::TrustRootsEmpty)
                }
                Err(TrustedIssuersReloadError::Read(error)) => {
                    return Err(DirectoryReloadError::Read(error))
                }
            };
        // minVersion is INCLUSIVE: a directory at `current_version` is admissible only
        // when `current_version >= trusted_min_version`. Below that floor, fail closed. The
        // running directory is unchanged (no successor to advance the chain onto), so keep
        // last-good (`None`) and let a successor at or above the floor self-heal.
        if current_version < trusted_min_version {
            return Ok(ReloadOutcome::BelowMinVersionFloor(None));
        }
        // RE-VERIFY THE UNCHANGED BUNDLE AGAINST THE CURRENT TRUST ROOTS (fail-closed).
        // The gate authorized this bundle against the issuer set that was trusted when it
        // was last verified; that set can shrink underneath a running relay (an operator
        // rotates or removes the issuer that signed it). A bundle signed by an issuer the
        // federation no longer trusts must stop admitting immediately, exactly as a restart
        // would reject it via `transport_bundle_trust`. Chain onto the bundle's own recorded
        // predecessor (its identity is unchanged, so this re-check is a pure signature/issuer
        // re-validation, not a rollback re-evaluation) and floor just below the running
        // version so the current version is still admissible. Any verification failure
        // (unknown issuer, invalid signature) fails closed to deny-all.
        let trust = TransportDirectoryBundleTrust {
            issuers,
            version_floor: current_version.saturating_sub(1),
            expected_previous_version_sha256: bundle.body.previous_version_sha256.clone(),
            now_unix_ms: now,
        };
        return match bundle.verify_bundle(&trust) {
            Ok(_verified) => Ok(ReloadOutcome::Unchanged),
            Err(_error) => Ok(ReloadOutcome::TrustRootsChanged),
        };
    }

    if bundle.body.version > current_version {
        // Strictly newer: verify against a floor of the current version, chaining
        // onto the current body hash, with a FRESH now. verify_bundle's validity
        // window rejects an already-expired successor, so an expired bundle cannot
        // be swapped in.
        let (issuers, trusted_min_version) =
            match read_trusted_issuers(&config.trusted_issuers_path) {
                Ok(parsed) => parsed,
                Err(TrustedIssuersReloadError::Empty) => {
                    return Ok(ReloadOutcome::TrustRootsEmpty)
                }
                Err(TrustedIssuersReloadError::Read(error)) => {
                    if expired {
                        return Ok(ReloadOutcome::ExpiredWhileRunning);
                    }
                    return Err(DirectoryReloadError::Read(error));
                }
            };
        // minVersion is INCLUSIVE: a successor is admissible only when its version is at or
        // above the trusted floor. A successor newer than the running version but STILL
        // BELOW that floor (operators raised minVersion past this staged version) can never
        // be admitted. It is still VERIFIED against the preserved chain so a valid one
        // ADVANCES last-good onto it (deny-all, like `LocalBindingRevoked`): a below-floor
        // successor is the immediate predecessor a later at-or-above-floor bundle chains
        // onto, so dropping it here would strand that recovery bundle (predecessor mismatch)
        // in deny-all until restart. A below-floor successor implies the running directory
        // is below the floor too, so a successor that does NOT verify still fails closed to
        // deny-all rather than keeping the below-floor directory admitting.
        if bundle.body.version < trusted_min_version {
            let trust = TransportDirectoryBundleTrust {
                issuers,
                version_floor: current_version,
                expected_previous_version_sha256: Some(current_body_sha256.to_string()),
                now_unix_ms: now,
            };
            return Ok(match bundle.verify_bundle(&trust) {
                Ok(verified) => ReloadOutcome::BelowMinVersionFloor(Some(verified)),
                Err(_error) => ReloadOutcome::BelowMinVersionFloor(None),
            });
        }
        let trust = TransportDirectoryBundleTrust {
            issuers,
            version_floor: current_version,
            expected_previous_version_sha256: Some(current_body_sha256.to_string()),
            now_unix_ms: now,
        };
        return match bundle.verify_bundle(&trust) {
            Ok(verified) => {
                // RECHECK THE LOCAL IDENTITY BINDING BEFORE SWAPPING (fail-closed).
                // The successor verified as a valid, in-window, monotone directory, but that
                // does NOT prove it still binds THIS node's local identity the way the startup
                // path (`load_iroh_serve_inputs` + `build_iroh_router`) requires. Mirror BOTH
                // startup checks EXACTLY, or a successor a restart would reject could be swapped
                // in live:
                //   - `resolve_transport_endpoint(local_kernel_id) == local_transport_endpoint`
                //     denies a successor that TOMBSTONES this node (resolve None), ROTATES its
                //     endpoint to a different `EndpointId` (resolve returns the new endpoint), or
                //     REASSIGNS the bound endpoint to a DIFFERENT kernel id (resolving THIS kernel
                //     yields a different or no endpoint); and
                //   - `directory.localKernelId == local_kernel_id` denies a successor that keeps
                //     this node's endpoint binding but REASSIGNS the directory's declared local
                //     identity: `build_iroh_router` requires the bundle's own `localKernelId` to
                //     equal the relay's configured local kernel id, so a restart would reject
                //     such a bundle even though the endpoint binding survives.
                // In every case the already-bound endpoint would keep serving iroh ingress under
                // the OLD `SecretKey` for a local identity the successor no longer binds to this
                // node. Fail closed to deny-all rather than admit under a revoked local identity.
                let binds_local_endpoint = verified
                    .resolve_transport_endpoint(&config.local_kernel_id)
                    == Some(config.local_transport_endpoint);
                let declares_local_kernel =
                    bundle.directory.local_kernel_id == config.local_kernel_id;
                if binds_local_endpoint && declares_local_kernel {
                    Ok(ReloadOutcome::Updated(verified))
                } else {
                    Ok(ReloadOutcome::LocalBindingRevoked(verified))
                }
            }
            Err(error) => {
                // A successor at or above the floor that fails verification (partially
                // written or bad) must NOT mask a running directory that is ITSELF below the
                // raised floor: a restart would reject the running directory via
                // `transport_bundle_trust`, so fail closed to deny-all rather than keep the
                // below-floor directory admitting until expiry. Order this ahead of the
                // transient paths so a bad successor cannot leave a below-floor directory
                // live. last-good is KEPT so a valid successor chained onto it self-heals.
                if current_version < trusted_min_version {
                    Ok(ReloadOutcome::BelowMinVersionFloor(None))
                } else if expired {
                    Ok(ReloadOutcome::ExpiredWhileRunning)
                } else {
                    Err(DirectoryReloadError::Verify(error.to_string()))
                }
            }
        };
    }

    // version <= current and not the in-window-unchanged case: either a rollback
    // attempt or an expired bundle with no newer successor. Fail closed if
    // expired; else reject the rollback and keep last-good.
    if expired {
        Ok(ReloadOutcome::ExpiredWhileRunning)
    } else {
        Err(DirectoryReloadError::Rollback {
            found: bundle.body.version,
            current: current_version,
        })
    }
}

/// The reloader's LAST-GOOD directory identity, tracked SEPARATELY from the admission
/// gate. A fail-closed deny-all swap (expiry / binding revoked) must NOT erase the
/// version + hash chain the next successor verifies against: if the reloader re-read
/// these from the gate, an expiry swap would leave the gate at the deny-all sentinel
/// (version 0, empty hash), and a later successor chained onto the last good bundle
/// would then fail verification (predecessor version/hash mismatch), stranding the
/// relay in deny-all until a restart. Holding last-good here lets the reloader SELF-HEAL
/// back to admission when a valid in-window successor appears.
struct ReloadState {
    version: u64,
    body_sha256: String,
    expires_at_unix_ms: u64,
}

impl ReloadState {
    /// Seed from the load-time-verified gate.
    fn from_gate(gate: &DirectoryGate) -> Self {
        Self {
            version: gate.current_version(),
            body_sha256: gate.current_body_sha256(),
            expires_at_unix_ms: gate.current_expires_at_unix_ms(),
        }
    }
}

/// One reload evaluation: re-verify against the preserved last-good chain and either
/// swap in a successor (advancing last-good), alarm + deny-all on expiry / binding
/// revocation (WITHOUT touching last-good, so a later successor can self-heal), or keep
/// last-good on a transient error. Extracted from the poll loop so the last-good
/// preservation + self-heal is unit-testable without the async timer.
fn directory_reload_step(
    gate: &DirectoryGate,
    config: &DirectoryReloadConfig,
    now: u64,
    state: &mut ReloadState,
    alive: &std::sync::atomic::AtomicBool,
) {
    use std::sync::atomic::Ordering;
    match reload_verified_directory(
        config,
        now,
        state.version,
        state.expires_at_unix_ms,
        &state.body_sha256,
    ) {
        Ok(ReloadOutcome::Updated(next)) => {
            // Advance the last-good chain to the newly-verified successor BEFORE the swap,
            // so a subsequent reload (and any recovery from a later lapse) chains onto it.
            // This is also the self-heal path back from a deny-all lapse: a valid in-window
            // successor verified against the preserved last-good chain restores admission
            // without a restart.
            state.version = next.version();
            state.body_sha256 = next.body_sha256().to_string();
            state.expires_at_unix_ms = next.expires_at_unix_ms();
            gate.swap(Arc::new(next));
            chio_federation_transport_iroh::metrics::record_directory_reload(
                chio_federation_transport_iroh::metrics::RELOAD_UPDATED,
            );
        }
        Ok(ReloadOutcome::Unchanged) => {
            chio_federation_transport_iroh::metrics::record_directory_reload(
                chio_federation_transport_iroh::metrics::RELOAD_UNCHANGED,
            );
        }
        Ok(ReloadOutcome::ExpiredWhileRunning) => {
            // Fail closed to deny-all but KEEP last-good (state untouched): a later valid
            // in-window successor chained onto it re-verifies and self-heals admission.
            gate.swap(Arc::new(
                chio_federation_transport_iroh::identity::VerifiedDirectory::empty_deny_all(),
            ));
            alive.store(false, Ordering::SeqCst);
            chio_federation_transport_iroh::metrics::record_directory_reload(
                chio_federation_transport_iroh::metrics::RELOAD_EXPIRED_FAILCLOSED,
            );
            tracing::error!(
                target: chio_federation_transport_iroh::observability::TARGET_ADMISSION,
                "transport directory expired with no valid successor; admitting nothing until a \
                 valid in-window successor is published"
            );
        }
        Ok(ReloadOutcome::LocalBindingRevoked(revoking)) => {
            // The successor verified but no longer binds this node's local identity the way
            // startup requires: it tombstoned this node, rotated or reassigned its bound
            // transport endpoint, or reassigned the directory's declared `localKernelId` away
            // from this node. The endpoint is still bound with the old key, so admitting peers
            // from the successor would serve ingress under a revoked identity. Fail closed to
            // deny-all and raise the same alarm as expiry.
            //
            // ADVANCE the last-good chain onto the revoking directory FIRST. The revoker is
            // a validly-signed, in-window, monotone directory: it is now the federation's
            // canonical successor, so a later directory that rebinds this node chains onto
            // THIS revoker's hash/version, not the pre-revoke version. Leaving the chain
            // pinned to the pre-revoke version would reject that correctly-chained rebinding
            // successor (predecessor mismatch) and strand the relay in deny-all until a
            // restart. The gate stays deny-all (we do NOT swap the revoker in, since it does
            // not bind this node); only the chain reference advances, so the documented
            // self-heal path works after a rebind.
            state.version = revoking.version();
            state.body_sha256 = revoking.body_sha256().to_string();
            state.expires_at_unix_ms = revoking.expires_at_unix_ms();
            gate.swap(Arc::new(
                chio_federation_transport_iroh::identity::VerifiedDirectory::empty_deny_all(),
            ));
            alive.store(false, Ordering::SeqCst);
            chio_federation_transport_iroh::metrics::record_directory_reload(
                chio_federation_transport_iroh::metrics::RELOAD_BINDING_REVOKED,
            );
            tracing::error!(
                target: chio_federation_transport_iroh::observability::TARGET_ADMISSION,
                "transport directory successor no longer binds this node's local identity \
                 (tombstoned, endpoint rotated or reassigned, or declared local kernel id \
                 changed); admitting nothing until a successor rebinds this node"
            );
        }
        Ok(ReloadOutcome::BelowMinVersionFloor(maybe_successor)) => {
            // The directory is below a trusted minVersion operators raised above it. A
            // restart would reject it, so fail closed to deny-all rather than keep admitting
            // until expiry.
            //
            // If a strictly-newer, validly-signed successor is present, it is itself below
            // the raised floor: it cannot admit, but ADVANCE the last-good chain onto it (as
            // `LocalBindingRevoked` does) so a later at-or-above-floor bundle chained onto
            // THIS successor self-heals instead of being stranded against a dropped chain.
            // Absent a successor (the unchanged running directory, or a below-floor running
            // directory whose successor did not verify), last-good is KEPT.
            if let Some(successor) = maybe_successor {
                state.version = successor.version();
                state.body_sha256 = successor.body_sha256().to_string();
                state.expires_at_unix_ms = successor.expires_at_unix_ms();
            }
            gate.swap(Arc::new(
                chio_federation_transport_iroh::identity::VerifiedDirectory::empty_deny_all(),
            ));
            alive.store(false, Ordering::SeqCst);
            chio_federation_transport_iroh::metrics::record_directory_reload(
                chio_federation_transport_iroh::metrics::RELOAD_BELOW_MIN_VERSION,
            );
            tracing::error!(
                target: chio_federation_transport_iroh::observability::TARGET_ADMISSION,
                "transport directory version is below the trusted minVersion floor operators \
                 raised; admitting nothing until a successor at or above the floor is published"
            );
        }
        Ok(ReloadOutcome::TrustRootsChanged) => {
            // The running directory is unchanged and in-window but its signing issuer is no
            // longer trusted (operators rotated or removed it). A restart would reject it, so
            // fail closed to deny-all rather than keep admitting under an untrusted signer.
            // last-good is KEPT (state untouched): a later successor signed by a currently
            // trusted issuer, chained onto the running directory, self-heals admission without
            // a restart.
            gate.swap(Arc::new(
                chio_federation_transport_iroh::identity::VerifiedDirectory::empty_deny_all(),
            ));
            alive.store(false, Ordering::SeqCst);
            chio_federation_transport_iroh::metrics::record_directory_reload(
                chio_federation_transport_iroh::metrics::RELOAD_TRUST_ROOTS_CHANGED,
            );
            tracing::error!(
                target: chio_federation_transport_iroh::observability::TARGET_ADMISSION,
                "transport directory signing issuer is no longer trusted; admitting nothing \
                 until a successor signed by a currently trusted issuer is published"
            );
        }
        Ok(ReloadOutcome::CurrentBodyReplaced) => {
            // The on-disk bundle carries the running version but a different body: the file
            // was replaced without a version bump, so it cannot be trusted as a monotone
            // successor. Fail closed to deny-all rather than keep the loaded directory
            // admitting. last-good is KEPT (state untouched): a properly versioned successor
            // chained onto the running directory self-heals admission without a restart.
            gate.swap(Arc::new(
                chio_federation_transport_iroh::identity::VerifiedDirectory::empty_deny_all(),
            ));
            alive.store(false, Ordering::SeqCst);
            chio_federation_transport_iroh::metrics::record_directory_reload(
                chio_federation_transport_iroh::metrics::RELOAD_CURRENT_BODY_REPLACED,
            );
            tracing::error!(
                target: chio_federation_transport_iroh::observability::TARGET_ADMISSION,
                "transport directory file was replaced at the running version with a different \
                 body; admitting nothing until a properly versioned successor is published"
            );
        }
        Ok(ReloadOutcome::TrustRootsEmpty) => {
            // The trusted-issuers file now pins no issuer: operators removed every issuer.
            // Trusting no signer must admit nothing, and startup rejects the same empty
            // configuration, so fail closed to deny-all rather than keep the previous signer
            // active until expiry. last-good is KEPT (state untouched): a successor under a
            // restored trusted issuer, chained onto the running directory, self-heals.
            gate.swap(Arc::new(
                chio_federation_transport_iroh::identity::VerifiedDirectory::empty_deny_all(),
            ));
            alive.store(false, Ordering::SeqCst);
            chio_federation_transport_iroh::metrics::record_directory_reload(
                chio_federation_transport_iroh::metrics::RELOAD_TRUST_ROOTS_EMPTY,
            );
            tracing::error!(
                target: chio_federation_transport_iroh::observability::TARGET_ADMISSION,
                "transport directory trusted-issuer set is empty; admitting nothing until a \
                 trusted issuer is restored and a successor it signs is published"
            );
        }
        Err(error) => {
            chio_federation_transport_iroh::metrics::record_directory_reload(
                chio_federation_transport_iroh::metrics::RELOAD_ERROR,
            );
            tracing::warn!(
                target: chio_federation_transport_iroh::observability::TARGET_ADMISSION,
                error = %error,
                "transport directory reload failed; keeping last-good"
            );
        }
    }
}

/// The reloader's next wake delay, driven by the LIVE admission gate's directory rather
/// than the reloader's last-good chain (which can point past a deny-all gate at an
/// already-advanced successor). `live_directory_expires_at_unix_ms` is
/// `DirectoryGate::current_expires_at_unix_ms`: `0` is the deny-all sentinel (admits
/// nothing), and any positive value is a live directory's validity-window end.
///
/// - Deny-all gate: poll on the fixed `interval` for a valid successor. No live directory
///   is admitting, so there is no expiry to enforce and never a zero-delay busy-loop.
/// - Live directory still in-window: wake at whichever comes first, the next fixed poll or
///   the expiry deadline, so a bundle that expires between two fixed polls fails closed AT
///   the deadline (`DirectoryGate::decide` is not itself time-aware).
/// - Live directory whose deadline elapsed mid-cycle (the step ran while it was in-window,
///   so the gate is still admitting it): recheck IMMEDIATELY so the next step fails it
///   closed at the deadline rather than after another full interval.
fn next_reload_delay(
    interval: Duration,
    now: u64,
    live_directory_expires_at_unix_ms: u64,
) -> Duration {
    if live_directory_expires_at_unix_ms == 0 {
        interval
    } else if live_directory_expires_at_unix_ms > now {
        std::cmp::min(
            interval,
            Duration::from_millis(live_directory_expires_at_unix_ms - now),
        )
    } else {
        Duration::ZERO
    }
}

/// Bounded poll loop: re-verify the directory and either swap in a successor, alarm +
/// deny-all on expiry, or keep last-good. Wakes at most every `interval`, but also
/// exactly at the running directory's expiry deadline (see [`next_reload_delay`]) so an
/// expired directory fails closed promptly instead of admitting until the next fixed
/// poll. A dedicated task feeds shared state (the admission gate and the alive flag)
/// and is joined on shutdown.
pub(crate) async fn run_directory_reloader(
    gate: DirectoryGate,
    config: DirectoryReloadConfig,
    now_fn: Arc<dyn Fn() -> u64 + Send + Sync>,
    alive: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut state = ReloadState::from_gate(&gate);
    loop {
        let now = now_fn();
        directory_reload_step(&gate, &config, now, &mut state, &alive);
        // Schedule off the LIVE gate's expiry (re-read after the step and with a fresh
        // clock): if the directory was still admitting at the step but its deadline elapsed
        // before this delay is computed, the gate expiry is now in the past and the reloader
        // rechecks immediately to fail it closed, rather than admitting for another interval.
        let delay = next_reload_delay(
            config.interval,
            now_fn(),
            gate.current_expires_at_unix_ms(),
        );
        tokio::time::sleep(delay).await;
    }
}

/// Per-tick router-liveness step, testable without a live router: flip the
/// `chio_iroh_router_alive` gauge and, on the transition to dead, log an alarm so a
/// panicked accept task that silently kills the router (while HTTP keeps serving)
/// becomes loud. Returns the liveness it was given.
pub(crate) fn note_router_liveness(alive: bool) -> bool {
    chio_federation_transport_iroh::metrics::set_router_alive(alive);
    if !alive {
        tracing::error!(
            target: chio_federation_transport_iroh::observability::TARGET_ADMISSION,
            "iroh router is down; federation ingress frozen while HTTP keeps serving"
        );
    }
    alive
}

/// Build and spawn the iroh router, sharing the relay's receiver + store.
///
/// One `Endpoint` with the [`DirectoryGate`] installed via `.hooks(gate)` (so
/// unadmitted endpoints are 403'd at `after_handshake` before any handler runs),
/// the configured `RelayMode`, the configured bind address, and the recommended
/// QUIC idle-timeout backstop. The pheromone lane is mounted with the SAME
/// `Arc<dyn RelayBatchReceiver>` + `Arc<SqlitePheromoneRelayStore>` the HTTP relay
/// holds. Fail-closed: any bind/verify error returns `Err`.
///
/// `peer_directory` is the SAME issuer-verified peer directory the HTTP relay holds;
/// the iroh ingress handler enforces `enforce_peer_batch_directory_scope` against it
/// before every `receive_batch`, so both transports apply one identical inbound scope
/// gate (an out-of-scope sender is rejected on the iroh path exactly as over HTTP).
///
/// `max_batch_bytes` is the relay profile's configured body-size limit (the HTTP
/// relay's `DefaultBodyLimit`); the ingress handler rejects any frame over it before
/// deserialization, so the iroh path is never a laxer ingress than HTTP.
pub(crate) async fn build_iroh_router(
    inputs: IrohServeInputs,
    receiver: Arc<dyn RelayBatchReceiver>,
    store: Arc<SqlitePheromoneRelayStore>,
    peer_directory: PeerDirectory,
    max_batch_bytes: usize,
) -> Result<IrohMount, CliError> {
    let IrohServeInputs {
        directory,
        transport_key,
        transport_local_kernel_id,
        config,
    } = inputs;

    // FAIL-CLOSED WIRING GUARD: only the pheromone lane is wireable on this serve
    // hook. Enabling lane c (fan-out) here is a fail-closed error and MUST stay so
    // until BOTH are satisfied: (1) the gossip Lagged handling has an anti-entropy
    // path or an explicit accepted-loss decision, and (2) any lane-c
    // mount passes the issuer-signed VerifiedDirectory (never a StaticTreatyMembership
    // and never the raw topic id) as the TreatyMembership oracle and derives origin
    // keys from the same trusted admission set. The per-treaty membership gate is
    // enforced at JOIN (subscribe_treaty_with_timeout) and RECEIVE
    // (verify_fanout_frame); this guard keeps it that way. parse_iroh_lanes already
    // rejected anything else, so this is a defense-in-depth re-check.
    if config.lanes.iter().any(|lane| !matches!(lane, IrohLane::Pheromone)) {
        return Err(CliError::cli_other_error(
            "Chio iroh transport: only the pheromone lane is wireable on the relay serve hook"
                .to_string(),
        ));
    }

    // Fail-closed relay/transport identity binding. The transport directory's own
    // `localKernelId` (the identity this endpoint authenticates AS, verified at load time
    // to match the endorsed transport key) MUST equal the relay's configured local
    // identity, which is `peer_directory.local_kernel_id()` (the SAME value the HTTP relay
    // sets as `PheromoneRelayConfig.local_kernel_id` and its receiver verifies every
    // inbound batch against). If they differ, the iroh endpoint authenticates as a
    // DIFFERENT kernel than the receiver expects, so valid deliveries are
    // rejected/dead-lettered while startup silently "succeeds". Reject BEFORE binding the
    // endpoint so the mount never comes up authenticating as the wrong kernel.
    let relay_local_kernel_id = peer_directory.local_kernel_id();
    if transport_local_kernel_id != relay_local_kernel_id {
        return Err(CliError::cli_other_error(format!(
            "Chio iroh transport: the transport directory's local kernel id '{transport_local_kernel_id}' \
             does not match the relay's configured local kernel id '{relay_local_kernel_id}'; the iroh \
             endpoint would authenticate as a different kernel than the relay's receiver verifies inbound \
             batches as, so valid deliveries would be rejected/dead-lettered"
        )));
    }

    let gate = DirectoryGate::new(directory);

    let idle_timeout: IdleTimeout = config.max_idle_timeout.try_into().map_err(|error| {
        CliError::cli_other_error(format!("Chio iroh transport idle timeout: {error}"))
    })?;
    // Each direct lane uses exactly one bidi stream per connection; bound the
    // per-connection window to the batch cap with headroom.
    let bidi_streams = VarInt::from(
        chio_federation_transport_iroh::lanes::limits::RECOMMENDED_MAX_BIDI_STREAMS,
    );
    let receive_window = VarInt::from_u64(
        chio_federation_transport_iroh::lanes::limits::recommended_receive_window_bytes(
            max_batch_bytes,
        ),
    )
    .unwrap_or(VarInt::MAX);
    let transport_config = QuicTransportConfig::builder()
        .max_idle_timeout(Some(idle_timeout))
        .max_concurrent_bidi_streams(bidi_streams)
        .receive_window(receive_window)
        .build();

    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(transport_key)
        .relay_mode(config.relay_mode)
        .transport_config(transport_config)
        // iroh's Endpoint builder is pre-seeded with BOTH default IP transports
        // (0.0.0.0 AND [::]); `bind_addr` only replaces the default for the address
        // FAMILY it names, so a single-family bind (e.g. 127.0.0.1:4433) would still
        // open an IPv6 wildcard ([::]) socket and expose the lane on an unintended
        // interface. Clear all default IP transports FIRST, then bind exactly the one
        // operator-intended address (`clear_ip_transports` removes every IP transport,
        // so it MUST precede `bind_addr` or it would drop the address just added).
        .clear_ip_transports()
        .bind_addr(config.bind_addr)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio iroh transport bind address: {error}"))
        })?
        .hooks(gate.clone())
        .bind()
        .await
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio iroh transport endpoint bind: {error}"))
        })?;
    let endpoint_id = endpoint.id();
    // Capture the ACTUAL bound socket(s) before the endpoint is moved into the
    // router. With the default ephemeral port this is the operator's only way to
    // learn the reachable address to configure on peers.
    let bound_sockets = endpoint.bound_sockets();

    // The shared clock the handler stamps received batches with.
    let now_fn: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(unix_now_ms);
    // Inbound directory-scope gate: reuse the shipped enforce_peer_batch_directory_scope
    // against the SAME peer directory the HTTP relay holds, so the iroh ingress path
    // applies the identical Origin/Hub + frame-cap + treaty-subscription + ladder-pin
    // check the HTTP handle_batch_relay runs before receive_batch (fail-closed).
    let scope_check: InboundBatchScopeCheck = Arc::new(move |sender, batch| {
        enforce_peer_batch_directory_scope(&peer_directory, sender, batch)
    });
    // Enforce the SAME body-size limit the HTTP relay applies (the relay profile's
    // max_body_bytes: 256 KiB production / 1 MiB local-dev) on the iroh ingress, so
    // the new transport is no laxer than the HTTP `DefaultBodyLimit` (fail-closed;
    // clamped to the transport hard cap inside the handler).
    // Clone the gate for the handler (it also feeds the installed .hooks(gate)):
    // the mount keeps a clone so the reloader can swap the shared directory.
    let handler = PheromoneBatchHandler::new(gate.clone(), receiver, store, now_fn, scope_check)
        .with_max_batch_bytes(max_batch_bytes);
    let router = mount_pheromone_lane(endpoint, handler);

    let enabled_lanes = config.lanes.iter().map(|lane| lane.label()).collect();
    Ok(IrohMount {
        router,
        endpoint_id,
        bound_sockets,
        enabled_lanes,
        gate,
        transport_local_kernel_id,
    })
}

/// Bind an OUTBOUND-only iroh endpoint for the relay tick's outbound drain
/// (`drain_outbox_over_iroh`).
///
/// This is the SAME gated endpoint [`build_iroh_router`] binds (the `DirectoryGate`
/// hooks, the configured relay mode, QUIC idle timeout, and rotatable transport key),
/// but on an EPHEMERAL outbound bind (the configured `--iroh-bind-addr`'s local
/// interface with the port zeroed) rather than the stable serving bind address, and
/// WITHOUT mounting an accept handler: the tick only DIALS recipients to deliver
/// queued batches, it does not accept inbound streams, so it needs no stable inbound
/// port and must NOT contend for the port a running serve process already holds.
/// Returns
/// the bound endpoint plus the issuer-verified transport directory the recipient
/// address resolver is derived from (kernel_id -> transport `EndpointId`). Fail-closed:
/// any bind error returns `Err`.
///
/// # Reachability
///
/// The verified transport directory binds `(kernel_id -> transport EndpointId)`; it
/// does NOT carry per-peer dialable socket addresses. So the tick resolves a recipient
/// to an EndpointId and then threads any direct socket(s) from the out-of-band
/// `--iroh-peer-addr` book onto it (the direct-address deployment). Where the
/// deployment instead provides path discovery (a configured `--iroh-relay-url` plus
/// discovery, mirroring how the serve mount logs its bound socket for operators to
/// configure on peers) the id-only address resolves without a book entry. Either way,
/// a recipient with no dialable path folds into the durable retry/dead-letter path
/// fail-closed (it never drops the batch).
pub(crate) async fn build_iroh_outbound_endpoint(
    inputs: IrohServeInputs,
    relay_local_kernel_id: &str,
) -> Result<(Endpoint, Arc<VerifiedDirectory>), CliError> {
    let IrohServeInputs {
        directory,
        transport_key,
        transport_local_kernel_id,
        config,
    } = inputs;

    // Fail-closed relay/transport identity binding, mirroring the serve path in
    // [`build_iroh_router`]: the transport directory's `localKernelId` (verified at load
    // time to match the endorsed transport key) MUST equal the relay's configured local
    // identity. If they differ, this outbound tick endpoint dials as a different kernel
    // than the relay's peers expect, so deliveries are rejected/dead-lettered. Reject
    // before binding the endpoint.
    if transport_local_kernel_id != relay_local_kernel_id {
        return Err(CliError::cli_other_error(format!(
            "Chio iroh transport: the transport directory's local kernel id '{transport_local_kernel_id}' \
             does not match the relay's configured local kernel id '{relay_local_kernel_id}'; the iroh tick \
             endpoint would dial as a different kernel than the relay's peers expect"
        )));
    }

    // Only the pheromone lane is drainable here; parse_iroh_lanes already rejected
    // anything else, so this is a defense-in-depth re-check.
    if config
        .lanes
        .iter()
        .any(|lane| !matches!(lane, IrohLane::Pheromone))
    {
        return Err(CliError::cli_other_error(
            "Chio iroh transport: only the pheromone lane is drainable on the relay tick hook"
                .to_string(),
        ));
    }

    // Install the admission gate even though this endpoint only dials: it is harmless
    // for an outbound-only endpoint and keeps the identity + relay setup byte-identical
    // to the serve mount. The directory is cloned so the caller keeps it for address
    // resolution.
    let gate = DirectoryGate::new(directory.clone());
    let idle_timeout: IdleTimeout = config.max_idle_timeout.try_into().map_err(|error| {
        CliError::cli_other_error(format!("Chio iroh transport idle timeout: {error}"))
    })?;
    // Drain endpoint: one bidi stream, batch-cap-bounded window. `max_batch_bytes`
    // is not in scope on this outbound-only path, so derive the window from the
    // transport hard cap.
    let bidi_streams = VarInt::from(
        chio_federation_transport_iroh::lanes::limits::RECOMMENDED_MAX_BIDI_STREAMS,
    );
    let receive_window = VarInt::from_u64(
        chio_federation_transport_iroh::lanes::limits::recommended_receive_window_bytes(
            chio_federation_transport_iroh::lanes::pheromone::MAX_PHEROMONE_BATCH_BYTES,
        ),
    )
    .unwrap_or(VarInt::MAX);
    let transport_config = QuicTransportConfig::builder()
        .max_idle_timeout(Some(idle_timeout))
        .max_concurrent_bidi_streams(bidi_streams)
        .receive_window(receive_window)
        .build();
    // An outbound-only TICK endpoint must NOT reuse the stable serving
    // `--iroh-bind-addr`. When a durable relay-serve process is already listening on
    // that addr:port (the deployment the serve log recommends), a second (tick)
    // process that reused the exact addr:port would fail to bind the already-in-use
    // UDP port, so iroh delivery would be unusable. Keep the configured local
    // interface (IP family) but zero the port so the OS assigns a free EPHEMERAL port:
    // the tick only DIALS, so it needs no stable inbound port. This is the one place
    // the tick (outbound, ephemeral) path diverges from the serve (inbound, stable
    // addr) path [`build_iroh_router`] takes.
    let mut outbound_bind_addr = config.bind_addr;
    outbound_bind_addr.set_port(0);
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(transport_key)
        .relay_mode(config.relay_mode)
        .transport_config(transport_config)
        // Clear both default IP transports (0.0.0.0 AND [::]) before binding, so the
        // ephemeral outbound socket lives on ONLY the operator-intended address family/
        // interface and never opens an unintended IPv6 wildcard socket. Must precede
        // `bind_addr` (see the serve-path bind for the full rationale).
        .clear_ip_transports()
        .bind_addr(outbound_bind_addr)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio iroh transport bind address: {error}"))
        })?
        .hooks(gate)
        .bind()
        .await
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio iroh transport endpoint bind: {error}"))
        })?;
    Ok((endpoint, directory))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use chio_core_types::canonical_json_bytes;
    use chio_core_types::sha256_hex;
    use chio_core_types::Keypair;
    use chio_federation::pheromone_gossip::PheromoneGossipBatch;
    use chio_federation::pheromone_gossip::PHEROMONE_GOSSIP_BATCH_SCHEMA;
    use chio_federation_transport_iroh::identity::transport_endorsement_preimage;
    use chio_federation_transport_iroh::identity::TransportDirectoryBundleBody;
    use chio_federation_transport_iroh::identity::TransportDirectoryDocument;
    use chio_federation_transport_iroh::identity::TransportDirectoryEntry;
    use chio_federation_transport_iroh::identity::TRANSPORT_DIRECTORY_BUNDLE_SCHEMA;
    use chio_federation_transport_iroh::lanes::pheromone::deliver_batch_over_iroh;
    use chio_federation_transport_iroh::lanes::pheromone::MAX_PHEROMONE_BATCH_BYTES;
    use chio_pheromone_relay::PeerDirectoryDocument;
    use chio_pheromone_relay::PeerDirectoryEntry;
    use chio_pheromone_relay::PheromoneRelayError;
    use chio_pheromone_relay::RelayRole;
    use chio_pheromone_relay::PHEROMONE_PEER_DIRECTORY_SCHEMA;
    use chio_pheromone_runtime::PheromoneReceiveReport;
    use iroh::EndpointAddr;
    use std::net::Ipv4Addr;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;

    const NOW: u64 = 2_000_000;

    fn endpoint_from_seed(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    /// A verified single-entry directory admitting `kernel_id` at the transport
    /// endpoint derived from `transport_seed` (mirrors the crate fixture).
    fn verified_directory(kernel_id: &str, transport_seed: u8) -> Arc<VerifiedDirectory> {
        let passport = Keypair::from_seed(&[7u8; 32]);
        let issuer = Keypair::from_seed(&[240u8; 32]);
        let transport = endpoint_from_seed(transport_seed);
        let entry = TransportDirectoryEntry {
            kernel_id: kernel_id.to_string(),
            passport_public_key: passport.public_key(),
            transport_endpoint_id: transport,
            passport_endorsement: passport
                .sign(&transport_endorsement_preimage(kernel_id, &transport)),
            revocation_signers: Vec::new(),
            removed: false,
        };
        let directory = TransportDirectoryDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            local_kernel_id: "did:chio:relay".to_string(),
            peers: vec![entry],
            treaties: Vec::new(),
        };
        let directory_sha256 = sha256_hex(&canonical_json_bytes(&directory).unwrap());
        let body = TransportDirectoryBundleBody {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            issuer: "did:chio:issuer".to_string(),
            key_id: "issuer-key-1".to_string(),
            directory_sha256,
            version: 1,
            previous_version_sha256: None,
            issued_at_unix_ms: NOW - 1,
            expires_at_unix_ms: NOW + 1,
        };
        let (signature, _) = issuer.sign_canonical(&body).unwrap();
        let bundle = TransportDirectoryBundleDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            body,
            directory,
            signature,
        };
        let trust = TransportDirectoryBundleTrust {
            issuers: vec![TrustedTransportDirectoryIssuer {
                issuer: "did:chio:issuer".to_string(),
                key_id: "issuer-key-1".to_string(),
                public_key: issuer.public_key(),
            }],
            version_floor: 0,
            expected_previous_version_sha256: None,
            now_unix_ms: NOW,
        };
        Arc::new(bundle.verify_bundle(&trust).expect("fixture bundle verifies"))
    }

    /// A receiver double: the loopback 403 test never reaches it (the gate rejects
    /// the unbound dialer at handshake), so it fails closed if ever invoked.
    #[derive(Debug)]
    struct RejectingReceiver;

    #[async_trait::async_trait]
    impl RelayBatchReceiver for RejectingReceiver {
        async fn receive_batch(
            &self,
            _batch: PheromoneGossipBatch,
            _authenticated_sender_kernel_id: String,
            _received_at_unix_ms: u64,
        ) -> Result<PheromoneReceiveReport, PheromoneRelayError> {
            Err(PheromoneRelayError::Json("test receiver never accepts".to_string()))
        }
    }

    /// A receiver double that records whether it was ever consulted, so the
    /// out-of-scope test can PROVE the inbound scope gate short-circuits BEFORE
    /// `receive_batch` (an out-of-scope sender must never reach the receiver).
    #[derive(Debug)]
    struct TripwireReceiver {
        called: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl RelayBatchReceiver for TripwireReceiver {
        async fn receive_batch(
            &self,
            _batch: PheromoneGossipBatch,
            _authenticated_sender_kernel_id: String,
            _received_at_unix_ms: u64,
        ) -> Result<PheromoneReceiveReport, PheromoneRelayError> {
            self.called.store(true, Ordering::SeqCst);
            Err(PheromoneRelayError::Json(
                "receiver must not be reached for an out-of-scope sender".to_string(),
            ))
        }
    }

    /// A minimal issuer-independent peer directory admitting `kernel_id` with the
    /// given `relay_role` (the field `enforce_peer_batch_directory_scope` gates the
    /// inbound submit authorization on). Subscribed to `treaty:test` so an Origin/Hub
    /// entry passes the treaty check too.
    fn peer_directory_admitting(kernel_id: &str, role: RelayRole) -> PeerDirectory {
        let passport = Keypair::from_seed(&[7u8; 32]);
        let document = PeerDirectoryDocument {
            schema: PHEROMONE_PEER_DIRECTORY_SCHEMA.to_string(),
            local_kernel_id: "did:chio:relay".to_string(),
            issued_at_unix_ms: NOW - 1,
            expires_at_unix_ms: NOW + 1,
            peers: vec![PeerDirectoryEntry {
                kernel_id: kernel_id.to_string(),
                public_key: passport.public_key(),
                endpoint: "https://peer.example/relay".to_string(),
                treaty_subscriptions: vec!["treaty:test".to_string()],
                relay_role: role,
                allowed_subject_class_namespaces: Vec::new(),
                accepted_ladder_refs: Vec::new(),
                max_batch_frames: 128,
                max_catchup_frames: 128,
                max_catchup_bytes: 1_048_576,
            }],
        };
        PeerDirectory::from_document(document, NOW).expect("peer directory builds")
    }

    fn loopback_config(lanes: Vec<IrohLane>) -> IrohMountConfig {
        IrohMountConfig {
            relay_mode: RelayMode::Disabled,
            bind_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            lanes,
            max_idle_timeout: RECOMMENDED_MAX_IDLE_TIMEOUT,
        }
    }

    fn empty_batch() -> PheromoneGossipBatch {
        PheromoneGossipBatch {
            schema: PHEROMONE_GOSSIP_BATCH_SCHEMA.to_string(),
            recipient_kernel_id: "did:chio:relay".to_string(),
            treaty_id: "treaty:test".to_string(),
            frames: Vec::new(),
            flushed_at_unix_ms: NOW,
        }
    }

    #[test]
    fn disabled_loads_no_inputs_and_touches_nothing() {
        // The opt-in-default-off guarantee: with iroh disabled, load returns None
        // before any file access (the bogus paths are never read) and constructs
        // nothing, so the serve path is byte-for-byte unchanged.
        let inputs = load_iroh_serve_inputs(
            false,
            Some(Path::new("/nonexistent/directory.json")),
            None,
            Some(Path::new("/nonexistent/issuers.json")),
            Some(Path::new("/nonexistent/key.json")),
            "0.0.0.0:0",
            &[],
            "pheromone",
            NOW,
        )
        .expect("disabled load never errors");
        assert!(inputs.is_none(), "disabled iroh must construct nothing");
    }

    #[test]
    fn enable_without_transport_directory_fails_closed() {
        let error = match load_iroh_serve_inputs(
            true,
            None,
            None,
            Some(Path::new("/nonexistent/issuers.json")),
            Some(Path::new("/nonexistent/key.json")),
            "0.0.0.0:0",
            &[],
            "pheromone",
            NOW,
        ) {
            Ok(_) => panic!("missing transport directory must fail closed"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("iroh-transport-directory"));
    }

    #[test]
    fn invalid_transport_directory_bundle_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.json");
        let issuers_path = dir.path().join("issuers.json");
        let key_path = dir.path().join("key.json");

        // A bundle that is not even the right schema: verification must reject it.
        std::fs::write(&bundle_path, "{\"schema\":\"totally.wrong\"}").unwrap();
        let issuer = Keypair::from_seed(&[240u8; 32]);
        let issuers = serde_json::json!({
            "issuers": [{
                "issuer": "did:chio:issuer",
                "keyId": "issuer-key-1",
                "publicKey": issuer.public_key(),
            }],
        });
        std::fs::write(&issuers_path, serde_json::to_string(&issuers).unwrap()).unwrap();
        std::fs::write(&key_path, "{\"seedHex\":\"".to_string() + &"11".repeat(32) + "\"}").unwrap();

        let error = match load_iroh_serve_inputs(
            true,
            Some(&bundle_path),
            None,
            Some(&issuers_path),
            Some(&key_path),
            "0.0.0.0:0",
            &[],
            "pheromone",
            NOW,
        ) {
            Ok(_) => panic!("an invalid/tampered directory bundle must fail closed"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("directory bundle"),
            "unexpected error: {error}"
        );
    }

    /// The local kernel id (`localKernelId`) the signed-bundle fixtures own; the
    /// local-transport-key binding check resolves THIS id.
    const LOCAL_KERNEL_ID: &str = "did:chio:relay";
    /// The transport seed the fixtures endorse for [`LOCAL_KERNEL_ID`]. Its
    /// `EndpointId` MUST equal the public of the seed the test key files carry
    /// (`0x11` bytes, i.e. `"11".repeat(32)`), so a matching key passes the check.
    const LOCAL_TRANSPORT_SEED: u8 = 0x11;

    /// The seedHex the test transport-key files carry, matching `transport_seed`.
    /// A file carrying this seed loads to a `SecretKey` whose public is
    /// `endpoint_from_seed(transport_seed)`.
    fn transport_key_json(transport_seed: u8) -> String {
        let seed_hex = hex::encode([transport_seed; 32]);
        format!("{{\"seedHex\":\"{seed_hex}\"}}")
    }

    /// A well-formed, non-removed directory entry binding `kernel_id` to the
    /// transport `EndpointId` derived from `transport_seed`, self-endorsed by a
    /// per-kernel passport.
    fn directory_entry(
        kernel_id: &str,
        passport_seed: u8,
        transport_seed: u8,
    ) -> TransportDirectoryEntry {
        let passport = Keypair::from_seed(&[passport_seed; 32]);
        let transport = endpoint_from_seed(transport_seed);
        TransportDirectoryEntry {
            kernel_id: kernel_id.to_string(),
            passport_public_key: passport.public_key(),
            transport_endpoint_id: transport,
            passport_endorsement: passport
                .sign(&transport_endorsement_preimage(kernel_id, &transport)),
            revocation_signers: Vec::new(),
            removed: false,
        }
    }

    /// The local relay's OWN transport binding (`LOCAL_KERNEL_ID -> transport seed`).
    /// The local-transport-key binding check verifies the loaded `--iroh-transport-key`
    /// against exactly this entry's `EndpointId`.
    fn local_relay_entry(transport_seed: u8) -> TransportDirectoryEntry {
        directory_entry(LOCAL_KERNEL_ID, 8, transport_seed)
    }

    /// Build and serialize a signed transport-directory bundle over `peers` at
    /// `version`, chaining onto `previous_version_sha256`. Returns the bundle JSON
    /// plus the issuer keypair whose public key the trusted-issuers file must pin.
    fn build_signed_bundle_json(
        peers: Vec<TransportDirectoryEntry>,
        version: u64,
        previous_version_sha256: Option<String>,
    ) -> (String, Keypair) {
        let issuer = Keypair::from_seed(&[240u8; 32]);
        let directory = TransportDirectoryDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
            peers,
            treaties: Vec::new(),
        };
        let directory_sha256 = sha256_hex(&canonical_json_bytes(&directory).unwrap());
        let body = TransportDirectoryBundleBody {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            issuer: "did:chio:issuer".to_string(),
            key_id: "issuer-key-1".to_string(),
            directory_sha256,
            version,
            previous_version_sha256,
            issued_at_unix_ms: NOW - 1,
            expires_at_unix_ms: NOW + 1,
        };
        let (signature, _) = issuer.sign_canonical(&body).unwrap();
        let bundle = TransportDirectoryBundleDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            body,
            directory,
            signature,
        };
        (serde_json::to_string(&bundle).unwrap(), issuer)
    }

    /// Build a signed bundle whose directory carries BOTH the local relay's own
    /// binding (`LOCAL_KERNEL_ID` at [`LOCAL_TRANSPORT_SEED`], so the default test
    /// key file matches) AND a peer `kernel_id` at `transport_seed`. This keeps the
    /// local-transport-key binding check satisfied by default.
    fn signed_bundle_json(
        kernel_id: &str,
        transport_seed: u8,
        version: u64,
        previous_version_sha256: Option<String>,
    ) -> (String, Keypair) {
        build_signed_bundle_json(
            vec![
                local_relay_entry(LOCAL_TRANSPORT_SEED),
                directory_entry(kernel_id, 7, transport_seed),
            ],
            version,
            previous_version_sha256,
        )
    }

    /// Build a signed successor whose directory DECLARES `local_kernel_id` as its owner
    /// while STILL binding the local relay's own transport endpoint. Used to prove the
    /// reloader rejects a successor that reassigns this node's declared local identity even
    /// though the endpoint binding survives (the startup path would reject the same bundle).
    fn signed_bundle_with_local_kernel_id(
        local_kernel_id: &str,
        version: u64,
        previous_version_sha256: Option<String>,
    ) -> String {
        let issuer = Keypair::from_seed(&[240u8; 32]);
        let directory = TransportDirectoryDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            local_kernel_id: local_kernel_id.to_string(),
            peers: vec![
                local_relay_entry(LOCAL_TRANSPORT_SEED),
                directory_entry("did:chio:bob", 7, 24),
            ],
            treaties: Vec::new(),
        };
        let directory_sha256 = sha256_hex(&canonical_json_bytes(&directory).unwrap());
        let body = TransportDirectoryBundleBody {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            issuer: "did:chio:issuer".to_string(),
            key_id: "issuer-key-1".to_string(),
            directory_sha256,
            version,
            previous_version_sha256,
            issued_at_unix_ms: NOW - 1,
            expires_at_unix_ms: NOW + 1,
        };
        let (signature, _) = issuer.sign_canonical(&body).unwrap();
        let bundle = TransportDirectoryBundleDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            body,
            directory,
            signature,
        };
        serde_json::to_string(&bundle).unwrap()
    }

    /// Overwrite the trusted-issuers file at `path` to pin a SINGLE issuer identity/key
    /// that is NOT the one the test bundles are signed with (issuer seed 240,
    /// `did:chio:issuer#issuer-key-1`), modeling operators rotating the signing issuer out
    /// of the trust set on a running relay.
    fn write_rotated_trusted_issuers(path: &std::path::Path) {
        let other_issuer = Keypair::from_seed(&[241u8; 32]);
        let issuers = serde_json::json!({
            "issuers": [{
                "issuer": "did:chio:issuer-2",
                "keyId": "issuer-key-2",
                "publicKey": other_issuer.public_key(),
            }],
        });
        std::fs::write(path, serde_json::to_string(&issuers).unwrap()).unwrap();
    }

    /// Write a signed, verifiable transport-directory bundle (peer did:chio:bob at
    /// transport seed 24, optionally tombstoned) plus its trusted-issuers file to
    /// `dir`. Returns (bundle_path, issuers_path, expires_at, body_sha256). The body
    /// hash is the full-document canonical sha256 the gate reports, so a successor
    /// can chain onto it. Bundles carry expires_at = NOW + 1.
    fn write_test_bundle(
        dir: &std::path::Path,
        version: u64,
        removed: bool,
        previous_version_sha256: Option<String>,
    ) -> (PathBuf, PathBuf, u64, String) {
        let issuer = Keypair::from_seed(&[240u8; 32]);
        let mut peer = directory_entry("did:chio:bob", 7, 24);
        peer.removed = removed;
        let directory = TransportDirectoryDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
            peers: vec![local_relay_entry(LOCAL_TRANSPORT_SEED), peer],
            treaties: Vec::new(),
        };
        let directory_sha256 = sha256_hex(&canonical_json_bytes(&directory).unwrap());
        let expires_at = NOW + 1;
        let body = TransportDirectoryBundleBody {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            issuer: "did:chio:issuer".to_string(),
            key_id: "issuer-key-1".to_string(),
            directory_sha256,
            version,
            previous_version_sha256,
            issued_at_unix_ms: NOW - 1,
            expires_at_unix_ms: expires_at,
        };
        let (signature, _) = issuer.sign_canonical(&body).unwrap();
        let bundle = TransportDirectoryBundleDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            body,
            directory,
            signature,
        };
        let body_hash = sha256_hex(&canonical_json_bytes(&bundle).unwrap());
        let bundle_path = dir.join(format!("bundle-{version}.json"));
        std::fs::write(&bundle_path, serde_json::to_string(&bundle).unwrap()).unwrap();
        let issuers_path = dir.join("issuers.json");
        let issuers = serde_json::json!({
            "issuers": [{
                "issuer": "did:chio:issuer",
                "keyId": "issuer-key-1",
                "publicKey": issuer.public_key(),
            }],
        });
        std::fs::write(&issuers_path, serde_json::to_string(&issuers).unwrap()).unwrap();
        (bundle_path, issuers_path, expires_at, body_hash)
    }

    #[test]
    fn reload_expiry_is_checked_before_the_unchanged_fast_path() {
        let dir = tempfile::tempdir().unwrap();
        let (bundle_path, issuers_path, expires_at, body_hash) =
            write_test_bundle(dir.path(), 1, false, None);
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path,
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };

        // In-window, same version on disk => Unchanged (the fast path fires).
        let now_in_window = expires_at - 1;
        assert!(matches!(
            reload_verified_directory(&config, now_in_window, 1, expires_at, &body_hash)
                .expect("reload runs"),
            ReloadOutcome::Unchanged
        ));

        // Same (unchanged) version on disk but now PAST expiry must NOT short-circuit
        // to Unchanged; with no strictly-newer in-window successor it fails closed as
        // ExpiredWhileRunning.
        let now_expired = expires_at + 1;
        assert!(matches!(
            reload_verified_directory(&config, now_expired, 1, expires_at, &body_hash)
                .expect("reload runs"),
            ReloadOutcome::ExpiredWhileRunning
        ));
    }

    #[test]
    fn reload_rejects_unchanged_bundle_when_signing_issuer_leaves_trust_roots() {
        let dir = tempfile::tempdir().unwrap();
        let (bundle_path, issuers_path, expires_at, body_hash) =
            write_test_bundle(dir.path(), 1, false, None);
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path,
            trusted_issuers_path: issuers_path.clone(),
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };
        let now_in_window = expires_at - 1;

        // Baseline: while the signing issuer is still trusted, the unchanged in-window
        // bundle takes the fast path.
        assert!(matches!(
            reload_verified_directory(&config, now_in_window, 1, expires_at, &body_hash)
                .expect("reload runs"),
            ReloadOutcome::Unchanged
        ));

        // Rotate the trust set so the bundle's signing issuer is no longer pinned. The
        // on-disk bundle is byte-unchanged, but a restart would now reject it (unknown
        // issuer); the unchanged fast path must fail closed identically rather than keep
        // admitting under a signer the federation no longer trusts.
        write_rotated_trusted_issuers(&issuers_path);
        let outcome = reload_verified_directory(&config, now_in_window, 1, expires_at, &body_hash)
            .expect("reload runs");
        assert!(
            matches!(outcome, ReloadOutcome::TrustRootsChanged),
            "an unchanged bundle whose signing issuer left the trust roots must fail closed, \
             got {outcome:?}"
        );
    }

    #[test]
    fn reload_fails_closed_when_trusted_issuers_becomes_empty() {
        // Removing every trusted issuer on a running relay must trust no signer and admit
        // nothing, in lockstep with startup rejecting the same empty configuration. It must
        // NOT fold into the transient keep-last-good read-error path, which would keep the
        // previous signer active until expiry.
        let dir = tempfile::tempdir().unwrap();
        let (bundle_path, issuers_path, expires_at, body_hash) =
            write_test_bundle(dir.path(), 1, false, None);
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path,
            trusted_issuers_path: issuers_path.clone(),
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };
        let now_in_window = expires_at - 1;

        // Baseline: with the issuer still pinned, the unchanged in-window bundle is Unchanged.
        assert!(matches!(
            reload_verified_directory(&config, now_in_window, 1, expires_at, &body_hash)
                .expect("reload runs"),
            ReloadOutcome::Unchanged
        ));

        // Empty the trusted-issuer set while the on-disk bundle stays byte-unchanged.
        std::fs::write(&issuers_path, r#"{"issuers":[]}"#).unwrap();
        let outcome =
            reload_verified_directory(&config, now_in_window, 1, expires_at, &body_hash)
                .expect("reload runs");
        assert!(
            matches!(outcome, ReloadOutcome::TrustRootsEmpty),
            "an empty trusted-issuer set must fail closed, got {outcome:?}"
        );

        // Step-level: the gate flips to deny-all, the alarm is raised, and last-good is
        // preserved so a successor under a restored issuer can self-heal.
        let gate = DirectoryGate::new(verified_directory("did:chio:bob", 24));
        assert_eq!(gate.current_version(), 1);
        let alive = AtomicBool::new(true);
        let mut state = ReloadState {
            version: 1,
            body_sha256: body_hash.clone(),
            expires_at_unix_ms: expires_at,
        };
        directory_reload_step(&gate, &config, now_in_window, &mut state, &alive);
        assert_eq!(
            gate.current_version(),
            0,
            "an empty issuer set fails closed to deny-all"
        );
        assert!(
            !alive.load(Ordering::SeqCst),
            "an empty issuer set raises the fail-closed alarm"
        );
        assert_eq!(
            state.version, 1,
            "last-good is preserved so a restored issuer can self-heal"
        );
    }

    #[test]
    fn reload_denies_same_version_bundle_whose_body_was_replaced() {
        // A same-version bundle whose canonical body differs from the loaded one (the file
        // was replaced without a version bump) must fail closed, not take the unchanged fast
        // path. Reporting it Unchanged would keep the loaded directory admitting peers the
        // replacement dropped. Here v1 is overwritten in place by a different v1 that
        // tombstones the peer, still signed by the trusted issuer so it verifies but hashes
        // differently.
        let dir = tempfile::tempdir().unwrap();
        let (_original_path, _original_issuers, expires_at, loaded_hash) =
            write_test_bundle(dir.path(), 1, false, None);
        // Overwrite bundle-1.json in place with a different v1 (peer tombstoned).
        let (bundle_path, issuers_path, _expires, replaced_hash) =
            write_test_bundle(dir.path(), 1, true, None);
        assert_ne!(
            loaded_hash, replaced_hash,
            "the replacement body must differ so the hash gate can catch it"
        );
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path,
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };
        let now_in_window = expires_at - 1;

        // Outcome-level: the loaded directory is the ORIGINAL v1 (loaded_hash); the on-disk
        // file is now a different v1, so the fast path fails closed rather than Unchanged.
        let outcome =
            reload_verified_directory(&config, now_in_window, 1, expires_at, &loaded_hash)
                .expect("reload runs");
        assert!(
            matches!(outcome, ReloadOutcome::CurrentBodyReplaced),
            "a same-version bundle whose body was replaced must fail closed, got {outcome:?}"
        );

        // Step-level: the gate flips to deny-all, the alarm is raised, and last-good is
        // preserved so a properly versioned successor can self-heal.
        let gate = DirectoryGate::new(verified_directory("did:chio:bob", 24));
        assert_eq!(gate.current_version(), 1);
        let alive = AtomicBool::new(true);
        let mut state = ReloadState {
            version: 1,
            body_sha256: loaded_hash.clone(),
            expires_at_unix_ms: expires_at,
        };
        directory_reload_step(&gate, &config, now_in_window, &mut state, &alive);
        assert_eq!(
            gate.current_version(),
            0,
            "a replaced same-version body fails closed to deny-all"
        );
        assert!(
            !alive.load(Ordering::SeqCst),
            "a replaced same-version body raises the fail-closed alarm"
        );
        assert_eq!(
            state.version, 1,
            "last-good is preserved so a properly versioned successor can self-heal"
        );
    }

    #[test]
    fn reload_rejects_successor_that_reassigns_local_kernel_id() {
        let dir = tempfile::tempdir().unwrap();
        let (bundle_path, issuers_path, expires_at, genesis_hash) =
            write_test_bundle(dir.path(), 1, false, None);
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path: bundle_path.clone(),
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };

        // A strictly-newer, validly-signed, in-window successor that STILL binds this node's
        // transport endpoint but DECLARES a different local kernel as the directory owner.
        // The startup path (`build_iroh_router`) rejects such a bundle because its declared
        // local kernel id no longer matches the relay's, so the live reloader must fail closed
        // to deny-all rather than swap it in under a changed identity binding.
        let successor =
            signed_bundle_with_local_kernel_id("did:chio:usurper", 2, Some(genesis_hash.clone()));
        std::fs::write(&bundle_path, successor).unwrap();

        let now_in_window = expires_at - 1;
        let outcome = reload_verified_directory(&config, now_in_window, 1, expires_at, &genesis_hash)
            .expect("reload runs");
        assert!(
            matches!(outcome, ReloadOutcome::LocalBindingRevoked(_)),
            "a successor reassigning this node's declared local kernel id must fail closed, \
             got {outcome:?}"
        );
    }

    #[test]
    fn directory_reload_swaps_in_successor_and_evicts_tombstoned_peer() {
        let dir = tempfile::tempdir().unwrap();
        // Genesis version 1 (peer live); its full-document hash is the chain pin.
        let (_v1_path, _v1_issuers, _v1_expires, v1_hash) =
            write_test_bundle(dir.path(), 1, false, None);
        // Version 2 on disk tombstones the peer, chaining onto v1's hash.
        let (bundle_path, issuers_path, expires_at, _v2_hash) =
            write_test_bundle(dir.path(), 2, true, Some(v1_hash.clone()));
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path,
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };

        let now_in_window = expires_at - 1;
        let outcome = reload_verified_directory(&config, now_in_window, 1, expires_at, &v1_hash)
            .expect("reload runs");
        let verified = match outcome {
            ReloadOutcome::Updated(verified) => verified,
            _ => panic!("expected Updated for a strictly-newer in-window successor"),
        };
        // Apply it through the gate and assert the tombstoned peer no longer admits.
        let gate = DirectoryGate::new(std::sync::Arc::new(verified));
        assert_eq!(gate.current_version(), 2);
        assert_eq!(gate.resolve(&endpoint_from_seed(24)), None);
    }

    /// Write a signed successor bundle (version `version`, chaining onto
    /// `previous_version_sha256`) that binds the LOCAL node at `local_transport_seed`
    /// (pass a seed != [`LOCAL_TRANSPORT_SEED`] to ROTATE this node's binding, so the
    /// successor no longer endorses the currently-bound endpoint). The peer entry is
    /// left live. Returns (bundle_path, issuers_path, expires_at).
    fn write_local_rotated_bundle(
        dir: &std::path::Path,
        version: u64,
        local_transport_seed: u8,
        previous_version_sha256: Option<String>,
    ) -> (PathBuf, PathBuf, u64) {
        let issuer = Keypair::from_seed(&[240u8; 32]);
        let directory = TransportDirectoryDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
            peers: vec![
                local_relay_entry(local_transport_seed),
                directory_entry("did:chio:bob", 7, 24),
            ],
            treaties: Vec::new(),
        };
        let directory_sha256 = sha256_hex(&canonical_json_bytes(&directory).unwrap());
        let expires_at = NOW + 1;
        let body = TransportDirectoryBundleBody {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            issuer: "did:chio:issuer".to_string(),
            key_id: "issuer-key-1".to_string(),
            directory_sha256,
            version,
            previous_version_sha256,
            issued_at_unix_ms: NOW - 1,
            expires_at_unix_ms: expires_at,
        };
        let (signature, _) = issuer.sign_canonical(&body).unwrap();
        let bundle = TransportDirectoryBundleDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            body,
            directory,
            signature,
        };
        let bundle_path = dir.join(format!("bundle-{version}.json"));
        std::fs::write(&bundle_path, serde_json::to_string(&bundle).unwrap()).unwrap();
        let issuers_path = dir.join("issuers.json");
        let issuers = serde_json::json!({
            "issuers": [{
                "issuer": "did:chio:issuer",
                "keyId": "issuer-key-1",
                "publicKey": issuer.public_key(),
            }],
        });
        std::fs::write(&issuers_path, serde_json::to_string(&issuers).unwrap()).unwrap();
        (bundle_path, issuers_path, expires_at)
    }

    #[test]
    fn directory_reload_fails_closed_when_successor_rotates_local_binding() {
        // Local-binding recheck (SECURITY). A strictly-newer, in-window, validly-signed
        // successor that ROTATES this node's local transport endpoint (or tombstones it)
        // no longer endorses the endpoint this node is bound to. Swapping it in would
        // leave the already-bound endpoint serving iroh ingress under the old key for
        // peers admitted in the new directory. The reloader must fail closed to
        // LocalBindingRevoked (deny-all), never Updated.
        //
        // The successor rotates the LOCAL entry from LOCAL_TRANSPORT_SEED (0x11) to a
        // DIFFERENT seed (0x22); the reloader's config pins the currently-bound endpoint
        // (endpoint_from_seed(LOCAL_TRANSPORT_SEED)). Without the recheck the successor
        // verifies and returns Updated, admitting under a revoked local identity; the
        // recheck instead denies the bound endpoint and returns LocalBindingRevoked.
        let dir = tempfile::tempdir().unwrap();
        let (_v1_path, _v1_issuers, _v1_expires, v1_hash) =
            write_test_bundle(dir.path(), 1, false, None);
        // Version 2 rotates the LOCAL node's transport endpoint to seed 0x22, chaining
        // onto v1's hash. The peer stays live, so only the local binding changed.
        let (bundle_path, issuers_path, expires_at) =
            write_local_rotated_bundle(dir.path(), 2, 0x22, Some(v1_hash.clone()));
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path,
            trusted_issuers_path: issuers_path,
            // The endpoint this node is actually bound to (the OLD seed 0x11), which the
            // rotated successor no longer endorses.
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };

        let now_in_window = expires_at - 1;
        let outcome = reload_verified_directory(&config, now_in_window, 1, expires_at, &v1_hash)
            .expect("reload runs");
        assert!(
            matches!(outcome, ReloadOutcome::LocalBindingRevoked(_)),
            "a successor that no longer binds this node's local endpoint fails closed, never Updated"
        );
    }

    /// Write a signed successor whose directory ROTATES the local node to
    /// `local_transport_seed` AND REASSIGNS a peer (`did:chio:bob`) to
    /// `peer_transport_seed`. Passing `peer_transport_seed == LOCAL_TRANSPORT_SEED` hands
    /// this node's currently-bound endpoint to a DIFFERENT kernel id, the exact case a
    /// bare `authorize(endpoint).is_some()` recheck would wrongly admit. Returns
    /// (bundle_path, issuers_path, expires_at).
    fn write_local_reassigned_bundle(
        dir: &std::path::Path,
        version: u64,
        local_transport_seed: u8,
        peer_transport_seed: u8,
        previous_version_sha256: Option<String>,
    ) -> (PathBuf, PathBuf, u64) {
        let (bundle_json, issuer) = build_signed_bundle_json(
            vec![
                directory_entry(LOCAL_KERNEL_ID, 8, local_transport_seed),
                directory_entry("did:chio:bob", 7, peer_transport_seed),
            ],
            version,
            previous_version_sha256,
        );
        let bundle_path = dir.join(format!("bundle-{version}.json"));
        std::fs::write(&bundle_path, &bundle_json).unwrap();
        let issuers_path = dir.join("issuers.json");
        let issuers = serde_json::json!({
            "issuers": [{
                "issuer": "did:chio:issuer",
                "keyId": "issuer-key-1",
                "publicKey": issuer.public_key(),
            }],
        });
        std::fs::write(&issuers_path, serde_json::to_string(&issuers).unwrap()).unwrap();
        (bundle_path, issuers_path, NOW + 1)
    }

    #[test]
    fn directory_reload_fails_closed_when_successor_reassigns_bound_endpoint() {
        // Local-binding recheck (SECURITY, deeper than the rotation case). A
        // strictly-newer, in-window, validly-signed successor that REASSIGNS this node's
        // bound transport endpoint to a DIFFERENT kernel id still `authorize`s the endpoint
        // (it resolves to the OTHER kernel), so a recheck that only asks "does the endpoint
        // resolve to some kernel?" would wrongly swap it in - leaving the relay serving iroh
        // ingress under the OLD secret for an identity the successor now assigns elsewhere.
        // The recheck must mirror STARTUP: require the successor to bind THIS kernel id to
        // THIS endpoint.
        //
        // v2 rotates the LOCAL node to seed 0x22 AND reassigns the peer to
        // LOCAL_TRANSPORT_SEED (0x11 = this node's bound endpoint). An
        // `authorize(endpoint).is_none()` recheck would see authorize(0x11) == Some(bob)
        // (not None) and swap it in, admitting under a reassigned local endpoint. The
        // `resolve_transport_endpoint(local_kernel_id) == endpoint` recheck instead
        // resolves LOCAL_KERNEL_ID to 0x22 != 0x11 and returns LocalBindingRevoked.
        let dir = tempfile::tempdir().unwrap();
        let (_v1_path, _v1_issuers, _v1_expires, v1_hash) =
            write_test_bundle(dir.path(), 1, false, None);
        let (bundle_path, issuers_path, expires_at) = write_local_reassigned_bundle(
            dir.path(),
            2,
            0x22,
            LOCAL_TRANSPORT_SEED,
            Some(v1_hash.clone()),
        );
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path,
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };
        let now_in_window = expires_at - 1;
        let outcome = reload_verified_directory(&config, now_in_window, 1, expires_at, &v1_hash)
            .expect("reload runs");
        assert!(
            matches!(outcome, ReloadOutcome::LocalBindingRevoked(_)),
            "a successor that reassigns this node's bound endpoint to another kernel fails closed"
        );
    }

    /// Write a trusted-issuers file at `dir/issuers.json` pinning `min_version`
    /// (camelCase on the wire) with the standard issuer key. Returns its path.
    fn write_issuers_with_min_version(dir: &std::path::Path, min_version: u64) -> PathBuf {
        let issuer = Keypair::from_seed(&[240u8; 32]);
        let issuers_path = dir.join("issuers.json");
        let issuers = serde_json::json!({
            "issuers": [{
                "issuer": "did:chio:issuer",
                "keyId": "issuer-key-1",
                "publicKey": issuer.public_key(),
            }],
            "minVersion": min_version,
        });
        std::fs::write(&issuers_path, serde_json::to_string(&issuers).unwrap()).unwrap();
        issuers_path
    }

    #[test]
    fn directory_reload_denies_newer_successor_below_raised_min_version() {
        // A staged successor that is NEWER than the running directory but STILL BELOW a
        // minVersion operators raised above it must fail closed to deny-all, exactly as
        // the unchanged path and a restart would. It must NOT surface as a transient verify
        // error that keeps the stale, now below-floor directory admitting until expiry. The
        // successor is still verified and CAPTURED so the last-good chain advances onto it,
        // letting a later at-or-above-floor bundle (which chains onto this successor)
        // self-heal.
        let dir = tempfile::tempdir().unwrap();
        let (_v1_path, _v1_issuers, _v1_expires, v1_hash) =
            write_test_bundle(dir.path(), 1, false, None);
        let (bundle_path, _v2_issuers, expires_at, v2_hash) =
            write_test_bundle(dir.path(), 2, false, Some(v1_hash.clone()));
        // Pin minVersion = 10 AFTER the bundles are written; the on-disk successor (v2) is
        // newer than the running v1 but still below the floor.
        let issuers_path = write_issuers_with_min_version(dir.path(), 10);
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path,
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };
        let now_in_window = expires_at - 1;

        // Outcome-level: the newer-but-still-below-floor successor fails closed and is
        // captured for chain advancement rather than returning a transient verify error.
        let outcome = reload_verified_directory(&config, now_in_window, 1, expires_at, &v1_hash)
            .expect("reload runs");
        assert!(
            matches!(outcome, ReloadOutcome::BelowMinVersionFloor(Some(_))),
            "a newer successor below the raised minVersion must fail closed, got {outcome:?}"
        );

        // Step-level: the gate flips to deny-all, the alarm is raised, and the chain advances
        // onto the below-floor successor so a later at-or-above-floor bundle can self-heal.
        let gate = DirectoryGate::new(verified_directory("did:chio:bob", 24));
        assert_eq!(gate.current_version(), 1);
        let alive = AtomicBool::new(true);
        let mut state = ReloadState {
            version: 1,
            body_sha256: v1_hash.clone(),
            expires_at_unix_ms: expires_at,
        };
        directory_reload_step(&gate, &config, now_in_window, &mut state, &alive);
        assert_eq!(
            gate.current_version(),
            0,
            "a newer-but-below-floor successor fails closed to deny-all"
        );
        assert!(
            !alive.load(Ordering::SeqCst),
            "a below-min-version successor raises the fail-closed alarm"
        );
        assert_eq!(
            state.version, 2,
            "the chain advances onto the below-floor successor so a later bundle can chain on"
        );
        assert_eq!(
            state.body_sha256, v2_hash,
            "the chain pin advances to the below-floor successor's hash"
        );
    }

    #[test]
    fn directory_reload_denies_unchanged_directory_below_raised_min_version() {
        // Raising minVersion above the running version must fail the running directory
        // closed on the next reload even when the on-disk bundle is unchanged (same
        // version): the unchanged fast path must not short-circuit to Unchanged before
        // honoring the minVersion floor a restart would enforce via transport_bundle_trust.
        // A version-1 directory whose issuers now pin minVersion 5 is below the floor, so
        // the reload fails closed to BelowMinVersionFloor and the gate flips to deny-all.
        let dir = tempfile::tempdir().unwrap();
        let (bundle_path, _issuers, expires_at, body_hash) =
            write_test_bundle(dir.path(), 1, false, None);
        // Raise minVersion to 5 while the running (and on-disk) version stays 1.
        let issuers_path = write_issuers_with_min_version(dir.path(), 5);
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path,
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };
        let now_in_window = expires_at - 1;

        // Outcome-level: the unchanged (v1 == on-disk) directory below the raised floor
        // fails closed rather than short-circuiting to Unchanged.
        let outcome = reload_verified_directory(&config, now_in_window, 1, expires_at, &body_hash)
            .expect("reload runs");
        assert!(
            matches!(outcome, ReloadOutcome::BelowMinVersionFloor(None)),
            "an unchanged directory below a raised minVersion must fail closed, not Unchanged"
        );

        // Step-level: the gate flips to deny-all, the alarm is raised, and last-good is
        // preserved so a successor at or above the floor can self-heal.
        let gate = DirectoryGate::new(verified_directory("did:chio:bob", 24));
        assert_eq!(gate.current_version(), 1);
        let alive = AtomicBool::new(true);
        let mut state = ReloadState {
            version: 1,
            body_sha256: body_hash.clone(),
            expires_at_unix_ms: expires_at,
        };
        directory_reload_step(&gate, &config, now_in_window, &mut state, &alive);
        assert_eq!(
            gate.current_version(),
            0,
            "a below-min-version directory fails closed to deny-all"
        );
        assert!(
            !alive.load(Ordering::SeqCst),
            "a below-min-version directory raises the fail-closed alarm"
        );
        assert_eq!(
            state.version, 1,
            "last-good is preserved so a successor at/above the floor can self-heal"
        );
    }

    #[test]
    fn directory_reload_self_heals_across_below_floor_successors() {
        // When operators raise minVersion above an intermediate successor, that successor is
        // denied admission but its hash must still advance the chain, so a later
        // at-or-above-floor bundle - which chains onto it - self-heals instead of being
        // stranded in deny-all against a dropped chain. minVersion is 3 here: v2 is below the
        // floor (deny-all, chain advances to v2), then v3 at the floor chains onto v2 and
        // restores admission without a restart.
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.json");
        let issuers_path = write_issuers_with_min_version(dir.path(), 3);
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path: bundle_path.clone(),
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };

        // v1 binds this node; the reloader's last-good starts here.
        let v1_hash = write_local_binding_bundle_at(&bundle_path, 1, LOCAL_TRANSPORT_SEED, None);
        let gate = DirectoryGate::new(verified_directory("did:chio:bob", 24));
        assert_eq!(gate.current_version(), 1);
        let alive = AtomicBool::new(true);
        let mut state = ReloadState {
            version: 1,
            body_sha256: v1_hash.clone(),
            expires_at_unix_ms: NOW + 1,
        };

        // v2 is a valid successor (chains onto v1) but below the raised floor: deny-all, and
        // the chain advances onto v2 so v3 can chain onto it.
        let v2_hash =
            write_local_binding_bundle_at(&bundle_path, 2, LOCAL_TRANSPORT_SEED, Some(v1_hash));
        directory_reload_step(&gate, &config, NOW, &mut state, &alive);
        assert_eq!(
            gate.current_version(),
            0,
            "a below-floor successor fails closed to deny-all"
        );
        assert!(
            !alive.load(Ordering::SeqCst),
            "a below-floor successor raises the fail-closed alarm"
        );
        assert_eq!(
            state.version, 2,
            "the chain advances onto the below-floor successor"
        );
        assert_eq!(
            state.body_sha256, v2_hash,
            "the chain pin advances to the below-floor successor's hash"
        );

        // v3 at the floor chains onto v2; self-heal must restore admission without a restart.
        let _v3_hash =
            write_local_binding_bundle_at(&bundle_path, 3, LOCAL_TRANSPORT_SEED, Some(v2_hash));
        alive.store(true, Ordering::SeqCst);
        directory_reload_step(&gate, &config, NOW, &mut state, &alive);
        assert_eq!(
            gate.current_version(),
            3,
            "an at-floor successor chained onto the below-floor one self-heals admission"
        );
        assert_eq!(
            state.version, 3,
            "last-good advances to the recovered successor"
        );
    }

    #[test]
    fn directory_reload_fails_closed_when_below_floor_running_directory_has_an_invalid_successor() {
        // Operators raised minVersion above the running directory, so a restart would reject
        // it. An on-disk successor at or above the floor that FAILS verification (partially
        // written or bad) must not mask that: the reloader must fail closed to deny-all
        // rather than keep the below-floor directory admitting until expiry.
        let dir = tempfile::tempdir().unwrap();
        // v1 is the running directory; its hash is the chain pin.
        let (_v1_path, _v1_issuers, expires_at, v1_hash) =
            write_test_bundle(dir.path(), 1, false, None);
        // An on-disk v3 at or above the raised floor but that does NOT chain onto v1 (a
        // bad/partial successor), so it fails verification.
        let (bundle_path, _v3_issuers, _v3_expires, _v3_hash) =
            write_test_bundle(dir.path(), 3, false, Some("00".repeat(32)));
        // Raise minVersion to 3: the running v1 is below the floor, the on-disk v3 is at it.
        let issuers_path = write_issuers_with_min_version(dir.path(), 3);
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path,
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };
        let now_in_window = expires_at - 1;

        // Outcome-level: the invalid at-floor successor does not mask the below-floor running
        // directory; the reload fails closed rather than returning a transient verify error.
        let outcome = reload_verified_directory(&config, now_in_window, 1, expires_at, &v1_hash)
            .expect("reload runs");
        assert!(
            matches!(outcome, ReloadOutcome::BelowMinVersionFloor(None)),
            "a below-floor running directory with an invalid successor must fail closed, got \
             {outcome:?}"
        );

        // Step-level: the gate flips to deny-all and the alarm is raised.
        let gate = DirectoryGate::new(verified_directory("did:chio:bob", 24));
        assert_eq!(gate.current_version(), 1);
        let alive = AtomicBool::new(true);
        let mut state = ReloadState {
            version: 1,
            body_sha256: v1_hash.clone(),
            expires_at_unix_ms: expires_at,
        };
        directory_reload_step(&gate, &config, now_in_window, &mut state, &alive);
        assert_eq!(
            gate.current_version(),
            0,
            "a below-floor directory with a bad successor fails closed to deny-all"
        );
        assert!(
            !alive.load(Ordering::SeqCst),
            "the fail-closed alarm is raised"
        );
    }

    /// Like [`write_test_bundle`] but with an explicit validity window, so a test can
    /// publish a still-in-window successor AFTER the running bundle has lapsed. Writes to
    /// `path` and returns the full-document body hash (the successor's chain pin).
    fn write_test_bundle_windowed(
        path: &std::path::Path,
        version: u64,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        previous_version_sha256: Option<String>,
    ) -> String {
        let issuer = Keypair::from_seed(&[240u8; 32]);
        let directory = TransportDirectoryDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
            peers: vec![
                local_relay_entry(LOCAL_TRANSPORT_SEED),
                directory_entry("did:chio:bob", 7, 24),
            ],
            treaties: Vec::new(),
        };
        let directory_sha256 = sha256_hex(&canonical_json_bytes(&directory).unwrap());
        let body = TransportDirectoryBundleBody {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            issuer: "did:chio:issuer".to_string(),
            key_id: "issuer-key-1".to_string(),
            directory_sha256,
            version,
            previous_version_sha256,
            issued_at_unix_ms,
            expires_at_unix_ms,
        };
        let (signature, _) = issuer.sign_canonical(&body).unwrap();
        let bundle = TransportDirectoryBundleDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            body,
            directory,
            signature,
        };
        let body_hash = sha256_hex(&canonical_json_bytes(&bundle).unwrap());
        std::fs::write(path, serde_json::to_string(&bundle).unwrap()).unwrap();
        body_hash
    }

    #[test]
    fn directory_reloader_self_heals_after_expiry_lapse() {
        // After an expiry lapses the gate to deny-all, a valid in-window successor must
        // be able to swap back in WITHOUT a restart. The reloader keeps the
        // last-good version + hash chain SEPARATELY from the admission gate, so the deny-all
        // sentinel (version 0, empty predecessor hash) never becomes the chain the successor
        // must verify against.
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.json");
        let issuers_path = write_issuers_with_min_version(dir.path(), 0);
        // v1: in-window early, expires at NOW + 1.
        let v1_hash = write_test_bundle_windowed(&bundle_path, 1, NOW - 1, NOW + 1, None);

        let gate = DirectoryGate::new(std::sync::Arc::new(
            chio_federation_transport_iroh::identity::VerifiedDirectory::empty_deny_all(),
        ));
        let alive = AtomicBool::new(true);
        // The reloader's preserved last-good, pinned to the running v1.
        let mut state = ReloadState {
            version: 1,
            body_sha256: v1_hash.clone(),
            expires_at_unix_ms: NOW + 1,
        };
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path: bundle_path.clone(),
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };

        // Tick 1: now is PAST v1's expiry with no successor on disk -> fail closed to
        // deny-all, but last-good (v1) is PRESERVED.
        let now_expired = NOW + 2;
        directory_reload_step(&gate, &config, now_expired, &mut state, &alive);
        assert_eq!(gate.current_version(), 0, "expiry lapses the gate to deny-all");
        assert!(
            !alive.load(Ordering::SeqCst),
            "expiry raises the fail-closed alarm"
        );
        assert_eq!(
            state.version, 1,
            "last-good is preserved across the deny-all lapse"
        );

        // Publish a valid in-window v2 successor (chained onto v1, issued after v1 lapsed).
        let _v2_hash =
            write_test_bundle_windowed(&bundle_path, 2, NOW + 1, NOW + 100, Some(v1_hash.clone()));

        // Counterfactual: had the reloader re-derived last-good FROM THE GATE, the
        // deny-all sentinel (version 0, empty hash) would be the predecessor and the same
        // successor would NOT swap in.
        let denied = reload_verified_directory(&config, now_expired, 0, 0, "")
            .expect("reload runs against the deny-all sentinel");
        assert!(
            !matches!(denied, ReloadOutcome::Updated(_)),
            "a successor chained onto last-good cannot recover from the deny-all sentinel"
        );

        // Tick 2: the same successor verified against the PRESERVED last-good chain
        // self-heals admission back to v2.
        directory_reload_step(&gate, &config, now_expired, &mut state, &alive);
        assert_eq!(
            gate.current_version(),
            2,
            "a valid successor self-heals admission after an expiry lapse"
        );
        assert_eq!(
            state.version, 2,
            "last-good advances to the recovered successor"
        );
    }

    /// Write a signed successor to a FIXED `path` (so successive versions overwrite one
    /// bundle the reloader re-reads), binding the LOCAL node at `local_transport_seed`
    /// (pass [`LOCAL_TRANSPORT_SEED`] to REBIND this node, any other seed to ROTATE it
    /// away), peer `did:chio:bob` live, chaining onto `previous_version_sha256`. Returns
    /// the full-document body hash (the successor's chain pin).
    fn write_local_binding_bundle_at(
        path: &std::path::Path,
        version: u64,
        local_transport_seed: u8,
        previous_version_sha256: Option<String>,
    ) -> String {
        let (bundle_json, _issuer) = build_signed_bundle_json(
            vec![
                local_relay_entry(local_transport_seed),
                directory_entry("did:chio:bob", 7, 24),
            ],
            version,
            previous_version_sha256,
        );
        std::fs::write(path, &bundle_json).unwrap();
        let bundle: TransportDirectoryBundleDocument = serde_json::from_str(&bundle_json).unwrap();
        sha256_hex(&canonical_json_bytes(&bundle).unwrap())
    }

    #[test]
    fn directory_reload_advances_chain_after_local_binding_revoked() {
        // When a valid v2 successor rotates or tombstones this node (LocalBindingRevoked
        // -> deny-all), the reload chain must advance to v2 so a later v3 that rebinds this
        // node - chaining onto v2, the canonical successor - can self-heal admission,
        // rather than staying pinned to v1 and rejecting the correctly-chained v3 forever.
        // Here v2 revokes the local binding (the chain must advance to v2), then v3 chained
        // onto v2 rebinds this node and restores admission through the gate.
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.json");
        let issuers_path = write_issuers_with_min_version(dir.path(), 0);
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path: bundle_path.clone(),
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };

        // v1 binds this node (0x11); the reloader's last-good starts here.
        let v1_hash = write_local_binding_bundle_at(&bundle_path, 1, LOCAL_TRANSPORT_SEED, None);
        let gate = DirectoryGate::new(verified_directory("did:chio:bob", 24));
        assert_eq!(gate.current_version(), 1);
        let alive = AtomicBool::new(true);
        let mut state = ReloadState {
            version: 1,
            body_sha256: v1_hash.clone(),
            expires_at_unix_ms: NOW + 1,
        };

        // v2 ROTATES this node away (LOCAL -> 0x22), chaining onto v1 -> LocalBindingRevoked.
        let v2_hash = write_local_binding_bundle_at(&bundle_path, 2, 0x22, Some(v1_hash.clone()));
        directory_reload_step(&gate, &config, NOW, &mut state, &alive);
        assert_eq!(
            gate.current_version(),
            0,
            "a revoked local binding fails closed to deny-all"
        );
        assert!(
            !alive.load(Ordering::SeqCst),
            "a revoked local binding raises the fail-closed alarm"
        );
        assert_eq!(
            state.version, 2,
            "the chain advances to the revoking successor so a rebind can self-heal"
        );
        assert_eq!(
            state.body_sha256, v2_hash,
            "the chain pin advances to the revoking successor's hash"
        );

        // v3 REBINDS this node (LOCAL -> 0x11), chaining onto v2. Self-heal must restore
        // admission without a restart.
        let _v3_hash =
            write_local_binding_bundle_at(&bundle_path, 3, LOCAL_TRANSPORT_SEED, Some(v2_hash));
        alive.store(true, Ordering::SeqCst);
        directory_reload_step(&gate, &config, NOW, &mut state, &alive);
        assert_eq!(
            gate.current_version(),
            3,
            "a rebinding successor chained onto the revoker self-heals admission"
        );
        assert_eq!(
            state.version, 3,
            "last-good advances to the recovered successor"
        );
    }

    #[test]
    fn reloader_wakes_at_expiry_before_the_fixed_interval() {
        // The reloader must re-check expiry at the deadline, not wait the full fixed
        // interval. With a 60s interval, a bundle that expires just after a poll would
        // otherwise keep admitting for almost a minute (the gate's decide() is not itself
        // time-aware). next_reload_delay caps the wake at the expiry deadline: in-window
        // with expiry sooner than the interval it wakes at expiry, not 60s.
        let interval = Duration::from_secs(60);
        assert_eq!(
            next_reload_delay(interval, 1_000, 1_005),
            Duration::from_millis(5),
            "wake at the expiry deadline when it precedes the next fixed poll"
        );
        // Expiry farther off than the interval -> the fixed interval caps the wake.
        assert_eq!(
            next_reload_delay(interval, 1_000, 1_000 + 120_000),
            interval,
            "the fixed interval caps the wake when expiry is far off"
        );
        // Deny-all sentinel (gate expiry 0, admitting nothing) -> the fixed interval
        // governs the poll for a successor; never a zero-delay busy-loop.
        assert_eq!(
            next_reload_delay(interval, 2_000, 0),
            interval,
            "a deny-all gate polls on the fixed interval, not a busy-loop"
        );
    }

    #[test]
    fn reloader_rechecks_immediately_when_a_live_directory_expires_mid_cycle() {
        // A LIVE directory (positive expiry) whose deadline elapsed between the reload step
        // and this delay computation is still admitting through the gate, so it must be
        // rechecked IMMEDIATELY to flip it closed at the deadline, not admit for another
        // full interval. This is the distinction between "still-admitting-but-just-expired"
        // and the "already-deny-all" sentinel, which polls on the interval.
        let interval = Duration::from_secs(60);
        assert_eq!(
            next_reload_delay(interval, 2_000, 1_000),
            Duration::ZERO,
            "a live directory whose expiry already passed rechecks immediately"
        );
        // Expiry exactly at `now` is already past (decide uses `expires_at <= now`), so a
        // live directory at that boundary also rechecks immediately.
        assert_eq!(
            next_reload_delay(interval, 1_000, 1_000),
            Duration::ZERO,
            "a live directory whose expiry equals now rechecks immediately"
        );
    }

    #[test]
    fn watchdog_flips_gauge_and_alarms_on_death() {
        // A liveness probe reporting dead flips the router-alive gauge to 0 (the
        // testable per-tick step the spawned watchdog loops over).
        chio_federation_transport_iroh::metrics::set_router_alive(true);
        let dead = true;
        note_router_liveness(!dead); // alive = false
        assert_eq!(chio_federation_transport_iroh::metrics::router_alive(), 0);
        // A live probe restores the gauge.
        note_router_liveness(true);
        assert_eq!(chio_federation_transport_iroh::metrics::router_alive(), 1);
    }

    #[test]
    fn directory_reload_rejects_rollback_and_keeps_last_good() {
        let dir = tempfile::tempdir().unwrap();
        // On-disk bundle is version 1; the running directory is already at version 3.
        let (bundle_path, issuers_path, expires_at, _hash) =
            write_test_bundle(dir.path(), 1, false, None);
        let config = DirectoryReloadConfig {
            interval: Duration::from_secs(60),
            bundle_path,
            trusted_issuers_path: issuers_path,
            local_transport_endpoint: endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };
        let now_in_window = expires_at - 1;
        let error =
            reload_verified_directory(&config, now_in_window, 3, expires_at, "current-hash")
                .expect_err("an in-window rollback is rejected");
        assert!(matches!(
            error,
            DirectoryReloadError::Rollback {
                found: 1,
                current: 3
            }
        ));
    }

    #[test]
    fn successor_bundle_accepted_with_rotation_state_supplied() {
        // A ROTATED successor bundle (version 5, chaining onto a predecessor hash)
        // is REJECTED at genesis defaults (floor 0, no predecessor) but ACCEPTED
        // once the rotation-state pin supplies the floor + expected predecessor
        // hash, so a durable directory rotation is loadable at startup.
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.json");
        let issuers_path = dir.path().join("issuers.json");
        let key_path = dir.path().join("key.json");
        let state_path = dir.path().join("state.json");

        let predecessor = "predecessor-bundle-sha256".to_string();
        let (bundle_json, issuer) =
            signed_bundle_json("did:chio:bob", 24, 5, Some(predecessor.clone()));
        std::fs::write(&bundle_path, &bundle_json).unwrap();

        let issuers = serde_json::json!({
            "issuers": [{
                "issuer": "did:chio:issuer",
                "keyId": "issuer-key-1",
                "publicKey": issuer.public_key(),
            }],
        });
        std::fs::write(&issuers_path, serde_json::to_string(&issuers).unwrap()).unwrap();
        std::fs::write(&key_path, "{\"seedHex\":\"".to_string() + &"11".repeat(32) + "\"}").unwrap();

        // Without the rotation state, the successor is rejected fail-closed: its
        // previousVersionSha256 cannot chain onto the genesis default of None.
        let rejected = load_iroh_serve_inputs(
            true,
            Some(&bundle_path),
            None,
            Some(&issuers_path),
            Some(&key_path),
            "0.0.0.0:0",
            &[],
            "pheromone",
            NOW,
        );
        assert!(
            rejected.is_err(),
            "a rotated successor bundle must be rejected without the rotation-state pin"
        );

        // With the floor + predecessor hash supplied, the successor is accepted.
        let state = serde_json::json!({
            "versionFloor": 4,
            "expectedPreviousVersionSha256": predecessor,
        });
        std::fs::write(&state_path, serde_json::to_string(&state).unwrap()).unwrap();

        let inputs = load_iroh_serve_inputs(
            true,
            Some(&bundle_path),
            Some(&state_path),
            Some(&issuers_path),
            Some(&key_path),
            "0.0.0.0:0",
            &[],
            "pheromone",
            NOW,
        )
        .expect("successor bundle accepted with the rotation-state pin")
        .expect("iroh enabled must produce serve inputs");
        assert_eq!(
            inputs.directory.version(),
            5,
            "the accepted directory must be the rotated successor (version 5)"
        );
    }

    #[test]
    fn bundle_below_trusted_issuer_min_version_is_rejected_without_state_file() {
        // The shared --trusted-issuers file sets minVersion (the SAME floor the HTTP
        // peer-directory loader enforces). With NO explicit transport-directory-state
        // pin, that minVersion must be the rollback floor, so a below-floor bundle is
        // rejected fail-closed rather than promoted against a hardcoded floor of 0.
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.json");
        let issuers_path = dir.path().join("issuers.json");
        let key_path = dir.path().join("key.json");

        // A genesis-shaped bundle at version 3 (no predecessor to chain onto).
        let (below_json, issuer) = signed_bundle_json("did:chio:bob", 24, 3, None);
        std::fs::write(&bundle_path, &below_json).unwrap();

        // Pin minVersion = 5 in the trusted-issuers file (camelCase on the wire).
        let issuers = serde_json::json!({
            "issuers": [{
                "issuer": "did:chio:issuer",
                "keyId": "issuer-key-1",
                "publicKey": issuer.public_key(),
            }],
            "minVersion": 5,
        });
        std::fs::write(&issuers_path, serde_json::to_string(&issuers).unwrap()).unwrap();
        std::fs::write(&key_path, "{\"seedHex\":\"".to_string() + &"11".repeat(32) + "\"}").unwrap();

        // No state file: the floor comes from minVersion (5), so version 3 is rejected.
        let rejected = load_iroh_serve_inputs(
            true,
            Some(&bundle_path),
            None,
            Some(&issuers_path),
            Some(&key_path),
            "0.0.0.0:0",
            &[],
            "pheromone",
            NOW,
        );
        assert!(
            rejected.is_err(),
            "a bundle below the trusted-issuer minVersion must be rejected even without a state file"
        );

        // A genesis-shaped bundle above the floor (version 6, no predecessor) loads.
        let (above_json, _issuer) = signed_bundle_json("did:chio:bob", 24, 6, None);
        std::fs::write(&bundle_path, &above_json).unwrap();
        let inputs = load_iroh_serve_inputs(
            true,
            Some(&bundle_path),
            None,
            Some(&issuers_path),
            Some(&key_path),
            "0.0.0.0:0",
            &[],
            "pheromone",
            NOW,
        )
        .expect("a bundle above the minVersion floor loads")
        .expect("iroh enabled must produce serve inputs");
        assert_eq!(
            inputs.directory.version(),
            6,
            "the accepted directory must be the above-floor bundle"
        );

        // Boundary: minVersion is INCLUSIVE, so a bundle EXACTLY at minVersion (5)
        // must be accepted (the exclusive `version_floor` maps to minVersion - 1).
        let (at_floor_json, _issuer) = signed_bundle_json("did:chio:bob", 24, 5, None);
        std::fs::write(&bundle_path, &at_floor_json).unwrap();
        let at_floor = load_iroh_serve_inputs(
            true,
            Some(&bundle_path),
            None,
            Some(&issuers_path),
            Some(&key_path),
            "0.0.0.0:0",
            &[],
            "pheromone",
            NOW,
        )
        .expect("a bundle exactly at the minVersion floor loads")
        .expect("iroh enabled must produce serve inputs");
        assert_eq!(
            at_floor.directory.version(),
            5,
            "a bundle at minVersion must be accepted (inclusive floor)"
        );

        // Boundary: one BELOW minVersion (4) must still be rejected fail-closed.
        let (below_floor_json, _issuer) = signed_bundle_json("did:chio:bob", 24, 4, None);
        std::fs::write(&bundle_path, &below_floor_json).unwrap();
        let below_floor = load_iroh_serve_inputs(
            true,
            Some(&bundle_path),
            None,
            Some(&issuers_path),
            Some(&key_path),
            "0.0.0.0:0",
            &[],
            "pheromone",
            NOW,
        );
        assert!(
            below_floor.is_err(),
            "a bundle one below minVersion must be rejected"
        );
    }

    #[test]
    fn matching_local_transport_key_binding_loads() {
        // The directory endorses LOCAL_TRANSPORT_SEED for the local kernel id, and the
        // key file carries that SAME seed: the local-transport-key binding check passes
        // and startup produces serve inputs whose transport key is the endorsed endpoint.
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.json");
        let issuers_path = dir.path().join("issuers.json");
        let key_path = dir.path().join("key.json");

        let (bundle_json, issuer) = signed_bundle_json("did:chio:bob", 24, 6, None);
        std::fs::write(&bundle_path, &bundle_json).unwrap();
        let issuers = serde_json::json!({
            "issuers": [{
                "issuer": "did:chio:issuer",
                "keyId": "issuer-key-1",
                "publicKey": issuer.public_key(),
            }],
        });
        std::fs::write(&issuers_path, serde_json::to_string(&issuers).unwrap()).unwrap();
        std::fs::write(&key_path, transport_key_json(LOCAL_TRANSPORT_SEED)).unwrap();

        let inputs = load_iroh_serve_inputs(
            true,
            Some(&bundle_path),
            None,
            Some(&issuers_path),
            Some(&key_path),
            "0.0.0.0:0",
            &[],
            "pheromone",
            NOW,
        )
        .expect("a matching local transport key must load")
        .expect("iroh enabled must produce serve inputs");
        assert_eq!(
            inputs.transport_key.public(),
            endpoint_from_seed(LOCAL_TRANSPORT_SEED),
            "the loaded transport key must be the directory-endorsed local endpoint"
        );
    }

    #[test]
    fn local_transport_key_mismatch_fails_closed() {
        // The directory endorses LOCAL_TRANSPORT_SEED for the local kernel id, but the
        // key file carries a DIFFERENT seed: the endpoint would authenticate as an
        // EndpointId no peer endorses, so startup must fail closed BEFORE returning
        // serve inputs (peers enforcing the same directory would reject/bypass it).
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.json");
        let issuers_path = dir.path().join("issuers.json");
        let key_path = dir.path().join("key.json");

        let (bundle_json, issuer) = signed_bundle_json("did:chio:bob", 24, 6, None);
        std::fs::write(&bundle_path, &bundle_json).unwrap();
        let issuers = serde_json::json!({
            "issuers": [{
                "issuer": "did:chio:issuer",
                "keyId": "issuer-key-1",
                "publicKey": issuer.public_key(),
            }],
        });
        std::fs::write(&issuers_path, serde_json::to_string(&issuers).unwrap()).unwrap();
        // A key whose public endpoint (seed 0x22) is NOT the endorsed local one
        // (LOCAL_TRANSPORT_SEED, 0x11).
        std::fs::write(&key_path, transport_key_json(0x22)).unwrap();

        let error = match load_iroh_serve_inputs(
            true,
            Some(&bundle_path),
            None,
            Some(&issuers_path),
            Some(&key_path),
            "0.0.0.0:0",
            &[],
            "pheromone",
            NOW,
        ) {
            Ok(_) => {
                panic!("a transport key that is not the endorsed local binding must fail closed")
            }
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("does not match the")
                && error.to_string().contains("transport endpoint"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn local_kernel_without_directory_binding_fails_closed() {
        // The directory admits a peer but binds NO transport endpoint for the local
        // kernel id, so there is nothing this node can authenticate as. Fail closed.
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle.json");
        let issuers_path = dir.path().join("issuers.json");
        let key_path = dir.path().join("key.json");

        // Only a peer entry (no LOCAL_KERNEL_ID binding) in the directory.
        let (bundle_json, issuer) =
            build_signed_bundle_json(vec![directory_entry("did:chio:bob", 7, 24)], 6, None);
        std::fs::write(&bundle_path, &bundle_json).unwrap();
        let issuers = serde_json::json!({
            "issuers": [{
                "issuer": "did:chio:issuer",
                "keyId": "issuer-key-1",
                "publicKey": issuer.public_key(),
            }],
        });
        std::fs::write(&issuers_path, serde_json::to_string(&issuers).unwrap()).unwrap();
        std::fs::write(&key_path, transport_key_json(LOCAL_TRANSPORT_SEED)).unwrap();

        let error = match load_iroh_serve_inputs(
            true,
            Some(&bundle_path),
            None,
            Some(&issuers_path),
            Some(&key_path),
            "0.0.0.0:0",
            &[],
            "pheromone",
            NOW,
        ) {
            Ok(_) => panic!("a directory with no local binding must fail closed"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("no non-removed transport endpoint"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn revocation_and_bilateral_lanes_are_rejected_fail_closed() {
        assert!(parse_iroh_lanes("revocation").is_err());
        assert!(parse_iroh_lanes("bilateral").is_err());
        assert!(parse_iroh_lanes("pheromone,bilateral").is_err());
        assert!(parse_iroh_lanes("").is_err());
        assert_eq!(parse_iroh_lanes("pheromone").unwrap(), vec![IrohLane::Pheromone]);
    }

    async fn bind_dialer(seed: u8) -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[seed; 32]))
            .relay_mode(RelayMode::Disabled)
            // Single-family loopback bind (mirrors the production bind sites): clear the
            // default 0.0.0.0 + [::] transports before binding the one loopback address.
            .clear_ip_transports()
            .bind_addr((Ipv4Addr::LOCALHOST, 0))
            .expect("loopback bind address parses")
            .bind()
            .await
            .expect("dialer endpoint binds on loopback")
    }

    fn direct_addr(endpoint: &Endpoint) -> EndpointAddr {
        let socket = endpoint
            .bound_sockets()
            .into_iter()
            .next()
            .expect("endpoint bound a socket");
        EndpointAddr::new(endpoint.id()).with_ip_addr(socket)
    }

    #[tokio::test]
    async fn build_iroh_router_succeeds_and_403s_unadmitted_over_loopback() {
        let dialer_seed = 24u8;
        let unbound_seed = 99u8;
        // The directory admits only the endpoint derived from dialer_seed.
        let directory = verified_directory("did:chio:bob", dialer_seed);
        let inputs = IrohServeInputs {
            directory,
            // The acceptor's own transport key is unrelated to the admitted set.
            transport_key: SecretKey::from_bytes(&[42u8; 32]),
            // Matches the relay's own local id (peer_directory below), so the
            // relay/transport identity binding guard passes.
            transport_local_kernel_id: LOCAL_KERNEL_ID.to_string(),
            config: loopback_config(vec![IrohLane::Pheromone]),
        };
        let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
        let receiver: Arc<dyn RelayBatchReceiver> = Arc::new(RejectingReceiver);
        let peer_directory = peer_directory_admitting("did:chio:bob", RelayRole::Origin);

        let mount = build_iroh_router(
            inputs,
            receiver,
            store,
            peer_directory,
            MAX_PHEROMONE_BATCH_BYTES,
        )
        .await
            .expect("mount builder succeeds with a valid directory + gate");
        assert_eq!(mount.enabled_lanes, vec!["pheromone"]);
        // DEPLOYABILITY: the mount returns the ACTUAL bound socket(s). Binding on
        // loopback port 0, the OS must have assigned a concrete, non-zero port the
        // operator can log + hand to peers.
        assert!(
            !mount.bound_sockets.is_empty(),
            "mount must report at least one bound socket"
        );
        assert!(
            mount.bound_sockets.iter().all(|socket| socket.port() != 0),
            "an ephemeral bind must resolve to a concrete non-zero port: {:?}",
            mount.bound_sockets
        );
        // SECURITY: the config binds a single IPv4 loopback address. `clear_ip_transports`
        // before `bind_addr` must have removed BOTH default IP transports (0.0.0.0 AND
        // [::]), so the endpoint binds ONLY the operator-intended family - no stray IPv6
        // wildcard socket exposing the lane on an unintended interface.
        assert!(
            mount.bound_sockets.iter().all(std::net::SocketAddr::is_ipv4),
            "a single-family (IPv4 loopback) bind must NOT open any IPv6 socket: {:?}",
            mount.bound_sockets
        );
        let acceptor_addr = direct_addr(mount.router.endpoint());

        // An unadmitted (unbound) endpoint is rejected at the admission gate (403 at
        // after_handshake) BEFORE any handler runs: the delivery must error.
        let unbound = bind_dialer(unbound_seed).await;
        let batch = empty_batch();
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            deliver_batch_over_iroh(&unbound, acceptor_addr, &batch),
        )
        .await
        .expect("dial resolves before timeout");
        assert!(
            result.is_err(),
            "an unadmitted endpoint must be 403'd at the gate, got {result:?}"
        );

        mount.router.shutdown().await.ok();
    }

    #[tokio::test]
    async fn iroh_ingress_rejects_out_of_scope_sender_before_the_receiver() {
        // The transport gate ADMITS the dialer endpoint (it resolves to did:chio:bob),
        // so the batch reaches the handler; but the peer directory lists did:chio:bob
        // as a Receiver (NOT an Origin/Hub), so it is not authorized to SUBMIT inbound
        // batches. enforce_peer_batch_directory_scope must reject the batch on the iroh
        // ingress path BEFORE receive_batch - exactly as the HTTP handle_batch_relay
        // would - and the TripwireReceiver proves the batch never reached the receiver.
        let dialer_seed = 24u8;
        let directory = verified_directory("did:chio:bob", dialer_seed);
        let inputs = IrohServeInputs {
            directory,
            transport_key: SecretKey::from_bytes(&[42u8; 32]),
            // Matches the relay's own local id (peer_directory below), so the
            // relay/transport identity binding guard passes.
            transport_local_kernel_id: LOCAL_KERNEL_ID.to_string(),
            config: loopback_config(vec![IrohLane::Pheromone]),
        };
        let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
        let called = Arc::new(AtomicBool::new(false));
        let receiver: Arc<dyn RelayBatchReceiver> = Arc::new(TripwireReceiver {
            called: called.clone(),
        });
        // Admitted at the transport endpoint, but only a Receiver in the peer
        // directory: NOT authorized to submit inbound batches.
        let peer_directory = peer_directory_admitting("did:chio:bob", RelayRole::Receiver);

        let mount = build_iroh_router(
            inputs,
            receiver,
            store,
            peer_directory,
            MAX_PHEROMONE_BATCH_BYTES,
        )
        .await
            .expect("mount builder succeeds");
        let acceptor_addr = direct_addr(mount.router.endpoint());

        let dialer = bind_dialer(dialer_seed).await;
        let batch = empty_batch();
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            deliver_batch_over_iroh(&dialer, acceptor_addr, &batch),
        )
        .await
        .expect("dial resolves before timeout");
        assert!(
            result.is_err(),
            "an out-of-scope (non-Origin/Hub) sender's batch must be rejected on the iroh path, got {result:?}"
        );
        assert!(
            !called.load(Ordering::SeqCst),
            "the inbound scope gate must reject BEFORE the receiver is ever consulted"
        );

        mount.router.shutdown().await.ok();
    }

    #[tokio::test]
    async fn build_iroh_router_rejects_relay_vs_transport_local_id_mismatch() {
        // The transport directory's own localKernelId is the identity the iroh endpoint
        // authenticates AS. It MUST equal the relay's configured local identity
        // (peer_directory.local_kernel_id()), which the relay's receiver verifies every
        // inbound batch against. When they differ, the endpoint authenticates as a
        // DIFFERENT kernel than the receiver expects, so valid deliveries would be
        // rejected/dead-lettered while startup silently "succeeds". The build must fail
        // closed BEFORE binding the endpoint.
        let directory = verified_directory("did:chio:bob", 24);
        let inputs = IrohServeInputs {
            directory,
            transport_key: SecretKey::from_bytes(&[42u8; 32]),
            // A transport-directory local id that is NOT the relay's own (peer_directory
            // below is "did:chio:relay").
            transport_local_kernel_id: "did:chio:someone-else".to_string(),
            config: loopback_config(vec![IrohLane::Pheromone]),
        };
        let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
        let receiver: Arc<dyn RelayBatchReceiver> = Arc::new(RejectingReceiver);
        // The relay's local identity is "did:chio:relay".
        let peer_directory = peer_directory_admitting("did:chio:bob", RelayRole::Origin);

        let error = match build_iroh_router(
            inputs,
            receiver,
            store,
            peer_directory,
            MAX_PHEROMONE_BATCH_BYTES,
        )
        .await
        {
            Ok(_) => {
                panic!("a transport-directory local id that is not the relay's own must fail closed")
            }
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("does not match the relay")
                && error.to_string().contains("local kernel id"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn tick_outbound_endpoint_uses_ephemeral_port_not_the_serving_bind_addr() {
        // A durable relay-serve process holds the stable --iroh-bind-addr for inbound
        // reachability. The tick is OUTBOUND-ONLY: it must NOT reuse that addr:port, or
        // a second process would fail to bind the already-in-use UDP port. Occupy a
        // loopback port (standing in for a running serve), configure the tick with that
        // SAME addr:port, and prove the outbound endpoint binds a DISTINCT ephemeral port.
        let serve = bind_dialer(200).await;
        let serve_socket = serve
            .bound_sockets()
            .into_iter()
            .next()
            .expect("serve endpoint bound a socket");
        let serve_port = serve_socket.port();
        assert_ne!(serve_port, 0, "the occupied serve port must be concrete");

        let directory = verified_directory("did:chio:bob", 24);
        let mut config = loopback_config(vec![IrohLane::Pheromone]);
        // Reuse the EXACT stable serving addr:port the running serve already holds.
        config.bind_addr = serve_socket;
        let inputs = IrohServeInputs {
            directory,
            transport_key: SecretKey::from_bytes(&[42u8; 32]),
            // Must equal the relay local id passed to build_iroh_outbound_endpoint below
            // (the tick path now enforces the same relay/transport identity binding).
            transport_local_kernel_id: LOCAL_KERNEL_ID.to_string(),
            config,
        };

        let (endpoint, _directory) = build_iroh_outbound_endpoint(inputs, LOCAL_KERNEL_ID)
            .await
            .expect("the outbound tick endpoint must bind despite the serve addr being in use");
        let bound = endpoint.bound_sockets();
        assert!(!bound.is_empty(), "the outbound endpoint must bind a socket");
        assert!(
            bound.iter().all(|socket| socket.port() != serve_port),
            "the outbound tick endpoint must NOT reuse the serving port {serve_port}, got {bound:?}"
        );
        assert!(
            bound.iter().all(|socket| socket.port() != 0),
            "the ephemeral bind must resolve to a concrete non-zero port: {bound:?}"
        );
        // SECURITY: the configured bind addr is IPv4 loopback, so `clear_ip_transports`
        // before `bind_addr` must have dropped the default [::] transport too - the
        // outbound tick socket lives on ONLY the intended family, never an IPv6 wildcard.
        assert!(
            bound.iter().all(std::net::SocketAddr::is_ipv4),
            "the outbound tick bind must be single-family (IPv4), got {bound:?}"
        );

        endpoint.close().await;
        drop(serve);
    }
}
