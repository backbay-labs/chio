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

    // Only the pheromone lane is wireable here; parse_iroh_lanes already rejected
    // anything else, so this is a defense-in-depth re-check.
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
    let transport_config = QuicTransportConfig::builder()
        .max_idle_timeout(Some(idle_timeout))
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
    let handler = PheromoneBatchHandler::new(gate, receiver, store, now_fn, scope_check)
        .with_max_batch_bytes(max_batch_bytes);
    let router = mount_pheromone_lane(endpoint, handler);

    let enabled_lanes = config.lanes.iter().map(|lane| lane.label()).collect();
    Ok(IrohMount {
        router,
        endpoint_id,
        bound_sockets,
        enabled_lanes,
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
    let transport_config = QuicTransportConfig::builder()
        .max_idle_timeout(Some(idle_timeout))
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
