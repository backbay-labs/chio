use super::*;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(serde::Serialize)]
struct ProofServeReport {
    schema: &'static str,
    bundle: String,
    static_root: String,
    ui_root: Option<String>,
    ui_mode: &'static str,
    listen: String,
    verifier_parity: &'static str,
}

pub(super) fn serve_proof_bundle(
    bundle: &Path,
    listen: &str,
    dry_run: bool,
    json_output: bool,
) -> Result<(), CliError> {
    let archive_root = archive::extract_proof_archive(bundle)?;
    let input_path = match archive_root.as_ref() {
        Some(archive_root) => archive_root.path(),
        None => bundle,
    };
    verify_static_proof_bundle(input_path)?;
    let static_root = proof_room_static_root(input_path);
    let ui_root = proof_room_ui_root()?;
    let bundle = bundle.to_string_lossy().into_owned();
    let static_root_report = static_root.to_string_lossy().into_owned();
    let ui_root_report = ui_root
        .as_ref()
        .map(|path| path.to_string_lossy().into_owned());
    let ui_mode = if ui_root.is_some() {
        "static-ui"
    } else {
        "bundle-assets-only"
    };
    if dry_run {
        let report = ProofServeReport {
            schema: "chio.proof.serve-report.v1",
            bundle,
            static_root: static_root_report,
            ui_root: ui_root_report,
            ui_mode,
            listen: listen.to_string(),
            verifier_parity: "verified",
        };
        write_serve_report(&report, json_output)?;
        return Ok(());
    }
    let fixture_root = proof_room_fixture_root();
    let router = chio_proof_room::proof_room_router_with_optional_ui_root(
        static_root,
        ui_root,
        fixture_root,
    )
    .map_err(|error| CliError::cli_other_error(error.to_string()))?;

    let address = listen.parse::<SocketAddr>().map_err(|error| {
        CliError::cli_other_error(format!("proof serve listen address parse failed: {error}"))
    })?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| CliError::cli_other_error(format!("proof serve runtime: {error}")))?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .map_err(|error| CliError::cli_io_error(format!("proof serve bind: {error}")))?;
        let bound_listen = listener
            .local_addr()
            .map_err(|error| CliError::cli_io_error(format!("proof serve bind: {error}")))?
            .to_string();
        let report = ProofServeReport {
            schema: "chio.proof.serve-report.v1",
            bundle,
            static_root: static_root_report,
            ui_root: ui_root_report,
            ui_mode,
            listen: bound_listen,
            verifier_parity: "verified",
        };
        write_serve_report(&report, json_output)?;

        let hygiene = chio_http_serve::ServeHygieneConfig::default();
        let router = chio_http_serve::apply_server_hygiene(router, &hygiene);
        let controller = chio_http_serve::ShutdownController::install();
        let listener = chio_http_serve::MaxConnListener::new(
            listener,
            hygiene.max_connections.unwrap_or(usize::MAX),
        );
        let server =
            axum::serve(listener, router).with_graceful_shutdown(controller.signalled());

        // Read-only static serving: nothing to flush after the drain.
        chio_http_serve::run_until_drained(
            server,
            controller.subscribe(),
            hygiene.drain_timeout,
            async { Ok::<(), String>(()) },
        )
        .await
        .map(|_outcome| ())
        .map_err(|error| CliError::cli_io_error(format!("proof serve: {error}")))
    })
}

fn write_serve_report(report: &ProofServeReport, json_output: bool) -> Result<(), CliError> {
    let mut stdout = std::io::stdout();
    if json_output {
        serde_json::to_writer(&mut stdout, report)?;
        stdout.write_all(b"\n")?;
    } else {
        writeln!(
            stdout,
            "serving {} from {}",
            report.bundle, report.static_root
        )?;
        if let Some(ui_root) = &report.ui_root {
            writeln!(stdout, "ui: {ui_root}")?;
        }
        writeln!(stdout, "verifier parity: {}", report.verifier_parity)?;
    }
    Ok(())
}

fn proof_room_static_root(bundle: &Path) -> PathBuf {
    bundle.to_path_buf()
}

fn proof_room_ui_root() -> Result<Option<PathBuf>, CliError> {
    if let Some(path) = std::env::var_os("CHIO_PROOF_ROOM_UI_DIR") {
        let path = PathBuf::from(path);
        if path.join("index.html").is_file() {
            return Ok(Some(path));
        }
        if path.is_dir() {
            return Err(CliError::cli_io_error(format!(
                "proof room UI index missing: {}",
                path.join("index.html").display()
            )));
        }
        return Err(CliError::cli_io_error(format!(
            "proof room UI directory does not exist: {}",
            path.display()
        )));
    }

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        manifest_dir.join("dashboard/dist"),
        PathBuf::from("/opt/chio/dashboard/dist"),
    ];
    Ok(candidates
        .into_iter()
        .find(|path| path.join("index.html").is_file()))
}

fn proof_room_fixture_root() -> Option<PathBuf> {
    if let Some(root) = fixture::installed_fixture_root() {
        return Some(root);
    }
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    [
        manifest_dir.join("../../../fixtures/proof-room"),
        PathBuf::from("/opt/chio/fixtures/proof-room"),
    ]
    .into_iter()
    .find(|path| path.join("catalog.json").is_file())
}
