use std::path::PathBuf;

use chio_conformance::{
    default_run_options, run_conformance_harness, ConformanceAuthMode, ConformanceRunSummary,
    PeerTarget,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut options = default_run_options();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--scenarios-dir" => options.scenarios_dir = next_path(&mut args, &flag)?,
            "--results-dir" => options.results_dir = next_path(&mut args, &flag)?,
            "--report-output" => options.report_output = next_path(&mut args, &flag)?,
            "--policy" => options.policy_path = next_path(&mut args, &flag)?,
            "--upstream-server" => options.upstream_server_script = next_path(&mut args, &flag)?,
            "--auth-mode" => {
                options.auth_mode =
                    parse_auth_mode(&next_string(&mut args, &flag)?).ok_or_else(|| {
                        format!("invalid value for {flag}: expected static-bearer or oauth-local")
                    })?;
            }
            "--auth-token" => options.auth_token = next_string(&mut args, &flag)?,
            "--admin-token" => options.admin_token = next_string(&mut args, &flag)?,
            "--auth-scope" => options.auth_scope = next_string(&mut args, &flag)?,
            "--listen" => options.listen = Some(next_string(&mut args, &flag)?.parse()?),
            "--peer" => {
                options.peers = parse_peers(&next_string(&mut args, &flag)?).ok_or_else(|| {
                    format!("invalid value for {flag}: expected js, python, go, cpp, or all")
                })?;
            }
            other => return Err(format!("unexpected flag: {other}").into()),
        }
    }

    let summary = run_conformance_harness(&options)?;
    print_summary(&summary);
    Ok(())
}

fn print_summary(summary: &ConformanceRunSummary) {
    println!("results: {}", summary.results_dir.display());
    println!("report:  {}", summary.report_output.display());
    println!("listen:  {}", summary.listen);
    for result in &summary.peer_result_files {
        println!("peer:    {}", result.display());
    }
}

fn parse_peers(value: &str) -> Option<Vec<PeerTarget>> {
    match value {
        "all" => Some(vec![
            PeerTarget::Js,
            PeerTarget::Python,
            PeerTarget::Go,
            PeerTarget::Cpp,
        ]),
        "js" => Some(vec![PeerTarget::Js]),
        "python" => Some(vec![PeerTarget::Python]),
        "go" => Some(vec![PeerTarget::Go]),
        "cpp" => Some(vec![PeerTarget::Cpp]),
        _ => None,
    }
}

fn parse_auth_mode(value: &str) -> Option<ConformanceAuthMode> {
    match value {
        "static-bearer" => Some(ConformanceAuthMode::StaticBearer),
        "oauth-local" => Some(ConformanceAuthMode::LocalOAuth),
        _ => None,
    }
}

fn next_path(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(PathBuf::from(next_string(args, flag)?))
}

fn next_string(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    args.next()
        .ok_or_else(|| format!("missing value for {flag}").into())
}
