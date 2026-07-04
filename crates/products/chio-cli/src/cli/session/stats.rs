#[derive(Default)]
pub(crate) struct SessionStats {
    pub(super) requests: u64,
    pub(super) allowed: u64,
    pub(super) denied: u64,
}

pub(crate) fn print_summary(stats: &SessionStats, exit_code: Option<i32>, json_output: bool) {
    if json_output {
        let output = serde_json::json!({
            "summary": {
                "requests": stats.requests,
                "allowed": stats.allowed,
                "denied": stats.denied,
                "exit_code": exit_code,
            }
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
    } else {
        eprintln!();
        eprintln!("--- chio session summary ---");
        eprintln!("requests: {}", stats.requests);
        eprintln!("allowed:  {}", stats.allowed);
        eprintln!("denied:   {}", stats.denied);
        if let Some(code) = exit_code {
            eprintln!("exit:     {code}");
        }
    }
}
