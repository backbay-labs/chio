use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(error) = hello_tool::run().await {
        eprintln!("{error}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
