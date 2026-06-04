use std::process::ExitCode;

fn main() -> ExitCode {
    let result =
        hello_a2a::parse_mode_arg(std::env::args()).and_then(|mode| hello_a2a::run_mode(&mode));
    if let Err(error) = result {
        eprintln!("{error}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
