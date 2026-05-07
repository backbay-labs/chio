use std::process::ExitCode;

use chio_tee::TEE_VERSION;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(first) = args.next() else {
        eprintln!("chio-tee runtime is not yet implemented");
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        eprintln!("chio-tee accepts only one command during skeleton bootstrap");
        return ExitCode::from(2);
    }
    match first.as_str() {
        "-h" | "--help" => {
            print_help();
            ExitCode::SUCCESS
        }
        "-V" | "--version" => {
            println!("chio-tee {TEE_VERSION}");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("chio-tee runtime is not yet implemented");
            ExitCode::from(2)
        }
    }
}

fn print_help() {
    println!(
        "chio-tee {TEE_VERSION}\n\
         \n\
         Usage: chio-tee [--help|--version]\n\
         \n\
         The TEE runtime is in skeleton bootstrap. Help and version are\n\
         read-only introspection paths; runtime commands fail closed until\n\
         the shadow runner is implemented."
    );
}
