fn main() {
    if let Err(error) = cross_provider_policy::run_from_env() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
