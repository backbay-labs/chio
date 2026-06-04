fn main() {
    if let Err(error) = chiodome_bilateral_example::run_from_env() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
