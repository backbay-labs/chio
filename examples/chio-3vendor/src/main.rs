fn main() {
    if let Err(error) = chio_three_vendor_example::run_from_env() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
