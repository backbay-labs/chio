use crate::CliError;

use chio_wasm_guards::blocklist::GuardDigestBlocklist;

pub(crate) fn cmd_guard_blocklist_remove(digest: &str) -> Result<(), CliError> {
    let blocklist = GuardDigestBlocklist::from_environment()
        .map_err(|e| CliError::Other(format!("failed to load guard blocklist: {e}")))?;
    let removed = blocklist
        .remove_digest(digest)
        .map_err(|e| CliError::Other(format!("failed to update guard blocklist: {e}")))?;
    if removed {
        println!("removed guard digest from blocklist: {digest}");
    } else {
        println!("guard digest was not blocklisted: {digest}");
    }
    println!("blocklist: {}", blocklist.path().display());
    Ok(())
}
