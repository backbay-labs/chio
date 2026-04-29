// Build-time check that the embedded Sigstore TUF root materials exist on
// disk under `sigstore-root/`. The trust root is shipped in-tree and refreshed
// via a quarterly CODEOWNERS-reviewed re-bake job; no network access at build time.

use std::path::Path;

fn main() {
    let root_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("sigstore-root");
    let trusted_root = root_dir.join("trusted_root.json");
    let tuf_root = root_dir.join("root.json");

    for required in [&trusted_root, &tuf_root] {
        if !required.exists() {
            panic!(
                "chio-attest-verify build aborted: missing embedded Sigstore \
                 trust-root file `{}`. Run the quarterly re-bake job or copy \
                 the canonical files from sigstore-rs `trust_root/prod/`.",
                required.display()
            );
        }
        println!("cargo:rerun-if-changed={}", required.display());
    }

    println!("cargo:rerun-if-changed=build.rs");
}
