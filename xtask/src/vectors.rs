use std::fs;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::support::{digest_to_hex, display_path, walk_json, workspace_root};
use crate::XtaskError;

const VECTORS_DIR: &str = "tests/bindings/vectors";
const VECTORS_MANIFEST: &str = "tests/bindings/vectors/MANIFEST.sha256";

pub(crate) fn freeze_vectors(args: Vec<String>) -> Result<(), XtaskError> {
    let mut check_only = false;
    for arg in args {
        match arg.as_str() {
            "--check" => check_only = true,
            other => {
                return Err(XtaskError::Usage(format!(
                    "freeze-vectors: unknown flag: {other}"
                )));
            }
        }
    }

    let workspace_root = workspace_root()?;
    let vectors_dir = workspace_root.join(VECTORS_DIR);
    let manifest_path = workspace_root.join(VECTORS_MANIFEST);

    let mut json_files: Vec<PathBuf> = Vec::new();
    if vectors_dir.exists() {
        walk_json(&vectors_dir, &mut json_files)?;
    }
    json_files.sort();

    // Build (relative-path, sha256-hex) pairs sorted by relative path.
    let mut entries: Vec<(String, String)> = Vec::with_capacity(json_files.len());
    for path in &json_files {
        let rel = path.strip_prefix(&workspace_root).map_err(|_| {
            XtaskError::Usage(format!(
                "freeze-vectors: vector file {} is not under workspace root",
                display_path(path)
            ))
        })?;
        let rel_str = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        let bytes = fs::read(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();
        let hex = digest_to_hex(&digest);
        entries.push((rel_str, hex));
    }
    // Sort lexicographically by relative path; tuples compare by `.0` first.
    entries.sort();

    // Format mirrors `shasum -a 256`: "<hex>  <path>\n" per file (including
    // a trailing newline after the last entry).
    let mut new_content = String::with_capacity(entries.len() * 96);
    for (rel_str, hex) in &entries {
        new_content.push_str(hex);
        new_content.push_str("  ");
        new_content.push_str(rel_str);
        new_content.push('\n');
    }

    if check_only {
        let existing = fs::read_to_string(&manifest_path)
            .map_err(|err| XtaskError::Io(display_path(&manifest_path), err))?;
        if existing != new_content {
            let drift = describe_manifest_drift(&existing, &new_content);
            return Err(XtaskError::Drift(format!(
                "{} is stale; rerun `cargo xtask freeze-vectors` ({} vector files inspected)\n{}",
                display_path(&manifest_path),
                entries.len(),
                drift
            )));
        }
        println!(
            "{} in sync with {} vector files",
            display_path(&manifest_path),
            entries.len()
        );
    } else {
        fs::write(&manifest_path, &new_content)
            .map_err(|err| XtaskError::Io(display_path(&manifest_path), err))?;
        println!(
            "wrote {} ({} vector files)",
            display_path(&manifest_path),
            entries.len()
        );
    }
    Ok(())
}

fn describe_manifest_drift(existing: &str, computed: &str) -> String {
    let existing_lines: Vec<&str> = existing.lines().collect();
    let computed_lines: Vec<&str> = computed.lines().collect();
    let mut diff = String::new();
    let mut shown = 0usize;
    let limit = 8usize;
    let max_len = existing_lines.len().max(computed_lines.len());
    for idx in 0..max_len {
        let lhs = existing_lines.get(idx).copied().unwrap_or("");
        let rhs = computed_lines.get(idx).copied().unwrap_or("");
        if lhs != rhs {
            if shown < limit {
                diff.push_str(&format!("  - on-disk: {lhs}\n"));
                diff.push_str(&format!("  + computed: {rhs}\n"));
            }
            shown += 1;
        }
    }
    if shown == 0 {
        // Bytes differ but no per-line difference (e.g. trailing newline).
        format!(
            "  on-disk bytes ({}) != computed bytes ({})",
            existing.len(),
            computed.len()
        )
    } else if shown > limit {
        format!("{diff}  ... ({} more differing lines)", shown - limit)
    } else {
        diff
    }
}
