use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

type BuildResult<T> = Result<T, Box<dyn std::error::Error>>;

fn main() -> BuildResult<()> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let fixture_root = manifest_dir.join("../../../fixtures/proof-room");
    let shared_source = manifest_dir.join("../proof_fixture_build.rs");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let generated_path = out_dir.join("proof_fixture_files.rs");

    println!("cargo:rerun-if-changed={}", shared_source.display());

    let mut files = Vec::new();
    println!("cargo:rerun-if-changed={}", fixture_root.display());

    for embedded_root in embedded_fixture_roots(&manifest_dir, &fixture_root)? {
        println!("cargo:rerun-if-changed={}", embedded_root.display());
        collect_fixture_files(&fixture_root, &embedded_root, &mut files)?;
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));

    let mut generated = fs::File::create(&generated_path)?;
    writeln!(
        generated,
        "const EMBEDDED_PROOF_FIXTURE_FILES: &[EmbeddedProofFixtureFile] = &["
    )?;
    for (relative_path, absolute_path) in files {
        writeln!(
            generated,
            "    EmbeddedProofFixtureFile {{ path: {:?}, contents: include_bytes!({:?}) }},",
            relative_path,
            absolute_path.to_string_lossy()
        )?;
    }
    writeln!(generated, "];")?;
    Ok(())
}

fn embedded_fixture_roots(manifest_dir: &Path, fixture_root: &Path) -> BuildResult<Vec<PathBuf>> {
    let package_name = manifest_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if package_name == "chio-proof-room" {
        return Ok(vec![fixture_root.join("first-run/single-call-authority")]);
    }
    if package_name == "chio-cli" {
        let mut roots = Vec::new();
        for entry in fs::read_dir(fixture_root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            if entry.file_name().to_str() == Some("public-stages") {
                continue;
            }
            roots.push(entry.path());
        }
        roots.sort();
        return Ok(roots);
    }
    Ok(vec![fixture_root.to_path_buf()])
}

fn collect_fixture_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<(String, PathBuf)>,
) -> BuildResult<()> {
    println!("cargo:rerun-if-changed={}", directory.display());
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_fixture_files(root, &path, files)?;
        } else if file_type.is_file() {
            println!("cargo:rerun-if-changed={}", path.display());
            files.push((relative_fixture_path(root, &path)?, path));
        } else {
            return Err(format!("unsupported proof fixture file type: {}", path.display()).into());
        }
    }
    Ok(())
}

fn relative_fixture_path(root: &Path, path: &Path) -> BuildResult<String> {
    let relative_path = path.strip_prefix(root)?;
    let mut parts = Vec::new();
    for component in relative_path.components() {
        match component {
            Component::Normal(part) => {
                let Some(part) = part.to_str() else {
                    return Err(
                        format!("proof fixture path is not utf8: {}", path.display()).into(),
                    );
                };
                parts.push(part.to_string());
            }
            _ => {
                return Err(format!("unsupported proof fixture path: {}", path.display()).into());
            }
        }
    }
    Ok(parts.join("/"))
}
